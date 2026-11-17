//! Thread-local COM access. Never executes/resolves shortcut targets or task actions.

use super::{Identity, MAX_ENTRIES, StartupEntry, StartupSnapshot, id, validate_entry, warn};
use crate::win::os_wide;
use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    marker::PhantomData,
    os::windows::ffi::OsStringExt,
    path::{Path, PathBuf},
    rc::Rc,
};
use windows::{
    Win32::{
        Foundation::{RPC_E_CHANGED_MODE, VARIANT_BOOL},
        System::{
            Com::{
                CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx,
                CoTaskMemFree, CoUninitialize, IPersistFile, STGM_READ,
            },
            TaskScheduler::*,
            Variant::VARIANT,
        },
        UI::Shell::{
            FOLDERID_CommonStartup, FOLDERID_Startup, IShellLinkW, KF_FLAG_DONT_VERIFY,
            SHGetKnownFolderPath, SLGP_RAWPATH, ShellLink,
        },
    },
    core::{BSTR, Interface, PCWSTR},
};

pub(super) struct ComScope {
    uninitialize: bool,
    _thread_bound: PhantomData<Rc<()>>,
}
impl ComScope {
    pub(super) fn new() -> Result<Self, String> {
        // SAFETY: initializes this thread only; successful calls are balanced by Drop on the same thread.
        let result = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        if result.is_err() && result != RPC_E_CHANGED_MODE {
            return Err(format!("Initialize startup COM: {result}"));
        }
        Ok(Self {
            uninitialize: result.is_ok(),
            _thread_bound: PhantomData,
        })
    }
}
impl Drop for ComScope {
    fn drop(&mut self) {
        if self.uninitialize {
            // SAFETY: this guard successfully initialized COM on this thread and is !Send.
            unsafe {
                CoUninitialize();
            }
        }
    }
}

pub(super) fn startup_folder(common: bool) -> Result<PathBuf, String> {
    let folder = if common {
        &FOLDERID_CommonStartup
    } else {
        &FOLDERID_Startup
    };
    // SAFETY: valid known-folder GUID; Windows allocates the returned path with the COM allocator.
    let path = unsafe { SHGetKnownFolderPath(folder, KF_FLAG_DONT_VERIFY, None) }
        .map_err(|e| format!("Locate startup folder: {e}"))?;
    // SAFETY: successful SHGetKnownFolderPath returns a NUL-terminated UTF-16 string.
    let result = unsafe { PathBuf::from(std::ffi::OsString::from_wide(path.as_wide())) };
    // SAFETY: path is the allocation returned by SHGetKnownFolderPath and is freed exactly once.
    unsafe {
        CoTaskMemFree(Some(path.0.cast()));
    }
    Ok(result)
}

fn text(value: BSTR) -> Result<String, String> {
    if value.len() > 32768 || value.contains(&0) {
        return Err("Startup COM string is oversized or contains a NUL".into());
    }
    String::from_utf16(&value).map_err(|_| "Startup COM string contains invalid UTF-16".into())
}

fn buffer_text(buffer: &[u16]) -> Result<String, String> {
    let length = buffer
        .iter()
        .position(|&x| x == 0)
        .ok_or("Shortcut command exceeded its buffer")?;
    String::from_utf16(&buffer[..length])
        .map_err(|_| "Shortcut command contains invalid UTF-16".into())
}

pub(super) fn shortcut_command(path: &Path) -> Result<String, String> {
    if std::fs::metadata(path).map_err(|e| e.to_string())?.len() > 1024 * 1024 {
        return Err("Startup shortcut exceeds 1 MiB; skipped".into());
    }
    // SAFETY: caller holds ComScope; only the system ShellLink class is instantiated. Load reads the local link without Resolve/execute.
    unsafe {
        let link: IShellLinkW = CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER)
            .map_err(|e| format!("Create shortcut reader: {e}"))?;
        let file: IPersistFile = link.cast().map_err(|e| e.to_string())?;
        file.Load(PCWSTR(os_wide(path.as_os_str()).as_ptr()), STGM_READ)
            .map_err(|e| format!("Read {}: {e}", path.display()))?;
        let mut target = vec![0u16; 32768];
        let mut arguments = vec![0u16; 32768];
        link.GetPath(&mut target, std::ptr::null_mut(), SLGP_RAWPATH.0 as u32)
            .map_err(|e| e.to_string())?;
        link.GetArguments(&mut arguments)
            .map_err(|e| e.to_string())?;
        let target = buffer_text(&target)?;
        if target.is_empty() {
            return Err(format!(
                "{}: shortcut target is not a filesystem command",
                path.display()
            ));
        }
        let arguments = buffer_text(&arguments)?;
        Ok(if arguments.is_empty() {
            format!("\"{target}\"")
        } else {
            format!("\"{target}\" {arguments}")
        })
    }
}

fn service() -> Result<ITaskService, String> {
    // SAFETY: caller initialized COM; empty variants connect to the local machine as the current user.
    unsafe {
        let service: ITaskService = CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER)
            .map_err(|e| format!("Create local Task Scheduler client: {e}"))?;
        let empty = VARIANT::default();
        service
            .Connect(&empty, &empty, &empty, &empty)
            .map_err(|e| format!("Connect to local Task Scheduler: {e}"))?;
        Ok(service)
    }
}

fn bounded_count(count: i32, limit: i32, context: &str) -> Result<i32, String> {
    if !(0..=limit).contains(&count) {
        return Err(format!(
            "{context} count {count} exceeds the inventory limit"
        ));
    }
    Ok(count)
}

fn inspect_task(task: &IRegisteredTask) -> Result<Option<StartupEntry>, String> {
    // SAFETY: task is a live COM interface on this thread. All output parameters are initialized valid storage.
    unsafe {
        let definition = task.Definition().map_err(|e| e.to_string())?;
        let triggers = definition.Triggers().map_err(|e| e.to_string())?;
        let mut count = 0;
        triggers.Count(&mut count).map_err(|e| e.to_string())?;
        let mut startup = false;
        let mut active_trigger = false;
        for index in 1..=bounded_count(count, 128, "Task trigger")? {
            let trigger = triggers.get_Item(index).map_err(|e| e.to_string())?;
            let mut kind = TASK_TRIGGER_TYPE2::default();
            trigger.Type(&mut kind).map_err(|e| e.to_string())?;
            if kind == TASK_TRIGGER_BOOT || kind == TASK_TRIGGER_LOGON {
                startup = true;
                let mut enabled = VARIANT_BOOL::default();
                trigger.Enabled(&mut enabled).map_err(|e| e.to_string())?;
                active_trigger |= enabled.as_bool();
            }
        }
        if !startup {
            return Ok(None);
        }
        let actions = definition.Actions().map_err(|e| e.to_string())?;
        actions.Count(&mut count).map_err(|e| e.to_string())?;
        let mut commands = Vec::new();
        for index in 1..=bounded_count(count, 32, "Task action")? {
            let action = actions.get_Item(index).map_err(|e| e.to_string())?;
            let mut kind = TASK_ACTION_TYPE::default();
            action.Type(&mut kind).map_err(|e| e.to_string())?;
            if kind == TASK_ACTION_EXEC {
                let action: IExecAction = action.cast().map_err(|e| e.to_string())?;
                let mut path = BSTR::new();
                let mut arguments = BSTR::new();
                action.Path(&mut path).map_err(|e| e.to_string())?;
                action
                    .Arguments(&mut arguments)
                    .map_err(|e| e.to_string())?;
                let path = text(path)?;
                let arguments = text(arguments)?;
                commands.push(if arguments.is_empty() {
                    format!("\"{path}\"")
                } else {
                    format!("\"{path}\" {arguments}")
                });
            } else if kind == TASK_ACTION_COM_HANDLER {
                let action: IComHandlerAction = action.cast().map_err(|e| e.to_string())?;
                let mut class = BSTR::new();
                action.ClassId(&mut class).map_err(|e| e.to_string())?;
                commands.push(format!("COM handler {}", text(class)?));
            } else {
                commands.push(format!("Task action type {}", kind.0));
            }
        }
        let path = text(task.Path().map_err(|e| e.to_string())?)?;
        let name = text(task.Name().map_err(|e| e.to_string())?)?;
        let xml = task.Xml().map_err(|e| e.to_string())?;
        if xml.len() > 512 * 1024 {
            return Err(format!("{path}: task definition exceeds 1 MiB"));
        }
        // A compact freshness token, not an authentication boundary. Windows enforces task ACLs.
        let mut hash = DefaultHasher::new();
        xml.hash(&mut hash);
        let token = format!("{:016x}", hash.finish());
        Ok(Some(StartupEntry {
            id: id(&Identity::Task {
                path: path.clone(),
                definition: token,
            }),
            name,
            source: if active_trigger {
                "Scheduled task (boot/logon)".into()
            } else {
                "Scheduled task (boot/logon, triggers disabled)".into()
            },
            location: path,
            command: commands.join(" ; "),
            enabled: task.Enabled().map_err(|e| e.to_string())?.as_bool() && active_trigger,
            // Enabling the task must actually enable a startup trigger; never rewrite individual triggers.
            can_toggle: active_trigger,
        }))
    }
}

pub(super) fn scan_tasks(snapshot: &mut StartupSnapshot) {
    if let Err(error) = scan_tasks_inner(snapshot) {
        warn(snapshot, error);
    }
}

fn scan_tasks_inner(snapshot: &mut StartupSnapshot) -> Result<(), String> {
    let service = service()?;
    // SAFETY: service is connected on this COM-initialized thread. Collections use valid one-based indices.
    unsafe {
        let root = service
            .GetFolder(&BSTR::from("\\"))
            .map_err(|e| format!("Read Task Scheduler root: {e}"))?;
        let mut pending = vec![root];
        let mut folders_seen = 0;
        let mut tasks_seen = 0;
        while let Some(folder) = pending.pop() {
            folders_seen += 1;
            if folders_seen > 2048 {
                return Err("Task Scheduler folder limit reached; inventory is incomplete".into());
            }
            let location = folder
                .Path()
                .map(|s| s.to_string())
                .unwrap_or_else(|_| "(unknown folder)".into());
            match folder.GetTasks(TASK_ENUM_HIDDEN.0) {
                Ok(collection) => {
                    let count = bounded_count(
                        collection.Count().map_err(|e| e.to_string())?,
                        8192,
                        "Scheduled task",
                    )?;
                    for index in 1..=count {
                        tasks_seen += 1;
                        if tasks_seen > 8192 || snapshot.entries.len() >= MAX_ENTRIES {
                            return Err(
                                "Task inventory limit reached; results are incomplete".into()
                            );
                        }
                        let result = collection
                            .get_Item(&VARIANT::from(index))
                            .map_err(|e| e.to_string())
                            .and_then(|task| inspect_task(&task));
                        match result {
                            Ok(Some(entry)) => snapshot.entries.push(entry),
                            Ok(None) => {}
                            Err(error) => {
                                warn(snapshot, format!("Task {location}, item {index}: {error}"))
                            }
                        }
                    }
                }
                Err(error) => warn(snapshot, format!("Tasks in {location}: {error}")),
            }
            match folder.GetFolders(0) {
                Ok(collection) => {
                    let count = bounded_count(
                        collection.Count().map_err(|e| e.to_string())?,
                        2048,
                        "Task folder",
                    )?;
                    if pending.len() + count as usize > 2048 {
                        return Err(
                            "Task folder queue limit reached; inventory is incomplete".into()
                        );
                    }
                    for index in 1..=count {
                        match collection.get_Item(&VARIANT::from(index)) {
                            Ok(child) => pending.push(child),
                            Err(error) => {
                                warn(snapshot, format!("Task subfolder in {location}: {error}"))
                            }
                        }
                    }
                }
                Err(error) => warn(snapshot, format!("Task subfolders in {location}: {error}")),
            }
        }
    }
    Ok(())
}

pub(super) fn set_task_enabled(
    expected: &StartupEntry,
    path: &str,
    enabled: bool,
) -> Result<(), String> {
    let _com = ComScope::new()?;
    let service = service()?;
    // SAFETY: connected local service; GetTask looks up an existing task, SetEnabled changes only its enabled bit.
    unsafe {
        let root = service
            .GetFolder(&BSTR::from("\\"))
            .map_err(|e| e.to_string())?;
        let task = root
            .GetTask(&BSTR::from(path))
            .map_err(|e| format!("Open task {path}: {e}"))?;
        let current = inspect_task(&task)?.ok_or("Task no longer has a boot/logon trigger")?;
        validate_entry(expected, &current)?;
        if current.enabled == enabled {
            return Ok(());
        }
        task.SetEnabled(VARIANT_BOOL::from(enabled))
            .map_err(|e| format!("Change task {path}: {e}"))?;
        if task.Enabled().map_err(|e| e.to_string())?.as_bool() != enabled {
            return Err("Task state changed concurrently; refresh to inspect current state".into());
        }
    }
    Ok(())
}
