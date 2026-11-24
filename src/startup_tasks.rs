//! Thread-local COM access. Never executes/resolves shortcut targets or task actions.

use super::{
    Identity, MAX_ENTRIES, StartupDelay, StartupEntry, StartupSnapshot, id, validate_current_entry,
    validate_entry, warn,
};
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

pub(super) struct ShortcutMetadata {
    pub command: String,
    pub executable: Option<String>,
    pub working_directory: Option<String>,
}

fn shortcut_working_directory(link: &IShellLinkW) -> Result<Option<String>, String> {
    let mut buffer = vec![0u16; 32768];
    // SAFETY: caller owns the live ShellLink in a balanced COM scope; buffer is writable and bounded.
    unsafe { link.GetWorkingDirectory(&mut buffer) }
        .map_err(|error| format!("Не удалось прочитать рабочую папку ярлыка: {error}"))?;
    let directory = buffer_text(&buffer)?;
    Ok((!directory.is_empty()).then_some(directory))
}

pub(super) fn shortcut_metadata(path: &Path) -> Result<ShortcutMetadata, String> {
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
        let executable = crate::icons::executable_path(&target);
        let command = if arguments.is_empty() {
            format!("\"{target}\"")
        } else {
            format!("\"{target}\" {arguments}")
        };
        Ok(ShortcutMetadata {
            command,
            executable,
            working_directory: shortcut_working_directory(&link)?,
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

fn parse_startup_delay(value: &str) -> Option<u32> {
    if value.is_empty() {
        return Some(0);
    }
    let mut bytes = value.strip_prefix('P')?.bytes().peekable();
    let mut seconds = 0u32;
    let mut time = false;
    let mut component = false;
    let mut time_component = false;
    let mut previous_rank = 5;
    while let Some(byte) = bytes.next() {
        if byte == b'T' && !time {
            time = true;
            continue;
        }
        if !byte.is_ascii_digit() {
            return None;
        }
        let mut number = u32::from(byte - b'0');
        while bytes.peek().is_some_and(u8::is_ascii_digit) {
            number = number
                .checked_mul(10)?
                .checked_add(u32::from(bytes.next()? - b'0'))?;
        }
        let (rank, multiplier) = match (time, bytes.next()?) {
            (false, b'D') => (4, 86400),
            (true, b'H') => (3, 3600),
            (true, b'M') => (2, 60),
            (true, b'S') => (1, 1),
            _ => return None,
        };
        if rank >= previous_rank {
            return None;
        }
        seconds = seconds.checked_add(number.checked_mul(multiplier)?)?;
        previous_rank = rank;
        component = true;
        time_component |= time;
    }
    (component && (!time || time_component)).then_some(seconds)
}

fn active_startup_triggers(definition: &ITaskDefinition) -> Result<(bool, Vec<ITrigger>), String> {
    // SAFETY: caller owns this thread's live task definition; collection indices are bounded.
    unsafe {
        let triggers = definition.Triggers().map_err(|e| e.to_string())?;
        let mut count = 0;
        triggers.Count(&mut count).map_err(|e| e.to_string())?;
        let mut startup = false;
        let mut active = Vec::new();
        for index in 1..=bounded_count(count, 128, "Task trigger")? {
            let trigger = triggers.get_Item(index).map_err(|e| e.to_string())?;
            let mut kind = TASK_TRIGGER_TYPE2::default();
            trigger.Type(&mut kind).map_err(|e| e.to_string())?;
            if kind != TASK_TRIGGER_BOOT && kind != TASK_TRIGGER_LOGON {
                continue;
            }
            startup = true;
            let mut enabled = VARIANT_BOOL::default();
            trigger.Enabled(&mut enabled).map_err(|e| e.to_string())?;
            if enabled.as_bool() {
                active.push(trigger);
            }
        }
        Ok((startup, active))
    }
}

fn trigger_delay(trigger: &ITrigger) -> Result<String, String> {
    // SAFETY: a live trigger is queried for its actual type before casting to the derived interface.
    unsafe {
        let mut kind = TASK_TRIGGER_TYPE2::default();
        trigger.Type(&mut kind).map_err(|e| e.to_string())?;
        let mut delay = BSTR::new();
        if kind == TASK_TRIGGER_BOOT {
            trigger
                .cast::<IBootTrigger>()
                .map_err(|e| e.to_string())?
                .Delay(&mut delay)
                .map_err(|e| e.to_string())?;
        } else if kind == TASK_TRIGGER_LOGON {
            trigger
                .cast::<ILogonTrigger>()
                .map_err(|e| e.to_string())?
                .Delay(&mut delay)
                .map_err(|e| e.to_string())?;
        } else {
            return Err("У задания изменился тип триггера; обновите список".into());
        }
        text(delay)
    }
}

fn common_startup_delay(triggers: &[ITrigger]) -> Option<u32> {
    let first = parse_startup_delay(&trigger_delay(triggers.first()?).ok()?)?;
    triggers
        .iter()
        .skip(1)
        .all(|trigger| {
            trigger_delay(trigger)
                .ok()
                .as_deref()
                .and_then(parse_startup_delay)
                == Some(first)
        })
        .then_some(first)
}

fn delay_edit_logon(definition: &ITaskDefinition) -> Result<TASK_LOGON_TYPE, String> {
    // SAFETY: read-only queries of a local, live definition on its COM thread.
    unsafe {
        let mut compatibility = TASK_COMPATIBILITY::default();
        definition
            .Settings()
            .map_err(|e| e.to_string())?
            .Compatibility(&mut compatibility)
            .map_err(|e| e.to_string())?;
        if compatibility.0 < TASK_COMPATIBILITY_V2.0 {
            return Err("Изменение задержки старого формата задания не поддерживается".into());
        }
        let principal = definition.Principal().map_err(|e| e.to_string())?;
        let mut logon = TASK_LOGON_TYPE::default();
        principal.LogonType(&mut logon).map_err(|e| e.to_string())?;
        if !matches!(
            logon,
            TASK_LOGON_INTERACTIVE_TOKEN | TASK_LOGON_GROUP | TASK_LOGON_SERVICE_ACCOUNT
        ) {
            return Err("Нельзя безопасно обновить задание с сохранёнными учётными данными".into());
        }
        let mut account = BSTR::new();
        if logon == TASK_LOGON_GROUP {
            principal.GroupId(&mut account).map_err(|e| e.to_string())?;
        } else {
            principal.UserId(&mut account).map_err(|e| e.to_string())?;
        }
        if text(account)?.is_empty() {
            return Err("У задания не определён контекст запуска".into());
        }
        let triggers = definition.Triggers().map_err(|e| e.to_string())?;
        let mut count = 0;
        triggers.Count(&mut count).map_err(|e| e.to_string())?;
        for index in 1..=bounded_count(count, 128, "Task trigger")? {
            let trigger = triggers.get_Item(index).map_err(|e| e.to_string())?;
            let mut kind = TASK_TRIGGER_TYPE2::default();
            let mut enabled = VARIANT_BOOL::default();
            trigger.Type(&mut kind).map_err(|e| e.to_string())?;
            trigger.Enabled(&mut enabled).map_err(|e| e.to_string())?;
            // IgnoreRegistrationTriggers suppresses registration triggers, but cannot
            // prevent an overdue time/idle/event trigger from firing during an update.
            if enabled.as_bool()
                && !matches!(
                    kind,
                    TASK_TRIGGER_BOOT | TASK_TRIGGER_LOGON | TASK_TRIGGER_REGISTRATION
                )
            {
                return Err(
                    "У задания есть другие активные триггеры; изменение задержки недоступно".into(),
                );
            }
        }
        Ok(logon)
    }
}

fn inspect_task(task: &IRegisteredTask) -> Result<Option<StartupEntry>, String> {
    // SAFETY: task is a live COM interface on this thread. All output parameters are initialized valid storage.
    unsafe {
        let definition = task.Definition().map_err(|e| e.to_string())?;
        let (startup, triggers) = active_startup_triggers(&definition)?;
        let mut count = 0;
        if !startup {
            return Ok(None);
        }
        let active_trigger = !triggers.is_empty();
        let startup_delay = StartupDelay::Task {
            seconds: common_startup_delay(&triggers),
            editable: active_trigger
                && delay_edit_logon(&definition).is_ok()
                && triggers.iter().all(|trigger| {
                    trigger_delay(trigger)
                        .ok()
                        .as_deref()
                        .and_then(parse_startup_delay)
                        .is_some()
                }),
        };
        let actions = definition.Actions().map_err(|e| e.to_string())?;
        actions.Count(&mut count).map_err(|e| e.to_string())?;
        let mut commands = Vec::new();
        let mut executable = None;
        let mut exec_seen = false;
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
                if !exec_seen {
                    executable = crate::icons::executable_path(&path);
                    exec_seen = true;
                }
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
        let identity = Identity::Task {
            path: path.clone(),
            definition: token,
        };
        let icon_index = executable.as_deref().and_then(crate::icons::for_file);
        Ok(Some(StartupEntry {
            id: id(&identity),
            origin: identity.origin(),
            added_at: None,
            startup_delay,
            executable,
            icon_index,
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
    let task = registered_task(path)?;
    // SAFETY: connected local service; GetTask looks up an existing task, SetEnabled changes only its enabled bit.
    unsafe {
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

pub(super) fn set_task_delay(
    expected: &StartupEntry,
    path: &str,
    seconds: u32,
) -> Result<(), String> {
    if !matches!(
        expected.startup_delay,
        StartupDelay::Task { editable: true, .. }
    ) {
        return Err("Изменение задержки этого задания недоступно".into());
    }
    let _com = ComScope::new()?;
    let task = registered_task(path)?;
    let current = inspect_task(&task)?
        .ok_or("У задания больше нет триггеров загрузки или входа; обновите список")?;
    validate_current_entry(expected, &current)?;
    // SAFETY: interfaces belong to this initialized COM thread; only a detached
    // definition's enabled boot/logon Delay properties are edited before TASK_UPDATE.
    unsafe {
        let definition = task.Definition().map_err(|e| e.to_string())?;
        let logon = delay_edit_logon(&definition)?;
        let (_, triggers) = active_startup_triggers(&definition)?;
        if triggers.is_empty()
            || triggers.iter().any(|trigger| {
                trigger_delay(trigger)
                    .ok()
                    .as_deref()
                    .and_then(parse_startup_delay)
                    .is_none()
            })
        {
            return Err("Не удалось безопасно прочитать задержки активных триггеров".into());
        }
        if common_startup_delay(&triggers) == Some(seconds) {
            return Ok(());
        }
        let security = task
            .GetSecurityDescriptor(7)
            .map_err(|e| format!("Не удалось проверить права задания: {e}"))?;
        let enabled = task.Enabled().map_err(|e| e.to_string())?.as_bool();
        let delay = BSTR::from(format!("PT{seconds}S"));
        for trigger in &triggers {
            let mut kind = TASK_TRIGGER_TYPE2::default();
            trigger.Type(&mut kind).map_err(|e| e.to_string())?;
            if kind == TASK_TRIGGER_BOOT {
                trigger
                    .cast::<IBootTrigger>()
                    .map_err(|e| e.to_string())?
                    .SetDelay(&delay)
                    .map_err(|e| e.to_string())?;
            } else if kind == TASK_TRIGGER_LOGON {
                trigger
                    .cast::<ILogonTrigger>()
                    .map_err(|e| e.to_string())?
                    .SetDelay(&delay)
                    .map_err(|e| e.to_string())?;
            } else {
                return Err("У задания изменился тип триггера; обновите список".into());
            }
        }
        // Recheck the persisted fingerprint immediately before writing. Scheduler
        // offers no compare-and-swap API; a concurrent external update can still race.
        let fresh = inspect_task(&task)?.ok_or("Задание изменилось; обновите список")?;
        validate_current_entry(expected, &fresh)?;
        let root = service()?
            .GetFolder(&BSTR::from("\\"))
            .map_err(|e| e.to_string())?;
        let mut flags =
            TASK_UPDATE.0 | TASK_IGNORE_REGISTRATION_TRIGGERS.0 | TASK_DONT_ADD_PRINCIPAL_ACE.0;
        if !enabled {
            flags |= TASK_DISABLE.0;
        }
        let empty = VARIANT::default();
        // MS-TSCH SchRpcRegisterTask: null sddl on UPDATE preserves the complete
        // existing descriptor (including SACL), unlike round-tripping a partial DACL.
        // DONT_ADD_PRINCIPAL_ACE prevents implicit additions/removals of principal ACEs.
        let updated = root
            .RegisterTaskDefinition(
                &BSTR::from(path),
                &definition,
                flags,
                &empty,
                &empty,
                logon,
                &empty,
            )
            .map_err(|e| format!("Не удалось изменить задержку задания: {e}"))?;
        let after = inspect_task(&updated)?.ok_or("Задание изменилось при сохранении")?;
        if after.command != current.command
            || updated.Enabled().map_err(|e| e.to_string())?.as_bool() != enabled
            || !matches!(after.startup_delay, StartupDelay::Task { seconds: Some(value), .. } if value == seconds)
            || updated
                .GetSecurityDescriptor(7)
                .map_err(|e| e.to_string())?
                != security
        {
            return Err("Параметры задания изменились при сохранении; обновите список".into());
        }
    }
    Ok(())
}

fn registered_task(path: &str) -> Result<IRegisteredTask, String> {
    let service = service()?;
    // SAFETY: caller holds the thread's COM scope; lookup is local, read-only, and uses a validated task path.
    unsafe {
        service
            .GetFolder(&BSTR::from("\\"))
            .map_err(|error| format!("Не удалось открыть планировщик заданий: {error}"))?
            .GetTask(&BSTR::from(path))
            .map_err(|error| format!("Не удалось открыть задание {path}: {error}"))
    }
}

pub(super) fn set_task_running(
    expected: &StartupEntry,
    path: &str,
    running: bool,
) -> Result<(), String> {
    let _com = ComScope::new()?;
    let task = registered_task(path)?;
    let current = inspect_task(&task)?
        .ok_or("У задания больше нет триггера загрузки или входа; обновите список")?;
    validate_current_entry(expected, &current)?;
    // SAFETY: same local task interface was reopened and checked on this COM-initialized thread.
    unsafe {
        if running {
            let mut allowed = VARIANT_BOOL::default();
            task.Definition()
                .map_err(|error| error.to_string())?
                .Settings()
                .map_err(|error| error.to_string())?
                .AllowDemandStart(&mut allowed)
                .map_err(|error| error.to_string())?;
            if !allowed.as_bool() {
                return Err("В настройках задания запрещён ручной запуск".into());
            }
            let _instance = task
                .Run(&VARIANT::default())
                .map_err(|error| format!("Не удалось запустить задание {path}: {error}"))?;
            return Ok(());
        }
        if let Some(executable) = current.executable.as_deref() {
            let own = std::env::current_exe()
                .and_then(std::fs::canonicalize)
                .map_err(|error| {
                    format!("Не удалось проверить путь текущего приложения: {error}")
                })?;
            let target = std::fs::canonicalize(executable).map_err(|error| {
                format!("Не удалось проверить исполняемый файл задания: {error}")
            })?;
            if own == target {
                return Err("Остановка текущего приложения через задание запрещена".into());
            }
        }
        let instances = task
            .GetInstances(0)
            .map_err(|error| format!("Не удалось проверить экземпляры задания: {error}"))?;
        let count = bounded_count(
            instances.Count().map_err(|error| error.to_string())?,
            1024,
            "Running task",
        )?;
        if count == 0 {
            return Ok(());
        }
        for index in 1..=count {
            let instance = instances
                .get_Item(&VARIANT::from(index))
                .map_err(|error| error.to_string())?;
            crate::processes::validate_process_stop(
                instance.EnginePID().map_err(|error| error.to_string())?,
            )?;
        }
        // Preserve S_FALSE, which the generated Result<()> wrapper would otherwise accept as success.
        let result = (Interface::vtable(&task).Stop)(Interface::as_raw(&task), 0);
        if result.0 == 1 {
            return Err("Планировщик не разрешил остановить экземпляры этого задания".into());
        }
        result
            .ok()
            .map_err(|error| format!("Не удалось остановить задание {path}: {error}"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_delay_parser_accepts_seconds_minutes_hours_and_days() {
        for (input, expected) in [
            ("", 0),
            ("PT0S", 0),
            ("PT90S", 90),
            ("PT1M", 60),
            ("PT2H3M4S", 7384),
            ("P1DT2H", 93600),
            ("P31D", 31 * 86400),
            ("P32D", 32 * 86400),
            ("PT4294967295S", u32::MAX),
        ] {
            assert_eq!(parse_startup_delay(input), Some(expected), "{input}");
        }
    }

    #[test]
    fn startup_delay_parser_rejects_ambiguous_or_unbounded_durations() {
        for input in [
            "P",
            "PT",
            "P1M",
            "P1Y",
            "P1W",
            "-PT1S",
            "PT-1S",
            "PT1.5S",
            "PT1S1M",
            "PT1M1M",
            "PT4294967296S",
            "P49711DT23296S",
            "PT999999999999999999999999999999S",
            " PT1S",
            "PT1S ",
            "P1DT",
        ] {
            assert_eq!(parse_startup_delay(input), None, "{input}");
        }
    }

    fn delay_fixture(service: &ITaskService) -> ITaskDefinition {
        // No task is registered here. The executable is inert unless a caller
        // explicitly registers/enables/runs this definition; this fixture stays disabled.
        let xml = r#"<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
          <Triggers>
            <LogonTrigger id="active"><Repetition><Interval>PT10M</Interval><Duration>PT1H</Duration><StopAtDurationEnd>true</StopAtDurationEnd></Repetition><StartBoundary>2100-01-01T00:00:00</StartBoundary><EndBoundary>2100-12-31T00:00:00</EndBoundary><Enabled>true</Enabled><Delay>PT1M</Delay></LogonTrigger>
            <LogonTrigger id="inactive"><Enabled>false</Enabled><Delay>PT7M</Delay></LogonTrigger>
            <TimeTrigger id="other"><StartBoundary>2100-01-01T00:00:00</StartBoundary><Enabled>false</Enabled><RandomDelay>PT2M</RandomDelay></TimeTrigger>
            <RegistrationTrigger id="registration"><Enabled>true</Enabled><Delay>PT5S</Delay></RegistrationTrigger>
            <BootTrigger id="boot"><StartBoundary>2100-01-01T00:00:00</StartBoundary><Enabled>true</Enabled><Delay>PT1M</Delay></BootTrigger>
          </Triggers>
          <Principals><Principal id="Author"><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
          <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>true</StopIfGoingOnBatteries><RunOnlyIfNetworkAvailable>true</RunOnlyIfNetworkAvailable><Enabled>false</Enabled><ExecutionTimeLimit>PT4M</ExecutionTimeLimit><Priority>7</Priority></Settings>
          <Actions Context="Author"><Exec><Command>cmd.exe</Command><Arguments>/c exit /b 0</Arguments><WorkingDirectory>C:\Windows</WorkingDirectory></Exec></Actions>
        </Task>"#;
        // SAFETY: this test holds ComScope; only an unregistered in-memory definition is created.
        unsafe {
            let definition = service.NewTask(0).unwrap();
            definition.SetXmlText(&BSTR::from(xml)).unwrap();
            definition
        }
    }

    #[test]
    fn startup_delay_reads_only_enabled_startup_triggers_and_rejects_unsafe_updates() {
        let _com = ComScope::new().unwrap();
        let definition = delay_fixture(&service().unwrap());
        let (has_startup, active) = active_startup_triggers(&definition).unwrap();
        assert!(has_startup);
        assert_eq!(active.len(), 2);
        assert_eq!(common_startup_delay(&active), Some(60));
        // SAFETY: this definition is unregistered; none of the fixture properties cause execution.
        unsafe {
            let principal = definition.Principal().unwrap();
            principal.SetUserId(&BSTR::from("S-1-5-18")).unwrap();
            assert!(delay_edit_logon(&definition).is_ok());
            principal.SetLogonType(TASK_LOGON_PASSWORD).unwrap();
            assert!(delay_edit_logon(&definition).is_err());
            principal
                .SetLogonType(TASK_LOGON_INTERACTIVE_TOKEN)
                .unwrap();
            let triggers = definition.Triggers().unwrap();
            triggers
                .get_Item(3)
                .unwrap()
                .SetEnabled(VARIANT_BOOL::from(true))
                .unwrap();
            assert!(delay_edit_logon(&definition).is_err());
            triggers
                .get_Item(3)
                .unwrap()
                .SetEnabled(VARIANT_BOOL::from(false))
                .unwrap();
            triggers
                .get_Item(2)
                .unwrap()
                .SetEnabled(VARIANT_BOOL::from(true))
                .unwrap();
            let (_, active) = active_startup_triggers(&definition).unwrap();
            assert_eq!(common_startup_delay(&active), None);
            assert!(
                delay_edit_logon(&definition).is_ok(),
                "different valid delays may be normalized together"
            );
        }
    }

    #[test]
    #[ignore = "Registers and deletes only an isolated disabled disposable task; explicit native smoke"]
    fn native_startup_delay_preserves_definition_acl_and_rejects_stale_snapshot() {
        struct TemporaryTask {
            folder: ITaskFolder,
            name: BSTR,
        }
        impl Drop for TemporaryTask {
            fn drop(&mut self) {
                // SAFETY: the exact unique task created by this test is deleted on the same COM thread.
                unsafe {
                    self.folder
                        .DeleteTask(&self.name, 0)
                        .expect("delete disposable task")
                };
            }
        }
        fn xml(definition: &ITaskDefinition) -> String {
            let mut value = BSTR::new();
            // SAFETY: valid live in-memory task definition with initialized output storage.
            unsafe { definition.XmlText(&mut value).unwrap() };
            text(value).unwrap()
        }
        let _com = ComScope::new().unwrap();
        let service = service().unwrap();
        let definition = delay_fixture(&service);
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let name = BSTR::from(format!(
            "AnVirNext-Delay-Fixture-{}-{unique}",
            std::process::id()
        ));
        // SAFETY: creation uses a unique test-owned name and a disabled definition.
        // Registration triggers are explicitly suppressed; no task is run by this test.
        let task = unsafe {
            let folder = service.GetFolder(&BSTR::from("\\")).unwrap();
            let empty = VARIANT::default();
            let task = folder
                .RegisterTaskDefinition(
                    &name,
                    &definition,
                    TASK_CREATE.0 | TASK_DISABLE.0 | TASK_IGNORE_REGISTRATION_TRIGGERS.0,
                    &empty,
                    &empty,
                    TASK_LOGON_INTERACTIVE_TOKEN,
                    &empty,
                )
                .unwrap();
            (task, TemporaryTask { folder, name })
        };
        let (task, _cleanup) = task;
        let entry = inspect_task(&task).unwrap().unwrap();
        let path = entry.location.clone();
        assert!(matches!(
            entry.startup_delay,
            StartupDelay::Task {
                seconds: Some(60),
                editable: true
            }
        ));
        // SAFETY: read-only queries of this test's registered disabled task.
        let (before_xml, before_security, before_last_run) = unsafe {
            (
                xml(&task.Definition().unwrap()),
                task.GetSecurityDescriptor(7).unwrap(),
                task.LastRunTime().unwrap(),
            )
        };
        set_task_delay(&entry, &path, 125).unwrap();
        let updated = registered_task(&path).unwrap();
        let current = inspect_task(&updated).unwrap().unwrap();
        assert!(matches!(
            current.startup_delay,
            StartupDelay::Task {
                seconds: Some(125),
                editable: true
            }
        ));
        assert!(!current.enabled);
        assert!(
            set_task_delay(&entry, &path, 20).is_err(),
            "old definition fingerprint must be rejected"
        );
        // SAFETY: read-only checks on the same unique disabled task; no foreign task is touched.
        unsafe {
            assert!(
                updated.GetSecurityDescriptor(7).unwrap() == before_security,
                "task owner/group/DACL must be preserved"
            );
            assert_eq!(updated.LastRunTime().unwrap(), before_last_run);
            let after_xml = xml(&updated.Definition().unwrap());
            assert!(
                after_xml
                    .replace("PT2M5S", "PT1M")
                    .replace("PT125S", "PT1M")
                    == before_xml,
                "only the active Boot/Logon Delay properties may change"
            );
        }
        set_task_delay(&current, &path, 0).unwrap();
        let immediate = registered_task(&path).unwrap();
        let current = inspect_task(&immediate).unwrap().unwrap();
        assert!(matches!(
            current.startup_delay,
            StartupDelay::Task {
                seconds: Some(0),
                editable: true
            }
        ));
        assert!(!current.enabled);
        // SAFETY: these final read-only checks refer only to the same disposable task.
        unsafe {
            assert!(!immediate.Enabled().unwrap().as_bool());
            assert!(
                immediate.GetSecurityDescriptor(7).unwrap() == before_security,
                "task owner/group/DACL must be preserved at zero delay"
            );
            assert_eq!(immediate.LastRunTime().unwrap(), before_last_run);
            // Scheduler omits zero-valued Delay nodes from its canonical XML.
            // Only these two active fixture triggers originally use PT1M.
            let without_delay = |value: &str, delay: &str| {
                value
                    .lines()
                    .filter(|line| line.trim() != delay)
                    .collect::<Vec<_>>()
                    .join("\n")
            };
            assert!(
                without_delay(
                    &xml(&immediate.Definition().unwrap()),
                    "<Delay>PT0S</Delay>"
                ) == without_delay(&before_xml, "<Delay>PT1M</Delay>"),
                "zero delay must retain all other task properties"
            );
        }
    }

    #[test]
    fn reads_target_and_arguments_from_an_isolated_shortcut_without_resolving_or_launching() {
        struct Temporary(PathBuf);
        impl Drop for Temporary {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.0);
            }
        }
        let _com = ComScope::new().unwrap();
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let temporary = Temporary(std::env::temp_dir().join(format!(
            "anvir-icon-shortcut-{}-{suffix}.lnk",
            std::process::id()
        )));
        let target = std::env::current_exe().unwrap();
        let arguments = "--this-is-never-executed \"argument with spaces\" --literal=%VARIABLE%";
        let working_directory = r"%TEMP%\AnVir start-in fixture";
        // SAFETY: balanced COM scope, local system ShellLink object, fixture path
        // in the temporary directory. Save writes a link; no Resolve/execute call.
        unsafe {
            let link: IShellLinkW =
                CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER).unwrap();
            link.SetPath(PCWSTR(os_wide(target.as_os_str()).as_ptr()))
                .unwrap();
            link.SetArguments(PCWSTR(crate::win::wide(arguments).as_ptr()))
                .unwrap();
            link.SetWorkingDirectory(PCWSTR(crate::win::wide(working_directory).as_ptr()))
                .unwrap();
            let file: IPersistFile = link.cast().unwrap();
            file.Save(PCWSTR(os_wide(temporary.0.as_os_str()).as_ptr()), true)
                .unwrap();
        }
        let metadata = shortcut_metadata(&temporary.0).unwrap();
        assert_eq!(
            metadata.command,
            format!("\"{}\" {arguments}", target.display())
        );
        assert_eq!(metadata.executable.as_deref(), target.to_str());
        assert_eq!(
            metadata.working_directory.as_deref(),
            Some(working_directory)
        );
        let program = super::super::folder_program_entry(
            false,
            &temporary.0,
            &mut StartupSnapshot::default(),
        )
        .unwrap();
        assert_eq!(program.entry.command, metadata.command);
        assert_eq!(
            program.working_directory.as_deref(),
            Some(working_directory)
        );
        assert!(
            !program.expand_environment,
            "shortcut arguments must retain literal percent variables"
        );
        assert!(
            metadata
                .executable
                .as_deref()
                .and_then(crate::icons::for_file)
                .is_some()
        );
    }
}
