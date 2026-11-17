//! Native Windows startup inventory and explicit, reversible controls.

use crate::win::{Handle, os_wide, wide};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    fs, io, mem,
    os::windows::fs::MetadataExt,
    path::{Component, Path},
    ptr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{
        ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS, ERROR_PATH_NOT_FOUND, FILETIME,
        HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT,
    },
    Storage::FileSystem::{
        FILE_NOTIFY_CHANGE_DIR_NAME, FILE_NOTIFY_CHANGE_FILE_NAME, FILE_NOTIFY_CHANGE_LAST_WRITE,
        FindCloseChangeNotification, FindFirstChangeNotificationW,
    },
    System::{
        Registry::*,
        Services::*,
        SystemInformation::GetSystemTimeAsFileTime,
        Threading::{CreateEventW, WaitForMultipleObjects},
    },
};

#[path = "startup_tasks.rs"]
mod tasks;

const CURRENT_VERSION: &str = r"Software\Microsoft\Windows\CurrentVersion";
const MAX_VALUE_BYTES: usize = 64 * 1024;
const MAX_ENTRIES: usize = 8192;
const MAX_WARNINGS: usize = 128;
static MUTATION_LOCK: Mutex<()> = Mutex::new(());
static WATCHER_DEGRADED: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Debug)]
pub struct StartupEntry {
    pub id: String,
    pub name: String,
    pub source: String,
    pub location: String,
    pub command: String,
    pub enabled: bool,
    pub can_toggle: bool,
}

#[derive(Clone, Debug, Default)]
pub struct StartupSnapshot {
    pub entries: Vec<StartupEntry>,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum Identity {
    Run {
        machine: bool,
        view32: bool,
        once: bool,
        name: String,
    },
    Folder {
        common: bool,
        name: String,
        size: u64,
        modified: u64,
    },
    Task {
        path: String,
        definition: String,
    },
    Service {
        name: String,
    },
}

fn parse_id(id: &str) -> Result<Identity, String> {
    if id.len() > MAX_VALUE_BYTES {
        return Err("Startup identity is too large".into());
    }
    let identity: Identity = serde_json::from_str(id).map_err(|_| "Invalid startup identity")?;
    let valid = match &identity {
        Identity::Run {
            machine,
            view32,
            name,
            ..
        } => (*machine || !view32) && name.len() <= 32767 && !name.contains('\0'),
        Identity::Folder { name, .. } => {
            !name.is_empty()
                && !name.contains(['\0', '\\', '/', ':'])
                && matches!(
                    (
                        Path::new(name).components().next(),
                        Path::new(name).components().nth(1)
                    ),
                    (Some(Component::Normal(_)), None)
                )
        }
        Identity::Task { path, definition } => {
            path.starts_with('\\')
                && !path.contains('\0')
                && path.len() <= 32767
                && definition.len() <= 256
        }
        Identity::Service { name } => !name.is_empty() && !name.contains(['\0', '\\', '/']),
    };
    if !valid {
        return Err("Unsafe startup identity".into());
    }
    Ok(identity)
}

fn approved_enabled(bytes: Option<&[u8]>) -> Result<bool, String> {
    let Some(bytes) = bytes else {
        return Ok(true);
    };
    if bytes.len() < 12 || bytes[1..4] != [0, 0, 0] {
        return Err("Malformed StartupApproved record; control is unavailable".into());
    }
    match bytes[0] {
        2 | 6 => Ok(true),
        3 | 7 => Ok(false),
        _ => Err(format!(
            "Unknown StartupApproved state {}; control is unavailable",
            bytes[0]
        )),
    }
}

fn approved_data(
    previous: Option<&[u8]>,
    enabled: bool,
    timestamp: u64,
) -> Result<Vec<u8>, String> {
    approved_enabled(previous)?;
    let mut bytes = previous.map_or_else(|| vec![0; 12], <[u8]>::to_vec);
    bytes[0] = if enabled { 2 } else { 3 };
    if !enabled {
        bytes[4..12].copy_from_slice(&timestamp.to_le_bytes());
    }
    Ok(bytes)
}

fn validate_entry(expected: &StartupEntry, current: &StartupEntry) -> Result<(), String> {
    if !expected.can_toggle || !current.can_toggle {
        return Err("This startup source is read-only".into());
    }
    if expected.id != current.id
        || expected.command != current.command
        || expected.enabled != current.enabled
    {
        return Err("Startup entry changed or was replaced; refresh before changing it".into());
    }
    Ok(())
}

fn id(identity: &Identity) -> String {
    serde_json::to_string(identity).expect("startup identity serializes")
}
fn win_error(context: &str, code: u32) -> String {
    format!(
        "{context}: {} (Win32 {code})",
        io::Error::from_raw_os_error(code as i32)
    )
}
fn warn(snapshot: &mut StartupSnapshot, message: impl Into<String>) {
    if snapshot.warnings.len() < MAX_WARNINGS {
        snapshot.warnings.push(message.into());
    }
}

struct Key(HKEY);
impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: Key owns an opened/created key, never a predefined root handle.
        unsafe {
            RegCloseKey(self.0);
        }
    }
}

fn root(machine: bool) -> HKEY {
    if machine {
        HKEY_LOCAL_MACHINE
    } else {
        HKEY_CURRENT_USER
    }
}
fn view(view32: bool) -> u32 {
    if view32 {
        KEY_WOW64_32KEY
    } else {
        KEY_WOW64_64KEY
    }
}
fn open_key(machine: bool, path: &str, view32: bool, access: u32) -> Result<Option<Key>, String> {
    let mut key = ptr::null_mut();
    // SAFETY: path is NUL-terminated and output points to valid storage.
    let result = unsafe {
        RegOpenKeyExW(
            root(machine),
            wide(path).as_ptr(),
            0,
            access | view(view32),
            &mut key,
        )
    };
    match result {
        0 => Ok(Some(Key(key))),
        ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => Ok(None),
        code => Err(win_error(
            &format!("{}\\{path}", if machine { "HKLM" } else { "HKCU" }),
            code,
        )),
    }
}

fn create_key(machine: bool, path: &str, access: u32) -> Result<Key, String> {
    let mut key = ptr::null_mut();
    // SAFETY: native-view registry path and output pointers are valid; no inherited ACL changes.
    let result = unsafe {
        RegCreateKeyExW(
            root(machine),
            wide(path).as_ptr(),
            0,
            ptr::null(),
            0,
            access | KEY_WOW64_64KEY,
            ptr::null(),
            &mut key,
            ptr::null_mut(),
        )
    };
    if result != 0 {
        return Err(win_error("Create startup registry key", result));
    }
    Ok(Key(key))
}

fn read_value(key: &Key, name: &str) -> Result<Option<(u32, Vec<u8>)>, String> {
    let mut size = 0;
    let mut kind = 0;
    let name = wide(name);
    // SAFETY: this is a size query; all non-null pointers reference valid storage.
    let result = unsafe {
        RegQueryValueExW(
            key.0,
            name.as_ptr(),
            ptr::null(),
            &mut kind,
            ptr::null_mut(),
            &mut size,
        )
    };
    if result == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    if result != 0 {
        return Err(win_error("Read startup value size", result));
    }
    for _ in 0..3 {
        if size as usize > MAX_VALUE_BYTES {
            return Err("Startup value exceeds 64 KiB; skipped".into());
        }
        let mut data = vec![0; size as usize];
        let mut actual = size;
        // SAFETY: data has the advertised capacity, name and output pointers are valid.
        let result = unsafe {
            RegQueryValueExW(
                key.0,
                name.as_ptr(),
                ptr::null(),
                &mut kind,
                data.as_mut_ptr(),
                &mut actual,
            )
        };
        if result == ERROR_MORE_DATA {
            size = actual;
            continue;
        }
        if result == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        if result != 0 {
            return Err(win_error("Read startup value", result));
        }
        data.truncate(actual as usize);
        return Ok(Some((kind, data)));
    }
    Err("Startup value is changing; refresh and retry".into())
}

fn registry_text(kind: u32, data: &[u8]) -> Result<String, String> {
    if !matches!(kind, REG_SZ | REG_EXPAND_SZ) || data.len() % 2 != 0 {
        return Err("Startup command is not a valid registry string".into());
    }
    let words: Vec<u16> = data
        .chunks_exact(2)
        .map(|x| u16::from_le_bytes([x[0], x[1]]))
        .collect();
    let words = words.strip_suffix(&[0]).unwrap_or(&words);
    if words.contains(&0) {
        return Err("Startup command contains an embedded NUL".into());
    }
    String::from_utf16(words).map_err(|_| "Startup command contains invalid UTF-16".into())
}

fn run_path(once: bool) -> String {
    format!(
        r"{CURRENT_VERSION}\{}",
        if once { "RunOnce" } else { "Run" }
    )
}
fn approval_path(group: &str) -> String {
    format!(r"{CURRENT_VERSION}\Explorer\StartupApproved\{group}")
}
fn approval_group(view32: bool) -> &'static str {
    if view32 { "Run32" } else { "Run" }
}

fn read_approval(machine: bool, group: &str, name: &str) -> Result<Option<Vec<u8>>, String> {
    let Some(key) = open_key(machine, &approval_path(group), false, KEY_QUERY_VALUE)? else {
        return Ok(None);
    };
    read_approval_value(&key, name)
}

fn read_approval_value(key: &Key, name: &str) -> Result<Option<Vec<u8>>, String> {
    let Some((kind, data)) = read_value(key, name)? else {
        return Ok(None);
    };
    if kind != REG_BINARY {
        return Err("StartupApproved value has an unexpected registry type".into());
    }
    Ok(Some(data))
}

fn approval_state(
    snapshot: &mut StartupSnapshot,
    machine: bool,
    group: &str,
    name: &str,
) -> (bool, bool) {
    match read_approval(machine, group, name).and_then(|data| approved_enabled(data.as_deref())) {
        Ok(enabled) => (enabled, true),
        Err(error) => {
            warn(snapshot, format!("{name}: {error}"));
            (false, false)
        }
    }
}

fn run_entry(
    machine: bool,
    view32: bool,
    once: bool,
    name: &str,
    snapshot: &mut StartupSnapshot,
) -> Result<Option<StartupEntry>, String> {
    let path = run_path(once);
    let Some(key) = open_key(machine, &path, view32, KEY_QUERY_VALUE)? else {
        return Ok(None);
    };
    let Some((kind, bytes)) = read_value(&key, name)? else {
        return Ok(None);
    };
    let command = registry_text(kind, &bytes)?;
    let (enabled, can_toggle) = if once {
        (true, false)
    } else {
        approval_state(snapshot, machine, approval_group(view32), name)
    };
    Ok(Some(StartupEntry {
        id: id(&Identity::Run {
            machine,
            view32,
            once,
            name: name.into(),
        }),
        name: if name.is_empty() {
            "(Default)".into()
        } else {
            name.into()
        },
        source: format!(
            "Registry {} {}{}",
            if once { "RunOnce" } else { "Run" },
            if view32 { "32-bit" } else { "64-bit" },
            if !once && !can_toggle {
                " (status unknown)"
            } else {
                ""
            }
        ),
        location: format!("{}\\{path}", if machine { "HKLM" } else { "HKCU" }),
        command,
        enabled,
        can_toggle,
    }))
}

fn scan_registry(snapshot: &mut StartupSnapshot) {
    for machine in [false, true] {
        // HKCU\Software is shared between views on x64 Windows. Enumerate once to avoid duplicate controls.
        for view32 in [false, true].into_iter().filter(|x| machine || !x) {
            for once in [false, true] {
                let path = run_path(once);
                let key = match open_key(machine, &path, view32, KEY_QUERY_VALUE) {
                    Ok(Some(key)) => key,
                    Ok(None) => continue,
                    Err(error) => {
                        warn(snapshot, error);
                        continue;
                    }
                };
                let mut name = vec![0u16; 32768];
                for index in 0..MAX_ENTRIES as u32 {
                    let mut length = name.len() as u32;
                    // SAFETY: name is a sufficiently sized writable UTF-16 buffer; optional outputs are null.
                    let result = unsafe {
                        RegEnumValueW(
                            key.0,
                            index,
                            name.as_mut_ptr(),
                            &mut length,
                            ptr::null(),
                            ptr::null_mut(),
                            ptr::null_mut(),
                            ptr::null_mut(),
                        )
                    };
                    if result == ERROR_NO_MORE_ITEMS {
                        break;
                    }
                    if result != 0 {
                        warn(snapshot, win_error(&format!("Enumerate {path}"), result));
                        break;
                    }
                    let name = match String::from_utf16(&name[..length as usize]) {
                        Ok(name) => name,
                        Err(_) => {
                            warn(snapshot, format!("{path}: invalid UTF-16 value name"));
                            continue;
                        }
                    };
                    match run_entry(machine, view32, once, &name, snapshot) {
                        Ok(Some(entry)) => snapshot.entries.push(entry),
                        Ok(None) => {}
                        Err(error) => warn(snapshot, format!("{path}\\{name}: {error}")),
                    }
                    if snapshot.entries.len() >= MAX_ENTRIES {
                        warn(
                            snapshot,
                            "Startup inventory entry limit reached; results are incomplete",
                        );
                        return;
                    }
                    if index + 1 == MAX_ENTRIES as u32 {
                        warn(
                            snapshot,
                            format!("{path}: registry enumeration limit reached"),
                        );
                    }
                }
            }
        }
    }
}

fn folder_entry(
    common: bool,
    path: &Path,
    snapshot: &mut StartupSnapshot,
) -> Result<StartupEntry, String> {
    let metadata = fs::symlink_metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if metadata.is_dir() || metadata.file_attributes() & 0x400 != 0 {
        return Err(format!(
            "{}: directory/reparse entries are read-only and excluded",
            path.display()
        ));
    }
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("Startup filename is not valid Unicode")?
        .to_string();
    let command = if path
        .extension()
        .is_some_and(|x| x.eq_ignore_ascii_case("lnk"))
    {
        tasks::shortcut_command(path)?
    } else {
        format!("\"{}\"", path.display())
    };
    let (enabled, can_toggle) = approval_state(snapshot, common, "StartupFolder", &name);
    Ok(StartupEntry {
        id: id(&Identity::Folder {
            common,
            name: name.clone(),
            size: metadata.file_size(),
            modified: metadata.last_write_time(),
        }),
        name,
        source: format!(
            "Startup folder ({}){}",
            if common { "all users" } else { "current user" },
            if can_toggle { "" } else { " (status unknown)" }
        ),
        location: path.display().to_string(),
        command,
        enabled,
        can_toggle,
    })
}

fn scan_folders(snapshot: &mut StartupSnapshot) {
    if snapshot.entries.len() >= MAX_ENTRIES {
        return;
    }
    for common in [false, true] {
        let folder = match tasks::startup_folder(common) {
            Ok(path) => path,
            Err(error) => {
                warn(snapshot, error);
                continue;
            }
        };
        let entries = match fs::read_dir(&folder) {
            Ok(entries) => entries,
            Err(error) => {
                warn(snapshot, format!("{}: {error}", folder.display()));
                continue;
            }
        };
        for item in entries.take(MAX_ENTRIES) {
            let item = match item {
                Ok(item) => item,
                Err(error) => {
                    warn(snapshot, format!("{}: {error}", folder.display()));
                    continue;
                }
            };
            if item.file_name().eq_ignore_ascii_case("desktop.ini") {
                continue;
            }
            match folder_entry(common, &item.path(), snapshot) {
                Ok(entry) => snapshot.entries.push(entry),
                Err(error) => warn(snapshot, error),
            }
            if snapshot.entries.len() >= MAX_ENTRIES {
                warn(
                    snapshot,
                    "Startup inventory entry limit reached; results are incomplete",
                );
                return;
            }
        }
    }
}

/// Full on-demand inventory. Tasks and services are intentionally never polled by the watcher.
pub fn scan() -> StartupSnapshot {
    let mut snapshot = StartupSnapshot::default();
    scan_registry(&mut snapshot);
    match tasks::ComScope::new() {
        Ok(_com) => {
            scan_folders(&mut snapshot);
            tasks::scan_tasks(&mut snapshot);
        }
        Err(error) => warn(&mut snapshot, error),
    }
    scan_services(&mut snapshot);
    if WATCHER_DEGRADED.load(Ordering::Acquire) {
        warn(
            &mut snapshot,
            "Some startup change notifications are unavailable; refresh manually to check those locations",
        );
    }
    snapshot
        .entries
        .sort_by(|a, b| a.source.cmp(&b.source).then_with(|| a.name.cmp(&b.name)));
    snapshot
}

fn write_approval(
    machine: bool,
    group: &str,
    name: &str,
    enabled: bool,
    expected: bool,
) -> Result<(), String> {
    let mut now = FILETIME::default();
    // SAFETY: now points to valid FILETIME storage.
    unsafe {
        GetSystemTimeAsFileTime(&mut now);
    }
    let key = create_key(
        machine,
        &approval_path(group),
        KEY_QUERY_VALUE | KEY_SET_VALUE,
    )?;
    update_approval_value(
        &key,
        name,
        enabled,
        expected,
        (u64::from(now.dwHighDateTime) << 32) | u64::from(now.dwLowDateTime),
    )
}

fn update_approval_value(
    key: &Key,
    name: &str,
    enabled: bool,
    expected: bool,
    timestamp: u64,
) -> Result<(), String> {
    let previous = read_approval_value(key, name)?;
    if approved_enabled(previous.as_deref())? != expected {
        return Err("Startup approval changed; refresh before changing it".into());
    }
    let bytes = approved_data(previous.as_deref(), enabled, timestamp)?;
    // SAFETY: key has write access; UTF-16 name and bounded binary data are valid.
    let result = unsafe {
        RegSetValueExW(
            key.0,
            wide(name).as_ptr(),
            0,
            REG_BINARY,
            bytes.as_ptr(),
            bytes.len() as u32,
        )
    };
    if result != 0 {
        return Err(win_error("Update startup approval", result));
    }
    let actual = read_approval_value(key, name)?;
    if actual.as_deref() != Some(&bytes) {
        return Err(
            "Startup approval changed concurrently; refresh to inspect current state".into(),
        );
    }
    Ok(())
}

/// Only explicit UI actions should call this. No command, task action or service is started.
pub fn set_enabled(entry: &StartupEntry, enabled: bool) -> Result<(), String> {
    let _guard = MUTATION_LOCK
        .lock()
        .map_err(|_| "Startup mutation lock was poisoned")?;
    if !entry.can_toggle {
        return Err("This startup source is read-only".into());
    }
    match parse_id(&entry.id)? {
        Identity::Run {
            machine,
            view32,
            once,
            name,
        } => {
            if once {
                return Err("RunOnce does not support StartupApproved; entry is read-only".into());
            }
            let current = run_entry(
                machine,
                view32,
                once,
                &name,
                &mut StartupSnapshot::default(),
            )?
            .ok_or("Startup entry no longer exists")?;
            validate_entry(entry, &current)?;
            if current.enabled == enabled {
                return Ok(());
            }
            write_approval(
                machine,
                approval_group(view32),
                &name,
                enabled,
                current.enabled,
            )
        }
        Identity::Folder { common, name, .. } => {
            let _com = tasks::ComScope::new()?;
            let path = tasks::startup_folder(common)?.join(&name);
            let current = folder_entry(common, &path, &mut StartupSnapshot::default())?;
            validate_entry(entry, &current)?;
            if current.enabled == enabled {
                return Ok(());
            }
            write_approval(common, "StartupFolder", &name, enabled, current.enabled)
        }
        Identity::Task { path, .. } => tasks::set_task_enabled(entry, &path, enabled),
        Identity::Service { .. } => {
            Err("Services are inventory-only; use Windows Services to change startup type".into())
        }
    }
}

fn self_command() -> Result<String, String> {
    let executable =
        std::env::current_exe().map_err(|e| format!("Get application executable: {e}"))?;
    let executable = executable
        .to_str()
        .ok_or("Application path is not valid Unicode")?;
    if executable.contains(['\0', '"']) {
        return Err("Application path cannot be safely quoted".into());
    }
    Ok(format!("\"{executable}\" --start-hidden"))
}

pub fn self_autostart_enabled() -> bool {
    let Ok(expected) = self_command() else {
        return false;
    };
    let Ok(Some(current)) = run_entry(
        false,
        false,
        false,
        "AnVirNext",
        &mut StartupSnapshot::default(),
    ) else {
        return false;
    };
    current.command == expected && current.enabled && current.can_toggle
}

/// Owns only HKCU Run\AnVirNext. Disabling preserves the command with StartupApproved.
pub fn set_self_autostart(enabled: bool) -> Result<(), String> {
    let _guard = MUTATION_LOCK
        .lock()
        .map_err(|_| "Startup mutation lock was poisoned")?;
    let expected = self_command()?;
    let existing = run_entry(
        false,
        false,
        false,
        "AnVirNext",
        &mut StartupSnapshot::default(),
    )?;
    if let Some(existing) = &existing {
        if existing.command != expected {
            return Err(
                "HKCU Run\\AnVirNext belongs to a different command; refusing to overwrite it"
                    .into(),
            );
        }
        if !existing.can_toggle {
            return Err("AnVirNext has an unreadable/unknown StartupApproved state".into());
        }
    } else {
        if !enabled {
            return Ok(());
        }
        // Validate approval before writing any startup command.
        approved_enabled(read_approval(false, "Run", "AnVirNext")?.as_deref())?;
        let key = create_key(false, &run_path(false), KEY_SET_VALUE)?;
        let words = wide(&expected);
        // SAFETY: words is a complete NUL-terminated UTF-16 registry string.
        let result = unsafe {
            RegSetValueExW(
                key.0,
                wide("AnVirNext").as_ptr(),
                0,
                REG_SZ,
                words.as_ptr().cast(),
                (words.len() * 2) as u32,
            )
        };
        if result != 0 {
            return Err(win_error("Enable AnVirNext at logon", result));
        }
    }
    let previous_enabled = match existing {
        Some(entry) => entry.enabled,
        None => approved_enabled(read_approval(false, "Run", "AnVirNext")?.as_deref())?,
    };
    write_approval(false, "Run", "AnVirNext", enabled, previous_enabled)
}

struct ServiceHandle(SC_HANDLE);
impl Drop for ServiceHandle {
    fn drop(&mut self) {
        // SAFETY: ServiceHandle owns a successful SCM/service open handle.
        unsafe {
            CloseServiceHandle(self.0);
        }
    }
}

/// Copy a NUL-terminated string whose allocation is owned by the currently live SCM output buffer.
unsafe fn service_text(text: *const u16) -> Result<String, String> {
    if text.is_null() {
        return Ok(String::new());
    }
    let mut length = 0;
    // SAFETY: callers pass documented NUL-terminated string fields in live SCM buffers.
    unsafe {
        while length < 32768 && *text.add(length) != 0 {
            length += 1;
        }
        if length == 32768 {
            return Err("Service string exceeds 32 KiB".into());
        }
        String::from_utf16(std::slice::from_raw_parts(text, length))
            .map_err(|_| "Service string contains invalid UTF-16".into())
    }
}

fn scan_services(snapshot: &mut StartupSnapshot) {
    if let Err(error) = scan_services_inner(snapshot) {
        warn(snapshot, error);
    }
}

fn scan_services_inner(snapshot: &mut StartupSnapshot) -> Result<(), String> {
    // SAFETY: null machine/database select the local active service database with read-only rights.
    let manager = unsafe {
        OpenSCManagerW(
            ptr::null(),
            ptr::null(),
            SC_MANAGER_ENUMERATE_SERVICE | SC_MANAGER_CONNECT,
        )
    };
    if manager.is_null() {
        return Err(format!(
            "Open local services: {}",
            io::Error::last_os_error()
        ));
    }
    let manager = ServiceHandle(manager);
    // usize storage keeps all returned structs and embedded pointers naturally aligned.
    let mut buffer = vec![0usize; 256 * 1024 / mem::size_of::<usize>()];
    let mut resume = 0;
    let mut seen = 0usize;
    loop {
        let mut needed = 0;
        let mut count = 0;
        // SAFETY: buffer is aligned, writable and sized in bytes; all outputs reference live storage.
        let success = unsafe {
            EnumServicesStatusExW(
                manager.0,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32,
                SERVICE_STATE_ALL,
                buffer.as_mut_ptr().cast(),
                (buffer.len() * mem::size_of::<usize>()) as u32,
                &mut needed,
                &mut count,
                &mut resume,
                ptr::null(),
            )
        };
        let error = if success == 0 {
            io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32
        } else {
            0
        };
        if success == 0 && error != ERROR_MORE_DATA {
            return Err(win_error("Enumerate local services", error));
        }
        if count as usize
            > buffer.len() * mem::size_of::<usize>()
                / mem::size_of::<ENUM_SERVICE_STATUS_PROCESSW>()
        {
            return Err("Invalid service enumeration response".into());
        }
        // SAFETY: successful/partial EnumServicesStatusExW initialized exactly count records inside the aligned buffer.
        let services = unsafe {
            std::slice::from_raw_parts(
                buffer.as_ptr().cast::<ENUM_SERVICE_STATUS_PROCESSW>(),
                count as usize,
            )
        };
        for service in services {
            seen += 1;
            if seen > MAX_ENTRIES || snapshot.entries.len() >= MAX_ENTRIES {
                return Err("Service inventory limit reached; results are incomplete".into());
            }
            // SAFETY: string pointers belong to the live enumeration buffer, open requests query-config rights only.
            let name = unsafe { service_text(service.lpServiceName) }?;
            // SAFETY: display name belongs to the same live enumeration buffer.
            let display = unsafe { service_text(service.lpDisplayName) }?;
            // SAFETY: manager is live, service name is NUL-terminated in the enumeration buffer; query-only access.
            let handle =
                unsafe { OpenServiceW(manager.0, service.lpServiceName, SERVICE_QUERY_CONFIG) };
            if handle.is_null() {
                warn(
                    snapshot,
                    format!("Read service {name}: {}", io::Error::last_os_error()),
                );
                continue;
            }
            let handle = ServiceHandle(handle);
            let mut config = vec![0usize; 8192 / mem::size_of::<usize>()];
            // SAFETY: config is aligned and writable; QueryServiceConfigW documents an 8 KiB maximum.
            let success = unsafe {
                QueryServiceConfigW(handle.0, config.as_mut_ptr().cast(), 8192, &mut needed)
            };
            if success == 0 {
                warn(
                    snapshot,
                    format!(
                        "Read service configuration {name}: {}",
                        io::Error::last_os_error()
                    ),
                );
                continue;
            }
            // SAFETY: QueryServiceConfigW initialized the header at this aligned buffer's start.
            let config = unsafe { &*config.as_ptr().cast::<QUERY_SERVICE_CONFIGW>() };
            if config.dwStartType != SERVICE_AUTO_START {
                continue;
            }
            // SAFETY: binary path points into the still-live query buffer.
            let command = unsafe { service_text(config.lpBinaryPathName) }?;
            snapshot.entries.push(StartupEntry {
                id: id(&Identity::Service { name: name.clone() }),
                name: if display.is_empty() {
                    name.clone()
                } else {
                    display
                },
                source: "Automatic service (read-only)".into(),
                location: format!(r"HKLM\SYSTEM\CurrentControlSet\Services\{name}"),
                command,
                enabled: true,
                can_toggle: false,
            });
        }
        if success != 0 {
            return Ok(());
        }
        if count == 0 {
            return Err("Service enumeration made no progress; results are incomplete".into());
        }
    }
}

enum Watch {
    Registry { _key: Key, event: Handle },
    Folder(HANDLE),
}
impl Watch {
    fn handle(&self) -> HANDLE {
        match self {
            Self::Registry { event, .. } => event.raw(),
            Self::Folder(handle) => *handle,
        }
    }
}
impl Drop for Watch {
    fn drop(&mut self) {
        if let Self::Folder(handle) = self {
            // SAFETY: this is a change-notification handle returned by FindFirstChangeNotificationW.
            unsafe {
                FindCloseChangeNotification(*handle);
            }
        }
    }
}

fn build_watches() -> Vec<Watch> {
    let mut watches = Vec::new();
    let mut degraded = false;
    // HKCU Software is shared; HKLM native/WOW64 are separate. Missing targets use
    // an ancestor NAME-only watch, so unrelated value writes do not cause refreshes.
    for (machine, view32) in [(false, false), (true, false), (true, true)] {
        for target in [
            run_path(false),
            run_path(true),
            format!(r"{CURRENT_VERSION}\Explorer\StartupApproved"),
        ] {
            // StartupApproved is always in the native view, including its Run32 group.
            if view32 && target.ends_with("StartupApproved") {
                continue;
            }
            match registry_watch(machine, view32, &target) {
                Some(watch) => watches.push(watch),
                None => degraded = true,
            }
        }
    }
    let mut folders = HashSet::new();
    for common in [false, true] {
        let Ok(mut path) = tasks::startup_folder(common) else {
            degraded = true;
            continue;
        };
        let mut subtree = false;
        // Observe creation of a missing Startup directory through its nearest existing ancestor.
        while !path.is_dir() {
            if !path.pop() {
                break;
            }
            subtree = true;
        }
        if !path.is_dir() {
            degraded = true;
            continue;
        }
        if !folders.insert(path.clone()) {
            continue;
        }
        // SAFETY: path is NUL-terminated; notification handle is owned by Watch::Folder.
        let handle = unsafe {
            FindFirstChangeNotificationW(
                os_wide(path.as_os_str()).as_ptr(),
                i32::from(subtree),
                FILE_NOTIFY_CHANGE_FILE_NAME
                    | FILE_NOTIFY_CHANGE_DIR_NAME
                    | FILE_NOTIFY_CHANGE_LAST_WRITE,
            )
        };
        if !handle.is_null() && handle != windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
            watches.push(Watch::Folder(handle));
        } else {
            degraded = true;
        }
    }
    WATCHER_DEGRADED.store(degraded, Ordering::Release);
    watches
}

fn registry_watch(machine: bool, view32: bool, target: &str) -> Option<Watch> {
    let mut path = target;
    let (key, ancestor) = loop {
        match open_key(machine, path, view32, KEY_NOTIFY) {
            Ok(Some(key)) => break (key, path != target),
            Ok(None) => {
                path = path.rsplit_once('\\')?.0;
            }
            Err(_) => return None,
        }
    };
    // SAFETY: null security/name, auto-reset event, initially nonsignaled.
    let event = Handle::new(unsafe { CreateEventW(ptr::null(), 0, 0, ptr::null()) }).ok()?;
    let filter = REG_NOTIFY_CHANGE_NAME
        | if ancestor {
            0
        } else {
            REG_NOTIFY_CHANGE_LAST_SET
        };
    // SAFETY: key/event remain alive in Watch; closing key cancels pending notification.
    if unsafe { RegNotifyChangeKeyValue(key.0, 1, filter, event.raw(), 1) } != 0 {
        return None;
    }
    Some(Watch::Registry { _key: key, event })
}

/// Namespace marker; the returned JoinHandle owns the watcher and is joined by the application.
pub struct StartupWatcher;

/// At most ten native notification handles; one-second stop checks and 350 ms event coalescing.
/// The initial baseline is silent. Task/service inventory remains manual to avoid background COM/RPC work.
pub fn watch_changes(stop: Arc<AtomicBool>, changed: Arc<AtomicBool>) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut watches = build_watches();
        let mut handles: Vec<_> = watches.iter().map(Watch::handle).collect();
        let mut pending: Option<Instant> = None;
        let mut failed = false;
        let mut retry_at = Instant::now();
        while !stop.load(Ordering::Acquire) {
            if watches.is_empty() {
                // A failed watcher is reported once via the same refresh path, never as a busy-loop.
                if !failed {
                    changed.store(true, Ordering::Release);
                    failed = true;
                }
                thread::sleep(Duration::from_secs(1));
                if retry_at.elapsed() >= Duration::from_secs(30) {
                    watches = build_watches();
                    handles = watches.iter().map(Watch::handle).collect();
                    retry_at = Instant::now();
                }
                continue;
            }
            let timeout = if pending.is_some() { 350 } else { 1000 };
            // SAFETY: all handles are valid live notification/event handles; count is at most ten.
            let result = unsafe {
                WaitForMultipleObjects(handles.len() as u32, handles.as_ptr(), 0, timeout)
            };
            if result < WAIT_OBJECT_0 + handles.len() as u32 {
                pending.get_or_insert_with(Instant::now);
                // Reopen/rearm in one place, including keys/folders deleted and recreated during the event.
                watches = build_watches();
                handles = watches.iter().map(Watch::handle).collect();
            } else if result != WAIT_TIMEOUT {
                changed.store(true, Ordering::Release);
                watches.clear();
                WATCHER_DEGRADED.store(true, Ordering::Release);
                failed = true;
            }
            if pending.is_some_and(|started| started.elapsed() >= Duration::from_millis(350)) {
                changed.store(true, Ordering::Release);
                pending = None;
            }
            if WATCHER_DEGRADED.load(Ordering::Acquire)
                && retry_at.elapsed() >= Duration::from_secs(30)
            {
                watches = build_watches();
                handles = watches.iter().map(Watch::handle).collect();
                retry_at = Instant::now();
                if !WATCHER_DEGRADED.load(Ordering::Acquire) {
                    changed.store(true, Ordering::Release);
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(command: &str) -> StartupEntry {
        StartupEntry {
            id: "identity".into(),
            name: "sample".into(),
            source: "Registry".into(),
            location: "test".into(),
            command: command.into(),
            enabled: true,
            can_toggle: true,
        }
    }

    #[test]
    fn startup_approval_preserves_payload_and_handles_known_states() {
        assert!(approved_enabled(None).unwrap());
        for (state, enabled) in [(2, true), (3, false), (6, true), (7, false)] {
            let mut data = [0; 12];
            data[0] = state;
            assert_eq!(approved_enabled(Some(&data)).unwrap(), enabled);
        }
        let data = [3, 0, 0, 0, 10, 11, 12, 13, 14, 15, 16, 17, 42];
        let enabled = approved_data(Some(&data), true, 0).unwrap();
        assert_eq!(enabled, [2, 0, 0, 0, 10, 11, 12, 13, 14, 15, 16, 17, 42]);
        assert_eq!(
            approved_data(None, false, 0x0102030405060708).unwrap(),
            [3, 0, 0, 0, 8, 7, 6, 5, 4, 3, 2, 1]
        );
    }

    #[test]
    fn startup_approval_rejects_unknown_or_malformed_records() {
        assert!(approved_enabled(Some(&[2])).is_err());
        assert!(approved_enabled(Some(&[9; 12])).is_err());
        assert!(approved_data(Some(&[9; 12]), false, 0).is_err());
        let mut data = [0; 12];
        data[0] = 2;
        data[1] = 1;
        assert!(approved_enabled(Some(&data)).is_err());
    }

    #[test]
    fn stale_or_forged_entries_cannot_mutate() {
        assert!(validate_entry(&entry("app.exe --safe"), &entry("app.exe --changed")).is_err());
        let mut current = entry("app.exe");
        current.id = "replacement".into();
        assert!(validate_entry(&entry("app.exe"), &current).is_err());
        let mut readonly = entry("app.exe");
        readonly.can_toggle = false;
        assert!(validate_entry(&entry("app.exe"), &readonly).is_err());
        assert!(validate_entry(&entry("app.exe"), &entry("app.exe")).is_ok());
    }

    #[test]
    fn identity_parser_rejects_paths_and_embedded_nuls() {
        assert!(parse_id("not-json").is_err());
        assert!(
            parse_id(r#"{"Folder":{"common":false,"name":"..\\other.exe","size":1,"modified":2}}"#)
                .is_err()
        );
        assert!(
            parse_id(
                r#"{"Run":{"machine":false,"view32":false,"once":false,"name":"bad\u0000name"}}"#
            )
            .is_err()
        );
        let identity = Identity::Run {
            machine: false,
            view32: false,
            once: false,
            name: "Имя \\ args".into(),
        };
        assert_eq!(
            parse_id(&serde_json::to_string(&identity).unwrap()).unwrap(),
            identity
        );
    }

    struct FixtureKey {
        key: Option<Key>,
        path: String,
    }
    impl FixtureKey {
        fn new() -> Self {
            let path = format!(
                r"Software\AnVirNextTestFixtures\startup-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            );
            Self {
                key: Some(
                    create_key(false, &path, KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_NOTIFY).unwrap(),
                ),
                path,
            }
        }
        fn key(&self) -> &Key {
            self.key.as_ref().unwrap()
        }
        fn put(&self, name: &str, kind: u32, bytes: &[u8]) {
            // SAFETY: writes only to this test's unique disposable HKCU key; inputs are valid buffers.
            assert_eq!(
                // SAFETY: this fixture owns the key and each input buffer lives throughout the synchronous write.
                unsafe {
                    RegSetValueExW(
                        self.key().0,
                        wide(name).as_ptr(),
                        0,
                        kind,
                        bytes.as_ptr(),
                        bytes.len() as u32,
                    )
                },
                0
            );
        }
    }
    impl Drop for FixtureKey {
        fn drop(&mut self) {
            self.key.take();
            // SAFETY: the unique leaf path was created by this fixture, never a real startup location.
            unsafe {
                RegDeleteKeyExW(
                    HKEY_CURRENT_USER,
                    wide(&self.path).as_ptr(),
                    KEY_WOW64_64KEY,
                    0,
                );
            }
        }
    }

    #[test]
    fn startup_isolated_registry_toggle_is_reversible_and_rejects_bad_data() {
        let fixture = FixtureKey::new();
        let command: Vec<u8> = wide(r#""C:\test app\app.exe" --sample"#)
            .iter()
            .flat_map(|x| x.to_le_bytes())
            .collect();
        fixture.put("Command", REG_SZ, &command);
        let original = [2, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 99];
        fixture.put("Approval", REG_BINARY, &original);
        update_approval_value(fixture.key(), "Approval", false, true, 9).unwrap();
        assert_eq!(
            read_value(fixture.key(), "Approval").unwrap().unwrap().1,
            [3, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 99]
        );
        assert!(update_approval_value(fixture.key(), "Approval", true, true, 0).is_err());
        update_approval_value(fixture.key(), "Approval", true, false, 0).unwrap();
        assert_eq!(
            read_value(fixture.key(), "Approval").unwrap().unwrap().1,
            [2, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 99]
        );
        assert_eq!(
            read_value(fixture.key(), "Command").unwrap().unwrap().1,
            command
        );
        fixture.put("Invalid", REG_BINARY, &[9; 12]);
        assert!(update_approval_value(fixture.key(), "Invalid", false, true, 0).is_err());
        assert_eq!(
            read_value(fixture.key(), "Invalid").unwrap().unwrap().1,
            [9; 12]
        );
        fixture.put("WrongType", REG_SZ, &command);
        assert!(update_approval_value(fixture.key(), "WrongType", false, true, 0).is_err());
        assert_eq!(
            read_value(fixture.key(), "WrongType").unwrap().unwrap().1,
            command
        );
    }

    #[test]
    fn startup_registry_watcher_observes_only_fixture_writes() {
        let fixture = FixtureKey::new();
        let watch = registry_watch(false, false, &fixture.path).unwrap();
        fixture.put("Signal", REG_BINARY, &[1]);
        // SAFETY: waits on one live owned handle.
        assert_eq!(
            // SAFETY: one live fixture notification handle is borrowed for this bounded wait.
            unsafe { WaitForMultipleObjects(1, &watch.handle(), 0, 2000) },
            WAIT_OBJECT_0
        );
    }

    #[test]
    fn startup_registry_watcher_catches_creation_of_missing_target() {
        let fixture = FixtureKey::new();
        let target = format!(r"{}\NotYetCreated", fixture.path);
        let watch = registry_watch(false, false, &target).unwrap();
        let key = create_key(false, &target, KEY_SET_VALUE).unwrap();
        // SAFETY: waits on one valid registry event, owned by watch.
        let result = unsafe { WaitForMultipleObjects(1, &watch.handle(), 0, 2000) };
        drop(key);
        // SAFETY: deletes only the empty test-owned child key, never a startup location.
        unsafe {
            RegDeleteKeyExW(
                HKEY_CURRENT_USER,
                wide(&target).as_ptr(),
                KEY_WOW64_64KEY,
                0,
            );
        }
        assert_eq!(result, WAIT_OBJECT_0);
    }

    #[test]
    fn startup_pre_stopped_watcher_keeps_baseline_silent() {
        let changed = Arc::new(AtomicBool::new(false));
        let start = Instant::now();
        watch_changes(Arc::new(AtomicBool::new(true)), changed.clone())
            .join()
            .unwrap();
        assert!(!changed.load(Ordering::Acquire));
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn startup_read_only_inventory_smoke() {
        let start = Instant::now();
        let snapshot = scan();
        eprintln!(
            "startup scan: {} entries, {} warnings, {:?}",
            snapshot.entries.len(),
            snapshot.warnings.len(),
            start.elapsed()
        );
        let mut sources = std::collections::BTreeMap::new();
        for entry in &snapshot.entries {
            *sources.entry(&entry.source).or_insert(0) += 1;
        }
        eprintln!("startup sources: {sources:?}");
        for warning in &snapshot.warnings {
            eprintln!("startup warning: {warning}");
        }
        assert!(!snapshot.entries.is_empty() || !snapshot.warnings.is_empty());
        let mut ids = HashSet::new();
        for entry in &snapshot.entries {
            assert!(parse_id(&entry.id).is_ok(), "{}", entry.id);
            assert!(ids.insert(&entry.id), "duplicate startup identity");
            if entry.source.contains("RunOnce") || entry.source.contains("service") {
                assert!(!entry.can_toggle);
            }
        }
        assert!(snapshot.entries.len() <= MAX_ENTRIES);
    }
}
