use crate::{
    model::{ProcessTimes, counter_rate, process_cpu},
    win::{Handle, filetime, wide},
};
use std::{
    collections::HashMap,
    ffi::c_void,
    io,
    mem::size_of,
    ptr,
    time::{Duration, Instant},
};
use windows_sys::{
    Wdk::System::{
        SystemInformation::{NtQuerySystemInformation, SystemProcessInformation},
        Threading::{
            NtQueryInformationProcess, ProcessBasicInformation, ProcessCommandLineInformation,
        },
    },
    Win32::{
        Foundation::{FILETIME, HANDLE, UNICODE_STRING},
        Storage::FileSystem::{GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW},
        System::{
            SystemInformation::{
                IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_ARM64, IMAGE_FILE_MACHINE_UNKNOWN,
            },
            Threading::*,
        },
    },
};

const MAX_SNAPSHOT: usize = 32 * 1024 * 1024;
const MAX_IDENTITIES: usize = 8192;
const MAX_METADATA: usize = 1024;
const MAX_QUERY: usize = 128 * 1024;
const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xc0000004u32 as i32;
const STATUS_BUFFER_TOO_SMALL: i32 = 0xc0000023u32 as i32;

#[derive(Clone, Debug)]
pub struct ProcessRow {
    pub pid: u32,
    pub name: String,
    pub times: Option<ProcessTimes>,
    pub cpu: Option<f64>,
    /// Resident working-set bytes, including shared resident pages.
    pub memory: Option<u64>,
    /// Read + write transfer bytes/s; includes non-disk file/device I/O.
    pub io_rate: Option<f64>,
    pub path: String,
    pub product: String,
    pub company: String,
    pub is_64_bit: Option<bool>,
}

// Native SystemProcessInformation ABI for Windows 11. Explicit time/I/O
// members replace winternl.h reserved fields; no remote pointers are read.
#[repr(C)]
#[derive(Clone, Copy)]
struct NativeProcess {
    next: u32,
    threads: u32,
    working_set_private: i64,
    hard_faults: u32,
    thread_high_watermark: u32,
    cycle_time: u64,
    created: i64,
    user: i64,
    kernel: i64,
    image: UNICODE_STRING,
    base_priority: i32,
    pid: HANDLE,
    parent: HANDLE,
    handles: u32,
    session: u32,
    unique_key: usize,
    peak_virtual: usize,
    virtual_size: usize,
    page_faults: u32,
    peak_working_set: usize,
    working_set: usize,
    quota_peak_paged: usize,
    quota_paged: usize,
    quota_peak_nonpaged: usize,
    quota_nonpaged: usize,
    pagefile: usize,
    peak_pagefile: usize,
    private_page: usize,
    read_ops: i64,
    write_ops: i64,
    other_ops: i64,
    read_bytes: i64,
    write_bytes: i64,
    other_bytes: i64,
}

#[derive(Clone)]
struct IdentityMetadata {
    path: String,
    is_64_bit: Option<bool>,
    retry_at: Instant,
}
struct VersionMetadata {
    product: String,
    company: String,
    touched: Instant,
}
struct Previous {
    times: ProcessTimes,
    io: u64,
}

#[derive(Default)]
pub struct ProcessSampler {
    buffer: Vec<usize>,
    previous: HashMap<u32, Previous>,
    identities: HashMap<(u32, u64), IdentityMetadata>,
    versions: HashMap<String, VersionMetadata>,
    sampled_at: Option<Instant>,
    pub last_error: Option<String>,
}

impl ProcessSampler {
    pub fn sample(&mut self, logical: usize) -> Vec<ProcessRow> {
        let length = match system_snapshot(&mut self.buffer) {
            Ok(length) => length,
            Err(error) => {
                self.last_error = Some(error);
                return Vec::new();
            }
        };
        self.last_error = None;
        let now = Instant::now();
        let elapsed = self.sampled_at.map(|previous| now.duration_since(previous));
        let mut rows = Vec::new();
        let mut previous = HashMap::new();
        let mut live = HashMap::new();
        let mut offset = 0usize;
        while offset
            .checked_add(size_of::<NativeProcess>())
            .is_some_and(|end| end <= length)
        {
            // SAFETY: the complete fixed header lies within the returned buffer.
            let info = unsafe {
                ptr::read_unaligned(
                    self.buffer
                        .as_ptr()
                        .cast::<u8>()
                        .add(offset)
                        .cast::<NativeProcess>(),
                )
            };
            let pid = info.pid as usize;
            if pid <= u32::MAX as usize {
                let pid = pid as u32;
                let times = ProcessTimes {
                    created: info.created.max(0) as u64,
                    cpu: info.user.max(0) as u64 + info.kernel.max(0) as u64,
                };
                let io =
                    (info.read_bytes.max(0) as u64).saturating_add(info.write_bytes.max(0) as u64);
                let old = self
                    .previous
                    .get(&pid)
                    .filter(|old| old.times.created == times.created);
                let cpu = old
                    .zip(elapsed)
                    .and_then(|(old, elapsed)| process_cpu(old.times, times, elapsed, logical));
                let io_rate = old
                    .zip(elapsed)
                    .and_then(|(old, elapsed)| counter_rate(old.io, io, elapsed));
                let key = (pid, times.created);
                let metadata = match self.identities.get(&key) {
                    Some(metadata) if !metadata.path.is_empty() || now < metadata.retry_at => {
                        metadata.clone()
                    }
                    _ => process_metadata(pid, times.created, now),
                };
                if live.len() < MAX_IDENTITIES {
                    live.insert(key, metadata.clone());
                }
                let (product, company) = self.version_metadata(&metadata.path, now);
                let name = unicode_from_buffer(info.image, self.buffer.as_ptr().cast(), length)
                    .unwrap_or_default();
                rows.push(ProcessRow {
                    pid,
                    name: if pid == 0 {
                        "System Idle Process".into()
                    } else if name.is_empty() {
                        format!("PID {pid}")
                    } else {
                        name
                    },
                    times: Some(times),
                    cpu,
                    memory: Some(info.working_set as u64),
                    io_rate,
                    path: metadata.path,
                    product,
                    company,
                    is_64_bit: metadata.is_64_bit,
                });
                if previous.len() < MAX_IDENTITIES {
                    previous.insert(pid, Previous { times, io });
                }
            }
            if info.next == 0 {
                break;
            }
            let next = offset.checked_add(info.next as usize);
            if info.next < size_of::<NativeProcess>() as u32
                || next.is_none_or(|next| next >= length)
            {
                self.last_error = Some("Invalid native process snapshot entry".into());
                break;
            }
            offset = next.unwrap();
        }
        self.previous = previous;
        self.identities = live;
        self.sampled_at = Some(now);
        rows
    }

    fn version_metadata(&mut self, path: &str, now: Instant) -> (String, String) {
        if path.is_empty() {
            return (String::new(), String::new());
        }
        let key = path.to_owned();
        if let Some(metadata) = self.versions.get(&key) {
            if now.duration_since(metadata.touched) < Duration::from_secs(600) {
                return (metadata.product.clone(), metadata.company.clone());
            }
        }
        if self.versions.len() >= MAX_METADATA {
            if let Some(oldest) = self
                .versions
                .iter()
                .min_by_key(|(_, entry)| entry.touched)
                .map(|(key, _)| key.clone())
            {
                self.versions.remove(&oldest);
            }
        }
        let (product, company) = file_version(path);
        self.versions.insert(
            key,
            VersionMetadata {
                product: product.clone(),
                company: company.clone(),
                touched: now,
            },
        );
        (product, company)
    }
}

fn system_snapshot(buffer: &mut Vec<usize>) -> Result<usize, String> {
    if buffer.is_empty() {
        buffer.resize(1024 * 1024 / size_of::<usize>(), 0);
    }
    for _ in 0..8 {
        let mut needed = 0;
        let bytes = buffer.len() * size_of::<usize>();
        // SAFETY: the vector is aligned and writable for exactly bytes bytes.
        let status = unsafe {
            NtQuerySystemInformation(
                SystemProcessInformation,
                buffer.as_mut_ptr().cast(),
                bytes as u32,
                &mut needed,
            )
        };
        if status >= 0 && needed as usize <= bytes {
            return Ok(needed as usize);
        }
        if status != STATUS_INFO_LENGTH_MISMATCH && status != STATUS_BUFFER_TOO_SMALL {
            return Err(format!(
                "Process snapshot failed: NTSTATUS 0x{:08x}",
                status as u32
            ));
        }
        let size = (needed as usize)
            .saturating_add(65536)
            .max(bytes.saturating_mul(2));
        if size > MAX_SNAPSHOT {
            return Err("Process snapshot exceeds 32 MiB limit".into());
        }
        buffer.resize(size.div_ceil(size_of::<usize>()), 0);
    }
    Err("Process list changed too quickly; retry refresh".into())
}

fn unicode_from_buffer(
    value: UNICODE_STRING,
    base: *const u8,
    length: usize,
) -> Result<String, String> {
    let count = value.Length as usize;
    if count == 0 {
        return Ok(String::new());
    }
    let start = value.Buffer as usize;
    let lower = base as usize;
    if count % 2 != 0
        || count > value.MaximumLength as usize
        || start % 2 != 0
        || start < lower
        || start
            .checked_add(count)
            .is_none_or(|end| end > lower.saturating_add(length))
    {
        return Err("Invalid native Unicode string".into());
    }
    // SAFETY: the string's aligned u16 range is completely inside the allocation.
    Ok(String::from_utf16_lossy(unsafe {
        std::slice::from_raw_parts(value.Buffer, count / 2)
    }))
}

fn process_metadata(pid: u32, created: u64, now: Instant) -> IdentityMetadata {
    let mut result = IdentityMetadata {
        path: String::new(),
        is_64_bit: None,
        retry_at: now + Duration::from_secs(30),
    };
    let Ok(handle) = open_process(pid, PROCESS_QUERY_LIMITED_INFORMATION) else {
        return result;
    };
    if !process_times(handle.raw()).is_ok_and(|times| times.created == created) {
        return result;
    }
    result.path = executable_path(handle.raw()).unwrap_or_default();
    let (mut process_machine, mut native_machine) = (0, 0);
    // SAFETY: valid query handle and writable machine-code outputs.
    if unsafe { IsWow64Process2(handle.raw(), &mut process_machine, &mut native_machine) } != 0 {
        result.is_64_bit = Some(
            process_machine == IMAGE_FILE_MACHINE_UNKNOWN
                && matches!(
                    native_machine,
                    IMAGE_FILE_MACHINE_AMD64 | IMAGE_FILE_MACHINE_ARM64
                ),
        );
    }
    result
}

fn file_version(path: &str) -> (String, String) {
    let path = wide(path);
    // SAFETY: path is NUL-terminated; the ignored handle output may be null.
    let length = unsafe { GetFileVersionInfoSizeW(path.as_ptr(), ptr::null_mut()) } as usize;
    if length == 0 || length > 2 * 1024 * 1024 {
        return (String::new(), String::new());
    }
    let mut data = vec![0usize; length.div_ceil(size_of::<usize>())];
    // SAFETY: writable allocation is at least length bytes.
    if unsafe { GetFileVersionInfoW(path.as_ptr(), 0, length as u32, data.as_mut_ptr().cast()) }
        == 0
    {
        return (String::new(), String::new());
    }
    let translation = wide("\\VarFileInfo\\Translation");
    let (mut value, mut count) = (ptr::null_mut(), 0);
    // SAFETY: initialized version block, NUL-terminated query and writable outputs.
    let translated = unsafe {
        VerQueryValueW(
            data.as_ptr().cast(),
            translation.as_ptr(),
            &mut value,
            &mut count,
        )
    };
    let mut languages = Vec::with_capacity(9);
    if translated != 0
        && count >= 4
        && pointer_range(data.as_ptr().cast(), length, value, count as usize)
    {
        for index in 0..(count as usize / 4).min(8) {
            // SAFETY: each pair lies inside the validated translation value.
            let pair = unsafe { ptr::read_unaligned(value.cast::<u32>().add(index)) };
            languages.push((pair as u16, (pair >> 16) as u16));
        }
    }
    languages.push((0x0409, 0x04b0));
    let read = |field: &str| -> String {
        for &(language, codepage) in &languages {
            let query = wide(&format!(
                "\\StringFileInfo\\{language:04x}{codepage:04x}\\{field}"
            ));
            let (mut value, mut count) = (ptr::null_mut(), 0);
            // SAFETY: initialized version block and valid query/output pointers.
            if unsafe {
                VerQueryValueW(data.as_ptr().cast(), query.as_ptr(), &mut value, &mut count)
            } == 0
            {
                continue;
            }
            let bytes = (count as usize).saturating_mul(2);
            if count == 0
                || bytes > 32768
                || value as usize % 2 != 0
                || !pointer_range(data.as_ptr().cast(), length, value, bytes)
            {
                continue;
            }
            // SAFETY: aligned UTF-16 result lies wholly inside the version block.
            let text = unsafe { std::slice::from_raw_parts(value.cast::<u16>(), count as usize) };
            return String::from_utf16_lossy(
                text.split(|value| *value == 0).next().unwrap_or_default(),
            );
        }
        String::new()
    };
    (read("ProductName"), read("CompanyName"))
}

fn pointer_range(base: *const u8, length: usize, value: *const c_void, count: usize) -> bool {
    let start = value as usize;
    start >= base as usize
        && start
            .checked_add(count)
            .is_some_and(|end| end <= (base as usize).saturating_add(length))
}

fn open_process(pid: u32, access: u32) -> Result<Handle, String> {
    // SAFETY: OpenProcess accepts integer IDs/access flags and returns an owned handle.
    Handle::new(unsafe { OpenProcess(access, 0, pid) })
        .map_err(|error| format!("Open process {pid}: {error}"))
}

fn process_times(handle: HANDLE) -> Result<ProcessTimes, String> {
    let (mut created, mut exited, mut kernel, mut user) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    // SAFETY: query handle and four writable FILETIME outputs.
    if unsafe { GetProcessTimes(handle, &mut created, &mut exited, &mut kernel, &mut user) } == 0 {
        return Err(last_error("Read process creation time"));
    }
    Ok(ProcessTimes {
        created: filetime(created),
        cpu: filetime(kernel).saturating_add(filetime(user)),
    })
}

fn executable_path(handle: HANDLE) -> Result<String, String> {
    let mut path = vec![0u16; 32768];
    let mut length = path.len() as u32;
    // SAFETY: valid query handle, buffer and character capacity.
    if unsafe { QueryFullProcessImageNameW(handle, 0, path.as_mut_ptr(), &mut length) } == 0 {
        return Err(last_error("Read executable path"));
    }
    Ok(String::from_utf16_lossy(&path[..length as usize]))
}

fn command_line(handle: HANDLE) -> Result<String, String> {
    let mut needed = 0;
    // SAFETY: size query with a null buffer and zero capacity.
    let status = unsafe {
        NtQueryInformationProcess(
            handle,
            ProcessCommandLineInformation,
            ptr::null_mut(),
            0,
            &mut needed,
        )
    };
    if status < 0 && status != STATUS_INFO_LENGTH_MISMATCH && status != STATUS_BUFFER_TOO_SMALL {
        return Err(format!(
            "Read command line: NTSTATUS 0x{:08x}",
            status as u32
        ));
    }
    for _ in 0..4 {
        let length = needed as usize;
        if !(size_of::<UNICODE_STRING>()..=MAX_QUERY).contains(&length) {
            return Err("Command line exceeds supported limit".into());
        }
        let mut buffer = vec![0usize; length.div_ceil(size_of::<usize>())];
        let capacity = buffer.len() * size_of::<usize>();
        // SAFETY: aligned, writable allocation of capacity bytes; no remote PEB read.
        let status = unsafe {
            NtQueryInformationProcess(
                handle,
                ProcessCommandLineInformation,
                buffer.as_mut_ptr().cast(),
                capacity as u32,
                &mut needed,
            )
        };
        if status >= 0 {
            // SAFETY: allocation contains at least one complete UNICODE_STRING.
            let value = unsafe { ptr::read(buffer.as_ptr().cast::<UNICODE_STRING>()) };
            return unicode_from_buffer(value, buffer.as_ptr().cast(), capacity);
        }
        if status != STATUS_INFO_LENGTH_MISMATCH && status != STATUS_BUFFER_TOO_SMALL {
            return Err(format!(
                "Read command line: NTSTATUS 0x{:08x}",
                status as u32
            ));
        }
    }
    Err("Command line changed too quickly; select process again".into())
}

#[derive(Clone, Debug)]
pub struct ProcessDetails {
    pub command_line: String,
    pub path: String,
    pub priority: u32,
    pub affinity: u64,
    pub available_affinity: u64,
    pub parent_pid: u32,
    pub created: u64,
}

pub fn details(pid: u32, expected_created: u64) -> Result<ProcessDetails, String> {
    let handle = open_process(pid, PROCESS_QUERY_LIMITED_INFORMATION)?;
    let times = verify_identity(handle.raw(), pid, expected_created)?;
    let mut basic = PROCESS_BASIC_INFORMATION::default();
    // SAFETY: writable SDK-defined basic-information structure, queried on a valid handle.
    let status = unsafe {
        NtQueryInformationProcess(
            handle.raw(),
            ProcessBasicInformation,
            (&mut basic as *mut PROCESS_BASIC_INFORMATION).cast(),
            size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            ptr::null_mut(),
        )
    };
    if status < 0 {
        return Err(format!("Read parent PID: NTSTATUS 0x{:08x}", status as u32));
    }
    // SAFETY: valid query handle.
    let priority = unsafe { GetPriorityClass(handle.raw()) };
    if priority == 0 {
        return Err(last_error("Read process priority"));
    }
    let (affinity, available_affinity) = affinity_masks(handle.raw())?;
    Ok(ProcessDetails {
        command_line: command_line(handle.raw())?,
        path: executable_path(handle.raw())?,
        priority,
        affinity,
        available_affinity,
        parent_pid: basic.InheritedFromUniqueProcessId as u32,
        created: times.created,
    })
}

fn verify_identity(
    handle: HANDLE,
    pid: u32,
    expected_created: u64,
) -> Result<ProcessTimes, String> {
    // SAFETY: valid process handle.
    let actual_pid = unsafe { GetProcessId(handle) };
    let times = process_times(handle)?;
    if actual_pid != pid || expected_created == 0 || times.created != expected_created {
        return Err("Process exited or PID was reused; refresh the list".into());
    }
    Ok(times)
}

pub fn validate_action(
    expected_pid: u32,
    expected_created: u64,
    actual_pid: u32,
    actual_created: u64,
    critical: bool,
    own_pid: u32,
) -> Result<(), String> {
    if expected_pid <= 4 || expected_pid == own_pid {
        return Err("Changing system or own process is prohibited".into());
    }
    if expected_pid != actual_pid || expected_created == 0 || expected_created != actual_created {
        return Err("Process exited or PID was reused; refresh the list".into());
    }
    if critical {
        return Err("Changing a critical process is prohibited".into());
    }
    Ok(())
}

fn mutation_handle(pid: u32, created: u64, access: u32) -> Result<Handle, String> {
    if pid <= 4 || pid == std::process::id() {
        return Err("Changing system or own process is prohibited".into());
    }
    let handle = open_process(pid, access | PROCESS_QUERY_LIMITED_INFORMATION)?;
    let times = verify_identity(handle.raw(), pid, created)?;
    let mut critical = 0;
    // SAFETY: valid query handle and writable BOOL; failures deliberately fail closed.
    if unsafe { IsProcessCritical(handle.raw(), &mut critical) } == 0 {
        return Err(last_error("Verify process critical status"));
    }
    // SAFETY: valid process handle.
    let actual_pid = unsafe { GetProcessId(handle.raw()) };
    validate_action(
        pid,
        created,
        actual_pid,
        times.created,
        critical != 0,
        std::process::id(),
    )?;
    Ok(handle)
}

pub fn terminate(pid: u32, expected_created: u64) -> Result<(), String> {
    let handle = mutation_handle(pid, expected_created, PROCESS_TERMINATE)?;
    // SAFETY: identity/critical/self validation applies to this same held process handle.
    if unsafe { TerminateProcess(handle.raw(), 1) } == 0 {
        return Err(last_error("Terminate process"));
    }
    Ok(())
}

pub fn validate_scheduling(priority: u32, affinity: u64, available: u64) -> Result<(), String> {
    if !matches!(
        priority,
        0 | IDLE_PRIORITY_CLASS
            | BELOW_NORMAL_PRIORITY_CLASS
            | NORMAL_PRIORITY_CLASS
            | ABOVE_NORMAL_PRIORITY_CLASS
            | HIGH_PRIORITY_CLASS
    ) {
        return Err("Unsupported priority; real-time priority is prohibited".into());
    }
    if affinity != 0 && (available == 0 || affinity & !available != 0) {
        return Err("Affinity contains unavailable processors".into());
    }
    Ok(())
}

fn affinity_masks(handle: HANDLE) -> Result<(u64, u64), String> {
    let (mut process, mut system) = (0usize, 0usize);
    // SAFETY: valid process query handle and writable masks.
    if unsafe { GetProcessAffinityMask(handle, &mut process, &mut system) } == 0 {
        return Err(last_error("Read processor affinity"));
    }
    if process == 0 || system == 0 {
        return Err("Multiple processor groups are not supported by this prototype".into());
    }
    Ok((process as u64, system as u64))
}

pub fn set_scheduling(
    pid: u32,
    expected_created: u64,
    priority: u32,
    affinity: u64,
) -> Result<(), String> {
    validate_scheduling(priority, affinity, u64::MAX)?;
    let handle = mutation_handle(pid, expected_created, PROCESS_SET_INFORMATION)?;
    let (old_affinity, available) = affinity_masks(handle.raw())?;
    validate_scheduling(priority, affinity, available)?;
    if affinity != 0 {
        // SAFETY: group count query has no pointer inputs.
        if unsafe { GetActiveProcessorGroupCount() } != 1 {
            return Err("Affinity changes require a single processor group".into());
        }
        // SAFETY: process handle has set rights and nonzero mask is within system mask.
        if unsafe { SetProcessAffinityMask(handle.raw(), affinity as usize) } == 0 {
            return Err(last_error("Set processor affinity"));
        }
    }
    // SAFETY: allowed non-real-time class and validated process handle with set rights.
    if priority != 0 && unsafe { SetPriorityClass(handle.raw(), priority) } == 0 {
        let error = last_error("Set process priority");
        if affinity != 0 {
            // SAFETY: restore the previously queried mask on this same held handle.
            if unsafe { SetProcessAffinityMask(handle.raw(), old_affinity as usize) } == 0 {
                return Err(format!(
                    "{error}; affinity rollback also failed: {}",
                    io::Error::last_os_error()
                ));
            }
        }
        return Err(error);
    }
    Ok(())
}

fn last_error(context: &str) -> String {
    format!("{context}: {}", io::Error::last_os_error())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_this_process_with_a_nonzero_creation_time_and_memory() {
        assert_eq!(size_of::<NativeProcess>(), 256);
        let mut sampler = ProcessSampler::default();
        let rows = sampler.sample(1);
        let this = rows
            .iter()
            .find(|row| row.pid == std::process::id())
            .expect("current process missing");
        assert!(this.times.is_some_and(|times| times.created > 0));
        assert!(this.memory.is_some_and(|memory| memory > 0));
        assert!(this.path.ends_with(".exe"));
        assert_eq!(this.is_64_bit, Some(true));
        assert!(sampler.last_error.is_none(), "{:?}", sampler.last_error);
    }

    #[test]
    fn process_actions_reject_reused_critical_system_and_own_processes() {
        assert!(validate_action(55, 100, 55, 100, false, 99).is_ok());
        assert!(validate_action(55, 100, 55, 101, false, 99).is_err());
        assert!(validate_action(55, 100, 56, 100, false, 99).is_err());
        assert!(validate_action(55, 100, 55, 100, true, 99).is_err());
        assert!(validate_action(4, 100, 4, 100, false, 99).is_err());
        assert!(validate_action(99, 100, 99, 100, false, 99).is_err());
        assert!(validate_action(55, 0, 55, 0, false, 99).is_err());
    }

    #[test]
    fn full_command_line_and_details_are_read_without_peb_access() {
        let rows = ProcessSampler::default().sample(1);
        let own = rows
            .iter()
            .find(|row| row.pid == std::process::id())
            .unwrap();
        let info = details(own.pid, own.times.unwrap().created).unwrap();
        let executable = std::env::current_exe().unwrap();
        assert!(
            info.command_line
                .contains(executable.file_name().unwrap().to_str().unwrap())
        );
        assert!(info.path.ends_with(".exe"));
        assert_ne!(info.priority, 0);
        assert_ne!(info.affinity, 0);
        assert_eq!(info.affinity & !info.available_affinity, 0);
        assert!(details(own.pid, info.created + 1).is_err());
        assert!(set_scheduling(own.pid, info.created, 0, 0).is_err());
    }

    #[test]
    fn scheduling_rejects_realtime_unknown_priorities_and_out_of_mask_bits() {
        assert!(validate_scheduling(0, 0, 0b1011).is_ok());
        assert!(validate_scheduling(0x20, 0b1001, 0b1011).is_ok());
        assert!(validate_scheduling(0x100, 1, 0b1011).is_err());
        assert!(validate_scheduling(7, 1, 0b1011).is_err());
        assert!(validate_scheduling(0x20, 0b0100, 0b1011).is_err());
        assert!(validate_scheduling(0, 1u64 << 63, 1u64 << 63).is_ok());
    }

    #[test]
    #[ignore = "only launched as a disposable child by the integration test"]
    fn controlled_child() {
        std::thread::sleep(Duration::from_secs(30));
    }

    #[test]
    fn controlled_child_preserves_long_arguments_and_accepts_verified_scheduling() {
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let marker = format!("anvir-long-argument-{}", "x".repeat(4096));
        let child = Child(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--ignored",
                    "--exact",
                    "processes::tests::controlled_child",
                    &marker,
                ])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap(),
        );
        let handle = open_process(child.0.id(), PROCESS_QUERY_LIMITED_INFORMATION).unwrap();
        let created = process_times(handle.raw()).unwrap().created;
        let original = details(child.0.id(), created).unwrap();
        assert!(original.command_line.contains(&marker));
        assert_eq!(original.parent_pid, std::process::id());
        let affinity = original.available_affinity & original.available_affinity.wrapping_neg();
        assert!(set_scheduling(child.0.id(), created + 1, IDLE_PRIORITY_CLASS, affinity).is_err());
        assert_eq!(
            details(child.0.id(), created).unwrap().priority,
            original.priority
        );
        set_scheduling(child.0.id(), created, BELOW_NORMAL_PRIORITY_CLASS, affinity).unwrap();
        let changed = details(child.0.id(), created).unwrap();
        assert_eq!(changed.priority, BELOW_NORMAL_PRIORITY_CLASS);
        assert_eq!(changed.affinity, affinity);
        assert!(set_scheduling(child.0.id(), created, REALTIME_PRIORITY_CLASS, affinity).is_err());
        assert_eq!(
            details(child.0.id(), created).unwrap().priority,
            BELOW_NORMAL_PRIORITY_CLASS
        );
        terminate(child.0.id(), created).unwrap();
    }

    #[test]
    fn reads_real_version_resource_product_and_company() {
        let system = std::env::var_os("SystemRoot").unwrap();
        let executable = std::path::PathBuf::from(system)
            .join("System32")
            .join("cmd.exe");
        let (product, company) = file_version(executable.to_str().unwrap());
        assert!(!product.is_empty());
        assert!(company.contains("Microsoft"));
    }
}
