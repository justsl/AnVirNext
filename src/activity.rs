//! Owned real-time kernel ETW activity; no packet contents, ETL files or generic-I/O estimates.

use crate::model::counter_rate;
use crate::win::{Handle, filetime, wide};
use std::{
    collections::{HashMap, HashSet},
    ffi::c_void,
    io,
    mem::{offset_of, size_of},
    ptr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use windows_sys::{
    Win32::{
        Foundation::{ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER, ERROR_MORE_DATA, FILETIME},
        System::{
            Com::CoCreateGuid,
            Diagnostics::Etw::*,
            RemoteDesktop::ProcessIdToSessionId,
            SystemInformation::GetSystemTimeAsFileTime,
            Threading::{
                GetCurrentProcess, GetCurrentProcessId, GetProcessTimes, OpenProcess,
                PROCESS_QUERY_LIMITED_INFORMATION,
            },
        },
    },
    core::GUID,
};

const MAX_PROCESSES: usize = 8192;
const MAX_THREADS: usize = 65536;
const MAX_IRPS: usize = 32768;
const IRP_TIMEOUT: u64 = 60 * 10_000_000;
const TRACE_FLAGS: u32 = EVENT_TRACE_FLAG_NETWORK_TCPIP
    | EVENT_TRACE_FLAG_DISK_IO
    | EVENT_TRACE_FLAG_DISK_IO_INIT
    | EVENT_TRACE_FLAG_THREAD
    | EVENT_TRACE_FLAG_PROCESS
    | EVENT_TRACE_FLAG_NO_SYSCONFIG;
const TRACE_MODE: u32 = EVENT_TRACE_REAL_TIME_MODE
    | EVENT_TRACE_SYSTEM_LOGGER_MODE
    | EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING;
const SESSION_PREFIX: &str = "AnVirNext.Activity.v1.";
const TCP_GUID: GUID = GUID::from_u128(0x9a280ac0_c8e0_11d1_84e2_00c04fb998a2);
const UDP_GUID: GUID = GUID::from_u128(0xbf3a50c5_a9c9_4988_a005_2df0b7c80f80);
const DISK_GUID: GUID = GUID::from_u128(0x3d6fa8d4_fe05_11d0_9dda_00c04fd7ba7c);
const THREAD_GUID: GUID = GUID::from_u128(0x3d6fa8d1_fe05_11d0_9dda_00c04fd7ba7c);
const PROCESS_GUID: GUID = GUID::from_u128(0x3d6fa8d0_fe05_11d0_9dda_00c04fd7ba7c);

#[derive(Clone, Copy, Debug, Default)]
pub struct ProcessRates {
    pub network_receive: Option<f64>,
    pub network_send: Option<f64>,
    pub disk_read: Option<f64>,
    pub disk_write: Option<f64>,
}

type Identity = (u32, u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Provider {
    Tcp,
    Udp,
    Disk,
    Thread,
    Process,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Event {
    Network {
        pid: u32,
        bytes: u32,
        receive: bool,
    },
    DiskInit {
        irp: u64,
        tid: u32,
        write: bool,
    },
    DiskDone {
        irp: u64,
        tid: u32,
        bytes: u32,
        write: bool,
    },
    Thread {
        pid: u32,
        tid: u32,
        start: bool,
        rundown: bool,
    },
    ProcessEnd {
        pid: u32,
    },
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Counters {
    receive: u64,
    send: u64,
    read: u64,
    write: u64,
    generation: u64,
}

fn u32_at(data: &[u8], offset: usize) -> Result<u32, &'static str> {
    Ok(u32::from_le_bytes(
        data.get(offset..offset + 4)
            .ok_or("truncated event")?
            .try_into()
            .map_err(|_| "truncated integer")?,
    ))
}
fn pointer_at(data: &[u8], offset: usize, pointer: usize) -> Result<u64, &'static str> {
    match pointer {
        4 => u32_at(data, offset).map(u64::from),
        8 => Ok(u64::from_le_bytes(
            data.get(offset..offset + 8)
                .ok_or("truncated pointer")?
                .try_into()
                .map_err(|_| "truncated pointer")?,
        )),
        _ => Err("unsupported pointer width"),
    }
}

fn decode(
    provider: Provider,
    version: u8,
    opcode: u8,
    pointer: usize,
    data: &[u8],
) -> Result<Option<Event>, &'static str> {
    if !matches!(pointer, 4 | 8) {
        return Err("unsupported pointer width");
    }
    match provider {
        Provider::Tcp | Provider::Udp => {
            if !matches!(opcode, 10 | 11 | 26 | 27) {
                return Ok(None);
            }
            if !matches!(version, 1 | 2) || (opcode >= 26 && version != 2) {
                return Err("unsupported network event version");
            }
            // Only consume the versioned fixed PID/size/IP/port prefix. Classic TCP v2
            // trailing connid fields can remain 32-bit on x64; they are not needed for byte totals.
            let minimum = if opcode >= 26 { 44 } else { 20 };
            if data.len() < minimum {
                return Err("truncated network event");
            }
            Ok(Some(Event::Network {
                pid: u32_at(data, 0)?,
                bytes: u32_at(data, 4)?,
                receive: matches!(opcode, 11 | 27),
            }))
        }
        Provider::Disk => {
            if !matches!(opcode, 10..=13) {
                return Ok(None);
            }
            // Version 3 adds issuing TID. Older completion/init layouts cannot safely establish this provenance.
            if version != 3 {
                return Err("unsupported disk event version");
            }
            if matches!(opcode, 12 | 13) {
                return Ok(Some(Event::DiskInit {
                    irp: pointer_at(data, 0, pointer)?,
                    tid: u32_at(data, pointer)?,
                    write: opcode == 13,
                }));
            }
            Ok(Some(Event::DiskDone {
                irp: pointer_at(data, 24 + pointer, pointer)?,
                tid: u32_at(data, 32 + pointer * 2)?,
                bytes: u32_at(data, 8)?,
                write: opcode == 11,
            }))
        }
        Provider::Thread => {
            if !matches!(opcode, 1..=4) {
                return Ok(None);
            }
            if !matches!(version, 2 | 3) {
                return Err("unsupported thread event version");
            }
            if data.len() < 12 + pointer * 7 {
                return Err("truncated thread event");
            }
            Ok(Some(Event::Thread {
                pid: u32_at(data, 0)?,
                tid: u32_at(data, 4)?,
                start: matches!(opcode, 1 | 3),
                rundown: matches!(opcode, 3 | 4),
            }))
        }
        Provider::Process => {
            if opcode != 2 {
                return Ok(None);
            }
            if !matches!(version, 2..=4) {
                return Err("unsupported process-end version");
            }
            Ok(Some(Event::ProcessEnd {
                pid: u32_at(data, pointer)?,
            }))
        }
    }
}

fn rates(old: Counters, new: Counters, elapsed: Duration) -> ProcessRates {
    if old.generation != new.generation {
        return ProcessRates::default();
    }
    ProcessRates {
        network_receive: counter_rate(old.receive, new.receive, elapsed),
        network_send: counter_rate(old.send, new.send, elapsed),
        disk_read: counter_rate(old.read, new.read, elapsed),
        disk_write: counter_rate(old.write, new.write, elapsed),
    }
}

#[derive(Clone, Copy)]
struct Lifetime {
    identity: Identity,
    end: Option<u64>,
}
#[derive(Clone, Copy)]
struct ThreadOwner {
    pid: u32,
    started: u64,
}
#[derive(Clone, Copy)]
struct Pending {
    owner: Option<Identity>,
    tid: u32,
    write: bool,
    started: u64,
}

#[derive(Clone, Copy, Debug, Default)]
struct Issues {
    unverified: u64,
    unmatched: u64,
    malformed: u64,
    overflow: u64,
    lost: u64,
}

#[derive(Default)]
struct Aggregate {
    active: HashMap<u32, Lifetime>,
    totals: HashMap<Identity, Counters>,
    threads: HashMap<u32, ThreadOwner>,
    irps: HashMap<u64, Pending>,
    issues: Issues,
    generation: u64,
    network_seen: bool,
    disk_seen: bool,
    last_schema_error: Option<String>,
}
impl Aggregate {
    fn install(&mut self, identity: Identity) {
        if identity.1 == 0 {
            return;
        }
        if self.totals.len() >= MAX_PROCESSES && !self.totals.contains_key(&identity) {
            self.overflow();
            return;
        }
        self.active.insert(
            identity.0,
            Lifetime {
                identity,
                end: None,
            },
        );
        self.totals.entry(identity).or_insert(Counters {
            generation: self.generation,
            ..Counters::default()
        });
    }
    fn end(&mut self, identity: Identity, timestamp: u64) {
        if let Some(lifetime) = self
            .active
            .get_mut(&identity.0)
            .filter(|entry| entry.identity == identity && timestamp >= identity.1)
        {
            lifetime.end = Some(lifetime.end.map_or(timestamp, |old| old.min(timestamp)));
        }
    }
    fn owner(&self, pid: u32, at: u64) -> Option<Identity> {
        let entry = self.active.get(&pid)?;
        (at >= entry.identity.1 && entry.end.is_none_or(|end| at <= end)).then_some(entry.identity)
    }
    fn thread_owner(&self, tid: u32, at: u64) -> Option<Identity> {
        let thread = self.threads.get(&tid)?;
        if at < thread.started {
            return None;
        }
        let owner = self.owner(thread.pid, at)?;
        // A pre-birth thread record belongs to a previous incarnation of this PID.
        (thread.started >= owner.1).then_some(owner)
    }
    fn overflow(&mut self) {
        self.issues.overflow = self.issues.overflow.saturating_add(1);
        self.generation = self.generation.wrapping_add(1);
    }
    fn add(&mut self, identity: Identity, bytes: u32, field: u8) {
        let Some(counter) = self.totals.get_mut(&identity) else {
            self.issues.unverified = self.issues.unverified.saturating_add(1);
            return;
        };
        let target = match field {
            0 => &mut counter.receive,
            1 => &mut counter.send,
            2 => &mut counter.read,
            _ => &mut counter.write,
        };
        match target.checked_add(u64::from(bytes)) {
            Some(value) => *target = value,
            None => {
                *target = 0;
                self.overflow();
            }
        }
    }
    fn event(&mut self, event: Event, timestamp: u64) {
        if timestamp == 0 {
            self.issues.malformed = self.issues.malformed.saturating_add(1);
            return;
        }
        match event {
            Event::Network {
                pid,
                bytes,
                receive,
            } => {
                self.network_seen = true;
                if let Some(owner) = self.owner(pid, timestamp) {
                    self.add(owner, bytes, if receive { 0 } else { 1 });
                } else {
                    self.issues.unverified = self.issues.unverified.saturating_add(1);
                }
            }
            Event::Thread {
                pid,
                tid,
                start,
                rundown,
            } => {
                if start {
                    if self.threads.len() >= MAX_THREADS && !self.threads.contains_key(&tid) {
                        self.overflow();
                        return;
                    }
                    if self
                        .threads
                        .get(&tid)
                        .is_none_or(|old| timestamp >= old.started)
                    {
                        self.threads.insert(
                            tid,
                            ThreadOwner {
                                pid,
                                started: timestamp,
                            },
                        );
                    }
                } else if !rundown
                    && self
                        .threads
                        .get(&tid)
                        .is_some_and(|old| old.pid == pid && timestamp >= old.started)
                {
                    self.threads.remove(&tid);
                }
            }
            Event::DiskInit { irp, tid, write } => {
                let owner = self.thread_owner(tid, timestamp);
                if owner.is_none() {
                    self.issues.unverified = self.issues.unverified.saturating_add(1);
                }
                if let Some(previous) = self.irps.get_mut(&irp) {
                    previous.owner = None;
                    self.issues.unmatched = self.issues.unmatched.saturating_add(1);
                    return;
                }
                if self.irps.len() >= MAX_IRPS {
                    self.overflow();
                    return;
                }
                self.irps.insert(
                    irp,
                    Pending {
                        owner,
                        tid,
                        write,
                        started: timestamp,
                    },
                );
            }
            Event::DiskDone {
                irp,
                tid,
                bytes,
                write,
            } => {
                self.disk_seen = true;
                let pending = self.irps.remove(&irp).filter(|pending| {
                    pending.tid == tid
                        && pending.write == write
                        && pending.started <= timestamp
                        && timestamp - pending.started <= IRP_TIMEOUT
                });
                if let Some(owner) = pending.and_then(|pending| pending.owner) {
                    self.add(owner, bytes, if write { 3 } else { 2 });
                } else {
                    self.issues.unmatched = self.issues.unmatched.saturating_add(1);
                }
            }
            Event::ProcessEnd { pid } => {
                if let Some(owner) = self.owner(pid, timestamp) {
                    self.end(owner, timestamp);
                }
            }
        }
    }
    fn counters(&self, identity: Identity) -> Option<Counters> {
        self.totals.get(&identity).map(|counter| Counters {
            generation: self.generation,
            ..*counter
        })
    }
    fn note_loss(&mut self, lost: u64) {
        if lost <= self.issues.lost {
            return;
        }
        self.issues.lost = lost;
        self.threads.clear();
        self.irps.clear();
        // Lost thread lifecycle events invalidate provenance. Keep only newly observed thread lifetimes.
        self.generation = self.generation.wrapping_add(1);
    }
    fn prune(&mut self, live: &HashSet<Identity>, now: u64) {
        self.totals.retain(|identity, _| live.contains(identity));
        self.active
            .retain(|_, lifetime| live.contains(&lifetime.identity));
        let live_pids: HashSet<_> = live.iter().map(|identity| identity.0).collect();
        // Initial DCStart may precede the first sampler identity installation. Preserve that rundown.
        self.threads
            .retain(|_, owner| live_pids.contains(&owner.pid));
        let previous = self.irps.len();
        self.irps
            .retain(|_, pending| now.saturating_sub(pending.started) <= IRP_TIMEOUT);
        self.issues.unmatched = self
            .issues
            .unmatched
            .saturating_add((previous - self.irps.len()) as u64);
    }
}

fn same_guid(a: GUID, b: GUID) -> bool {
    a.data1 == b.data1 && a.data2 == b.data2 && a.data3 == b.data3 && a.data4 == b.data4
}
fn guid_number(guid: GUID) -> u128 {
    (u128::from(guid.data1) << 96)
        | (u128::from(guid.data2) << 80)
        | (u128::from(guid.data3) << 64)
        | u128::from(u64::from_be_bytes(guid.data4))
}
fn error(context: &str, code: u32) -> String {
    format!(
        "{context}: {} (Win32 {code})",
        io::Error::from_raw_os_error(code as i32)
    )
}
fn now_filetime() -> u64 {
    let mut value = FILETIME::default();
    // SAFETY: value is writable FILETIME storage.
    unsafe {
        GetSystemTimeAsFileTime(&mut value);
    }
    filetime(value)
}

fn process_times(handle: windows_sys::Win32::Foundation::HANDLE) -> Result<(u64, u64), String> {
    let mut created = FILETIME::default();
    let mut exited = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: handle is a query-capable process handle or the current-process pseudo handle; all output pointers are valid.
    if unsafe { GetProcessTimes(handle, &mut created, &mut exited, &mut kernel, &mut user) } == 0 {
        return Err(format!(
            "Verify activity process identity: {}",
            io::Error::last_os_error()
        ));
    }
    Ok((filetime(created), filetime(exited)))
}

#[repr(C)]
struct Properties {
    header: EVENT_TRACE_PROPERTIES,
    name: [u16; 1024],
    file: [u16; 1024],
}
impl Properties {
    fn new() -> Box<Self> {
        let mut value = Box::new(Self {
            header: EVENT_TRACE_PROPERTIES::default(),
            name: [0; 1024],
            file: [0; 1024],
        });
        value.header.Wnode.BufferSize = size_of::<Self>() as u32;
        value.header.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        value.header.LoggerNameOffset = offset_of!(Self, name) as u32;
        value
    }
    fn name(&self) -> Option<String> {
        let offset = self.header.LoggerNameOffset as usize;
        if offset % 2 != 0
            || offset < size_of::<EVENT_TRACE_PROPERTIES>()
            || offset >= size_of::<Self>()
        {
            return None;
        }
        // SAFETY: validated even offset and remaining length are within this live, aligned properties allocation.
        let text = unsafe {
            std::slice::from_raw_parts(
                (self as *const Self).cast::<u8>().add(offset).cast::<u16>(),
                (size_of::<Self>() - offset) / 2,
            )
        };
        let length = text.iter().position(|&x| x == 0)?;
        String::from_utf16(&text[..length]).ok()
    }
}

fn stale_candidate(
    name: &str,
    properties: &EVENT_TRACE_PROPERTIES,
    session_id: u32,
) -> Option<Identity> {
    let mut fields = name.strip_prefix(SESSION_PREFIX)?.split('.');
    let logon: u32 = fields.next()?.strip_prefix('s')?.parse().ok()?;
    let pid: u32 = fields.next()?.parse().ok()?;
    let birth: u64 = fields.next()?.parse().ok()?;
    let guid_text = fields.next()?;
    if fields.next().is_some()
        || logon != session_id
        || pid == 0
        || birth == 0
        || guid_text.len() != 32
    {
        return None;
    }
    let guid = GUID::from_u128(u128::from_str_radix(guid_text, 16).ok()?);
    if !same_guid(guid, properties.Wnode.Guid)
        || properties.EnableFlags != TRACE_FLAGS
        || properties.LogFileMode != TRACE_MODE
        || properties.LogFileNameOffset != 0
        || properties.BufferSize != 64
    {
        return None;
    }
    Some((pid, birth))
}

fn owner_proven_dead(identity: Identity) -> bool {
    // SAFETY: read-only process query, no inheritance, no process mutation.
    let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, identity.0) };
    if raw.is_null() {
        return io::Error::last_os_error().raw_os_error() == Some(ERROR_INVALID_PARAMETER as i32);
    }
    let Ok(handle) = Handle::new(raw) else {
        return false;
    };
    matches!(process_times(handle.raw()), Ok((created, exited)) if created != identity.1 || exited != 0)
}

fn cleanup_stale_sessions(session_id: u32) {
    // Enumerate read-only. Every stop is restricted to our exact namespace, GUID, flags, no-file mode and proven-dead owner.
    let mut properties: Vec<_> = (0..128).map(|_| Properties::new()).collect();
    let mut pointers: Vec<_> = properties
        .iter_mut()
        .map(|properties| &mut properties.header as *mut _)
        .collect();
    let mut count = 0;
    // SAFETY: each pointer references a complete independently owned writable properties buffer.
    let result =
        unsafe { QueryAllTracesW(pointers.as_mut_ptr(), pointers.len() as u32, &mut count) };
    if result != 0 && result != ERROR_MORE_DATA {
        return;
    }
    for properties in properties.iter_mut().take(count.min(128) as usize) {
        let Some(name) = properties.name() else {
            continue;
        };
        let Some(identity) = stale_candidate(&name, &properties.header, session_id) else {
            continue;
        };
        if !owner_proven_dead(identity) {
            continue;
        }
        let mut current = Properties::new();
        let name = wide(&name);
        // SAFETY: read-only re-query by the exact validated name before any stop, never a global/generic session.
        if unsafe {
            ControlTraceW(
                CONTROLTRACE_HANDLE::default(),
                name.as_ptr(),
                &mut current.header,
                EVENT_TRACE_CONTROL_QUERY,
            )
        } != 0
        {
            continue;
        }
        let Some(current_name) = current.name() else {
            continue;
        };
        if stale_candidate(&current_name, &current.header, session_id) != Some(identity)
            || !same_guid(current.header.Wnode.Guid, properties.header.Wnode.Guid)
            || !owner_proven_dead(identity)
        {
            continue;
        }
        current.header.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        current.header.LogFileNameOffset = 0;
        // SAFETY: this is exclusively an orphaned AnVirNext activity session whose immutable GUID/owner were checked twice.
        unsafe {
            ControlTraceW(
                CONTROLTRACE_HANDLE::default(),
                name.as_ptr(),
                &mut current.header,
                EVENT_TRACE_CONTROL_STOP,
            );
        }
    }
}

struct Shared {
    aggregate: Mutex<Aggregate>,
    stop: AtomicBool,
    started: AtomicBool,
    done: AtomicBool,
    failure: Mutex<Option<String>>,
    reader: AtomicU64,
}
impl Default for Shared {
    fn default() -> Self {
        Self {
            aggregate: Mutex::new(Aggregate::default()),
            stop: AtomicBool::new(false),
            started: AtomicBool::new(false),
            done: AtomicBool::new(false),
            failure: Mutex::new(None),
            reader: AtomicU64::new(u64::MAX),
        }
    }
}
impl Shared {
    fn fail(&self, message: String) {
        if let Ok(mut failure) = self.failure.lock() {
            *failure = Some(message);
        }
    }
}

unsafe extern "system" fn event_callback(record: *mut EVENT_RECORD) {
    if record.is_null() {
        return;
    }
    // SAFETY: ETW calls this with a live record; UserContext is the Shared pointer registered in OpenTrace.
    let (record, shared) = unsafe {
        let record = &*record;
        if record.UserContext.is_null() {
            return;
        }
        (record, &*record.UserContext.cast::<Shared>())
    };
    if shared.stop.load(Ordering::Relaxed) {
        return;
    }
    let header = &record.EventHeader;
    let provider = if same_guid(header.ProviderId, TCP_GUID) {
        Provider::Tcp
    } else if same_guid(header.ProviderId, UDP_GUID) {
        Provider::Udp
    } else if same_guid(header.ProviderId, DISK_GUID) {
        Provider::Disk
    } else if same_guid(header.ProviderId, THREAD_GUID) {
        Provider::Thread
    } else if same_guid(header.ProviderId, PROCESS_GUID) {
        Provider::Process
    } else {
        return;
    };
    let Ok(mut aggregate) = shared.aggregate.lock() else {
        shared.fail("ETW activity aggregator lock was poisoned".into());
        return;
    };
    let pointer = if header.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER as u16 != 0 {
        4
    } else {
        8
    };
    let result = if record.UserData.is_null() && record.UserDataLength != 0 {
        Err("null ETW payload")
    } else {
        // SAFETY: ETW guarantees UserDataLength readable bytes for the duration of this callback; zero-length null is handled separately.
        let data = if record.UserDataLength == 0 {
            &[]
        } else {
            // SAFETY: ETW owns this non-null payload with the advertised readable length for this callback.
            unsafe {
                std::slice::from_raw_parts(
                    record.UserData.cast::<u8>(),
                    record.UserDataLength as usize,
                )
            }
        };
        decode(
            provider,
            header.EventDescriptor.Version,
            header.EventDescriptor.Opcode,
            pointer,
            data,
        )
    };
    match result {
        Ok(Some(event)) if header.TimeStamp > 0 => aggregate.event(event, header.TimeStamp as u64),
        Ok(None) => {}
        _ => {
            aggregate.issues.malformed = aggregate.issues.malformed.saturating_add(1);
            if aggregate.last_schema_error.is_none() {
                aggregate.last_schema_error = Some(format!(
                    "{provider:?} version {} opcode {} length {}: {}",
                    header.EventDescriptor.Version,
                    header.EventDescriptor.Opcode,
                    record.UserDataLength,
                    result.err().unwrap_or("invalid timestamp")
                ));
            }
        }
    }
}

unsafe extern "system" fn buffer_callback(logfile: *mut EVENT_TRACE_LOGFILEW) -> u32 {
    if logfile.is_null() {
        return 0;
    }
    // SAFETY: ETW owns the live logfile record; Context is the stable Arc allocation registered before ProcessTrace.
    let (logfile, shared) = unsafe {
        let logfile = &*logfile;
        if logfile.Context.is_null() {
            return 0;
        }
        (logfile, &*logfile.Context.cast::<Shared>())
    };
    if logfile.EventsLost > 0 {
        if let Ok(mut aggregate) = shared.aggregate.lock() {
            aggregate.note_loss(u64::from(logfile.EventsLost));
        }
    }
    u32::from(!shared.stop.load(Ordering::Acquire))
}

struct Session {
    controller: CONTROLTRACE_HANDLE,
    name: Vec<u16>,
    guid: GUID,
    consumer: Option<JoinHandle<()>>,
    shared: Arc<Shared>,
}
impl Session {
    fn start(shared: Arc<Shared>) -> Result<Self, String> {
        let mut guid = GUID::default();
        // SAFETY: CoCreateGuid requires no COM apartment and writes one GUID.
        let result = unsafe { CoCreateGuid(&mut guid) };
        if result < 0 {
            return Err(format!("Create ETW session identity: HRESULT {result:#x}"));
        }
        // SAFETY: pseudo current-process handle is borrowed, never closed.
        let birth = process_times(unsafe { GetCurrentProcess() })?.0;
        // SAFETY: GetCurrentProcessId has no parameters.
        let pid = unsafe { GetCurrentProcessId() };
        let mut logon = 0;
        // SAFETY: valid current PID and writable session-id storage. A failure leaves the namespace at session zero.
        unsafe {
            ProcessIdToSessionId(pid, &mut logon);
        }
        cleanup_stale_sessions(logon);
        let name = wide(&format!(
            "{SESSION_PREFIX}s{logon}.{pid}.{birth}.{:032x}",
            guid_number(guid)
        ));
        let mut properties = Properties::new();
        properties.header.Wnode.Guid = guid;
        properties.header.Wnode.ClientContext = 1; // QPC; ProcessTrace converts event timestamps to FILETIME.
        properties.header.BufferSize = 64;
        properties.header.MinimumBuffers = 16;
        properties.header.MaximumBuffers = 64;
        properties.header.FlushTimer = 1;
        properties.header.LogFileMode = TRACE_MODE;
        properties.header.EnableFlags = TRACE_FLAGS;
        let mut controller = CONTROLTRACE_HANDLE::default();
        // SAFETY: complete writable properties/name allocation; no ETL file offset or global logger GUID/name.
        let result = unsafe { StartTraceW(&mut controller, name.as_ptr(), &mut properties.header) };
        if result != 0 {
            return Err(error(
                if result == ERROR_ACCESS_DENIED {
                    "ETW Network/Disk unavailable; run AnVir Next as administrator"
                } else {
                    "Start private ETW Network/Disk session"
                },
                result,
            ));
        }
        let mut session = Self {
            controller,
            name: name.clone(),
            guid,
            consumer: None,
            shared: shared.clone(),
        };
        let (sender, receiver) = mpsc::sync_channel(1);
        session.consumer = Some(
            thread::Builder::new()
                .name("anvir-activity-etw".into())
                .spawn(move || {
                    let mut name = name;
                    let mut logfile = EVENT_TRACE_LOGFILEW {
                        LoggerName: name.as_mut_ptr(),
                        ..EVENT_TRACE_LOGFILEW::default()
                    };
                    logfile.Anonymous1.ProcessTraceMode =
                        PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
                    logfile.Anonymous2.EventRecordCallback = Some(event_callback);
                    logfile.BufferCallback = Some(buffer_callback);
                    logfile.Context = Arc::as_ptr(&shared).cast_mut().cast::<c_void>();
                    // SAFETY: logfile/name/Shared remain live on this consumer thread until ProcessTrace returns.
                    let reader = unsafe { OpenTraceW(&mut logfile) };
                    if reader.Value == u64::MAX {
                        let message =
                            format!("Open private ETW consumer: {}", io::Error::last_os_error());
                        shared.fail(message.clone());
                        let _ = sender.send(Err(message));
                        shared.done.store(true, Ordering::Release);
                        return;
                    }
                    if shared.stop.load(Ordering::Acquire) {
                        // SAFETY: reader belongs exclusively to this just-opened consumer and was not published.
                        unsafe {
                            CloseTrace(reader);
                        }
                        shared.done.store(true, Ordering::Release);
                        return;
                    }
                    shared.reader.store(reader.Value, Ordering::Release);
                    if sender.send(Ok(())).is_err() {
                        // SAFETY: no controller received this handle, so this consumer closes it.
                        let value = shared.reader.swap(u64::MAX, Ordering::AcqRel);
                        if value != u64::MAX {
                            // SAFETY: this thread atomically claimed closing ownership for the unpublished reader.
                            unsafe {
                                CloseTrace(PROCESSTRACE_HANDLE { Value: value });
                            }
                        }
                        shared.done.store(true, Ordering::Release);
                        return;
                    }
                    shared.started.store(true, Ordering::Release);
                    // SAFETY: one valid reader; synchronous callbacks borrow this thread's live logfile/Shared allocation.
                    let result = unsafe { ProcessTrace(&reader, 1, ptr::null(), ptr::null()) };
                    if !shared.stop.load(Ordering::Acquire) {
                        shared.fail(if result == 0 {
                            "ETW activity session stopped unexpectedly".into()
                        } else {
                            error("Read ETW activity", result)
                        });
                    }
                    let value = shared.reader.swap(u64::MAX, Ordering::AcqRel);
                    if value != u64::MAX {
                        // SAFETY: atomically claimed closing ownership; the controller has not closed this handle.
                        unsafe {
                            CloseTrace(PROCESSTRACE_HANDLE { Value: value });
                        }
                    }
                    shared.done.store(true, Ordering::Release);
                })
                .map_err(|e| format!("Start ETW consumer thread: {e}"))?,
        );
        receiver
            .recv_timeout(Duration::from_secs(3))
            .map_err(|_| "ETW consumer initialization timed out".to_string())??;
        Ok(session)
    }
    fn query_loss(&self) -> Result<u64, String> {
        let mut properties = Properties::new();
        // SAFETY: query targets only the successfully created private session handle, using a complete writable buffer.
        let result = unsafe {
            ControlTraceW(
                self.controller,
                self.name.as_ptr(),
                &mut properties.header,
                EVENT_TRACE_CONTROL_QUERY,
            )
        };
        if result != 0 {
            return Err(error("Query private ETW session", result));
        }
        if !same_guid(properties.header.Wnode.Guid, self.guid) {
            return Err("ETW session ownership changed; activity is unavailable".into());
        }
        Ok(u64::from(properties.header.EventsLost)
            + u64::from(properties.header.RealTimeBuffersLost))
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::Release);
        let reader = self.shared.reader.swap(u64::MAX, Ordering::AcqRel);
        if reader != u64::MAX {
            // SAFETY: this is our published real-time reader, closed once; pending callbacks retain their Arc allocation.
            unsafe {
                CloseTrace(PROCESSTRACE_HANDLE { Value: reader });
            }
        }
        let mut properties = Properties::new();
        // SAFETY: read-only lookup of our GUID-bearing unique name before stopping; never target an opaque handle that could have been reused.
        if unsafe {
            ControlTraceW(
                CONTROLTRACE_HANDLE::default(),
                self.name.as_ptr(),
                &mut properties.header,
                EVENT_TRACE_CONTROL_QUERY,
            )
        } == 0
            && same_guid(properties.header.Wnode.Guid, self.guid)
        {
            properties.header.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
            properties.header.LogFileNameOffset = 0;
            // SAFETY: exact GUID-validated private name; no unrelated logger can match this session identity.
            unsafe {
                ControlTraceW(
                    CONTROLTRACE_HANDLE::default(),
                    self.name.as_ptr(),
                    &mut properties.header,
                    EVENT_TRACE_CONTROL_STOP,
                );
            }
        }
        if let Some(consumer) = self.consumer.take() {
            let deadline = Instant::now() + Duration::from_secs(2);
            while !consumer.is_finished() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(5));
            }
            if consumer.is_finished() {
                let _ = consumer.join();
            }
            // In the exceptional timeout case detach safely: the consumer owns all callback context/name allocations.
        }
    }
}

/// Construct and sample on the existing collector thread. Only ProcessTrace needs a dedicated blocking thread.
pub struct ActivityMonitor {
    session: Option<Session>,
    shared: Arc<Shared>,
    handles: HashMap<Identity, Handle>,
    denied: HashSet<Identity>,
    previous: HashMap<Identity, Counters>,
    sampled_at: Option<Instant>,
    failure: Option<String>,
    observed_issues: Issues,
    recent_partial: bool,
    recent_loss: bool,
}
impl Default for ActivityMonitor {
    fn default() -> Self {
        Self::new()
    }
}
impl ActivityMonitor {
    pub fn new() -> Self {
        let shared = Arc::new(Shared::default());
        let (session, failure) = match Session::start(shared.clone()) {
            Ok(session) => (Some(session), None),
            Err(error) => (None, Some(error)),
        };
        Self {
            session,
            shared,
            handles: HashMap::new(),
            denied: HashSet::new(),
            previous: HashMap::new(),
            sampled_at: None,
            failure,
            observed_issues: Issues::default(),
            recent_partial: false,
            recent_loss: false,
        }
    }
    pub fn sample(
        &mut self,
        identities: impl IntoIterator<Item = Identity>,
    ) -> HashMap<Identity, ProcessRates> {
        let now = Instant::now();
        let elapsed = self.sampled_at.map(|previous| now.duration_since(previous));
        self.sampled_at = Some(now);
        let live: HashSet<_> = identities
            .into_iter()
            .filter(|&(_, created)| created != 0)
            .take(MAX_PROCESSES)
            .collect();
        if let Some(session) = &self.session {
            match session.query_loss() {
                Ok(lost) => {
                    if let Ok(mut aggregate) = self.shared.aggregate.lock() {
                        aggregate.note_loss(lost);
                    }
                }
                Err(error) => self.failure = Some(error),
            }
        }
        if self.session.is_none()
            || self.failure.is_some()
            || self.shared.done.load(Ordering::Acquire)
        {
            return live
                .into_iter()
                .map(|identity| (identity, ProcessRates::default()))
                .collect();
        }
        // Handle verification is performed only once per newly observed identity, outside the callback's lock.
        self.denied.retain(|identity| live.contains(identity));
        let mut installed = Vec::new();
        for &identity in &live {
            if self.handles.contains_key(&identity) || self.denied.contains(&identity) {
                continue;
            }
            // SAFETY: read-only query rights, non-inheritable handle; PID is from the current native process snapshot.
            let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, identity.0) };
            let handle = match Handle::new(raw) {
                Ok(handle) => handle,
                Err(_) => {
                    self.denied.insert(identity);
                    continue;
                }
            };
            match process_times(handle.raw()) {
                Ok((created, exited)) if created == identity.1 && exited == 0 => {
                    self.handles.insert(identity, handle);
                    installed.push(identity);
                }
                _ => {
                    self.denied.insert(identity);
                }
            }
        }
        let mut ended = Vec::new();
        self.handles.retain(|identity, handle| {
            if live.contains(identity) {
                return true;
            }
            if let Ok((created, exited)) = process_times(handle.raw()) {
                if created == identity.1 && exited != 0 {
                    ended.push((*identity, exited));
                }
            }
            false
        });
        let Ok(mut aggregate) = self.shared.aggregate.lock() else {
            self.failure = Some("ETW activity aggregator lock was poisoned".into());
            return live
                .into_iter()
                .map(|identity| (identity, ProcessRates::default()))
                .collect();
        };
        for (identity, exited) in ended {
            aggregate.end(identity, exited);
        }
        aggregate.prune(&live, now_filetime());
        for identity in installed {
            aggregate.install(identity);
        }
        let mut previous = HashMap::with_capacity(live.len());
        let mut result = HashMap::with_capacity(live.len());
        for identity in live {
            let mut value = ProcessRates::default();
            if let Some(current) = aggregate.counters(identity) {
                if let Some((old, elapsed)) = self.previous.get(&identity).zip(elapsed) {
                    value = rates(*old, current, elapsed);
                }
                if !aggregate.network_seen {
                    value.network_receive = None;
                    value.network_send = None;
                }
                if !aggregate.disk_seen {
                    value.disk_read = None;
                    value.disk_write = None;
                }
                previous.insert(identity, current);
            }
            result.insert(identity, value);
        }
        self.previous = previous;
        let issues = aggregate.issues;
        self.recent_loss = issues.lost > self.observed_issues.lost
            || issues.overflow > self.observed_issues.overflow;
        self.recent_partial = elapsed.is_some()
            && (issues.unverified > self.observed_issues.unverified
                || issues.unmatched > self.observed_issues.unmatched
                || issues.malformed > self.observed_issues.malformed);
        self.observed_issues = issues;
        result
    }
    pub fn status(&self) -> Option<String> {
        self.status_for(true)
    }

    pub(crate) fn disk_status(&self) -> Option<String> {
        self.status_for(false)
    }

    fn status_for(&self, include_network: bool) -> Option<String> {
        let subject = if include_network {
            "Данные сети и диска"
        } else {
            "Данные диска по процессам"
        };
        if let Some(failure) = &self.failure {
            return Some(if failure.contains("as administrator") {
                format!("{subject} недоступны: нужны права администратора")
            } else {
                format!("{subject} недоступны")
            });
        }
        if let Ok(failure) = self.shared.failure.lock() {
            if failure.is_some() {
                return Some(format!("{subject} недоступны"));
            }
        }
        let aggregate = match self.shared.aggregate.lock() {
            Ok(aggregate) => aggregate,
            Err(_) => return Some(format!("{subject} недоступны")),
        };
        if self.recent_loss {
            return Some("Часть событий активности потеряна; данные временно неполные".into());
        }
        if self.recent_partial {
            return Some("Часть данных недоступна".into());
        }
        if !self.denied.is_empty() {
            return Some("Статистика части системных процессов недоступна".into());
        }
        if !self.shared.started.load(Ordering::Acquire)
            || include_network && !aggregate.network_seen
            || !aggregate.disk_seen
        {
            return Some(
                if include_network {
                    "Ожидание данных сети и диска"
                } else {
                    "Ожидание данных диска"
                }
                .into(),
            );
        }
        None
    }
}

fn disk_fixture() -> Result<(), String> {
    use std::{
        fs::OpenOptions,
        io::{Read, Seek, SeekFrom, Write},
        os::windows::fs::OpenOptionsExt,
    };
    use windows_sys::Win32::{
        Storage::FileSystem::{FILE_FLAG_NO_BUFFERING, FILE_FLAG_WRITE_THROUGH},
        System::Memory::{
            MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE, VirtualAlloc, VirtualFree,
        },
    };
    struct Aligned(*mut c_void);
    impl Drop for Aligned {
        fn drop(&mut self) {
            // SAFETY: this owns one complete VirtualAlloc allocation, released once with MEM_RELEASE and size zero.
            unsafe {
                VirtualFree(self.0, 0, MEM_RELEASE);
            }
        }
    }
    let path = std::env::temp_dir().join(format!(
        "AnVirNext-activity-{}-{}.tmp",
        std::process::id(),
        now_filetime()
    ));
    let mut created = false;
    let result = (|| {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .custom_flags(FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH)
            .open(&path)
            .map_err(|e| format!("Create isolated disk fixture: {e}"))?;
        created = true;
        // SAFETY: a 64 KiB committed/reserved allocation, page-aligned for uncached disk I/O, no executable permission.
        let memory =
            unsafe { VirtualAlloc(ptr::null(), 65536, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE) };
        if memory.is_null() {
            return Err(format!(
                "Allocate aligned disk fixture buffer: {}",
                io::Error::last_os_error()
            ));
        }
        let memory = Aligned(memory);
        // SAFETY: the allocation owns 65536 writable bytes and no other references exist.
        let buffer = unsafe { std::slice::from_raw_parts_mut(memory.0.cast::<u8>(), 65536) };
        buffer.fill(0x5a);
        for _ in 0..64 {
            file.write_all(buffer)
                .map_err(|e| format!("Write uncached fixture: {e}"))?;
        }
        file.sync_all().map_err(|e| format!("Flush fixture: {e}"))?;
        file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
        for _ in 0..64 {
            file.read_exact(buffer)
                .map_err(|e| format!("Read uncached fixture: {e}"))?;
        }
        Ok(())
    })();
    if created {
        if let Err(error) = std::fs::remove_file(&path) {
            return Err(format!(
                "{result:?}; remove isolated fixture {}: {error}",
                path.display()
            ));
        }
    }
    result
}

fn network_fixture(ipv6: bool) -> Result<(), String> {
    use std::{
        io::{Read, Write},
        net::{TcpListener, TcpStream, UdpSocket},
    };
    let address = if ipv6 { "[::1]:0" } else { "127.0.0.1:0" };
    let listener =
        TcpListener::bind(address).map_err(|e| format!("Bind local TCP fixture: {e}"))?;
    let mut client = TcpStream::connect_timeout(
        &listener.local_addr().map_err(|e| e.to_string())?,
        Duration::from_secs(2),
    )
    .map_err(|e| e.to_string())?;
    let (mut server, _) = listener.accept().map_err(|e| e.to_string())?;
    for socket in [&server, &client] {
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .map_err(|e| e.to_string())?;
        socket
            .set_write_timeout(Some(Duration::from_secs(2)))
            .map_err(|e| e.to_string())?;
    }
    let echo = thread::spawn(move || -> io::Result<()> {
        let mut buffer = vec![0u8; 1024 * 1024];
        server.read_exact(&mut buffer)?;
        server.write_all(&buffer)
    });
    let mut buffer = vec![0x33u8; 1024 * 1024];
    let client_result = client
        .write_all(&buffer)
        .and_then(|_| client.read_exact(&mut buffer));
    let server_result = echo.join().map_err(|_| "TCP fixture thread failed")?;
    client_result.map_err(|e| format!("Local TCP fixture: {e}"))?;
    server_result.map_err(|e| format!("Local TCP echo: {e}"))?;
    let a = UdpSocket::bind(address).map_err(|e| e.to_string())?;
    let b = UdpSocket::bind(address).map_err(|e| e.to_string())?;
    for socket in [&a, &b] {
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .map_err(|e| e.to_string())?;
    }
    let mut packet = [0x44u8; 1024];
    for _ in 0..16 {
        a.send_to(&packet, b.local_addr().map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        let (_, source) = b.recv_from(&mut packet).map_err(|e| e.to_string())?;
        b.send_to(&packet, source).map_err(|e| e.to_string())?;
        a.recv_from(&mut packet).map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Explicit diagnostic only: a disposable 4 MiB uncached file and local TCP/UDP traffic.
/// No external destinations, packet payload collection, user-file reads or trace files.
pub fn diagnose_activity() -> String {
    let mut monitor = ActivityMonitor::new();
    if monitor.session.is_none() {
        return format!(
            "ETW fixture unavailable: {}; detail={:?}",
            monitor
                .status()
                .unwrap_or_else(|| "initialization failed".into()),
            monitor.failure
        );
    }
    let mut sampler = crate::processes::ProcessSampler::default();
    let mut identities = || {
        sampler
            .sample_names()
            .unwrap_or_default()
            .into_iter()
            .map(|(identity, _)| identity)
    };
    let initial: Vec<_> = identities().collect();
    let pid = std::process::id();
    let Some(identity) = initial.iter().copied().find(|&(current, _)| current == pid) else {
        return "ETW fixture failed: current native process identity unavailable".into();
    };
    monitor.sample(initial);
    thread::sleep(Duration::from_millis(1200));
    monitor.sample(identities());
    let before = monitor
        .shared
        .aggregate
        .lock()
        .ok()
        .and_then(|aggregate| aggregate.counters(identity))
        .unwrap_or_default();
    let disk = disk_fixture();
    let ipv4 = network_fixture(false);
    let ipv6 = network_fixture(true);
    thread::sleep(Duration::from_millis(1500));
    let measured = monitor
        .sample(identities())
        .get(&identity)
        .copied()
        .unwrap_or_default();
    let after = monitor
        .shared
        .aggregate
        .lock()
        .ok()
        .and_then(|aggregate| aggregate.counters(identity))
        .unwrap_or_default();
    let received_bytes = after.receive.saturating_sub(before.receive);
    let sent_bytes = after.send.saturating_sub(before.send);
    // Each local TCP echo accounts for 2 MiB in each direction to this same process.
    // Both families must be visible; UDP-only traffic must never make this diagnostic pass.
    let passed = disk.is_ok()
        && ipv4.is_ok()
        && ipv6.is_ok()
        && received_bytes >= 4 * 1024 * 1024
        && sent_bytes >= 4 * 1024 * 1024
        && [
            measured.network_receive,
            measured.network_send,
            measured.disk_read,
            measured.disk_write,
        ]
        .into_iter()
        .all(|value| value.is_some_and(|value| value > 0.));
    let diagnostics = monitor
        .shared
        .aggregate
        .lock()
        .map(|aggregate| {
            format!(
                "threads={}, pending_irps={}, issues={:?}, schema_error={:?}",
                aggregate.threads.len(),
                aggregate.irps.len(),
                aggregate.issues,
                aggregate.last_schema_error
            )
        })
        .unwrap_or_else(|_| "aggregator poisoned".into());
    format!(
        "ETW fixture {}: pid={}, receive={:?} B/s, send={:?} B/s, disk_read={:?} B/s, disk_write={:?} B/s; received_bytes={received_bytes}, sent_bytes={sent_bytes}; disk={disk:?}; IPv4={ipv4:?}; IPv6={ipv6:?}; {diagnostics}; status={:?}",
        if passed { "passed" } else { "failed" },
        pid,
        measured.network_receive,
        measured.network_send,
        measured.disk_read,
        measured.disk_write,
        monitor.status()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(pid: u32, bytes: u32, receive: bool) -> Event {
        Event::Network {
            pid,
            bytes,
            receive,
        }
    }

    #[test]
    fn activity_network_schema_reads_payload_pid_and_both_address_families() {
        for (provider, opcode, receive, length) in [
            (Provider::Tcp, 10, false, 40),
            (Provider::Tcp, 11, true, 32),
            (Provider::Tcp, 26, false, 64),
            (Provider::Tcp, 27, true, 56),
            (Provider::Udp, 10, false, 20),
            (Provider::Udp, 11, true, 20),
            (Provider::Udp, 26, false, 56),
            (Provider::Udp, 27, true, 56),
        ] {
            let mut bytes = vec![0; length];
            bytes[..4].copy_from_slice(&42u32.to_le_bytes());
            bytes[4..8].copy_from_slice(&8192u32.to_le_bytes());
            assert_eq!(
                decode(provider, 2, opcode, 8, &bytes).unwrap(),
                Some(net(42, 8192, receive))
            );
            assert!(decode(provider, 2, opcode, 8, &bytes[..7]).is_err());
            assert!(decode(provider, 99, opcode, 8, &bytes).is_err());
        }
        assert_eq!(
            decode(Provider::Tcp, 2, 14, 8, &[0; 32]).unwrap(),
            None,
            "retransmits must not be counted twice"
        );
    }

    #[test]
    fn activity_win11_tcp_fixed_prefix_does_not_assume_connection_id_pointer_width() {
        // Observed on the elevated Win11 fixture: classic TCP v2 receive is 28 bytes even on x64.
        // The consumed PID/size/address/port prefix is identical; trailing connid layout is irrelevant.
        for (opcode, length) in [(10, 36), (11, 28), (26, 60), (27, 52)] {
            let mut bytes = vec![0; length];
            bytes[..4].copy_from_slice(&42u32.to_le_bytes());
            bytes[4..8].copy_from_slice(&65536u32.to_le_bytes());
            assert_eq!(
                decode(Provider::Tcp, 2, opcode, 8, &bytes).unwrap(),
                Some(net(42, 65536, matches!(opcode, 11 | 27)))
            );
            let prefix = if opcode >= 26 { 44 } else { 20 };
            assert!(decode(Provider::Tcp, 2, opcode, 8, &bytes[..prefix - 1]).is_err());
        }
    }

    #[test]
    fn activity_disk_schema_respects_pointer_width_and_issuing_thread() {
        for pointer in [4, 8] {
            let mut init = vec![0; pointer + 4];
            init[0] = 0x34;
            init[1] = 0x12;
            init[pointer..].copy_from_slice(&77u32.to_le_bytes());
            assert_eq!(
                decode(Provider::Disk, 3, 12, pointer, &init).unwrap(),
                Some(Event::DiskInit {
                    irp: 0x1234,
                    tid: 77,
                    write: false
                })
            );
            let mut completion = vec![0; 36 + pointer * 2];
            completion[8..12].copy_from_slice(&4096u32.to_le_bytes());
            completion[24 + pointer] = 0x34;
            completion[25 + pointer] = 0x12;
            completion[32 + pointer * 2..36 + pointer * 2].copy_from_slice(&77u32.to_le_bytes());
            assert_eq!(
                decode(Provider::Disk, 3, 10, pointer, &completion).unwrap(),
                Some(Event::DiskDone {
                    irp: 0x1234,
                    tid: 77,
                    bytes: 4096,
                    write: false
                })
            );
            assert!(decode(Provider::Disk, 3, 10, pointer, &completion[..20]).is_err());
        }
    }

    #[test]
    fn activity_pid_reuse_and_queued_events_never_cross_process_births() {
        let mut aggregate = Aggregate::default();
        aggregate.install((42, 100));
        aggregate.event(net(42, 10, true), 150);
        aggregate.end((42, 100), 200);
        aggregate.install((42, 300));
        aggregate.event(net(42, 999, true), 199);
        aggregate.event(net(42, 888, true), 250);
        aggregate.event(net(42, 20, true), 350);
        assert_eq!(aggregate.counters((42, 100)).unwrap().receive, 10);
        assert_eq!(aggregate.counters((42, 300)).unwrap().receive, 20);
    }

    #[test]
    fn activity_disk_completion_uses_saved_irp_owner_after_thread_exit_and_reuse() {
        let mut aggregate = Aggregate::default();
        aggregate.install((42, 100));
        aggregate.install((88, 100));
        aggregate.event(
            Event::Thread {
                pid: 42,
                tid: 77,
                start: true,
                rundown: false,
            },
            110,
        );
        aggregate.event(
            Event::DiskInit {
                irp: 123,
                tid: 77,
                write: true,
            },
            120,
        );
        aggregate.event(
            Event::Thread {
                pid: 42,
                tid: 77,
                start: false,
                rundown: false,
            },
            130,
        );
        aggregate.event(
            Event::Thread {
                pid: 88,
                tid: 77,
                start: true,
                rundown: false,
            },
            140,
        );
        aggregate.event(
            Event::DiskDone {
                irp: 123,
                tid: 77,
                bytes: 4096,
                write: true,
            },
            150,
        );
        assert_eq!(aggregate.counters((42, 100)).unwrap().write, 4096);
        assert_eq!(aggregate.counters((88, 100)).unwrap().write, 0);
        aggregate.event(
            Event::DiskDone {
                irp: 999,
                tid: 77,
                bytes: 8192,
                write: true,
            },
            160,
        );
        assert_eq!(aggregate.counters((88, 100)).unwrap().write, 0);
        assert!(aggregate.issues.unmatched > 0);
    }

    #[test]
    fn activity_counter_reset_or_lost_generation_is_unavailable() {
        let old = Counters {
            receive: 10,
            send: 20,
            read: 30,
            write: 40,
            generation: 1,
        };
        let new = Counters {
            receive: 30,
            send: 60,
            read: 90,
            write: 120,
            generation: 1,
        };
        let value = rates(old, new, Duration::from_secs(2));
        assert_eq!(value.network_receive, Some(10.));
        assert_eq!(value.disk_write, Some(40.));
        assert_eq!(
            rates(new, old, Duration::from_secs(2)).network_receive,
            None
        );
        assert_eq!(
            rates(
                old,
                Counters {
                    generation: 2,
                    ..new
                },
                Duration::from_secs(2)
            )
            .disk_write,
            None
        );
        assert_eq!(rates(old, new, Duration::ZERO).disk_read, None);
    }

    #[test]
    fn activity_unverified_processes_and_ambiguous_irps_are_dropped() {
        let mut aggregate = Aggregate::default();
        aggregate.event(net(42, 100, true), 150);
        assert!(aggregate.counters((42, 100)).is_none());
        assert!(aggregate.issues.unverified > 0);
        aggregate.install((42, 100));
        aggregate.event(
            Event::Thread {
                pid: 42,
                tid: 77,
                start: true,
                rundown: false,
            },
            160,
        );
        aggregate.event(
            Event::DiskInit {
                irp: 123,
                tid: 77,
                write: false,
            },
            170,
        );
        aggregate.event(
            Event::DiskInit {
                irp: 123,
                tid: 77,
                write: true,
            },
            180,
        );
        aggregate.event(
            Event::DiskDone {
                irp: 123,
                tid: 77,
                bytes: 8192,
                write: false,
            },
            190,
        );
        assert_eq!(aggregate.counters((42, 100)).unwrap().read, 0);
    }

    #[test]
    fn activity_loss_clears_untrustworthy_thread_and_irp_provenance() {
        let mut aggregate = Aggregate::default();
        aggregate.install((42, 100));
        aggregate.event(
            Event::Thread {
                pid: 42,
                tid: 77,
                start: true,
                rundown: false,
            },
            110,
        );
        aggregate.event(
            Event::DiskInit {
                irp: 123,
                tid: 77,
                write: true,
            },
            120,
        );
        let old = aggregate.counters((42, 100)).unwrap();
        aggregate.note_loss(1);
        aggregate.event(
            Event::DiskDone {
                irp: 123,
                tid: 77,
                bytes: 4096,
                write: true,
            },
            150,
        );
        let new = aggregate.counters((42, 100)).unwrap();
        assert_eq!(new.write, 0);
        assert!(aggregate.threads.is_empty());
        assert_eq!(aggregate.issues.lost, 1);
        assert_eq!(rates(old, new, Duration::from_secs(1)).disk_write, None);
    }

    #[test]
    fn activity_limits_are_bounded_and_counter_overflow_invalidates_the_interval() {
        let mut aggregate = Aggregate::default();
        aggregate.install((42, 100));
        aggregate.totals.get_mut(&(42, 100)).unwrap().receive = u64::MAX;
        let old = aggregate.counters((42, 100)).unwrap();
        aggregate.event(net(42, 1, true), 110);
        assert_eq!(
            rates(
                old,
                aggregate.counters((42, 100)).unwrap(),
                Duration::from_secs(1)
            )
            .network_receive,
            None
        );
        for tid in 1..=MAX_THREADS as u32 + 1 {
            aggregate.event(
                Event::Thread {
                    pid: 42,
                    tid,
                    start: true,
                    rundown: false,
                },
                110,
            );
        }
        assert_eq!(aggregate.threads.len(), MAX_THREADS);
        assert!(aggregate.issues.overflow > 0);
        for irp in 1..=MAX_IRPS as u64 + 1 {
            aggregate.event(
                Event::DiskInit {
                    irp,
                    tid: 1,
                    write: false,
                },
                120,
            );
        }
        assert_eq!(aggregate.irps.len(), MAX_IRPS);
        aggregate.prune(&HashSet::from([(42, 100)]), 120 + IRP_TIMEOUT + 1);
        assert!(aggregate.irps.is_empty());
    }

    #[test]
    fn activity_initial_thread_rundown_survives_first_sampler_identity_installation() {
        let mut aggregate = Aggregate::default();
        aggregate.event(
            Event::Thread {
                pid: 42,
                tid: 77,
                start: true,
                rundown: true,
            },
            150,
        );
        aggregate.prune(&HashSet::from([(42, 100)]), 160);
        aggregate.install((42, 100));
        aggregate.event(
            Event::DiskInit {
                irp: 123,
                tid: 77,
                write: false,
            },
            170,
        );
        aggregate.event(
            Event::DiskDone {
                irp: 123,
                tid: 77,
                bytes: 4096,
                write: false,
            },
            180,
        );
        assert_eq!(aggregate.counters((42, 100)).unwrap().read, 4096);
    }

    #[test]
    fn activity_stale_cleanup_requires_exact_namespace_guid_session_and_configuration() {
        let guid = GUID::from_u128(0x00112233_4455_6677_8899_aabbccddeeff);
        let name = "AnVirNext.Activity.v1.s2.42.123.00112233445566778899aabbccddeeff";
        let mut properties = EVENT_TRACE_PROPERTIES::default();
        properties.Wnode.Guid = guid;
        properties.EnableFlags = TRACE_FLAGS;
        properties.LogFileMode = TRACE_MODE;
        properties.BufferSize = 64;
        assert_eq!(stale_candidate(name, &properties, 2), Some((42, 123)));
        assert!(stale_candidate(name, &properties, 1).is_none());
        assert!(stale_candidate("NT Kernel Logger", &properties, 2).is_none());
        assert!(stale_candidate(&format!("{name}.extra"), &properties, 2).is_none());
        properties.Wnode.Guid = GUID::default();
        assert!(stale_candidate(name, &properties, 2).is_none());
        properties.Wnode.Guid = guid;
        properties.LogFileNameOffset = 200;
        assert!(stale_candidate(name, &properties, 2).is_none());
        // SAFETY: GetCurrentProcess is a borrowed query-capable pseudo handle.
        let birth = process_times(unsafe { GetCurrentProcess() }).unwrap().0;
        assert!(!owner_proven_dead((std::process::id(), birth)));
    }

    #[test]
    #[ignore = "Explicit native ETW smoke; creates only our session, a temporary file and local sockets"]
    fn activity_native_fixture_smoke() {
        let result = diagnose_activity();
        eprintln!("{result}");
        assert!(
            result.contains("ETW fixture passed")
                || result.contains("run AnVir Next as administrator"),
            "{result}"
        );
    }
}
