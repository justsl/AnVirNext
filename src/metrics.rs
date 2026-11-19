use crate::{
    model::{CpuTimes, counter_rate, cpu_usage},
    win::{filetime, wide},
};
use serde::Serialize;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    mem::{offset_of, size_of},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ptr,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::FILETIME,
    NetworkManagement::IpHelper::{
        FreeMibTable, GetIfTable2, GetUnicastIpAddressTable, MIB_IF_TABLE2,
        MIB_UNICASTIPADDRESS_ROW, MIB_UNICASTIPADDRESS_TABLE,
    },
    Networking::WinSock::{
        AF_INET, AF_INET6, AF_UNSPEC, IpDadStateDeprecated, IpDadStatePreferred,
    },
    System::{
        Performance::*,
        SystemInformation::{
            GROUP_AFFINITY, GetLogicalProcessorInformationEx, GlobalMemoryStatusEx, MEMORYSTATUSEX,
            PROCESSOR_RELATIONSHIP, RelationProcessorCore, SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX,
        },
        Threading::GetSystemTimes,
    },
};

fn network_rates(
    previous: &HashMap<u64, (u64, u64)>,
    current: &HashMap<u64, (u64, u64)>,
    elapsed: Duration,
) -> (Option<f64>, Option<f64>) {
    if current.is_empty() {
        return (Some(0.0), Some(0.0));
    }
    let (mut received, mut sent, mut valid) = (0.0, 0.0, false);
    for (id, &(rx, tx)) in current {
        let Some(&(old_rx, old_tx)) = previous.get(id) else {
            continue;
        };
        let (Some(rx_rate), Some(tx_rate)) = (
            counter_rate(old_rx, rx, elapsed),
            counter_rate(old_tx, tx, elapsed),
        ) else {
            continue;
        };
        received += rx_rate;
        sent += tx_rate;
        valid = true;
    }
    if valid {
        (Some(received), Some(sent))
    } else {
        (None, None)
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct SystemSample {
    pub cpu: Option<f64>,
    pub cpu_cores: Vec<Option<f64>>,
    pub physical_cores: usize,
    pub memory_percent: Option<f64>,
    pub memory_used: u64,
    pub memory_total: u64,
    pub disk_read: Option<f64>,
    pub disk_write: Option<f64>,
    pub disk_devices: Vec<DiskDevice>,
    pub network_receive: Option<f64>,
    pub network_send: Option<f64>,
    pub network_adapters: Vec<String>,
    pub network_received: Option<u64>,
    pub network_sent: Option<u64>,
    pub network_link_speed: Option<u64>,
    pub logical_processors: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct DiskDevice {
    pub name: String,
    pub busy: Option<f64>,
    pub read: Option<f64>,
    pub write: Option<f64>,
}

fn physical_disk_name(name: &str) -> bool {
    if name.len() > 128 {
        return false;
    }
    let mut parts = name.split(' ');
    let Some(number) = parts.next() else {
        return false;
    };
    if !number.bytes().all(|byte| byte.is_ascii_digit()) || number.parse::<u32>().is_err() {
        return false;
    }
    let mut letters = 0u32;
    for volume in parts {
        let bytes = volume.as_bytes();
        if bytes.len() != 2 || !bytes[0].is_ascii_alphabetic() || bytes[1] != b':' {
            return false;
        }
        let bit = 1u32 << (bytes[0].to_ascii_uppercase() - b'A');
        if letters & bit != 0 {
            return false;
        }
        letters |= bit;
    }
    true
}

fn merge_disk_value(
    devices: &mut BTreeMap<String, [Option<f64>; 3]>,
    name: &str,
    column: usize,
    value: Option<f64>,
) {
    if column >= 3 || !physical_disk_name(name) {
        return;
    }
    let value = value
        .filter(|number| number.is_finite())
        .and_then(|number| {
            if column == 0 {
                Some((100.0 - number).clamp(0.0, 100.0))
            } else {
                (number >= 0.0).then_some(number)
            }
        });
    if let Some(values) = devices.get_mut(name) {
        values[column] = value;
        return;
    }
    let mut values = [None; 3];
    values[column] = value;
    devices.insert(name.into(), values);
}

pub struct Metrics {
    previous_cpu: Option<CpuTimes>,
    previous_network: Option<HashMap<u64, (u64, u64)>>,
    previous_time: Instant,
    logical: usize,
    cores: Vec<Vec<(u16, u8)>>,
    counters: Option<PerformanceCounters>,
}

impl Default for Metrics {
    fn default() -> Self {
        Self {
            previous_cpu: None,
            previous_network: None,
            previous_time: Instant::now(),
            logical: std::thread::available_parallelism()
                .map(usize::from)
                .unwrap_or(1),
            cores: read_core_topology(),
            counters: PerformanceCounters::open(),
        }
    }
}

impl Metrics {
    /// Called only for a requested Network hover, using the last selected physical LUID set.
    pub(crate) fn physical_addresses(&self) -> Option<PhysicalAddresses> {
        let interfaces = self.previous_network.as_ref()?;
        if interfaces.is_empty() {
            return Some(PhysicalAddresses::default());
        }
        let mut table: *mut MIB_UNICASTIPADDRESS_TABLE = ptr::null_mut();
        // SAFETY: a read-only OS table query initializes this owned output allocation.
        if unsafe { GetUnicastIpAddressTable(AF_UNSPEC, &mut table) } != 0 || table.is_null() {
            return None;
        }
        // SAFETY: successful API returns the header and count contiguous rows; we cap the count before making a slice.
        let result = unsafe {
            let count = (*table).NumEntries as usize;
            if count <= 4096 {
                Some(physical_scope(
                    std::slice::from_raw_parts((*table).Table.as_ptr(), count),
                    interfaces,
                ))
            } else {
                None
            }
        };
        // SAFETY: this allocation came from GetUnicastIpAddressTable and is freed exactly once.
        unsafe {
            FreeMibTable(table.cast());
        }
        result
    }
    pub fn sample(&mut self) -> SystemSample {
        let now = Instant::now();
        let elapsed = now.saturating_duration_since(self.previous_time);
        self.previous_time = now;
        let mut sample = SystemSample {
            logical_processors: self.logical,
            physical_cores: self.cores.len(),
            ..SystemSample::default()
        };
        if let Some(current) = read_cpu() {
            sample.cpu = self
                .previous_cpu
                .and_then(|previous| cpu_usage(previous, current));
            self.previous_cpu = Some(current);
        } else {
            self.previous_cpu = None;
        }

        let mut memory = MEMORYSTATUSEX {
            dwLength: size_of::<MEMORYSTATUSEX>() as u32,
            ..MEMORYSTATUSEX::default()
        };
        // SAFETY: memory is initialized and advertises its exact writable size.
        if unsafe { GlobalMemoryStatusEx(&mut memory) } != 0 && memory.ullTotalPhys > 0 {
            sample.memory_total = memory.ullTotalPhys;
            sample.memory_used = memory.ullTotalPhys.saturating_sub(memory.ullAvailPhys);
            sample.memory_percent =
                Some(sample.memory_used as f64 / sample.memory_total as f64 * 100.0);
        }
        if let Some(network) = read_network() {
            if let Some(previous) = &self.previous_network {
                (sample.network_receive, sample.network_send) =
                    network_rates(previous, &network.counters, elapsed);
            }
            self.previous_network = Some(network.counters);
            sample.network_adapters = network.names;
            sample.network_received = network.received;
            sample.network_sent = network.sent;
            sample.network_link_speed = network.link_speed;
        } else {
            self.previous_network = None;
        }
        if let Some(counters) = &mut self.counters {
            let (values, logical_loads, disk_devices) = counters.read();
            sample.disk_read = values[0];
            sample.disk_write = values[1];
            sample.disk_devices = disk_devices;
            // GetSystemTimes covers the current processor group on large hosts.
            if self.logical > 64 {
                sample.cpu = values[2].map(|value| value.clamp(0.0, 100.0));
            }
            sample.cpu_cores = core_loads(&self.cores, &logical_loads);
        }
        sample
    }
}

fn read_cpu() -> Option<CpuTimes> {
    let (mut idle, mut kernel, mut user) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    // SAFETY: all three pointers refer to distinct initialized FILETIME outputs.
    if unsafe { GetSystemTimes(&mut idle, &mut kernel, &mut user) } == 0 {
        return None;
    }
    Some(CpuTimes {
        idle: filetime(idle),
        kernel: filetime(kernel),
        user: filetime(user),
    })
}

// Operational physical Ethernet, Wi-Fi and WWAN. Reject software/tunnel/filter
// interfaces using driver metadata, not localized or user-editable adapter names.
fn external_interface(kind: u32, status: i32, flags: u8, tunnel: i32) -> bool {
    matches!(kind, 6 | 71 | 243 | 244)
        && status == 1
        && flags & 1 != 0
        && flags & (2 | 16) == 0
        && tunnel == 0
}

type InterfaceCounters = HashMap<u64, (u64, u64)>;

/// Address-based direct unicast scope, not wire/NIC-byte attribution.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct PhysicalAddresses {
    pub(crate) physical: HashSet<IpAddr>,
    pub(crate) local: HashSet<IpAddr>,
    pub(crate) broadcast: HashSet<IpAddr>,
}

pub(crate) fn canonical_address(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(value) => value.to_ipv4_mapped().map_or(address, IpAddr::V4),
        _ => address,
    }
}

impl PhysicalAddresses {
    pub(crate) fn allows(&self, a: IpAddr, b: IpAddr) -> bool {
        let a = canonical_address(a);
        let b = canonical_address(b);
        if !direct_unicast(a)
            || !direct_unicast(b)
            || self.broadcast.contains(&a)
            || self.broadcast.contains(&b)
        {
            return false;
        }
        // Endpoint labels in classic UDP receive events vary. Exactly one endpoint
        // must be an unambiguous physical local address; direction comes from opcode.
        (self.physical.contains(&a) && !self.local.contains(&b))
            || (self.physical.contains(&b) && !self.local.contains(&a))
    }
}

fn direct_unicast(address: IpAddr) -> bool {
    match canonical_address(address) {
        IpAddr::V4(value) => {
            !value.is_loopback()
                && !value.is_multicast()
                && value.octets()[0] != 0
                && value.octets()[0] < 240
        }
        IpAddr::V6(value) => {
            !value.is_unspecified()
                && !value.is_loopback()
                && !value.is_multicast()
                && !value.is_unicast_link_local()
        }
    }
}

fn unicast_address(row: &MIB_UNICASTIPADDRESS_ROW) -> Option<IpAddr> {
    // SAFETY: SOCKADDR_INET's documented family discriminates the initialized address union member.
    unsafe {
        match row.Address.si_family {
            AF_INET => Some(IpAddr::V4(Ipv4Addr::from(
                row.Address.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes(),
            ))),
            AF_INET6 => Some(canonical_address(IpAddr::V6(Ipv6Addr::from(
                row.Address.Ipv6.sin6_addr.u.Byte,
            )))),
            _ => None,
        }
    }
}

fn physical_scope(
    rows: &[MIB_UNICASTIPADDRESS_ROW],
    selected: &InterfaceCounters,
) -> PhysicalAddresses {
    let mut scope = PhysicalAddresses::default();
    let mut excluded = HashSet::new();
    for row in rows {
        let Some(address) = unicast_address(row) else {
            continue;
        };
        scope.local.insert(address);
        // SAFETY: InterfaceLuid's Value is the native integral representation used by the selected counters.
        let physical = selected.contains_key(&unsafe { row.InterfaceLuid.Value });
        let usable = (row.DadState == IpDadStatePreferred || row.DadState == IpDadStateDeprecated)
            && row.ValidLifetime != 0;
        if !physical || !usable {
            excluded.insert(address);
            continue;
        }
        if !direct_unicast(address) {
            continue;
        }
        scope.physical.insert(address);
        if let IpAddr::V4(address) = address {
            if row.OnLinkPrefixLength <= 30 {
                let mask = u32::MAX
                    .checked_shl(u32::from(32 - row.OnLinkPrefixLength))
                    .unwrap_or(0);
                scope
                    .broadcast
                    .insert(IpAddr::V4(Ipv4Addr::from(u32::from(address) | !mask)));
            }
        }
    }
    scope.physical.retain(|address| !excluded.contains(address));
    scope
}
type LogicalLoads = BTreeMap<(u16, u8), f64>;

struct NetworkSample {
    counters: InterfaceCounters,
    names: Vec<String>,
    received: Option<u64>,
    sent: Option<u64>,
    link_speed: Option<u64>,
}

fn read_network() -> Option<NetworkSample> {
    let mut table: *mut MIB_IF_TABLE2 = ptr::null_mut();
    // SAFETY: GetIfTable2 initializes the out pointer to a caller-owned OS allocation.
    if unsafe { GetIfTable2(&mut table) } != 0 || table.is_null() {
        return None;
    }
    // SAFETY: the successful OS call returns a valid header and NumEntries contiguous rows.
    let result = unsafe {
        let count = (*table).NumEntries as usize;
        if count > 4096 {
            FreeMibTable(table.cast());
            return None;
        }
        let rows = std::slice::from_raw_parts((*table).Table.as_ptr(), count);
        let mut totals = HashMap::with_capacity(count);
        let mut names = Vec::new();
        let (mut received, mut sent, mut link_speed) = (Some(0u64), Some(0u64), Some(0u64));
        for row in rows {
            if !external_interface(
                row.Type,
                row.OperStatus,
                row.InterfaceAndOperStatusFlags._bitfield,
                row.TunnelType,
            ) {
                continue;
            }
            totals.insert(row.InterfaceLuid.Value, (row.InOctets, row.OutOctets));
            received = received.and_then(|total| total.checked_add(row.InOctets));
            sent = sent.and_then(|total| total.checked_add(row.OutOctets));
            link_speed = link_speed.and_then(|total| total.checked_add(row.ReceiveLinkSpeed));
            if names.len() < 16 {
                let end = row
                    .Alias
                    .iter()
                    .position(|unit| *unit == 0)
                    .unwrap_or(row.Alias.len());
                names.push(String::from_utf16_lossy(&row.Alias[..end]));
            }
        }
        FreeMibTable(table.cast());
        names.sort_unstable();
        NetworkSample {
            counters: totals,
            names,
            received,
            sent,
            link_speed: link_speed.filter(|speed| *speed > 0),
        }
    };
    Some(result)
}

struct PerformanceCounters {
    query: PDH_HQUERY,
    counters: [PDH_HCOUNTER; 7],
    array_buffer: Vec<usize>,
}

impl PerformanceCounters {
    fn open() -> Option<Self> {
        let mut query = ptr::null_mut();
        // SAFETY: a null source requests live counters and query is a valid out pointer.
        if unsafe { PdhOpenQueryW(ptr::null(), 0, &mut query) } != 0 {
            return None;
        }
        let mut result = Self {
            query,
            counters: [ptr::null_mut(); 7],
            array_buffer: Vec::new(),
        };
        for (index, path) in [
            r"\PhysicalDisk(_Total)\Disk Read Bytes/sec",
            r"\PhysicalDisk(_Total)\Disk Write Bytes/sec",
            r"\Processor Information(_Total)\% Processor Time",
            r"\Processor Information(*)\% Processor Time",
            r"\PhysicalDisk(*)\% Idle Time",
            r"\PhysicalDisk(*)\Disk Read Bytes/sec",
            r"\PhysicalDisk(*)\Disk Write Bytes/sec",
        ]
        .iter()
        .enumerate()
        {
            let path = wide(path);
            // SAFETY: query is live; PDH copies the terminated path before return.
            if unsafe {
                PdhAddEnglishCounterW(query, path.as_ptr(), 0, &mut result.counters[index])
            } != 0
            {
                result.counters[index] = ptr::null_mut();
            }
        }
        // SAFETY: this is a valid live PDH query. The first read primes rate counters.
        unsafe {
            PdhCollectQueryData(query);
        }
        Some(result)
    }

    fn read(&mut self) -> ([Option<f64>; 3], LogicalLoads, Vec<DiskDevice>) {
        let mut result = [None; 3];
        // SAFETY: the query remains owned by this object until Drop.
        if unsafe { PdhCollectQueryData(self.query) } != 0 {
            return (result, BTreeMap::new(), Vec::new());
        }
        for (index, counter) in self.counters[..3].iter().enumerate() {
            if counter.is_null() {
                continue;
            }
            let mut value = PDH_FMT_COUNTERVALUE::default();
            // SAFETY: counter is live and the writable result matches the requested DOUBLE format.
            let status = unsafe {
                PdhGetFormattedCounterValue(*counter, PDH_FMT_DOUBLE, ptr::null_mut(), &mut value)
            };
            if status != 0
                || !matches!(value.CStatus, PDH_CSTATUS_VALID_DATA | PDH_CSTATUS_NEW_DATA)
            {
                continue;
            }
            // SAFETY: a successful PDH_FMT_DOUBLE call initialized this union member.
            let number = unsafe { value.Anonymous.doubleValue };
            if number.is_finite() && number >= 0.0 {
                result[index] = Some(number);
            }
        }
        (result, self.read_logical_loads(), self.read_disk_devices())
    }

    fn read_logical_loads(&mut self) -> LogicalLoads {
        let mut loads = BTreeMap::new();
        self.read_array(3, |name, value| {
            let Some(value) = value.filter(|value| *value >= 0.0) else {
                return;
            };
            let Some((group, index)) = name.split_once(',') else {
                return;
            };
            let (Ok(group), Ok(index)) = (group.parse::<u16>(), index.parse::<u8>()) else {
                return;
            };
            if index < 64 {
                loads.insert((group, index), value.clamp(0.0, 100.0));
            }
        });
        loads
    }

    fn read_disk_devices(&mut self) -> Vec<DiskDevice> {
        let mut devices = BTreeMap::new();
        for column in 0..3 {
            self.read_array(4 + column, |name, value| {
                merge_disk_value(&mut devices, name, column, value)
            });
        }
        devices
            .into_iter()
            .map(|(name, [busy, read, write])| DiskDevice {
                name,
                busy,
                read,
                write,
            })
            .collect()
    }

    fn read_array(&mut self, index: usize, mut consume: impl FnMut(&str, Option<f64>)) {
        let Some(&counter) = self
            .counters
            .get(index)
            .filter(|counter| !counter.is_null())
        else {
            return;
        };
        let (mut bytes, mut count) = (0, 0);
        // SAFETY: a null buffer asks PDH for the size of its current instance array.
        if unsafe {
            PdhGetFormattedCounterArrayW(
                counter,
                PDH_FMT_DOUBLE,
                &mut bytes,
                &mut count,
                ptr::null_mut(),
            )
        } != PDH_MORE_DATA
            || bytes == 0
            || bytes > 1024 * 1024
        {
            return;
        }
        self.array_buffer
            .resize((bytes as usize).div_ceil(size_of::<usize>()), 0);
        let capacity = self.array_buffer.len() * size_of::<usize>();
        // SAFETY: the allocation is pointer-aligned, bounded and at least the requested byte size.
        let status = unsafe {
            PdhGetFormattedCounterArrayW(
                counter,
                PDH_FMT_DOUBLE,
                &mut bytes,
                &mut count,
                self.array_buffer.as_mut_ptr().cast(),
            )
        };
        if status != 0
            || bytes as usize > capacity
            || count > 8192
            || count as usize * size_of::<PDH_FMT_COUNTERVALUE_ITEM_W>() > bytes as usize
        {
            return;
        }
        let start = self.array_buffer.as_ptr() as usize;
        let end = start + bytes as usize;
        // SAFETY: PDH initialized count records and their names inside this live buffer.
        let items = unsafe {
            std::slice::from_raw_parts(
                self.array_buffer
                    .as_ptr()
                    .cast::<PDH_FMT_COUNTERVALUE_ITEM_W>(),
                count as usize,
            )
        };
        for item in items {
            let address = item.szName as usize;
            if address < start || address >= end || address % size_of::<u16>() != 0 {
                continue;
            }
            // Logical CPU or physical ID plus drive letters; bound malformed names.
            let limit = ((end - address) / size_of::<u16>()).min(129);
            // SAFETY: checked address range/alignment and bounded to the PDH allocation.
            let name = unsafe { std::slice::from_raw_parts(item.szName, limit) };
            let Some(length) = name.iter().position(|unit| *unit == 0) else {
                continue;
            };
            let Ok(name) = String::from_utf16(&name[..length]) else {
                continue;
            };
            let value = if matches!(
                item.FmtValue.CStatus,
                PDH_CSTATUS_VALID_DATA | PDH_CSTATUS_NEW_DATA
            ) {
                // SAFETY: PDH_FMT_DOUBLE initialized this member for a valid item.
                let value = unsafe { item.FmtValue.Anonymous.doubleValue };
                value.is_finite().then_some(value)
            } else {
                None
            };
            consume(&name, value);
        }
    }
}

fn core_loads(topology: &[Vec<(u16, u8)>], logical: &LogicalLoads) -> Vec<Option<f64>> {
    if topology.is_empty() {
        return logical.values().copied().map(Some).collect();
    }
    topology
        .iter()
        .map(|threads| {
            let sum = threads.iter().try_fold(0.0, |sum, index| {
                logical.get(index).map(|value| sum + value)
            })?;
            (!threads.is_empty()).then_some(sum / threads.len() as f64)
        })
        .collect()
}

fn read_core_topology() -> Vec<Vec<(u16, u8)>> {
    let mut bytes = 0;
    // SAFETY: the sizing call has no output buffer and writes only its byte count.
    unsafe {
        GetLogicalProcessorInformationEx(RelationProcessorCore, ptr::null_mut(), &mut bytes);
    }
    if bytes == 0 || bytes > 1024 * 1024 {
        return Vec::new();
    }
    let mut buffer = vec![0usize; (bytes as usize).div_ceil(size_of::<usize>())];
    let capacity = buffer.len() * size_of::<usize>();
    // SAFETY: pointer-aligned buffer is sized from the preceding OS call.
    if unsafe {
        GetLogicalProcessorInformationEx(
            RelationProcessorCore,
            buffer.as_mut_ptr().cast(),
            &mut bytes,
        )
    } == 0
        || bytes as usize > capacity
    {
        return Vec::new();
    }
    // SAFETY: the successful OS call initialized exactly bytes bytes of this live allocation.
    let data = unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), bytes as usize) };
    parse_core_topology(data).unwrap_or_default()
}

fn parse_core_topology(data: &[u8]) -> Option<Vec<Vec<(u16, u8)>>> {
    let processor = offset_of!(SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX, Anonymous);
    let masks = processor + offset_of!(PROCESSOR_RELATIONSHIP, GroupMask);
    let group_count = processor + offset_of!(PROCESSOR_RELATIONSHIP, GroupCount);
    let mut cores = Vec::new();
    let mut seen = HashSet::new();
    let mut position = 0;
    while position < data.len() {
        let header = data.get(position..position.checked_add(8)?)?;
        let kind = i32::from_ne_bytes(header[..4].try_into().ok()?);
        let size = u32::from_ne_bytes(header[4..].try_into().ok()?) as usize;
        if kind != RelationProcessorCore || size < masks || cores.len() >= 4096 {
            return None;
        }
        let record = data.get(position..position.checked_add(size)?)?;
        let groups =
            u16::from_ne_bytes(record.get(group_count..group_count + 2)?.try_into().ok()?) as usize;
        if groups == 0 || groups > 64 || masks + groups * size_of::<GROUP_AFFINITY>() > size {
            return None;
        }
        let mut threads = Vec::new();
        for index in 0..groups {
            let offset = masks + index * size_of::<GROUP_AFFINITY>();
            // SAFETY: this complete fixed-size mask is bounded by the validated record;
            // read_unaligned also supports byte-slice test fixtures.
            let affinity = unsafe {
                ptr::read_unaligned(record.as_ptr().add(offset).cast::<GROUP_AFFINITY>())
            };
            for bit in 0..usize::BITS as u8 {
                if affinity.Mask & (1usize << bit) != 0 {
                    if seen.len() >= 4096 || !seen.insert((affinity.Group, bit)) {
                        return None;
                    }
                    threads.push((affinity.Group, bit));
                }
            }
        }
        if threads.is_empty() {
            return None;
        }
        cores.push(threads);
        position += size;
    }
    Some(cores)
}

impl Drop for PerformanceCounters {
    fn drop(&mut self) {
        // SAFETY: the query is owned once and closing it releases all its counters.
        unsafe {
            PdhCloseQuery(self.query);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn physical_address_scope_excludes_local_virtual_loopback_and_nonunicast_peers() {
        let physical: IpAddr = "192.0.2.10".parse().unwrap();
        let virtual_ip: IpAddr = "10.8.0.2".parse().unwrap();
        let remote: IpAddr = "198.51.100.20".parse().unwrap();
        let broadcast: IpAddr = "192.0.2.255".parse().unwrap();
        let scope = PhysicalAddresses {
            physical: HashSet::from([physical]),
            local: HashSet::from([physical, virtual_ip]),
            broadcast: HashSet::from([broadcast]),
        };
        assert!(scope.allows(physical, remote));
        assert!(scope.allows(remote, physical));
        for peer in [
            physical,
            virtual_ip,
            broadcast,
            "127.0.0.1".parse().unwrap(),
            "0.0.0.0".parse().unwrap(),
            "224.0.0.1".parse().unwrap(),
            "255.255.255.255".parse().unwrap(),
        ] {
            assert!(!scope.allows(physical, peer));
        }
        assert!(!scope.allows(virtual_ip, remote));
        assert!(scope.allows(
            "::ffff:192.0.2.10".parse().unwrap(),
            "::ffff:198.51.100.20".parse().unwrap()
        ));
    }

    fn address_row(address: &str, luid: u64) -> MIB_UNICASTIPADDRESS_ROW {
        use windows_sys::Win32::Networking::WinSock::{
            IN_ADDR, IN_ADDR_0, IN6_ADDR, IN6_ADDR_0, SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_INET,
        };
        let mut row = MIB_UNICASTIPADDRESS_ROW {
            DadState: IpDadStatePreferred,
            ValidLifetime: 3600,
            ..MIB_UNICASTIPADDRESS_ROW::default()
        };
        row.InterfaceLuid.Value = luid;
        row.Address = match address.parse::<IpAddr>().unwrap() {
            IpAddr::V4(ip) => {
                row.OnLinkPrefixLength = 24;
                SOCKADDR_INET {
                    Ipv4: SOCKADDR_IN {
                        sin_family: AF_INET,
                        sin_addr: IN_ADDR {
                            S_un: IN_ADDR_0 {
                                S_addr: u32::from_ne_bytes(ip.octets()),
                            },
                        },
                        ..SOCKADDR_IN::default()
                    },
                }
            }
            IpAddr::V6(ip) => {
                row.OnLinkPrefixLength = 64;
                SOCKADDR_INET {
                    Ipv6: SOCKADDR_IN6 {
                        sin6_family: AF_INET6,
                        sin6_addr: IN6_ADDR {
                            u: IN6_ADDR_0 { Byte: ip.octets() },
                        },
                        ..SOCKADDR_IN6::default()
                    },
                }
            }
        };
        row
    }

    #[test]
    fn physical_scope_joins_selected_luids_and_rejects_ambiguous_and_tentative_addresses() {
        let mut tentative = address_row("192.0.2.30", 1);
        tentative.DadState = 1;
        let rows = [
            address_row("192.0.2.10", 1),
            address_row("10.8.0.2", 2),
            address_row("192.0.2.20", 1),
            address_row("192.0.2.20", 2),
            address_row("2001:db8::10", 1),
            tentative,
        ];
        let scope = physical_scope(&rows, &HashMap::from([(1, (0, 0))]));
        assert_eq!(
            scope.physical,
            HashSet::from([
                "192.0.2.10".parse().unwrap(),
                "2001:db8::10".parse().unwrap()
            ])
        );
        assert_eq!(scope.local.len(), 5);
        assert!(scope.broadcast.contains(&"192.0.2.255".parse().unwrap()));
        assert!(!scope.allows("2001:db8::10".parse().unwrap(), "fe80::1".parse().unwrap()));
    }

    #[test]
    fn physical_addresses_native_read_only_smoke() {
        let mut metrics = Metrics::default();
        metrics.sample();
        if let Some(scope) = metrics.physical_addresses() {
            eprintln!(
                "physical addresses: {} direct, {} host, {} broadcast exclusions",
                scope.physical.len(),
                scope.local.len(),
                scope.broadcast.len()
            );
            assert!(scope.physical.is_subset(&scope.local));
            assert!(
                scope
                    .physical
                    .iter()
                    .all(|&address| direct_unicast(address))
            );
        }
    }

    #[test]
    fn physical_disks_merge_exact_instances_and_preserve_unavailable_values() {
        let mut disks = BTreeMap::new();
        merge_disk_value(&mut disks, "0 C:", 0, Some(30.0));
        merge_disk_value(&mut disks, "1 D: E:", 0, None);
        merge_disk_value(&mut disks, "0 C:", 1, Some(4096.0));
        merge_disk_value(&mut disks, "1 D: E:", 2, Some(0.0));
        merge_disk_value(&mut disks, "2", 0, Some(125.0));
        merge_disk_value(&mut disks, "3", 0, Some(-5.0));
        merge_disk_value(&mut disks, "0 C:", 2, Some(-1.0));
        merge_disk_value(&mut disks, "2", 1, Some(f64::NAN));
        merge_disk_value(&mut disks, "3", 2, Some(f64::INFINITY));
        assert_eq!(disks.len(), 4);
        let first = &disks["0 C:"];
        assert_eq!(*first, [Some(70.0), Some(4096.0), None]);
        assert_eq!(disks["1 D: E:"], [None, None, Some(0.0)]);
        assert_eq!((disks["2"][0], disks["2"][1]), (Some(0.0), None));
        assert_eq!((disks["3"][0], disks["3"][2]), (Some(100.0), None));
        merge_disk_value(&mut disks, "0 C: D:", 1, Some(12.0));
        assert_eq!(disks["0 C:"][1], Some(4096.0));
        assert_eq!(disks["0 C: D:"][1], Some(12.0));
    }

    #[test]
    fn physical_disk_names_exclude_total_invalid_labels_and_unbounded_instances() {
        let mut disks = BTreeMap::new();
        for name in [
            "_Total",
            "",
            "drive C:",
            "4294967296 C:",
            "0 C:\\folder",
            "0 C:",
            "1 Z:",
        ] {
            merge_disk_value(&mut disks, name, 1, Some(100.0));
        }
        assert_eq!(disks.len(), 2);
        assert!(disks.contains_key("0 C:") && disks.contains_key("1 Z:"));
        merge_disk_value(
            &mut disks,
            &format!("1 {}", "C: ".repeat(100)),
            1,
            Some(1.0),
        );
        assert_eq!(disks.len(), 2);
    }

    #[test]
    fn topology_checks_variable_records_groups_truncation_and_duplicate_threads() {
        let body = offset_of!(SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX, Anonymous);
        let masks = body + offset_of!(PROCESSOR_RELATIONSHIP, GroupMask);
        let count = body + offset_of!(PROCESSOR_RELATIONSHIP, GroupCount);
        let mut data = vec![0u8; masks + 2 * size_of::<GROUP_AFFINITY>()];
        let length = data.len() as u32;
        data[4..8].copy_from_slice(&length.to_ne_bytes());
        data[count..count + 2].copy_from_slice(&2u16.to_ne_bytes());
        for (index, group, mask) in [(0, 0u16, 3usize), (1, 1u16, 1usize)] {
            let base = masks + index * size_of::<GROUP_AFFINITY>();
            data[base..base + size_of::<usize>()].copy_from_slice(&mask.to_ne_bytes());
            let group_offset = base + offset_of!(GROUP_AFFINITY, Group);
            data[group_offset..group_offset + 2].copy_from_slice(&group.to_ne_bytes());
        }
        assert_eq!(
            parse_core_topology(&data),
            Some(vec![vec![(0, 0), (0, 1), (1, 0)]])
        );
        assert!(parse_core_topology(&data[..data.len() - 1]).is_none());
        let duplicate_offset =
            masks + size_of::<GROUP_AFFINITY>() + offset_of!(GROUP_AFFINITY, Group);
        data[duplicate_offset..duplicate_offset + 2].copy_from_slice(&0u16.to_ne_bytes());
        assert!(parse_core_topology(&data).is_none());
        data[4..8].copy_from_slice(&0u32.to_ne_bytes());
        assert!(parse_core_topology(&data).is_none());
    }

    #[test]
    fn external_network_excludes_virtual_tunnel_filter_disconnected_interfaces() {
        assert!(external_interface(6, 1, 1, 0));
        assert!(external_interface(71, 1, 1, 0));
        assert!(external_interface(243, 1, 1, 0));
        for (kind, status, flags, tunnel) in [
            (24, 1, 1, 0),
            (131, 1, 1, 0),
            (6, 1, 0, 0),
            (6, 1, 3, 0),
            (6, 1, 17, 0),
            (6, 2, 1, 0),
            (6, 1, 1, 2),
        ] {
            assert!(!external_interface(kind, status, flags, tunnel));
        }
    }

    #[test]
    fn core_bars_average_smt_and_require_every_thread_of_that_core() {
        let topology = vec![vec![(0, 0), (0, 1)], vec![(1, 0)], vec![(1, 1)]];
        let values = [((0, 0), 20.0), ((0, 1), 80.0), ((1, 0), 35.0)].into();
        assert_eq!(
            core_loads(&topology, &values),
            vec![Some(50.0), Some(35.0), None]
        );
        assert_eq!(
            core_loads(&[], &values),
            vec![Some(20.0), Some(80.0), Some(35.0)]
        );
    }

    #[test]
    fn reads_real_windows_memory_and_cpu_after_a_counter_interval() {
        let mut metrics = Metrics::default();
        metrics.sample();
        std::thread::sleep(std::time::Duration::from_millis(1100));
        let sample = metrics.sample();
        assert!(sample.memory_total > 0);
        assert!(sample.memory_used <= sample.memory_total);
        assert!(
            sample
                .cpu
                .is_some_and(|cpu| cpu.is_finite() && (0.0..=100.0).contains(&cpu))
        );
        assert!(sample.logical_processors > 0);
        assert!(sample.physical_cores > 0);
        assert_eq!(sample.cpu_cores.len(), sample.physical_cores);
        assert!(sample.cpu_cores.iter().any(Option::is_some));
        assert!(!sample.disk_devices.is_empty());
        assert!(
            sample
                .disk_devices
                .iter()
                .all(|disk| physical_disk_name(&disk.name))
        );
        assert!(
            sample
                .disk_devices
                .iter()
                .any(|disk| disk.busy.is_some() && disk.read.is_some() && disk.write.is_some())
        );
        assert!(sample.disk_devices.iter().all(|disk| {
            disk.busy
                .is_none_or(|busy| busy.is_finite() && (0.0..=100.0).contains(&busy))
                && [disk.read, disk.write]
                    .into_iter()
                    .flatten()
                    .all(|rate| rate.is_finite() && rate >= 0.0)
        }));
        assert!(
            sample
                .cpu_cores
                .iter()
                .flatten()
                .all(|load| load.is_finite() && (0.0..=100.0).contains(load))
        );
    }

    #[test]
    fn a_new_adapter_never_contributes_its_lifetime_bytes_to_the_rate() {
        let previous = HashMap::from([(1, (1000, 2000))]);
        let current = HashMap::from([(1, (3000, 6000)), (2, (9_000_000_000, 8_000_000_000))]);
        assert_eq!(
            network_rates(&previous, &current, Duration::from_secs(2)),
            (Some(1000.0), Some(2000.0))
        );
        assert_eq!(
            network_rates(
                &current,
                &HashMap::from([(1, (1, 1))]),
                Duration::from_secs(2)
            ),
            (None, None)
        );
        assert_eq!(
            network_rates(&current, &HashMap::new(), Duration::from_secs(2)),
            (Some(0.0), Some(0.0))
        );
    }
}
