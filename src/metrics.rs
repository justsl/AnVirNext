use crate::{
    model::{CpuTimes, counter_rate, cpu_usage},
    win::{filetime, wide},
};
use serde::Serialize;
use std::{
    collections::HashMap,
    mem::size_of,
    ptr,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::FILETIME,
    NetworkManagement::IpHelper::{FreeMibTable, GetIfTable2, MIB_IF_TABLE2},
    System::{
        Performance::*,
        SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX},
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
    pub memory_percent: Option<f64>,
    pub memory_used: u64,
    pub memory_total: u64,
    pub disk_read: Option<f64>,
    pub disk_write: Option<f64>,
    pub network_receive: Option<f64>,
    pub network_send: Option<f64>,
    pub logical_processors: usize,
}

pub struct Metrics {
    previous_cpu: Option<CpuTimes>,
    previous_network: Option<HashMap<u64, (u64, u64)>>,
    previous_time: Instant,
    logical: usize,
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
            counters: PerformanceCounters::open(),
        }
    }
}

impl Metrics {
    pub fn sample(&mut self) -> SystemSample {
        let now = Instant::now();
        let elapsed = now.saturating_duration_since(self.previous_time);
        self.previous_time = now;
        let mut sample = SystemSample {
            logical_processors: self.logical,
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
        if let Some(current) = read_network() {
            if let Some(previous) = &self.previous_network {
                (sample.network_receive, sample.network_send) =
                    network_rates(previous, &current, elapsed);
            }
            self.previous_network = Some(current);
        } else {
            self.previous_network = None;
        }
        if let Some(counters) = &mut self.counters {
            let values = counters.read();
            sample.disk_read = values[0];
            sample.disk_write = values[1];
            // GetSystemTimes covers the current processor group on large hosts.
            if self.logical > 64 {
                sample.cpu = values[2].map(|value| value.clamp(0.0, 100.0));
            }
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

fn read_network() -> Option<HashMap<u64, (u64, u64)>> {
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
        for row in rows {
            // Physical adapters only: avoid double-counting VPN/Hyper-V/loopback traffic.
            if row.OperStatus != 1
                || row.InterfaceAndOperStatusFlags._bitfield & 1 == 0
                || row.Type == 24
            {
                continue;
            }
            totals.insert(row.InterfaceLuid.Value, (row.InOctets, row.OutOctets));
        }
        FreeMibTable(table.cast());
        totals
    };
    Some(result)
}

struct PerformanceCounters {
    query: PDH_HQUERY,
    counters: [PDH_HCOUNTER; 3],
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
            counters: [ptr::null_mut(); 3],
        };
        for (index, path) in [
            r"\PhysicalDisk(_Total)\Disk Read Bytes/sec",
            r"\PhysicalDisk(_Total)\Disk Write Bytes/sec",
            r"\Processor Information(_Total)\% Processor Time",
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

    fn read(&mut self) -> [Option<f64>; 3] {
        let mut result = [None; 3];
        // SAFETY: the query remains owned by this object until Drop.
        if unsafe { PdhCollectQueryData(self.query) } != 0 {
            return result;
        }
        for (index, counter) in self.counters.iter().enumerate() {
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
        result
    }
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
    fn reads_real_windows_memory_and_cpu_after_a_counter_interval() {
        let mut metrics = Metrics::default();
        metrics.sample();
        std::thread::sleep(std::time::Duration::from_millis(80));
        let sample = metrics.sample();
        assert!(sample.memory_total > 0);
        assert!(sample.memory_used <= sample.memory_total);
        assert!(
            sample
                .cpu
                .is_some_and(|cpu| cpu.is_finite() && (0.0..=100.0).contains(&cpu))
        );
        assert!(sample.logical_processors > 0);
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
