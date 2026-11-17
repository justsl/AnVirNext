use std::time::Duration;

#[derive(Clone, Copy, Debug)]
pub struct CpuTimes {
    pub idle: u64,
    pub kernel: u64,
    pub user: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct ProcessTimes {
    pub created: u64,
    pub cpu: u64,
}

pub fn cpu_usage(previous: CpuTimes, current: CpuTimes) -> Option<f64> {
    let idle = current.idle.checked_sub(previous.idle)?;
    let total = current
        .kernel
        .checked_sub(previous.kernel)?
        .checked_add(current.user.checked_sub(previous.user)?)?;
    if total == 0 || idle > total {
        return None;
    }
    Some((total - idle) as f64 / total as f64 * 100.0)
}

pub fn counter_rate(previous: u64, current: u64, elapsed: Duration) -> Option<f64> {
    if elapsed.is_zero() {
        return None;
    }
    Some(current.checked_sub(previous)? as f64 / elapsed.as_secs_f64())
}

pub fn process_cpu(
    previous: ProcessTimes,
    current: ProcessTimes,
    elapsed: Duration,
    logical_processors: usize,
) -> Option<f64> {
    if previous.created != current.created || logical_processors == 0 {
        return None;
    }
    Some(
        (counter_rate(previous.cpu, current.cpu, elapsed)? / 100_000.0 / logical_processors as f64)
            .clamp(0.0, 100.0),
    )
}

#[derive(Clone, Debug)]
pub struct History<const N: usize> {
    values: [f64; N],
    length: usize,
    next: usize,
}

impl<const N: usize> Default for History<N> {
    fn default() -> Self {
        Self {
            values: [0.0; N],
            length: 0,
            next: 0,
        }
    }
}

impl<const N: usize> History<N> {
    pub fn push(&mut self, value: f64) {
        if N == 0 || !value.is_finite() {
            return;
        }
        self.values[self.next] = value;
        self.next = (self.next + 1) % N;
        self.length = (self.length + 1).min(N);
    }

    pub fn values(&self) -> Vec<f64> {
        if N == 0 {
            return Vec::new();
        }
        let start = if self.length == N { self.next } else { 0 };
        (0..self.length)
            .map(|offset| self.values[(start + offset) % N])
            .collect()
    }
}

pub fn format_bytes(bytes: f64) -> String {
    if !bytes.is_finite() || bytes < 0.0 {
        return "—".into();
    }
    let units = ["Б", "КиБ", "МиБ", "ГиБ", "ТиБ"];
    let mut value = bytes;
    let mut unit = 0;
    while value >= 1024.0 && unit < units.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{value:.0} {}", units[unit])
    } else {
        format!("{value:.1} {}", units[unit])
    }
}

pub fn format_rate(rate: Option<f64>) -> String {
    rate.map(|value| format!("{}/с", format_bytes(value)))
        .unwrap_or_else(|| "—".into())
}

pub fn format_percent(value: Option<f64>) -> String {
    value
        .map(|number| format!("{number:.1}%"))
        .unwrap_or_else(|| "—".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_excludes_idle_from_the_kernel_counter() {
        let previous = CpuTimes {
            idle: 100,
            kernel: 400,
            user: 600,
        };
        let current = CpuTimes {
            idle: 200,
            kernel: 600,
            user: 800,
        };
        assert_eq!(cpu_usage(previous, current), Some(75.0));
    }

    #[test]
    fn invalid_cpu_counter_transitions_are_unavailable() {
        let times = CpuTimes {
            idle: 100,
            kernel: 400,
            user: 600,
        };
        assert_eq!(cpu_usage(times, times), None);
        assert_eq!(
            cpu_usage(
                times,
                CpuTimes {
                    idle: 0,
                    kernel: 0,
                    user: 0
                }
            ),
            None
        );
        assert_eq!(
            cpu_usage(
                times,
                CpuTimes {
                    idle: 200,
                    kernel: 410,
                    user: 610
                }
            ),
            None
        );
    }

    #[test]
    fn transfer_rates_use_elapsed_time_and_reject_resets() {
        assert_eq!(
            counter_rate(100, 2100, Duration::from_secs(2)),
            Some(1000.0)
        );
        assert_eq!(counter_rate(2100, 100, Duration::from_secs(2)), None);
        assert_eq!(counter_rate(100, 2100, Duration::ZERO), None);
    }

    #[test]
    fn pid_reuse_never_inherits_the_previous_process_cpu() {
        let previous = ProcessTimes {
            created: 10,
            cpu: 20_000_000,
        };
        let same_process = ProcessTimes {
            created: 10,
            cpu: 40_000_000,
        };
        let replacement = ProcessTimes {
            created: 11,
            cpu: 40_000_000,
        };
        assert_eq!(
            process_cpu(previous, same_process, Duration::from_secs(2), 4),
            Some(25.0)
        );
        assert_eq!(
            process_cpu(previous, replacement, Duration::from_secs(2), 4),
            None
        );
        assert_eq!(process_cpu(previous, same_process, Duration::ZERO, 4), None);
    }

    #[test]
    fn history_retains_only_the_latest_finite_samples_in_order() {
        let mut history = History::<3>::default();
        for value in [1.0, 2.0, f64::NAN, 3.0, 4.0] {
            history.push(value);
        }
        assert_eq!(history.values(), [2.0, 3.0, 4.0]);
        let mut empty = History::<0>::default();
        empty.push(1.0);
        assert!(empty.values().is_empty());
    }

    #[test]
    fn byte_formatting_covers_unit_boundaries_and_bad_values() {
        assert_eq!(format_bytes(0.0), "0 Б");
        assert_eq!(format_bytes(1536.0), "1.5 КиБ");
        assert_eq!(format_bytes(1_048_576.0), "1.0 МиБ");
        assert_eq!(format_bytes(f64::NAN), "—");
        assert_eq!(format_bytes(-1.0), "—");
    }
}
