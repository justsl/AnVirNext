use crate::{
    activity::{ActivityMonitor, ProcessRates},
    metrics::{Metrics, SystemSample},
    model::History,
    process_rules::{ProcessRule, RuleBook},
    processes::{self, ProcessDetails, ProcessRow, ProcessSampler, StartupRuntimeOutcome},
    sensors::{self, SensorState},
    settings::Settings,
    startup::{self, StartupEntry, StartupHistory, StartupSnapshot},
    win::Notifier,
};
use std::{
    collections::HashSet,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        mpsc::{self, SyncSender},
    },
    thread,
    time::{Duration, Instant},
};

#[derive(Clone)]
pub struct ViewSnapshot {
    pub system: SystemSample,
    /// CPU %, memory %, physical disk bytes/s and physical network bytes/s.
    pub history: [History<60>; 4],
    pub processes: Arc<Vec<ProcessRow>>,
    pub process_error: Option<String>,
    pub activity_error: Option<String>,
    pub(crate) disk_top: Option<Arc<DiskTop>>,
    pub updated: Instant,
}

impl Default for ViewSnapshot {
    fn default() -> Self {
        Self {
            system: SystemSample::default(),
            history: std::array::from_fn(|_| History::default()),
            processes: Arc::new(Vec::new()),
            process_error: None,
            activity_error: None,
            disk_top: None,
            updated: Instant::now(),
        }
    }
}

#[derive(Debug)]
pub(crate) struct DiskProcess {
    pub pid: u32,
    pub name: String,
    pub rate: f64,
}

#[derive(Debug)]
pub(crate) struct DiskTop {
    pub measured_at: Instant,
    pub directions: [Option<Vec<DiskProcess>>; 2],
    pub status: Option<String>,
}

fn rank_disk<'a>(
    rows: impl IntoIterator<Item = (u32, &'a str, ProcessRates)>,
    status: Option<String>,
) -> DiskTop {
    const TOP: usize = 3;
    let mut directions = [None::<Vec<(u32, &str, f64)>>, None];
    for (pid, name, rates) in rows {
        for (direction, rate) in directions
            .iter_mut()
            .zip([rates.disk_read, rates.disk_write])
        {
            let Some(rate) = rate.filter(|rate| rate.is_finite() && *rate >= 0.0) else {
                continue;
            };
            let top = direction.get_or_insert_with(|| Vec::with_capacity(TOP));
            if rate == 0.0 {
                continue;
            }
            let index = top
                .partition_point(|&(other, _, value)| value > rate || value == rate && other < pid);
            if index < TOP {
                if top.len() == TOP {
                    top.pop();
                }
                top.insert(index, (pid, name, rate));
            }
        }
    }
    DiskTop {
        measured_at: Instant::now(),
        directions: directions.map(|direction| {
            direction.map(|top| {
                top.into_iter()
                    .map(|(pid, name, rate)| DiskProcess {
                        pid,
                        name: name.into(),
                        rate,
                    })
                    .collect()
            })
        }),
        status,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disk_summary_ranks_read_and_write_independently_and_distinguishes_idle_from_unknown() {
        let rows = [
            (5, Some(8.0), Some(0.0)),
            (9, Some(8.0), Some(3.0)),
            (2, None, Some(20.0)),
            (4, Some(10.0), None),
            (1, Some(2.0), None),
        ];
        let top = rank_disk(
            rows.map(|(pid, disk_read, disk_write)| {
                (
                    pid,
                    "fixture",
                    ProcessRates {
                        disk_read,
                        disk_write,
                        ..Default::default()
                    },
                )
            }),
            None,
        );
        assert_eq!(
            top.directions[0]
                .as_ref()
                .unwrap()
                .iter()
                .map(|row| row.pid)
                .collect::<Vec<_>>(),
            [4, 5, 9]
        );
        assert_eq!(
            top.directions[1]
                .as_ref()
                .unwrap()
                .iter()
                .map(|row| row.pid)
                .collect::<Vec<_>>(),
            [2, 9]
        );
        let idle = rank_disk(
            [(
                5,
                "fixture",
                ProcessRates {
                    disk_read: Some(0.0),
                    ..Default::default()
                },
            )],
            None,
        );
        assert!(idle.directions[0].as_ref().unwrap().is_empty());
        assert!(idle.directions[1].is_none());
    }
}

#[derive(Clone)]
pub struct DetailsResult {
    pub pid: u32,
    pub created: u64,
    pub result: Result<ProcessDetails, String>,
}

#[derive(Clone)]
pub struct Notice {
    pub id: u64,
    pub text: String,
    pub is_error: bool,
    pub popup: bool,
}

#[derive(Clone, Default)]
pub struct UiStatus {
    pub details: Option<DetailsResult>,
    pub startup: Arc<StartupSnapshot>,
    pub startup_loading: bool,
    pub notice: Option<Notice>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartupAction {
    Enable,
    Disable,
    Start,
    Stop,
}

pub enum Command {
    SelectProcess {
        pid: u32,
        created: u64,
    },
    RefreshStartup,
    StartupBatch {
        entries: Vec<StartupEntry>,
        action: StartupAction,
    },
    Scheduling {
        pid: u32,
        created: u64,
        executable: String,
        priority: u32,
        affinity: u64,
        remember: bool,
    },
    RemoveRule {
        executable: String,
    },
    Terminate {
        pid: u32,
        created: u64,
    },
    UpdateSettings(Settings),
    SetSelfStartup(bool),
    Stop,
}

pub struct Shared {
    pub data: Mutex<ViewSnapshot>,
    pub sensors: Arc<Mutex<SensorState>>,
    pub status: Mutex<UiStatus>,
    pub rules: Mutex<Option<RuleBook>>,
    pub settings: Mutex<Settings>,
    pub visible: AtomicBool,
    pub(crate) disk_hovered: AtomicBool,
    /// 0 processes, 1 autostart, 2 sensors, 3 saved process rules.
    pub active_tab: AtomicUsize,
    pub stop: Arc<AtomicBool>,
    pub notifier: Arc<Notifier>,
    sender: SyncSender<Command>,
    selected: Mutex<Option<(u32, u64)>>,
    details_pending: AtomicBool,
    startup_pending: AtomicBool,
    notice_id: AtomicU64,
    startup_events: Arc<AtomicBool>,
    collector: Mutex<Option<thread::JoinHandle<()>>>,
    config_directory: PathBuf,
}

impl Shared {
    pub fn new(config_directory: PathBuf, settings: Settings) -> Result<Arc<Self>, String> {
        let (sender, receiver) = mpsc::sync_channel(8);
        let rule_result = RuleBook::load(&config_directory.join("process-rules.json"));
        let rule_error = rule_result.as_ref().err().cloned();
        let shared = Arc::new(Self {
            data: Mutex::new(ViewSnapshot::default()),
            sensors: Arc::new(Mutex::new(SensorState::default())),
            status: Mutex::new(UiStatus::default()),
            rules: Mutex::new(rule_result.ok()),
            settings: Mutex::new(settings),
            visible: AtomicBool::new(false),
            disk_hovered: AtomicBool::new(false),
            active_tab: AtomicUsize::new(0),
            stop: Arc::new(AtomicBool::new(false)),
            notifier: Arc::new(Notifier::default()),
            sender,
            selected: Mutex::new(None),
            details_pending: AtomicBool::new(false),
            startup_pending: AtomicBool::new(false),
            notice_id: AtomicU64::new(1),
            startup_events: Arc::new(AtomicBool::new(false)),
            collector: Mutex::new(None),
            config_directory,
        });
        if let Some(error) = rule_error {
            shared.post_notice(
                format!("Правила процессов не загружены: {error}"),
                true,
                false,
            );
        }
        let worker_shared = Arc::clone(&shared);
        let collector = thread::Builder::new()
            .name("system-monitor".into())
            .spawn(move || collect(worker_shared))
            .map_err(|error| error.to_string())?;
        *shared
            .collector
            .lock()
            .unwrap_or_else(|poison| poison.into_inner()) = Some(collector);
        let actions_shared = Arc::clone(&shared);
        if let Err(error) = thread::Builder::new()
            .name("system-actions".into())
            .spawn(move || {
                let mut history = match StartupHistory::load(
                    actions_shared.config_directory.join("startup-history.json"),
                ) {
                    Ok(history) => Some(history),
                    Err(error) => {
                        actions_shared.post_notice(
                            format!("Даты автозагрузки не загружены: {error}"),
                            true,
                            false,
                        );
                        None
                    }
                };
                while let Ok(command) = receiver.recv() {
                    if actions_shared.stop.load(Ordering::Acquire) {
                        break;
                    }
                    if matches!(command, Command::Stop) {
                        break;
                    }
                    execute(&actions_shared, command, history.as_mut());
                }
            })
        {
            shared.shutdown();
            shared.wait_for_shutdown();
            return Err(error.to_string());
        }
        if let Err(error) = sensors::start(
            Arc::clone(&shared.sensors),
            Arc::clone(&shared.stop),
            Arc::clone(&shared.notifier),
        ) {
            shared
                .sensors
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .error = Some(format!("Датчики не запущены: {error}"));
        }
        startup::watch_changes(Arc::clone(&shared.stop), Arc::clone(&shared.startup_events));
        Ok(shared)
    }

    pub fn send(&self, command: Command) -> Result<(), String> {
        match command {
            Command::SelectProcess { pid, created } => {
                *self
                    .selected
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner()) = Some((pid, created));
                if self.details_pending.swap(true, Ordering::AcqRel) {
                    return Ok(());
                }
                if self
                    .sender
                    .try_send(Command::SelectProcess { pid, created })
                    .is_err()
                {
                    self.details_pending.store(false, Ordering::Release);
                    return Err("Операция уже выполняется. Повторите через секунду.".into());
                }
            }
            Command::RefreshStartup => {
                if self.startup_pending.swap(true, Ordering::AcqRel) {
                    return Ok(());
                }
                self.status
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner())
                    .startup_loading = true;
                if self.sender.try_send(Command::RefreshStartup).is_err() {
                    self.startup_pending.store(false, Ordering::Release);
                    self.status
                        .lock()
                        .unwrap_or_else(|poison| poison.into_inner())
                        .startup_loading = false;
                    return Err("Операция уже выполняется. Повторите через секунду.".into());
                }
                self.notifier.notify();
            }
            other => self
                .sender
                .try_send(other)
                .map_err(|_| "Операция уже выполняется. Повторите через секунду.".to_owned())?,
        }
        Ok(())
    }

    pub fn snapshot(&self) -> ViewSnapshot {
        self.data
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .clone()
    }
    pub fn ui_status(&self) -> UiStatus {
        self.status
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .clone()
    }
    pub fn current_settings(&self) -> Settings {
        self.settings
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .clone()
    }
    pub fn saved_rules(&self) -> Vec<ProcessRule> {
        self.rules
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .as_ref()
            .map(|book| book.rules().to_vec())
            .unwrap_or_default()
    }

    pub fn shutdown(&self) {
        self.stop.store(true, Ordering::Release);
        self.notifier.bind(std::ptr::null_mut());
        let _ = self.sender.try_send(Command::Stop);
    }

    /// Called after the UI loop exits, so trace cleanup never blocks a window callback.
    pub fn wait_for_shutdown(&self) {
        let collector = self
            .collector
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .take();
        if let Some(collector) = collector {
            let _ = collector.join();
        }
    }

    pub fn post_notice(&self, text: String, is_error: bool, popup: bool) {
        let text: String = text.chars().take(4096).collect();
        self.status
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .notice = Some(Notice {
            id: self.notice_id.fetch_add(1, Ordering::Relaxed),
            text,
            is_error,
            popup,
        });
        self.notifier.notify();
    }
}

fn collect(shared: Arc<Shared>) {
    let mut metrics = Metrics::default();
    let mut processes = ProcessSampler::default();
    let mut activity: Option<ActivityMonitor> = None;
    let mut last_activity = None::<Instant>;
    let mut last_processes = Instant::now() - Duration::from_secs(3);
    let mut last_system = Instant::now() - Duration::from_secs(6);
    let mut system = SystemSample::default();
    let mut startup_dirty = true;
    let mut next_startup_scan = Instant::now();
    while !shared.stop.load(Ordering::Acquire) {
        let started = Instant::now();
        startup_dirty |= shared.startup_events.swap(false, Ordering::AcqRel);
        // Watch notifications cover Run/Startup and a periodic reconciliation
        // also captures tasks and services without a permanent COM/RPC poll.
        if (startup_dirty || started >= next_startup_scan)
            && !shared.startup_pending.load(Ordering::Acquire)
            && shared.send(Command::RefreshStartup).is_ok()
        {
            startup_dirty = false;
            next_startup_scan = started + Duration::from_secs(60);
        }
        let interval = Duration::from_secs(u64::from(shared.current_settings().interval_seconds));
        let system_changed = last_system.elapsed() >= interval;
        if system_changed {
            system = metrics.sample();
            last_system = Instant::now();
        }
        let has_rules = shared
            .rules
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .as_ref()
            .is_some_and(RuleBook::has_rules);
        let processes_visible = shared.visible.load(Ordering::Acquire)
            && shared.active_tab.load(Ordering::Relaxed) == 0;
        let disk_hovered = shared.disk_hovered.load(Ordering::Acquire);
        if processes_visible || disk_hovered {
            activity.get_or_insert_with(ActivityMonitor::new);
        } else {
            activity = None;
            last_activity = None;
        }
        let processes_needed = processes_visible || has_rules;
        let mut disk_top = None;
        let mut activity_error = None;
        let rows = if processes_needed && last_processes.elapsed() >= Duration::from_secs(2) {
            last_processes = Instant::now();
            let mut rows = processes.sample(system.logical_processors as u32, processes_visible);
            if let Some(activity) = &mut activity {
                let rates = activity.sample(
                    rows.iter()
                        .filter_map(|row| row.times.map(|times| (row.pid, times.created))),
                );
                last_activity = Some(Instant::now());
                disk_top = Some(rank_disk(
                    rows.iter().filter_map(|row| {
                        let rates = *rates.get(&(row.pid, row.times?.created))?;
                        Some((row.pid, row.name.as_str(), rates))
                    }),
                    activity.disk_status(),
                ));
                if processes_visible {
                    activity_error = activity.status();
                }
                for row in &mut rows {
                    if let Some(value) = row
                        .times
                        .and_then(|times| rates.get(&(row.pid, times.created)))
                    {
                        row.network_receive = value.network_receive;
                        row.network_send = value.network_send;
                        row.disk_read = value.disk_read;
                        row.disk_write = value.disk_write;
                    }
                }
            }
            if has_rules {
                let errors = shared
                    .rules
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner())
                    .as_mut()
                    .map(|book| book.apply_new(&rows))
                    .unwrap_or_default();
                if let Some(error) = errors.first() {
                    shared.post_notice(format!("Правило процесса: {error}"), true, false);
                }
            }
            Some(Arc::new(rows))
        } else {
            None
        };
        if disk_hovered
            && !processes_visible
            && last_activity.is_none_or(|previous| previous.elapsed() >= Duration::from_secs(2))
            && let Some(activity) = &mut activity
        {
            last_activity = Some(Instant::now());
            disk_top = Some(match processes.sample_names() {
                Ok(names) => {
                    let rates = activity.sample(names.iter().map(|(identity, _)| *identity));
                    rank_disk(
                        names.iter().filter_map(|(identity, name)| {
                            Some((identity.0, name.as_str(), *rates.get(identity)?))
                        }),
                        activity.disk_status(),
                    )
                }
                Err(_) => rank_disk([], Some("Не удалось получить список процессов".into())),
            });
        }
        let mut data = shared
            .data
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if system_changed {
            for (index, value) in [
                system.cpu,
                system.memory_percent,
                system
                    .disk_read
                    .zip(system.disk_write)
                    .map(|(read, write)| read + write),
                system
                    .network_receive
                    .zip(system.network_send)
                    .map(|(rx, tx)| rx + tx),
            ]
            .into_iter()
            .enumerate()
            {
                if let Some(value) = value {
                    data.history[index].push(value);
                }
            }
            data.system = system.clone();
            data.updated = Instant::now();
        }
        let processes_changed = rows.is_some();
        if let Some(rows) = rows {
            data.processes = rows;
            data.process_error = processes.last_error.clone();
            data.activity_error = activity_error;
        }
        let disk_changed = if let Some(top) = disk_top {
            data.disk_top = Some(Arc::new(top));
            true
        } else {
            activity.is_none() && data.disk_top.take().is_some()
        };
        drop(data);
        if system_changed || processes_changed || disk_changed {
            shared.notifier.notify();
        }
        // A cheap 1s scheduling tick keeps process-rule latency <=2s independently
        // of the user-selected interval for system metrics.
        if let Some(remaining) = Duration::from_secs(1).checked_sub(started.elapsed()) {
            thread::sleep(remaining);
        }
    }
}

fn scan_startup(shared: &Shared, history: Option<&mut StartupHistory>) -> Arc<StartupSnapshot> {
    let mut snapshot = startup::scan();
    if let Some(history) = history {
        match history.observe(&mut snapshot) {
            Ok(added) if added > 0 => shared.post_notice(
                format!("Новых записей в автозагрузке: {added}"),
                false,
                false,
            ),
            Err(error) => shared.post_notice(format!("Даты автозагрузки: {error}"), true, false),
            _ => {}
        }
    }
    Arc::new(snapshot)
}

fn execute(shared: &Shared, command: Command, history: Option<&mut StartupHistory>) {
    let result: Result<Option<String>, String> = (|| match command {
        Command::SelectProcess { .. } => {
            shared.details_pending.store(false, Ordering::Release);
            let selected = *shared
                .selected
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            if let Some((pid, created)) = selected {
                let result = processes::details(pid, created);
                shared
                    .status
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner())
                    .details = Some(DetailsResult {
                    pid,
                    created,
                    result,
                });
                shared.notifier.notify();
            }
            Ok(None)
        }
        Command::RefreshStartup => {
            let startup = scan_startup(shared, history);
            let mut status = shared
                .status
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            status.startup = startup;
            status.startup_loading = false;
            shared.startup_pending.store(false, Ordering::Release);
            drop(status);
            shared.notifier.notify();
            Ok(None)
        }
        Command::StartupBatch { entries, action } => {
            if entries.is_empty() || entries.len() > 8192 {
                return Err("Некорректное количество записей автозагрузки".into());
            }
            let mut seen = HashSet::new();
            let (mut succeeded, mut already_running, mut failed) = (0, 0, 0);
            let mut examples = Vec::new();
            for entry in &entries {
                if shared.stop.load(Ordering::Acquire) {
                    return Ok(None);
                }
                if !seen.insert(entry.id.as_str()) {
                    continue;
                }
                let result = match action {
                    StartupAction::Enable | StartupAction::Disable => {
                        startup::set_enabled(entry, action == StartupAction::Enable)
                            .map(|()| StartupRuntimeOutcome::Applied)
                    }
                    StartupAction::Start | StartupAction::Stop => {
                        startup::set_running(entry, action == StartupAction::Start)
                    }
                };
                match result {
                    Ok(StartupRuntimeOutcome::Applied) => succeeded += 1,
                    Ok(StartupRuntimeOutcome::AlreadyRunning) => already_running += 1,
                    Err(error) => {
                        failed += 1;
                        if examples.len() < 3 {
                            examples.push(format!("{} — {error}", entry.name));
                        }
                    }
                }
            }
            if matches!(action, StartupAction::Enable | StartupAction::Disable) {
                let startup = scan_startup(shared, history);
                shared
                    .status
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner())
                    .startup = startup;
            }
            let already = if already_running > 0 {
                format!(" Уже запущено: {already_running}.")
            } else {
                String::new()
            };
            if failed > 0 {
                return Err(format!(
                    "Выполнено: {succeeded}.{already} Ошибок: {failed}.\r\n\r\n{}",
                    examples.join("\r\n")
                ));
            }
            let label = match action {
                StartupAction::Enable => "Включено",
                StartupAction::Disable => "Отключено",
                StartupAction::Start if succeeded == 0 && already_running == 1 => {
                    return Ok(Some("Программа уже запущена".into()));
                }
                StartupAction::Start => "Запуск запрошен",
                StartupAction::Stop => "Остановлено",
            };
            Ok(Some(format!("{label}: {succeeded}.{already}")))
        }
        Command::Scheduling {
            pid,
            created,
            executable,
            priority,
            affinity,
            remember,
        } => {
            if remember
                && shared
                    .rules
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner())
                    .is_none()
            {
                return Err("Хранилище правил недоступно".into());
            }
            processes::set_scheduling(pid, created, priority, affinity)?;
            if remember {
                let result = shared
                    .rules
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner())
                    .as_mut()
                    .ok_or("Хранилище правил недоступно")?
                    .upsert(ProcessRule {
                        executable,
                        priority,
                        affinity,
                    });
                result.map_err(|error| {
                    format!("Параметры процесса изменены, но правило не сохранено: {error}")
                })?;
            }
            let result = processes::details(pid, created);
            shared
                .status
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .details = Some(DetailsResult {
                pid,
                created,
                result,
            });
            Ok(Some(
                if remember {
                    "Параметры применены. Правило сохранено для будущих запусков этого файла."
                } else {
                    "Параметры процесса применены"
                }
                .into(),
            ))
        }
        Command::RemoveRule { executable } => {
            shared
                .rules
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .as_mut()
                .ok_or("Хранилище правил недоступно")?
                .remove(&executable)?;
            Ok(Some("Правило для будущих запусков удалено".into()))
        }
        Command::Terminate { pid, created } => {
            processes::terminate(pid, created)?;
            Ok(Some("Процесс завершён".into()))
        }
        Command::UpdateSettings(mut settings) => {
            settings.normalize();
            settings
                .save_at(&shared.config_directory.join("settings.json"))
                .map_err(|error| format!("Настройки не сохранены: {error}"))?;
            *shared
                .settings
                .lock()
                .unwrap_or_else(|poison| poison.into_inner()) = settings;
            Ok(None)
        }
        Command::SetSelfStartup(enabled) => {
            startup::set_self_autostart(enabled)?;
            Ok(Some(
                if enabled {
                    "Автозапуск AnVir Next включён"
                } else {
                    "Автозапуск AnVir Next выключен"
                }
                .into(),
            ))
        }
        Command::Stop => Ok(None),
    })();
    match result {
        Ok(Some(text)) => shared.post_notice(text, false, false),
        Ok(None) => shared.notifier.notify(),
        Err(error) => shared.post_notice(error, true, true),
    }
}
