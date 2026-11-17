use crate::{
    metrics::{Metrics, SystemSample},
    model::History,
    process_rules::{ProcessRule, RuleBook},
    processes::{self, ProcessDetails, ProcessRow, ProcessSampler},
    sensors::{self, SensorState},
    settings::Settings,
    startup::{self, StartupEntry, StartupSnapshot},
    win::Notifier,
};
use std::{
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
    pub updated: Instant,
}

impl Default for ViewSnapshot {
    fn default() -> Self {
        Self {
            system: SystemSample::default(),
            history: std::array::from_fn(|_| History::default()),
            processes: Arc::new(Vec::new()),
            process_error: None,
            updated: Instant::now(),
        }
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
    pub startup_changed: bool,
    pub notice: Option<Notice>,
}

pub enum Command {
    SelectProcess {
        pid: u32,
        created: u64,
    },
    RefreshStartup,
    ToggleStartup {
        entry: StartupEntry,
        enabled: bool,
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
            active_tab: AtomicUsize::new(0),
            stop: Arc::new(AtomicBool::new(false)),
            notifier: Arc::new(Notifier::default()),
            sender,
            selected: Mutex::new(None),
            details_pending: AtomicBool::new(false),
            startup_pending: AtomicBool::new(false),
            notice_id: AtomicU64::new(1),
            startup_events: Arc::new(AtomicBool::new(false)),
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
        thread::Builder::new()
            .name("system-monitor".into())
            .spawn(move || collect(worker_shared))
            .map_err(|error| error.to_string())?;
        let actions_shared = Arc::clone(&shared);
        if let Err(error) = thread::Builder::new()
            .name("system-actions".into())
            .spawn(move || {
                while let Ok(command) = receiver.recv() {
                    if actions_shared.stop.load(Ordering::Acquire) {
                        break;
                    }
                    if matches!(command, Command::Stop) {
                        break;
                    }
                    execute(&actions_shared, command);
                }
            })
        {
            shared.shutdown();
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
    let mut last_processes = Instant::now() - Duration::from_secs(3);
    let mut last_system = Instant::now() - Duration::from_secs(6);
    let mut system = SystemSample::default();
    while !shared.stop.load(Ordering::Acquire) {
        let started = Instant::now();
        if shared.startup_events.swap(false, Ordering::AcqRel) {
            shared
                .status
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .startup_changed = true;
            shared.post_notice(
                "Обнаружено изменение автозагрузки Windows".into(),
                false,
                false,
            );
            if shared.visible.load(Ordering::Acquire)
                && shared.active_tab.load(Ordering::Relaxed) == 1
            {
                let _ = shared.send(Command::RefreshStartup);
            }
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
        let processes_needed = (shared.visible.load(Ordering::Acquire)
            && shared.active_tab.load(Ordering::Relaxed) == 0)
            || has_rules;
        let rows = if processes_needed && last_processes.elapsed() >= Duration::from_secs(2) {
            last_processes = Instant::now();
            let rows = processes.sample(system.logical_processors);
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
        }
        drop(data);
        if system_changed || processes_changed {
            shared.notifier.notify();
        }
        // A cheap 1s scheduling tick keeps process-rule latency <=2s independently
        // of the user-selected interval for system metrics.
        if let Some(remaining) = Duration::from_secs(1).checked_sub(started.elapsed()) {
            thread::sleep(remaining);
        }
    }
}

fn execute(shared: &Shared, command: Command) {
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
            let startup = startup::scan();
            let mut status = shared
                .status
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            status.startup = Arc::new(startup);
            status.startup_loading = false;
            status.startup_changed = false;
            shared.startup_pending.store(false, Ordering::Release);
            drop(status);
            shared.notifier.notify();
            Ok(None)
        }
        Command::ToggleStartup { entry, enabled } => {
            startup::set_enabled(&entry, enabled)?;
            let startup = startup::scan();
            shared
                .status
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .startup = Arc::new(startup);
            Ok(Some("Состояние автозагрузки изменено".into()))
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
