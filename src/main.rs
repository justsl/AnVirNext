#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(windows)]
fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        if !std::env::args().any(|argument| argument.starts_with("--diagnose")) {
            let text = anvir_next::win::wide(&error);
            let title = anvir_next::win::wide("AnVir Next");
            // SAFETY: both strings are terminated and live for the modal call.
            unsafe {
                windows_sys::Win32::UI::WindowsAndMessaging::MessageBoxW(
                    std::ptr::null_mut(),
                    text.as_ptr(),
                    title.as_ptr(),
                    windows_sys::Win32::UI::WindowsAndMessaging::MB_OK
                        | windows_sys::Win32::UI::WindowsAndMessaging::MB_ICONERROR,
                );
            }
        }
        std::process::exit(1);
    }
}

#[cfg(windows)]
fn run() -> Result<(), String> {
    use anvir_next::{
        metrics::Metrics,
        monitor::Shared,
        processes::ProcessSampler,
        settings::Settings,
        win::{Handle, wide},
    };
    use windows_sys::Win32::{
        Foundation::{ERROR_ALREADY_EXISTS, GetLastError},
        System::Threading::{CreateMutexW, OpenProcess, PROCESS_SYNCHRONIZE, WaitForSingleObject},
        UI::{Shell::IsUserAnAdmin, WindowsAndMessaging::*},
    };
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    let preview =
        cfg!(debug_assertions) && arguments.iter().any(|argument| argument == "--preview");
    if arguments
        .first()
        .is_some_and(|argument| argument == "--version")
    {
        println!("AnVir Next {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    if arguments
        .first()
        .is_some_and(|argument| argument == "--diagnose-sensors")
    {
        return diagnose_sensors();
    }
    if arguments
        .first()
        .is_some_and(|argument| argument == "--diagnose-activity")
    {
        println!("{}", anvir_next::activity::diagnose_activity());
        return Ok(());
    }
    if arguments
        .first()
        .is_some_and(|argument| argument == "--diagnose-startup")
    {
        let started = std::time::Instant::now();
        let snapshot = anvir_next::startup::scan();
        let mut sources = std::collections::BTreeMap::<String, usize>::new();
        for entry in &snapshot.entries {
            *sources.entry(entry.source.clone()).or_default() += 1;
        }
        println!(
            "{}",
            serde_json::json!({"entries":snapshot.entries.len(),"sources":sources,"warnings":snapshot.warnings,"duration_ms":started.elapsed().as_millis()})
        );
        return Ok(());
    }
    if arguments
        .first()
        .is_some_and(|argument| argument == "--diagnose")
    {
        let mut metrics = Metrics::default();
        metrics.sample();
        std::thread::sleep(std::time::Duration::from_millis(1100));
        let sample = metrics.sample();
        let mut sampler = ProcessSampler::default();
        let rows = sampler.sample(sample.logical_processors as u32, true);
        let this = rows.iter().find(|row| row.pid == std::process::id());
        let command_line_available = this.and_then(|row| row.times).is_some_and(|times| {
            anvir_next::processes::details(std::process::id(), times.created).is_ok()
        });
        println!(
            "{}",
            serde_json::json!({"system":sample,"processes":rows.len(),"snapshot_error":sampler.last_error,"self_memory_bytes":this.and_then(|row| row.memory),"self_is_64_bit":this.and_then(|row| row.is_64_bit),"self_command_line_available":command_line_available})
        );
        return Ok(());
    }

    let parent = if let [verb, pid] = arguments.as_slice() {
        if verb == "--replace" {
            Some(
                pid.parse::<u32>()
                    .ok()
                    .filter(|pid| *pid != 0 && *pid != std::process::id())
                    .ok_or("Некорректный PID предыдущей копии")?,
            )
        } else {
            None
        }
    } else {
        None
    };
    if parent.is_none()
        && arguments
            .iter()
            .any(|argument| argument != "--start-hidden" && !(preview && argument == "--preview"))
    {
        return Err("Неизвестный аргумент командной строки".into());
    }
    // SAFETY: this queries the effective group membership of the current token.
    if !preview && unsafe { IsUserAnAdmin() } == 0 {
        // Keep the logon entry launchable by Explorer. The application starts
        // monitoring only in the child created after the normal Windows prompt.
        anvir_next::win::launch_elevated(&arguments.join(" "))?;
        return Ok(());
    }
    if let Some(parent) = parent {
        // SAFETY: read-only synchronization access to the explicitly supplied previous application process.
        if let Ok(handle) = Handle::new(unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, parent) }) {
            // SAFETY: the process handle remains live for a bounded wait.
            if unsafe { WaitForSingleObject(handle.raw(), 15_000) } == 258 {
                return Err("Предыдущая копия AnVir Next не завершилась".into());
            }
        }
    }
    let mutex_name = wide(if preview {
        "Local\\AnVirNext.Preview.v1"
    } else {
        "Local\\AnVirNext.Monitor.v1"
    });
    // SAFETY: this creates/opens an unnamed-security, non-inherited session-local singleton handle.
    let raw_mutex = unsafe { CreateMutexW(std::ptr::null(), 0, mutex_name.as_ptr()) };
    // SAFETY: capture the result status immediately after CreateMutexW.
    let existed = unsafe { GetLastError() } == ERROR_ALREADY_EXISTS;
    let _singleton = Handle::new(raw_mutex)
        .map_err(|error| format!("Не удалось открыть экземпляр приложения: {error}"))?;
    if existed {
        let class = wide(anvir_next::ui::WINDOW_CLASS);
        // SAFETY: the message has no pointers and only restores the existing matching application window.
        unsafe {
            let window = FindWindowW(class.as_ptr(), std::ptr::null());
            if !window.is_null() {
                PostMessageW(window, WM_APP + 10, 0, 0);
            }
        }
        return Ok(());
    }
    let local_data = std::env::var_os("LOCALAPPDATA")
        .ok_or("Папка локальных настроек пользователя недоступна")?;
    // Debug-only visual preview: separate configuration and no notification icons,
    // so inspecting a new build cannot interfere with the installed running copy.
    let directory = if preview {
        std::env::temp_dir().join("AnVirNext-preview")
    } else {
        std::path::PathBuf::from(local_data).join("AnVirNext")
    };
    let settings = if preview {
        Settings {
            cpu_icon: false,
            disk_icon: false,
            network_icon: false,
            memory_icon: false,
            temperature_icon: false,
            ..Settings::default()
        }
    } else {
        Settings::load_at(&directory.join("settings.json"))
    };
    let shared = Shared::new(directory, settings)?;
    let hidden = arguments
        .iter()
        .any(|argument| argument == "--start-hidden");
    let result = anvir_next::ui::run(std::sync::Arc::clone(&shared), hidden);
    shared.shutdown();
    shared.wait_for_shutdown();
    result
}

#[cfg(windows)]
fn diagnose_sensors() -> Result<(), String> {
    use std::process::{Command, Stdio};
    let path = anvir_next::sensors::bridge_path().ok_or("Компонент датчиков не найден")?;
    let mut child = Command::new(&path)
        .current_dir(path.parent().ok_or("Некорректный путь")?)
        .arg("--once")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| error.to_string())?;
    let mut stdout = std::io::BufReader::new(child.stdout.take().ok_or("Нет канала датчиков")?);
    let result = anvir_next::sensors::read_frame_line(&mut stdout)
        .map_err(|error| error.to_string())
        .and_then(|line| line.ok_or_else(|| "Компонент не вернул датчики".to_owned()))
        .and_then(|line| anvir_next::sensors::parse_frame(&line));
    let _ = child.kill();
    let _ = child.wait();
    let frame = result?;
    let temperatures: Vec<_> = frame.sensors.iter().filter(|sensor| sensor.kind == "Temperature").map(|sensor| serde_json::json!({"hardware":sensor.hardware,"name":sensor.name,"value":sensor.value})).collect();
    println!(
        "{}",
        serde_json::json!({"sensors":frame.sensors.len(),"driver_available":frame.driver_available,"elevated":frame.elevated,"temperatures":temperatures,"errors":frame.errors})
    );
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("AnVir Next currently requires Windows 11 x64.");
}
