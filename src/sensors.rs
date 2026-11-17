use serde::Deserialize;
use std::{
    io::{self, BufRead, Read},
    sync::Arc,
    time::{Duration, Instant},
};

pub const MAX_SENSOR_FRAME: usize = 1_048_576;

#[derive(Clone, Debug, Deserialize)]
pub struct SensorReading {
    pub id: String,
    pub name: String,
    pub hardware: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub value: f64,
}

#[derive(Clone, Debug, Deserialize)]
pub struct SensorFrame {
    pub version: u8,
    pub driver_available: bool,
    pub elevated: bool,
    pub sensors: Vec<SensorReading>,
    pub errors: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub struct SensorState {
    pub frame: Option<Arc<SensorFrame>>,
    pub received: Option<Instant>,
    pub error: Option<String>,
}

impl SensorState {
    pub fn current(&self) -> Option<Arc<SensorFrame>> {
        if self.received?.elapsed() > Duration::from_secs(12) {
            return None;
        }
        self.frame.clone()
    }

    pub fn status(&self) -> String {
        if let Some(error) = &self.error {
            return error.clone();
        }
        let Some(frame) = self.current() else {
            return if self.received.is_some() {
                "Датчики не обновляются".into()
            } else {
                "Подключение датчиков…".into()
            };
        };
        if !frame.driver_available {
            return format!(
                "{} датчиков · Для температуры CPU нужен доступ к PawnIO",
                frame.sensors.len()
            );
        }
        if let Some(error) = frame.errors.first() {
            return format!("{} датчиков · {error}", frame.sensors.len());
        }
        format!("{} датчиков · LibreHardwareMonitor", frame.sensors.len())
    }
}

pub fn read_frame_line<R: BufRead>(reader: &mut R) -> io::Result<Option<Vec<u8>>> {
    let mut bytes = Vec::new();
    (&mut *reader)
        .take(MAX_SENSOR_FRAME as u64 + 3)
        .read_until(b'\n', &mut bytes)?;
    if bytes.is_empty() {
        return Ok(None);
    }
    if bytes.len() > MAX_SENSOR_FRAME + 2 || bytes.last() != Some(&b'\n') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Unbounded or incomplete sensor frame",
        ));
    }
    while matches!(bytes.last(), Some(b'\r' | b'\n')) {
        bytes.pop();
    }
    if bytes.len() > MAX_SENSOR_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Oversized sensor frame",
        ));
    }
    Ok(Some(bytes))
}

impl SensorReading {
    pub fn display_value(&self) -> String {
        // AMD exposes the unavailable fullscreen frame-rate sentinel as Factor -1.
        if self.kind == "Factor" && self.name.contains("FPS") {
            return if self.value < 0.0 {
                "—".into()
            } else {
                format!("{:.1} кадр/с", self.value)
            };
        }
        match self.kind.as_str() {
            "Temperature" => format!("{:.1} °C", self.value),
            "Load" | "Control" | "Level" => format!("{:.1}%", self.value),
            "Clock" => format!("{:.0} МГц", self.value),
            "Power" => format!("{:.1} Вт", self.value),
            "Voltage" => format!("{:.3} В", self.value),
            "Fan" => format!("{:.0} об/мин", self.value),
            "Data" => format!("{:.2} ГиБ", self.value),
            "SmallData" => format!("{:.0} МиБ", self.value),
            "Throughput" => crate::model::format_rate(Some(self.value)),
            "Factor" => format!("{:.2} ×", self.value),
            _ => format!("{:.2}", self.value),
        }
    }
}

pub fn cpu_temperature(frame: &SensorFrame) -> Option<f64> {
    if !frame.driver_available {
        return None;
    }
    frame
        .sensors
        .iter()
        .filter(|sensor| {
            sensor.kind == "Temperature"
                && (sensor.id.starts_with("/amdcpu/") || sensor.id.starts_with("/intelcpu/"))
        })
        .map(|sensor| sensor.value)
        .max_by(f64::total_cmp)
}

#[cfg(windows)]
pub fn bridge_path() -> Option<std::path::PathBuf> {
    let next_to_exe = std::env::current_exe()
        .ok()?
        .parent()?
        .join("hardware-monitor")
        .join("AnVirNext.SensorBridge.exe");
    if next_to_exe.is_file() {
        return Some(next_to_exe);
    }
    if cfg!(debug_assertions) {
        let development = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("vendor/LibreHardwareMonitor/v0.9.6/AnVirNext.SensorBridge.exe");
        if development.is_file() {
            return Some(development);
        }
    }
    None
}

#[cfg(windows)]
pub fn start(
    state: Arc<std::sync::Mutex<SensorState>>,
    stop: Arc<std::sync::atomic::AtomicBool>,
    notifier: Arc<crate::win::Notifier>,
) -> io::Result<std::thread::JoinHandle<()>> {
    use crate::win::Handle;
    use std::{
        os::windows::{io::AsRawHandle, process::CommandExt},
        process::{Command, Stdio},
        sync::atomic::Ordering,
    };
    use windows_sys::Win32::System::{JobObjects::*, Threading::CREATE_NO_WINDOW};

    std::thread::Builder::new()
        .name("hardware-sensors".into())
        .spawn(move || {
            let result = (|| -> Result<(), String> {
                let path =
                    bridge_path().ok_or("Компонент датчиков не найден рядом с приложением")?;
                // SAFETY: null attributes/name request a private unnamed job owned by this thread.
                let job =
                    Handle::new(unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) })
                        .map_err(|error| error.to_string())?;
                let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
                limits.BasicLimitInformation.LimitFlags =
                    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_PROCESS_MEMORY;
                limits.ProcessMemoryLimit = 512 * 1024 * 1024;
                // SAFETY: the exact initialized information structure belongs to this live job.
                if unsafe {
                    SetInformationJobObject(
                        job.raw(),
                        JobObjectExtendedLimitInformation,
                        (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                        std::mem::size_of_val(&limits) as u32,
                    )
                } == 0
                {
                    return Err("Не удалось ограничить компонент датчиков".into());
                }
                let mut child = Command::new(&path)
                    .current_dir(
                        path.parent()
                            .ok_or("Некорректный путь компонента датчиков")?,
                    )
                    .args(["--parent", &std::process::id().to_string()])
                    .creation_flags(CREATE_NO_WINDOW)
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::null())
                    .spawn()
                    .map_err(|error| format!("Компонент датчиков не запущен: {error}"))?;
                // SAFETY: the child handle is borrowed only for this synchronous assignment.
                if unsafe { AssignProcessToJobObject(job.raw(), child.as_raw_handle()) } == 0 {
                    let _ = child.kill();
                    return Err("Не удалось привязать время жизни компонента датчиков".into());
                }
                let stdout = child.stdout.take().ok_or("Нет канала датчиков")?;
                let mut reader = io::BufReader::new(stdout);
                loop {
                    if stop.load(Ordering::Acquire) {
                        break;
                    }
                    let Some(line) =
                        read_frame_line(&mut reader).map_err(|error| error.to_string())?
                    else {
                        break;
                    };
                    let frame = parse_frame(&line)?;
                    let mut latest = state.lock().unwrap_or_else(|error| error.into_inner());
                    latest.frame = Some(Arc::new(frame));
                    latest.received = Some(Instant::now());
                    latest.error = None;
                    drop(latest);
                    notifier.notify();
                }
                // The private job kills this child on every return path, including malformed output.
                let _ = child.kill();
                drop(job);
                if stop.load(Ordering::Acquire) {
                    Ok(())
                } else {
                    Err("Компонент датчиков завершил работу".into())
                }
            })();
            if let Err(error) = result {
                state
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner())
                    .error = Some(error);
                notifier.notify();
            }
        })
}

pub fn parse_frame(bytes: &[u8]) -> Result<SensorFrame, String> {
    if bytes.len() > MAX_SENSOR_FRAME {
        return Err("Слишком большой пакет датчиков".into());
    }
    let frame: SensorFrame =
        serde_json::from_slice(bytes).map_err(|_| "Некорректный пакет датчиков".to_owned())?;
    if frame.version != 1 {
        return Err("Несовместимая версия протокола датчиков".into());
    }
    if frame.sensors.len() > 1024 || frame.errors.len() > 8 {
        return Err("Превышен лимит датчиков".into());
    }
    for reading in &frame.sensors {
        if reading.id.is_empty()
            || reading.id.chars().count() > 256
            || reading.name.chars().count() > 128
            || reading.hardware.chars().count() > 128
            || reading.kind.chars().count() > 32
            || !reading.value.is_finite()
        {
            return Err("Некорректное значение датчика".into());
        }
    }
    if frame.errors.iter().any(|error| error.chars().count() > 256) {
        return Err("Слишком длинное сообщение датчика".into());
    }
    Ok(frame)
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &[u8] = br#"{"version":1,"driver_available":false,"elevated":false,"sensors":[{"id":"/gpu/0/temperature/0","name":"GPU","hardware":"RTX","type":"Temperature","value":0}],"errors":[]}"#;

    #[test]
    fn decodes_a_real_zero_reading_and_partial_driver_status() {
        let frame = parse_frame(VALID).unwrap();
        assert_eq!(frame.sensors.len(), 1);
        assert_eq!(frame.sensors[0].value, 0.0);
        assert!(!frame.driver_available);
    }

    #[test]
    fn rejects_unknown_protocol_versions_and_unbounded_frames() {
        let unknown = String::from_utf8(VALID.to_vec())
            .unwrap()
            .replace("\"version\":1", "\"version\":2");
        assert!(parse_frame(unknown.as_bytes()).is_err());
        assert!(parse_frame(&vec![b' '; MAX_SENSOR_FRAME + 1]).is_err());
        assert!(parse_frame(b"{bad json}").is_err());
    }

    #[test]
    fn rejects_unbounded_sensor_metadata() {
        let mut value: serde_json::Value = serde_json::from_slice(VALID).unwrap();
        value["sensors"][0]["name"] = serde_json::Value::String("x".repeat(129));
        assert!(parse_frame(&serde_json::to_vec(&value).unwrap()).is_err());
    }

    #[test]
    fn a_stalled_companion_does_not_leave_old_temperatures_visible() {
        let mut state = SensorState {
            frame: Some(Arc::new(parse_frame(VALID).unwrap())),
            received: Some(Instant::now()),
            error: None,
        };
        assert!(state.current().is_some());
        state.received = Some(Instant::now() - Duration::from_secs(20));
        assert!(state.current().is_none());
    }

    #[test]
    fn pipe_reader_keeps_frame_boundaries_and_rejects_unbounded_lines() {
        let mut data = io::Cursor::new([VALID, b"\r\n", VALID, b"\n"].concat());
        assert_eq!(read_frame_line(&mut data).unwrap().as_deref(), Some(VALID));
        assert_eq!(read_frame_line(&mut data).unwrap().as_deref(), Some(VALID));
        assert!(read_frame_line(&mut data).unwrap().is_none());
        assert!(read_frame_line(&mut io::Cursor::new(vec![b'x'; MAX_SENSOR_FRAME + 3])).is_err());
    }

    #[test]
    fn unavailable_gpu_fps_is_not_rendered_as_a_negative_multiplier() {
        let mut sensor = SensorReading {
            id: "/gpu/0/factor/0".into(),
            name: "Fullscreen FPS".into(),
            hardware: "GPU".into(),
            kind: "Factor".into(),
            value: -1.0,
        };
        assert_eq!(sensor.display_value(), "—");
        sensor.value = 60.0;
        assert_eq!(sensor.display_value(), "60.0 кадр/с");
    }
}
