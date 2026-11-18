use crate::{
    model::{format_bytes, format_percent, format_rate},
    monitor::{Command, Shared, ViewSnapshot},
    sensors::{SensorState, cpu_temperature},
    settings::Settings,
    startup,
    win::{launch_elevated, wide},
};
use std::{
    fmt::Write,
    mem::size_of,
    ptr,
    time::{Duration, Instant},
};
use windows_sys::{
    Win32::{
        Foundation::{HWND, LPARAM, POINT, RECT},
        Graphics::Gdi::*,
        UI::{
            HiDpi::{GetDpiForSystem, GetSystemMetricsForDpi},
            Shell::*,
            WindowsAndMessaging::*,
        },
    },
    core::GUID,
};

pub const WM_TRAY: u32 = WM_APP + 3;
pub(crate) const DISK_HOVER_TIMER: usize = 2;
const DISK_ICON: usize = 4;
const HOVER_DELAY: Duration = Duration::from_millis(425);

#[path = "disk_tooltip.rs"]
mod disk_tooltip;
use disk_tooltip::DiskTooltip;
pub enum TrayAction {
    Show,
    Exit,
    None,
}

#[derive(Clone, PartialEq)]
struct Visual {
    label: String,
    background: [u8; 3],
    graph: Graph,
    accent: [u8; 3],
}

#[derive(Clone, PartialEq)]
enum Graph {
    None,
    Cores(Vec<Option<f64>>),
    Pair {
        values: [Option<f64>; 2],
        colors: [[u8; 3]; 2],
        scale: f64,
    },
}

struct Icon(windows_sys::Win32::UI::WindowsAndMessaging::HICON);
impl Drop for Icon {
    fn drop(&mut self) {
        // SAFETY: each generated icon is owned once and is not a shared resource icon.
        unsafe {
            DestroyIcon(self.0);
        }
    }
}

struct LiveIcon {
    image: Icon,
    visual: Visual,
    tooltip: String,
    registered: bool,
}

pub struct Tray {
    window: HWND,
    canvas: Canvas,
    icons: [Option<LiveIcon>; 5],
    force_render: bool,
    disk_hover: Option<(RECT, Instant)>,
    disk_tooltip: Option<DiskTooltip>,
    pub last_error: Option<String>,
}

impl Tray {
    pub fn new(window: HWND) -> Result<Self, String> {
        Ok(Self {
            window,
            canvas: Canvas::new(icon_size())?,
            icons: std::array::from_fn(|_| None),
            force_render: true,
            disk_hover: None,
            disk_tooltip: None,
            last_error: None,
        })
    }

    pub fn recreate(&mut self) {
        self.close_disk_tooltip();
        for icon in self.icons.iter_mut().flatten() {
            icon.registered = false;
        }
        self.force_render = true;
    }

    pub fn update(&mut self, snapshot: &ViewSnapshot, sensor: &SensorState, settings: &Settings) {
        let size = icon_size();
        if self.canvas.size != size {
            match Canvas::new(size) {
                Ok(canvas) => {
                    self.canvas = canvas;
                    self.force_render = true;
                }
                Err(error) => self.last_error = Some(error),
            }
        }
        let fresh = snapshot.updated.elapsed().as_secs() <= 10;
        let system = &snapshot.system;
        let cpu = if fresh { system.cpu } else { None };
        let memory = if fresh { system.memory_percent } else { None };
        let temperature = sensor.current().and_then(|frame| cpu_temperature(&frame));
        let disk = [
            system.disk_read.filter(|_| fresh),
            system.disk_write.filter(|_| fresh),
        ];
        let numeric = |value: Option<f64>, decimal: bool| {
            value
                .map(|number| {
                    if decimal && number < 10.0 {
                        format!("{number:.1}")
                    } else {
                        format!("{number:.0}")
                    }
                })
                .unwrap_or_else(|| "—".into())
        };
        let descriptions = [
            (
                settings.temperature_icon,
                Visual {
                    label: numeric(temperature, false),
                    background: if temperature.is_some() {
                        [202, 45, 35]
                    } else {
                        [103, 71, 66]
                    },
                    graph: Graph::None,
                    accent: [255; 3],
                },
                format!(
                    "Температура CPU: {}\n{}",
                    temperature
                        .map(|value| format!("{value:.1} °C"))
                        .unwrap_or_else(|| "недоступна".into()),
                    sensor.status()
                ),
            ),
            (
                settings.cpu_icon,
                Visual {
                    label: numeric(cpu, true),
                    background: [0; 3],
                    graph: Graph::Cores(if fresh {
                        system.cpu_cores.clone()
                    } else {
                        Vec::new()
                    }),
                    accent: [38, 143, 207],
                },
                format!(
                    "CPU: {}\n{} ядер · {} логических процессоров",
                    format_percent(cpu),
                    system.physical_cores,
                    system.logical_processors
                ),
            ),
            (
                settings.memory_icon,
                Visual {
                    label: numeric(memory, false),
                    background: [47, 124, 120],
                    graph: Graph::None,
                    accent: [255; 3],
                },
                format!(
                    "Память: {}\n{} из {}",
                    format_percent(memory),
                    format_bytes(system.memory_used as f64),
                    format_bytes(system.memory_total as f64)
                ),
            ),
            (
                settings.network_icon,
                Visual {
                    label: if fresh
                        && system.network_receive.is_some()
                        && system.network_send.is_some()
                    {
                        String::new()
                    } else {
                        "—".into()
                    },
                    background: [255; 3],
                    graph: Graph::Pair {
                        values: [
                            system.network_receive.filter(|_| fresh),
                            system.network_send.filter(|_| fresh),
                        ],
                        colors: [[46, 63, 231], [100, 32, 167]],
                        scale: snapshot.history[3].peak().max(1024.0),
                    },
                    accent: [0; 3],
                },
                network_tooltip(system, fresh),
            ),
            (
                settings.disk_icon,
                Visual {
                    label: if disk.iter().all(Option::is_none) {
                        "—".into()
                    } else {
                        String::new()
                    },
                    background: [255; 3],
                    graph: Graph::Pair {
                        values: disk,
                        colors: [[214, 144, 21], [191, 68, 45]],
                        scale: snapshot.history[2].peak().max(1024.0),
                    },
                    accent: [0; 3],
                },
                String::new(),
            ),
        ];
        for (index, (enabled, visual, tooltip)) in descriptions.into_iter().enumerate() {
            if !enabled {
                self.remove(index);
                continue;
            }
            let render = self.force_render
                || self.icons[index]
                    .as_ref()
                    .is_none_or(|icon| icon.visual != visual);
            let new_image = if render {
                match self.canvas.render(&visual) {
                    Ok(image) => Some(image),
                    Err(error) => {
                        self.last_error = Some(error);
                        continue;
                    }
                }
            } else {
                None
            };
            let needs_update = render
                || self.icons[index]
                    .as_ref()
                    .is_none_or(|icon| !icon.registered || icon.tooltip != tooltip);
            if !needs_update {
                continue;
            }
            let current = self.icons[index].as_ref();
            let image = new_image
                .as_ref()
                .map(|image| image.0)
                .or_else(|| current.map(|icon| icon.image.0));
            let Some(image) = image else {
                continue;
            };
            let adding = current.is_none_or(|icon| !icon.registered);
            let mut data = icon_data(self.window, index);
            data.uFlags |= NIF_ICON | NIF_MESSAGE;
            if index != DISK_ICON {
                data.uFlags |= NIF_TIP | NIF_SHOWTIP;
            }
            data.uCallbackMessage = WM_TRAY;
            data.hIcon = image;
            copy_text(&mut data.szTip, &tooltip);
            // SAFETY: all handles/text remain live throughout this synchronous shell copy.
            if unsafe { Shell_NotifyIconW(if adding { NIM_ADD } else { NIM_MODIFY }, &data) } == 0 {
                self.last_error = Some("Панель задач не приняла значок мониторинга".into());
                continue;
            }
            if adding {
                data.Anonymous.uVersion = NOTIFYICON_VERSION_4;
                // SAFETY: this identifies the icon successfully added above.
                unsafe {
                    Shell_NotifyIconW(NIM_SETVERSION, &data);
                }
            }
            if let Some(image) = new_image {
                self.icons[index] = Some(LiveIcon {
                    image,
                    visual,
                    tooltip,
                    registered: true,
                });
            } else if let Some(icon) = &mut self.icons[index] {
                icon.tooltip = tooltip;
                icon.registered = true;
            }
        }
        if let (Some(tooltip), Some((anchor, _))) = (&mut self.disk_tooltip, self.disk_hover) {
            tooltip.update(anchor, disk_tooltip_text(snapshot));
        }
        self.force_render = false;
    }

    pub(crate) fn disk_tooltip_open(&self) -> bool {
        self.disk_tooltip.is_some()
    }

    pub(crate) fn disk_hover_event(&mut self, event: LPARAM, snapshot: &ViewSnapshot) {
        let event = event as u32;
        let message = event & 0xffff;
        if (event >> 16) as usize != DISK_ICON + 1 {
            if message == WM_MOUSEMOVE {
                self.close_disk_tooltip();
            }
            return;
        }
        if !matches!(message, WM_MOUSEMOVE | NIN_POPUPOPEN) {
            self.close_disk_tooltip();
            return;
        }
        if self.disk_hover.is_none()
            && self.icons[DISK_ICON]
                .as_ref()
                .is_some_and(|icon| icon.registered)
        {
            let data = icon_data(self.window, DISK_ICON);
            let identifier = NOTIFYICONIDENTIFIER {
                cbSize: size_of::<NOTIFYICONIDENTIFIER>() as u32,
                hWnd: self.window,
                uID: data.uID,
                guidItem: data.guidItem,
            };
            let mut anchor = RECT::default();
            // SAFETY: identifier is the registered own icon; anchor is a writable RECT.
            if unsafe { Shell_NotifyIconGetRect(&identifier, &mut anchor) } >= 0
                && anchor.left < anchor.right
                && anchor.top < anchor.bottom
            {
                let started = Instant::now();
                self.disk_hover = Some((anchor, started));
                // Windows 11 may deliver mouse moves without popup notifications.
                // The timer is armed only while this icon is under the pointer.
                // SAFETY: the timer posts messages to the live own UI window.
                if unsafe { SetTimer(self.window, DISK_HOVER_TIMER, 225, None) } == 0 {
                    self.disk_hover = None;
                }
            }
        }
        if message == NIN_POPUPOPEN {
            if let Some((_, started)) = &mut self.disk_hover {
                *started = Instant::now() - HOVER_DELAY;
            }
            self.disk_hover_tick(snapshot);
        }
    }

    pub(crate) fn disk_hover_tick(&mut self, snapshot: &ViewSnapshot) {
        let Some((anchor, started)) = self.disk_hover else {
            return;
        };
        let mut point = POINT::default();
        // SAFETY: point is writable; anchor is our copied screen rectangle.
        let inside = unsafe { GetCursorPos(&mut point) != 0 && PtInRect(&anchor, point) != 0 };
        if !inside {
            self.close_disk_tooltip();
        } else if self.disk_tooltip.is_none() && started.elapsed() >= HOVER_DELAY {
            self.disk_tooltip = DiskTooltip::open(anchor, disk_tooltip_text(snapshot));
            if self.disk_tooltip.is_none() {
                self.close_disk_tooltip();
            }
        }
    }

    pub(crate) fn close_disk_tooltip(&mut self) {
        if self.disk_hover.take().is_some() {
            // SAFETY: timer is owned by this tray's window and id.
            unsafe {
                KillTimer(self.window, DISK_HOVER_TIMER);
            }
        }
        self.disk_tooltip = None;
    }

    fn remove(&mut self, index: usize) {
        if index == DISK_ICON {
            self.close_disk_tooltip();
        }
        if self.icons[index].take().is_some() {
            let data = icon_data(self.window, index);
            // SAFETY: the fixed GUID identifies only this application's owned icon.
            unsafe {
                Shell_NotifyIconW(NIM_DELETE, &data);
            }
        }
    }

    // HWND is an opaque OS handle, never a dereferenced Rust memory pointer.
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub fn settings_menu(&mut self, window: HWND, shared: &Shared) -> Option<TrayAction> {
        let mut settings = shared.current_settings();
        // SAFETY: an empty native popup is returned to this caller for destruction.
        let menu = unsafe { CreatePopupMenu() };
        if menu.is_null() {
            return None;
        }
        let append = |id: usize, label: &str, checked: bool| {
            let label = wide(label);
            // SAFETY: menu is live and AppendMenu copies the temporary text.
            unsafe {
                AppendMenuW(
                    menu,
                    MF_STRING | if checked { MF_CHECKED } else { 0 },
                    id,
                    label.as_ptr(),
                );
            }
        };
        let separator = || {
            // SAFETY: null text is required for a separator in this owned menu.
            unsafe {
                AppendMenuW(menu, MF_SEPARATOR, 0, ptr::null());
            }
        };
        append(1, "Открыть AnVir Next", false);
        separator();
        append(10, "Температура CPU", settings.temperature_icon);
        append(11, "Загрузка CPU", settings.cpu_icon);
        append(12, "Память, %", settings.memory_icon);
        append(13, "Сеть", settings.network_icon);
        append(14, "Диски", settings.disk_icon);
        separator();
        for seconds in [1, 2, 5] {
            append(
                20 + seconds as usize,
                &format!("Обновлять каждые {seconds} с"),
                settings.interval_seconds == seconds,
            );
        }
        separator();
        append(
            30,
            "Запускать вместе с Windows",
            startup::self_autostart_enabled(),
        );
        // SAFETY: querying this process's existing token changes no privileges.
        let elevated = unsafe { IsUserAnAdmin() } != 0;
        if !elevated {
            append(31, "Запустить от администратора…", false);
        }
        separator();
        append(2, "Выход", false);
        let mut point = POINT::default();
        // SAFETY: point is writable, window owns the popup and the popup is destroyed after tracking.
        let selected = unsafe {
            GetCursorPos(&mut point);
            SetForegroundWindow(window);
            let selected = TrackPopupMenuEx(
                menu,
                TPM_RETURNCMD | TPM_RIGHTBUTTON,
                point.x,
                point.y,
                window,
                ptr::null(),
            ) as u32;
            DestroyMenu(menu);
            PostMessageW(window, WM_NULL, 0, 0);
            selected
        };
        let update = match selected {
            1 => return Some(TrayAction::Show),
            2 => return Some(TrayAction::Exit),
            10 => {
                settings.temperature_icon = !settings.temperature_icon;
                true
            }
            11 => {
                settings.cpu_icon = !settings.cpu_icon;
                true
            }
            12 => {
                settings.memory_icon = !settings.memory_icon;
                true
            }
            13 => {
                settings.network_icon = !settings.network_icon;
                true
            }
            14 => {
                settings.disk_icon = !settings.disk_icon;
                true
            }
            21 | 22 | 25 => {
                settings.interval_seconds = selected - 20;
                true
            }
            30 => {
                if let Err(error) =
                    shared.send(Command::SetSelfStartup(!startup::self_autostart_enabled()))
                {
                    shared.post_notice(error, true, true);
                }
                false
            }
            31 => {
                match launch_elevated(&format!("--replace {}", std::process::id())) {
                    Ok(true) => return Some(TrayAction::Exit),
                    Ok(false) => {}
                    Err(error) => shared.post_notice(error, true, false),
                }
                false
            }
            _ => false,
        };
        if update {
            settings.normalize();
            if let Err(error) = shared.send(Command::UpdateSettings(settings)) {
                shared.post_notice(error, true, true);
            }
        }
        Some(TrayAction::None)
    }
}

impl Drop for Tray {
    fn drop(&mut self) {
        for index in 0..self.icons.len() {
            self.remove(index);
        }
    }
}

fn icon_size() -> i32 {
    // SAFETY: these read-only system queries require no owned pointers.
    unsafe { GetSystemMetricsForDpi(SM_CXSMICON, GetDpiForSystem()).clamp(16, 64) }
}

fn icon_data(window: HWND, index: usize) -> NOTIFYICONDATAW {
    NOTIFYICONDATAW {
        cbSize: size_of::<NOTIFYICONDATAW>() as u32,
        hWnd: window,
        uID: index as u32 + 1,
        uFlags: NIF_GUID,
        guidItem: GUID {
            data1: 0xa30c18f0 + index as u32,
            data2: 0x6372,
            data3: 0x49cb,
            data4: [0xb8, 0x7b, 0x6f, 0xc2, 0x18, 0x12, 0x0a, 0x41],
        },
        ..NOTIFYICONDATAW::default()
    }
}

fn copy_text<const N: usize>(destination: &mut [u16; N], text: &str) {
    let units = wide(text);
    let mut length = units.len().saturating_sub(1).min(N.saturating_sub(1));
    if length > 0 && (0xd800..=0xdbff).contains(&units[length - 1]) {
        length -= 1;
    }
    destination[..length].copy_from_slice(&units[..length]);
}

fn color_pixel(color: [u8; 3]) -> u32 {
    0xff000000 | (u32::from(color[0]) << 16) | (u32::from(color[1]) << 8) | u32::from(color[2])
}

fn network_tooltip(system: &crate::metrics::SystemSample, fresh: bool) -> String {
    let names: String = system
        .network_adapters
        .join(", ")
        .chars()
        .take(22)
        .collect();
    let names = if names.is_empty() {
        "Внешняя сеть"
    } else {
        &names
    };
    let bytes = |value: Option<u64>| {
        value
            .filter(|_| fresh)
            .map(|value| format_bytes(value as f64))
            .unwrap_or_else(|| "—".into())
    };
    let link = system
        .network_link_speed
        .filter(|_| fresh)
        .map(|bits| format!("{:.0} Мбит/с", bits as f64 / 1_000_000.0))
        .unwrap_or_else(|| "—".into());
    let state = if !fresh {
        "Данные устарели"
    } else if system.network_adapters.is_empty() {
        "Не подключено"
    } else {
        "Подключено"
    };
    format!(
        "{names}\n↓ {} · ↑ {}\nПолучено: {}\nОтправлено: {}\n{state} · {link}",
        format_rate(if fresh { system.network_receive } else { None }),
        format_rate(if fresh { system.network_send } else { None }),
        bytes(system.network_received),
        bytes(system.network_sent)
    )
}

fn disk_tooltip_text(snapshot: &ViewSnapshot) -> String {
    let mut text = String::new();
    let system = &snapshot.system;
    if snapshot.updated.elapsed() <= Duration::from_secs(10) {
        let _ = writeln!(
            text,
            "Диски · чтение {} · запись {}",
            format_rate(system.disk_read),
            format_rate(system.disk_write)
        );
        let mut disks: Vec<_> = system.disk_devices.iter().collect();
        disks.sort_by(|a, b| {
            b.busy
                .partial_cmp(&a.busy)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.name.cmp(&b.name))
        });
        for disk in disks.iter().take(6) {
            let _ = writeln!(
                text,
                "Диск {} · {} · Ч {} · З {}",
                disk.name,
                format_percent(disk.busy),
                format_rate(disk.read),
                format_rate(disk.write)
            );
        }
        if disks.len() > 6 {
            let _ = writeln!(text, "Ещё дисков: {}", disks.len() - 6);
        } else if disks.is_empty() {
            let _ = writeln!(text, "Нет показаний по отдельным дискам");
        }
    } else {
        let _ = writeln!(text, "Диски · показания устарели");
    }
    let Some(top) = snapshot
        .disk_top
        .as_ref()
        .filter(|top| top.measured_at.elapsed() < Duration::from_secs(6))
    else {
        text.push_str("\nСобираю статистику процессов…");
        return text;
    };
    for (header, direction) in ["Лидеры чтения", "Лидеры записи"]
        .into_iter()
        .zip(&top.directions)
    {
        let _ = writeln!(text, "\n{header}");
        match direction {
            Some(rows) if !rows.is_empty() => {
                for row in rows {
                    let name: String = row
                        .name
                        .chars()
                        .filter(|character| !character.is_control())
                        .take(32)
                        .collect();
                    let _ = writeln!(
                        text,
                        "{name} ({}) · {}",
                        row.pid,
                        format_rate(Some(row.rate))
                    );
                }
            }
            Some(_) => {
                let _ = writeln!(text, "Нет активности");
            }
            None => {
                let _ = writeln!(text, "—");
            }
        }
    }
    if let Some(status) = &top.status {
        let _ = write!(text, "\n{status}");
    } else if top.directions.iter().all(Option::is_none) {
        text.push_str("\nСобираю статистику процессов…");
    }
    text.trim_end().to_owned()
}

fn bar_height(value: f64, maximum: f64, height: usize) -> usize {
    if !value.is_finite() || !maximum.is_finite() || maximum <= 0.0 {
        return 0;
    }
    (value / maximum * height as f64)
        .round()
        .clamp(0.0, height as f64) as usize
}

fn draw_graph(pixels: &mut [u32], size: usize, graph: &Graph, accent: [u8; 3]) {
    if size < 4 || pixels.len() != size * size {
        return;
    }
    let mut column = |x: usize, height: usize, color: [u8; 3]| {
        for y in size - height..size {
            pixels[y * size + x] = color_pixel(color);
        }
    };
    match graph {
        Graph::None => {}
        Graph::Cores(values) => {
            if values.is_empty() {
                return;
            }
            if values.len() <= size {
                let gap = usize::from(size >= values.len() * 2);
                for (core, value) in values.iter().enumerate() {
                    let height = value.map_or(0, |value| bar_height(value, 100.0, size));
                    for x in core * size / values.len()..(core + 1) * size / values.len() - gap {
                        column(x, height, accent);
                    }
                }
            } else {
                // A sub-pixel core still contributes to the mean of its visible bucket.
                for x in 0..size {
                    let bucket = &values[x * values.len() / size..(x + 1) * values.len() / size];
                    let sum = bucket
                        .iter()
                        .try_fold(0.0, |sum, value| value.map(|value| sum + value));
                    let height =
                        sum.map_or(0, |sum| bar_height(sum / bucket.len() as f64, 100.0, size));
                    column(x, height, accent);
                }
            }
        }
        Graph::Pair {
            values,
            colors,
            scale,
        } => {
            for (side, (value, color)) in values.iter().zip(colors).enumerate() {
                let height = value
                    .filter(|value| value.is_finite() && *value > 0.0)
                    .map_or(0, |value| bar_height(value, *scale, size).max(1));
                let (start, end) = if side == 0 {
                    (1, size / 2 - 1)
                } else {
                    (size / 2 + 1, size - 1)
                };
                for x in start..end {
                    column(x, height, *color);
                }
            }
        }
    }
}

struct Canvas {
    size: i32,
    dc: HDC,
    bitmap: HBITMAP,
    old_bitmap: HGDIOBJ,
    mask: HBITMAP,
    font: HFONT,
    small_font: HFONT,
    cpu_font: HFONT,
    backdrop: Vec<u32>,
    pixels: *mut u32,
}

impl Canvas {
    fn new(size: i32) -> Result<Self, String> {
        let mut canvas = Self {
            size,
            dc: ptr::null_mut(),
            bitmap: ptr::null_mut(),
            old_bitmap: ptr::null_mut(),
            mask: ptr::null_mut(),
            font: ptr::null_mut(),
            small_font: ptr::null_mut(),
            cpu_font: ptr::null_mut(),
            backdrop: vec![0; (size * size) as usize],
            pixels: ptr::null_mut(),
        };
        let info = BITMAPINFO {
            bmiHeader: BITMAPINFOHEADER {
                biSize: size_of::<BITMAPINFOHEADER>() as u32,
                biWidth: size,
                biHeight: -size,
                biPlanes: 1,
                biBitCount: 32,
                biCompression: BI_RGB,
                ..BITMAPINFOHEADER::default()
            },
            ..BITMAPINFO::default()
        };
        // SAFETY: the DIB is a bounded 16–64 pixel bitmap, every output is owned by canvas and released on error/Drop.
        unsafe {
            canvas.dc = CreateCompatibleDC(ptr::null_mut());
            if canvas.dc.is_null() {
                return Err("Не удалось создать значки трея".into());
            }
            let mut bits = ptr::null_mut();
            canvas.bitmap = CreateDIBSection(
                canvas.dc,
                &info,
                DIB_RGB_COLORS,
                &mut bits,
                ptr::null_mut(),
                0,
            );
            canvas.pixels = bits.cast();
            if canvas.bitmap.is_null() || canvas.pixels.is_null() {
                return Err("Не удалось создать изображение значка".into());
            }
            canvas.old_bitmap = SelectObject(canvas.dc, canvas.bitmap);
            canvas.mask = CreateBitmap(size, size, 1, 1, ptr::null());
            let face = wide("Segoe UI");
            let font = |height: i32, weight| {
                CreateFontW(
                    -height,
                    0,
                    0,
                    0,
                    weight,
                    0,
                    0,
                    0,
                    DEFAULT_CHARSET as u32,
                    OUT_DEFAULT_PRECIS as u32,
                    CLIP_DEFAULT_PRECIS as u32,
                    ANTIALIASED_QUALITY as u32,
                    DEFAULT_PITCH as u32,
                    face.as_ptr(),
                )
            };
            canvas.font = font(size * 82 / 100, 400);
            canvas.small_font = font(size * 68 / 100, 400);
            canvas.cpu_font = font((size * 55 / 100).max(8), 600);
        }
        if canvas.mask.is_null()
            || canvas.font.is_null()
            || canvas.small_font.is_null()
            || canvas.cpu_font.is_null()
        {
            return Err("Не удалось создать шрифт значков".into());
        }
        Ok(canvas)
    }

    fn render(&mut self, visual: &Visual) -> Result<Icon, String> {
        // SAFETY: pixels points to exactly size*size writable BGRA pixels owned by this canvas; GDI is flushed before direct access.
        unsafe {
            GdiFlush();
            let pixels =
                std::slice::from_raw_parts_mut(self.pixels, (self.size * self.size) as usize);
            pixels.fill(color_pixel(visual.background));
            draw_graph(pixels, self.size as usize, &visual.graph, visual.accent);
            if !visual.label.is_empty() {
                let cpu = matches!(visual.graph, Graph::Cores(_));
                let font = if cpu {
                    self.backdrop.copy_from_slice(pixels);
                    self.cpu_font
                } else if visual.label.chars().count() > 2 {
                    self.small_font
                } else {
                    self.font
                };
                let old_font = SelectObject(self.dc, font);
                SetBkMode(self.dc, TRANSPARENT as i32);
                SetTextColor(
                    self.dc,
                    if visual
                        .background
                        .iter()
                        .map(|value| u32::from(*value))
                        .sum::<u32>()
                        > 384
                    {
                        0x00202020
                    } else {
                        0x00ffffff
                    },
                );
                let text = wide(&visual.label);
                let mut rectangle = RECT {
                    left: 0,
                    top: 0,
                    right: self.size,
                    bottom: self.size,
                };
                DrawTextW(
                    self.dc,
                    text.as_ptr(),
                    -1,
                    &mut rectangle,
                    DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX,
                );
                SelectObject(self.dc, old_font);
                GdiFlush();
                let pixels = std::slice::from_raw_parts_mut(self.pixels, self.backdrop.len());
                if cpu {
                    // Average the glyph's resulting RGB with the saved chart,
                    // without carrying between color bytes. The icon stays opaque.
                    for (painted, background) in pixels.iter_mut().zip(&self.backdrop) {
                        let shared_bits = *painted & *background;
                        let differences = *painted ^ *background;
                        *painted = 0xff000000
                            | ((shared_bits + ((differences & 0x00fefefe) >> 1)) & 0x00ffffff);
                    }
                } else {
                    for pixel in pixels {
                        *pixel |= 0xff000000;
                    }
                }
            }
            let information = ICONINFO {
                fIcon: 1,
                hbmMask: self.mask,
                hbmColor: self.bitmap,
                ..ICONINFO::default()
            };
            let image = CreateIconIndirect(&information);
            if image.is_null() {
                Err("Не удалось обновить значок трея".into())
            } else {
                Ok(Icon(image))
            }
        }
    }
}

impl Drop for Canvas {
    fn drop(&mut self) {
        // SAFETY: restore selected objects, then release only resources created by this canvas.
        unsafe {
            if !self.dc.is_null() && !self.old_bitmap.is_null() {
                SelectObject(self.dc, self.old_bitmap);
            }
            for object in [
                self.bitmap,
                self.mask,
                self.font,
                self.small_font,
                self.cpu_font,
            ] {
                if !object.is_null() {
                    DeleteObject(object);
                }
            }
            if !self.dc.is_null() {
                DeleteDC(self.dc);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_cpu_icon_contains_both_core_columns_and_the_total_number() {
        let mut canvas = Canvas::new(24).unwrap();
        let visual = Visual {
            label: "52".into(),
            background: [0; 3],
            graph: Graph::Cores(vec![Some(70.0); 16]),
            accent: [38, 143, 207],
        };
        let icon = canvas.render(&visual).unwrap();
        assert!(!icon.0.is_null());
        // SAFETY: render flushed GDI; this canvas owns exactly size² readable pixels.
        let pixels = unsafe { std::slice::from_raw_parts(canvas.pixels, 24 * 24) };
        assert!(
            pixels
                .iter()
                .any(|pixel| *pixel == color_pixel(visual.accent))
        );
        let black = color_pixel(visual.background);
        let bar = color_pixel(visual.accent);
        assert!(pixels.iter().any(|pixel| *pixel != black && *pixel != bar));
        assert!(!pixels.contains(&0xffffffff));
        assert!(pixels.iter().all(|pixel| *pixel >> 24 == 255));
    }

    #[test]
    fn core_columns_keep_fixed_percent_scale_and_include_cores_narrower_than_a_pixel() {
        let mut pixels = vec![0u32; 16 * 16];
        let cores = Graph::Cores(vec![Some(0.0), Some(50.0), Some(100.0), None]);
        draw_graph(&mut pixels, 16, &cores, [20, 70, 120]);
        assert_eq!(pixels[15 * 16], 0);
        assert_ne!(pixels[15 * 16 + 4], 0);
        assert_eq!(pixels[6 * 16 + 4], 0);
        assert_ne!(pixels[8], 0);
        assert_eq!(pixels[15 * 16 + 12], 0);
        // With more cores than pixels, every core still contributes to its bucket.
        pixels.fill(0);
        draw_graph(
            &mut pixels,
            16,
            &Graph::Cores(vec![Some(50.0); 64]),
            [20, 70, 120],
        );
        assert!(pixels[15 * 16..].iter().all(|pixel| *pixel != 0));
    }

    #[test]
    fn tray_pair_has_two_independent_columns_with_a_shared_scale() {
        let mut pixels = vec![0u32; 16 * 16];
        draw_graph(
            &mut pixels,
            16,
            &Graph::Pair {
                values: [Some(100.0), Some(50.0)],
                colors: [[214, 144, 21], [191, 68, 45]],
                scale: 100.0,
            },
            [0; 3],
        );
        assert_ne!(pixels[1], 0);
        assert_eq!(pixels[10], 0);
        assert_ne!(pixels[8 * 16 + 10], 0);
        assert_eq!(pixels[15 * 16 + 7], 0); // clear centre gutter
        assert_eq!(pixels[15 * 16 + 8], 0);
        assert_ne!(pixels[15 * 16 + 1], pixels[15 * 16 + 10]);
    }
}
