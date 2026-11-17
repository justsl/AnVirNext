use crate::{
    model::{format_bytes, format_percent, format_rate},
    monitor::{Command, Shared, ViewSnapshot},
    sensors::{SensorState, cpu_temperature},
    settings::Settings,
    startup,
    win::{os_wide, wide},
};
use std::{mem::size_of, ptr};
use windows_sys::{
    Win32::{
        Foundation::{HWND, POINT, RECT},
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
pub enum TrayAction {
    Show,
    Exit,
    None,
}

#[derive(Clone, PartialEq)]
struct Visual {
    label: String,
    background: [u8; 3],
    graph: Vec<f64>,
    accent: [u8; 3],
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
    pub last_error: Option<String>,
}

impl Tray {
    pub fn new(window: HWND) -> Result<Self, String> {
        Ok(Self {
            window,
            canvas: Canvas::new(icon_size())?,
            icons: std::array::from_fn(|_| None),
            force_render: true,
            last_error: None,
        })
    }

    pub fn recreate(&mut self) {
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
                    graph: Vec::new(),
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
                    background: [111, 29, 113],
                    graph: Vec::new(),
                    accent: [255; 3],
                },
                format!(
                    "CPU: {}\n{} логических процессоров",
                    format_percent(cpu),
                    system.logical_processors
                ),
            ),
            (
                settings.memory_icon,
                Visual {
                    label: numeric(memory, false),
                    background: [47, 124, 120],
                    graph: Vec::new(),
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
                    label: String::new(),
                    background: [248, 250, 252],
                    graph: if fresh {
                        snapshot.history[3].values()
                    } else {
                        Vec::new()
                    },
                    accent: [113, 54, 195],
                },
                format!(
                    "Сеть · физические адаптеры\nПриём: {}\nПередача: {}",
                    format_rate(if fresh { system.network_receive } else { None }),
                    format_rate(if fresh { system.network_send } else { None })
                ),
            ),
            (
                settings.disk_icon,
                Visual {
                    label: String::new(),
                    background: [248, 250, 252],
                    graph: if fresh {
                        snapshot.history[2].values()
                    } else {
                        Vec::new()
                    },
                    accent: [178, 116, 0],
                },
                format!(
                    "Физические диски\nЧтение: {}\nЗапись: {}",
                    format_rate(if fresh { system.disk_read } else { None }),
                    format_rate(if fresh { system.disk_write } else { None })
                ),
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
            data.uFlags |= NIF_ICON | NIF_MESSAGE | NIF_TIP | NIF_SHOWTIP;
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
        self.force_render = false;
    }

    fn remove(&mut self, index: usize) {
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
                if let Ok(executable) = std::env::current_exe() {
                    let path = os_wide(executable.as_os_str());
                    let verb = wide("runas");
                    let parameters = wide(&format!("--replace {}", std::process::id()));
                    // SAFETY: explicit user action launches this same executable through the OS consent flow.
                    let status = unsafe {
                        ShellExecuteW(
                            window,
                            verb.as_ptr(),
                            path.as_ptr(),
                            parameters.as_ptr(),
                            ptr::null(),
                            SW_SHOWNORMAL,
                        )
                    } as isize;
                    if status > 32 {
                        return Some(TrayAction::Exit);
                    }
                    shared.post_notice(
                        "Запуск с правами администратора не выполнен".into(),
                        true,
                        false,
                    );
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

struct Canvas {
    size: i32,
    dc: HDC,
    bitmap: HBITMAP,
    old_bitmap: HGDIOBJ,
    mask: HBITMAP,
    font: HFONT,
    small_font: HFONT,
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
            canvas.font = CreateFontW(
                -(size * 82 / 100),
                0,
                0,
                0,
                400,
                0,
                0,
                0,
                DEFAULT_CHARSET as u32,
                OUT_DEFAULT_PRECIS as u32,
                CLIP_DEFAULT_PRECIS as u32,
                ANTIALIASED_QUALITY as u32,
                DEFAULT_PITCH as u32,
                face.as_ptr(),
            );
            canvas.small_font = CreateFontW(
                -(size * 68 / 100),
                0,
                0,
                0,
                400,
                0,
                0,
                0,
                DEFAULT_CHARSET as u32,
                OUT_DEFAULT_PRECIS as u32,
                CLIP_DEFAULT_PRECIS as u32,
                ANTIALIASED_QUALITY as u32,
                DEFAULT_PITCH as u32,
                face.as_ptr(),
            );
        }
        if canvas.mask.is_null() || canvas.font.is_null() || canvas.small_font.is_null() {
            return Err("Не удалось создать шрифт значков".into());
        }
        Ok(canvas)
    }

    fn render(&mut self, visual: &Visual) -> Result<Icon, String> {
        let pixel = |color: [u8; 3]| {
            0xff000000
                | (u32::from(color[0]) << 16)
                | (u32::from(color[1]) << 8)
                | u32::from(color[2])
        };
        // SAFETY: pixels points to exactly size*size writable BGRA pixels owned by this canvas; GDI is flushed before direct access.
        unsafe {
            GdiFlush();
            std::slice::from_raw_parts_mut(self.pixels, (self.size * self.size) as usize)
                .fill(pixel(visual.background));
            if visual.label.is_empty() {
                let pixels =
                    std::slice::from_raw_parts_mut(self.pixels, (self.size * self.size) as usize);
                let width = self.size as usize;
                let maximum = visual.graph.iter().copied().fold(1.0, f64::max);
                for x in 0..width {
                    let height = if visual.graph.is_empty() {
                        0
                    } else {
                        let value = visual.graph[x * visual.graph.len() / width];
                        (value / maximum * (self.size - 4) as f64)
                            .clamp(0.0, (self.size - 4) as f64) as usize
                    };
                    for y in (width - height)..width {
                        pixels[y * width + x] = pixel(visual.accent);
                    }
                    pixels[(width - 1) * width + x] = pixel(visual.accent);
                }
                for y in 1..3 {
                    for x in 1..4 {
                        pixels[y * width + x] = pixel(visual.accent);
                    }
                }
            } else {
                let font = if visual.label.chars().count() > 2 {
                    self.small_font
                } else {
                    self.font
                };
                let old_font = SelectObject(self.dc, font);
                SetBkMode(self.dc, TRANSPARENT as i32);
                SetTextColor(self.dc, 0x00ffffff);
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
                for pixel in
                    std::slice::from_raw_parts_mut(self.pixels, (self.size * self.size) as usize)
                {
                    *pixel |= 0xff000000;
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
            for object in [self.bitmap, self.mask, self.font, self.small_font] {
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
