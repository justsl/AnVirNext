//! Native, owner-data Win32 process and system viewer.
use crate::{
    model::{format_bytes, format_percent, format_rate},
    monitor::{Command, Shared, UiStatus, ViewSnapshot},
    process_rules::ProcessRule,
    processes::{ProcessDetails, ProcessRow},
    scheduling_dialog,
    sensors::SensorState,
    startup::{StartupEntry, StartupSnapshot},
    tray::{Tray, TrayAction},
    win::{WM_SAMPLE_UPDATED, wide},
};
use std::{
    cell::RefCell,
    cmp::Ordering as Compare,
    mem::size_of,
    ptr,
    sync::{Arc, atomic::Ordering},
    time::Duration,
};
use windows_sys::Win32::{
    Foundation::*,
    Graphics::Gdi::*,
    System::LibraryLoader::GetModuleHandleW,
    UI::{
        Controls::*, HiDpi::GetDpiForWindow, Input::KeyboardAndMouse::EnableWindow, Shell::*,
        WindowsAndMessaging::*,
    },
};

const FILTER: usize = 102;
pub const WINDOW_CLASS: &str = "AnVirNext.Main";
const WM_SHOW_EXISTING: u32 = WM_APP + 10;
const PRIMARY: usize = 103;
const SECONDARY: usize = 104;
const THIRD: usize = 105;
const SETTINGS: usize = 106;
const TABLE: usize = 107;
const TABS: usize = 108;
const STALE_AFTER: Duration = Duration::from_secs(10);
const NIN_KEYSELECT_NOTIFICATION: u32 = NIN_SELECT | NINF_KEY;
// Win32 integer resources are low-word IDs, not aligned/dereferenceable pointers.
const APP_ICON_RESOURCE: *const u16 = ptr::without_provenance::<u16>(1);

#[derive(Clone, Debug, PartialEq, Eq)]
enum Key {
    Process(u32, u64),
    Entry(String),
    Rule(String),
    Sensor(String),
}
struct Row {
    key: Key,
    cells: Vec<String>,
}

struct Ui {
    hwnd: HWND,
    shared: Arc<Shared>,
    tray: Option<Tray>,
    taskbar_created: u32,
    summary: HWND,
    tabs: HWND,
    filter_label: HWND,
    filter: HWND,
    table: HWND,
    primary: HWND,
    secondary: HWND,
    third: HWND,
    settings: HWND,
    details_label: HWND,
    details_edit: HWND,
    status_line: HWND,
    font: HFONT,
    summary_font: HFONT,
    dpi: u32,
    tab: usize,
    column_count: usize,
    sort: usize,
    descending: bool,
    filter_text: String,
    snapshot: ViewSnapshot,
    status: UiStatus,
    sensor: SensorState,
    startup: Arc<StartupSnapshot>,
    rules: Vec<ProcessRule>,
    order: Vec<usize>,
    order_keys: Vec<Key>,
    other: Vec<Row>,
    selected: Option<Key>,
    details_text: String,
    notice_id: u64,
}

enum Effect {
    None,
    Error(String),
    Popup(String, bool),
    Exit,
    Confirm {
        text: String,
        command: Command,
    },
    Schedule {
        pid: u32,
        created: u64,
        details: ProcessDetails,
    },
}

struct WindowState {
    shared: Arc<Shared>,
    ui: RefCell<Ui>,
}

impl Drop for Ui {
    fn drop(&mut self) {
        self.shared.notifier.bind(ptr::null_mut());
        self.tray.take();
        // SAFETY: fonts are exclusively owned and their controls have been destroyed.
        unsafe {
            DeleteObject(self.font);
            DeleteObject(self.summary_font);
        }
    }
}

fn identity(row: &ProcessRow) -> Key {
    Key::Process(row.pid, row.times.map(|times| times.created).unwrap_or(0))
}

fn process_cell(row: &ProcessRow, column: usize) -> String {
    match column {
        0 => format!(
            "{}{}",
            row.name,
            if row.is_64_bit == Some(false) {
                " (32 бит)"
            } else {
                ""
            }
        ),
        1 => row.product.clone(),
        2 => format_percent(row.cpu),
        3 => format_rate(row.io_rate),
        4 => row
            .memory
            .map(|bytes| format_bytes(bytes as f64))
            .unwrap_or_else(|| "—".into()),
        5 => row.company.clone(),
        6 => row.path.clone(),
        7 => row.pid.to_string(),
        _ => String::new(),
    }
}

fn compare_process(a: &ProcessRow, b: &ProcessRow, column: usize) -> Compare {
    match column {
        0 => a.name.cmp(&b.name),
        1 => a.product.cmp(&b.product),
        2 => a.cpu.partial_cmp(&b.cpu).unwrap_or(Compare::Equal),
        3 => a.io_rate.partial_cmp(&b.io_rate).unwrap_or(Compare::Equal),
        4 => a.memory.cmp(&b.memory),
        5 => a.company.cmp(&b.company),
        6 => a.path.cmp(&b.path),
        7 => a.pid.cmp(&b.pid),
        _ => Compare::Equal,
    }
    .then_with(|| a.pid.cmp(&b.pid))
}

fn matches_process(row: &ProcessRow, filter: &str) -> bool {
    filter.is_empty()
        || [&row.name, &row.product, &row.company, &row.path]
            .iter()
            .any(|value| value.to_lowercase().contains(filter))
        || row.pid.to_string().contains(filter)
}

fn scroll_target(previous_top: usize, anchor_index: Option<usize>, row_count: usize) -> usize {
    // Row zero follows the sort, while a manually scrolled view follows its process.
    if previous_top == 0 {
        return 0;
    }
    anchor_index
        .unwrap_or(previous_top)
        .min(row_count.saturating_sub(1))
}

fn detail_view_demand(is_visible: bool, is_iconic: bool) -> bool {
    is_visible && !is_iconic
}

unsafe fn update_visibility(hwnd: HWND, shared: &Shared) -> bool {
    // SAFETY: caller owns the live window on this UI thread; both queries take opaque handles.
    let demand = unsafe { detail_view_demand(IsWindowVisible(hwnd) != 0, IsIconic(hwnd) != 0) };
    shared.visible.store(demand, Ordering::Release);
    demand
}

impl Ui {
    fn scale(&self, value: i32) -> i32 {
        value * self.dpi as i32 / 96
    }

    unsafe fn initialize(hwnd: HWND, shared: Arc<Shared>) -> Result<Self, String> {
        // SAFETY: hwnd belongs to this UI thread; all temporary strings outlive synchronous calls.
        unsafe {
            let mut ui = Self {
                hwnd,
                snapshot: shared.snapshot(),
                status: shared.ui_status(),
                shared,
                tray: None,
                taskbar_created: RegisterWindowMessageW(wide("TaskbarCreated").as_ptr()),
                summary: ptr::null_mut(),
                tabs: ptr::null_mut(),
                filter_label: ptr::null_mut(),
                filter: ptr::null_mut(),
                table: ptr::null_mut(),
                primary: ptr::null_mut(),
                secondary: ptr::null_mut(),
                third: ptr::null_mut(),
                settings: ptr::null_mut(),
                details_label: ptr::null_mut(),
                details_edit: ptr::null_mut(),
                status_line: ptr::null_mut(),
                font: ptr::null_mut(),
                summary_font: ptr::null_mut(),
                dpi: GetDpiForWindow(hwnd).max(96),
                tab: 0,
                column_count: 0,
                sort: 2,
                descending: true,
                filter_text: String::new(),
                sensor: SensorState::default(),
                startup: Arc::new(StartupSnapshot::default()),
                rules: Vec::new(),
                order: Vec::new(),
                order_keys: Vec::new(),
                other: Vec::new(),
                selected: None,
                details_text: String::new(),
                notice_id: 0,
            };
            ui.summary = ui.child("STATIC", "AnVir Next · Получение данных…", 0, 0, 0);
            ui.tabs = ui.child("SysTabControl32", "", WS_TABSTOP | TCS_FOCUSNEVER, TABS, 0);
            for (index, title) in ["Процессы", "Автозагрузка", "Датчики", "Сохранённые правила"]
                .iter()
                .enumerate()
            {
                let mut title = wide(title);
                let item = TCITEMW {
                    mask: TCIF_TEXT,
                    pszText: title.as_mut_ptr(),
                    ..Default::default()
                };
                SendMessageW(
                    ui.tabs,
                    TCM_INSERTITEMW,
                    index,
                    (&item as *const TCITEMW) as isize,
                );
            }
            ui.filter_label = ui.child("STATIC", "Фильтр:", 0, 0, 0);
            ui.filter = ui.child(
                "EDIT",
                "",
                WS_TABSTOP | ES_AUTOHSCROLL as u32,
                FILTER,
                WS_EX_CLIENTEDGE,
            );
            SendMessageW(ui.filter, EM_SETLIMITTEXT, 256, 0);
            ui.primary = ui.child(
                "BUTTON",
                "Завершить…",
                WS_TABSTOP | BS_PUSHBUTTON as u32,
                PRIMARY,
                0,
            );
            ui.secondary = ui.child(
                "BUTTON",
                "Приоритет / CPU…",
                WS_TABSTOP | BS_PUSHBUTTON as u32,
                SECONDARY,
                0,
            );
            ui.third = ui.child(
                "BUTTON",
                "Открыть папку",
                WS_TABSTOP | BS_PUSHBUTTON as u32,
                THIRD,
                0,
            );
            ui.settings = ui.child(
                "BUTTON",
                "Настройки ▾",
                WS_TABSTOP | BS_PUSHBUTTON as u32,
                SETTINGS,
                0,
            );
            ui.table = ui.child(
                "SysListView32",
                "",
                WS_TABSTOP | LVS_REPORT | LVS_OWNERDATA | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
                TABLE,
                WS_EX_CLIENTEDGE,
            );
            SendMessageW(
                ui.table,
                LVM_SETEXTENDEDLISTVIEWSTYLE,
                0,
                (LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP) as isize,
            );
            ui.details_label = ui.child(
                "STATIC",
                "Командная строка и параметры выбранного процесса (можно копировать)",
                0,
                0,
                0,
            );
            ui.details_edit = ui.child(
                "EDIT",
                "Выберите процесс в таблице.",
                WS_TABSTOP
                    | WS_VSCROLL
                    | WS_HSCROLL
                    | ES_MULTILINE as u32
                    | ES_AUTOVSCROLL as u32
                    | ES_AUTOHSCROLL as u32
                    | ES_READONLY as u32,
                0,
                WS_EX_CLIENTEDGE,
            );
            SendMessageW(ui.details_edit, EM_SETLIMITTEXT, 262144, 0);
            ui.status_line = ui.child("STATIC", "", 0, 0, 0);
            if [
                ui.summary,
                ui.tabs,
                ui.filter_label,
                ui.filter,
                ui.primary,
                ui.secondary,
                ui.third,
                ui.settings,
                ui.table,
                ui.details_label,
                ui.details_edit,
                ui.status_line,
            ]
            .iter()
            .any(|control| control.is_null())
            {
                DestroyWindow(hwnd);
                return Err(format!(
                    "Не удалось создать элементы окна: {}",
                    std::io::Error::last_os_error()
                ));
            }
            ui.set_fonts();
            ui.set_columns();
            ui.layout();
            ui.tray = Some(match Tray::new(hwnd) {
                Ok(tray) => tray,
                Err(error) => {
                    DestroyWindow(hwnd);
                    return Err(error);
                }
            });
            Ok(ui)
        }
    }

    unsafe fn child(&self, class: &str, title: &str, style: u32, id: usize, extended: u32) -> HWND {
        // SAFETY: the parent is live on this thread; Win32 copies both terminated strings.
        unsafe {
            CreateWindowExW(
                extended,
                wide(class).as_ptr(),
                wide(title).as_ptr(),
                WS_CHILD | WS_VISIBLE | style,
                0,
                0,
                10,
                10,
                self.hwnd,
                id as HMENU,
                GetModuleHandleW(ptr::null()),
                ptr::null(),
            )
        }
    }

    unsafe fn set_fonts(&mut self) {
        // SAFETY: all controls are owned here; old fonts are detached before deletion.
        unsafe {
            let create = |height| {
                CreateFontW(
                    -self.scale(height),
                    0,
                    0,
                    0,
                    FW_NORMAL as i32,
                    0,
                    0,
                    0,
                    DEFAULT_CHARSET as u32,
                    OUT_DEFAULT_PRECIS as u32,
                    CLIP_DEFAULT_PRECIS as u32,
                    CLEARTYPE_QUALITY as u32,
                    DEFAULT_PITCH as u32,
                    wide("Segoe UI").as_ptr(),
                )
            };
            let font = create(14);
            let summary_font = create(18);
            if !font.is_null() {
                for control in [
                    self.tabs,
                    self.filter_label,
                    self.filter,
                    self.primary,
                    self.secondary,
                    self.third,
                    self.settings,
                    self.table,
                    self.details_label,
                    self.details_edit,
                    self.status_line,
                ] {
                    SendMessageW(control, WM_SETFONT, font as usize, 1);
                }
                let old = std::mem::replace(&mut self.font, font);
                DeleteObject(old);
            }
            if !summary_font.is_null() {
                SendMessageW(self.summary, WM_SETFONT, summary_font as usize, 1);
                let old = std::mem::replace(&mut self.summary_font, summary_font);
                DeleteObject(old);
            }
        }
    }

    unsafe fn layout(&self) {
        // SAFETY: child handles and writable RECT belong to the current UI thread.
        unsafe {
            let mut client = RECT::default();
            GetClientRect(self.hwnd, &mut client);
            let s = |value| self.scale(value);
            let width = client.right;
            let height = client.bottom;
            let move_control = |control, x, y, w: i32, h: i32| {
                MoveWindow(control, x, y, w.max(1), h.max(1), 1);
            };
            move_control(self.summary, s(12), s(12), width - s(24), s(29));
            move_control(self.tabs, s(10), s(50), width - s(20), s(30));
            move_control(self.filter_label, s(12), s(92), s(60), s(24));
            move_control(self.filter, s(72), s(86), s(200), s(28));
            move_control(self.primary, s(284), s(85), s(120), s(30));
            move_control(self.secondary, s(410), s(85), s(155), s(30));
            move_control(self.third, s(571), s(85), s(134), s(30));
            move_control(self.settings, width - s(145), s(85), s(133), s(30));
            let detail_height = s(142).min((height / 3).max(s(85)));
            let table_bottom = height - detail_height - s(74);
            move_control(
                self.table,
                s(10),
                s(124),
                width - s(20),
                table_bottom - s(124),
            );
            move_control(
                self.details_label,
                s(12),
                table_bottom + s(10),
                width - s(24),
                s(23),
            );
            move_control(
                self.details_edit,
                s(10),
                table_bottom + s(36),
                width - s(20),
                detail_height,
            );
            move_control(
                self.status_line,
                s(12),
                height - s(27),
                width - s(24),
                s(24),
            );
        }
    }

    unsafe fn set_columns(&mut self) {
        // SAFETY: the listview copies column strings and structures synchronously.
        unsafe {
            for _ in 0..self.column_count {
                SendMessageW(self.table, LVM_DELETECOLUMN, 0, 0);
            }
            let columns: &[(&str, i32, bool)] = match self.tab {
                0 => &[
                    ("Процесс", 190, false),
                    ("Продукт", 180, false),
                    ("CPU %", 75, true),
                    ("I/O, Б/с", 110, true),
                    ("Память (раб. набор)", 145, true),
                    ("Компания", 160, false),
                    ("Исполняемый файл", 330, false),
                    ("PID", 75, true),
                ],
                1 => &[
                    ("Имя", 220, false),
                    ("Состояние", 155, false),
                    ("Источник", 240, false),
                    ("Команда", 450, false),
                    ("Расположение", 400, false),
                ],
                2 => &[
                    ("Оборудование", 285, false),
                    ("Датчик", 280, false),
                    ("Тип", 155, false),
                    ("Значение", 140, true),
                ],
                _ => &[
                    ("Исполняемый файл", 600, false),
                    ("Приоритет", 180, false),
                    ("Маска процессоров", 180, false),
                ],
            };
            self.column_count = columns.len();
            for (index, (name, width, numeric)) in columns.iter().enumerate() {
                let mut title = wide(name);
                let column = LVCOLUMNW {
                    mask: LVCF_TEXT | LVCF_WIDTH | LVCF_FMT,
                    fmt: if *numeric { LVCFMT_RIGHT } else { LVCFMT_LEFT },
                    cx: self.scale(*width),
                    pszText: title.as_mut_ptr(),
                    ..Default::default()
                };
                SendMessageW(
                    self.table,
                    LVM_INSERTCOLUMNW,
                    index,
                    (&column as *const LVCOLUMNW) as isize,
                );
            }
        }
    }

    fn len(&self) -> usize {
        if self.tab == 0 {
            self.order.len()
        } else {
            self.other.len()
        }
    }
    fn key(&self, index: usize) -> Option<Key> {
        if self.tab == 0 {
            self.order_keys.get(index).cloned()
        } else {
            self.other.get(index).map(|row| row.key.clone())
        }
    }
    fn cell(&self, index: usize, column: usize) -> String {
        if self.tab == 0 {
            self.order
                .get(index)
                .and_then(|index| self.snapshot.processes.get(*index))
                .map(|row| {
                    if self.snapshot.updated.elapsed() > STALE_AFTER && matches!(column, 2..=4) {
                        "—".into()
                    } else {
                        process_cell(row, column)
                    }
                })
                .unwrap_or_default()
        } else {
            self.other
                .get(index)
                .and_then(|row| row.cells.get(column))
                .cloned()
                .unwrap_or_default()
        }
    }

    unsafe fn rebuild(&mut self, preserve_scroll: bool) {
        // SAFETY: item indices are bounded by the installed virtual count; structs live through SendMessage.
        unsafe {
            let old_top = if preserve_scroll {
                SendMessageW(self.table, LVM_GETTOPINDEX, 0, 0).max(0) as usize
            } else {
                0
            };
            let top_key = self.key(old_top);
            if self.tab == 0 {
                self.order = self
                    .snapshot
                    .processes
                    .iter()
                    .enumerate()
                    .filter(|(_, row)| matches_process(row, &self.filter_text))
                    .map(|(index, _)| index)
                    .collect();
                let rows = &self.snapshot.processes;
                let column = self.sort;
                let descending = self.descending;
                self.order.sort_unstable_by(|a, b| {
                    let order = compare_process(&rows[*a], &rows[*b], column);
                    if descending { order.reverse() } else { order }
                });
                self.order_keys = self
                    .order
                    .iter()
                    .map(|index| identity(&rows[*index]))
                    .collect();
            } else {
                self.other = match self.tab {
                    1 => self
                        .startup
                        .entries
                        .iter()
                        .map(|entry| Row {
                            key: Key::Entry(entry.id.clone()),
                            cells: vec![
                                entry.name.clone(),
                                if entry.source.contains("status unknown") {
                                    "Неизвестно".into()
                                } else if entry.enabled {
                                    "Включено".into()
                                } else {
                                    "Отключено".into()
                                },
                                entry.source.clone(),
                                entry.command.clone(),
                                entry.location.clone(),
                            ],
                        })
                        .collect(),
                    2 => self
                        .sensor
                        .current()
                        .map(|frame| {
                            frame
                                .sensors
                                .iter()
                                .map(|sensor| Row {
                                    key: Key::Sensor(sensor.id.clone()),
                                    cells: vec![
                                        sensor.hardware.clone(),
                                        sensor.name.clone(),
                                        sensor.kind.clone(),
                                        sensor.display_value(),
                                    ],
                                })
                                .collect()
                        })
                        .unwrap_or_default(),
                    _ => self
                        .rules
                        .iter()
                        .map(|rule| Row {
                            key: Key::Rule(rule.executable.clone()),
                            cells: vec![
                                rule.executable.clone(),
                                scheduling_dialog::priority_name(rule.priority).into(),
                                format!("0x{:016X}", rule.affinity),
                            ],
                        })
                        .collect(),
                };
                if !self.filter_text.is_empty() {
                    self.other.retain(|row| {
                        row.cells
                            .iter()
                            .any(|cell| cell.to_lowercase().contains(&self.filter_text))
                    });
                }
                let column = self.sort;
                let descending = self.descending;
                self.other.sort_by(|a, b| {
                    let order = a.cells.get(column).cmp(&b.cells.get(column));
                    if descending { order.reverse() } else { order }
                });
            }
            SendMessageW(self.table, WM_SETREDRAW, 0, 0);
            SendMessageW(
                self.table,
                LVM_SETITEMCOUNT,
                self.len(),
                (LVSICF_NOINVALIDATEALL | LVSICF_NOSCROLL) as isize,
            );
            let mut item = LVITEMW {
                stateMask: LVIS_SELECTED | LVIS_FOCUSED,
                ..Default::default()
            };
            SendMessageW(
                self.table,
                LVM_SETITEMSTATE,
                usize::MAX,
                (&item as *const LVITEMW) as isize,
            );
            let selected_index = self.selected.as_ref().and_then(|key| {
                (0..self.len()).find(|index| self.key(*index).as_ref() == Some(key))
            });
            if let Some(index) = selected_index {
                item.state = LVIS_SELECTED | LVIS_FOCUSED;
                SendMessageW(
                    self.table,
                    LVM_SETITEMSTATE,
                    index,
                    (&item as *const LVITEMW) as isize,
                );
            } else {
                self.selected = None;
            }
            let anchor_index = top_key.and_then(|key| {
                (0..self.len()).find(|index| self.key(*index).as_ref() == Some(&key))
            });
            let top = scroll_target(old_top, anchor_index, self.len());
            let current_top = SendMessageW(self.table, LVM_GETTOPINDEX, 0, 0).max(0) as i32;
            let mut rect = RECT {
                left: LVIR_BOUNDS as i32,
                ..Default::default()
            };
            if self.len() > 0
                && SendMessageW(
                    self.table,
                    LVM_GETITEMRECT,
                    0,
                    (&mut rect as *mut RECT) as isize,
                ) != 0
            {
                SendMessageW(
                    self.table,
                    LVM_SCROLL,
                    0,
                    ((top as i32 - current_top) * (rect.bottom - rect.top)) as isize,
                );
            }
            SendMessageW(self.table, WM_SETREDRAW, 1, 0);
            InvalidateRect(self.table, ptr::null(), 0);
            self.show_details();
            self.buttons();
        }
    }

    fn selected_details(&self) -> Option<(u32, u64, ProcessDetails)> {
        let Key::Process(pid, created) = self.selected.as_ref()? else {
            return None;
        };
        if *created == 0 {
            return None;
        }
        let details = self.status.details.as_ref()?;
        if details.pid != *pid || details.created != *created {
            return None;
        }
        details
            .result
            .as_ref()
            .ok()
            .filter(|details| details.created == *created)
            .map(|details| (*pid, *created, details.clone()))
    }

    fn selected_startup(&self) -> Option<StartupEntry> {
        let Key::Entry(id) = self.selected.as_ref()? else {
            return None;
        };
        self.startup
            .entries
            .iter()
            .find(|entry| entry.id == *id)
            .cloned()
    }

    unsafe fn show_details(&mut self) {
        let text = match self.tab {
            0 => if let Some((pid, _, details)) = self.selected_details() {
                format!("Командная строка:\r\n{}\r\n\r\nФайл: {}\r\nPID: {}    Родитель: {}    Приоритет: {}    Процессоры: 0x{:016X}", details.command_line, details.path, pid, details.parent_pid, scheduling_dialog::priority_name(details.priority), details.affinity)
            } else if let Some(Key::Process(pid, created)) = &self.selected {
                self.status.details.as_ref().filter(|details| details.pid == *pid && details.created == *created).and_then(|details| details.result.as_ref().err()).cloned()
                    .unwrap_or_else(|| if *created == 0 { "Детали недоступны: не удалось проверить время создания процесса.".into() } else { "Чтение командной строки и параметров процесса…".into() })
            } else { "Выберите процесс. Полная командная строка и аргументы появятся здесь.".into() },
            1 => {
                let warnings = self.startup.warnings.join("\r\n");
                let details = self.selected_startup().map(|entry| format!("Команда:\r\n{}\r\n\r\nИсточник: {}\r\nРасположение: {}{}", entry.command, entry.source, entry.location,
                    if entry.can_toggle { "" } else { "\r\nЭта запись доступна только для чтения." })).unwrap_or_else(|| "Выберите запись автозагрузки. RunOnce и службы доступны только для чтения.".into());
                if warnings.is_empty() { details } else { format!("{details}\r\n\r\nПредупреждения сканирования:\r\n{warnings}") }
            }
            2 => self.sensor.status(),
            _ => match &self.selected { Some(Key::Rule(path)) => format!("Правило применяется к новым запускам этого файла:\r\n{path}\r\n\r\nУдаление правила не меняет уже работающие процессы."), _ => "Сохранённые приоритеты и маски CPU применяются только к новым запускам указанного .exe.".into() },
        };
        if text != self.details_text {
            // SAFETY: EDIT is live; SetWindowText copies the terminated UTF-16 buffer.
            unsafe {
                SetWindowTextW(self.details_edit, wide(&text).as_ptr());
            }
            self.details_text = text;
        }
    }

    unsafe fn buttons(&self) {
        // SAFETY: controls are owned on this thread and text buffers survive each call.
        unsafe {
            let (primary, secondary, third) = match self.tab {
                0 => ("Завершить…", "Приоритет / CPU…", "Открыть папку"),
                1 => ("Обновить", "Вкл. / выкл.…", ""),
                2 => ("", "", ""),
                _ => ("Удалить правило…", "", ""),
            };
            for (control, text) in [
                (self.primary, primary),
                (self.secondary, secondary),
                (self.third, third),
            ] {
                SetWindowTextW(control, wide(text).as_ptr());
                ShowWindow(control, if text.is_empty() { SW_HIDE } else { SW_SHOW });
            }
            let process = self.selected_details().is_some();
            EnableWindow(
                self.primary,
                match self.tab {
                    0 => process,
                    1 => !self.status.startup_loading,
                    3 => matches!(self.selected, Some(Key::Rule(_))),
                    _ => false,
                } as i32,
            );
            EnableWindow(
                self.secondary,
                if self.tab == 0 {
                    process
                } else {
                    self.selected_startup()
                        .is_some_and(|entry| entry.can_toggle)
                } as i32,
            );
            EnableWindow(self.third, process as i32);
        }
    }

    unsafe fn refresh(&mut self, force: bool) -> Effect {
        // SAFETY: no worker touches controls; snapshot locks are released before Win32 calls.
        unsafe {
            let next = self.shared.snapshot();
            let processes_changed = !Arc::ptr_eq(&next.processes, &self.snapshot.processes);
            self.snapshot = next;
            self.status = self.shared.ui_status();
            self.sensor = self
                .shared
                .sensors
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .clone();
            let startup_changed = !Arc::ptr_eq(&self.startup, &self.status.startup);
            self.startup = Arc::clone(&self.status.startup);
            let rules = self.shared.saved_rules();
            let rules_changed = self.rules.len() != rules.len()
                || self.rules.iter().zip(&rules).any(|(a, b)| {
                    a.executable != b.executable
                        || a.priority != b.priority
                        || a.affinity != b.affinity
                });
            self.rules = rules;
            let stale = self.snapshot.updated.elapsed() > STALE_AFTER;
            let s = &self.snapshot.system;
            let temperature = self
                .sensor
                .current()
                .and_then(|frame| crate::sensors::cpu_temperature(&frame))
                .map(|value| format!("{value:.0} °C"))
                .unwrap_or_else(|| "—".into());
            let summary = if stale {
                "CPU —     Память —     Диск —     Сеть —     CPU t° —".into()
            } else {
                format!(
                    "CPU {}     Память {}     Диск {}     Сеть ↓{} ↑{}     CPU t° {}",
                    format_percent(s.cpu),
                    format_percent(s.memory_percent),
                    format_rate(
                        s.disk_read
                            .zip(s.disk_write)
                            .map(|(read, write)| read + write)
                    ),
                    format_rate(s.network_receive),
                    format_rate(s.network_send),
                    temperature
                )
            };
            SetWindowTextW(self.summary, wide(&summary).as_ptr());
            if let Some(tray) = &mut self.tray {
                tray.update(
                    &self.snapshot,
                    &self.sensor,
                    &self.shared.current_settings(),
                );
            }
            if update_visibility(self.hwnd, &self.shared) {
                if force
                    || match self.tab {
                        0 => processes_changed,
                        1 => startup_changed,
                        2 => true,
                        _ => rules_changed,
                    }
                {
                    self.rebuild(true);
                } else {
                    self.show_details();
                    self.buttons();
                    if stale {
                        InvalidateRect(self.table, ptr::null(), 0);
                    }
                }
                let status = if stale {
                    "Данные не обновлялись более 10 секунд".into()
                } else if let Some(notice) = &self.status.notice {
                    notice.text.clone()
                } else if let Some(error) =
                    self.tray.as_ref().and_then(|tray| tray.last_error.as_ref())
                {
                    format!("Значки панели задач: {error}")
                } else if self.tab == 2 {
                    self.sensor.status()
                } else if self.tab == 1 && self.status.startup_loading {
                    "Сканирование автозагрузки…".into()
                } else if self.tab == 0 {
                    self.snapshot.process_error.clone().unwrap_or_else(|| {
                        format!(
                            "{} процессов · I/O включает файловые и другие операции устройств",
                            self.snapshot.processes.len()
                        )
                    })
                } else {
                    format!("Записей: {}", self.len())
                };
                SetWindowTextW(self.status_line, wide(&status).as_ptr());
            }
            if let Some(notice) = &self.status.notice {
                if notice.id != self.notice_id {
                    self.notice_id = notice.id;
                    if notice.popup {
                        return Effect::Popup(notice.text.clone(), notice.is_error);
                    }
                }
            }
            Effect::None
        }
    }

    unsafe fn select(&mut self) -> Effect {
        // SAFETY: the listview query returns an index, which key() bounds-checks.
        unsafe {
            let index = SendMessageW(
                self.table,
                LVM_GETNEXTITEM,
                usize::MAX,
                LVNI_SELECTED as isize,
            );
            let key = if index < 0 {
                None
            } else {
                self.key(index as usize)
            };
            if key == self.selected {
                return Effect::None;
            }
            self.selected = key;
            let result = if let Some(Key::Process(pid, created)) = self.selected {
                if created != 0 {
                    self.shared.send(Command::SelectProcess { pid, created })
                } else {
                    Ok(())
                }
            } else {
                Ok(())
            };
            self.show_details();
            self.buttons();
            result.err().map(Effect::Error).unwrap_or(Effect::None)
        }
    }

    unsafe fn change_tab(&mut self) -> Effect {
        // SAFETY: controls are live; the selected tab index is clamped before use.
        unsafe {
            let tab = SendMessageW(self.tabs, TCM_GETCURSEL, 0, 0).clamp(0, 3) as usize;
            if tab == self.tab {
                return Effect::None;
            }
            self.tab = tab;
            self.shared.active_tab.store(tab, Ordering::Release);
            self.selected = None;
            self.sort = if tab == 0 { 2 } else { 0 };
            self.descending = tab == 0;
            self.filter_text.clear();
            SetWindowTextW(self.filter, wide("").as_ptr());
            SetWindowTextW(
                self.details_label,
                wide(if tab == 0 {
                    "Командная строка и параметры выбранного процесса (можно копировать)"
                } else {
                    "Подробности (текст можно выделять и копировать)"
                })
                .as_ptr(),
            );
            SendMessageW(self.table, LVM_SETITEMCOUNT, 0, 0);
            self.order.clear();
            self.order_keys.clear();
            self.other.clear();
            self.set_columns();
            if tab == 1 {
                if let Err(error) = self.shared.send(Command::RefreshStartup) {
                    return Effect::Error(error);
                }
            }
            self.refresh(true)
        }
    }

    unsafe fn command(&mut self, id: usize, notification: u16) -> Effect {
        // SAFETY: UI-thread handles are live and text capacity is bounded before retrieval.
        unsafe {
            if id == FILTER && notification == EN_CHANGE as u16 {
                let length = GetWindowTextLengthW(self.filter).clamp(0, 256) as usize;
                let mut buffer = vec![0u16; length + 1];
                GetWindowTextW(self.filter, buffer.as_mut_ptr(), buffer.len() as i32);
                self.filter_text = String::from_utf16_lossy(&buffer[..length]).to_lowercase();
                self.rebuild(false);
                return Effect::None;
            }
            if id == SETTINGS {
                let action = self
                    .tray
                    .as_mut()
                    .and_then(|tray| tray.settings_menu(self.hwnd, &self.shared));
                return match action {
                    Some(TrayAction::Exit) => Effect::Exit,
                    _ => Effect::None,
                };
            }
            match (self.tab, id) {
                (0, PRIMARY) => {
                    if let Some((pid, created, details)) = self.selected_details() {
                        Effect::Confirm {
                            text: format!(
                                "Завершить процесс PID {pid}? Несохранённые данные могут быть потеряны.\r\n\r\n{}",
                                details.path
                            ),
                            command: Command::Terminate { pid, created },
                        }
                    } else {
                        Effect::None
                    }
                }
                (0, SECONDARY) => self
                    .selected_details()
                    .map(|(pid, created, details)| Effect::Schedule {
                        pid,
                        created,
                        details,
                    })
                    .unwrap_or(Effect::None),
                (0, THIRD) => {
                    if let Some((_, _, details)) = self.selected_details() {
                        if let Some(parent) = std::path::Path::new(&details.path)
                            .parent()
                            .filter(|path| path.is_absolute())
                        {
                            let folder = crate::win::os_wide(parent.as_os_str());
                            if ShellExecuteW(
                                self.hwnd,
                                wide("open").as_ptr(),
                                folder.as_ptr(),
                                ptr::null(),
                                ptr::null(),
                                SW_SHOWNORMAL,
                            ) as isize
                                <= 32
                            {
                                return Effect::Error(
                                    "Не удалось открыть папку исполняемого файла".into(),
                                );
                            }
                        }
                    }
                    Effect::None
                }
                (1, PRIMARY) => self
                    .shared
                    .send(Command::RefreshStartup)
                    .err()
                    .map(Effect::Error)
                    .unwrap_or(Effect::None),
                (1, SECONDARY) => {
                    if let Some(entry) = self.selected_startup().filter(|entry| entry.can_toggle) {
                        let enabled = !entry.enabled;
                        Effect::Confirm {
                            text: format!(
                                "{} запись автозагрузки «{}»?\r\n\r\n{}\r\n{}",
                                if enabled {
                                    "Включить"
                                } else {
                                    "Отключить"
                                },
                                entry.name,
                                entry.source,
                                entry.command
                            ),
                            command: Command::ToggleStartup { entry, enabled },
                        }
                    } else {
                        Effect::None
                    }
                }
                (3, PRIMARY) => {
                    if let Some(Key::Rule(executable)) = &self.selected {
                        Effect::Confirm {
                            text: format!(
                                "Удалить сохранённое правило для будущих запусков?\r\n\r\n{executable}"
                            ),
                            command: Command::RemoveRule {
                                executable: executable.clone(),
                            },
                        }
                    } else {
                        Effect::None
                    }
                }
                _ => Effect::None,
            }
        }
    }
}

unsafe fn execute_effect(hwnd: HWND, shared: &Shared, effect: Effect) {
    // SAFETY: caller releases UI state before modal calls; HWND remains owned by run's message loop.
    unsafe {
        match effect {
            Effect::None => {}
            Effect::Error(error) | Effect::Popup(error, true) => {
                MessageBoxW(
                    hwnd,
                    wide(&error).as_ptr(),
                    wide("AnVir Next").as_ptr(),
                    MB_OK | MB_ICONERROR,
                );
            }
            Effect::Popup(text, false) => {
                MessageBoxW(
                    hwnd,
                    wide(&text).as_ptr(),
                    wide("AnVir Next").as_ptr(),
                    MB_OK | MB_ICONINFORMATION,
                );
            }
            Effect::Exit => {
                shared.shutdown();
                DestroyWindow(hwnd);
            }
            Effect::Confirm { text, command } => {
                if MessageBoxW(
                    hwnd,
                    wide(&text).as_ptr(),
                    wide("Подтверждение действия").as_ptr(),
                    MB_YESNO | MB_DEFBUTTON2 | MB_ICONWARNING,
                ) == IDYES
                {
                    if let Err(error) = shared.send(command) {
                        execute_effect(hwnd, shared, Effect::Error(error));
                    }
                }
            }
            Effect::Schedule {
                pid,
                created,
                details,
            } => match scheduling_dialog::show(hwnd, &details) {
                Ok(Some(choice)) => {
                    if let Err(error) = shared.send(Command::Scheduling {
                        pid,
                        created,
                        executable: details.path,
                        priority: choice.priority,
                        affinity: choice.affinity,
                        remember: choice.remember,
                    }) {
                        execute_effect(hwnd, shared, Effect::Error(error));
                    }
                }
                Ok(None) => {}
                Err(error) => execute_effect(hwnd, shared, Effect::Error(error)),
            },
        }
    }
}

unsafe fn show(ui: &mut Ui) -> Effect {
    // SAFETY: Ui holds live thread-owned HWNDs; callbacks enforce RefCell reentrancy guards.
    unsafe {
        ShowWindow(
            ui.hwnd,
            if IsIconic(ui.hwnd) != 0 {
                SW_RESTORE
            } else {
                SW_SHOW
            },
        );
        SetForegroundWindow(ui.hwnd);
        ui.refresh(true)
    }
}

unsafe extern "system" fn procedure(
    hwnd: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    // SAFETY: Windows supplies message-specific pointers; userdata is installed by run and outlives HWND.
    unsafe {
        let pointer = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *const WindowState;
        if pointer.is_null() {
            return DefWindowProcW(hwnd, message, wparam, lparam);
        }
        let state = &*pointer;
        if message == WM_SAMPLE_UPDATED {
            state.shared.notifier.acknowledge();
        }
        if matches!(message, WM_SIZE | WM_SHOWWINDOW) {
            // Demand must be reconciled even when a synchronous resize/show
            // notification re-enters while Ui is already mutably borrowed.
            update_visibility(hwnd, &state.shared);
        }
        // Synchronous common-control notifications and modal loops may re-enter us.
        // Never create an aliased &mut Ui; nested layout notifications can be ignored.
        let Ok(mut ui) = state.ui.try_borrow_mut() else {
            return DefWindowProcW(hwnd, message, wparam, lparam);
        };
        let mut effect = Effect::None;
        match message {
            WM_SAMPLE_UPDATED => {
                effect = ui.refresh(false);
            }
            WM_TIMER => {
                effect = ui.refresh(false);
            }
            WM_SHOW_EXISTING => {
                effect = show(&mut ui);
            }
            WM_SIZE => {
                if wparam != SIZE_MINIMIZED as usize {
                    ui.layout();
                }
            }
            WM_GETMINMAXINFO => {
                if lparam != 0 {
                    let info = &mut *(lparam as *mut MINMAXINFO);
                    info.ptMinTrackSize = POINT {
                        x: ui.scale(960),
                        y: ui.scale(590),
                    };
                }
            }
            WM_SHOWWINDOW => {}
            WM_CLOSE => {
                ShowWindow(hwnd, SW_HIDE);
                ui.shared.visible.store(false, Ordering::Release);
            }
            WM_COMMAND => {
                effect = ui.command(wparam & 0xffff, ((wparam >> 16) & 0xffff) as u16);
            }
            WM_NOTIFY if lparam != 0 => {
                let header = &*(lparam as *const NMHDR);
                if header.hwndFrom == ui.table {
                    match header.code {
                        LVN_GETDISPINFOW => {
                            let info = &mut *(lparam as *mut NMLVDISPINFOW);
                            if info.item.mask & LVIF_TEXT != 0
                                && !info.item.pszText.is_null()
                                && info.item.cchTextMax > 0
                                && info.item.iItem >= 0
                                && info.item.iSubItem >= 0
                            {
                                let text = wide(
                                    &ui.cell(info.item.iItem as usize, info.item.iSubItem as usize),
                                );
                                let length =
                                    (text.len() - 1).min(info.item.cchTextMax as usize - 1);
                                ptr::copy_nonoverlapping(text.as_ptr(), info.item.pszText, length);
                                *info.item.pszText.add(length) = 0;
                            }
                        }
                        LVN_ITEMCHANGED | LVN_ODSTATECHANGED => {
                            effect = ui.select();
                        }
                        LVN_COLUMNCLICK => {
                            let item = &*(lparam as *const NMLISTVIEW);
                            if item.iSubItem >= 0 && item.iSubItem < ui.column_count as i32 {
                                let column = item.iSubItem as usize;
                                ui.descending = if ui.sort == column {
                                    !ui.descending
                                } else {
                                    ui.tab == 0 && matches!(column, 2..=4)
                                };
                                ui.sort = column;
                                ui.rebuild(false);
                            }
                        }
                        _ => {}
                    }
                } else if header.hwndFrom == ui.tabs && header.code == TCN_SELCHANGE {
                    effect = ui.change_tab();
                }
            }
            WM_DPICHANGED => {
                ui.dpi = (wparam & 0xffff) as u32;
                ui.set_fonts();
                ui.set_columns();
                if lparam != 0 {
                    let rect = &*(lparam as *const RECT);
                    SetWindowPos(
                        hwnd,
                        ptr::null_mut(),
                        rect.left,
                        rect.top,
                        rect.right - rect.left,
                        rect.bottom - rect.top,
                        SWP_NOZORDER | SWP_NOACTIVATE,
                    );
                }
                ui.layout();
                if let Some(tray) = &mut ui.tray {
                    tray.recreate();
                }
                effect = ui.refresh(true);
            }
            crate::tray::WM_TRAY => match lparam as u32 & 0xffff {
                WM_LBUTTONUP | NIN_SELECT | NIN_KEYSELECT_NOTIFICATION => {
                    effect = show(&mut ui);
                }
                WM_CONTEXTMENU | WM_RBUTTONUP => {
                    let shared = Arc::clone(&ui.shared);
                    let action = ui
                        .tray
                        .as_mut()
                        .and_then(|tray| tray.settings_menu(hwnd, &shared));
                    effect = match action {
                        Some(TrayAction::Show) => show(&mut ui),
                        Some(TrayAction::Exit) => Effect::Exit,
                        _ => Effect::None,
                    };
                }
                _ => {}
            },
            WM_DESTROY => {
                ui.shared.shutdown();
                KillTimer(hwnd, 1);
                PostQuitMessage(0);
            }
            WM_NCDESTROY => {
                SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
                drop(ui);
                return DefWindowProcW(hwnd, message, wparam, lparam);
            }
            _ if message == ui.taskbar_created => {
                if let Some(tray) = &mut ui.tray {
                    tray.recreate();
                }
                effect = ui.refresh(false);
            }
            _ => {
                // Default processing can call accessibility providers and pump
                // nested messages. Let those messages borrow the UI normally.
                drop(ui);
                return DefWindowProcW(hwnd, message, wparam, lparam);
            }
        }
        let shared = Arc::clone(&ui.shared);
        drop(ui); // Modal dialogs and confirmations pump messages: release before entering them.
        execute_effect(hwnd, &shared, effect);
        0
    }
}

pub fn run(shared: Arc<Shared>, start_hidden: bool) -> Result<(), String> {
    // SAFETY: this function owns HWND, userdata, fonts and the message pump until destruction.
    unsafe {
        let controls = INITCOMMONCONTROLSEX {
            dwSize: size_of::<INITCOMMONCONTROLSEX>() as u32,
            dwICC: ICC_LISTVIEW_CLASSES | ICC_TAB_CLASSES | ICC_STANDARD_CLASSES,
        };
        if InitCommonControlsEx(&controls) == 0 {
            return Err("Не удалось инициализировать общие элементы Windows".into());
        }
        let instance = GetModuleHandleW(ptr::null());
        let class = wide(WINDOW_CLASS);
        let mut icon = LoadImageW(
            instance,
            APP_ICON_RESOURCE,
            IMAGE_ICON,
            0,
            0,
            LR_DEFAULTSIZE | LR_SHARED,
        ) as HICON;
        if icon.is_null() {
            // Shared system icon remains valid for the registered window class.
            icon = LoadIconW(ptr::null_mut(), IDI_APPLICATION);
            if icon.is_null() {
                return Err(format!(
                    "Не удалось загрузить значок приложения: {}",
                    std::io::Error::last_os_error()
                ));
            }
        }
        let wc = WNDCLASSEXW {
            cbSize: size_of::<WNDCLASSEXW>() as u32,
            lpfnWndProc: Some(procedure),
            hInstance: instance,
            hIcon: icon,
            hIconSm: icon,
            hCursor: LoadCursorW(ptr::null_mut(), IDC_ARROW),
            hbrBackground: (COLOR_WINDOW + 1) as HBRUSH,
            lpszClassName: class.as_ptr(),
            ..Default::default()
        };
        if RegisterClassExW(&wc) == 0 && GetLastError() != ERROR_CLASS_ALREADY_EXISTS {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let hwnd = CreateWindowExW(
            0,
            class.as_ptr(),
            wide("AnVir Next — процессы и система").as_ptr(),
            WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            1180,
            780,
            ptr::null_mut(),
            ptr::null_mut(),
            instance,
            ptr::null(),
        );
        if hwnd.is_null() {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let ui = match Ui::initialize(hwnd, Arc::clone(&shared)) {
            Ok(ui) => ui,
            Err(error) => {
                DestroyWindow(hwnd);
                shared.shutdown();
                return Err(error);
            }
        };
        SetWindowPos(
            hwnd,
            ptr::null_mut(),
            0,
            0,
            ui.scale(1180),
            ui.scale(780),
            SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE,
        );
        let mut state = Box::new(WindowState {
            shared: Arc::clone(&shared),
            ui: RefCell::new(ui),
        });
        SetWindowLongPtrW(
            hwnd,
            GWLP_USERDATA,
            (&mut *state as *mut WindowState) as isize,
        );
        shared.notifier.bind(hwnd);
        shared.active_tab.store(0, Ordering::Release);
        if !start_hidden {
            ShowWindow(hwnd, SW_SHOW);
        }
        SetTimer(hwnd, 1, 2500, None);
        let effect = state.ui.borrow_mut().refresh(true);
        execute_effect(hwnd, &shared, effect);
        let mut message = MSG::default();
        let mut error = None;
        loop {
            let result = GetMessageW(&mut message, ptr::null_mut(), 0, 0);
            if result <= 0 {
                if result < 0 {
                    error = Some(std::io::Error::last_os_error().to_string());
                }
                break;
            }
            if IsDialogMessageW(hwnd, &message) == 0 {
                TranslateMessage(&message);
                DispatchMessageW(&message);
            }
        }
        shared.shutdown();
        if IsWindow(hwnd) != 0 {
            DestroyWindow(hwnd);
        }
        drop(state);
        error.map_or(Ok(()), Err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn row(pid: u32, created: u64, cpu: Option<f64>) -> ProcessRow {
        ProcessRow {
            pid,
            name: "example.exe".into(),
            times: Some(crate::model::ProcessTimes { created, cpu: 0 }),
            cpu,
            memory: None,
            io_rate: None,
            path: "C:\\Program Files\\Example\\example.exe".into(),
            product: "Example Product".into(),
            company: "Publisher".into(),
            is_64_bit: Some(true),
        }
    }
    #[test]
    fn filter_includes_full_path_product_company_and_pid() {
        let row = row(42, 100, None);
        for filter in ["program files", "example product", "publisher", "42"] {
            assert!(matches_process(&row, filter));
        }
        assert!(!matches_process(&row, "missing"));
    }
    #[test]
    fn process_identity_distinguishes_pid_reuse_and_numeric_sort_is_numeric() {
        let a = row(42, 100, Some(2.0));
        let b = row(42, 200, Some(12.0));
        assert_ne!(identity(&a), identity(&b));
        assert_eq!(compare_process(&a, &b, 2), Compare::Less);
        assert_eq!(process_cell(&row(1, 1, None), 4), "—");
    }
    #[test]
    fn cpu_updates_keep_top_pinned_but_preserve_a_scrolled_process_anchor() {
        // Initial rows have unavailable CPU readings. Their first PID can move
        // far down after the first measured CPU sample; it must not drag row 0.
        assert_eq!(scroll_target(0, Some(180), 800), 0);
        assert_eq!(scroll_target(42, Some(55), 800), 55);
        assert_eq!(scroll_target(42, None, 20), 19);
        assert_eq!(scroll_target(42, Some(55), 0), 0);
    }
    #[test]
    fn detailed_collection_and_rebuild_demand_excludes_minimized_windows() {
        assert!(detail_view_demand(true, false));
        assert!(!detail_view_demand(true, true));
        assert!(!detail_view_demand(false, false));
        assert!(!detail_view_demand(false, true));
    }
}
