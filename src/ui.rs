//! Native, owner-data Win32 process and system viewer.
use crate::{
    icons::{self, ActionImages},
    model::{format_bytes, format_percent, format_rate},
    monitor::{Command, DetailsResult, Shared, StartupAction, UiStatus, ViewSnapshot},
    process_rules::ProcessRule,
    processes::{ProcessDetails, ProcessRow},
    scheduling_dialog,
    sensors::SensorState,
    startup::{StartupEntry, StartupOrigin, StartupSnapshot},
    tray::{Tray, TrayAction},
    win::{WM_SAMPLE_UPDATED, wide},
};
#[path = "startup_view.rs"]
mod startup_view;
use startup_view::Group;
use std::{
    borrow::Cow,
    cell::RefCell,
    cmp::Ordering as Compare,
    collections::{BTreeSet, HashMap},
    mem::size_of,
    ptr,
    sync::{Arc, atomic::Ordering},
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::*,
    Graphics::Gdi::*,
    System::{
        DataExchange::*,
        LibraryLoader::GetModuleHandleW,
        Memory::*,
        SystemServices::{SS_ICON, SS_REALSIZECONTROL},
    },
    UI::{
        Controls::*,
        HiDpi::GetDpiForWindow,
        Input::KeyboardAndMouse::{EnableWindow, GetKeyState, SetFocus, VK_CONTROL, VK_DELETE},
        Shell::*,
        WindowsAndMessaging::*,
    },
};

const FILTER: usize = 102;
pub const WINDOW_CLASS: &str = if cfg!(debug_assertions) {
    "AnVirNext.Debug"
} else {
    "AnVirNext.Main"
};
const WM_SHOW_EXISTING: u32 = WM_APP + 10;
const PRIMARY: usize = 103;
const SECONDARY: usize = 104;
const THIRD: usize = 105;
const SETTINGS: usize = 106;
const TABLE: usize = 107;
const TABS: usize = 108;
const STARTUP_TREE: usize = 109;
const MENU_DETAILS: usize = 200;
const MENU_PROPERTIES: usize = 201;
const MENU_COPY_COMMAND: usize = 202;
const MENU_COPY_PATH: usize = 203;
const MENU_COPY_PID: usize = 204;
const MENU_COPY_LOCATION: usize = 205;
const MENU_COPY_ARGUMENTS: usize = 206;
const MENU_START: usize = 207;
const MENU_STOP: usize = 208;
const MENU_ENABLE: usize = 209;
const MENU_DISABLE: usize = 210;
const STALE_AFTER: Duration = Duration::from_secs(10);
const DETAILS_TIMEOUT: Duration = Duration::from_secs(5);
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
    icon: Option<i32>,
    added_at: Option<u64>,
}

struct Ui {
    hwnd: HWND,
    shared: Arc<Shared>,
    tray: Option<Tray>,
    taskbar_created: u32,
    summary: HWND,
    tabs: HWND,
    filter_label: HWND,
    filter_icon: HWND,
    filter: HWND,
    table: HWND,
    startup_tree: HWND,
    startup_nodes: Vec<startup_view::Node>,
    startup_items: Vec<HTREEITEM>,
    startup_group: Group,
    primary: HWND,
    secondary: HWND,
    third: HWND,
    settings: HWND,
    details_label: HWND,
    details_icon: HWND,
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
    startup_selection: BTreeSet<String>,
    details_text: String,
    notice_id: u64,
    context_menu_open: bool,
    action_images: ActionImages,
    buttons_tab: Option<usize>,
    pending_details: Option<PendingDetails>,
}

enum Effect {
    None,
    Error(String),
    Popup(String, bool),
    Exit,
    Send(Command),
    Confirm {
        text: String,
        command: Command,
    },
    Schedule {
        pid: u32,
        created: u64,
        details: ProcessDetails,
    },
    ContextMenu {
        point: POINT,
        target: MenuTarget,
        details_edit: HWND,
    },
    SettingsMenu,
    OpenFolder(String),
    Properties(String),
    Copy(String),
    FocusDetails(HWND),
    NeedDetails {
        pid: u32,
        created: u64,
        action: DetailAction,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DetailAction {
    Schedule,
    CopyCommand,
}
struct PendingDetails {
    pid: u32,
    created: u64,
    action: DetailAction,
    started: Instant,
}

fn detail_action_effect(
    pid: u32,
    created: u64,
    action: DetailAction,
    details: ProcessDetails,
) -> Effect {
    if created == 0 || details.created != created {
        return Effect::Error("Процесс был перезапущен. Выберите его заново.".into());
    }
    match action {
        DetailAction::Schedule => Effect::Schedule {
            pid,
            created,
            details,
        },
        DetailAction::CopyCommand => Effect::Copy(details.command_line),
    }
}

fn resolved_details(pending: &PendingDetails, result: &DetailsResult) -> Option<Effect> {
    if result.pid != pending.pid || result.created != pending.created {
        return None;
    }
    Some(match &result.result {
        Ok(details) => detail_action_effect(
            pending.pid,
            pending.created,
            pending.action,
            details.clone(),
        ),
        Err(error) => Effect::Error(error.clone()),
    })
}

#[derive(Clone)]
enum MenuTarget {
    Process {
        pid: u32,
        created: u64,
        path: String,
        details: Option<ProcessDetails>,
        arguments: Option<Arc<str>>,
    },
    Startup(Vec<StartupEntry>),
}

fn startup_supports(entry: &StartupEntry, action: StartupAction) -> bool {
    match action {
        StartupAction::Enable => entry.can_toggle && !entry.enabled,
        StartupAction::Disable => entry.can_toggle && entry.enabled,
        StartupAction::Start | StartupAction::Stop => {
            entry.executable.is_some()
                || matches!(
                    entry.origin,
                    StartupOrigin::Task { .. } | StartupOrigin::Service
                )
        }
    }
}

fn startup_batch_effect(entries: &[StartupEntry], action: StartupAction) -> Effect {
    let eligible: Vec<_> = entries
        .iter()
        .filter(|entry| startup_supports(entry, action))
        .cloned()
        .collect();
    if eligible.is_empty() {
        return Effect::None;
    }
    let count = eligible.len();
    let skipped = entries.len() - count;
    let names = eligible
        .iter()
        .take(5)
        .map(|entry| {
            entry
                .name
                .chars()
                .take(160)
                .map(|character| {
                    if character.is_control() {
                        ' '
                    } else {
                        character
                    }
                })
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("\r\n");
    let more = if count > 5 {
        format!("\r\n… и ещё {}", count - 5)
    } else {
        String::new()
    };
    let command = Command::StartupBatch {
        entries: eligible,
        action,
    };
    if action == StartupAction::Start && entries.len() == 1 {
        return Effect::Send(command);
    }
    let verb = match action {
        StartupAction::Enable => "Включить автозагрузку",
        StartupAction::Disable => "Отключить автозагрузку",
        StartupAction::Start => "Запустить",
        StartupAction::Stop => "Остановить",
    };
    let warning = if action == StartupAction::Stop {
        "\r\nНесохранённые данные запущенных программ могут быть потеряны."
    } else {
        ""
    };
    let skipped = if skipped > 0 {
        format!("\r\nПропущено неподдерживаемых записей: {skipped}.")
    } else {
        String::new()
    };
    Effect::Confirm {
        text: format!(
            "{verb} для выбранных записей ({count})?\r\n\r\n{names}{more}{warning}{skipped}"
        ),
        command,
    }
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

fn process_cell(row: &ProcessRow, column: usize) -> Cow<'_, str> {
    match column {
        0 if row.is_64_bit == Some(false) => Cow::Owned(format!("{} (32 бит)", row.name)),
        0 => Cow::Borrowed(&row.name),
        1 => Cow::Borrowed(&row.product),
        2 => Cow::Owned(format_percent(row.cpu)),
        3 => Cow::Owned(format_rate(row.disk_read)),
        4 => Cow::Owned(format_rate(row.disk_write)),
        5 => Cow::Owned(format_rate(row.network_receive)),
        6 => Cow::Owned(format_rate(row.network_send)),
        7 => row
            .memory
            .map(|bytes| Cow::Owned(format_bytes(bytes as f64)))
            .unwrap_or(Cow::Borrowed("—")),
        8 => Cow::Borrowed(row.arguments.as_deref().unwrap_or("—")),
        9 => Cow::Borrowed(&row.company),
        10 => Cow::Borrowed(&row.path),
        11 => Cow::Owned(row.pid.to_string()),
        _ => Cow::Borrowed(""),
    }
}

fn compare_process(a: &ProcessRow, b: &ProcessRow, column: usize) -> Compare {
    match column {
        0 => a.name.cmp(&b.name),
        1 => a.product.cmp(&b.product),
        2 => a.cpu.partial_cmp(&b.cpu).unwrap_or(Compare::Equal),
        3 => a
            .disk_read
            .partial_cmp(&b.disk_read)
            .unwrap_or(Compare::Equal),
        4 => a
            .disk_write
            .partial_cmp(&b.disk_write)
            .unwrap_or(Compare::Equal),
        5 => a
            .network_receive
            .partial_cmp(&b.network_receive)
            .unwrap_or(Compare::Equal),
        6 => a
            .network_send
            .partial_cmp(&b.network_send)
            .unwrap_or(Compare::Equal),
        7 => a.memory.cmp(&b.memory),
        8 => a.arguments.as_deref().cmp(&b.arguments.as_deref()),
        9 => a.company.cmp(&b.company),
        10 => a.path.cmp(&b.path),
        11 => a.pid.cmp(&b.pid),
        _ => Compare::Equal,
    }
    .then_with(|| a.pid.cmp(&b.pid))
}

// Build this small lowercase failure table once per rebuild, then scan even
// 32K command tails without allocating lowercase copies or quadratic matching.
struct SearchPattern {
    characters: Vec<char>,
    fallback: Vec<usize>,
}
impl SearchPattern {
    fn new(filter: &str) -> Self {
        let characters: Vec<_> = filter.chars().flat_map(char::to_lowercase).collect();
        let mut fallback = vec![0; characters.len()];
        for index in 1..characters.len() {
            let mut matched = fallback[index - 1];
            while matched > 0 && characters[index] != characters[matched] {
                matched = fallback[matched - 1];
            }
            if characters[index] == characters[matched] {
                matched += 1;
            }
            fallback[index] = matched;
        }
        Self {
            characters,
            fallback,
        }
    }
    fn contains(&self, text: &str) -> bool {
        if self.characters.is_empty() {
            return true;
        }
        let mut matched = 0;
        for character in text.chars().flat_map(char::to_lowercase) {
            while matched > 0 && character != self.characters[matched] {
                matched = self.fallback[matched - 1];
            }
            if character == self.characters[matched] {
                matched += 1;
            }
            if matched == self.characters.len() {
                return true;
            }
        }
        false
    }
}

fn matches_process(row: &ProcessRow, filter: &SearchPattern) -> bool {
    filter.characters.is_empty()
        || [&row.name, &row.product, &row.company, &row.path]
            .iter()
            .any(|value| filter.contains(value))
        || row
            .arguments
            .as_deref()
            .is_some_and(|arguments| filter.contains(arguments))
        || filter.contains(&row.pid.to_string())
}

fn write_utf16_cell(text: &str, output: &mut [u16]) -> usize {
    let Some(capacity) = output.len().checked_sub(1) else {
        return 0;
    };
    let mut written = 0;
    for character in text.chars() {
        let character = if character == '\0' {
            '\u{fffd}'
        } else {
            character
        };
        let count = character.len_utf16();
        if count > capacity - written {
            break;
        }
        character.encode_utf16(&mut output[written..written + count]);
        written += count;
    }
    output[written] = 0;
    written
}

fn process_order(
    rows: &[ProcessRow],
    filter: &str,
    column: usize,
    descending: bool,
    previous: &[Key],
    frozen: bool,
) -> Vec<usize> {
    let search = SearchPattern::new(filter);
    let mut remaining: Vec<usize> = rows
        .iter()
        .enumerate()
        .filter(|(_, row)| matches_process(row, &search))
        .map(|(index, _)| index)
        .collect();
    let compare = |a: &usize, b: &usize| {
        let order = compare_process(&rows[*a], &rows[*b], column);
        if descending { order.reverse() } else { order }
    };
    if !frozen {
        remaining.sort_unstable_by(compare);
        return remaining;
    }
    let mut identities: HashMap<(u32, u64), usize> = remaining
        .drain(..)
        .map(|index| {
            let row = &rows[index];
            (
                (row.pid, row.times.map(|times| times.created).unwrap_or(0)),
                index,
            )
        })
        .collect();
    let mut order = Vec::with_capacity(identities.len());
    for key in previous {
        if let Key::Process(pid, created) = key {
            if let Some(index) = identities.remove(&(*pid, *created)) {
                order.push(index);
            }
        }
    }
    remaining.extend(identities.into_values());
    remaining.sort_unstable_by(compare);
    order.extend(remaining);
    order
}

fn selection_updates(
    current: Option<usize>,
    target: Option<usize>,
) -> (Option<usize>, Option<usize>) {
    if current == target {
        (None, None)
    } else {
        (current, target)
    }
}

fn selected_startup_indices(rows: &[Row], selected: &BTreeSet<String>) -> BTreeSet<usize> {
    rows.iter()
        .enumerate()
        .filter_map(|(index, row)| {
            matches!(&row.key, Key::Entry(id) if selected.contains(id)).then_some(index)
        })
        .collect()
}

fn startup_targets(entries: &[StartupEntry], selected: &BTreeSet<String>) -> Vec<StartupEntry> {
    entries
        .iter()
        .filter(|entry| selected.contains(&entry.id))
        .cloned()
        .collect()
}

fn compare_startup_rows(a: &Row, b: &Row, column: usize) -> Compare {
    if column == 5 {
        a.added_at.cmp(&b.added_at)
    } else {
        a.cells.get(column).cmp(&b.cells.get(column))
    }
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

fn context_index(
    hit: Option<usize>,
    keyboard: bool,
    selected: Option<usize>,
    count: usize,
) -> Option<usize> {
    (if keyboard { selected } else { hit }).filter(|index| *index < count)
}

fn target_effect(target: &MenuTarget, action: usize, details_edit: HWND) -> Effect {
    match target {
        MenuTarget::Process {
            pid,
            created,
            path,
            details,
            arguments,
        } => match action {
            MENU_DETAILS => Effect::FocusDetails(details_edit),
            PRIMARY if *created != 0 => Effect::Confirm {
                text: format!(
                    "Завершить процесс PID {pid}? Несохранённые данные могут быть потеряны.\r\n\r\n{path}"
                ),
                command: Command::Terminate {
                    pid: *pid,
                    created: *created,
                },
            },
            SECONDARY if *created != 0 => details
                .as_ref()
                .map(|details| {
                    detail_action_effect(*pid, *created, DetailAction::Schedule, details.clone())
                })
                .unwrap_or(Effect::NeedDetails {
                    pid: *pid,
                    created: *created,
                    action: DetailAction::Schedule,
                }),
            THIRD if !path.is_empty() => Effect::OpenFolder(path.clone()),
            MENU_PROPERTIES if !path.is_empty() => Effect::Properties(path.clone()),
            MENU_COPY_COMMAND if *created != 0 => details
                .as_ref()
                .map(|details| {
                    detail_action_effect(*pid, *created, DetailAction::CopyCommand, details.clone())
                })
                .unwrap_or(Effect::NeedDetails {
                    pid: *pid,
                    created: *created,
                    action: DetailAction::CopyCommand,
                }),
            MENU_COPY_PATH if !path.is_empty() => Effect::Copy(path.clone()),
            MENU_COPY_PID => Effect::Copy(pid.to_string()),
            MENU_COPY_ARGUMENTS => arguments
                .as_ref()
                .map(|arguments| Effect::Copy(arguments.to_string()))
                .unwrap_or(Effect::None),
            _ => Effect::None,
        },
        MenuTarget::Startup(entries) => {
            let batch_action = match action {
                MENU_ENABLE => Some(StartupAction::Enable),
                MENU_DISABLE => Some(StartupAction::Disable),
                MENU_START => Some(StartupAction::Start),
                MENU_STOP => Some(StartupAction::Stop),
                SECONDARY => Some(StartupAction::Disable),
                _ => None,
            };
            if let Some(action) = batch_action {
                return startup_batch_effect(entries, action);
            }
            let [entry] = entries.as_slice() else {
                return Effect::None;
            };
            match action {
                THIRD => entry
                    .executable
                    .as_ref()
                    .map(|path| Effect::OpenFolder(path.clone()))
                    .unwrap_or(Effect::None),
                MENU_PROPERTIES => entry
                    .executable
                    .as_ref()
                    .map(|path| Effect::Properties(path.clone()))
                    .unwrap_or(Effect::None),
                MENU_COPY_COMMAND => Effect::Copy(entry.command.clone()),
                MENU_COPY_LOCATION => {
                    Effect::Copy(format!("{}\r\n{}", entry.source, entry.location))
                }
                _ => Effect::None,
            }
        }
    }
}

fn delete_effect(target: &MenuTarget, details_edit: HWND) -> Effect {
    match target {
        MenuTarget::Process { .. } => target_effect(target, PRIMARY, details_edit),
        MenuTarget::Startup(entries) => startup_batch_effect(entries, StartupAction::Disable),
    }
}

unsafe fn track_context_menu(hwnd: HWND, point: POINT, target: &MenuTarget) -> Option<usize> {
    // SAFETY: popup is privately owned for this call; labels are copied synchronously by Win32.
    unsafe {
        let menu = CreatePopupMenu();
        if menu.is_null() {
            return None;
        }
        let append = |id, title: &str, enabled| {
            AppendMenuW(
                menu,
                MF_STRING | if enabled { 0 } else { MF_GRAYED },
                id,
                wide(title).as_ptr(),
            );
        };
        match target {
            MenuTarget::Process {
                created,
                path,
                arguments,
                ..
            } => {
                append(MENU_DETAILS, "Командная строка и подробности", true);
                append(SECONDARY, "Приоритет и процессоры…", *created != 0);
                append(THIRD, "Открыть папку файла", !path.is_empty());
                append(MENU_PROPERTIES, "Свойства файла…", !path.is_empty());
                AppendMenuW(menu, MF_SEPARATOR, 0, ptr::null());
                append(
                    MENU_COPY_COMMAND,
                    "Копировать командную строку",
                    *created != 0,
                );
                append(
                    MENU_COPY_ARGUMENTS,
                    "Копировать аргументы",
                    arguments.is_some(),
                );
                append(MENU_COPY_PATH, "Копировать путь", !path.is_empty());
                append(MENU_COPY_PID, "Копировать PID", true);
                AppendMenuW(menu, MF_SEPARATOR, 0, ptr::null());
                append(PRIMARY, "Завершить процесс…", *created != 0);
            }
            MenuTarget::Startup(entries) => {
                let supports = |action| entries.iter().any(|entry| startup_supports(entry, action));
                append(MENU_START, "Запустить", supports(StartupAction::Start));
                append(MENU_STOP, "Остановить…", supports(StartupAction::Stop));
                AppendMenuW(menu, MF_SEPARATOR, 0, ptr::null());
                append(
                    MENU_ENABLE,
                    "Включить автозагрузку…",
                    supports(StartupAction::Enable),
                );
                append(
                    MENU_DISABLE,
                    "Отключить автозагрузку…",
                    supports(StartupAction::Disable),
                );
                let entry = if entries.len() == 1 {
                    entries.first()
                } else {
                    None
                };
                append(
                    THIRD,
                    "Открыть папку файла",
                    entry.is_some_and(|entry| entry.executable.is_some()),
                );
                append(
                    MENU_PROPERTIES,
                    "Свойства файла…",
                    entry.is_some_and(|entry| entry.executable.is_some()),
                );
                AppendMenuW(menu, MF_SEPARATOR, 0, ptr::null());
                append(MENU_COPY_COMMAND, "Копировать команду", entry.is_some());
                append(
                    MENU_COPY_LOCATION,
                    "Копировать источник и расположение",
                    entry.is_some(),
                );
                AppendMenuW(menu, MF_SEPARATOR, 0, ptr::null());
                append(PRIMARY, "Обновить автозагрузку", true);
            }
        }
        SetForegroundWindow(hwnd);
        let chosen = TrackPopupMenuEx(
            menu,
            TPM_RETURNCMD | TPM_RIGHTBUTTON,
            point.x,
            point.y,
            hwnd,
            ptr::null(),
        );
        DestroyMenu(menu);
        PostMessageW(hwnd, WM_NULL, 0, 0);
        (chosen != 0).then_some(chosen as usize)
    }
}

unsafe fn copy_text(hwnd: HWND, text: &str) -> Result<(), String> {
    // SAFETY: the bounded movable allocation is copied before clipboard ownership transfer;
    // every failure frees it and closes an opened clipboard on this UI thread.
    unsafe {
        if text.encode_utf16().take(262145).count() > 262144 {
            return Err("Текст слишком длинный для копирования".into());
        }
        let text = wide(text);
        let allocation = GlobalAlloc(GMEM_MOVEABLE, text.len() * size_of::<u16>());
        if allocation.is_null() {
            return Err("Не удалось выделить память буфера обмена".into());
        }
        let destination = GlobalLock(allocation);
        if destination.is_null() {
            GlobalFree(allocation);
            return Err("Не удалось подготовить буфер обмена".into());
        }
        ptr::copy_nonoverlapping(text.as_ptr(), destination.cast::<u16>(), text.len());
        GlobalUnlock(allocation);
        if OpenClipboard(hwnd) == 0 {
            GlobalFree(allocation);
            return Err("Буфер обмена занят другим приложением".into());
        }
        let result = if EmptyClipboard() == 0
            || SetClipboardData(13 /* CF_UNICODETEXT */, allocation).is_null()
        {
            GlobalFree(allocation);
            Err("Не удалось скопировать текст".into())
        } else {
            Ok(())
        };
        CloseClipboard();
        result
    }
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
            let dpi = GetDpiForWindow(hwnd).max(96);
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
                filter_icon: ptr::null_mut(),
                filter: ptr::null_mut(),
                table: ptr::null_mut(),
                startup_tree: ptr::null_mut(),
                startup_nodes: Vec::new(),
                startup_items: Vec::new(),
                startup_group: Group::Regular,
                primary: ptr::null_mut(),
                secondary: ptr::null_mut(),
                third: ptr::null_mut(),
                settings: ptr::null_mut(),
                details_label: ptr::null_mut(),
                details_icon: ptr::null_mut(),
                details_edit: ptr::null_mut(),
                status_line: ptr::null_mut(),
                font: ptr::null_mut(),
                summary_font: ptr::null_mut(),
                dpi,
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
                startup_selection: BTreeSet::new(),
                details_text: String::new(),
                notice_id: 0,
                context_menu_open: false,
                pending_details: None,
                action_images: ActionImages::new(dpi),
                buttons_tab: None,
            };
            ui.summary = ui.child("STATIC", "AnVir Next · Получение данных…", 0, 0, 0);
            ui.tabs = ui.child("SysTabControl32", "", WS_TABSTOP, TABS, 0);
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
            ui.filter_icon = ui.child("STATIC", "", SS_ICON | SS_REALSIZECONTROL, 0, 0);
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
                "Настройки",
                WS_TABSTOP | BS_PUSHBUTTON as u32,
                SETTINGS,
                0,
            );
            ui.table = ui.child(
                "SysListView32",
                "",
                WS_TABSTOP
                    | LVS_REPORT
                    | LVS_OWNERDATA
                    | LVS_SINGLESEL
                    | LVS_SHOWSELALWAYS
                    | LVS_SHAREIMAGELISTS,
                TABLE,
                WS_EX_CLIENTEDGE,
            );
            SendMessageW(
                ui.table,
                LVM_SETEXTENDEDLISTVIEWSTYLE,
                0,
                (LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP) as isize,
            );
            ui.startup_tree = ui.child(
                "SysTreeView32",
                "",
                WS_TABSTOP | TVS_HASBUTTONS | TVS_HASLINES | TVS_LINESATROOT | TVS_SHOWSELALWAYS,
                STARTUP_TREE,
                WS_EX_CLIENTEDGE,
            );
            ShowWindow(ui.startup_tree, SW_HIDE);
            if let Some(images) = icons::small_image_list() {
                // Warm stock indices here so owner-data painting only reads cached metadata.
                let _ = (icons::application_index(), icons::folder_index());
                SendMessageW(ui.table, LVM_SETIMAGELIST, LVSIL_SMALL as usize, images);
                SendMessageW(
                    ui.startup_tree,
                    TVM_SETIMAGELIST,
                    TVSIL_NORMAL as usize,
                    images,
                );
            }
            ui.details_label = ui.child(
                "STATIC",
                "Командная строка и параметры выбранного процесса (можно копировать)",
                0,
                0,
                0,
            );
            ui.details_icon = ui.child("STATIC", "", SS_ICON | SS_REALSIZECONTROL, 0, 0);
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
                ui.filter_icon,
                ui.filter,
                ui.primary,
                ui.secondary,
                ui.third,
                ui.settings,
                ui.table,
                ui.startup_tree,
                ui.details_label,
                ui.details_icon,
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
            ui.apply_action_images();
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
                    self.startup_tree,
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

    unsafe fn apply_action_images(&mut self) {
        // SAFETY: controls are live and ActionImages is retained until their destruction.
        unsafe {
            self.action_images.apply_label(self.filter_icon, SIID_FIND);
            self.action_images.apply_label(self.details_icon, SIID_INFO);
            self.action_images
                .apply_button(self.settings, SIID_SETTINGS);
            self.buttons_tab = None;
            self.buttons();
            if let Some(images) = icons::small_image_list() {
                SendMessageW(self.tabs, TCM_SETIMAGELIST, 0, images);
                for (index, stock) in [
                    SIID_APPLICATION,
                    SIID_SOFTWARE,
                    SIID_DESKTOPPC,
                    SIID_SETTINGS,
                ]
                .into_iter()
                .enumerate()
                {
                    let item = TCITEMW {
                        mask: TCIF_IMAGE,
                        iImage: icons::stock_index(stock).unwrap_or_else(icons::application_index),
                        ..Default::default()
                    };
                    SendMessageW(
                        self.tabs,
                        TCM_SETITEMW,
                        index,
                        (&item as *const TCITEMW) as isize,
                    );
                }
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
            move_control(self.filter_icon, s(12), s(93), s(16), s(16));
            move_control(self.filter_label, s(36), s(92), s(48), s(24));
            move_control(self.filter, s(86), s(86), s(186), s(28));
            move_control(
                self.primary,
                s(284),
                s(85),
                s(if self.tab == 3 { 153 } else { 128 }),
                s(30),
            );
            move_control(self.secondary, s(418), s(85), s(176), s(30));
            move_control(self.third, s(600), s(85), s(145), s(30));
            move_control(self.settings, width - s(145), s(85), s(133), s(30));
            let detail_height = s(142).min((height / 3).max(s(85)));
            let table_bottom = height - detail_height - s(74);
            let tree_width = if self.tab == 1 { s(260) } else { 0 };
            move_control(
                self.startup_tree,
                s(10),
                s(124),
                tree_width - s(8),
                table_bottom - s(124),
            );
            move_control(
                self.table,
                s(10) + tree_width,
                s(124),
                width - s(20) - tree_width,
                table_bottom - s(124),
            );
            move_control(
                self.details_label,
                s(38),
                table_bottom + s(10),
                width - s(50),
                s(23),
            );
            move_control(self.details_icon, s(12), table_bottom + s(12), s(16), s(16));
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
                    ("Продукт", 140, false),
                    ("CPU %", 70, true),
                    ("Диск: чтение", 100, true),
                    ("Диск: запись", 100, true),
                    ("Сеть: приём", 100, true),
                    ("Сеть: отдача", 100, true),
                    ("Память (раб. набор)", 135, true),
                    ("Аргументы командной строки", 500, false),
                    ("Компания", 150, false),
                    ("Исполняемый файл", 330, false),
                    ("PID", 75, true),
                ],
                1 => &[
                    ("Имя", 220, false),
                    ("Состояние", 155, false),
                    ("Источник", 240, false),
                    ("Команда", 450, false),
                    ("Расположение", 400, false),
                    ("Когда добавлено", 150, false),
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
    fn cell(&self, index: usize, column: usize) -> Cow<'_, str> {
        if self.tab == 0 {
            self.order
                .get(index)
                .and_then(|index| self.snapshot.processes.get(*index))
                .map(|row| {
                    if self.snapshot.updated.elapsed() > STALE_AFTER && matches!(column, 2..=7) {
                        Cow::Borrowed("—")
                    } else {
                        process_cell(row, column)
                    }
                })
                .unwrap_or(Cow::Borrowed(""))
        } else {
            self.other
                .get(index)
                .and_then(|row| row.cells.get(column))
                .map(|cell| Cow::Borrowed(cell.as_str()))
                .unwrap_or(Cow::Borrowed(""))
        }
    }

    fn image(&self, index: usize) -> i32 {
        let image = if self.tab == 0 {
            self.order
                .get(index)
                .and_then(|index| self.snapshot.processes.get(*index))
                .and_then(|row| row.icon_index)
        } else {
            self.other.get(index).and_then(|row| row.icon)
        };
        if matches!(self.tab, 0 | 1) {
            image.unwrap_or_else(icons::application_index)
        } else {
            I_IMAGENONE
        }
    }

    unsafe fn rebuild_startup_tree(&mut self) {
        // SAFETY: tree handles are thread-owned; item strings/structs survive synchronous sends.
        unsafe {
            let first = self.startup_items.is_empty();
            let expanded: BTreeSet<_> = self
                .startup_nodes
                .iter()
                .zip(&self.startup_items)
                .filter(|(_, item)| {
                    SendMessageW(
                        self.startup_tree,
                        TVM_GETITEMSTATE,
                        **item as usize,
                        TVIS_EXPANDED as isize,
                    ) & TVIS_EXPANDED as isize
                        != 0
                })
                .map(|(node, _)| node.group.clone())
                .collect();
            SendMessageW(self.startup_tree, WM_SETREDRAW, 0, 0);
            SendMessageW(self.startup_tree, TVM_DELETEITEM, 0, TVI_ROOT);
            self.startup_nodes = startup_view::nodes(&self.startup.entries, &self.filter_text);
            self.startup_items.clear();
            if !self
                .startup_nodes
                .iter()
                .any(|node| node.group == self.startup_group)
            {
                self.startup_group = Group::Regular;
            }
            for (index, node) in self.startup_nodes.iter().enumerate() {
                let mut text = wide(&format!("{} ({})", node.title, node.count));
                let image = icons::folder_index();
                let item = TVITEMW {
                    mask: TVIF_TEXT | TVIF_PARAM | TVIF_IMAGE | TVIF_SELECTEDIMAGE,
                    pszText: text.as_mut_ptr(),
                    iImage: image,
                    iSelectedImage: image,
                    lParam: index as isize,
                    ..Default::default()
                };
                let insertion = TVINSERTSTRUCTW {
                    hParent: node
                        .parent
                        .and_then(|index| self.startup_items.get(index))
                        .copied()
                        .unwrap_or(TVI_ROOT),
                    hInsertAfter: TVI_LAST,
                    Anonymous: TVINSERTSTRUCTW_0 { item },
                };
                let handle = SendMessageW(
                    self.startup_tree,
                    TVM_INSERTITEMW,
                    0,
                    (&insertion as *const TVINSERTSTRUCTW) as isize,
                ) as HTREEITEM;
                self.startup_items.push(handle);
                let default_open = matches!(
                    node.group,
                    Group::All
                        | Group::Regular
                        | Group::Registry
                        | Group::Folders
                        | Group::RegistryScope(false)
                );
                if expanded.contains(&node.group) || first && default_open {
                    SendMessageW(
                        self.startup_tree,
                        TVM_EXPAND,
                        TVE_EXPAND as usize,
                        handle as isize,
                    );
                }
                if node.group == self.startup_group {
                    SendMessageW(
                        self.startup_tree,
                        TVM_SELECTITEM,
                        TVGN_CARET as usize,
                        handle as isize,
                    );
                }
            }
            SendMessageW(self.startup_tree, WM_SETREDRAW, 1, 0);
            InvalidateRect(self.startup_tree, ptr::null(), 0);
        }
    }

    fn menu_target(&self) -> Option<MenuTarget> {
        match &self.selected {
            Some(Key::Process(pid, created)) if self.tab == 0 => {
                let row = self
                    .snapshot
                    .processes
                    .iter()
                    .find(|row| identity(row) == Key::Process(*pid, *created))?;
                Some(MenuTarget::Process {
                    pid: *pid,
                    created: *created,
                    path: row.path.clone(),
                    details: self.selected_details().map(|(_, _, details)| details),
                    arguments: row.arguments.clone(),
                })
            }
            _ if self.tab == 1 => {
                let entries = startup_targets(&self.startup.entries, &self.startup_selection);
                (!entries.is_empty()).then_some(MenuTarget::Startup(entries))
            }
            _ => None,
        }
    }

    unsafe fn context_menu(&mut self, lparam: LPARAM) -> Effect {
        // SAFETY: all rectangle/hit-test buffers are initialized, and selected indices are bounds checked.
        unsafe {
            if !matches!(self.tab, 0 | 1) {
                return Effect::None;
            }
            let keyboard = lparam == -1;
            let selected = SendMessageW(
                self.table,
                LVM_GETNEXTITEM,
                usize::MAX,
                LVNI_SELECTED as isize,
            );
            let mut point = POINT {
                x: (lparam as u16 as i16) as i32,
                y: ((lparam as u32 >> 16) as u16 as i16) as i32,
            };
            let hit = if keyboard {
                None
            } else {
                let mut client_point = point;
                ScreenToClient(self.table, &mut client_point);
                let mut bounds = RECT::default();
                GetClientRect(self.table, &mut bounds);
                if PtInRect(&bounds, client_point) == 0 {
                    return Effect::None;
                }
                let mut hit = LVHITTESTINFO {
                    pt: client_point,
                    ..Default::default()
                };
                let index = SendMessageW(
                    self.table,
                    LVM_SUBITEMHITTEST,
                    0,
                    (&mut hit as *mut LVHITTESTINFO) as isize,
                );
                (index >= 0 && hit.flags & LVHT_NOWHERE == 0).then_some(index as usize)
            };
            let Some(index) = context_index(
                hit,
                keyboard,
                (selected >= 0).then_some(selected as usize),
                self.len(),
            ) else {
                return Effect::None;
            };
            let item = LVITEMW {
                state: LVIS_SELECTED | LVIS_FOCUSED,
                stateMask: LVIS_SELECTED | LVIS_FOCUSED,
                ..Default::default()
            };
            let clear = LVITEMW {
                stateMask: LVIS_SELECTED | LVIS_FOCUSED,
                ..Default::default()
            };
            let keep_batch = self.tab == 1
                && self.key(index).is_some_and(
                    |key| matches!(key, Key::Entry(id) if self.startup_selection.contains(&id)),
                );
            if !keep_batch {
                SendMessageW(
                    self.table,
                    LVM_SETITEMSTATE,
                    usize::MAX,
                    (&clear as *const LVITEMW) as isize,
                );
            }
            SendMessageW(
                self.table,
                LVM_SETITEMSTATE,
                index,
                (&item as *const LVITEMW) as isize,
            );
            let selection_effect = self.select();
            if let Effect::Error(_) = selection_effect {
                return selection_effect;
            }
            if keyboard {
                let mut rect = RECT {
                    left: LVIR_BOUNDS as i32,
                    ..Default::default()
                };
                SendMessageW(
                    self.table,
                    LVM_GETITEMRECT,
                    index,
                    (&mut rect as *mut RECT) as isize,
                );
                point = POINT {
                    x: rect.left + self.scale(24),
                    y: rect.bottom,
                };
                ClientToScreen(self.table, &mut point);
            }
            if let Some(target) = self.menu_target() {
                self.context_menu_open = true;
                Effect::ContextMenu {
                    point,
                    target,
                    details_edit: self.details_edit,
                }
            } else {
                Effect::None
            }
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
                let rows = &self.snapshot.processes;
                let mut cursor = POINT::default();
                let hovered = GetCursorPos(&mut cursor) != 0 && {
                    let pointed = WindowFromPoint(cursor);
                    pointed == self.table || IsChild(self.table, pointed) != 0
                };
                let frozen = preserve_scroll && (self.context_menu_open || hovered);
                self.order = process_order(
                    rows,
                    &self.filter_text,
                    self.sort,
                    self.descending,
                    &self.order_keys,
                    frozen,
                );
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
                        .filter(|entry| {
                            startup_view::matches_group(entry, &self.startup_group)
                                && startup_view::matches_search(entry, &self.filter_text)
                        })
                        .map(|entry| Row {
                            key: Key::Entry(entry.id.clone()),
                            icon: entry.icon_index,
                            added_at: entry.added_at,
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
                                startup_view::format_added_at(entry.added_at),
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
                                    icon: None,
                                    added_at: None,
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
                            icon: None,
                            added_at: None,
                            cells: vec![
                                rule.executable.clone(),
                                scheduling_dialog::priority_name(rule.priority).into(),
                                format!("0x{:016X}", rule.affinity),
                            ],
                        })
                        .collect(),
                };
                if self.tab != 1 && !self.filter_text.is_empty() {
                    self.other.retain(|row| {
                        row.cells
                            .iter()
                            .any(|cell| cell.to_lowercase().contains(&self.filter_text))
                    });
                }
                let column = self.sort;
                let descending = self.descending;
                self.other.sort_by(|a, b| {
                    let order = if self.tab == 1 {
                        compare_startup_rows(a, b, column)
                    } else {
                        a.cells.get(column).cmp(&b.cells.get(column))
                    };
                    if descending { order.reverse() } else { order }
                });
            }
            if SendMessageW(self.table, LVM_GETITEMCOUNT, 0, 0) as usize != self.len() {
                SendMessageW(
                    self.table,
                    LVM_SETITEMCOUNT,
                    self.len(),
                    (LVSICF_NOINVALIDATEALL | LVSICF_NOSCROLL) as isize,
                );
            }
            if self.tab == 1 {
                self.restore_startup_selection();
            } else {
                let mut item = LVITEMW {
                    stateMask: LVIS_SELECTED | LVIS_FOCUSED,
                    ..Default::default()
                };
                let selected_index = self.selected.as_ref().and_then(|key| {
                    (0..self.len()).find(|index| self.key(*index).as_ref() == Some(key))
                });
                let current_selection = SendMessageW(
                    self.table,
                    LVM_GETNEXTITEM,
                    usize::MAX,
                    LVNI_SELECTED as isize,
                );
                let (clear, select) = selection_updates(
                    (current_selection >= 0).then_some(current_selection as usize),
                    selected_index,
                );
                if let Some(index) = clear {
                    SendMessageW(
                        self.table,
                        LVM_SETITEMSTATE,
                        index,
                        (&item as *const LVITEMW) as isize,
                    );
                }
                if let Some(index) = select {
                    item.state = LVIS_SELECTED | LVIS_FOCUSED;
                    SendMessageW(
                        self.table,
                        LVM_SETITEMSTATE,
                        index,
                        (&item as *const LVITEMW) as isize,
                    );
                }
                if selected_index.is_none() {
                    self.selected = None;
                    self.pending_details = None;
                }
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
                && top as i32 != current_top
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

    fn request_detail_action(&mut self, pid: u32, created: u64, action: DetailAction) -> Effect {
        if self.tab != 0 || created == 0 || self.selected != Some(Key::Process(pid, created)) {
            return Effect::None;
        }
        self.pending_details = None;
        let pending = PendingDetails {
            pid,
            created,
            action,
            started: Instant::now(),
        };
        if let Some(effect) = self
            .status
            .details
            .as_ref()
            .and_then(|result| resolved_details(&pending, result))
        {
            return effect;
        }
        if let Err(error) = self.shared.send(Command::SelectProcess { pid, created }) {
            return Effect::Error(error);
        }
        self.pending_details = Some(pending);
        Effect::None
    }

    fn poll_detail_action(&mut self, visible: bool) -> Effect {
        let Some(pending) = &self.pending_details else {
            return Effect::None;
        };
        if !visible || self.selected != Some(Key::Process(pending.pid, pending.created)) {
            self.pending_details = None;
            return Effect::None;
        }
        if self.context_menu_open {
            return Effect::None;
        }
        let effect = if pending.started.elapsed() >= DETAILS_TIMEOUT {
            Some(Effect::Error(
                "Не удалось вовремя получить свойства процесса. Повторите действие.".into(),
            ))
        } else {
            self.status
                .details
                .as_ref()
                .and_then(|result| resolved_details(pending, result))
        };
        match effect {
            Some(effect) => {
                self.pending_details = None;
                effect
            }
            None => Effect::None,
        }
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

    unsafe fn native_selected_indices(&self) -> BTreeSet<usize> {
        // SAFETY: list queries return integer indices; no pointers escape synchronous messages.
        unsafe {
            let mut selected = BTreeSet::new();
            let mut previous = -1isize;
            loop {
                let index = SendMessageW(
                    self.table,
                    LVM_GETNEXTITEM,
                    previous as usize,
                    LVNI_SELECTED as isize,
                );
                if index < 0 || index <= previous || index as usize >= self.len() {
                    break;
                }
                selected.insert(index as usize);
                previous = index;
            }
            selected
        }
    }

    unsafe fn update_startup_focus(&mut self) {
        // SAFETY: focused index is bounds checked against current virtual rows.
        unsafe {
            let focused = SendMessageW(
                self.table,
                LVM_GETNEXTITEM,
                usize::MAX,
                LVNI_FOCUSED as isize,
            );
            let key = (focused >= 0)
                .then(|| self.key(focused as usize))
                .flatten()
                .filter(|key| matches!(key, Key::Entry(id) if self.startup_selection.contains(id)));
            self.selected = key.or_else(|| self.selected.take().filter(|key| matches!(key, Key::Entry(id) if self.startup_selection.contains(id))))
                .or_else(|| self.other.iter().find(|row| matches!(&row.key, Key::Entry(id) if self.startup_selection.contains(id))).map(|row| row.key.clone()));
        }
    }

    unsafe fn sync_startup_selection(&mut self) {
        // SAFETY: all selected indices originate from the live list and key() bounds checks them.
        unsafe {
            self.startup_selection = self
                .native_selected_indices()
                .into_iter()
                .filter_map(|index| match self.key(index) {
                    Some(Key::Entry(id)) => Some(id),
                    _ => None,
                })
                .collect();
            self.update_startup_focus();
            self.show_details();
            self.buttons();
        }
    }

    unsafe fn startup_state_changed(&mut self, code: u32, lparam: LPARAM) {
        // SAFETY: caller dispatches the list's matching native notification structure.
        unsafe {
            let (from, to, old, new) = if code == LVN_ODSTATECHANGED {
                let change = &*(lparam as *const NMLVODSTATECHANGE);
                (change.iFrom, change.iTo, change.uOldState, change.uNewState)
            } else {
                let change = &*(lparam as *const NMLISTVIEW);
                if change.uChanged & LVIF_STATE == 0 {
                    return;
                }
                (
                    change.iItem,
                    change.iItem,
                    change.uOldState,
                    change.uNewState,
                )
            };
            if (old ^ new) & LVIS_SELECTED != 0 && from >= 0 && to >= from {
                for index in from as usize..=(to as usize).min(self.len().saturating_sub(1)) {
                    if let Some(Key::Entry(id)) = self.key(index) {
                        if new & LVIS_SELECTED != 0 {
                            self.startup_selection.insert(id);
                        } else {
                            self.startup_selection.remove(&id);
                        }
                    }
                }
            }
            self.update_startup_focus();
            self.show_details();
            self.buttons();
        }
    }

    unsafe fn restore_startup_selection(&mut self) {
        // SAFETY: state writes affect only changed native indices; all identity mapping is in-memory.
        unsafe {
            let visible: BTreeSet<_> = self
                .other
                .iter()
                .filter_map(|row| {
                    if let Key::Entry(id) = &row.key {
                        Some(id.clone())
                    } else {
                        None
                    }
                })
                .collect();
            self.startup_selection.retain(|id| visible.contains(id));
            let desired = selected_startup_indices(&self.other, &self.startup_selection);
            let current = self.native_selected_indices();
            for index in current.symmetric_difference(&desired) {
                let item = LVITEMW {
                    stateMask: LVIS_SELECTED,
                    state: if desired.contains(index) {
                        LVIS_SELECTED
                    } else {
                        0
                    },
                    ..Default::default()
                };
                SendMessageW(
                    self.table,
                    LVM_SETITEMSTATE,
                    *index,
                    (&item as *const LVITEMW) as isize,
                );
            }
            let focused = self
                .selected
                .as_ref()
                .and_then(|key| self.other.iter().position(|row| &row.key == key))
                .filter(|index| desired.contains(index))
                .or_else(|| desired.first().copied());
            let old_focus = SendMessageW(
                self.table,
                LVM_GETNEXTITEM,
                usize::MAX,
                LVNI_FOCUSED as isize,
            );
            if (old_focus >= 0).then_some(old_focus as usize) != focused {
                for (index, focus) in [
                    (old_focus, false),
                    (focused.map(|index| index as isize).unwrap_or(-1), true),
                ] {
                    if index >= 0 {
                        let item = LVITEMW {
                            stateMask: LVIS_FOCUSED,
                            state: if focus { LVIS_FOCUSED } else { 0 },
                            ..Default::default()
                        };
                        SendMessageW(
                            self.table,
                            LVM_SETITEMSTATE,
                            index as usize,
                            (&item as *const LVITEMW) as isize,
                        );
                    }
                }
            }
            self.selected = focused.and_then(|index| self.key(index));
        }
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
                let details = if self.startup_selection.len() > 1 {
                    format!("Выбрано записей: {}. Действия «Запустить», «Остановить», «Включить» и «Отключить» доступны в контекстном меню. Delete отключает только включённые записи, допускающие изменение.", self.startup_selection.len())
                } else {
                self.selected_startup().map(|entry| format!("Команда:\r\n{}\r\n\r\nИсточник: {}\r\nРасположение: {}\r\nКогда добавлено: {}{}", entry.command, entry.source, entry.location, startup_view::format_added_at(entry.added_at),
                    if entry.can_toggle { "" } else { "\r\nИзменение настройки автозагрузки недоступно. Запуск и остановка зависят от разрешений." })).unwrap_or_else(|| if self.len() == 0 && !self.status.startup_loading { "В выбранной группе нет записей, соответствующих фильтру. Автозагрузка RunOnce и служб доступна только для чтения.".into() } else { "Выберите запись автозагрузки. Настройки RunOnce и служб доступны только для чтения.".into() })
                };
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

    unsafe fn buttons(&mut self) {
        // SAFETY: controls are owned on this thread and text buffers survive each call.
        unsafe {
            let (primary, secondary, third) = match self.tab {
                0 => ("Завершить…", "Приоритет / CPU…", "Открыть папку"),
                1 => ("Обновить", "Отключить…", ""),
                2 => ("", "", ""),
                _ => ("Удалить правило…", "", ""),
            };
            if self.buttons_tab != Some(self.tab) {
                for (control, text) in [
                    (self.primary, primary),
                    (self.secondary, secondary),
                    (self.third, third),
                ] {
                    SetWindowTextW(control, wide(text).as_ptr());
                    ShowWindow(control, if text.is_empty() { SW_HIDE } else { SW_SHOW });
                }
                self.action_images.apply_button(
                    self.primary,
                    if self.tab == 1 {
                        SIID_AUTOLIST
                    } else {
                        SIID_DELETE
                    },
                );
                self.action_images
                    .apply_button(self.secondary, SIID_SETTINGS);
                self.action_images.apply_button(self.third, SIID_FOLDEROPEN);
                self.buttons_tab = Some(self.tab);
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
                    self.startup.entries.iter().any(|entry| {
                        self.startup_selection.contains(&entry.id)
                            && startup_supports(entry, StartupAction::Disable)
                    })
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
                self.shared
                    .disk_hovered
                    .store(tray.disk_tooltip_open(), Ordering::Release);
            }
            let visible = update_visibility(self.hwnd, &self.shared);
            if visible {
                if self.tab == 1 && (force || startup_changed || self.startup_items.is_empty()) {
                    self.rebuild_startup_tree();
                }
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
                    if let Some(error) = &self.snapshot.process_error {
                        error.clone()
                    } else if let Some(error) = &self.snapshot.activity_error {
                        format!("Счётчики диска и сети: {error}")
                    } else {
                        format!(
                            "{} процессов · Диск и сеть: байт/с · — данные недоступны",
                            self.snapshot.processes.len()
                        )
                    }
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
            self.poll_detail_action(visible)
        }
    }

    unsafe fn select(&mut self) -> Effect {
        // SAFETY: the listview query returns an index, which key() bounds-checks.
        unsafe {
            if self.tab == 1 {
                self.sync_startup_selection();
                return Effect::None;
            }
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
            self.pending_details = None;
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
            let style = GetWindowLongPtrW(self.table, GWL_STYLE) as u32;
            SetWindowLongPtrW(
                self.table,
                GWL_STYLE,
                if tab == 1 {
                    style & !LVS_SINGLESEL
                } else {
                    style | LVS_SINGLESEL
                } as isize,
            );
            SetWindowPos(
                self.table,
                ptr::null_mut(),
                0,
                0,
                0,
                0,
                SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED,
            );
            ShowWindow(self.startup_tree, if tab == 1 { SW_SHOW } else { SW_HIDE });
            self.layout();
            self.shared.active_tab.store(tab, Ordering::Release);
            self.selected = None;
            self.pending_details = None;
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
                if self.tab == 1 {
                    self.rebuild_startup_tree();
                }
                self.rebuild(false);
                return Effect::None;
            }
            if id == SETTINGS {
                return Effect::SettingsMenu;
            }
            match (self.tab, id) {
                (0, PRIMARY | SECONDARY | THIRD) | (1, SECONDARY | THIRD) => self
                    .menu_target()
                    .map(|target| target_effect(&target, id, self.details_edit))
                    .unwrap_or(Effect::None),
                (1, PRIMARY) => self
                    .shared
                    .send(Command::RefreshStartup)
                    .err()
                    .map(Effect::Error)
                    .unwrap_or(Effect::None),
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
            Effect::Send(command) => {
                if let Err(error) = shared.send(command) {
                    execute_effect(hwnd, shared, Effect::Error(error));
                }
            }
            Effect::SettingsMenu => {
                let pointer = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *const WindowState;
                if pointer.is_null() {
                    return;
                }
                let tray = (*pointer).ui.try_borrow_mut().ok().and_then(|mut ui| {
                    ui.context_menu_open = true;
                    ui.tray.take()
                });
                if let Some(mut tray) = tray {
                    tray.close_disk_tooltip();
                    shared.disk_hovered.store(false, Ordering::Release);
                    let action = tray.settings_menu(hwnd, shared);
                    if IsWindow(hwnd) == 0 {
                        return;
                    }
                    if let Ok(mut ui) = (*pointer).ui.try_borrow_mut() {
                        ui.tray = Some(tray);
                        ui.context_menu_open = false;
                    }
                    match action {
                        Some(TrayAction::Exit) => execute_effect(hwnd, shared, Effect::Exit),
                        Some(TrayAction::Show) => {
                            let mut ui = (*pointer).ui.borrow_mut();
                            let effect = show(&mut ui);
                            drop(ui);
                            execute_effect(hwnd, shared, effect);
                        }
                        _ => {}
                    }
                }
            }
            Effect::FocusDetails(control) => {
                if IsWindow(control) != 0 {
                    SetFocus(control);
                }
            }
            Effect::NeedDetails {
                pid,
                created,
                action,
            } => {
                if !update_visibility(hwnd, shared) {
                    return;
                }
                let pointer = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *const WindowState;
                if pointer.is_null() {
                    return;
                }
                let Ok(mut ui) = (*pointer).ui.try_borrow_mut() else {
                    return;
                };
                let effect = ui.request_detail_action(pid, created, action);
                drop(ui);
                execute_effect(hwnd, shared, effect);
            }
            Effect::Copy(text) => {
                if let Err(error) = copy_text(hwnd, &text) {
                    execute_effect(hwnd, shared, Effect::Error(error));
                }
            }
            Effect::OpenFolder(path) => {
                if let Some(parent) = std::path::Path::new(&path)
                    .parent()
                    .filter(|path| path.is_absolute())
                {
                    if ShellExecuteW(
                        hwnd,
                        wide("open").as_ptr(),
                        crate::win::os_wide(parent.as_os_str()).as_ptr(),
                        ptr::null(),
                        ptr::null(),
                        SW_SHOWNORMAL,
                    ) as isize
                        <= 32
                    {
                        execute_effect(
                            hwnd,
                            shared,
                            Effect::Error("Не удалось открыть папку файла".into()),
                        );
                    }
                } else {
                    execute_effect(
                        hwnd,
                        shared,
                        Effect::Error("Полный путь файла недоступен".into()),
                    );
                }
            }
            Effect::Properties(path) => {
                let verb = wide("properties");
                let path = wide(&path);
                let mut info = SHELLEXECUTEINFOW {
                    cbSize: size_of::<SHELLEXECUTEINFOW>() as u32,
                    fMask: SEE_MASK_INVOKEIDLIST | SEE_MASK_NOASYNC,
                    hwnd,
                    lpVerb: verb.as_ptr(),
                    lpFile: path.as_ptr(),
                    nShow: SW_SHOWNORMAL,
                    ..Default::default()
                };
                if ShellExecuteExW(&mut info) == 0 {
                    execute_effect(
                        hwnd,
                        shared,
                        Effect::Error("Не удалось открыть свойства файла".into()),
                    );
                }
            }
            Effect::ContextMenu {
                point,
                target,
                details_edit,
            } => {
                let action = track_context_menu(hwnd, point, &target);
                if IsWindow(hwnd) != 0 {
                    let pointer = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *const WindowState;
                    if !pointer.is_null() {
                        if let Ok(mut ui) = (*pointer).ui.try_borrow_mut() {
                            ui.context_menu_open = false;
                        }
                    }
                }
                if let Some(action) = action {
                    if IsWindow(hwnd) == 0 {
                        return;
                    }
                    if action == PRIMARY && matches!(target, MenuTarget::Startup(_)) {
                        if let Err(error) = shared.send(Command::RefreshStartup) {
                            execute_effect(hwnd, shared, Effect::Error(error));
                        }
                    } else {
                        execute_effect(hwnd, shared, target_effect(&target, action, details_edit));
                    }
                }
            }
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
        if let Some(result) = crate::theme::handle_message(hwnd, message, wparam, lparam) {
            return result;
        }
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
            WM_TIMER if wparam == crate::tray::DISK_HOVER_TIMER => {
                let ui = &mut *ui;
                if let Some(tray) = &mut ui.tray {
                    tray.disk_hover_tick(&ui.snapshot);
                    ui.shared
                        .disk_hovered
                        .store(tray.disk_tooltip_open(), Ordering::Release);
                }
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
                } else {
                    ui.pending_details = None;
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
            WM_SHOWWINDOW => {
                if wparam == 0 {
                    ui.pending_details = None;
                }
            }
            WM_CLOSE => {
                ui.pending_details = None;
                ShowWindow(hwnd, SW_HIDE);
                ui.shared.visible.store(false, Ordering::Release);
            }
            WM_COMMAND => {
                effect = ui.command(wparam & 0xffff, ((wparam >> 16) & 0xffff) as u16);
            }
            WM_CONTEXTMENU if wparam as HWND == ui.table || wparam as HWND == hwnd => {
                effect = ui.context_menu(lparam);
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
                                let text =
                                    ui.cell(info.item.iItem as usize, info.item.iSubItem as usize);
                                let output = std::slice::from_raw_parts_mut(
                                    info.item.pszText,
                                    info.item.cchTextMax as usize,
                                );
                                write_utf16_cell(&text, output);
                            }
                            if info.item.mask & LVIF_IMAGE != 0 && info.item.iItem >= 0 {
                                info.item.iImage = ui.image(info.item.iItem as usize);
                            }
                        }
                        LVN_ITEMCHANGED | LVN_ODSTATECHANGED => {
                            if ui.tab == 1 {
                                ui.startup_state_changed(header.code, lparam);
                            } else {
                                effect = ui.select();
                            }
                        }
                        LVN_KEYDOWN => {
                            let key = &*(lparam as *const NMLVKEYDOWN);
                            if ui.tab == 1
                                && key.wVKey == b'A' as u16
                                && GetKeyState(VK_CONTROL as i32) < 0
                            {
                                let item = LVITEMW {
                                    stateMask: LVIS_SELECTED,
                                    state: LVIS_SELECTED,
                                    ..Default::default()
                                };
                                SendMessageW(
                                    ui.table,
                                    LVM_SETITEMSTATE,
                                    usize::MAX,
                                    (&item as *const LVITEMW) as isize,
                                );
                                ui.sync_startup_selection();
                            } else if key.wVKey == VK_DELETE {
                                if let Some(target) = ui.menu_target() {
                                    effect = delete_effect(&target, ui.details_edit);
                                }
                            }
                        }
                        LVN_COLUMNCLICK => {
                            let item = &*(lparam as *const NMLISTVIEW);
                            if item.iSubItem >= 0 && item.iSubItem < ui.column_count as i32 {
                                let column = item.iSubItem as usize;
                                ui.descending = if ui.sort == column {
                                    !ui.descending
                                } else {
                                    ui.tab == 0 && matches!(column, 2..=7)
                                        || ui.tab == 1 && column == 5
                                };
                                ui.sort = column;
                                ui.rebuild(false);
                            }
                        }
                        _ => {}
                    }
                } else if header.hwndFrom == ui.startup_tree && header.code == TVN_SELCHANGEDW {
                    let change = &*(lparam as *const NMTREEVIEWW);
                    if let Some(node) = ui.startup_nodes.get(change.itemNew.lParam.max(0) as usize)
                    {
                        let group = node.group.clone();
                        if group != ui.startup_group {
                            ui.startup_group = group;
                            ui.selected = None;
                            ui.rebuild(false);
                        }
                    }
                } else if header.hwndFrom == ui.tabs && header.code == TCN_SELCHANGE {
                    effect = ui.change_tab();
                }
            }
            WM_DPICHANGED => {
                ui.dpi = (wparam & 0xffff) as u32;
                ui.set_fonts();
                let new_images = ActionImages::new(ui.dpi);
                // Keep the old, still-attached resources if cosmetic allocation
                // fails; a slightly mismatched icon size is preferable to a dangling handle.
                if new_images.has_images() {
                    let old_images = std::mem::replace(&mut ui.action_images, new_images);
                    ui.apply_action_images();
                    drop(old_images);
                }
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
            crate::tray::WM_TRAY => {
                let ui = &mut *ui;
                if let Some(tray) = &mut ui.tray {
                    tray.disk_hover_event(lparam, &ui.snapshot);
                    ui.shared
                        .disk_hovered
                        .store(tray.disk_tooltip_open(), Ordering::Release);
                }
                match lparam as u32 & 0xffff {
                    WM_LBUTTONUP | NIN_SELECT | NIN_KEYSELECT_NOTIFICATION => {
                        effect = show(ui);
                    }
                    WM_CONTEXTMENU | WM_RBUTTONUP => {
                        effect = Effect::SettingsMenu;
                    }
                    _ => {}
                }
            }
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
    crate::theme::initialize();
    // SAFETY: this function owns HWND, userdata, fonts and the message pump until destruction.
    unsafe {
        let controls = INITCOMMONCONTROLSEX {
            dwSize: size_of::<INITCOMMONCONTROLSEX>() as u32,
            dwICC: ICC_LISTVIEW_CLASSES
                | ICC_TAB_CLASSES
                | ICC_TREEVIEW_CLASSES
                | ICC_STANDARD_CLASSES,
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
            wide(&format!(
                "AnVir Next {} — {}",
                env!("CARGO_PKG_VERSION"),
                if cfg!(debug_assertions) {
                    "предпросмотр"
                } else {
                    "процессы и система"
                }
            ))
            .as_ptr(),
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
        let initial_size = (ui.scale(1180), ui.scale(780));
        let mut state = Box::new(WindowState {
            shared: Arc::clone(&shared),
            ui: RefCell::new(ui),
        });
        SetWindowLongPtrW(
            hwnd,
            GWLP_USERDATA,
            (&mut *state as *mut WindowState) as isize,
        );
        crate::theme::apply_window(hwnd);
        SetWindowPos(
            hwnd,
            ptr::null_mut(),
            0,
            0,
            initial_size.0,
            initial_size.1,
            SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE,
        );
        shared.notifier.bind(hwnd);
        shared.active_tab.store(0, Ordering::Release);
        // Start the isolated debug preview on the new startup surface. This also
        // keeps automated accessibility inspection away from a large live list.
        #[cfg(debug_assertions)]
        if std::env::args().any(|argument| argument == "--preview") {
            let effect = {
                let mut ui = state.ui.borrow_mut();
                SendMessageW(ui.tabs, TCM_SETCURSEL, 1, 0);
                ui.change_tab()
            };
            execute_effect(hwnd, &shared, effect);
        }
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
    fn startup_entry(id: &str, enabled: bool, can_toggle: bool) -> StartupEntry {
        StartupEntry {
            id: id.into(),
            name: id.into(),
            source: "HKCU Run".into(),
            location: "fixture".into(),
            command: "fixture.exe --arg".into(),
            enabled,
            can_toggle,
            icon_index: None,
            executable: None,
            added_at: None,
            origin: StartupOrigin::Registry {
                machine: false,
                view32: false,
                once: false,
            },
        }
    }
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
            icon_index: None,
            arguments: None,
            network_receive: None,
            network_send: None,
            disk_read: None,
            disk_write: None,
        }
    }
    #[test]
    fn filter_includes_full_path_product_company_and_pid() {
        let row = row(42, 100, None);
        for filter in ["program files", "example product", "publisher", "42"] {
            assert!(matches_process(&row, &SearchPattern::new(filter)));
        }
        assert!(!matches_process(&row, &SearchPattern::new("missing")));
    }
    #[test]
    fn process_identity_distinguishes_pid_reuse_and_numeric_sort_is_numeric() {
        let a = row(42, 100, Some(2.0));
        let b = row(42, 200, Some(12.0));
        assert_ne!(identity(&a), identity(&b));
        assert_eq!(compare_process(&a, &b, 2), Compare::Less);
        assert_eq!(process_cell(&row(1, 1, None), 7), "—");
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
    #[test]
    fn hovered_process_order_remaps_creation_identity_and_appends_new_processes() {
        let old = [
            row(10, 100, Some(80.0)),
            row(20, 200, Some(20.0)),
            row(30, 300, Some(10.0)),
            row(50, 500, Some(0.0)),
        ];
        let previous: Vec<_> = old.iter().map(identity).collect();
        let next = [
            row(40, 400, Some(90.0)),
            row(20, 201, Some(80.0)),
            row(30, 300, Some(70.0)),
            row(10, 100, Some(0.0)),
        ];
        let frozen = process_order(&next, "", 2, true, &previous, true);
        let keys: Vec<_> = frozen.iter().map(|index| identity(&next[*index])).collect();
        assert_eq!(
            keys,
            [
                Key::Process(10, 100),
                Key::Process(30, 300),
                Key::Process(40, 400),
                Key::Process(20, 201)
            ]
        );
        assert_eq!(next[frozen[0]].cpu, Some(0.0)); // Values refresh even while row order is frozen.
        let live = process_order(&next, "", 2, true, &previous, false);
        assert_eq!(live, [0, 1, 2, 3]);
        assert_eq!(process_order(&next, "40", 2, true, &previous, false), [0]);
    }
    #[test]
    fn unchanged_selection_does_not_emit_state_updates_and_missing_rows_clear_once() {
        assert_eq!(selection_updates(Some(12), Some(12)), (None, None));
        assert_eq!(selection_updates(None, None), (None, None));
        assert_eq!(selection_updates(Some(12), Some(5)), (Some(12), Some(5)));
        assert_eq!(selection_updates(Some(12), None), (Some(12), None));
    }
    #[test]
    fn context_target_uses_hit_row_or_keyboard_selection_never_an_old_selection_on_blank_space() {
        assert_eq!(context_index(Some(3), false, Some(8), 10), Some(3));
        assert_eq!(context_index(None, false, Some(8), 10), None);
        assert_eq!(context_index(None, true, Some(8), 10), Some(8));
        assert_eq!(context_index(Some(20), false, Some(8), 10), None);
        assert_eq!(context_index(None, true, Some(8), 0), None);
    }

    #[test]
    fn delete_disables_startup_once_and_ignores_disabled_or_read_only_entries() {
        let target = |enabled, can_toggle| {
            MenuTarget::Startup(vec![startup_entry("fixture-identity", enabled, can_toggle)])
        };
        match delete_effect(&target(true, true), ptr::null_mut()) {
            Effect::Confirm {
                command:
                    Command::StartupBatch {
                        entries,
                        action: StartupAction::Disable,
                    },
                ..
            } => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].id, "fixture-identity");
            }
            _ => panic!("Delete must confirm disabling an enabled startup entry"),
        }
        assert!(matches!(
            delete_effect(&target(false, true), ptr::null_mut()),
            Effect::None
        ));
        assert!(matches!(
            delete_effect(&target(true, false), ptr::null_mut()),
            Effect::None
        ));
        assert!(matches!(
            delete_effect(&target(false, false), ptr::null_mut()),
            Effect::None
        ));
    }

    #[test]
    fn process_delete_reuses_confirmation_and_retains_the_creation_identity() {
        let target = MenuTarget::Process {
            pid: 123,
            created: 456,
            path: "C:\\fixture.exe".into(),
            arguments: None,
            details: Some(ProcessDetails {
                command_line: "fixture.exe --args".into(),
                path: "C:\\fixture.exe".into(),
                priority: 0x20,
                affinity: 1,
                available_affinity: 1,
                parent_pid: 1,
                created: 456,
            }),
        };
        assert!(matches!(
            delete_effect(&target, ptr::null_mut()),
            Effect::Confirm {
                command: Command::Terminate {
                    pid: 123,
                    created: 456
                },
                ..
            }
        ));
        let unavailable = MenuTarget::Process {
            pid: 123,
            created: 0,
            path: String::new(),
            arguments: None,
            details: None,
        };
        assert!(matches!(
            delete_effect(&unavailable, ptr::null_mut()),
            Effect::None
        ));
    }

    #[test]
    fn native_utf16_cells_are_bounded_terminated_and_never_split_surrogates() {
        assert_eq!(write_utf16_cell("text", &mut []), 0);
        let mut only_terminator = [99];
        assert_eq!(write_utf16_cell("text", &mut only_terminator), 0);
        assert_eq!(only_terminator, [0]);
        let mut short = [0xaaaa; 5];
        assert_eq!(write_utf16_cell("a😀Z", &mut short[..3]), 1);
        assert_eq!(short, [b'a' as u16, 0, 0xaaaa, 0xaaaa, 0xaaaa]);
        let written = write_utf16_cell("a😀Z", &mut short[..4]);
        assert_eq!(written, 3);
        assert_eq!(String::from_utf16(&short[..written]).unwrap(), "a😀");
        assert_eq!(short[written], 0);
        let mut nul = [99; 4];
        assert_eq!(write_utf16_cell("a\0b", &mut nul), 3);
        assert_eq!(nul, [b'a' as u16, 0xfffd, b'b' as u16, 0]);
        assert_eq!(write_utf16_cell("", &mut nul), 0);
        assert_eq!(nul[0], 0);
    }

    #[test]
    fn arguments_are_borrowed_searchable_and_sorted_without_changing_the_raw_tail() {
        let mut a = row(1, 1, None);
        a.arguments = Some(Arc::from(format!(
            "{} --MiXeD=İ \\\"preserve quotes\\\"",
            "a".repeat(32700)
        )));
        assert!(matches!(process_cell(&a, 8), Cow::Borrowed(_)));
        assert!(matches_process(&a, &SearchPattern::new("--mixed=i\u{307}")));
        assert!(
            SearchPattern::new(&format!("{}b", "a".repeat(255)))
                .contains(&format!("{}b", "a".repeat(32700)))
        );
        assert!(!SearchPattern::new("not-present").contains(a.arguments.as_deref().unwrap()));
        let mut output = [99; 16];
        assert_eq!(write_utf16_cell(&process_cell(&a, 8), &mut output), 15);
        assert_eq!(output[15], 0);
        a.arguments = Some(Arc::from("Zebra"));
        let mut b = row(2, 2, None);
        b.arguments = Some(Arc::from("apple"));
        assert_eq!(compare_process(&a, &b, 8), Compare::Less);
        b.arguments = Some(Arc::from(""));
        assert_eq!(process_cell(&b, 8), "");
        b.arguments = None;
        assert_eq!(process_cell(&b, 8), "—");
    }

    #[test]
    fn traffic_columns_distinguish_unavailable_data_from_real_zero_and_sort_numerically() {
        let mut a = row(1, 1, None);
        let mut b = row(2, 2, None);
        for column in 3..=6 {
            assert_eq!(process_cell(&a, column), "—");
        }
        a.disk_read = Some(0.0);
        a.disk_write = Some(2.0);
        a.network_receive = Some(3.0);
        a.network_send = Some(4.0);
        b.disk_read = Some(1.0);
        b.disk_write = Some(10.0);
        b.network_receive = Some(30.0);
        b.network_send = Some(40.0);
        assert_eq!(process_cell(&a, 3), "0 Б/с");
        for column in 3..=6 {
            assert_eq!(compare_process(&a, &b, column), Compare::Less);
        }
    }

    #[test]
    fn first_context_menu_snapshot_can_terminate_without_async_details() {
        let snapshot = MenuTarget::Process {
            pid: 123,
            created: 456,
            path: "C:\\fixture.exe".into(),
            details: None,
            arguments: Some(Arc::from("--cached-args")),
        };
        assert!(matches!(
            target_effect(&snapshot, PRIMARY, ptr::null_mut()),
            Effect::Confirm {
                command: Command::Terminate {
                    pid: 123,
                    created: 456
                },
                ..
            }
        ));
        assert!(
            matches!(target_effect(&snapshot, MENU_COPY_ARGUMENTS, ptr::null_mut()), Effect::Copy(text) if text == "--cached-args")
        );
    }

    #[test]
    fn startup_batch_filters_enable_disable_and_confirms_start_stop_once() {
        let enabled = startup_entry("enabled", true, true);
        let disabled = startup_entry("disabled", false, true);
        let mut task = startup_entry("task", true, false);
        task.origin = StartupOrigin::Task {
            folder: "\\".into(),
        };
        let mut service = startup_entry("service", true, false);
        service.origin = StartupOrigin::Service;
        let mut application = startup_entry("app", false, false);
        application.executable = Some("C:\\fixture.exe".into());
        let entries = vec![enabled, disabled, task, service, application];
        for (action, expected) in [
            (StartupAction::Disable, vec!["enabled"]),
            (StartupAction::Enable, vec!["disabled"]),
            (StartupAction::Stop, vec!["task", "service", "app"]),
            (StartupAction::Start, vec!["task", "service", "app"]),
        ] {
            match startup_batch_effect(&entries, action) {
                Effect::Confirm {
                    command:
                        Command::StartupBatch {
                            entries,
                            action: actual,
                        },
                    ..
                } => {
                    assert_eq!(actual, action);
                    assert_eq!(
                        entries
                            .iter()
                            .map(|entry| entry.id.as_str())
                            .collect::<Vec<_>>(),
                        expected
                    );
                }
                _ => panic!("a batch must produce one confirmation with only supported targets"),
            }
        }
        assert!(matches!(
            startup_batch_effect(&entries[2..3], StartupAction::Start),
            Effect::Send(Command::StartupBatch {
                action: StartupAction::Start,
                ..
            })
        ));
        assert!(matches!(
            startup_batch_effect(&entries[..1], StartupAction::Start),
            Effect::None
        ));
    }

    #[test]
    fn startup_selection_and_batch_snapshot_follow_ids_after_reorder_and_removal() {
        let selected = BTreeSet::from(["a".to_string(), "c".to_string()]);
        let make_row = |id: &str| Row {
            key: Key::Entry(id.into()),
            cells: Vec::new(),
            icon: None,
            added_at: None,
        };
        let reordered = [make_row("b"), make_row("c"), make_row("a")];
        assert_eq!(
            selected_startup_indices(&reordered, &selected),
            BTreeSet::from([1, 2])
        );
        let removed = [make_row("new"), make_row("c")];
        assert_eq!(
            selected_startup_indices(&removed, &selected),
            BTreeSet::from([1])
        );
        let snapshot = startup_targets(
            &[
                startup_entry("b", true, true),
                startup_entry("c", true, true),
                startup_entry("a", false, true),
            ],
            &selected,
        );
        assert_eq!(
            snapshot
                .iter()
                .map(|entry| entry.id.as_str())
                .collect::<Vec<_>>(),
            ["c", "a"]
        );
        assert!(matches!(
            target_effect(
                &MenuTarget::Startup(snapshot),
                MENU_COPY_COMMAND,
                ptr::null_mut()
            ),
            Effect::None
        ));
    }

    #[test]
    fn added_at_sort_uses_utc_value_instead_of_day_first_display_text() {
        let older = Row {
            key: Key::Entry("old".into()),
            cells: vec![
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                "31.12.2023 23:59".into(),
            ],
            icon: None,
            added_at: Some(100),
        };
        let newer = Row {
            key: Key::Entry("new".into()),
            cells: vec![
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                "01.01.2024 00:00".into(),
            ],
            icon: None,
            added_at: Some(200),
        };
        assert_eq!(compare_startup_rows(&older, &newer, 5), Compare::Less);
        assert!(older.cells[5] > newer.cells[5]);
    }
}
