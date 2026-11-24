//! Native seconds editor for two explicitly separate startup-delay scopes.
use crate::{icons::ActionImages, startup::ExplorerDelay, win::wide};
use std::{
    cell::{Cell, RefCell},
    mem::size_of,
    ptr,
};
use windows_sys::Win32::{
    Foundation::*,
    Graphics::Gdi::*,
    System::LibraryLoader::GetModuleHandleW,
    UI::{
        Controls::*,
        HiDpi::GetDpiForWindow,
        Input::KeyboardAndMouse::{EnableWindow, IsWindowEnabled, SetFocus},
        Shell::{SIID_DELETE, SIID_SETTINGS},
        WindowsAndMessaging::*,
    },
};

const DEFAULTS: usize = 20;
const SECONDS: usize = 21;
const ERROR_LABEL: usize = 22;
pub(super) const EXPLORER_MAX_SECONDS: u32 = u32::MAX / 1000;

pub(super) enum Mode {
    Explorer(ExplorerDelay),
    Tasks {
        count: usize,
        seconds: Option<u32>,
        skipped: usize,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Choice {
    Seconds(u32),
    WindowsDefaults,
}

fn parse_seconds(text: &str, maximum: u32) -> Option<u32> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse::<u32>().ok().filter(|value| *value <= maximum)
}

fn explorer_initial_seconds(current: ExplorerDelay) -> Option<u32> {
    current
        .milliseconds
        .filter(|value| value % 1000 == 0)
        .map(|value| value / 1000)
}

struct Dialog {
    font: HFONT,
    _images: ActionImages,
    input: HWND,
    defaults: HWND,
    error: HWND,
    maximum: u32,
    result: Option<Choice>,
    done: bool,
    dpi: u32,
    positions: Vec<(HWND, [i32; 4])>,
    apply: HWND,
    cancel: HWND,
}

unsafe fn create_font(dpi: u32) -> HFONT {
    // SAFETY: creates one private font with a terminated family name; caller owns the returned handle.
    unsafe {
        CreateFontW(
            -(14 * dpi as i32 / 96),
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
    }
}
impl Drop for Dialog {
    fn drop(&mut self) {
        // SAFETY: the message-loop owner destroys all assigned controls before this owned font.
        unsafe {
            DeleteObject(self.font);
        }
    }
}

/// # Safety
/// The owner is a live window on this UI thread. Call without a UI RefCell borrow.
pub(super) unsafe fn show(owner: HWND, mode: Mode) -> Result<Option<Choice>, String> {
    // SAFETY: all windows/resources are owned on this thread, with local buffers alive during FFI calls.
    unsafe {
        let class = wide("AnVirNext.StartupDelay");
        let instance = GetModuleHandleW(ptr::null());
        let wc = WNDCLASSEXW {
            cbSize: size_of::<WNDCLASSEXW>() as u32,
            lpfnWndProc: Some(procedure),
            hInstance: instance,
            hIcon: GetClassLongPtrW(owner, GCLP_HICON) as HICON,
            hIconSm: GetClassLongPtrW(owner, GCLP_HICONSM) as HICON,
            hCursor: LoadCursorW(ptr::null_mut(), IDC_ARROW),
            hbrBackground: (COLOR_BTNFACE + 1) as HBRUSH,
            lpszClassName: class.as_ptr(),
            ..Default::default()
        };
        if RegisterClassExW(&wc) == 0 && GetLastError() != ERROR_CLASS_ALREADY_EXISTS {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let dpi = GetDpiForWindow(owner).max(96);
        let scale = |value: i32| value * dpi as i32 / 96;
        let mut bounds = RECT::default();
        GetWindowRect(owner, &mut bounds);
        let width = scale(580);
        let height = scale(454);
        let hwnd = CreateWindowExW(
            WS_EX_DLGMODALFRAME | WS_EX_CONTROLPARENT,
            class.as_ptr(),
            wide("Задержка запуска").as_ptr(),
            WS_CAPTION | WS_SYSMENU | WS_POPUP,
            bounds.left + (bounds.right - bounds.left - width) / 2,
            bounds.top + (bounds.bottom - bounds.top - height) / 2,
            width,
            height,
            owner,
            ptr::null_mut(),
            instance,
            ptr::null(),
        );
        if hwnd.is_null() {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let font = create_font(dpi);
        let images = ActionImages::new(dpi);
        let failed = Cell::new(font.is_null());
        let positions = RefCell::new(Vec::new());
        let child = |class: &str, text: &str, style, extended, id: usize, x, y, w, h| {
            let control = CreateWindowExW(
                extended,
                wide(class).as_ptr(),
                wide(text).as_ptr(),
                WS_CHILD | WS_VISIBLE | style,
                scale(x),
                scale(y),
                scale(w),
                scale(h),
                hwnd,
                id as HMENU,
                instance,
                ptr::null(),
            );
            if control.is_null() {
                failed.set(true);
            }
            positions.borrow_mut().push((control, [x, y, w, h]));
            SendMessageW(control, WM_SETFONT, font as usize, 0);
            control
        };
        let (title, current, initial, default_checked, maximum) = match mode {
            Mode::Explorer(current) => {
                let milliseconds = current
                    .milliseconds
                    .map(|value| format!("{value} мс"))
                    .unwrap_or_else(|| "по умолчанию".into());
                let idle = match current.wait_for_idle {
                    None => "по умолчанию".into(),
                    Some(0) => "отключено".into(),
                    Some(1) => "включено".into(),
                    Some(value) => format!("неизвестное значение ({value})"),
                };
                let initial = explorer_initial_seconds(current)
                    .map(|value| value.to_string())
                    .unwrap_or_default();
                (
                    "Общая задержка Проводника".to_string(),
                    format!("Задержка {milliseconds}. Ожидание простоя {idle}."),
                    initial,
                    current.milliseconds.is_none() && current.wait_for_idle.is_none(),
                    EXPLORER_MAX_SECONDS,
                )
            }
            Mode::Tasks {
                count,
                seconds,
                skipped,
            } => {
                let value = seconds
                    .map(|value| format!("{value} с"))
                    .unwrap_or_else(|| "значения различаются или не определены".into());
                let mut current = format!("Текущее значение {value}.");
                if skipped > 0 {
                    current.push_str(&format!(" Пропущено недоступных записей — {skipped}."));
                }
                (
                    format!("Задержка выбранных заданий ({count})"),
                    current,
                    seconds.map(|value| value.to_string()).unwrap_or_default(),
                    false,
                    u32::MAX,
                )
            }
        };
        let (applies_to, timing) = if matches!(mode, Mode::Explorer(_)) {
            (
                "Для записей Run и папок «Автозагрузка» текущего пользователя.",
                "Настройка вступит в силу при следующем входе в Windows.",
            )
        } else {
            (
                "Для включённых триггеров загрузки и входа выбранных заданий.",
                "Новое значение действует при следующем срабатывании триггера.",
            )
        };
        child("STATIC", &title, 0, 0, 0, 18, 16, 535, 24);
        child("STATIC", applies_to, 0, 0, 0, 18, 50, 535, 45);
        child("STATIC", &current, 0, 0, 0, 18, 119, 535, 70);
        child("STATIC", "Задержка, сек.", 0, 0, 0, 18, 208, 140, 24);
        let input = child(
            "EDIT",
            &initial,
            WS_TABSTOP | ES_NUMBER as u32 | ES_AUTOHSCROLL as u32,
            WS_EX_CLIENTEDGE,
            SECONDS,
            165,
            204,
            135,
            28,
        );
        SendMessageW(input, EM_SETLIMITTEXT, 10, 0);
        let defaults = if matches!(mode, Mode::Explorer(_)) {
            let checkbox = child(
                "BUTTON",
                "Вернуть настройки Windows по умолчанию",
                WS_TABSTOP | BS_AUTOCHECKBOX as u32,
                0,
                DEFAULTS,
                18,
                244,
                535,
                25,
            );
            SendMessageW(
                checkbox,
                BM_SETCHECK,
                if default_checked {
                    BST_CHECKED as usize
                } else {
                    BST_UNCHECKED as usize
                },
                0,
            );
            EnableWindow(input, (!default_checked) as i32);
            checkbox
        } else {
            ptr::null_mut()
        };
        let scope = if matches!(mode, Mode::Explorer(_)) {
            "Явная задержка отключает ожидание простоя. 0 — без задержки."
        } else {
            "0 означает отсутствие явной задержки триггеров этих задач."
        };
        child("STATIC", scope, 0, 0, 0, 18, 276, 535, 22);
        child("STATIC", timing, 0, 0, 0, 18, 304, 535, 35);
        let error = child("STATIC", "", 0, 0, ERROR_LABEL, 18, 357, 300, 40);
        let apply = child(
            "BUTTON",
            "Применить",
            WS_TABSTOP | BS_DEFPUSHBUTTON as u32,
            0,
            IDOK as usize,
            325,
            359,
            112,
            30,
        );
        let cancel = child(
            "BUTTON",
            "Отмена",
            WS_TABSTOP | BS_PUSHBUTTON as u32,
            0,
            IDCANCEL as usize,
            445,
            359,
            108,
            30,
        );
        images.apply_button(apply, SIID_SETTINGS);
        images.apply_button(cancel, SIID_DELETE);
        if failed.get() {
            DestroyWindow(hwnd);
            DeleteObject(font);
            return Err("Не удалось создать диалог задержки запуска".into());
        }
        let mut state = Box::new(RefCell::new(Dialog {
            font,
            _images: images,
            input,
            defaults,
            error,
            maximum,
            result: None,
            done: false,
            dpi,
            positions: positions.into_inner(),
            apply,
            cancel,
        }));
        SetWindowLongPtrW(
            hwnd,
            GWLP_USERDATA,
            (&mut *state as *mut RefCell<Dialog>) as isize,
        );
        crate::theme::apply_window(hwnd);
        let enabled = IsWindowEnabled(owner) != 0;
        EnableWindow(owner, 0);
        ShowWindow(hwnd, SW_SHOW);
        SetFocus(if default_checked { defaults } else { input });
        let mut message = MSG::default();
        let mut message_error = None;
        while !state.borrow().done {
            let result = GetMessageW(&mut message, ptr::null_mut(), 0, 0);
            if result <= 0 {
                if result == 0 {
                    PostQuitMessage(message.wParam as i32);
                } else {
                    message_error = Some(std::io::Error::last_os_error().to_string());
                }
                break;
            }
            if IsDialogMessageW(hwnd, &message) == 0 {
                TranslateMessage(&message);
                DispatchMessageW(&message);
            }
        }
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        if IsWindow(hwnd) != 0 {
            DestroyWindow(hwnd);
        }
        if enabled {
            EnableWindow(owner, 1);
        }
        SetForegroundWindow(owner);
        let result = state.borrow_mut().result.take();
        message_error.map_or(Ok(result), Err)
    }
}

unsafe extern "system" fn procedure(
    hwnd: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    // SAFETY: userdata is owned by show's Box until after HWND destruction; native message pointers are synchronous.
    unsafe {
        if let Some(result) = crate::theme::handle_message(hwnd, message, wparam, lparam) {
            return result;
        }
        let pointer = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *const RefCell<Dialog>;
        if pointer.is_null() {
            return DefWindowProcW(hwnd, message, wparam, lparam);
        }
        let Ok(mut state) = (*pointer).try_borrow_mut() else {
            return DefWindowProcW(hwnd, message, wparam, lparam);
        };
        match message {
            WM_COMMAND => match wparam as u16 as usize {
                DEFAULTS => {
                    let checked =
                        SendMessageW(state.defaults, BM_GETCHECK, 0, 0) == BST_CHECKED as isize;
                    EnableWindow(state.input, (!checked) as i32);
                    SetWindowTextW(state.error, wide("").as_ptr());
                }
                SECONDS if (wparam >> 16) as u32 == EN_CHANGE => {
                    SetWindowTextW(state.error, wide("").as_ptr());
                }
                value if value == IDOK as usize => {
                    let defaults = !state.defaults.is_null()
                        && SendMessageW(state.defaults, BM_GETCHECK, 0, 0) == BST_CHECKED as isize;
                    let choice = if defaults {
                        Some(Choice::WindowsDefaults)
                    } else {
                        let mut text = [0u16; 11];
                        let count =
                            GetWindowTextW(state.input, text.as_mut_ptr(), text.len() as i32);
                        parse_seconds(
                            &String::from_utf16_lossy(&text[..count.max(0) as usize]),
                            state.maximum,
                        )
                        .map(Choice::Seconds)
                    };
                    let Some(choice) = choice else {
                        SetWindowTextW(
                            state.error,
                            wide(&format!("Введите целые секунды: 0–{}.", state.maximum)).as_ptr(),
                        );
                        SetFocus(state.input);
                        return 0;
                    };
                    state.result = Some(choice);
                    state.done = true;
                    drop(state);
                    DestroyWindow(hwnd);
                }
                value if value == IDCANCEL as usize => {
                    state.done = true;
                    drop(state);
                    DestroyWindow(hwnd);
                }
                _ => {}
            },
            WM_CLOSE => {
                state.done = true;
                drop(state);
                DestroyWindow(hwnd);
            }
            WM_DPICHANGED => {
                state.dpi = (wparam as u32 & 0xffff).max(96);
                let font = create_font(state.dpi);
                for (control, [x, y, width, height]) in &state.positions {
                    let scale = |value: i32| value * state.dpi as i32 / 96;
                    MoveWindow(
                        *control,
                        scale(*x),
                        scale(*y),
                        scale(*width),
                        scale(*height),
                        1,
                    );
                    if !font.is_null() {
                        SendMessageW(*control, WM_SETFONT, font as usize, 1);
                    }
                }
                if !font.is_null() {
                    let old = std::mem::replace(&mut state.font, font);
                    DeleteObject(old);
                }
                let images = ActionImages::new(state.dpi);
                if images.has_images() {
                    images.apply_button(state.apply, SIID_SETTINGS);
                    images.apply_button(state.cancel, SIID_DELETE);
                    state._images = images;
                }
                if lparam != 0 {
                    let bounds = &*(lparam as *const RECT);
                    SetWindowPos(
                        hwnd,
                        ptr::null_mut(),
                        bounds.left,
                        bounds.top,
                        bounds.right - bounds.left,
                        bounds.bottom - bounds.top,
                        SWP_NOZORDER | SWP_NOACTIVATE,
                    );
                }
            }
            WM_NCDESTROY => {
                SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
                drop(state);
                return DefWindowProcW(hwnd, message, wparam, lparam);
            }
            _ => {
                drop(state);
                return DefWindowProcW(hwnd, message, wparam, lparam);
            }
        }
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn seconds_validation_distinguishes_explicit_zero_and_rejects_overflow_or_partial_input() {
        assert_eq!(parse_seconds("0", EXPLORER_MAX_SECONDS), Some(0));
        assert_eq!(
            parse_seconds("4294967", EXPLORER_MAX_SECONDS),
            Some(4_294_967)
        );
        assert_eq!(parse_seconds("4294968", EXPLORER_MAX_SECONDS), None);
        assert_eq!(parse_seconds("4294967295", u32::MAX), Some(u32::MAX));
        for value in ["", "4294967296", "-1", "+1", "1.5", "1 second", " 1"] {
            assert_eq!(parse_seconds(value, u32::MAX), None);
        }
    }

    #[test]
    fn existing_millisecond_values_are_never_silently_rounded_in_the_seconds_editor() {
        let current = |milliseconds| ExplorerDelay {
            milliseconds,
            wait_for_idle: Some(1),
        };
        assert_eq!(explorer_initial_seconds(current(Some(4500))), None);
        assert_eq!(explorer_initial_seconds(current(Some(4000))), Some(4));
        assert_eq!(explorer_initial_seconds(current(Some(0))), Some(0));
        assert_eq!(explorer_initial_seconds(current(None)), None);
    }
}
