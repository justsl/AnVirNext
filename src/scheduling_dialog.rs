//! Explicit per-process scheduling choices. This module never mutates a process.
use crate::{processes::ProcessDetails, win::wide};
use std::{
    cell::{Cell, RefCell},
    mem::size_of,
    ptr,
};
use windows_sys::Win32::{
    Foundation::*,
    Graphics::Gdi::*,
    System::{LibraryLoader::GetModuleHandleW, Threading::*},
    UI::{
        Controls::*,
        HiDpi::GetDpiForWindow,
        Input::KeyboardAndMouse::{EnableWindow, IsWindowEnabled, SetFocus},
        WindowsAndMessaging::*,
    },
};

const PRIORITIES: [(u32, &str); 5] = [
    (IDLE_PRIORITY_CLASS, "Низкий"),
    (BELOW_NORMAL_PRIORITY_CLASS, "Ниже обычного"),
    (NORMAL_PRIORITY_CLASS, "Обычный"),
    (ABOVE_NORMAL_PRIORITY_CLASS, "Выше обычного"),
    (HIGH_PRIORITY_CLASS, "Высокий"),
];

pub fn priority_name(value: u32) -> &'static str {
    PRIORITIES
        .iter()
        .find(|(priority, _)| *priority == value)
        .map(|(_, name)| *name)
        .unwrap_or("Неизвестный")
}

#[derive(Clone, Debug)]
pub struct Choice {
    pub priority: u32,
    pub affinity: u64,
    pub remember: bool,
}

struct Dialog {
    hwnd: HWND,
    font: HFONT,
    combo: HWND,
    remember: HWND,
    processors: Vec<(u32, HWND)>,
    allowed: u64,
    result: Option<Choice>,
    done: bool,
}

impl Drop for Dialog {
    fn drop(&mut self) {
        // SAFETY: the owned font is deleted only after dialog and child destruction.
        unsafe {
            DeleteObject(self.font);
        }
    }
}

fn valid_mask(mask: u64, allowed: u64) -> bool {
    mask != 0 && mask & !allowed == 0
}

/// The caller passes a DetailsResult already matched to the selected process identity.
///
/// # Safety
/// `owner` must be a live window on the current UI thread, with a running message pump.
pub unsafe fn show(owner: HWND, details: &ProcessDetails) -> Result<Option<Choice>, String> {
    // SAFETY: caller guarantees a live owner; local state and buffers outlive the modal window.
    unsafe {
        let instance = GetModuleHandleW(ptr::null());
        let class = wide("AnVirNext.Scheduling");
        let wc = WNDCLASSEXW {
            cbSize: size_of::<WNDCLASSEXW>() as u32,
            lpfnWndProc: Some(procedure),
            hInstance: instance,
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
        let mut owner_rect = RECT::default();
        GetWindowRect(owner, &mut owner_rect);
        let width = scale(568);
        let height = scale(490);
        let x = owner_rect.left + (owner_rect.right - owner_rect.left - width) / 2;
        let y = owner_rect.top + (owner_rect.bottom - owner_rect.top - height) / 2;
        let hwnd = CreateWindowExW(
            WS_EX_DLGMODALFRAME | WS_EX_CONTROLPARENT,
            class.as_ptr(),
            wide("Приоритет и процессоры").as_ptr(),
            WS_CAPTION | WS_SYSMENU | WS_POPUP,
            x,
            y,
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
        let font = CreateFontW(
            -scale(14),
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
        );
        let control_failed = Cell::new(false);
        let child = |class: &str, text: &str, style: u32, id: usize, x, y, w, h| {
            let control = CreateWindowExW(
                0,
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
                control_failed.set(true);
            }
            SendMessageW(control, WM_SETFONT, font as usize, 0);
            control
        };
        child("STATIC", "Приоритет процесса", 0, 0, 18, 16, 180, 23);
        let combo = child(
            "COMBOBOX",
            "",
            CBS_DROPDOWNLIST as u32 | WS_TABSTOP | WS_VSCROLL,
            10,
            210,
            13,
            315,
            180,
        );
        for (_, name) in PRIORITIES {
            SendMessageW(combo, CB_ADDSTRING, 0, wide(name).as_ptr() as isize);
        }
        let selected = PRIORITIES
            .iter()
            .position(|(priority, _)| *priority == details.priority);
        SendMessageW(combo, CB_SETCURSEL, selected.unwrap_or(usize::MAX), 0);
        child(
            "STATIC",
            "Разрешённые логические процессоры",
            0,
            0,
            18,
            59,
            480,
            22,
        );
        let mut processors = Vec::new();
        for index in 0..64u32 {
            if details.available_affinity & (1u64 << index) == 0 {
                continue;
            }
            let control = child(
                "BUTTON",
                &format!("CPU {index}"),
                BS_AUTOCHECKBOX as u32 | WS_TABSTOP,
                100 + index as usize,
                18 + (index % 8) as i32 * 65,
                90 + (index / 8) as i32 * 27,
                65,
                25,
            );
            SendMessageW(
                control,
                BM_SETCHECK,
                if details.affinity & (1u64 << index) != 0 {
                    BST_CHECKED as usize
                } else {
                    BST_UNCHECKED as usize
                },
                0,
            );
            processors.push((index, control));
        }
        child(
            "BUTTON",
            "Все",
            BS_PUSHBUTTON as u32 | WS_TABSTOP,
            11,
            18,
            312,
            105,
            28,
        );
        let remember = child(
            "BUTTON",
            "Запомнить для будущих запусков этого .exe",
            BS_AUTOCHECKBOX as u32 | WS_TABSTOP,
            12,
            18,
            352,
            510,
            25,
        );
        child(
            "STATIC",
            "Высокий приоритет может ухудшить отзывчивость Windows.",
            0,
            0,
            18,
            382,
            510,
            22,
        );
        child(
            "BUTTON",
            "Применить",
            BS_DEFPUSHBUTTON as u32 | WS_TABSTOP,
            IDOK as usize,
            304,
            417,
            108,
            30,
        );
        child(
            "BUTTON",
            "Отмена",
            BS_PUSHBUTTON as u32 | WS_TABSTOP,
            IDCANCEL as usize,
            422,
            417,
            105,
            30,
        );
        if control_failed.get() {
            DestroyWindow(hwnd);
            DeleteObject(font);
            return Err("Не удалось создать элементы диалога параметров процесса".into());
        }
        let mut state = Box::new(RefCell::new(Dialog {
            hwnd,
            font,
            combo,
            remember,
            processors,
            allowed: details.available_affinity,
            result: None,
            done: false,
        }));
        SetWindowLongPtrW(
            hwnd,
            GWLP_USERDATA,
            (&mut *state as *mut RefCell<Dialog>) as isize,
        );
        let was_enabled = IsWindowEnabled(owner) != 0;
        EnableWindow(owner, 0);
        ShowWindow(hwnd, SW_SHOW);
        SetFocus(combo);
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
        if IsWindow(hwnd) != 0 {
            DestroyWindow(hwnd);
        }
        if was_enabled {
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
    // SAFETY: userdata points to the Box retained by show; Windows supplies HWND/message parameters.
    unsafe {
        let pointer = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *const RefCell<Dialog>;
        if pointer.is_null() {
            return DefWindowProcW(hwnd, message, wparam, lparam);
        }
        let Ok(mut state) = (*pointer).try_borrow_mut() else {
            return DefWindowProcW(hwnd, message, wparam, lparam);
        };
        match message {
            WM_COMMAND => match wparam as u16 as i32 {
                IDOK => {
                    let affinity = state
                        .processors
                        .iter()
                        .filter(|(_, control)| {
                            SendMessageW(*control, BM_GETCHECK, 0, 0) == BST_CHECKED as isize
                        })
                        .fold(0u64, |mask, (index, _)| mask | (1u64 << index));
                    let selected = SendMessageW(state.combo, CB_GETCURSEL, 0, 0);
                    if !valid_mask(affinity, state.allowed)
                        || !(0..PRIORITIES.len() as isize).contains(&selected)
                    {
                        MessageBoxW(
                            hwnd,
                            wide("Выберите хотя бы один доступный процессор и приоритет.").as_ptr(),
                            wide("Параметры процесса").as_ptr(),
                            MB_OK | MB_ICONWARNING,
                        );
                        return 0;
                    }
                    state.result = Some(Choice {
                        priority: PRIORITIES[selected as usize].0,
                        affinity,
                        remember: SendMessageW(state.remember, BM_GETCHECK, 0, 0)
                            == BST_CHECKED as isize,
                    });
                    state.done = true;
                    DestroyWindow(state.hwnd);
                }
                IDCANCEL => {
                    state.done = true;
                    DestroyWindow(state.hwnd);
                }
                11 => {
                    for (_, control) in &state.processors {
                        SendMessageW(*control, BM_SETCHECK, BST_CHECKED as usize, 0);
                    }
                }
                _ => {}
            },
            WM_CLOSE => {
                state.done = true;
                DestroyWindow(state.hwnd);
            }
            WM_NCDESTROY => {
                SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
                return DefWindowProcW(hwnd, message, wparam, lparam);
            }
            _ => return DefWindowProcW(hwnd, message, wparam, lparam),
        }
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn affinity_requires_an_allowed_nonempty_subset_including_bit_63() {
        assert!(!valid_mask(0, u64::MAX));
        assert!(!valid_mask(4, 3));
        assert!(valid_mask(3, 7));
        assert!(valid_mask(1u64 << 63, u64::MAX));
        assert!(
            !PRIORITIES
                .iter()
                .any(|(priority, _)| *priority == REALTIME_PRIORITY_CLASS)
        );
    }
}
