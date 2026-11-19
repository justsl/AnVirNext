use crate::{theme, win::wide};
use std::{mem::size_of, ptr};
use windows_sys::Win32::{
    Foundation::{HWND, LPARAM, LRESULT, RECT, WPARAM},
    Graphics::Gdi::*,
    UI::{
        HiDpi::GetDpiForWindow,
        Shell::{DefSubclassProc, SetWindowSubclass},
        WindowsAndMessaging::*,
    },
};

const MAX_TEXT: usize = 2048;
const TEXT_FLAGS: u32 = DT_NOPREFIX | DT_WORDBREAK;

fn bounded_text(mut text: String) -> String {
    if text.encode_utf16().take(MAX_TEXT + 1).count() <= MAX_TEXT {
        return text;
    }
    let mut units = 0;
    let mut end = 0;
    for (offset, character) in text.char_indices() {
        if units + character.len_utf16() > MAX_TEXT - 1 {
            break;
        }
        units += character.len_utf16();
        end = offset + character.len_utf8();
    }
    text.truncate(end);
    text.push('…');
    text
}

pub(super) struct TrayTooltip {
    window: HWND,
    font: HFONT,
    text: String,
    colors: (u32, u32),
    dpi: i32,
}

impl TrayTooltip {
    pub(super) fn open(anchor: RECT, text: String) -> Option<Self> {
        let mut tooltip = Self::new(anchor)?;
        tooltip.update(anchor, text);
        // SAFETY: show the popup without activating or moving focus from the desktop.
        unsafe {
            ShowWindow(tooltip.window, SW_SHOWNOACTIVATE);
        }
        Some(tooltip)
    }

    fn new(anchor: RECT) -> Option<Self> {
        // SAFETY: we own the native text window and its font on this UI thread.
        unsafe {
            let window = CreateWindowExW(
                WS_EX_TOOLWINDOW | WS_EX_TOPMOST | WS_EX_NOACTIVATE | WS_EX_TRANSPARENT,
                wide("STATIC").as_ptr(),
                ptr::null(),
                WS_POPUP | WS_BORDER,
                anchor.left,
                anchor.top,
                0,
                0,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null(),
            );
            if window.is_null() {
                return None;
            }
            let dpi = GetDpiForWindow(window).max(96) as i32;
            let font = CreateFontW(
                -(14 * dpi / 96),
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
                CLEARTYPE_QUALITY as u32,
                DEFAULT_PITCH as u32,
                wide("Segoe UI").as_ptr(),
            );
            let tooltip = Self {
                window,
                font,
                text: String::new(),
                colors: theme::tooltip_colors(),
                dpi,
            };
            if font.is_null() || SetWindowSubclass(window, Some(paint_tooltip), 1, 0) == 0 {
                return None;
            }
            SendMessageW(window, WM_SETFONT, font as usize, 0);
            Some(tooltip)
        }
    }

    pub(super) fn update(&mut self, anchor: RECT, text: String) {
        let text = bounded_text(text);
        let colors = theme::tooltip_colors();
        // SAFETY: all GDI and window access is to our own live popup on this thread.
        unsafe {
            if self.text == text {
                if self.colors != colors {
                    InvalidateRect(self.window, ptr::null(), 0);
                }
                self.colors = colors;
                return;
            }
            self.colors = colors;
            let words = wide(&text);
            let mut rect = RECT {
                right: 380 * self.dpi / 96,
                ..Default::default()
            };
            let dc = GetDC(self.window);
            if dc.is_null() {
                return;
            }
            let old = SelectObject(dc, self.font);
            DrawTextW(dc, words.as_ptr(), -1, &mut rect, TEXT_FLAGS | DT_CALCRECT);
            SelectObject(dc, old);
            ReleaseDC(self.window, dc);
            let margin = 8 * self.dpi / 96;
            let size = (rect.right + margin * 2 + 2, rect.bottom + margin * 2 + 2);
            let mut monitor = MONITORINFO {
                cbSize: size_of::<MONITORINFO>() as u32,
                ..Default::default()
            };
            let (x, y) = if GetMonitorInfoW(
                MonitorFromRect(&anchor, MONITOR_DEFAULTTONEAREST),
                &mut monitor,
            ) != 0
            {
                popup_position(anchor, monitor.rcWork, size, margin)
            } else {
                (anchor.left - size.0, anchor.top - size.1)
            };
            SetWindowTextW(self.window, words.as_ptr());
            SetWindowPos(
                self.window,
                HWND_TOPMOST,
                x,
                y,
                size.0,
                size.1,
                SWP_NOACTIVATE,
            );
            InvalidateRect(self.window, ptr::null(), 0);
            self.text = text;
        }
    }
}

impl Drop for TrayTooltip {
    fn drop(&mut self) {
        // SAFETY: release the control before releasing the font assigned to it.
        unsafe {
            DestroyWindow(self.window);
            if !self.font.is_null() {
                DeleteObject(self.font);
            }
        }
    }
}

unsafe extern "system" fn paint_tooltip(
    window: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
    _: usize,
    _: usize,
) -> LRESULT {
    // SAFETY: this runs on the popup's UI thread. The subclass stores no Rust
    // pointers; painted text is copied from the native control into a bounded buffer.
    unsafe {
        match message {
            WM_NCHITTEST => HTTRANSPARENT as isize,
            WM_ERASEBKGND => 1,
            WM_PAINT => {
                let mut paint = PAINTSTRUCT::default();
                let dc = BeginPaint(window, &mut paint);
                if !dc.is_null() {
                    let mut bounds = RECT::default();
                    GetClientRect(window, &mut bounds);
                    let (background, foreground) = theme::tooltip_colors();
                    SetDCBrushColor(dc, background);
                    FillRect(dc, &bounds, GetStockObject(DC_BRUSH) as HBRUSH);
                    let margin = 8 * GetDpiForWindow(window).max(96) as i32 / 96;
                    InflateRect(&mut bounds, -margin, -margin);
                    let mut text = [0u16; MAX_TEXT + 1];
                    let length = GetWindowTextW(window, text.as_mut_ptr(), text.len() as i32);
                    let font = SendMessageW(window, WM_GETFONT, 0, 0) as HFONT;
                    let old = SelectObject(dc, font);
                    SetBkMode(dc, TRANSPARENT as i32);
                    SetTextColor(dc, foreground);
                    DrawTextW(dc, text.as_ptr(), length, &mut bounds, TEXT_FLAGS);
                    SelectObject(dc, old);
                }
                EndPaint(window, &paint);
                0
            }
            _ => DefSubclassProc(window, message, wparam, lparam),
        }
    }
}

fn popup_position(anchor: RECT, work: RECT, (width, height): (i32, i32), gap: i32) -> (i32, i32) {
    let (mut x, mut y) = (anchor.left, anchor.top - height - gap);
    if anchor.left >= work.right - gap {
        x = anchor.left - width - gap;
        y = anchor.top + (anchor.bottom - anchor.top - height) / 2;
    } else if anchor.right <= work.left + gap {
        x = anchor.right + gap;
        y = anchor.top + (anchor.bottom - anchor.top - height) / 2;
    } else if y < work.top {
        y = anchor.bottom + gap;
    }
    (
        x.clamp(work.left, (work.right - width).max(work.left)),
        y.clamp(work.top, (work.bottom - height).max(work.top)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_bounds_match_the_paint_buffer_without_cutting_utf16_surrogates() {
        assert_eq!(bounded_text("short😀".into()), "short😀");
        let text = bounded_text(format!("{}😀tail", "a".repeat(MAX_TEXT - 2)));
        assert!(text.ends_with('…'));
        assert!(text.encode_utf16().count() <= MAX_TEXT);
        assert!(!text.ends_with("tail"));
        let text = bounded_text("😀".repeat(MAX_TEXT));
        assert_eq!(text.encode_utf16().count(), MAX_TEXT - 1);
        assert!(text.ends_with('…'));
    }

    #[test]
    fn summary_stays_inside_the_work_area_on_a_negative_coordinate_monitor() {
        let work = RECT {
            left: -1920,
            top: 0,
            right: -60,
            bottom: 1080,
        };
        let icon = RECT {
            left: -50,
            top: 1040,
            right: -20,
            bottom: 1070,
        };
        assert_eq!(popup_position(icon, work, (380, 285), 6), (-440, 795));
    }

    #[test]
    fn native_popup_measures_and_updates_multiline_text_beyond_shell_limit() {
        let anchor = RECT {
            left: 10,
            top: 10,
            right: 26,
            bottom: 26,
        };
        let mut popup = TrayTooltip::new(anchor).unwrap();
        popup.update(anchor, "Диск".into());
        let mut short = RECT::default();
        // SAFETY: this is the test's hidden popup; short is initialized writable RECT storage.
        unsafe {
            assert_ne!(GetWindowRect(popup.window, &mut short), 0);
        }
        let sample = "Физический диск C: · 34% · чтение 12 МиБ/с · запись 7 МиБ/с\r\n".repeat(8);
        assert!(sample.encode_utf16().count() > 128);
        popup.update(anchor, sample);
        let mut detailed = RECT::default();
        // SAFETY: the same live hidden popup and a second writable output.
        unsafe {
            assert_ne!(GetWindowRect(popup.window, &mut detailed), 0);
        }
        assert!(detailed.right - detailed.left > short.right - short.left);
        assert!(detailed.bottom - detailed.top > 3 * (short.bottom - short.top));
    }
}
