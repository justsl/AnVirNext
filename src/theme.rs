//! System app-theme support for the native windows, without periodic polling.

use crate::win::wide;
use std::{
    cell::Cell,
    mem::size_of,
    ptr,
    sync::{
        OnceLock,
        atomic::{AtomicBool, AtomicU8, Ordering},
    },
};
use windows_sys::Win32::{
    Foundation::*,
    Graphics::{
        Dwm::{DWMWA_USE_IMMERSIVE_DARK_MODE, DwmSetWindowAttribute},
        Gdi::*,
    },
    System::{
        LibraryLoader::{GetModuleHandleW, GetProcAddress},
        Registry::{HKEY_CURRENT_USER, RRF_RT_REG_DWORD, RegGetValueW},
        SystemInformation::{GetVersionExW, OSVERSIONINFOW},
    },
    UI::{
        Accessibility::{HCF_HIGHCONTRASTON, HIGHCONTRASTW},
        Controls::*,
        Input::KeyboardAndMouse::{GetFocus, IsWindowEnabled},
        Shell::{DefSubclassProc, RemoveWindowSubclass, SetWindowSubclass},
        WindowsAndMessaging::*,
    },
};

static MODE: AtomicU8 = AtomicU8::new(Mode::Light as u8);
static INITIALIZED: AtomicBool = AtomicBool::new(false);
thread_local! { static APPLYING: Cell<bool> = const { Cell::new(false) }; }
const SUBCLASS_ID: usize = 0x4156_5448;
const TAB_STRIP: usize = 1;
const HEADER_STRIP: usize = 2;

const fn rgb(red: u8, green: u8, blue: u8) -> COLORREF {
    red as u32 | ((green as u32) << 8) | ((blue as u32) << 16)
}
const BACKGROUND: COLORREF = rgb(32, 32, 32);
const SURFACE: COLORREF = rgb(27, 27, 27);
const TEXT: COLORREF = rgb(238, 238, 238);
const DISABLED: COLORREF = rgb(155, 155, 155);
const BORDER: COLORREF = rgb(86, 86, 86);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum Mode {
    Light,
    Dark,
    HighContrast,
}

fn preferred_mode(apps_use_light: Option<u32>, high_contrast: bool) -> Mode {
    if high_contrast {
        return Mode::HighContrast;
    }
    if apps_use_light == Some(0) {
        Mode::Dark
    } else {
        Mode::Light
    }
}

fn current() -> Mode {
    match MODE.load(Ordering::Relaxed) {
        1 => Mode::Dark,
        2 => Mode::HighContrast,
        _ => Mode::Light,
    }
}

pub(crate) fn tooltip_colors() -> (COLORREF, COLORREF) {
    if current() == Mode::Dark {
        (BACKGROUND, TEXT)
    } else {
        // SAFETY: Win32 returns the colors for the current system scheme, including high contrast.
        unsafe { (GetSysColor(COLOR_INFOBK), GetSysColor(COLOR_INFOTEXT)) }
    }
}

fn system_mode() -> Mode {
    let mut value = 1u32;
    let mut length = size_of::<u32>() as u32;
    let mut contrast = HIGHCONTRASTW {
        cbSize: size_of::<HIGHCONTRASTW>() as u32,
        ..Default::default()
    };
    // SAFETY: bounded DWORD/structure outputs and terminated constant registry strings.
    unsafe {
        let result = RegGetValueW(
            HKEY_CURRENT_USER,
            wide(r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize").as_ptr(),
            wide("AppsUseLightTheme").as_ptr(),
            RRF_RT_REG_DWORD,
            ptr::null_mut(),
            (&mut value as *mut u32).cast(),
            &mut length,
        );
        let contrast_result = SystemParametersInfoW(
            SPI_GETHIGHCONTRAST,
            contrast.cbSize,
            (&mut contrast as *mut HIGHCONTRASTW).cast(),
            0,
        );
        preferred_mode(
            (result == 0 && length == 4).then_some(value),
            contrast_result == 0 || contrast.dwFlags & HCF_HIGHCONTRASTON != 0,
        )
    }
}

type PreferredAppMode = unsafe extern "system" fn(i32) -> i32;
type AllowWindow = unsafe extern "system" fn(HWND, bool) -> bool;
type RefreshNative = unsafe extern "system" fn();

#[derive(Default)]
struct NativeTheme {
    preferred: Option<PreferredAppMode>,
    allow: Option<AllowWindow>,
    refresh: Option<RefreshNative>,
    flush: Option<RefreshNative>,
}

fn native() -> &'static NativeTheme {
    static FUNCTIONS: OnceLock<NativeTheme> = OnceLock::new();
    FUNCTIONS.get_or_init(|| {
        let mut version = OSVERSIONINFOW {
            dwOSVersionInfoSize: size_of::<OSVERSIONINFOW>() as u32,
            ..Default::default()
        };
        // SAFETY: one initialized OS version output; app manifest declares Windows 10/11 support.
        unsafe {
            if GetVersionExW(&mut version) == 0
                || version.dwMajorVersion != 10
                || version.dwBuildNumber < 22000
            {
                return NativeTheme::default();
            }
            // UXTheme is already a linked system DLL. These optional Windows 11
            // exports enable dark common controls/menus; the color fallback is independent.
            // ABI references: microsoft/PowerToys src/modules/ZoomIt/ZoomIt/Utility.cpp.
            let module = GetModuleHandleW(wide("uxtheme.dll").as_ptr());
            if module.is_null() {
                return NativeTheme::default();
            }
            NativeTheme {
                preferred: GetProcAddress(module, ptr::without_provenance(135)).map(|f| {
                    std::mem::transmute::<unsafe extern "system" fn() -> isize, PreferredAppMode>(f)
                }),
                allow: GetProcAddress(module, ptr::without_provenance(133)).map(|f| {
                    std::mem::transmute::<unsafe extern "system" fn() -> isize, AllowWindow>(f)
                }),
                refresh: GetProcAddress(module, ptr::without_provenance(104)).map(|f| {
                    std::mem::transmute::<unsafe extern "system" fn() -> isize, RefreshNative>(f)
                }),
                flush: GetProcAddress(module, ptr::without_provenance(136)).map(|f| {
                    std::mem::transmute::<unsafe extern "system" fn() -> isize, RefreshNative>(f)
                }),
            }
        }
    })
}

fn set_mode(mode: Mode) {
    let previous = MODE.swap(mode as u8, Ordering::Relaxed);
    if INITIALIZED.swap(true, Ordering::Relaxed) && previous == mode as u8 {
        return;
    }
    let functions = native();
    // SAFETY: resolved exports use the verified Windows 11 ABIs; absent exports are skipped.
    unsafe {
        if let Some(refresh) = functions.refresh {
            refresh();
        }
        if let Some(preferred) = functions.preferred {
            preferred(match mode {
                Mode::HighContrast => 0,
                Mode::Dark => 2,
                Mode::Light => 3,
            });
        }
        if let Some(flush) = functions.flush {
            flush();
        }
    }
}

/// Called on the UI thread before creating the first window.
pub fn initialize() {
    set_mode(system_mode());
}

/// Applies the cached app theme to a window and its existing native children.
///
/// # Safety
/// The caller owns the live window and its children on the current UI thread.
pub unsafe fn apply_window(hwnd: HWND) {
    // SAFETY: caller supplies a live UI-thread HWND; all child calls are synchronous.
    unsafe {
        APPLYING.with(|applying| {
            if applying.replace(true) {
                return;
            }
            let dark = current() == Mode::Dark;
            if let Some(allow) = native().allow {
                allow(hwnd, dark);
            }
            let enabled = i32::from(dark);
            let _ = DwmSetWindowAttribute(
                hwnd,
                DWMWA_USE_IMMERSIVE_DARK_MODE as u32,
                (&enabled as *const i32).cast(),
                size_of::<i32>() as u32,
            );
            EnumChildWindows(hwnd, Some(apply_child), 0);
            RedrawWindow(
                hwnd,
                ptr::null(),
                ptr::null_mut(),
                RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN | RDW_FRAME,
            );
            applying.set(false);
        });
    }
}

unsafe extern "system" fn apply_child(hwnd: HWND, _: LPARAM) -> i32 {
    // SAFETY: EnumChildWindows provides live children; APIs copy strings synchronously.
    unsafe {
        let dark = current() == Mode::Dark;
        if let Some(allow) = native().allow {
            allow(hwnd, dark);
        }
        let mut name = [0u16; 64];
        let length = GetClassNameW(hwnd, name.as_mut_ptr(), name.len() as i32).max(0) as usize;
        let name = String::from_utf16_lossy(&name[..length]);
        let theme = match name.as_str() {
            "ComboBox" => "DarkMode_CFD",
            "SysHeader32" => "DarkMode_ItemsView",
            _ => "DarkMode_Explorer",
        };
        let theme_name = dark.then(|| wide(theme));
        SetWindowTheme(
            hwnd,
            theme_name
                .as_ref()
                .map_or(ptr::null(), |name| name.as_ptr()),
            ptr::null(),
        );
        let background = if dark {
            SURFACE
        } else {
            GetSysColor(COLOR_WINDOW)
        };
        let text = if dark {
            TEXT
        } else {
            GetSysColor(COLOR_WINDOWTEXT)
        };
        match name.as_str() {
            "SysListView32" => {
                SendMessageW(hwnd, LVM_SETBKCOLOR, 0, background as isize);
                SendMessageW(hwnd, LVM_SETTEXTBKCOLOR, 0, background as isize);
                SendMessageW(hwnd, LVM_SETTEXTCOLOR, 0, text as isize);
            }
            "SysTreeView32" => {
                SendMessageW(hwnd, TVM_SETBKCOLOR, 0, background as isize);
                SendMessageW(hwnd, TVM_SETTEXTCOLOR, 0, text as isize);
            }
            "SysTabControl32" | "SysHeader32" => {
                SetWindowSubclass(
                    hwnd,
                    Some(strip_procedure),
                    SUBCLASS_ID,
                    if name == "SysTabControl32" {
                        TAB_STRIP
                    } else {
                        HEADER_STRIP
                    },
                );
            }
            _ => {}
        }
        1
    }
}

/// Handles theme notifications and dark native background/text colors before borrowing UI state.
///
/// # Safety
/// Parameters must be a genuine window-procedure message for the live UI-thread window.
pub unsafe fn handle_message(
    hwnd: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> Option<LRESULT> {
    // SAFETY: message-specific HWND/HDC parameters come from the owning window procedure.
    unsafe {
        if matches!(
            message,
            WM_SETTINGCHANGE | WM_THEMECHANGED | WM_SYSCOLORCHANGE
        ) {
            if !APPLYING.with(Cell::get) {
                initialize();
                apply_window(hwnd);
            }
            return None;
        }
        if current() != Mode::Dark {
            return None;
        }
        match message {
            WM_ERASEBKGND => {
                let dc = wparam as HDC;
                let mut rect = RECT::default();
                GetClientRect(hwnd, &mut rect);
                fill(dc, &rect, BACKGROUND);
                Some(1)
            }
            WM_CTLCOLORSTATIC | WM_CTLCOLOREDIT | WM_CTLCOLORBTN | WM_CTLCOLORDLG
            | WM_CTLCOLORLISTBOX => {
                let dc = wparam as HDC;
                let control = lparam as HWND;
                let mut class = [0u16; 16];
                let length = GetClassNameW(control, class.as_mut_ptr(), class.len() as i32);
                let is_edit = length == 4 && class[..4] == [69, 100, 105, 116];
                let background =
                    if is_edit || matches!(message, WM_CTLCOLOREDIT | WM_CTLCOLORLISTBOX) {
                        SURFACE
                    } else {
                        BACKGROUND
                    };
                SetTextColor(
                    dc,
                    if IsWindowEnabled(control) == 0 {
                        DISABLED
                    } else {
                        TEXT
                    },
                );
                SetBkColor(dc, background);
                SetDCBrushColor(dc, background);
                Some(GetStockObject(DC_BRUSH) as LRESULT)
            }
            _ => None,
        }
    }
}

unsafe fn fill(dc: HDC, rect: &RECT, color: COLORREF) {
    // SAFETY: caller supplies a valid paint/control DC and rectangle; DC_BRUSH is borrowed.
    unsafe {
        SetDCBrushColor(dc, color);
        FillRect(dc, rect, GetStockObject(DC_BRUSH) as HBRUSH);
    }
}

unsafe extern "system" fn strip_procedure(
    hwnd: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
    _: usize,
    kind: usize,
) -> LRESULT {
    // SAFETY: comctl32 owns this subclass's lifetime; no Rust pointers are retained.
    unsafe {
        if message == WM_NCDESTROY {
            RemoveWindowSubclass(hwnd, Some(strip_procedure), SUBCLASS_ID);
            return DefSubclassProc(hwnd, message, wparam, lparam);
        }
        if current() != Mode::Dark {
            return DefSubclassProc(hwnd, message, wparam, lparam);
        }
        match message {
            WM_ERASEBKGND => 1,
            WM_PAINT => {
                let mut paint = PAINTSTRUCT::default();
                let dc = BeginPaint(hwnd, &mut paint);
                paint_strip(hwnd, dc, kind);
                EndPaint(hwnd, &paint);
                0
            }
            WM_PRINTCLIENT => {
                paint_strip(hwnd, wparam as HDC, kind);
                0
            }
            _ => DefSubclassProc(hwnd, message, wparam, lparam),
        }
    }
}

unsafe fn paint_strip(hwnd: HWND, dc: HDC, kind: usize) {
    // SAFETY: all queried strings/rectangles use fixed writable buffers; the DC is restored before return.
    unsafe {
        let saved = SaveDC(dc);
        if saved == 0 {
            return;
        }
        let mut bounds = RECT::default();
        GetClientRect(hwnd, &mut bounds);
        fill(dc, &bounds, BACKGROUND);
        let font = SendMessageW(hwnd, WM_GETFONT, 0, 0) as HFONT;
        if !font.is_null() {
            SelectObject(dc, font);
        }
        SetBkMode(dc, TRANSPARENT as i32);
        SetTextColor(dc, TEXT);
        let count_message = if kind == TAB_STRIP {
            TCM_GETITEMCOUNT
        } else {
            HDM_GETITEMCOUNT
        };
        let count = SendMessageW(hwnd, count_message, 0, 0).clamp(0, 128) as usize;
        let selected = if kind == TAB_STRIP {
            SendMessageW(hwnd, TCM_GETCURSEL, 0, 0)
        } else {
            -1
        };
        let images = SendMessageW(
            hwnd,
            if kind == TAB_STRIP {
                TCM_GETIMAGELIST
            } else {
                HDM_GETIMAGELIST
            },
            0,
            0,
        ) as HIMAGELIST;
        let (mut image_width, mut image_height) = (0, 0);
        if images != 0 {
            ImageList_GetIconSize(images, &mut image_width, &mut image_height);
        }
        for index in 0..count {
            let mut rect = RECT::default();
            let mut text = [0u16; 512];
            let mut alignment = DT_CENTER;
            let mut image_index = -1;
            if kind == TAB_STRIP {
                if SendMessageW(
                    hwnd,
                    TCM_GETITEMRECT,
                    index,
                    (&mut rect as *mut RECT) as isize,
                ) == 0
                {
                    continue;
                }
                let mut item = TCITEMW {
                    mask: TCIF_TEXT | TCIF_IMAGE,
                    pszText: text.as_mut_ptr(),
                    cchTextMax: text.len() as i32,
                    ..Default::default()
                };
                SendMessageW(
                    hwnd,
                    TCM_GETITEMW,
                    index,
                    (&mut item as *mut TCITEMW) as isize,
                );
                image_index = item.iImage;
            } else {
                if SendMessageW(
                    hwnd,
                    HDM_GETITEMRECT,
                    index,
                    (&mut rect as *mut RECT) as isize,
                ) == 0
                {
                    continue;
                }
                let mut item = HDITEMW {
                    mask: HDI_TEXT | HDI_FORMAT | HDI_IMAGE,
                    pszText: text.as_mut_ptr(),
                    cchTextMax: text.len() as i32,
                    ..Default::default()
                };
                SendMessageW(
                    hwnd,
                    HDM_GETITEMW,
                    index,
                    (&mut item as *mut HDITEMW) as isize,
                );
                alignment = if item.fmt & HDF_RIGHT != 0 {
                    DT_RIGHT
                } else {
                    DT_LEFT
                };
                if item.fmt & HDF_IMAGE != 0 {
                    image_index = item.iImage;
                }
            }
            text[text.len() - 1] = 0;
            fill(
                dc,
                &rect,
                if selected == index as isize {
                    rgb(48, 48, 48)
                } else {
                    BACKGROUND
                },
            );
            SetDCBrushColor(dc, BORDER);
            FrameRect(dc, &rect, GetStockObject(DC_BRUSH) as HBRUSH);
            if selected == index as isize
                && GetFocus() == hwnd
                && SendMessageW(hwnd, WM_QUERYUISTATE, 0, 0) & UISF_HIDEFOCUS as isize == 0
            {
                let mut focus = rect;
                InflateRect(&mut focus, -3, -3);
                DrawFocusRect(dc, &focus);
            }
            let padding = if kind == TAB_STRIP { 2 } else { 8 };
            rect.left += padding;
            rect.right -= padding;
            if image_index >= 0 && images != 0 && image_width > 0 {
                ImageList_Draw(
                    images,
                    image_index,
                    dc,
                    rect.left + 2,
                    rect.top + (rect.bottom - rect.top - image_height) / 2,
                    ILD_TRANSPARENT,
                );
                rect.left += image_width + 6;
            }
            DrawTextW(
                dc,
                text.as_ptr(),
                -1,
                &mut rect,
                alignment | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX,
            );
        }
        RestoreDC(dc, saved);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn follows_app_preference_and_falls_back_when_it_is_unavailable() {
        assert_eq!(preferred_mode(Some(0), false), Mode::Dark);
        assert_eq!(preferred_mode(Some(1), false), Mode::Light);
        assert_eq!(preferred_mode(None, false), Mode::Light);
        assert_eq!(preferred_mode(Some(7), false), Mode::Light);
    }

    #[test]
    fn high_contrast_preserves_native_colors_even_when_apps_are_dark() {
        for preference in [None, Some(0), Some(1)] {
            assert_eq!(preferred_mode(preference, true), Mode::HighContrast);
        }
    }

    #[test]
    fn dark_text_contrast_is_readable_on_each_surface() {
        fn luminance(color: COLORREF) -> f64 {
            let channel = |offset: u32| {
                let value = ((color >> offset) & 255u32) as f64 / 255.0;
                if value <= 0.04045 {
                    value / 12.92
                } else {
                    ((value + 0.055) / 1.055).powf(2.4)
                }
            };
            channel(0) * 0.2126 + channel(8) * 0.7152 + channel(16) * 0.0722
        }
        for background in [BACKGROUND, SURFACE, rgb(48, 48, 48)] {
            for foreground in [TEXT, DISABLED] {
                assert!((luminance(foreground) + 0.05) / (luminance(background) + 0.05) >= 4.5);
            }
        }
    }

    #[test]
    fn native_controls_switch_colors_and_settings_message_redetects_without_os_changes() {
        unsafe extern "system" fn procedure(
            hwnd: HWND,
            message: u32,
            wparam: WPARAM,
            lparam: LPARAM,
        ) -> LRESULT {
            // SAFETY: this isolated fixture owns the window/message pump on its creating thread.
            unsafe {
                handle_message(hwnd, message, wparam, lparam)
                    .unwrap_or_else(|| DefWindowProcW(hwnd, message, wparam, lparam))
            }
        }
        struct Fixture {
            hwnd: HWND,
            class: Vec<u16>,
            instance: HINSTANCE,
        }
        impl Drop for Fixture {
            fn drop(&mut self) {
                // SAFETY: the fixture owns this window/class and never changes user preferences.
                unsafe {
                    DestroyWindow(self.hwnd);
                    UnregisterClassW(self.class.as_ptr(), self.instance);
                }
                initialize();
            }
        }
        // SAFETY: all handles belong to disposable hidden fixture windows and are cleaned up above.
        unsafe {
            let controls = INITCOMMONCONTROLSEX {
                dwSize: size_of::<INITCOMMONCONTROLSEX>() as u32,
                dwICC: ICC_LISTVIEW_CLASSES | ICC_TREEVIEW_CLASSES,
            };
            assert_ne!(InitCommonControlsEx(&controls), 0);
            let class = wide(&format!("AnVirNext.ThemeFixture.{}", std::process::id()));
            let instance = GetModuleHandleW(ptr::null());
            let registration = WNDCLASSW {
                lpfnWndProc: Some(procedure),
                hInstance: instance,
                lpszClassName: class.as_ptr(),
                ..Default::default()
            };
            assert_ne!(RegisterClassW(&registration), 0);
            let hwnd = CreateWindowExW(
                0,
                class.as_ptr(),
                wide("Theme test").as_ptr(),
                WS_OVERLAPPEDWINDOW,
                0,
                0,
                400,
                300,
                ptr::null_mut(),
                ptr::null_mut(),
                instance,
                ptr::null(),
            );
            assert!(!hwnd.is_null());
            let _fixture = Fixture {
                hwnd,
                class,
                instance,
            };
            let child = |class: &str| {
                CreateWindowExW(
                    0,
                    wide(class).as_ptr(),
                    wide("").as_ptr(),
                    WS_CHILD,
                    0,
                    0,
                    100,
                    100,
                    hwnd,
                    ptr::null_mut(),
                    instance,
                    ptr::null(),
                )
            };
            let list = child("SysListView32");
            let tree = child("SysTreeView32");
            assert!(!list.is_null() && !tree.is_null());
            for mode in [Mode::Dark, Mode::Light, Mode::HighContrast, Mode::Dark] {
                set_mode(mode);
                apply_window(hwnd);
                let background = if mode == Mode::Dark {
                    SURFACE
                } else {
                    GetSysColor(COLOR_WINDOW)
                };
                let text = if mode == Mode::Dark {
                    TEXT
                } else {
                    GetSysColor(COLOR_WINDOWTEXT)
                };
                assert_eq!(SendMessageW(list, LVM_GETBKCOLOR, 0, 0) as u32, background);
                assert_eq!(SendMessageW(list, LVM_GETTEXTCOLOR, 0, 0) as u32, text);
                assert_eq!(SendMessageW(tree, TVM_GETBKCOLOR, 0, 0) as u32, background);
                assert_eq!(SendMessageW(tree, TVM_GETTEXTCOLOR, 0, 0) as u32, text);
            }
            let detected = system_mode();
            set_mode(if detected == Mode::Dark {
                Mode::Light
            } else {
                Mode::Dark
            });
            SendMessageW(hwnd, WM_SETTINGCHANGE, 0, 0);
            assert_eq!(current(), detected);
            let expected = if detected == Mode::Dark {
                SURFACE
            } else {
                GetSysColor(COLOR_WINDOW)
            };
            assert_eq!(SendMessageW(list, LVM_GETBKCOLOR, 0, 0) as u32, expected);
        }
    }
}
