use std::{
    ffi::OsStr,
    io,
    os::windows::ffi::OsStrExt,
    sync::atomic::{AtomicBool, AtomicIsize, Ordering},
};
use windows_sys::Win32::Foundation::{CloseHandle, FILETIME, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::UI::WindowsAndMessaging::{PostMessageW, WM_APP};

pub const WM_SAMPLE_UPDATED: u32 = WM_APP + 2;

#[derive(Default)]
pub struct Notifier {
    window: AtomicIsize,
    pending: AtomicBool,
}

impl Notifier {
    pub fn bind(&self, window: windows_sys::Win32::Foundation::HWND) {
        self.window.store(window as isize, Ordering::Release);
    }
    pub fn acknowledge(&self) {
        self.pending.store(false, Ordering::Release);
    }
    pub fn notify(&self) {
        let window = self.window.load(Ordering::Acquire);
        if window == 0 || self.pending.swap(true, Ordering::AcqRel) {
            return;
        }
        // SAFETY: messages carry no pointers; a concurrently destroyed HWND simply rejects the post.
        if unsafe { PostMessageW(window as _, WM_SAMPLE_UPDATED, 0, 0) } == 0 {
            self.pending.store(false, Ordering::Release);
        }
    }
}

pub fn wide(text: &str) -> Vec<u16> {
    text.chars()
        .map(|character| {
            if character == '\0' {
                '\u{fffd}'
            } else {
                character
            }
        })
        .collect::<String>()
        .encode_utf16()
        .chain(Some(0))
        .collect()
}

pub fn os_wide(text: &OsStr) -> Vec<u16> {
    text.encode_wide().chain(Some(0)).collect()
}

pub fn filetime(time: FILETIME) -> u64 {
    (u64::from(time.dwHighDateTime) << 32) | u64::from(time.dwLowDateTime)
}

pub struct Handle(HANDLE);

impl Handle {
    /// Takes ownership of a handle returned by a Win32 creation/open function.
    /// The caller must not pass a borrowed or pseudo handle.
    pub fn new(handle: HANDLE) -> io::Result<Self> {
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(handle))
    }
    pub fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: this wrapper owns one valid, non-pseudo Win32 handle.
        unsafe {
            CloseHandle(self.0);
        }
    }
}
