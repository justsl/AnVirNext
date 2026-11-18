//! Borrowed Shell system-image-list indices and bounded owned copies for native action controls.
use crate::win::wide;
use std::{
    collections::HashMap,
    marker::PhantomData,
    mem::size_of,
    path::{Component, Path, PathBuf, Prefix},
    ptr,
    rc::Rc,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{HWND, RECT, RPC_E_CHANGED_MODE},
    Storage::FileSystem::{
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
        GetDriveTypeW, GetFileAttributesW, INVALID_FILE_ATTRIBUTES,
    },
    System::{
        Com::{COINIT_MULTITHREADED, CoInitializeEx, CoUninitialize},
        Environment::ExpandEnvironmentStringsW,
        LibraryLoader::{GetModuleHandleW, GetProcAddress},
        SystemInformation::GetSystemDirectoryW,
    },
    UI::{
        Controls::*,
        Shell::*,
        WindowsAndMessaging::{
            CopyImage, DestroyIcon, HICON, IMAGE_ICON, STM_SETICON, SendMessageW,
        },
    },
};

const MAX_CACHE: usize = 512;
const MAX_WIDE: usize = 32767;
const CACHE_TTL: Duration = Duration::from_secs(600);
struct Cache<T> {
    entries: HashMap<String, (Instant, T)>,
}
impl<T: Clone> Cache<T> {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }
    fn get(&mut self, key: &str, now: Instant) -> Option<T> {
        if self
            .entries
            .get(key)
            .is_some_and(|entry| now.saturating_duration_since(entry.0) >= CACHE_TTL)
        {
            self.entries.remove(key);
        }
        self.entries.get(key).map(|entry| entry.1.clone())
    }
    fn insert(&mut self, key: String, value: T, now: Instant) {
        if !self.entries.contains_key(&key) && self.entries.len() >= MAX_CACHE {
            if let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.0)
                .map(|(key, _)| key.clone())
            {
                self.entries.remove(&oldest);
            }
        }
        self.entries.insert(key, (now, value));
    }
}

struct ComScope {
    uninitialize: bool,
    _thread: PhantomData<Rc<()>>,
}
impl ComScope {
    fn new() -> Option<Self> {
        // SAFETY: initializes only this thread; successful initialization is balanced by Drop.
        let status = unsafe { CoInitializeEx(ptr::null(), COINIT_MULTITHREADED as u32) };
        if status < 0 && status != RPC_E_CHANGED_MODE {
            return None;
        }
        Some(Self {
            uninitialize: status >= 0,
            _thread: PhantomData,
        })
    }
}
impl Drop for ComScope {
    fn drop(&mut self) {
        if self.uninitialize {
            // SAFETY: this !Send guard initialized COM successfully on this same thread.
            unsafe {
                CoUninitialize();
            }
        }
    }
}

/// Borrowed, read-only Shell image list. Controls must use LVS_SHAREIMAGELISTS;
/// callers must never destroy or modify this image list.
fn system_images() -> Option<(HIMAGELIST, i32)> {
    static LIST: OnceLock<Option<(HIMAGELIST, i32)>> = OnceLock::new();
    *LIST.get_or_init(|| {
        let _com = ComScope::new()?;
        initialize_image_cache()?;
        let mut info = SHFILEINFOW::default();
        // SAFETY: a synthetic extension plus USEFILEATTRIBUTES avoids file I/O;
        // SYSICONINDEX does not allocate an HICON, and returns a borrowed list.
        let list = unsafe {
            SHGetFileInfoW(
                wide(".exe").as_ptr(),
                FILE_ATTRIBUTE_NORMAL,
                &mut info,
                size_of::<SHFILEINFOW>() as u32,
                SHGFI_SYSICONINDEX | SHGFI_SMALLICON | SHGFI_USEFILEATTRIBUTES,
            )
        };
        (list != 0 && info.iIcon >= 0).then_some((list as HIMAGELIST, info.iIcon))
    })
}
fn initialize_image_cache() -> Option<()> {
    // SAFETY: Shell32 is already imported by this module; this obtains a borrowed
    // KnownDLL module handle. Microsoft documents FileIconInit at ordinal 660.
    let module = unsafe { GetModuleHandleW(wide("shell32.dll").as_ptr()) };
    if module.is_null() {
        return None;
    }
    // SAFETY: integer ordinal is encoded as required by GetProcAddress.
    let function = unsafe { GetProcAddress(module, 660usize as *const u8) }?;
    // SAFETY: ordinal 660's documented ABI is BOOL WINAPI FileIconInit(BOOL).
    let initialize: unsafe extern "system" fn(i32) -> i32 =
        unsafe { std::mem::transmute(function) };
    // SAFETY: initializes this process's Shell-owned image cache; no owned list or
    // icon handles are allocated, modified directly or destroyed by the caller.
    (unsafe { initialize(0) } != 0).then_some(())
}
/// Borrowed Shell list; attach only with LVS_SHAREIMAGELISTS and never destroy it.
pub fn small_image_list() -> Option<HIMAGELIST> {
    system_images().map(|images| images.0)
}
pub fn stock_index(stock: SHSTOCKICONID) -> Option<i32> {
    static INDICES: [OnceLock<Option<i32>>; SIID_MAX_ICONS as usize] =
        [const { OnceLock::new() }; SIID_MAX_ICONS as usize];
    let cached = INDICES.get(usize::try_from(stock).ok()?)?;
    *cached.get_or_init(|| {
        small_image_list()?;
        let _com = ComScope::new()?;
        let mut info = SHSTOCKICONINFO {
            cbSize: size_of::<SHSTOCKICONINFO>() as u32,
            ..Default::default()
        };
        // SAFETY: validated stock ID and initialized output; returns only a borrowed system index.
        let status =
            unsafe { SHGetStockIconInfo(stock, SHGSI_SYSICONINDEX | SHGSI_SMALLICON, &mut info) };
        (status >= 0 && info.iSysImageIndex >= 0).then_some(info.iSysImageIndex)
    })
}
pub fn application_index() -> i32 {
    static INDEX: OnceLock<i32> = OnceLock::new();
    *INDEX.get_or_init(|| {
        stock_index(SIID_APPLICATION)
            .unwrap_or_else(|| system_images().map(|images| images.1).unwrap_or(-2))
    })
}
pub fn folder_index() -> i32 {
    static INDEX: OnceLock<i32> = OnceLock::new();
    *INDEX.get_or_init(|| stock_index(SIID_FOLDER).unwrap_or_else(application_index))
}
pub fn for_file(path: &str) -> Option<i32> {
    static CACHE: OnceLock<Mutex<Cache<Option<i32>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(Cache::new()));
    let path = local_syntax(path)?;
    let now = Instant::now();
    if let Some(index) = cache
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .get(&path, now)
    {
        return index;
    }
    // Release the cache mutex before native filesystem/Shell calls.
    let index = (|| {
        let path = local_file(&path)?;
        system_images()?;
        let _com = ComScope::new()?;
        let mut info = SHFILEINFOW::default();
        // SAFETY: validated local regular file, initialized output, no ICON flag;
        // result is an index in the borrowed system small image list.
        let list = unsafe {
            SHGetFileInfoW(
                wide(&path).as_ptr(),
                0,
                &mut info,
                size_of::<SHFILEINFOW>() as u32,
                SHGFI_SYSICONINDEX | SHGFI_SMALLICON,
            )
        };
        (list != 0 && info.iIcon >= 0).then_some(info.iIcon)
    })();
    cache
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .insert(path, index, now);
    index
}

pub fn executable_from_command(command: &str) -> Option<String> {
    static CACHE: OnceLock<Mutex<Cache<Option<String>>>> = OnceLock::new();
    if !bounded(command) {
        return None;
    }
    let cache = CACHE.get_or_init(|| Mutex::new(Cache::new()));
    let now = Instant::now();
    if let Some(path) = cache
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .get(command, now)
    {
        return path;
    }
    let resolved = (|| {
        let expanded = expand(command)?;
        for candidate in candidates(&expanded)? {
            if let Some(path) = resolve_candidate(candidate) {
                return Some(path);
            }
        }
        None
    })();
    cache
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .insert(command.into(), resolved.clone(), now);
    resolved
}
/// Known .lnk/ExecAction target: preserve spaces as part of the path rather than
/// guessing an executable boundary from its separately supplied arguments.
pub(crate) fn executable_path(path: &str) -> Option<String> {
    if !bounded(path) {
        return None;
    }
    resolve_candidate(&expand(path)?)
}

/// Explicit Run/Stop validation: no extension inference or executable search.
pub(crate) fn local_program_path(path: &str) -> Option<String> {
    if !bounded(path) {
        return None;
    }
    let path = local_file(path)?;
    let extension = Path::new(&path).extension()?.to_str()?;
    ["exe", "com"]
        .iter()
        .any(|known| extension.eq_ignore_ascii_case(known))
        .then_some(path)
}
fn bounded(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_WIDE * 4
        && !value.contains('\0')
        && value.encode_utf16().count() <= MAX_WIDE
}
fn expand(value: &str) -> Option<String> {
    let input = wide(value);
    // SAFETY: NUL-terminated input; null output and zero capacity query required size.
    let mut needed = unsafe { ExpandEnvironmentStringsW(input.as_ptr(), ptr::null_mut(), 0) };
    for _ in 0..3 {
        if needed == 0 || needed as usize > MAX_WIDE + 1 {
            return None;
        }
        let mut output = vec![0u16; needed as usize];
        // SAFETY: complete writable UTF-16 buffer and exact character capacity.
        let length = unsafe {
            ExpandEnvironmentStringsW(input.as_ptr(), output.as_mut_ptr(), output.len() as u32)
        };
        if length == 0 {
            return None;
        }
        if length <= output.len() as u32 {
            return String::from_utf16(&output[..length as usize - 1]).ok();
        }
        needed = length;
    }
    None
}
pub(crate) fn candidates(command: &str) -> Option<Vec<&str>> {
    if !bounded(command) {
        return None;
    }
    let command = command.trim_start_matches([' ', '\t']);
    if let Some(quoted) = command.strip_prefix('"') {
        let closing = quoted.find('"')?;
        if closing == 0
            || quoted[closing + 1..]
                .chars()
                .next()
                .is_some_and(|character| !matches!(character, ' ' | '\t'))
        {
            return None;
        }
        return Some(vec![&quoted[..closing]]);
    }
    let mut paths = Vec::new();
    for (offset, character) in command.char_indices() {
        if matches!(character, ' ' | '\t')
            && offset > 0
            && !command[..offset].ends_with([' ', '\t'])
        {
            paths.push(&command[..offset]);
            if paths.len() == 32 {
                break;
            }
        }
        if character == '"' {
            break;
        }
    }
    if paths.len() < 32 && !command.contains('"') {
        paths.push(command.trim_end_matches([' ', '\t']));
    }
    (!paths.is_empty()).then_some(paths)
}
fn local_syntax(path: &str) -> Option<String> {
    if !bounded(path) {
        return None;
    }
    let path = path.replace('/', "\\");
    let bytes = path.as_bytes();
    if bytes.len() < 4
        || !bytes[0].is_ascii_alphabetic()
        || bytes[1..3] != *b":\\"
        || path[2..].contains([':', '"', '*', '?', '<', '>', '|', '\r', '\n'])
    {
        return None;
    }
    let mut normalized = PathBuf::new();
    let mut depth = 0usize;
    for component in Path::new(&path).components() {
        match component {
            Component::Prefix(prefix) if matches!(prefix.kind(), Prefix::Disk(_)) => {
                normalized.push(prefix.as_os_str())
            }
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir if depth > 0 => {
                normalized.pop();
                depth -= 1;
            }
            Component::Normal(part) => {
                let part = part.to_str()?;
                if part.ends_with([' ', '.']) {
                    return None;
                }
                normalized.push(part);
                depth += 1;
            }
            _ => return None,
        }
    }
    (depth != 0).then(|| normalized.to_string_lossy().into_owned())
}
fn local_file(path: &str) -> Option<String> {
    let path = local_syntax(path)?;
    let extension = Path::new(&path).extension()?.to_str()?;
    if !["exe", "com", "bat", "cmd", "dll", "ico"]
        .iter()
        .any(|known| extension.eq_ignore_ascii_case(known))
    {
        return None;
    }
    checked_local_path(path, false)
}

pub(crate) fn local_directory_path(path: &str) -> Option<String> {
    if !bounded(path) {
        return None;
    }
    let normalized = path.replace('/', "\\");
    let bytes = normalized.as_bytes();
    let path = if bytes.len() == 3 && bytes[0].is_ascii_alphabetic() && bytes[1..] == *b":\\" {
        normalized
    } else {
        local_syntax(&normalized)?
    };
    checked_local_path(path, true)
}

fn checked_local_path(path: String, directory: bool) -> Option<String> {
    let root = wide(&path[..3]);
    // SAFETY: local drive-root string. Reject mapped/network/removable drives.
    if !matches!(unsafe { GetDriveTypeW(root.as_ptr()) }, 3 | 6) {
        return None;
    }
    let mut current = PathBuf::from(&path[..3]);
    let components: Vec<_> = Path::new(&path).components().skip(2).collect();
    for (index, component) in components.iter().enumerate() {
        current.push(component.as_os_str());
        // SAFETY: NUL-terminated local path; parents are checked before traversing
        // them, excluding reparse/cloud/remote targets from Shell icon reads.
        let attributes = unsafe { GetFileAttributesW(wide(current.to_str()?).as_ptr()) };
        if attributes == INVALID_FILE_ATTRIBUTES || attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return None;
        }
        let is_directory = attributes & FILE_ATTRIBUTE_DIRECTORY != 0;
        if is_directory != (directory || index + 1 < components.len()) {
            return None;
        }
    }
    Some(path)
}
fn resolve_candidate(candidate: &str) -> Option<String> {
    if candidate.is_empty() || candidate.contains(['"', '\r', '\n']) {
        return None;
    }
    let target = if Path::new(candidate).extension().is_none() {
        format!("{candidate}.exe")
    } else {
        candidate.into()
    };
    if let Some(path) = local_file(&target) {
        return Some(path);
    }
    if target.contains(['\\', '/', ':', '%']) {
        return None;
    }
    let mut directories = Vec::new();
    let mut system = vec![0u16; 32768];
    // SAFETY: writable path buffer with exact character capacity.
    let length = unsafe { GetSystemDirectoryW(system.as_mut_ptr(), system.len() as u32) } as usize;
    if length != 0 && length < system.len() {
        directories.push(String::from_utf16(&system[..length]).ok()?);
    }
    if let Ok(root) = std::env::var("SystemRoot") {
        directories.push(root);
    }
    if let Ok(path) = std::env::var("PATH") {
        if bounded(&path) {
            directories.extend(
                path.split(';')
                    .take(64)
                    .map(|part| part.trim_matches('"').to_owned()),
            );
        }
    }
    for directory in directories {
        if local_syntax(&format!("{directory}\\{target}")).is_none() {
            continue;
        }
        if let Some(path) = local_file(&format!("{directory}\\{target}")) {
            return Some(path);
        }
    }
    None
}

struct ActionImage {
    stock: SHSTOCKICONID,
    list: HIMAGELIST,
    icon: HICON,
}
impl Drop for ActionImage {
    fn drop(&mut self) {
        // SAFETY: these are private image-list/icon copies; controls detach before replacement/drop.
        unsafe {
            ImageList_Destroy(self.list);
            DestroyIcon(self.icon);
        }
    }
}

/// Six bounded stock-action copies. Keep the owner alive until attached controls are destroyed.
pub(crate) struct ActionImages {
    images: Vec<ActionImage>,
    dpi: u32,
}
impl ActionImages {
    pub(crate) fn new(dpi: u32) -> Self {
        let mut images = Vec::with_capacity(6);
        let dpi = dpi.max(96);
        let size = (16 * dpi / 96) as i32;
        if let Some(shared) = self::small_image_list() {
            for stock in [
                SIID_DELETE,
                SIID_SETTINGS,
                SIID_FOLDEROPEN,
                SIID_AUTOLIST,
                SIID_FIND,
                SIID_INFO,
            ] {
                let Some(index) = self::stock_index(stock) else {
                    continue;
                };
                // SAFETY: get/copy creates private handles; the system list itself stays borrowed.
                unsafe {
                    let original = ImageList_GetIcon(shared, index, ILD_TRANSPARENT);
                    if original.is_null() {
                        continue;
                    }
                    let icon = CopyImage(original, IMAGE_ICON, size, size, 0) as HICON;
                    DestroyIcon(original);
                    if icon.is_null() {
                        continue;
                    }
                    let list = ImageList_Create(size, size, ILC_COLOR32 | ILC_MASK, 1, 0);
                    if list == 0 || ImageList_ReplaceIcon(list, -1, icon) < 0 {
                        if list != 0 {
                            ImageList_Destroy(list);
                        }
                        DestroyIcon(icon);
                        continue;
                    }
                    images.push(ActionImage { stock, list, icon });
                }
            }
        }
        // An owner is complete or empty, so changing tab actions can never leave
        // a different action's old glyph attached after a partial allocation failure.
        if images.len() != 6 {
            images.clear();
        }
        Self { images, dpi }
    }

    pub(crate) fn has_images(&self) -> bool {
        !self.images.is_empty()
    }

    /// # Safety
    /// `button` is a live native button on this UI thread, outlived by this owner.
    pub(crate) unsafe fn apply_button(&self, button: HWND, stock: SHSTOCKICONID) {
        let Some(image) = self.images.iter().find(|image| image.stock == stock) else {
            return;
        };
        let margin = (5 * self.dpi / 96) as i32;
        let images = BUTTON_IMAGELIST {
            himl: image.list,
            margin: RECT {
                left: margin,
                right: margin,
                top: 0,
                bottom: 0,
            },
            uAlign: BUTTON_IMAGELIST_ALIGN_LEFT,
        };
        // SAFETY: the control copies the struct and borrows this owner's live image list.
        unsafe {
            SendMessageW(
                button,
                BCM_SETIMAGELIST,
                0,
                (&images as *const BUTTON_IMAGELIST) as isize,
            );
        }
    }

    /// # Safety
    /// `label` is a live SS_ICON static on this UI thread, outlived by this owner.
    pub(crate) unsafe fn apply_label(&self, label: HWND, stock: SHSTOCKICONID) {
        let Some(image) = self.images.iter().find(|image| image.stock == stock) else {
            return;
        };
        // SAFETY: the static borrows the private icon until it is replaced or destroyed.
        unsafe {
            SendMessageW(label, STM_SETICON, image.icon as usize, 0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    #[test]
    fn command_parser_preserves_quoted_targets_and_tests_unquoted_boundaries_in_order() {
        assert_eq!(
            candidates(r#""C:\Program Files\App\app.exe" --quiet"#).unwrap(),
            [r"C:\Program Files\App\app.exe"]
        );
        let paths = candidates(r"C:\Program Files\App\app.exe --quiet").unwrap();
        assert_eq!(paths[0], r"C:\Program");
        assert!(paths.contains(&r"C:\Program Files\App\app.exe"));
        assert!(candidates(r#""C:\app.exe"tail"#).is_none());
        assert!(candidates("\"C:\\unterminated.exe").is_none());
        assert!(candidates(&"a".repeat(32768)).is_none());
        assert!(candidates("bad\0.exe").is_none());
    }
    #[test]
    fn path_syntax_rejects_network_devices_urls_and_ambiguous_names() {
        assert_eq!(
            local_syntax(r"C:/Apps/sub/../app.exe"),
            Some(r"C:\Apps\app.exe".into())
        );
        for value in [
            r"\\server\share\app.exe",
            r"\\?\C:\app.exe",
            r"\\.\pipe\thing",
            "https://example.com/app.exe",
            r"C:app.exe",
            r"\SystemRoot\app.exe",
            r"C:\app.exe:stream",
            r"C:\dir.\app.exe",
        ] {
            assert!(local_syntax(value).is_none(), "{value}");
        }
    }
    #[test]
    fn cache_expires_negative_entries_and_never_exceeds_its_bound() {
        let now = Instant::now();
        let mut cache = Cache::<Option<i32>>::new();
        cache.insert("negative".into(), None, now);
        assert_eq!(cache.get("negative", now), Some(None));
        assert_eq!(cache.get("negative", now + Duration::from_secs(601)), None);
        for index in 0..MAX_CACHE + 10 {
            cache.insert(
                index.to_string(),
                Some(index as i32),
                now + Duration::from_millis(index as u64),
            );
        }
        assert!(cache.entries.len() <= MAX_CACHE);
        assert_eq!(
            cache.get(&(MAX_CACHE + 9).to_string(), now + Duration::from_secs(1)),
            Some(Some((MAX_CACHE + 9) as i32))
        );
    }
    #[test]
    fn resolves_own_executable_env_expansion_and_real_system_image_indices() {
        let own = std::env::current_exe().unwrap();
        let own = own.to_str().unwrap();
        assert_eq!(
            executable_from_command(&format!("\"{own}\" --argument")),
            Some(own.into())
        );
        let expanded =
            executable_from_command(r"%SystemRoot%\System32\cmd.exe /c echo ignored").unwrap();
        assert!(
            expanded
                .to_ascii_lowercase()
                .ends_with(r"\system32\cmd.exe")
        );
        assert!(for_file(own).is_some_and(|index| index >= 0));
        assert!(small_image_list().is_some_and(|list| list != 0));
        assert!(application_index() >= 0);
        assert!(folder_index() >= 0);
        assert!(executable_from_command(r"\\untrusted.invalid\share\app.exe --flag").is_none());
        assert!(for_file("https://untrusted.invalid/app.exe").is_none());
    }
}
