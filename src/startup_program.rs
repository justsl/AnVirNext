//! Explicit startup program actions. Never invoked by inventory or polling.

use super::{
    ProcessSampler, arguments_tail, command_line, executable_path, last_error, mutation_handle,
    open_process, terminate_handle, verify_identity,
};
use crate::win::{Handle, wide};
use std::{borrow::Cow, mem::size_of, path::Path, ptr};
use windows::{
    Win32::{
        Foundation::{E_ACCESSDENIED, RPC_E_CHANGED_MODE},
        System::{
            Com::{
                CLSCTX_LOCAL_SERVER, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx,
                CoUninitialize, IDispatch, IServiceProvider,
            },
            Variant::VARIANT,
        },
        UI::Shell::{
            CSIDL_DESKTOP, IShellBrowser, IShellDispatch2, IShellFolderViewDual, IShellWindows,
            SID_STopLevelBrowser, SVGIO_BACKGROUND, SWC_DESKTOP, SWFO_NEEDDISPATCH, ShellWindows,
        },
    },
    core::{BSTR, Interface},
};
use windows_sys::Win32::{
    Foundation::HANDLE,
    Globalization::{CSTR_EQUAL, CompareStringOrdinal},
    Security::{
        DuplicateTokenEx, GetTokenInformation, SecurityImpersonation, TOKEN_DUPLICATE,
        TOKEN_IMPERSONATE, TOKEN_INFORMATION_CLASS, TOKEN_QUERY, TokenElevation, TokenPrimary,
        TokenSessionId,
    },
    System::{
        Environment::ExpandEnvironmentStringsForUserW, RemoteDesktop::ProcessIdToSessionId,
        Threading::*,
    },
    UI::WindowsAndMessaging::{GetShellWindow, GetWindowThreadProcessId, SW_SHOWNORMAL},
};

struct Program<'a> {
    executable: String,
    arguments: &'a str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartupRuntimeOutcome {
    Applied,
    AlreadyRunning,
}

fn program<'a>(command: &'a str, executable: &str) -> Result<Program<'a>, String> {
    let (token, arguments) = command_parts(command)?;
    let expected = crate::icons::local_program_path(executable)
        .ok_or("Only an exact existing local .exe or .com can be controlled")?;
    let (actual, arguments) = if let Some(actual) = crate::icons::local_program_path(&token) {
        (actual, arguments)
    } else {
        // Registry Run values commonly store absolute paths with spaces and
        // no quotes. Use the same boundaries as inventory without inferring
        // extensions or searching PATH. Explorer receives an explicit path.
        let error = "Не удалось определить полный путь к программе в команде автозагрузки";
        if command[..command.len() - arguments.len()].contains('"') {
            return Err(error.into());
        }
        crate::icons::candidates(command)
            .and_then(|candidates| {
                candidates.into_iter().find_map(|prefix| {
                    let actual = crate::icons::local_program_path(prefix)?;
                    let tail = command[prefix.len()..].trim_start_matches([' ', '\t']);
                    Some((actual, tail))
                })
            })
            .ok_or(error)?
    };
    if !same_path(&expected, &actual) {
        return Err("Startup command no longer matches its executable".into());
    }
    Ok(Program {
        executable: expected,
        arguments,
    })
}

pub fn start_startup_program(
    command: &str,
    executable: &str,
    expand_environment: bool,
    working_directory: Option<&str>,
) -> Result<StartupRuntimeOutcome, String> {
    let (token, shell_pid) = desktop_token()?;
    let command = command_for_user(command, expand_environment.then_some(token.raw()))?;
    let program = program(&command, executable)?;
    let session = session_id(std::process::id())?;
    if matching_running_processes(&program, session).is_ok_and(|processes| !processes.is_empty()) {
        return Ok(StartupRuntimeOutcome::AlreadyRunning);
    }
    let directory = startup_directory(working_directory, token.raw())?;
    start_program(&program, shell_pid, directory.as_deref())?;
    Ok(StartupRuntimeOutcome::Applied)
}

pub fn stop_startup_program(
    command: &str,
    executable: &str,
    expand_environment: bool,
) -> Result<(), String> {
    let token = if expand_environment {
        Some(desktop_token()?.0)
    } else {
        None
    };
    let command = command_for_user(command, token.as_ref().map(Handle::raw))?;
    let program = program(&command, executable)?;
    let session = session_id(std::process::id())?;
    let mut stopped = 0;
    let mut failure = None;
    for (pid, created) in matching_running_processes(&program, session)? {
        let result = (|| {
            // Reopen with mutation rights and repeat every match on this same
            // guard-validated handle. No new PID/creation can inherit the action.
            let handle = mutation_handle(pid, created, PROCESS_TERMINATE)?;
            let path = executable_path(handle.raw())?;
            let command = command_line(handle.raw())?;
            if session_id(pid)? != session
                || !matches_command(&program.executable, program.arguments, &path, &command)
            {
                return Err("Startup process changed; no termination performed".into());
            }
            terminate_handle(handle.raw())
        })();
        match result {
            Ok(()) => stopped += 1,
            Err(error) => {
                if failure.is_none() {
                    failure = Some(error);
                }
            }
        }
    }
    if let Some(error) = failure {
        return Err(format!("Stopped {stopped} matching instance(s); {error}"));
    }
    if stopped == 0 {
        return Err("Запущенный процесс с таким путём и аргументами не найден".into());
    }
    Ok(())
}

fn matching_running_processes(
    program: &Program<'_>,
    session: u32,
) -> Result<Vec<(u32, u64)>, String> {
    let basename = Path::new(&program.executable)
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("Invalid startup executable name")?;
    let mut sampler = ProcessSampler::default();
    let names = sampler.sample_names()?;
    let mut matches = Vec::new();
    for ((pid, created), name) in names {
        if pid <= 4 || pid == std::process::id() || !same_path(basename, &name) {
            continue;
        }
        if session_id(pid).ok() != Some(session) {
            continue;
        }
        let Ok(handle) = open_process(pid, PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE)
        else {
            continue;
        };
        if verify_identity(handle.raw(), pid, created).is_err() {
            continue;
        }
        let (Ok(path), Ok(command)) = (executable_path(handle.raw()), command_line(handle.raw()))
        else {
            continue;
        };
        if matches_command(&program.executable, program.arguments, &path, &command) {
            // SAFETY: the checked handle has synchronization rights. A zero
            // timeout tests liveness without waiting for the process to exit.
            if unsafe { WaitForSingleObject(handle.raw(), 0) }
                == windows_sys::Win32::Foundation::WAIT_TIMEOUT
            {
                matches.push((pid, created));
            }
        }
    }
    Ok(matches)
}

fn command_for_user(command: &str, token: Option<HANDLE>) -> Result<Cow<'_, str>, String> {
    if command.is_empty()
        || command.len() > 131068
        || command.contains('\0')
        || command.encode_utf16().count() > 32767
    {
        return Err("Startup text is empty, oversized or malformed".into());
    }
    let Some(token) = token else {
        return Ok(Cow::Borrowed(command));
    };
    if token.is_null() {
        return Err("Verified desktop user token is required for environment expansion".into());
    }
    let source = wide(command);
    let mut expanded = vec![0u16; 32768];
    // SAFETY: verified user token, NUL-terminated source and exact writable
    // capacity. The per-user API fails on insufficient capacity; no fallback.
    if unsafe {
        ExpandEnvironmentStringsForUserW(
            token,
            source.as_ptr(),
            expanded.as_mut_ptr(),
            expanded.len() as u32,
        )
    } == 0
    {
        return Err(last_error("Expand startup text for desktop user"));
    }
    let end = expanded
        .iter()
        .position(|unit| *unit == 0)
        .ok_or("Expanded startup text exceeds 32767 UTF-16 units")?;
    String::from_utf16(&expanded[..end])
        .map(Cow::Owned)
        .map_err(|_| "Expanded startup text contains invalid UTF-16".into())
}

fn startup_directory(directory: Option<&str>, token: HANDLE) -> Result<Option<String>, String> {
    let Some(directory) = directory else {
        return Ok(None);
    };
    let expanded = command_for_user(directory, Some(token))?;
    crate::icons::local_directory_path(&expanded)
        .map(Some)
        .ok_or_else(|| {
            "Startup working directory is not an existing absolute local directory".into()
        })
}

fn command_parts(command: &str) -> Result<(String, &str), String> {
    if command.is_empty()
        || command.len() > 131068
        || command.encode_utf16().count() > 32767
        || command.contains(['\0', '\r', '\n'])
        || command.starts_with([' ', '\t'])
    {
        return Err("Startup command is empty, oversized or malformed".into());
    }
    let (mut quoted, mut end) = (false, command.len());
    for (index, byte) in command.bytes().enumerate() {
        if byte == b'"' {
            quoted = !quoted;
        } else if !quoted && matches!(byte, b' ' | b'\t') {
            end = index;
            break;
        }
    }
    if quoted {
        return Err("Startup executable has an unclosed quote".into());
    }
    let executable = command[..end].replace('"', "");
    if executable.is_empty() {
        return Err("Startup executable is empty".into());
    }
    let arguments = command[end..].trim_start_matches([' ', '\t']);
    let (mut quoted, mut slashes) = (false, 0usize);
    let mut bytes = arguments.bytes().peekable();
    while let Some(byte) = bytes.next() {
        if byte == b'\\' {
            slashes += 1;
            continue;
        }
        if byte == b'"' && slashes % 2 == 0 {
            if quoted && bytes.peek() == Some(&b'"') {
                bytes.next();
            } else {
                quoted = !quoted;
            }
        }
        slashes = 0;
    }
    if quoted {
        return Err("Startup arguments have an unclosed quote".into());
    }
    Ok((executable, arguments))
}

fn same_path(left: &str, right: &str) -> bool {
    if left.len() > 131068 || right.len() > 131068 {
        return false;
    }
    let left: Vec<_> = left.encode_utf16().collect();
    let right: Vec<_> = right.encode_utf16().collect();
    // SAFETY: valid bounded UTF-16 slices and explicit character lengths.
    unsafe {
        CompareStringOrdinal(
            left.as_ptr(),
            left.len() as i32,
            right.as_ptr(),
            right.len() as i32,
            1,
        ) == CSTR_EQUAL
    }
}
fn matches_command(
    executable: &str,
    arguments: &str,
    actual_path: &str,
    actual_command: &str,
) -> bool {
    same_path(executable, actual_path) && arguments_tail(actual_command) == arguments
}
fn validate_shell_token(
    expected_session: u32,
    actual_session: u32,
    elevated: bool,
) -> Result<(), String> {
    if actual_session != expected_session {
        return Err("Desktop shell belongs to another session".into());
    }
    if elevated {
        return Err("Desktop shell is elevated; unsafe startup launch refused".into());
    }
    Ok(())
}
fn session_id(pid: u32) -> Result<u32, String> {
    let mut session = 0;
    // SAFETY: writable session ID for the supplied numeric process ID.
    if unsafe { ProcessIdToSessionId(pid, &mut session) } == 0 {
        return Err(last_error("Read process session"));
    }
    Ok(session)
}
fn process_token(handle: HANDLE, access: u32) -> Result<Handle, String> {
    let mut token = ptr::null_mut();
    // SAFETY: valid process handle and writable token handle output.
    if unsafe { OpenProcessToken(handle, access, &mut token) } == 0 {
        return Err(last_error("Read process token"));
    }
    Handle::new(token).map_err(|error| error.to_string())
}
fn token_value(token: HANDLE, kind: TOKEN_INFORMATION_CLASS) -> Result<u32, String> {
    let (mut value, mut length) = (0u32, 0u32);
    // SAFETY: only DWORD-sized TokenSessionId/TokenElevation classes are used;
    // Windows validates the exact writable output size and returns its length.
    if unsafe {
        GetTokenInformation(
            token,
            kind,
            (&mut value as *mut u32).cast(),
            size_of::<u32>() as u32,
            &mut length,
        )
    } == 0
        || length != size_of::<u32>() as u32
    {
        return Err(last_error("Read desktop token security state"));
    }
    Ok(value)
}
fn desktop_token() -> Result<(Handle, u32), String> {
    // SAFETY: queries current desktop Shell window without changing desktop state.
    let window = unsafe { GetShellWindow() };
    if window.is_null() {
        return Err("No unelevated desktop shell is available".into());
    }
    let mut pid = 0;
    // SAFETY: window is an observed HWND and pid is writable.
    if unsafe { GetWindowThreadProcessId(window, &mut pid) } == 0 || pid == 0 {
        return Err(last_error("Read desktop shell identity"));
    }
    let session = session_id(std::process::id())?;
    if session_id(pid)? != session {
        return Err("Desktop shell belongs to another session".into());
    }
    let process = open_process(pid, PROCESS_QUERY_LIMITED_INFORMATION)?;
    let token = process_token(process.raw(), TOKEN_QUERY | TOKEN_DUPLICATE)?;
    validate_shell_token(
        session,
        token_value(token.raw(), TokenSessionId)?,
        token_value(token.raw(), TokenElevation)? != 0,
    )?;
    let mut duplicated = ptr::null_mut();
    // SAFETY: queried non-elevated Shell token, explicit minimal rights, a primary
    // duplicate and writable output. No privilege or token-session changes occur.
    if unsafe {
        DuplicateTokenEx(
            token.raw(),
            TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE,
            ptr::null(),
            SecurityImpersonation,
            TokenPrimary,
            &mut duplicated,
        )
    } == 0
    {
        return Err(last_error("Duplicate desktop shell token"));
    }
    let duplicated = Handle::new(duplicated).map_err(|error| error.to_string())?;
    validate_shell_token(
        session,
        token_value(duplicated.raw(), TokenSessionId)?,
        token_value(duplicated.raw(), TokenElevation)? != 0,
    )?;
    let mut current_pid = 0;
    // SAFETY: read-only recheck of the current desktop Shell window.
    let current_window = unsafe { GetShellWindow() };
    // SAFETY: observed window handle and a writable PID output.
    let current_thread = unsafe { GetWindowThreadProcessId(window, &mut current_pid) };
    if current_window != window || current_thread == 0 || current_pid != pid {
        return Err("Desktop shell changed; retry the explicit start action".into());
    }
    Ok((duplicated, pid))
}

fn start_program(
    program: &Program<'_>,
    shell_pid: u32,
    working_directory: Option<&str>,
) -> Result<(), String> {
    let directory = working_directory
        .or_else(|| {
            Path::new(&program.executable)
                .parent()
                .and_then(|path| path.to_str())
        })
        .ok_or("Invalid startup working directory")?;
    // SAFETY: initialize this action thread for COM and balance it once all
    // desktop interfaces have been released. COM proxies own their references.
    unsafe {
        let com = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
        if com.is_err() && com != RPC_E_CHANGED_MODE {
            return Err(format!("Не удалось подключиться к Проводнику: {com:?}"));
        }
        // Use the existing desktop's application object. Creating Shell.Application
        // in-process would execute with the monitor's elevated token.
        let result = (|| -> windows::core::Result<()> {
            let windows: IShellWindows =
                CoCreateInstance(&ShellWindows, None, CLSCTX_LOCAL_SERVER)?;
            let mut hwnd = 0;
            let desktop = windows.FindWindowSW(
                &VARIANT::from(CSIDL_DESKTOP as i32),
                &VARIANT::default(),
                SWC_DESKTOP,
                &mut hwnd,
                SWFO_NEEDDISPATCH,
            )?;
            let mut pid = 0;
            if hwnd == 0
                || GetWindowThreadProcessId(hwnd as u32 as usize as _, &mut pid) == 0
                || pid != shell_pid
            {
                return Err(windows::core::Error::new(
                    E_ACCESSDENIED,
                    "Проводник рабочего стола изменился",
                ));
            }
            let browser: IShellBrowser = desktop
                .cast::<IServiceProvider>()?
                .QueryService(&SID_STopLevelBrowser)?;
            let view: IShellFolderViewDual = browser
                .QueryActiveShellView()?
                .GetItemObject::<IDispatch>(SVGIO_BACKGROUND)?
                .cast()?;
            let shell: IShellDispatch2 = view.Application()?.cast()?;
            shell.ShellExecute(
                &BSTR::from(program.executable.as_str()),
                &VARIANT::from(BSTR::from(program.arguments)),
                &VARIANT::from(BSTR::from(directory)),
                &VARIANT::from(BSTR::from("open")),
                &VARIANT::from(SW_SHOWNORMAL),
            )
        })();
        if com.is_ok() {
            CoUninitialize();
        }
        result.map_err(|error| format!("Не удалось запустить через Проводник: {error}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expandable_values_use_the_desktop_user_environment_but_reg_sz_stays_raw() {
        let (token, _) = desktop_token().unwrap();
        let raw = r#""%SystemRoot%\System32\cmd.exe" --file="%USERPROFILE%\two  words""#;
        let preserved = command_for_user(raw, None).unwrap();
        assert!(matches!(preserved, Cow::Borrowed(_)));
        assert_eq!(preserved, raw);
        let expanded = command_for_user(raw, Some(token.raw())).unwrap();
        assert!(!expanded.contains("%SystemRoot%"));
        assert!(!expanded.contains("%USERPROFILE%"));
        assert!(expanded.contains(r#"\two  words""#));
        let (path, arguments) = command_parts(&expanded).unwrap();
        let program = program(&expanded, &path).unwrap();
        assert!(matches_command(
            &program.executable,
            program.arguments,
            &path,
            &expanded
        ));
        assert!(arguments.starts_with("--file=\""));
        assert!(command_for_user(raw, Some(ptr::null_mut())).is_err());
        assert!(command_for_user(&"x".repeat(32768), Some(token.raw())).is_err());
    }

    #[test]
    fn shortcut_start_in_directory_is_expanded_validated_and_not_silently_discarded() {
        let (token, _) = desktop_token().unwrap();
        assert!(startup_directory(None, token.raw()).unwrap().is_none());
        let directory = startup_directory(Some(r"%SystemRoot%\System32"), token.raw())
            .unwrap()
            .unwrap();
        assert!(
            directory
                .to_ascii_lowercase()
                .ends_with(r"\windows\system32")
        );
        for path in [
            "",
            r"relative\directory",
            r"\\untrusted.invalid\share",
            r"C:\missing-anvir-fixture-directory-0000",
            r"%SystemRoot%\System32\cmd.exe",
        ] {
            assert!(
                startup_directory(Some(path), token.raw()).is_err(),
                "{path}"
            );
        }
        let root = startup_directory(Some(r"%SystemDrive%\"), token.raw())
            .unwrap()
            .unwrap();
        assert_eq!(root.len(), 3);
    }
    #[test]
    fn parses_program_quoting_without_rebuilding_the_raw_argument_tail() {
        for (command, path, arguments) in [
            (
                r#""C:\Program Files\app.exe"  --flag="two  words"  "" "#,
                r"C:\Program Files\app.exe",
                r#"--flag="two  words"  "" "#,
            ),
            (
                r#"C:\"Program Files"\app.exe --имя="日本 語""#,
                r"C:\Program Files\app.exe",
                r#"--имя="日本 語""#,
            ),
            ("C:\\app.com\t\t--x", r"C:\app.com", "--x"),
            (r"C:\app.exe", r"C:\app.exe", ""),
        ] {
            assert_eq!(command_parts(command).unwrap(), (path.into(), arguments));
        }
        for command in [
            "",
            " app.exe --x",
            r#""C:\unclosed.exe --x"#,
            r#"C:\app.exe "unclosed"#,
            "C:\\app.exe\0bad",
            "C:\\app.exe\r\n--bad",
        ] {
            assert!(command_parts(command).is_err(), "{command:?}");
        }
    }
    #[test]
    fn stop_matching_uses_exact_executable_and_raw_arguments() {
        assert!(matches_command(
            r"C:\Apps\host.exe",
            "--task=one",
            r"c:\APPS\HOST.EXE",
            r#""c:\Apps\host.exe" --task=one"#
        ));
        assert!(!matches_command(
            r"C:\Apps\host.exe",
            "--task=one",
            r"C:\Other\host.exe",
            r"host.exe --task=one"
        ));
        assert!(!matches_command(
            r"C:\Apps\host.exe",
            "--task=one",
            r"C:\Apps\host.exe",
            r"host.exe --task=one-more"
        ));
        assert!(!matches_command(
            r"C:\Apps\host.exe",
            r#"--task="one""#,
            r"C:\Apps\host.exe",
            r"host.exe --task=one"
        ));
        assert!(!matches_command(
            r"C:\Apps\host.exe",
            "--task=one",
            r"C:\Apps\host.exe",
            r"host.exe --task=two"
        ));
    }
    #[test]
    fn elevated_or_other_session_shell_tokens_are_rejected() {
        assert!(validate_shell_token(2, 2, false).is_ok());
        assert!(validate_shell_token(2, 3, false).is_err());
        assert!(validate_shell_token(2, 2, true).is_err());
    }

    #[test]
    fn desktop_primary_token_is_read_only_unelevated_and_in_our_session() {
        let (token, _) = desktop_token().unwrap();
        assert_eq!(token_value(token.raw(), TokenElevation).unwrap(), 0);
        assert_eq!(
            token_value(token.raw(), TokenSessionId).unwrap(),
            session_id(std::process::id()).unwrap()
        );
    }

    #[test]
    fn program_actions_reject_ambiguous_or_unsupported_targets_before_launch() {
        let executable = std::env::current_exe().unwrap();
        let executable = executable.to_str().unwrap();
        let command = format!("\"{executable}\" --safe=\"quoted value\"");
        let parsed = program(&command, executable).unwrap();
        assert_eq!(parsed.arguments, "--safe=\"quoted value\"");
        assert!(program("app.exe --flag", executable).is_err());
        assert!(program(r"C:\Program Files\app.exe --flag", executable).is_err());
        assert!(program("https://untrusted.invalid/app.exe", executable).is_err());
        assert!(program(r"\\untrusted.invalid\share\app.exe", executable).is_err());
        assert!(program(&command, "script.cmd").is_err());
        assert!(command_parts(&"x".repeat(32768)).is_err());
    }

    #[test]
    fn run_entries_accept_an_unquoted_absolute_path_with_spaces() {
        let directory =
            std::env::temp_dir().join(format!("AnVir startup space test {}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        let executable = directory.join("Sample App.exe");
        let shorter_executable = directory.join("Sample.exe");
        std::fs::write(&executable, []).unwrap();
        std::fs::write(&shorter_executable, []).unwrap();
        let path = executable.to_str().unwrap();
        let command = format!("{path}\t --name=\"two  words\" ");
        let bare = program(path, path);
        let with_arguments = program(&command, path);
        let mismatched = program(&command, shorter_executable.to_str().unwrap());
        let _ = std::fs::remove_file(&executable);
        let _ = std::fs::remove_file(&shorter_executable);
        let _ = std::fs::remove_dir(&directory);
        assert_eq!(bare.unwrap().arguments, "");
        let parsed = with_arguments.unwrap();
        assert_eq!(parsed.executable, path);
        assert_eq!(parsed.arguments, "--name=\"two  words\" ");
        assert!(mismatched.is_err());
    }

    #[test]
    fn stopping_exact_fixture_leaves_another_command_of_the_same_executable_alive() {
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        fn child(marker: &str) -> Child {
            Child(
                std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--ignored",
                        "--exact",
                        "processes::tests::controlled_child",
                        marker,
                    ])
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn()
                    .unwrap(),
            )
        }
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let mut target = child(&format!("startup-target-{suffix}"));
        let mut sibling = child(&format!("startup-sibling-{suffix}"));
        let handle = open_process(target.0.id(), PROCESS_QUERY_LIMITED_INFORMATION).unwrap();
        let created = super::super::process_times(handle.raw()).unwrap().created;
        let details = super::super::details(target.0.id(), created).unwrap();
        assert!(super::super::validate_process_stop(target.0.id()).is_ok());
        assert!(super::super::validate_process_stop(std::process::id()).is_err());
        assert!(
            stop_startup_program(
                &format!("{} --different", details.command_line),
                &details.path,
                false
            )
            .is_err()
        );
        assert!(target.0.try_wait().unwrap().is_none());
        assert!(sibling.0.try_wait().unwrap().is_none());
        stop_startup_program(&details.command_line, &details.path, false).unwrap();
        assert!(target.0.wait().unwrap().code().is_some());
        assert!(sibling.0.try_wait().unwrap().is_none());
    }

    #[test]
    #[ignore = "Explicit elevated smoke: compiles and starts only a temporary windowless GUI fixture"]
    fn native_unelevated_start_stop_fixture() {
        use std::{
            fs,
            os::windows::process::CommandExt,
            path::PathBuf,
            time::{Duration, Instant},
        };
        struct Fixture {
            directory: PathBuf,
            commands: Vec<(String, String)>,
        }
        impl Drop for Fixture {
            fn drop(&mut self) {
                for (command, executable) in &self.commands {
                    let _ = stop_startup_program(command, executable, false);
                }
                let safe_directory = std::env::temp_dir()
                    .canonicalize()
                    .ok()
                    .zip(self.directory.canonicalize().ok())
                    .is_some_and(|(root, resolved)| {
                        resolved.parent() == Some(root.as_path())
                            && resolved.file_name() == self.directory.file_name()
                    });
                if safe_directory {
                    for _ in 0..20 {
                        if fs::remove_dir_all(&self.directory).is_ok() {
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(50));
                    }
                }
            }
        }
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "AnVir startup smoke {}-{stamp}",
            std::process::id()
        ));
        fs::create_dir(&directory).unwrap();
        let mut fixture = Fixture {
            directory,
            commands: Vec::new(),
        };
        let source = fixture.directory.join("fixture.rs");
        let executable = fixture
            .directory
            .join(format!("startup-fixture-{stamp}.exe"));
        let working = fixture.directory.join("Start In directory");
        fs::create_dir(&working).unwrap();
        fs::write(&source, r##"
#![windows_subsystem = "windows"]
use std::{ffi::c_void, ptr};
#[link(name="kernel32")] unsafe extern "system" { fn GetCurrentProcess()->*mut c_void; fn CloseHandle(handle:*mut c_void)->i32; }
#[link(name="advapi32")] unsafe extern "system" { fn OpenProcessToken(process:*mut c_void, access:u32, token:*mut *mut c_void)->i32; fn GetTokenInformation(token:*mut c_void, class:i32, value:*mut c_void, size:u32, needed:*mut u32)->i32; }
fn main() {
    let mut token = ptr::null_mut(); let mut elevated = 99u32; let mut needed = 0;
    unsafe { assert_ne!(OpenProcessToken(GetCurrentProcess(), 8, &mut token), 0); assert_ne!(GetTokenInformation(token,20,(&mut elevated as *mut u32).cast(),4,&mut needed),0); CloseHandle(token); }
    let arguments:Vec<_> = std::env::args().collect();
    let result = format!("elevated={elevated}\ncwd={}\narg={}\nprofile={}\n", std::env::current_dir().unwrap().display(), arguments[3], std::env::var("USERPROFILE").unwrap());
    assert_eq!(arguments[2], "two  words"); std::fs::write(&arguments[1], result).unwrap();
    std::thread::sleep(std::time::Duration::from_secs(30));
}
"##).unwrap();
        let rustc = std::env::var_os("RUSTC")
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("USERPROFILE")
                    .map(|profile| PathBuf::from(profile).join(".cargo/bin/rustc.exe"))
            })
            .unwrap_or_else(|| "rustc".into());
        let compiled = std::process::Command::new(rustc)
            .args([
                "--edition=2024",
                "--crate-name",
                "anvir_startup_gui_fixture",
                "-C",
                "panic=abort",
            ])
            .arg(&source)
            .arg("-o")
            .arg(&executable)
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .unwrap();
        assert!(
            compiled.status.success(),
            "{}",
            String::from_utf8_lossy(&compiled.stderr)
        );
        let executable = executable.to_str().unwrap().to_owned();
        for expand in [false, true] {
            let marker = fixture.directory.join(format!("result-{expand}.txt"));
            let command = format!(
                "{executable} \"{}\" \"two  words\" \"%USERPROFILE%\"",
                marker.display()
            );
            let (token, _) = desktop_token().unwrap();
            let expanded = command_for_user(&command, expand.then_some(token.raw()))
                .unwrap()
                .into_owned();
            fixture
                .commands
                .push((expanded.clone(), executable.clone()));
            assert_eq!(
                start_startup_program(&command, &executable, expand, working.to_str()).unwrap(),
                StartupRuntimeOutcome::Applied
            );
            let deadline = Instant::now() + Duration::from_secs(10);
            while !marker.is_file() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(25));
            }
            let observed = fs::read_to_string(&marker).unwrap();
            assert!(observed.contains("elevated=0\n"), "{observed}");
            assert!(
                observed.contains(&format!("cwd={}\n", working.display())),
                "{observed}"
            );
            let profile = observed
                .lines()
                .find_map(|line| line.strip_prefix("profile="))
                .unwrap();
            let argument = observed
                .lines()
                .find_map(|line| line.strip_prefix("arg="))
                .unwrap();
            assert_eq!(argument, if expand { profile } else { "%USERPROFILE%" });
            assert_eq!(
                start_startup_program(&command, &executable, expand, working.to_str()).unwrap(),
                StartupRuntimeOutcome::AlreadyRunning
            );
            stop_startup_program(&command, &executable, expand).unwrap();
        }
    }
}
