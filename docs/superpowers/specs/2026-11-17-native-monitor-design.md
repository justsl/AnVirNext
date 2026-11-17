# Native monitor first version

## Intent

Build a useful, low-overhead Windows 11 x64 replacement for the daily monitoring portion of AnVir. Use Rust for tray, UI and operating-system metrics and the latest stable LibreHardwareMonitor for device sensors.

The user authorized beginning in the supplied empty directory after delegating inspection of the installed application. The concrete first-version scope below is the implementer's proposal carried into execution under that authorization.

## Approaches

1. Rust/Win32 plus a small .NET sensor companion: selected as the implementation approach. It keeps the notification UI native and reuses the upstream managed library without running its complete GUI.
2. Rust/Tauri plus the same sensor dependency: easier web UI work, but adds a WebView to a persistent utility.
3. Bun: executable packaging is available, but low-level integration still needs native components.

## Behavior

The user's subsequent screenshot-backed requirements expand the first version: native x64 process counters, product/company/path columns, full selected-process command line and arguments, guarded priority/affinity changes and saved rules for future executable launches, autostart inventory/toggling/change monitoring, and numeric tray indicators close to the reference. The Security Risk column is explicitly excluded.

- CPU temperature, CPU activity, memory percentage, disk and network notification icons on by default. A context menu opens the window, changes icon visibility, toggles startup only on user action, or exits.
- Native window with real current activity, bounded recent history, process list, autostart, hardware sensors and saved rules. All measurements indicate unavailable data explicitly.
- System metrics refresh once per second by default; detailed processes every two seconds for a visible, non-minimized Processes tab or saved-rule enforcement; hardware sensors every two seconds in a separate process.
- Process actions identify the original process, reject PID reuse and critical processes, and confirm termination. Details query native command-line information without a cross-bitness PEB read. Saved rules match full Windows ordinal case-insensitive executable paths; new-process polling runs every two seconds. Saving or editing a rule affects the selected process explicitly and processes created after that rule's activation, preserving already-running siblings.
- Autostart inventory covers user/machine Run/RunOnce and WOW64, Startup folders, startup/logon scheduled tasks and automatic services. RunOnce/services/unknown approval states are read-only. Native background notifications cover Run/Startup/StartupApproved; expensive task/service enumeration is lazy/manual. Preserve unknown state and access warnings.
- Settings persist in the current user's local application-data directory with bounded reads and atomic replacement. No settings are imported or changed in AnVir.
- The sensor companion uses redirected local pipes, not an HTTP listener. It never installs drivers or requests elevation automatically. Missing PawnIO or access produces a visible partial-data status.
- The Rust parent owns the companion lifetime. A failed, blocked or stalled companion cannot block tray updates or cause unbounded messages/memory growth.
- Taskbar recreation restores icons. Window and icons support DPI changes. Closing the UI keeps monitoring; explicit Exit ends it and the companion.

## Distribution and safety

Portable x64 release. Official LibreHardwareMonitor v0.9.6 zip, SHA-256 checked against the GitHub release asset digest. Ship upstream license and notices. Bundled managed dependencies must load beside the companion. Do not disable antivirus, change real startup entries or terminate existing user processes during development checks. Any manual driver setup uses the signed official bundled installer and the user's Windows elevation interaction; the application itself never installs a driver.

## Validation

Unit tests for time/counter math, reset and PID-reuse behavior, history bounds, settings recovery and sensor protocol bounds. Run formatting, clippy, tests and a release build. Smoke-test real metric acquisition and the companion, then inspect the native UI and tray behavior. Report actual environmental limitations rather than claiming complete hardware coverage.
