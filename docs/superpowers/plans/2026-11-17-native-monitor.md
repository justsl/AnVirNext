# Native Monitor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a working native Windows tray monitor, process window and LibreHardwareMonitor sensor integration.

**Architecture:** Rust owns the Win32 UI, notification icons and system metrics. A small .NET Framework companion calls the upstream LibreHardwareMonitor library and sends bounded JSON frames through a redirected pipe. No web server, automatic driver installation or global hooks.

**Tech Stack:** Rust, windows-sys, serde/serde_json; .NET Framework 4.7.2 and LibreHardwareMonitor 0.9.6.

**Spec:** `docs/superpowers/specs/2026-11-17-native-monitor-design.md`

## Global Constraints

- Windows 11 x64 first; work in the user-supplied directory.
- CPU temperature/activity, memory, disk and network icons follow the later screenshot-backed request.
- Current metrics every second; processes every two seconds for a visible, non-minimized Processes tab or saved-rule enforcement; sensors every two seconds.
- No antivirus changes, automatic elevation/driver installation or changes to existing applications. Manual official signed driver setup is separate from application behavior.
- All streams, histories, settings reads and queues have explicit bounds.

## Review Focus

- PID reuse and protected/critical processes cannot redirect a destructive action.
- Reconnected interfaces or reset counters cannot produce enormous transfer rates.
- A missing, blocked or hung sensor companion leaves the tray responsive and values visibly unavailable.
- Explorer/taskbar recreation and DPI changes do not leak icons or GDI handles.
- Corrupt settings, malformed frames and abrupt exit cannot cause unbounded allocation or orphan helpers.

### Task 1: Verified dependencies and sensor companion

**Files:** `scripts/fetch-hardware-monitor.ps1`, `scripts/build.ps1`, `sensor-bridge/Program.cs`, `sensor-bridge/Protocol.cs`, `sensor-bridge/Protocol.Tests.cs`.

**Interface:** The companion writes one JSON object per line with protocol version 1, driver/elevation status, sensor records and bounded errors. Sensor values are finite numbers; unavailable readings are omitted. `--once` provides a smoke-test mode; normal mode requires a live parent PID.

- [x] Download and hash-check the official latest stable hardware monitor and preserve license/notices.
- [x] Write protocol tests for escaping names, retaining real zero, dropping unavailable/nonfinite readings and bounding records. Compile a minimal scaffold and watch the assertions fail.
- [x] Implement the protocol and collector; run the tests, then probe actual available sensors without changing drivers or antivirus.

### Task 2: Rust data and operating-system monitoring

**Files:** `Cargo.toml`, `src/lib.rs`, `src/model.rs`, `src/settings.rs`, `src/metrics.rs`, `src/processes.rs`, `src/sensors.rs`, `src/win.rs`.

**Interfaces:** `Snapshot` carries optional system measurements, bounded history, process rows and `SensorState`. The collector publishes only the latest state. Settings validate icon visibility and recover from malformed files.

- [x] Add tests before implementing: counter decreases/zero elapsed, CPU delta and PID reuse, fixed-capacity history, corrupt settings and oversized/malformed sensor frames.
- [x] Run the tests and verify intended failures when Rust becomes available.
- [x] Implement Win32 CPU/memory/physical-network sampling, persistent PDH disk counters and demand-driven process sampling.
- [x] Implement the supervised sensor reader and bounded settings persistence; run the full tests.

### Task 3: Native UI, distribution and verification

**Files:** `src/main.rs`, `src/ui.rs`, `src/tray.rs`, `build.rs`, `assets/app.manifest`, `assets/app.ico`, `README.md`.

**Interfaces:** The UI reads snapshots without performing monitoring I/O on its thread. Process actions verify identity using creation time. Diagnostic CLI output supports real-system checks without UI interaction.

- [x] Build the Win32 window, tables, tray menus, icon rendering, settings controls and process actions.
- [x] Add manifest, versioned portable packaging and build instructions.
- [x] Run `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test` and the release build. Probe actual metrics and sensor frames.
- [x] Inspect the native window, resizing, hide/restore and clean exit; perform one independent final code review and address material findings.

## Validation notes — 2026-11-17

- 45 Rust tests passed; one helper entrypoint is intentionally ignored by the ordinary runner and invoked by controlled-child tests. Six managed sensor-protocol tests passed. Strict Clippy, formatting and the portable release build passed.
- Read-only probes returned approximately 900 processes, x64 identity/command line, native counters and 156 autostart entries. UI inspection showed a real 5.2 GiB x64 process, full selected-process arguments and the processor-selection dialog. Real user processes and autostart entries were not modified.
- Review fixes cover future-launch activation cutoffs, the embedded icon resource, minimized sampling and releasing mutable UI borrows before native default message handling.
- Measured the native parent and sensor companion separately, with visible/minimized windows and no saved rules. UI Automation inspection of the unfiltered virtual table itself adds substantial temporary work; idle measurements exclude that inspector.
- CPU temperature remains an environment-dependent pending check: the signed upstream PawnIO installer is awaiting the user's elevated-window interaction. Available GPU temperatures are verified; unavailable CPU temperatures remain an em dash. No antivirus exclusions were added.
