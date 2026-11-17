# Native Monitor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a working native Windows tray monitor, process window and LibreHardwareMonitor sensor integration.

**Architecture:** Rust owns the Win32 UI, notification icons and system metrics. A small .NET Framework companion calls the upstream LibreHardwareMonitor library and sends bounded JSON frames through a redirected pipe. No web server, automatic driver installation or global hooks.

**Tech Stack:** Rust, windows-sys, serde/serde_json; .NET Framework 4.7.2 and LibreHardwareMonitor 0.9.6.

**Spec:** `docs/superpowers/specs/2026-11-17-native-monitor-design.md`

## Global Constraints

- Windows 11 x64 first; work in the user-supplied directory.
- CPU/disk/network defaults follow the inspected AnVir setup.
- Current metrics every second, processes every two seconds only while visible, sensors every two seconds.
- No antivirus changes, automatic elevation, driver installation or changes to existing applications.
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

- [ ] Download and hash-check the official latest stable hardware monitor and preserve license/notices.
- [ ] Write protocol tests for escaping names, retaining real zero, dropping unavailable/nonfinite readings and bounding records. Compile a minimal scaffold and watch the assertions fail.
- [ ] Implement the protocol and collector; run the tests, then probe actual available sensors without changing drivers or antivirus.

### Task 2: Rust data and operating-system monitoring

**Files:** `Cargo.toml`, `src/lib.rs`, `src/model.rs`, `src/settings.rs`, `src/metrics.rs`, `src/processes.rs`, `src/sensors.rs`, `src/win.rs`.

**Interfaces:** `Snapshot` carries optional system measurements, bounded history, process rows and `SensorState`. The collector publishes only the latest state. Settings validate icon visibility and recover from malformed files.

- [ ] Add tests before implementing: counter decreases/zero elapsed, CPU delta and PID reuse, fixed-capacity history, corrupt settings and oversized/malformed sensor frames.
- [ ] Run the tests and verify intended failures when Rust becomes available.
- [ ] Implement Win32 CPU/memory/physical-network sampling, persistent PDH disk counters and a process sampler used only while the window is visible.
- [ ] Implement the supervised sensor reader and bounded settings persistence; run the full tests.

### Task 3: Native UI, distribution and verification

**Files:** `src/main.rs`, `src/ui.rs`, `src/tray.rs`, `build.rs`, `assets/app.manifest`, `assets/app.ico`, `README.md`.

**Interfaces:** The UI reads snapshots without performing monitoring I/O on its thread. Process actions verify identity using creation time. Diagnostic CLI output supports real-system checks without UI interaction.

- [ ] Build the Win32 window, tables, tray menus, icon rendering, settings controls and process actions.
- [ ] Add manifest, versioned portable packaging and build instructions.
- [ ] Run `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test` and the release build. Probe actual metrics and sensor frames.
- [ ] Inspect the native window, resizing, hide/restore and clean exit; perform one independent final code review and address material findings.
