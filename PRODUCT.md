# AnVir Next

<!-- impeccable:product-schema 1 -->

## Platform

Native Windows desktop, Windows 11 x64 first.

## Stack

Rust and native Win32 controls. The user is installing Rust. Use the official LibreHardwareMonitor library for hardware sensors; keep its .NET dependency outside the native UI.

## Users and purpose

A personal replacement for the user's aging AnVir Task Manager. The application should make current CPU, storage and network activity immediately visible in the notification area and make processes and temperatures easy to inspect.

## Confirmed constraints

- Work in `D:\work\pet\AnVir-Next`.
- Prioritize correctness/security, then performance, then simplicity and maintenance.
- Keep background CPU, memory and wakeups low. No browser engine.
- Reuse the latest stable official LibreHardwareMonitor instead of recreating device drivers.
- Do not change antivirus settings or restore quarantined AnVir components.
- The user delegated discovery of the existing setup and authorized beginning implementation.

## Evidence

Observed 2026-11-17: AnVir Free 9.4.0 uses its bundled OpenHardwareMonitor 0.9.6 process. CPU, per-core, disk and network tray indicators are enabled; memory and battery indicators, startup protection, automatic priority reduction and memory optimization are disabled. Process refresh interval is two seconds. WMI exposes 53 sensor readings, including GPU temperature, but no CPU or SSD temperatures.

## First-version decisions

These are implementation choices for review, not additional user requirements: native tray indicators and a compact window with system activity, a process list and a sensor list. Process manipulation requires explicit UI actions. Hardware monitoring must degrade clearly when privileged sensors or their driver are unavailable. No proprietary AnVir code or binaries are reused.

## Confirmed scope update

The user supplied reference screenshots and explicitly requested a working prototype with:
- Native x64 process enumeration and correct memory readings for 64-bit programs.
- Columns matching the reference: process, product, CPU, disk/I/O activity, memory, company and executable path. Security Risk must not exist. Network columns in the reference are disabled; per-process network tracing is not required.
- Selected-process details prominently expose the full launch command line and arguments.
- Priority and processor-affinity changes can be saved for future launches of the same executable.
- Accessible Windows autostart management and change monitoring.
- Tray indicators close to the screenshot, particularly CPU activity/temperature, memory percentage and network activity.
- Low background overhead remains a high priority.

Arbitrary-window hooks, antivirus/reputation features and full driver/DLL inspection remain outside the prototype.
