# System Theme Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans inline. Preserve the existing native Win32 architecture.

**Goal:** Follow the Windows app light/dark preference automatically, including changes while running, and correct initial layout at non-default DPI.

**Subsequent user scope:** Source-navigation tree for autostart, row context menus, application/action icons, stable non-flashing process updates and Delete shortcuts (terminate process or disable startup, with confirmation). Compare the actual installed AnVir through read-only interaction; no real process/startup changes during development checks.

**Further explicit scope:** A searchable raw command-line argument column; combined CPU core-bar/total-number tray icon; two-bar receive/send tray for physical external adapters only; separate accurate per-process network RX/TX and physical disk read/write. Use an owned private ETW session only on the visible Processes tab, degrade clearly without administrator rights, preserve exact process-birth identity and stop the session on hide/shutdown. No other trace sessions may be modified.

**Architecture:** A small shared native theme module reads the preference only at startup and on Windows settings/theme messages. Native controls retain their behavior and accessibility. Custom painting is limited to dark tab/header strips that lack a native dark visual style. High contrast retains system colors. Optional UXTheme dark-control exports are resolved only on Windows 11 and are never required for basic color rendering.

**Tech Stack:** Existing Rust/windows-sys; DWM and accessibility feature flags, no new packages.

**Spec:** DESIGN.md; user's screenshot and explicit automatic system light/dark request.

## Constraints and review focus

- No global Windows theme changes, antivirus changes, extra polling or web runtime.
- Read AppsUseLightTheme rather than the taskbar/system color preference; high contrast wins.
- Apply both main-window and priority/affinity-dialog colors, captions, lists, headers, text fields and native controls.
- Do not hold Rust UI borrows across theme callbacks or store Rust pointers in control subclasses.
- Restore native light/high-contrast rendering; clean up subclasses with control lifetime.
- Install window state before the initial DPI-scaled resize, so WM_SIZE reaches the layout handler.

## Steps

- [x] Observe failing preference/high-contrast regressions and the supplied initial-DPI layout failure.
- [x] Implement cached native theme detection, event handling and rendering; integrate with both windows and fix initial resize ordering.
- [x] Verify light/dark control colors in a disposable native fixture without altering Windows settings; run formatting, Clippy and relevant/full tests.
- [x] Add typed autostart tree grouping, cached application icons, context-menu target guards, shared stock action images and Delete behavior; verify focused regressions.
- [x] Add bounded lazy argument caching, borrowed/bounded table rendering and new argument/disk/network columns.
- [x] Render CPU core bars beneath the overall number and separate receive/send network bars; verify physical-adapter filtering and processor-group topology.
- [ ] Verify the owned kernel activity trace against native TCP/UDP IPv4/IPv6 and uncached disk fixtures, including permission denial, loss and schema guards.
- [ ] Build and inspect the real dark window and dialog, including the 150% layout; address one bounded batch of visual defects.
- [ ] Verify privileged CPU readings after PawnIO setup, rebuild/package the portable distribution and report the actual result.
