pub mod model;
pub mod sensors;
pub mod settings;
pub mod storage;

#[cfg(windows)]
pub mod activity;

#[cfg(windows)]
pub mod icons;
#[cfg(windows)]
pub mod metrics;
#[cfg(windows)]
pub mod monitor;
#[cfg(windows)]
pub mod process_rules;
#[cfg(windows)]
pub mod processes;
#[cfg(windows)]
pub mod scheduling_dialog;
#[cfg(windows)]
pub mod startup;
#[cfg(windows)]
pub mod theme;
#[cfg(windows)]
pub mod tray;
#[cfg(windows)]
pub mod ui;
#[cfg(windows)]
pub mod win;
