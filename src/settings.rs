use serde::{Deserialize, Serialize};
use std::{io, path::Path};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub cpu_icon: bool,
    pub disk_icon: bool,
    pub network_icon: bool,
    pub memory_icon: bool,
    pub temperature_icon: bool,
    pub interval_seconds: u32,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            cpu_icon: true,
            disk_icon: true,
            network_icon: true,
            memory_icon: true,
            temperature_icon: true,
            interval_seconds: 1,
        }
    }
}

impl Settings {
    pub fn load_at(path: &Path) -> Self {
        crate::storage::read_bounded(path, 65536)
            .map(|bytes| Self::from_json(&bytes))
            .unwrap_or_default()
    }
    pub fn save_at(&self, path: &Path) -> io::Result<()> {
        let bytes = serde_json::to_vec_pretty(self).map_err(io::Error::other)?;
        crate::storage::write_atomic(path, &bytes)
    }
    pub fn from_json(bytes: &[u8]) -> Self {
        if bytes.len() > 65536 {
            return Self::default();
        }
        let mut settings: Self = serde_json::from_slice(bytes).unwrap_or_default();
        settings.normalize();
        settings
    }

    pub fn normalize(&mut self) {
        if !self.cpu_icon
            && !self.disk_icon
            && !self.network_icon
            && !self.memory_icon
            && !self.temperature_icon
        {
            self.cpu_icon = true;
        }
        if !matches!(self.interval_seconds, 1 | 2 | 5) {
            self.interval_seconds = 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restores_user_choices_without_allowing_an_unreachable_tray() {
        let settings = Settings::from_json(br#"{"cpu_icon":false,"disk_icon":false,"network_icon":true,"memory_icon":true,"interval_seconds":2}"#);
        assert!(
            !settings.cpu_icon
                && !settings.disk_icon
                && settings.network_icon
                && settings.memory_icon
        );
        assert_eq!(settings.interval_seconds, 2);
        let hidden = Settings::from_json(br#"{"cpu_icon":false,"disk_icon":false,"network_icon":false,"memory_icon":false,"temperature_icon":false}"#);
        assert!(hidden.cpu_icon);
    }

    #[test]
    fn malformed_or_oversized_settings_cannot_break_startup() {
        for bytes in [b"{".as_slice(), b"null".as_slice(), b"[]".as_slice()] {
            assert!(Settings::from_json(bytes).cpu_icon);
        }
        let huge = vec![b' '; 65537];
        assert!(Settings::from_json(&huge).cpu_icon);
        assert_eq!(
            Settings::from_json(br#"{"interval_seconds":0}"#).interval_seconds,
            1
        );
    }

    #[test]
    fn atomically_replaces_existing_settings_and_loads_them() {
        let directory =
            std::env::temp_dir().join(format!("anvir-next-settings-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("settings.json");
        std::fs::write(&path, b"{old corrupt settings").unwrap();
        let settings = Settings {
            cpu_icon: false,
            disk_icon: true,
            network_icon: false,
            memory_icon: true,
            temperature_icon: true,
            interval_seconds: 5,
        };
        let saved = settings.save_at(&path);
        let loaded = Settings::load_at(&path);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&directory);
        saved.unwrap();
        assert!(!loaded.cpu_icon && loaded.memory_icon);
        assert_eq!(loaded.interval_seconds, 5);
    }
}
