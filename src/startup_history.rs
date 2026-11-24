//! Bounded first-detection history. No commands, executable metadata or enabled states are persisted.

use super::{Identity, MAX_ENTRIES, StartupSnapshot, id, parse_id};
use crate::storage::{read_bounded, write_atomic};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, io, path::PathBuf};

const MAX_HISTORY_BYTES: usize = 8 * 1024 * 1024;
const MAX_HISTORY_ENTRIES: usize = 32768;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
enum HistoryKey {
    Run {
        machine: bool,
        view32: bool,
        once: bool,
        name: String,
    },
    Folder {
        common: bool,
        name: String,
    },
    Task {
        path: String,
    },
    Service {
        name: String,
    },
}
impl HistoryKey {
    fn from_identity(identity: Identity) -> Self {
        match identity {
            Identity::Run {
                machine,
                view32,
                once,
                name,
            } => Self::Run {
                machine,
                view32,
                once,
                name,
            },
            Identity::Folder { common, name, .. } => Self::Folder { common, name },
            Identity::Task { path, .. } => Self::Task { path },
            Identity::Service { name } => Self::Service { name },
        }
    }
    fn validate(&self) -> Result<(), String> {
        let identity = match self {
            Self::Run {
                machine,
                view32,
                once,
                name,
            } => Identity::Run {
                machine: *machine,
                view32: *view32,
                once: *once,
                name: name.clone(),
            },
            Self::Folder { common, name } => Identity::Folder {
                common: *common,
                name: name.clone(),
                size: 0,
                modified: 0,
            },
            Self::Task { path } => Identity::Task {
                path: path.clone(),
                definition: String::new(),
            },
            Self::Service { name } => Identity::Service { name: name.clone() },
        };
        parse_id(&id(&identity)).map(|_| ())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryFile {
    version: u32,
    entries: Vec<(HistoryKey, Option<u64>)>,
}

pub struct StartupHistory {
    path: PathBuf,
    entries: BTreeMap<HistoryKey, Option<u64>>,
    saved: Option<Vec<u8>>,
}
impl StartupHistory {
    pub fn load(path: PathBuf) -> Result<Self, String> {
        let bytes = match read_bounded(&path, MAX_HISTORY_BYTES) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(Self {
                    path,
                    entries: BTreeMap::new(),
                    saved: None,
                });
            }
            Err(error) => {
                return Err(format!(
                    "Не удалось прочитать историю автозагрузки: {error}"
                ));
            }
        };
        let file: HistoryFile = serde_json::from_slice(&bytes).map_err(|error| {
            format!("История автозагрузки повреждена и не будет перезаписана: {error}")
        })?;
        if file.version != 1 || file.entries.len() > MAX_HISTORY_ENTRIES {
            return Err("Неподдерживаемая или слишком большая история автозагрузки".into());
        }
        let mut entries = BTreeMap::new();
        for (key, timestamp) in file.entries {
            key.validate()
                .map_err(|error| format!("Неверная запись истории автозагрузки: {error}"))?;
            if timestamp.is_some_and(|time| time == 0 || time > i64::MAX as u64) {
                return Err("Неверная дата в истории автозагрузки".into());
            }
            if entries.insert(key, timestamp).is_some() {
                return Err("История автозагрузки содержит повторяющиеся записи".into());
            }
        }
        Ok(Self {
            path,
            entries,
            saved: Some(bytes),
        })
    }
    pub fn observe(&mut self, snapshot: &mut StartupSnapshot) -> Result<usize, String> {
        let mut now = windows_sys::Win32::Foundation::FILETIME::default();
        // SAFETY: now points to writable FILETIME storage; no settings are changed.
        unsafe {
            windows_sys::Win32::System::SystemInformation::GetSystemTimeAsFileTime(&mut now);
        }
        self.observe_at(snapshot, crate::win::filetime(now))
    }
    fn observe_at(&mut self, snapshot: &mut StartupSnapshot, now: u64) -> Result<usize, String> {
        if snapshot.entries.len() > MAX_ENTRIES || now == 0 || now > i64::MAX as u64 {
            return Err("Неверный снимок или дата истории автозагрузки".into());
        }
        let mut discovered = BTreeMap::new();
        let mut estimated_new_bytes = 0usize;
        for entry in &mut snapshot.entries {
            entry.added_at = None;
            let key = HistoryKey::from_identity(parse_id(&entry.id)?);
            if let Some(timestamp) = self.entries.get(&key) {
                entry.added_at = *timestamp;
                continue;
            }
            if discovered.contains_key(&key) {
                continue;
            }
            let key_bytes = serde_json::to_vec(&key)
                .map_err(|error| format!("Не удалось подготовить историю автозагрузки: {error}"))?;
            estimated_new_bytes = estimated_new_bytes.saturating_add(key_bytes.len() + 32);
            if estimated_new_bytes > MAX_HISTORY_BYTES
                || self.entries.len() + discovered.len() >= MAX_HISTORY_ENTRIES
            {
                return Err(
                    "Достигнут предел истории автозагрузки; существующие даты сохранены".into(),
                );
            }
            discovered.insert(key, self.saved.as_ref().map(|_| now));
        }
        if self.saved.is_some() && discovered.is_empty() {
            return Ok(0);
        }
        // A wholly inaccessible initial inventory is not a usable baseline.
        if self.saved.is_none() && snapshot.entries.is_empty() && !snapshot.warnings.is_empty() {
            return Ok(0);
        }
        let new_count = if self.saved.is_some() {
            discovered.len()
        } else {
            0
        };
        let mut candidate = self.entries.clone();
        candidate.extend(discovered);
        let file = HistoryFile {
            version: 1,
            entries: candidate
                .iter()
                .map(|(key, timestamp)| (key.clone(), *timestamp))
                .collect(),
        };
        let bytes = serde_json::to_vec(&file)
            .map_err(|error| format!("Не удалось записать историю автозагрузки: {error}"))?;
        if bytes.len() > MAX_HISTORY_BYTES {
            return Err(
                "Достигнут предел размера истории автозагрузки; существующие даты сохранены".into(),
            );
        }
        // Detect external changes, including corruption, before replacing an existing history.
        let current = match read_bounded(&self.path, MAX_HISTORY_BYTES) {
            Ok(current) => Some(current),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => {
                return Err(format!(
                    "Не удалось проверить историю автозагрузки: {error}"
                ));
            }
        };
        if current != self.saved {
            return Err(
                "Файл истории автозагрузки изменён другим приложением; перезапись отменена".into(),
            );
        }
        write_atomic(&self.path, &bytes)
            .map_err(|error| format!("Не удалось сохранить историю автозагрузки: {error}"))?;
        self.entries = candidate;
        self.saved = Some(bytes);
        for entry in &mut snapshot.entries {
            let key = HistoryKey::from_identity(parse_id(&entry.id)?);
            entry.added_at = self.entries.get(&key).copied().flatten();
        }
        Ok(new_count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{read_bounded, write_atomic};
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let folder = std::env::temp_dir().join(format!(
                "AnVirNext-startup-history-{}-{nonce}",
                std::process::id()
            ));
            fs::create_dir(&folder).unwrap();
            Self(folder.join("history.json"))
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
            let _ = fs::remove_dir(self.0.parent().unwrap());
        }
    }
    fn entry(identity: Identity) -> super::super::StartupEntry {
        super::super::StartupEntry {
            id: id(&identity),
            origin: identity.origin(),
            name: "display".into(),
            source: "display source".into(),
            location: "location".into(),
            command: "secret.exe --password=must-not-be-stored".into(),
            enabled: true,
            can_toggle: true,
            icon_index: None,
            executable: None,
            added_at: None,
            startup_delay: super::super::StartupDelay::None,
        }
    }
    fn run(name: &str) -> super::super::StartupEntry {
        entry(Identity::Run {
            machine: false,
            view32: false,
            once: false,
            name: name.into(),
        })
    }
    fn snapshot(entries: Vec<super::super::StartupEntry>) -> StartupSnapshot {
        StartupSnapshot {
            entries,
            ..StartupSnapshot::default()
        }
    }

    #[test]
    fn startup_history_baseline_unknown_new_timestamp_and_reload_are_durable() {
        let fixture = Fixture::new();
        let mut history = StartupHistory::load(fixture.0.clone()).unwrap();
        let mut baseline = snapshot(vec![run("old")]);
        assert_eq!(history.observe_at(&mut baseline, 100).unwrap(), 0);
        assert_eq!(baseline.entries[0].added_at, None);
        let mut changed = snapshot(vec![run("old"), run("new")]);
        assert_eq!(history.observe_at(&mut changed, 200).unwrap(), 1);
        assert_eq!(changed.entries[0].added_at, None);
        assert_eq!(changed.entries[1].added_at, Some(200));
        let persisted = read_bounded(&fixture.0, 1024 * 1024).unwrap();
        assert!(
            !String::from_utf8(persisted.clone())
                .unwrap()
                .contains("password")
        );
        let mut history = StartupHistory::load(fixture.0.clone()).unwrap();
        assert_eq!(history.observe_at(&mut changed, 300).unwrap(), 0);
        assert_eq!(changed.entries[1].added_at, Some(200));
        assert_eq!(read_bounded(&fixture.0, 1024 * 1024).unwrap(), persisted);
    }

    #[test]
    fn startup_history_mutable_commands_approvals_and_revision_ids_do_not_reset_dates() {
        let fixture = Fixture::new();
        let mut history = StartupHistory::load(fixture.0.clone()).unwrap();
        history.observe_at(&mut snapshot(Vec::new()), 100).unwrap();
        let mut added = snapshot(vec![
            run("run"),
            entry(Identity::Folder {
                common: false,
                name: "link.lnk".into(),
                size: 1,
                modified: 2,
            }),
            entry(Identity::Task {
                path: r"\Vendor\Task".into(),
                definition: "first".into(),
            }),
        ]);
        assert_eq!(history.observe_at(&mut added, 200).unwrap(), 3);
        added.entries[0].enabled = false;
        added.entries[0].command = "changed.exe --different".into();
        added.entries[1].id = id(&Identity::Folder {
            common: false,
            name: "link.lnk".into(),
            size: 99,
            modified: 100,
        });
        added.entries[1].icon_index = Some(100);
        added.entries[1].executable = Some("different path".into());
        added.entries[2].id = id(&Identity::Task {
            path: r"\Vendor\Task".into(),
            definition: "changed".into(),
        });
        assert_eq!(history.observe_at(&mut added, 300).unwrap(), 0);
        assert!(
            added
                .entries
                .iter()
                .all(|entry| entry.added_at == Some(200))
        );
    }

    #[test]
    fn startup_history_partial_absences_preserve_existing_dates() {
        let fixture = Fixture::new();
        let mut history = StartupHistory::load(fixture.0.clone()).unwrap();
        history
            .observe_at(&mut snapshot(vec![run("baseline")]), 100)
            .unwrap();
        let mut added = snapshot(vec![run("added")]);
        history.observe_at(&mut added, 200).unwrap();
        let mut incomplete = StartupSnapshot {
            entries: Vec::new(),
            warnings: vec!["access denied".into()],
            ..StartupSnapshot::default()
        };
        assert_eq!(history.observe_at(&mut incomplete, 300).unwrap(), 0);
        let mut history = StartupHistory::load(fixture.0.clone()).unwrap();
        assert_eq!(history.observe_at(&mut added, 400).unwrap(), 0);
        assert_eq!(added.entries[0].added_at, Some(200));
        let mut old = snapshot(vec![run("baseline")]);
        history.observe_at(&mut old, 500).unwrap();
        assert_eq!(old.entries[0].added_at, None);
    }

    #[test]
    fn startup_history_corruption_and_external_replacement_are_not_overwritten() {
        let fixture = Fixture::new();
        write_atomic(&fixture.0, b"malformed").unwrap();
        assert!(StartupHistory::load(fixture.0.clone()).is_err());
        assert_eq!(fs::read(&fixture.0).unwrap(), b"malformed");
        fs::remove_file(&fixture.0).unwrap();
        let mut history = StartupHistory::load(fixture.0.clone()).unwrap();
        history
            .observe_at(&mut snapshot(vec![run("baseline")]), 100)
            .unwrap();
        write_atomic(&fixture.0, b"externally corrupted").unwrap();
        assert!(
            history
                .observe_at(&mut snapshot(vec![run("new")]), 200)
                .is_err()
        );
        assert_eq!(fs::read(&fixture.0).unwrap(), b"externally corrupted");
    }

    #[test]
    fn startup_history_unchanged_observation_never_writes_or_reads_again() {
        let fixture = Fixture::new();
        let mut history = StartupHistory::load(fixture.0.clone()).unwrap();
        let mut baseline = snapshot(vec![run("old")]);
        history.observe_at(&mut baseline, 100).unwrap();
        fs::remove_file(&fixture.0).unwrap();
        assert_eq!(history.observe_at(&mut baseline, 200).unwrap(), 0);
        assert!(!fixture.0.exists());
    }

    #[test]
    fn startup_history_rejects_bad_version_duplicate_keys_dates_and_oversized_files() {
        let fixture = Fixture::new();
        for bytes in [
            br#"{"version":2,"entries":[]}"#.as_slice(),
            br#"{"version":1,"entries":[[{"Service":{"name":"same"}},null],[{"Service":{"name":"same"}},100]]}"#.as_slice(),
            br#"{"version":1,"entries":[[{"Service":{"name":"service"}},0]]}"#.as_slice(),
            br#"{"version":1,"entries":[[{"Folder":{"common":false,"name":"../bad"}},100]]}"#.as_slice(),
            br#"{"version":1,"entries":[],"unknown":true}"#.as_slice(),
        ] {
            write_atomic(&fixture.0, bytes).unwrap(); assert!(StartupHistory::load(fixture.0.clone()).is_err()); assert_eq!(fs::read(&fixture.0).unwrap(), bytes);
        }
        let bytes = vec![b' '; MAX_HISTORY_BYTES + 1];
        write_atomic(&fixture.0, &bytes).unwrap();
        assert!(StartupHistory::load(fixture.0.clone()).is_err());
        assert_eq!(fs::metadata(&fixture.0).unwrap().len(), bytes.len() as u64);
    }

    #[test]
    fn startup_history_unavailable_initial_scan_and_invalid_ids_do_not_commit_baseline() {
        let fixture = Fixture::new();
        let mut history = StartupHistory::load(fixture.0.clone()).unwrap();
        let mut unavailable = StartupSnapshot {
            entries: Vec::new(),
            warnings: vec!["unavailable".into()],
            ..StartupSnapshot::default()
        };
        assert_eq!(history.observe_at(&mut unavailable, 100).unwrap(), 0);
        assert!(!fixture.0.exists());
        let mut invalid = run("invalid");
        invalid.id = "not-json".into();
        assert!(
            history
                .observe_at(&mut snapshot(vec![invalid]), 100)
                .is_err()
        );
        assert!(!fixture.0.exists());
        let mut first = snapshot(vec![run("first")]);
        assert_eq!(history.observe_at(&mut first, 200).unwrap(), 0);
        assert_eq!(first.entries[0].added_at, None);
        let mut duplicate = snapshot(vec![run("new"), run("new")]);
        assert_eq!(history.observe_at(&mut duplicate, 300).unwrap(), 1);
        assert!(
            duplicate
                .entries
                .iter()
                .all(|entry| entry.added_at == Some(300))
        );
    }
}
