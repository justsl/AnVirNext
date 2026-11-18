use crate::{
    processes::{ProcessRow, set_scheduling, validate_scheduling},
    storage::{read_bounded, write_atomic},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    io,
    path::{Component, Path, PathBuf, Prefix},
};
use windows_sys::Win32::{
    Foundation::FILETIME,
    Globalization::{CSTR_EQUAL, CompareStringOrdinal},
    System::SystemInformation::GetSystemTimePreciseAsFileTime,
};

const MAX_RULES: usize = 128;
const MAX_FILE: usize = 128 * 1024;
const MAX_TRACKED: usize = 8192;
const MAX_ATTEMPTS: u8 = 3;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProcessRule {
    pub executable: String,
    pub priority: u32,
    pub affinity: u64,
}
#[derive(Serialize, Deserialize)]
struct StoredRule {
    #[serde(flatten)]
    rule: ProcessRule,
    #[serde(default)]
    activated_after: Option<u64>,
}
struct Attempt {
    rule_id: u64,
    count: u8,
    done: bool,
}
pub struct RuleBook {
    path: PathBuf,
    rules: Vec<ProcessRule>,
    rule_paths: Vec<Vec<u16>>,
    rule_ids: Vec<u64>,
    activations: Vec<u64>,
    next_id: u64,
    attempts: HashMap<(u32, u64), Attempt>,
}
impl RuleBook {
    pub fn load(path: &Path) -> Result<Self, String> {
        // Legacy arrays lack an eligibility boundary. Exclude existing processes
        // using this runtime baseline, without writing during a read-only load.
        let legacy_baseline = activation_time();
        let bytes = match read_bounded(path, MAX_FILE) {
            Ok(bytes) => Some(bytes),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(format!("Read process rules: {error}")),
        };
        let stored: Vec<StoredRule> = match bytes {
            Some(bytes) => serde_json::from_slice(&bytes)
                .map_err(|error| format!("Invalid process rules: {error}"))?,
            None => Vec::new(),
        };
        if stored.len() > MAX_RULES {
            return Err("At most 128 process rules are supported".into());
        }
        let mut rules = Vec::with_capacity(stored.len());
        let mut activations = Vec::with_capacity(stored.len());
        for entry in stored {
            let activation = entry.activated_after.unwrap_or(legacy_baseline);
            if activation == 0 {
                return Err("Invalid process rule activation time".into());
            }
            rules.push(entry.rule);
            activations.push(activation);
        }
        for index in 0..rules.len() {
            validate_rule(&mut rules[index])?;
            if rules[..index]
                .iter()
                .any(|other| paths_equal(&other.executable, &rules[index].executable))
            {
                return Err("Duplicate executable in process rules".into());
            }
        }
        let count = rules.len() as u64;
        let rule_paths = rules
            .iter()
            .map(|rule| rule.executable.encode_utf16().collect())
            .collect();
        Ok(Self {
            path: path.into(),
            rules,
            rule_paths,
            rule_ids: (1..=count).collect(),
            activations,
            next_id: count + 1,
            attempts: HashMap::new(),
        })
    }
    pub fn rules(&self) -> &[ProcessRule] {
        &self.rules
    }
    pub fn upsert(&mut self, mut rule: ProcessRule) -> Result<(), String> {
        validate_rule(&mut rule)?;
        let index = self
            .rules
            .iter()
            .position(|other| paths_equal(&other.executable, &rule.executable));
        if index.is_none() && self.rules.len() == MAX_RULES {
            return Err("At most 128 process rules are supported".into());
        }
        let next_id = self
            .next_id
            .checked_add(1)
            .ok_or("Process rule revision limit reached")?;
        let mut rules = self.rules.clone();
        let mut activations = self.activations.clone();
        let activation = activation_time();
        match index {
            Some(index) => {
                rules[index] = rule;
                activations[index] = activation;
            }
            None => {
                rules.push(rule);
                activations.push(activation);
            }
        }
        self.persist(&rules, &activations)?;
        match index {
            Some(index) => self.rule_ids[index] = self.next_id,
            None => self.rule_ids.push(self.next_id),
        }
        self.next_id = next_id;
        self.rule_paths = rules
            .iter()
            .map(|rule| rule.executable.encode_utf16().collect())
            .collect();
        self.rules = rules;
        self.activations = activations;
        Ok(())
    }
    pub fn remove(&mut self, executable: &str) -> Result<(), String> {
        let executable = normalize_path(executable)?;
        let Some(index) = self
            .rules
            .iter()
            .position(|rule| paths_equal(&rule.executable, &executable))
        else {
            return Ok(());
        };
        let mut rules = self.rules.clone();
        let mut activations = self.activations.clone();
        rules.remove(index);
        activations.remove(index);
        self.persist(&rules, &activations)?;
        self.rules = rules;
        self.activations = activations;
        self.rule_paths.remove(index);
        let id = self.rule_ids.remove(index);
        self.attempts.retain(|_, attempt| attempt.rule_id != id);
        Ok(())
    }
    pub fn has_rules(&self) -> bool {
        !self.rules.is_empty()
    }
    fn persist(&self, rules: &[ProcessRule], activations: &[u64]) -> Result<(), String> {
        let stored: Vec<_> = rules
            .iter()
            .zip(activations)
            .map(|(rule, activation)| StoredRule {
                rule: rule.clone(),
                activated_after: Some(*activation),
            })
            .collect();
        let bytes = serde_json::to_vec_pretty(&stored).map_err(|error| error.to_string())?;
        if bytes.len() > MAX_FILE {
            return Err("Process rules exceed 128 KiB limit".into());
        }
        write_atomic(&self.path, &bytes).map_err(|error| format!("Save process rules: {error}"))
    }
    /// Called by the existing sampler, never by a separate polling loop.
    pub fn apply_new(&mut self, rows: &[ProcessRow]) -> Vec<String> {
        let mut errors = Vec::new();
        if self.rules.is_empty() {
            self.attempts.clear();
            return errors;
        }
        let live: HashSet<_> = rows
            .iter()
            .filter_map(|row| row.times.map(|times| (row.pid, times.created)))
            .take(MAX_TRACKED)
            .collect();
        self.attempts.retain(|identity, _| live.contains(identity));
        for row in rows {
            let Some(times) = row.times.filter(|times| times.created != 0) else {
                continue;
            };
            let identity = (row.pid, times.created);
            if !live.contains(&identity) || row.path.is_empty() {
                continue;
            }
            let Ok(path) = normalize_path(&row.path) else {
                continue;
            };
            let path: Vec<_> = path.encode_utf16().collect();
            let Some(index) = self
                .rule_paths
                .iter()
                .position(|rule| wide_equal(rule, &path))
            else {
                continue;
            };
            // Creation identity is stable across samples/reloads. A rule edit
            // advances this boundary instead of changing already-running siblings.
            if times.created <= self.activations[index] {
                continue;
            }
            let id = self.rule_ids[index];
            let attempt = self.attempts.entry(identity).or_insert(Attempt {
                rule_id: id,
                count: 0,
                done: false,
            });
            if attempt.rule_id != id {
                *attempt = Attempt {
                    rule_id: id,
                    count: 0,
                    done: false,
                };
            }
            if attempt.done || attempt.count >= MAX_ATTEMPTS {
                continue;
            }
            attempt.count += 1;
            let rule = &self.rules[index];
            match set_scheduling(row.pid, times.created, rule.priority, rule.affinity) {
                Ok(()) => attempt.done = true,
                Err(error) => errors.push(format!(
                    "{} (PID {}, attempt {}/{}): {error}",
                    row.name, row.pid, attempt.count, MAX_ATTEMPTS
                )),
            }
        }
        errors
    }
}

fn activation_time() -> u64 {
    let mut now = FILETIME::default();
    // SAFETY: one writable FILETIME output; available on the Windows 11 target.
    unsafe {
        GetSystemTimePreciseAsFileTime(&mut now);
    }
    crate::win::filetime(now)
}

fn validate_rule(rule: &mut ProcessRule) -> Result<(), String> {
    validate_scheduling(rule.priority, rule.affinity, u64::MAX)?;
    if rule.priority == 0 && rule.affinity == 0 {
        return Err("A rule must change priority or affinity".into());
    }
    rule.executable = normalize_path(&rule.executable)?;
    Ok(())
}

fn normalize_path(value: &str) -> Result<String, String> {
    if value.is_empty() || value.contains('\0') || value.encode_utf16().count() > 32767 {
        return Err("Invalid executable path".into());
    }
    let replaced = value.replace('/', "\\");
    let path = if replaced
        .get(..8)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(r"\\?\UNC\"))
    {
        format!(r"\\{}", &replaced[8..])
    } else if let Some(path) = replaced.strip_prefix(r"\\?\") {
        path.into()
    } else {
        replaced
    };
    let path = Path::new(&path);
    if !path.is_absolute() {
        return Err("An absolute executable path is required".into());
    }
    let mut normalized = PathBuf::new();
    let mut depth = 0usize;
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => {
                if !matches!(prefix.kind(), Prefix::Disk(_) | Prefix::UNC(_, _)) {
                    return Err("Unsupported executable path namespace".into());
                }
                normalized.push(prefix.as_os_str());
            }
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::CurDir => {}
            Component::Normal(part) => {
                normalized.push(part);
                depth += 1;
            }
            Component::ParentDir => {
                if depth == 0 {
                    return Err("Executable path escapes its root".into());
                }
                normalized.pop();
                depth -= 1;
            }
        }
    }
    if depth == 0 {
        return Err("Executable path must identify a file".into());
    }
    normalized
        .into_os_string()
        .into_string()
        .map_err(|_| "Invalid executable path encoding".into())
}

fn paths_equal(left: &str, right: &str) -> bool {
    let left: Vec<_> = left.encode_utf16().collect();
    let right: Vec<_> = right.encode_utf16().collect();
    wide_equal(&left, &right)
}

fn wide_equal(left: &[u16], right: &[u16]) -> bool {
    // SAFETY: valid UTF-16 slices and bounded lengths; comparison is Windows ordinal.
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        sync::atomic::{AtomicUsize, Ordering},
    };
    struct Temporary(PathBuf);
    impl Temporary {
        fn new() -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let path = std::env::temp_dir().join(format!(
                "anvir-rule-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
        fn path(&self) -> PathBuf {
            self.0.join("rules.json")
        }
    }
    impl Drop for Temporary {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn rule(path: &str) -> ProcessRule {
        ProcessRule {
            executable: path.into(),
            priority: 0x20,
            affinity: 3,
        }
    }

    #[test]
    fn persists_replaces_and_removes_using_full_case_insensitive_normalized_path() {
        let temp = Temporary::new();
        let mut book = RuleBook::load(&temp.path()).unwrap();
        assert!(book.rules().is_empty());
        book.upsert(rule(r"C:\Apps\Tools\..\Worker.EXE")).unwrap();
        book.upsert(ProcessRule {
            executable: "c:/apps/worker.exe".into(),
            priority: 0x4000,
            affinity: 1,
        })
        .unwrap();
        book.upsert(rule(r"C:\Other\worker.exe")).unwrap();
        let loaded = RuleBook::load(&temp.path()).unwrap();
        assert_eq!(loaded.rules().len(), 2);
        assert_eq!(loaded.rules()[0].priority, 0x4000);
        book.remove(r"C:\APPS\WORKER.exe").unwrap();
        assert_eq!(RuleBook::load(&temp.path()).unwrap().rules().len(), 1);
    }

    #[test]
    fn rejects_relative_paths_realtime_empty_changes_and_oversized_configuration() {
        let temp = Temporary::new();
        let mut book = RuleBook::load(&temp.path()).unwrap();
        assert!(book.upsert(rule("worker.exe")).is_err());
        assert!(book.upsert(rule(r"C:worker.exe")).is_err());
        assert!(
            book.upsert(ProcessRule {
                executable: r"C:\worker.exe".into(),
                priority: 0x100,
                affinity: 1
            })
            .is_err()
        );
        assert!(
            book.upsert(ProcessRule {
                executable: r"C:\worker.exe".into(),
                priority: 0,
                affinity: 0
            })
            .is_err()
        );
        fs::write(temp.path(), vec![b' '; 128 * 1024 + 1]).unwrap();
        assert!(RuleBook::load(&temp.path()).is_err());
    }

    #[test]
    fn refuses_more_than_128_rules_and_keeps_memory_unchanged_on_write_failure() {
        let temp = Temporary::new();
        let rules: Vec<_> = (0..128)
            .map(|index| rule(&format!(r"C:\app{index}.exe")))
            .collect();
        fs::write(temp.path(), serde_json::to_vec(&rules).unwrap()).unwrap();
        let mut book = RuleBook::load(&temp.path()).unwrap();
        assert!(book.upsert(rule(r"C:\extra.exe")).is_err());
        assert_eq!(book.rules().len(), 128);
        let parent_file = temp.0.join("file");
        let mut unwritable = RuleBook::load(&parent_file.join("rules.json")).unwrap();
        fs::write(&parent_file, b"not a directory").unwrap();
        assert!(unwritable.upsert(rule(r"C:\worker.exe")).is_err());
        assert!(unwritable.rules().is_empty());
    }

    #[test]
    fn failed_rule_application_is_finite_and_a_reused_pid_gets_new_attempts() {
        let temp = Temporary::new();
        let mut book = RuleBook::load(&temp.path()).unwrap();
        let mut row = crate::processes::ProcessSampler::default()
            .sample(1, false)
            .into_iter()
            .find(|row| row.pid == std::process::id())
            .unwrap();
        book.upsert(ProcessRule {
            executable: row.path.clone(),
            priority: 0x4000,
            affinity: 0,
        })
        .unwrap();
        // A future identity that safely fails self/identity validation exercises
        // retry bookkeeping without changing any live process.
        row.times.as_mut().unwrap().created = u64::MAX - 1;
        for _ in 0..3 {
            assert_eq!(book.apply_new(&[row.clone()]).len(), 1);
        }
        assert!(book.apply_new(std::slice::from_ref(&row)).is_empty());
        row.times.as_mut().unwrap().created += 1;
        assert_eq!(book.apply_new(&[row.clone()]).len(), 1);
        book.apply_new(&[]);
        assert_eq!(book.apply_new(&[row.clone()]).len(), 1);
        row.path = r"C:\Unrelated\same-name.exe".into();
        assert!(book.apply_new(&[row]).is_empty());
    }

    #[test]
    fn successful_rule_is_applied_once_to_a_controlled_child() {
        let temp = Temporary::new();
        let mut book = RuleBook::load(&temp.path()).unwrap();
        book.upsert(ProcessRule {
            executable: std::env::current_exe().unwrap().to_str().unwrap().into(),
            priority: 0x4000,
            affinity: 0,
        })
        .unwrap();
        let child = ControlledChild::new();
        let row = child.row();
        let created = row.times.unwrap().created;
        assert!(book.apply_new(std::slice::from_ref(&row)).is_empty());
        assert_eq!(
            crate::processes::details(row.pid, created)
                .unwrap()
                .priority,
            0x4000
        );
        set_scheduling(row.pid, created, 0x20, 0).unwrap();
        assert!(book.apply_new(std::slice::from_ref(&row)).is_empty());
        assert_eq!(
            crate::processes::details(row.pid, created)
                .unwrap()
                .priority,
            0x20
        );
    }

    struct ControlledChild(std::process::Child);
    impl ControlledChild {
        fn new() -> Self {
            Self(
                std::process::Command::new(std::env::current_exe().unwrap())
                    .args(["--ignored", "--exact", "processes::tests::controlled_child"])
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn()
                    .unwrap(),
            )
        }
        fn row(&self) -> ProcessRow {
            crate::processes::ProcessSampler::default()
                .sample(1, false)
                .into_iter()
                .find(|row| row.pid == self.0.id())
                .unwrap()
        }
    }
    impl Drop for ControlledChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    fn priority(row: &ProcessRow) -> u32 {
        crate::processes::details(row.pid, row.times.unwrap().created)
            .unwrap()
            .priority
    }

    #[test]
    fn saved_and_edited_rules_exclude_old_siblings_and_preserve_cutoff_after_reload() {
        let selected = ControlledChild::new();
        let sibling = ControlledChild::new();
        let selected_row = selected.row();
        let sibling_row = sibling.row();
        let sibling_priority = priority(&sibling_row);
        let temp = Temporary::new();
        let mut book = RuleBook::load(&temp.path()).unwrap();
        set_scheduling(
            selected_row.pid,
            selected_row.times.unwrap().created,
            0x4000,
            0,
        )
        .unwrap();
        book.upsert(ProcessRule {
            executable: selected_row.path.clone(),
            priority: 0x4000,
            affinity: 0,
        })
        .unwrap();
        let mut rows = vec![selected_row.clone(), sibling_row.clone()];
        assert!(book.apply_new(&rows).is_empty());
        assert_eq!(priority(&selected_row), 0x4000);
        assert_eq!(
            priority(&sibling_row),
            sibling_priority,
            "saving a future-launch rule changed an unselected old sibling"
        );

        let future = ControlledChild::new();
        let future_row = future.row();
        rows.push(future_row.clone());
        assert!(book.apply_new(&rows).is_empty());
        assert_eq!(priority(&future_row), 0x4000);
        set_scheduling(future_row.pid, future_row.times.unwrap().created, 0x20, 0).unwrap();
        set_scheduling(
            selected_row.pid,
            selected_row.times.unwrap().created,
            0x40,
            0,
        )
        .unwrap();
        book.upsert(ProcessRule {
            executable: selected_row.path.clone(),
            priority: 0x40,
            affinity: 0,
        })
        .unwrap();
        assert!(book.apply_new(&rows).is_empty());
        assert_eq!(priority(&selected_row), 0x40);
        assert_eq!(priority(&sibling_row), sibling_priority);
        assert_eq!(
            priority(&future_row),
            0x20,
            "editing a rule changed an already-running instance"
        );

        let newest = ControlledChild::new();
        let newest_row = newest.row();
        rows.push(newest_row.clone());
        let mut loaded = RuleBook::load(&temp.path()).unwrap();
        assert!(loaded.apply_new(&rows).is_empty());
        assert_eq!(priority(&sibling_row), sibling_priority);
        assert_eq!(
            priority(&future_row),
            0x20,
            "reload lost the edited rule's activation cutoff"
        );
        assert_eq!(priority(&newest_row), 0x40);
    }

    #[test]
    fn legacy_rules_exclude_existing_instances_without_writing_on_load() {
        let old = ControlledChild::new();
        let old_row = old.row();
        let old_priority = priority(&old_row);
        let temp = Temporary::new();
        let legacy = serde_json::to_vec(&[ProcessRule {
            executable: old_row.path.clone(),
            priority: 0x4000,
            affinity: 0,
        }])
        .unwrap();
        fs::write(temp.path(), &legacy).unwrap();
        let mut book = RuleBook::load(&temp.path()).unwrap();
        assert!(book.apply_new(std::slice::from_ref(&old_row)).is_empty());
        assert_eq!(priority(&old_row), old_priority);
        assert_eq!(fs::read(temp.path()).unwrap(), legacy);
        let future = ControlledChild::new();
        let future_row = future.row();
        assert!(book.apply_new(std::slice::from_ref(&future_row)).is_empty());
        assert_eq!(priority(&future_row), 0x4000);
    }

    #[test]
    fn failed_save_keeps_activation_rule_and_application_state_unchanged() {
        use std::os::windows::fs::OpenOptionsExt;
        let temp = Temporary::new();
        let mut book = RuleBook::load(&temp.path()).unwrap();
        let executable = std::env::current_exe()
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        book.upsert(ProcessRule {
            executable: executable.clone(),
            priority: 0x4000,
            affinity: 0,
        })
        .unwrap();
        let saved = fs::read(temp.path()).unwrap();
        let child = ControlledChild::new();
        let row = child.row();
        // Deny delete-sharing on this fixture file so its atomic replacement fails.
        let _locked = fs::OpenOptions::new()
            .read(true)
            .share_mode(1)
            .open(temp.path())
            .unwrap();
        assert!(
            book.upsert(ProcessRule {
                executable: executable.clone(),
                priority: 0x40,
                affinity: 0
            })
            .is_err()
        );
        assert_eq!(book.rules()[0].priority, 0x4000);
        assert!(book.apply_new(std::slice::from_ref(&row)).is_empty());
        assert_eq!(
            priority(&row),
            0x4000,
            "failed edit advanced the activation cutoff"
        );
        set_scheduling(row.pid, row.times.unwrap().created, 0x20, 0).unwrap();
        assert!(book.remove(&executable).is_err());
        assert!(book.apply_new(std::slice::from_ref(&row)).is_empty());
        assert_eq!(
            priority(&row),
            0x20,
            "failed save reset successful-application bookkeeping"
        );
        assert_eq!(fs::read(temp.path()).unwrap(), saved);
    }
}
