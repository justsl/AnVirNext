//! Source grouping and local timestamp formatting for the native startup view.
use crate::startup::{ExplorerDelay, StartupDelay, StartupEntry, StartupOrigin};
use std::collections::{BTreeMap, BTreeSet};
use windows_sys::Win32::{
    Foundation::{FILETIME, SYSTEMTIME},
    System::Time::{FileTimeToSystemTime, SystemTimeToTzSpecificLocalTimeEx},
};

pub fn format_added_at(value: Option<u64>) -> String {
    let Some(value) = value else {
        return "—".into();
    };
    let filetime = FILETIME {
        dwLowDateTime: value as u32,
        dwHighDateTime: (value >> 32) as u32,
    };
    let mut utc = SYSTEMTIME::default();
    let mut local = SYSTEMTIME::default();
    // SAFETY: initialized input/output structures; null timezone requests the local dynamic rules,
    // including the historical DST rules for the timestamp's year, without changing OS settings.
    let converted = unsafe {
        FileTimeToSystemTime(&filetime, &mut utc) != 0
            && SystemTimeToTzSpecificLocalTimeEx(std::ptr::null(), &utc, &mut local) != 0
    };
    if !converted || !(1601..=9999).contains(&local.wYear) {
        return "—".into();
    }
    format!(
        "{:02}.{:02}.{:04} {:02}:{:02}",
        local.wDay, local.wMonth, local.wYear, local.wHour, local.wMinute
    )
}

pub fn delay_cell(delay: &StartupDelay, explorer: Option<ExplorerDelay>) -> (String, Option<u64>) {
    match delay {
        StartupDelay::None => ("—".into(), None),
        StartupDelay::Explorer => match explorer {
            None => ("Windows: недоступно".into(), None),
            Some(delay) => match delay.milliseconds {
                None => ("Windows: по умолчанию".into(), None),
                Some(milliseconds) => (
                    if milliseconds % 1000 == 0 {
                        format!("Windows: {} с", milliseconds / 1000)
                    } else {
                        format!("Windows: {milliseconds} мс")
                    },
                    Some(u64::from(milliseconds)),
                ),
            },
        },
        StartupDelay::Task { seconds, editable } => match seconds {
            Some(0) => ("Задача: без задержки".into(), Some(0)),
            Some(seconds) => (
                format!("Задача: {seconds} с"),
                Some(u64::from(*seconds) * 1000),
            ),
            None => (
                if *editable {
                    "Задача: разная/неизвестна"
                } else {
                    "Задача: недоступно"
                }
                .into(),
                None,
            ),
        },
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Group {
    All,
    Regular,
    Registry,
    RegistryScope(bool),
    RegistryKey {
        machine: bool,
        view32: bool,
        once: bool,
    },
    Folders,
    Folder(bool),
    Tasks,
    TaskFolder(String),
    Services,
}

pub struct Node {
    pub group: Group,
    pub parent: Option<usize>,
    pub title: String,
    pub count: usize,
}

fn task_folders(folder: &str) -> Vec<String> {
    let mut folders = vec!["\\".into()];
    let mut path = String::new();
    for part in folder.split('\\').filter(|part| !part.is_empty()) {
        path.push('\\');
        path.push_str(part);
        folders.push(path.clone());
    }
    folders
}

fn memberships(entry: &StartupEntry) -> Vec<Group> {
    let mut result = vec![Group::All];
    match &entry.origin {
        StartupOrigin::Registry {
            machine,
            view32,
            once,
        } => result.extend([
            Group::Regular,
            Group::Registry,
            Group::RegistryScope(*machine),
            Group::RegistryKey {
                machine: *machine,
                view32: *view32,
                once: *once,
            },
        ]),
        StartupOrigin::Folder { common } => {
            result.extend([Group::Regular, Group::Folders, Group::Folder(*common)])
        }
        StartupOrigin::Task { folder } => {
            result.push(Group::Tasks);
            result.extend(task_folders(folder).into_iter().map(Group::TaskFolder));
        }
        StartupOrigin::Service => result.push(Group::Services),
    }
    result
}

pub fn matches_group(entry: &StartupEntry, group: &Group) -> bool {
    match group {
        Group::All => true,
        Group::Regular => matches!(
            entry.origin,
            StartupOrigin::Registry { .. } | StartupOrigin::Folder { .. }
        ),
        Group::Registry => matches!(entry.origin, StartupOrigin::Registry { .. }),
        Group::RegistryScope(scope) => {
            matches!(&entry.origin, StartupOrigin::Registry { machine, .. } if machine == scope)
        }
        Group::RegistryKey {
            machine: scope,
            view32: view,
            once: run_once,
        } => {
            matches!(&entry.origin, StartupOrigin::Registry { machine, view32, once } if machine == scope && view32 == view && once == run_once)
        }
        Group::Folders => matches!(entry.origin, StartupOrigin::Folder { .. }),
        Group::Folder(scope) => {
            matches!(&entry.origin, StartupOrigin::Folder { common } if common == scope)
        }
        Group::Tasks => matches!(entry.origin, StartupOrigin::Task { .. }),
        Group::TaskFolder(path) => {
            matches!(&entry.origin, StartupOrigin::Task { folder } if folder == path || path == "\\" || folder.strip_prefix(path).is_some_and(|suffix| suffix.starts_with('\\')))
        }
        Group::Services => matches!(entry.origin, StartupOrigin::Service),
    }
}

pub fn matches_search(entry: &StartupEntry, search: &str) -> bool {
    search.is_empty()
        || [&entry.name, &entry.command, &entry.source, &entry.location]
            .iter()
            .any(|value| value.to_lowercase().contains(search))
        || entry
            .executable
            .as_ref()
            .is_some_and(|path| path.to_lowercase().contains(search))
}

pub fn nodes(entries: &[StartupEntry], search: &str) -> Vec<Node> {
    let mut counts = BTreeMap::<Group, usize>::new();
    let mut folders = BTreeSet::<String>::new();
    for entry in entries {
        if let StartupOrigin::Task { folder } = &entry.origin {
            folders.extend(task_folders(folder));
        }
        if matches_search(entry, search) {
            for group in memberships(entry) {
                *counts.entry(group).or_default() += 1;
            }
        }
    }
    let mut nodes = Vec::new();
    let mut indices = BTreeMap::<Group, usize>::new();
    let mut add = |group: Group, parent: Option<Group>, title: String| {
        let count = counts.get(&group).copied().unwrap_or(0);
        let parent = parent.and_then(|group| indices.get(&group).copied());
        indices.insert(group.clone(), nodes.len());
        nodes.push(Node {
            group,
            parent,
            title,
            count,
        });
    };
    add(Group::All, None, "Все источники".into());
    add(
        Group::Regular,
        Some(Group::All),
        "Обычная автозагрузка".into(),
    );
    add(
        Group::Registry,
        Some(Group::Regular),
        "Реестр Windows".into(),
    );
    for machine in [false, true] {
        add(
            Group::RegistryScope(machine),
            Some(Group::Registry),
            if machine {
                "Все пользователи · HKLM"
            } else {
                "Текущий пользователь · HKCU"
            }
            .into(),
        );
        for view32 in [false, true] {
            for once in [false, true] {
                add(
                    Group::RegistryKey {
                        machine,
                        view32,
                        once,
                    },
                    Some(Group::RegistryScope(machine)),
                    format!(
                        "{}{}{}",
                        if once { "RunOnce" } else { "Run" },
                        if view32 {
                            " · 32 бит"
                        } else {
                            " · 64 бит"
                        },
                        if once {
                            " · только чтение"
                        } else {
                            ""
                        }
                    ),
                );
            }
        }
    }
    add(
        Group::Folders,
        Some(Group::Regular),
        "Папки автозагрузки".into(),
    );
    for common in [false, true] {
        add(
            Group::Folder(common),
            Some(Group::Folders),
            if common {
                "Все пользователи"
            } else {
                "Текущий пользователь"
            }
            .into(),
        );
    }
    add(Group::Tasks, Some(Group::All), "Планировщик заданий".into());
    for folder in folders {
        let parent = if folder == "\\" {
            Group::Tasks
        } else {
            let split = folder.rfind('\\').unwrap_or(0);
            Group::TaskFolder(if split == 0 {
                "\\".into()
            } else {
                folder[..split].into()
            })
        };
        let title = if folder == "\\" {
            "Корневая папка".into()
        } else {
            folder.rsplit('\\').next().unwrap_or(&folder).into()
        };
        add(Group::TaskFolder(folder), Some(parent), title);
    }
    add(
        Group::Services,
        Some(Group::All),
        "Автоматические службы · только чтение".into(),
    );
    nodes
}

#[cfg(test)]
mod tests {
    use super::*;
    fn entry(origin: StartupOrigin, name: &str) -> StartupEntry {
        StartupEntry {
            id: name.into(),
            name: name.into(),
            source: "unrelated localized source".into(),
            location: "location".into(),
            command: "command".into(),
            enabled: true,
            can_toggle: false,
            icon_index: None,
            executable: None,
            added_at: None,
            startup_delay: StartupDelay::None,
            origin,
        }
    }
    #[test]
    fn grouping_uses_typed_origin_and_keeps_services_out_of_regular_startup() {
        let entries = vec![
            entry(
                StartupOrigin::Registry {
                    machine: true,
                    view32: true,
                    once: true,
                },
                "registry",
            ),
            entry(StartupOrigin::Folder { common: false }, "folder"),
            entry(StartupOrigin::Service, "service"),
        ];
        assert_eq!(
            entries
                .iter()
                .filter(|entry| matches_group(entry, &Group::Regular))
                .count(),
            2
        );
        assert!(matches_group(
            &entries[0],
            &Group::RegistryKey {
                machine: true,
                view32: true,
                once: true
            }
        ));
        let nodes = nodes(&entries, "registry");
        assert_eq!(
            nodes
                .iter()
                .find(|node| node.group == Group::All)
                .unwrap()
                .count,
            1
        );
        assert_eq!(
            nodes
                .iter()
                .find(|node| node.group == Group::Services)
                .unwrap()
                .count,
            0
        );
    }
    #[test]
    fn task_folders_have_parents_and_match_only_path_boundaries() {
        let task = entry(
            StartupOrigin::Task {
                folder: "\\Vendor\\Nested".into(),
            },
            "task",
        );
        assert!(matches_group(&task, &Group::TaskFolder("\\Vendor".into())));
        assert!(!matches_group(&task, &Group::TaskFolder("\\Ven".into())));
        let nodes = nodes(&[task], "");
        let index = nodes
            .iter()
            .position(|node| node.group == Group::TaskFolder("\\Vendor\\Nested".into()))
            .unwrap();
        assert_eq!(
            nodes[nodes[index].parent.unwrap()].group,
            Group::TaskFolder("\\Vendor".into())
        );
    }

    #[test]
    fn local_added_time_keeps_unknown_invalid_values_and_formats_valid_filetime() {
        assert_eq!(format_added_at(None), "—");
        assert_eq!(format_added_at(Some(u64::MAX)), "—");
        let epoch = format_added_at(Some(116_444_736_000_000_000));
        assert_eq!(epoch.len(), 16);
        assert_eq!(&epoch[2..3], ".");
        assert_eq!(&epoch[5..6], ".");
        assert_eq!(&epoch[10..11], " ");
        assert_eq!(&epoch[13..14], ":");
        assert!(
            epoch[..2]
                .parse::<u16>()
                .is_ok_and(|day| (1..=31).contains(&day))
        );
        assert!(
            epoch[3..5]
                .parse::<u16>()
                .is_ok_and(|month| (1..=12).contains(&month))
        );
        assert!(epoch[11..13].parse::<u16>().is_ok_and(|hour| hour < 24));
        assert!(epoch[14..].parse::<u16>().is_ok_and(|minute| minute < 60));
    }

    #[test]
    fn delay_cells_keep_shared_windows_scope_separate_from_tasks_and_unknown_values() {
        assert_eq!(delay_cell(&StartupDelay::None, None), ("—".into(), None));
        assert_eq!(
            delay_cell(&StartupDelay::Explorer, None),
            ("Windows: недоступно".into(), None)
        );
        assert_eq!(
            delay_cell(&StartupDelay::Explorer, Some(ExplorerDelay::default())),
            ("Windows: по умолчанию".into(), None)
        );
        assert_eq!(
            delay_cell(
                &StartupDelay::Explorer,
                Some(ExplorerDelay {
                    milliseconds: Some(1500),
                    wait_for_idle: Some(1)
                })
            ),
            ("Windows: 1500 мс".into(), Some(1500))
        );
        assert_eq!(
            delay_cell(
                &StartupDelay::Task {
                    seconds: Some(0),
                    editable: true
                },
                None
            ),
            ("Задача: без задержки".into(), Some(0))
        );
        assert_eq!(
            delay_cell(
                &StartupDelay::Task {
                    seconds: Some(u32::MAX),
                    editable: true
                },
                None
            )
            .1,
            Some(u64::from(u32::MAX) * 1000)
        );
        assert!(
            delay_cell(
                &StartupDelay::Task {
                    seconds: None,
                    editable: true
                },
                None
            )
            .0
            .contains("разная/неизвестна")
        );
        assert_eq!(
            delay_cell(
                &StartupDelay::Task {
                    seconds: None,
                    editable: false
                },
                None
            ),
            ("Задача: недоступно".into(), None)
        );
    }
}
