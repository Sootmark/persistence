//! systemd units and drop-ins: `[Section]` headers and `Key=value`
//! settings, lines continued with a trailing backslash, `#` and `;`
//! comments. Every setting is an entry; the `Exec…=` commands are the
//! entry's command and timers' triggers its schedule.

use crate::text::{logical_lines, Continuation};
use crate::{Detail, Entry, Kind, Parsed};

/// Settings whose value is a command line.
const EXEC_KEYS: [&str; 7] = [
    "ExecCondition",
    "ExecStartPre",
    "ExecStart",
    "ExecStartPost",
    "ExecReload",
    "ExecStop",
    "ExecStopPost",
];
/// Timer settings that say when the unit runs.
const TIMER_KEYS: [&str; 6] = [
    "OnCalendar",
    "OnBootSec",
    "OnStartupSec",
    "OnActiveSec",
    "OnUnitActiveSec",
    "OnUnitInactiveSec",
];
/// Characters that may precede an `Exec…=` command.
const EXEC_PREFIXES: [char; 5] = ['-', '@', ':', '+', '!'];

/// Read a unit or a drop-in. `owner` is the account whose home a user
/// unit is in: its commands run as them.
pub(crate) fn unit(text: &str, owner: Option<&str>) -> Parsed {
    let mut parsed = Parsed::default();
    let mut section: Option<String> = None;
    for (number, line) in logical_lines(text, Continuation::Systemd) {
        let line = line.trim();
        if line.is_empty() || line.starts_with(['#', ';']) {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = Some(name.to_owned());
            continue;
        }
        let Some(section) = &section else {
            parsed.problem(number, "a setting outside a section");
            continue;
        };
        let Some((key, value)) = line.split_once('=') else {
            parsed.problem(number, "not a setting");
            continue;
        };
        parsed
            .entries
            .push(setting(number, section, key.trim(), value.trim()));
    }
    let run_as = service_user(&parsed.entries).or(owner).map(str::to_owned);
    for entry in &mut parsed.entries {
        if is_exec(entry) {
            entry.user.clone_from(&run_as);
        }
    }
    parsed
}

fn setting(number: usize, section: &str, key: &str, value: &str) -> Entry {
    let is_exec_key = EXEC_KEYS.contains(&key);
    let command = if is_exec_key {
        value.trim_start_matches(EXEC_PREFIXES)
    } else {
        value
    };
    let exec_prefixes = &value[..value.len() - command.len()];
    let detail = Detail::UnitSetting {
        section: section.to_owned(),
        key: key.to_owned(),
        value: value.to_owned(),
        exec_prefixes: exec_prefixes.to_owned(),
    };
    let mut entry = Entry::new(Kind::SystemdUnit, number, detail);
    if is_exec_key && !command.is_empty() {
        entry.command = Some(command.trim_start().to_owned());
    }
    if TIMER_KEYS.contains(&key) && !value.is_empty() {
        entry.schedule = Some(value.to_owned());
    }
    entry
}

/// `User=` in `[Service]`: the last one written.
fn service_user(entries: &[Entry]) -> Option<&str> {
    entries.iter().rev().find_map(|entry| match &entry.detail {
        Detail::UnitSetting {
            section,
            key,
            value,
            ..
        } if section == "Service" && key == "User" && !value.is_empty() => Some(value.as_str()),
        _ => None,
    })
}

fn is_exec(entry: &Entry) -> bool {
    matches!(&entry.detail, Detail::UnitSetting { key, .. } if EXEC_KEYS.contains(&key.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setting_of(entry: &Entry) -> (&str, &str, &str, &str) {
        match &entry.detail {
            Detail::UnitSetting {
                section,
                key,
                value,
                exec_prefixes,
            } => (section, key, value, exec_prefixes),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn commands_prefixes_and_user() {
        let parsed = unit(
            "[Unit]\nDescription=x\n[Service]\nExecStartPre=-+/bin/true\n\
             ExecStart=/usr/bin/env \\\n  bash -c 'id'\nUser=svc\nExecStop=\n",
            None,
        );
        assert!(parsed.problems.is_empty());
        let pre = &parsed.entries[1];
        assert_eq!(
            setting_of(pre),
            ("Service", "ExecStartPre", "-+/bin/true", "-+")
        );
        assert_eq!(pre.command.as_deref(), Some("/bin/true"));
        assert_eq!(pre.user.as_deref(), Some("svc"));
        let start = &parsed.entries[2];
        assert_eq!(start.line, 5);
        assert_eq!(
            start.command.as_deref(),
            Some("/usr/bin/env    bash -c 'id'")
        );
        // `ExecStop=` empties the list: no command.
        assert_eq!(parsed.entries[4].command, None);
        // Settings that aren't commands don't run as anyone.
        assert_eq!(parsed.entries[0].user, None);
    }

    #[test]
    fn user_units_run_as_their_owner() {
        let parsed = unit(
            "[Service]\nExecStart=/home/alice/.local/bin/agent\n",
            Some("alice"),
        );
        assert_eq!(parsed.entries[0].user.as_deref(), Some("alice"));
    }

    #[test]
    fn timers_have_a_schedule() {
        let parsed = unit("[Timer]\nOnBootSec=5min\nUnit=x.service\n", None);
        assert_eq!(parsed.entries[0].schedule.as_deref(), Some("5min"));
        assert_eq!(parsed.entries[1].schedule, None);
    }

    #[test]
    fn damaged_lines_are_problems() {
        let parsed = unit("Orphan=1\n[Service]\njust words\n[Broken\n", None);
        assert!(parsed.entries.is_empty());
        assert_eq!(
            parsed.problems,
            [
                "line 1: a setting outside a section",
                "line 3: not a setting",
                "line 4: not a setting",
            ]
        );
    }
}
