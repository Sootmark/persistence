//! XDG autostart entries (`etc/xdg/autostart/*.desktop`, a home's
//! `.config/autostart/*.desktop`): desktop sessions (GNOME, KDE, Xfce…)
//! start their `Exec=` command when the account logs in, unless the entry
//! is `Hidden=true` or `X-GNOME-Autostart-enabled=false`. One entry per
//! `Exec=` line of the `[Desktop Entry]` group.

use crate::text::numbered;
use crate::{Detail, Entry, Kind, Parsed};

const GROUP: &str = "Desktop Entry";

/// Read a `.desktop` file, belonging to `owner` when in a home.
pub(crate) fn entry(text: &str, owner: Option<&str>) -> Parsed {
    let mut parsed = Parsed::default();
    let mut group: Option<&str> = None;
    let (mut name, mut disabled) = (None, false);
    let mut commands = Vec::new();
    for (number, line) in numbered(text) {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(header) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            group = Some(header);
            continue;
        }
        if group != Some(GROUP) {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            parsed.problem(number, "not a key=value line");
            continue;
        };
        match (key.trim(), value.trim()) {
            ("Exec", command) => commands.push((number, command.to_owned())),
            ("Name", value) => name = Some(value.to_owned()),
            ("Hidden", "true") | ("X-GNOME-Autostart-enabled", "false") => disabled = true,
            _ => {}
        }
    }
    for (number, command) in commands {
        let detail = Detail::Autostart {
            name: name.clone(),
            disabled,
        };
        let mut entry = Entry::new(Kind::XdgAutostart, number, detail);
        entry.user = owner.map(str::to_owned);
        entry.command = Some(command);
        parsed.entries.push(entry);
    }
    parsed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exec_lines_of_the_desktop_entry_group() {
        let parsed = entry(
            "[Desktop Entry]\nType=Application\nName=Updater\nExec=/home/alice/.local/bin/upd --bg\nX-GNOME-Autostart-enabled=false\n[Desktop Action x]\nExec=other\n",
            Some("alice"),
        );
        assert_eq!(parsed.entries.len(), 1);
        let entry = &parsed.entries[0];
        assert_eq!(
            (entry.line, entry.command.as_deref(), entry.user.as_deref()),
            (4, Some("/home/alice/.local/bin/upd --bg"), Some("alice"))
        );
        assert_eq!(
            entry.detail,
            Detail::Autostart {
                name: Some("Updater".to_owned()),
                disabled: true
            }
        );
    }
}
