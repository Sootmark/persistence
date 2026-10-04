//! `rc.local` and shell start-up files: every line that isn't blank or a
//! comment, lines ending in a backslash joined as the shell joins them.
//! The shell's grammar isn't read: a here-document or a quoted string
//! spanning lines gives one entry per line, and `then`, `fi` or `}` are
//! entries like any other line.

use crate::text::{logical_lines, Continuation};
use crate::{Detail, Entry, Kind, Parsed};

/// Read a script of `kind`, run as or belonging to `account`.
pub(crate) fn script(text: &str, kind: Kind, account: Option<&str>) -> Parsed {
    let entries = logical_lines(text, Continuation::Shell)
        .into_iter()
        .filter_map(|(number, line)| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let mut entry = Entry::new(kind, number, Detail::ShellCommand);
            entry.user = account.map(str::to_owned);
            entry.command = Some(line.to_owned());
            Some(entry)
        })
        .collect();
    Parsed {
        entries,
        problems: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_lines() {
        let parsed = script(
            "#!/bin/sh -e\n\n# boot tasks\nnohup /usr/local/bin/x \\\n  --quiet &\nexit 0\n",
            Kind::RcLocal,
            Some("root"),
        );
        let commands: Vec<_> = parsed
            .entries
            .iter()
            .map(|e| (e.line, e.command.as_deref().unwrap_or_default()))
            .collect();
        assert_eq!(
            commands,
            [(4, "nohup /usr/local/bin/x   --quiet &"), (6, "exit 0")]
        );
        assert_eq!(parsed.entries[0].user.as_deref(), Some("root"));
    }
}
