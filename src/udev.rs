//! udev rules (`etc/udev/rules.d/*.rules`, `usr/lib/udev/rules.d`, …):
//! each rule is a line of comma-separated `KEY{attribute}op"value"` pairs,
//! continued with a trailing backslash. Pairs comparing (`==`, `!=`) say
//! which devices it applies to; the others act. What a rule runs, the
//! entry's command, is its `RUN` (not `RUN{builtin}`), `PROGRAM` and
//! `IMPORT{program}` values: udev runs them as root when a matching device
//! appears, a way to run code at boot or when a USB key is plugged in.

use crate::text::{logical_lines, Continuation};
use crate::{Detail, Entry, Kind, Parsed, UdevPair};

/// Read a rules file.
pub(crate) fn rules(text: &str) -> Parsed {
    let mut parsed = Parsed::default();
    for (number, line) in logical_lines(text, Continuation::Shell) {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match pairs(line) {
            Some(pairs) => parsed.entries.push(rule(number, pairs)),
            None => parsed.problem(number, "not a udev rule"),
        }
    }
    parsed
}

fn rule(number: usize, pairs: Vec<UdevPair>) -> Entry {
    let commands: Vec<&str> = pairs
        .iter()
        .filter(|pair| runs(pair))
        .map(|pair| pair.value.as_str())
        .collect();
    let command = (!commands.is_empty()).then(|| commands.join("; "));
    let mut entry = Entry::new(Kind::Udev, number, Detail::UdevRule(pairs));
    entry.user = command.as_ref().map(|_| "root".to_owned());
    entry.command = command;
    entry
}

/// Whether a pair names a program udev runs.
fn runs(pair: &UdevPair) -> bool {
    let attribute = pair.attribute.as_deref();
    match pair.key.as_str() {
        "RUN" => attribute.is_none() || attribute == Some("program"),
        "PROGRAM" => true,
        "IMPORT" => attribute == Some("program"),
        _ => false,
    }
}

/// A rule's pairs, or `None` when the line isn't one.
fn pairs(line: &str) -> Option<Vec<UdevPair>> {
    let mut pairs = Vec::new();
    let mut rest = line;
    loop {
        rest = rest.trim_start_matches(|c: char| c == ',' || c.is_whitespace());
        if rest.is_empty() {
            break;
        }
        let (pair, after) = pair(rest)?;
        pairs.push(pair);
        rest = after;
    }
    (!pairs.is_empty()).then_some(pairs)
}

/// `KEY{attribute}op"value"` at the start of `text`, and what follows.
fn pair(text: &str) -> Option<(UdevPair, &str)> {
    let key_end = text.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))?;
    let (key, rest) = text.split_at(key_end);
    if key.is_empty() {
        return None;
    }
    let (attribute, rest) = match rest.strip_prefix('{') {
        Some(inside) => {
            let (attribute, rest) = inside.split_once('}')?;
            (Some(attribute.to_owned()), rest)
        }
        None => (None, rest),
    };
    let rest = rest.trim_start();
    let operator = ["==", "!=", "+=", "-=", ":=", "="]
        .into_iter()
        .find(|op| rest.starts_with(op))?;
    let (value, rest) = quoted(rest[operator.len()..].trim_start())?;
    let pair = UdevPair {
        key: key.to_owned(),
        attribute,
        operator: operator.to_owned(),
        value,
    };
    Some((pair, rest))
}

/// A double-quoted value (`\"` escapes a quote), and what follows it.
fn quoted(text: &str) -> Option<(String, &str)> {
    let inside = text.strip_prefix('"')?;
    let mut value = String::new();
    let mut chars = inside.char_indices();
    while let Some((at, c)) = chars.next() {
        match c {
            '"' => return Some((value, &inside[at + 1..])),
            '\\' => {
                let (_, next) = chars.next()?;
                if next != '"' {
                    value.push('\\');
                }
                value.push(next);
            }
            _ => value.push(c),
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_actions_and_commands() {
        let parsed = rules(
            "# keyboard\n\
             ACTION==\"add\", SUBSYSTEM==\"usb\", ATTR{idVendor}==\"1d6b\", \\\n  RUN+=\"/usr/local/bin/x --q\", RUN{builtin}+=\"kmod load\"\n\
             KERNEL==\"sd*\", PROGRAM==\"/lib/udev/scsi_id -g\", IMPORT{program}=\"ata_id $devnode\", SYMLINK+=\"disk/%c\"\n\
             ENV{X}=\"a \\\"b\\\"\"\n\
             not a rule\n",
        );
        assert_eq!(parsed.problems, ["line 6: not a udev rule"]);
        let commands: Vec<_> = parsed
            .entries
            .iter()
            .map(|e| e.command.as_deref())
            .collect();
        assert_eq!(
            commands,
            [
                Some("/usr/local/bin/x --q"),
                Some("/lib/udev/scsi_id -g; ata_id $devnode"),
                None
            ]
        );
        assert_eq!(parsed.entries[0].line, 2);
        assert_eq!(parsed.entries[0].user.as_deref(), Some("root"));
        let Detail::UdevRule(pairs) = &parsed.entries[2].detail else {
            panic!("a rule")
        };
        assert_eq!(pairs[0].value, "a \"b\"");
        assert_eq!(pairs[0].attribute.as_deref(), Some("X"));
    }
}
