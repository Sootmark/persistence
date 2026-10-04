//! sudoers: rules (`who host = (run-as) TAGS: commands`), aliases kept as
//! written, `Defaults` lines and includes, lines continued with a trailing
//! backslash, as sudoers(5) describes them.
//!
//! A rule's commands may switch run-as or tags midway (`/bin/a, (bob)
//! NOPASSWD: /bin/b`): the first run-as written is the rule's, and tags
//! anywhere are gathered for all its commands. A second host part
//! (`: host2 = …`) stays in the last command's text.

use crate::text::{logical_lines, split_list, split_word, unquote, Continuation};
use crate::{Detail, Entry, Kind, Parsed, SudoRule};

const ALIAS_KINDS: [&str; 5] = [
    "User_Alias",
    "Runas_Alias",
    "Host_Alias",
    "Cmnd_Alias",
    "Cmd_Alias",
];
/// Include directives, the directory ones first: they start with the
/// others.
const INCLUDES: [(&str, bool); 4] = [
    ("@includedir", true),
    ("#includedir", true),
    ("@include", false),
    ("#include", false),
];

/// Read sudoers.
pub(crate) fn rules(text: &str) -> Parsed {
    let mut parsed = Parsed::default();
    for (number, line) in logical_lines(text, Continuation::Shell) {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let details = if let Some(include) = include(line) {
            vec![include]
        } else if is_comment(line) {
            continue;
        } else if let Some(defaults) = defaults(line) {
            vec![defaults]
        } else if let Some(aliases) = aliases(line) {
            aliases
        } else if let Some(rule) = rule(line) {
            vec![rule]
        } else {
            parsed.problem(number, "not a sudoers line");
            continue;
        };
        for detail in details {
            parsed.entries.push(entry(number, detail));
        }
    }
    parsed
}

fn entry(number: usize, detail: Detail) -> Entry {
    let (user, command) = match &detail {
        Detail::SudoRule(rule) => (Some(rule.users.join(", ")), Some(rule.commands.join(", "))),
        _ => (None, None),
    };
    let mut entry = Entry::new(Kind::Sudoers, number, detail);
    entry.user = user;
    entry.command = command;
    entry
}

/// `#` starts a comment, except `#` and digits: a uid.
fn is_comment(line: &str) -> bool {
    line.strip_prefix('#')
        .is_some_and(|rest| !rest.starts_with(|c: char| c.is_ascii_digit()))
}

fn include(line: &str) -> Option<Detail> {
    INCLUDES.iter().find_map(|&(directive, directory)| {
        let path = line.strip_prefix(directive)?;
        path.starts_with(char::is_whitespace)
            .then(|| Detail::SudoInclude {
                path: unquote(path.trim()).to_owned(),
                directory,
            })
    })
}

/// `Defaults[:@>!scope] settings`.
fn defaults(line: &str) -> Option<Detail> {
    let rest = line.strip_prefix("Defaults")?;
    let (scope, settings) = if rest.starts_with([':', '@', '>', '!']) {
        let (scope, settings) = split_word(rest);
        (Some(scope.to_owned()), settings)
    } else if rest.starts_with(char::is_whitespace) {
        (None, rest.trim_start())
    } else {
        return None;
    };
    Some(Detail::SudoDefaults {
        scope,
        settings: settings.to_owned(),
    })
}

/// `Cmnd_Alias NAME = a, b : OTHER = c`: one entry per alias.
fn aliases(line: &str) -> Option<Vec<Detail>> {
    let (alias_kind, rest) = split_word(line);
    if !ALIAS_KINDS.contains(&alias_kind) {
        return None;
    }
    split_definitions(rest)
        .into_iter()
        .map(|definition| {
            let (name, members) = definition.split_once('=')?;
            let name = name.trim();
            (!name.is_empty()).then(|| Detail::SudoAlias {
                alias_kind: alias_kind.to_owned(),
                name: name.to_owned(),
                members: split_list(members),
            })
        })
        .collect()
}

/// Definitions separated by `:`, where what follows is `NAME =`.
fn split_definitions(text: &str) -> Vec<&str> {
    let mut definitions = Vec::new();
    let mut start = 0;
    for (at, _) in text.match_indices(':') {
        let next = text[at + 1..].trim_start();
        let name_length = next
            .find(|c: char| !(c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'))
            .unwrap_or(next.len());
        if name_length > 0 && next[name_length..].trim_start().starts_with('=') {
            definitions.push(&text[start..at]);
            start = at + 1;
        }
    }
    definitions.push(&text[start..]);
    definitions
}

/// `users hosts = cmnd-spec, cmnd-spec`.
fn rule(line: &str) -> Option<Detail> {
    let (who, specs) = line.split_once('=')?;
    let mut lists = lists(who).into_iter();
    let (Some(users), Some(hosts), None) = (lists.next(), lists.next(), lists.next()) else {
        return None;
    };
    let mut rule = SudoRule {
        users: split_list(&users),
        hosts: split_list(&hosts),
        run_as: None,
        tags: Vec::new(),
        commands: Vec::new(),
    };
    for spec in split_list(specs) {
        command_spec(&spec, &mut rule);
    }
    (!rule.commands.is_empty()).then_some(Detail::SudoRule(rule))
}

/// Comma-separated lists separated by white space: `alice, bob ALL` is
/// `alice,bob` and `ALL`.
fn lists(text: &str) -> Vec<String> {
    let mut lists: Vec<String> = Vec::new();
    for word in text.split_whitespace() {
        match lists.last_mut() {
            Some(last) if last.ends_with(',') || word.starts_with(',') => last.push_str(word),
            _ => lists.push(word.to_owned()),
        }
    }
    lists
}

/// `(run-as) TAG: TAG: OPTION=value command`: the command, the run-as and
/// tags gathered into the rule.
fn command_spec(spec: &str, rule: &mut SudoRule) {
    let mut rest = spec.trim();
    if let Some((run_as, after)) = rest.strip_prefix('(').and_then(|r| r.split_once(')')) {
        rule.run_as.get_or_insert_with(|| run_as.trim().to_owned());
        rest = after.trim_start();
    }
    while let Some((tag, after)) = leading_tag(rest) {
        if !rule.tags.iter().any(|t| t == tag) {
            rule.tags.push(tag.to_owned());
        }
        rest = after;
    }
    if !rest.is_empty() {
        rule.commands.push(rest.to_owned());
    }
}

/// `NOPASSWD:` or `CWD=/srv` at the start of `text`, and what follows.
fn leading_tag(text: &str) -> Option<(&str, &str)> {
    let name_length = text
        .find(|c: char| !(c.is_ascii_uppercase() || c == '_'))
        .filter(|&length| length > 0)?;
    match text[name_length..].chars().next()? {
        ':' => Some((&text[..name_length], text[name_length + 1..].trim_start())),
        '=' => {
            let (option, after) = split_word(text);
            Some((option, after))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule_of(line: &str) -> SudoRule {
        match rule(line) {
            Some(Detail::SudoRule(rule)) => rule,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn rules_with_run_as_and_tags() {
        let rule =
            rule_of("alice, %ops  ALL = (root) NOPASSWD: SETENV: /usr/bin/apt, (bob) /bin/ls");
        assert_eq!(rule.users, ["alice", "%ops"]);
        assert_eq!(rule.hosts, ["ALL"]);
        assert_eq!(rule.run_as.as_deref(), Some("root"));
        assert_eq!(rule.tags, ["NOPASSWD", "SETENV"]);
        assert_eq!(rule.commands, ["/usr/bin/apt", "/bin/ls"]);
        let rule = rule_of("#1001 ALL=(ALL:ALL) CWD=/srv ALL");
        assert_eq!(rule.users, ["#1001"]);
        assert_eq!(rule.tags, ["CWD=/srv"]);
        assert_eq!(rule.commands, ["ALL"]);
    }

    #[test]
    fn lines_of_every_kind() {
        let parsed = rules(
            "# comment\nDefaults:alice !authenticate\nDefaults\tenv_reset\n\
             Cmnd_Alias SHELLS = /bin/sh, /bin/bash : NET = /usr/bin/nc\n\
             alice ALL=(ALL) \\\n  NOPASSWD: ALL\n@includedir /etc/sudoers.d\n\
             #include \"/etc/sudoers.local\"\nnonsense\n",
        );
        let details: Vec<_> = parsed.entries.iter().map(|e| (e.line, &e.detail)).collect();
        assert_eq!(details.len(), 7);
        assert_eq!(
            details[0].1,
            &Detail::SudoDefaults {
                scope: Some(":alice".to_owned()),
                settings: "!authenticate".to_owned()
            }
        );
        assert_eq!(
            details[3].1,
            &Detail::SudoAlias {
                alias_kind: "Cmnd_Alias".to_owned(),
                name: "NET".to_owned(),
                members: vec!["/usr/bin/nc".to_owned()]
            }
        );
        let rule = &parsed.entries[4];
        assert_eq!(rule.line, 5);
        assert_eq!(rule.user.as_deref(), Some("alice"));
        assert_eq!(rule.command.as_deref(), Some("ALL"));
        assert_eq!(
            details[5].1,
            &Detail::SudoInclude {
                path: "/etc/sudoers.d".to_owned(),
                directory: true
            }
        );
        assert_eq!(
            details[6].1,
            &Detail::SudoInclude {
                path: "/etc/sudoers.local".to_owned(),
                directory: false
            }
        );
        assert_eq!(parsed.problems, ["line 9: not a sudoers line"]);
    }
}
