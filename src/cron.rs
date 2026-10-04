//! Crontabs: users' (`var/spool/cron/crontabs/<user>`), the system's
//! (`etc/crontab`, `etc/cron.d/*`, with an account between schedule and
//! command), and anacron's `etc/anacrontab`.
//!
//! cron reads a line at a time: a trailing backslash doesn't continue a
//! line, it stays in the command. An unescaped `%` in a command ends what
//! the shell runs (the rest is fed to its input); the command is kept as
//! written.

use crate::text::{numbered, split_word, unquote};
use crate::{Detail, Entry, Kind, Parsed};

/// Schedules written as a word.
const NICKNAMES: [&str; 8] = [
    "@reboot",
    "@yearly",
    "@annually",
    "@monthly",
    "@weekly",
    "@daily",
    "@midnight",
    "@hourly",
];

/// A crontab's form.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Form<'a> {
    /// A user's: jobs run as the account named (the file's name).
    User(Option<&'a str>),
    /// The system's: each job names its account.
    System,
}

/// Read a crontab.
pub(crate) fn crontab(text: &str, form: Form<'_>) -> Parsed {
    let kind = match form {
        Form::User(_) => Kind::Crontab,
        Form::System => Kind::SystemCrontab,
    };
    let mut parsed = Parsed::default();
    for (number, line) in content_lines(text) {
        if let Some(entry) = environment(kind, number, line) {
            parsed.entries.push(entry);
            continue;
        }
        match job(kind, number, line, form) {
            Ok(entry) => parsed.entries.push(entry),
            Err(what) => parsed.problem(number, what),
        }
    }
    parsed
}

/// Read anacron's table: `period delay id command`, run as root.
pub(crate) fn anacrontab(text: &str) -> Parsed {
    let mut parsed = Parsed::default();
    for (number, line) in content_lines(text) {
        if let Some(entry) = environment(Kind::Anacrontab, number, line) {
            parsed.entries.push(entry);
            continue;
        }
        match anacron_job(number, line) {
            Ok(entry) => parsed.entries.push(entry),
            Err(what) => parsed.problem(number, what),
        }
    }
    parsed
}

/// Lines that aren't blank or comments, trimmed.
fn content_lines(text: &str) -> impl Iterator<Item = (usize, &str)> {
    numbered(text)
        .map(|(number, line)| (number, line.trim()))
        .filter(|(_, line)| !line.is_empty() && !line.starts_with('#'))
}

/// `NAME=value`, as cron tells it from a job: a single word before `=`.
fn environment(kind: Kind, number: usize, line: &str) -> Option<Entry> {
    let (name, value) = line.split_once('=')?;
    let name = unquote(name.trim());
    if name.is_empty() || name.contains(char::is_whitespace) {
        return None;
    }
    let detail = Detail::Environment {
        name: name.to_owned(),
        value: unquote(value.trim()).to_owned(),
    };
    Some(Entry::new(kind, number, detail))
}

fn job(kind: Kind, number: usize, line: &str, form: Form<'_>) -> Result<Entry, &'static str> {
    let (schedule, rest) = schedule(line).ok_or("not a cron job")?;
    let (user, command) = match form {
        Form::User(owner) => (owner, rest),
        Form::System => {
            let (user, command) = split_word(rest);
            (Some(user).filter(|u| !u.is_empty()), command)
        }
    };
    if command.is_empty() {
        return Err("a cron job without a command");
    }
    let mut entry = Entry::new(kind, number, Detail::CronJob);
    entry.schedule = Some(schedule);
    entry.user = user.map(str::to_owned);
    entry.command = Some(command.to_owned());
    Ok(entry)
}

/// The schedule (`@daily`, or five time fields joined by a space) and the
/// rest of the line.
fn schedule(line: &str) -> Option<(String, &str)> {
    let (first, mut rest) = split_word(line);
    if first.starts_with('@') {
        return NICKNAMES.contains(&first).then(|| (first.to_owned(), rest));
    }
    let mut fields = vec![first];
    while fields.len() < 5 {
        let (field, after) = split_word(rest);
        fields.push(field);
        rest = after;
    }
    fields
        .iter()
        .all(|f| is_time_field(f))
        .then(|| (fields.join(" "), rest))
}

/// `*`, `5`, `1-5`, `*/10`, `mon,wed`, cronie's `~` (random).
fn is_time_field(field: &str) -> bool {
    !field.is_empty()
        && field
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "*,-/~".contains(c))
}

fn anacron_job(number: usize, line: &str) -> Result<Entry, &'static str> {
    let (period, rest) = split_word(line);
    let (delay, rest) = split_word(rest);
    let (id, command) = split_word(rest);
    let is_period = period.starts_with('@') || period.bytes().all(|b| b.is_ascii_digit());
    if !is_period {
        return Err("not an anacron job");
    }
    let delay_minutes = delay
        .parse()
        .map_err(|_| "an anacron job without a delay")?;
    if command.is_empty() {
        return Err("an anacron job without a command");
    }
    let detail = Detail::AnacronJob {
        delay_minutes,
        id: id.to_owned(),
    };
    let mut entry = Entry::new(Kind::Anacrontab, number, detail);
    entry.schedule = Some(period.to_owned());
    entry.user = Some("root".to_owned());
    entry.command = Some(command.to_owned());
    Ok(entry)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(text: &str, form: Form<'_>) -> Entry {
        let parsed = crontab(text, form);
        assert!(parsed.problems.is_empty(), "{:?}", parsed.problems);
        parsed.entries.into_iter().next().unwrap()
    }

    #[test]
    fn user_jobs_run_as_the_owner() {
        let entry = one(
            "*/5 * * * * /tmp/.x/run.sh >/dev/null 2>&1",
            Form::User(Some("alice")),
        );
        assert_eq!(entry.schedule.as_deref(), Some("*/5 * * * *"));
        assert_eq!(entry.user.as_deref(), Some("alice"));
        assert_eq!(
            entry.command.as_deref(),
            Some("/tmp/.x/run.sh >/dev/null 2>&1")
        );
    }

    #[test]
    fn system_jobs_name_their_account() {
        let entry = one("@reboot\troot   sleep 30 && /usr/local/bin/x", Form::System);
        assert_eq!(entry.schedule.as_deref(), Some("@reboot"));
        assert_eq!(entry.user.as_deref(), Some("root"));
        assert_eq!(
            entry.command.as_deref(),
            Some("sleep 30 && /usr/local/bin/x")
        );
    }

    #[test]
    fn environment_lines_are_kept() {
        let entry = one("MAILTO = \"\"", Form::System);
        assert_eq!(
            entry.detail,
            Detail::Environment {
                name: "MAILTO".to_owned(),
                value: String::new()
            }
        );
        // `=` in a job's command doesn't make it a variable.
        let entry = one("0 0 * * * root FOO=1 /bin/run", Form::System);
        assert_eq!(entry.detail, Detail::CronJob);
    }

    /// As Debian's cron 3.0pl1 checks it (`crontab -n`): the first line is
    /// a job, the second "bad minute".
    #[test]
    fn a_trailing_backslash_does_not_continue() {
        let parsed = crontab("* * * * * echo a \\\necho b\n", Form::User(None));
        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(parsed.entries[0].command.as_deref(), Some("echo a \\"));
        assert_eq!(parsed.problems, ["line 2: not a cron job"]);
    }

    #[test]
    fn damaged_lines_are_problems() {
        let parsed = crontab("@sometimes root x\n1 2 3\n* * * * * root\n", Form::System);
        assert!(parsed.entries.is_empty());
        assert_eq!(
            parsed.problems,
            [
                "line 1: not a cron job",
                "line 2: not a cron job",
                "line 3: a cron job without a command",
            ]
        );
    }

    #[test]
    fn anacron_jobs() {
        let parsed = anacrontab(
            "@monthly\t15\tcron.monthly\trun-parts /etc/cron.monthly\nx 1 y z\n1 soon id c\n",
        );
        let entry = &parsed.entries[0];
        assert_eq!(entry.schedule.as_deref(), Some("@monthly"));
        assert_eq!(entry.user.as_deref(), Some("root"));
        assert_eq!(
            entry.detail,
            Detail::AnacronJob {
                delay_minutes: 15,
                id: "cron.monthly".to_owned()
            }
        );
        assert_eq!(
            parsed.problems,
            [
                "line 2: not an anacron job",
                "line 3: an anacron job without a delay"
            ]
        );
    }
}
