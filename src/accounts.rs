//! The account files: `etc/passwd` (who may log in, with which id and
//! shell), `etc/shadow` (the state of each password: never its hash) and
//! `etc/group` (who is in which group). An account added for later is
//! the oldest way to keep access; its traces are a second id 0, a system
//! account given a shell, a password left empty, an unexpected member of
//! `sudo` or `wheel`, and the day a password last changed.

use crate::{Detail, Entry, Kind, Parsed};

/// Shells that refuse a login, or run one command and end (Red Hat's
/// `shutdown` and `halt` accounts).
const NO_LOGIN: [&str; 10] = [
    "/usr/sbin/nologin",
    "/sbin/nologin",
    "/usr/bin/nologin",
    "/bin/false",
    "/usr/bin/false",
    "/bin/sync",
    "/sbin/shutdown",
    "/usr/sbin/shutdown",
    "/sbin/halt",
    "/usr/sbin/halt",
];
/// Days from 1970-01-01 to 0000-03-01, for the civil date of a day count.
const DAYS_TO_EPOCH: i64 = 719_468;

/// An account of `etc/passwd`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    /// Its id; 0 is root's power, whatever the name.
    pub uid: Option<u32>,
    /// Its primary group's id.
    pub gid: Option<u32>,
    /// The comment field (often the person's name).
    pub gecos: String,
    /// Its home.
    pub home: String,
    /// What runs when it logs in.
    pub shell: String,
    /// The password field is empty, not `x`: no password at all, without
    /// looking at `etc/shadow`.
    pub empty_password: bool,
}

impl Account {
    /// Whether its shell lets it log in (not `nologin`, `false`, `sync`,
    /// or none).
    #[must_use]
    pub fn can_log_in(&self) -> bool {
        !self.shell.is_empty() && !NO_LOGIN.contains(&self.shell.as_str())
    }
}

/// The state of an account's password, from `etc/shadow`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Password {
    /// What the password field holds, never the hash itself.
    pub state: PasswordState,
    /// The day it last changed (`2026-10-04`, UTC); `None` when not set.
    /// Set when the account is created, so for an account never changed
    /// since, its creation day.
    pub last_change: Option<String>,
    /// The day the account expires, if it does.
    pub expires: Option<String>,
}

/// What a shadow password field holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PasswordState {
    /// Empty: no password needed, where PAM allows it (`nullok`).
    Empty,
    /// `*` or `!` alone: no password can match; logins by key still work.
    NoPassword,
    /// A hash behind `!`: locked (`passwd -l`), the hash kept.
    Locked,
    /// A hash: the account logs in with a password. Its scheme
    /// (`yescrypt`, `sha512crypt`, …) as the hash's prefix names it.
    Hash(&'static str),
}

impl PasswordState {
    /// A short label: `empty`, `no password`, `locked`, or the scheme.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::NoPassword => "no password",
            Self::Locked => "locked",
            Self::Hash(scheme) => scheme,
        }
    }
}

/// `etc/passwd`: `name:password:uid:gid:gecos:home:shell`.
pub(crate) fn passwd(text: &str) -> Parsed {
    let mut parsed = Parsed::default();
    for (index, line) in records(text) {
        let fields: Vec<&str> = line.split(':').collect();
        let [name, password, uid, gid, gecos, home, shell] = fields[..] else {
            parsed.problem(index + 1, "not seven fields");
            continue;
        };
        let account = Account {
            uid: uid.parse().ok(),
            gid: gid.parse().ok(),
            gecos: gecos.to_owned(),
            home: home.to_owned(),
            shell: shell.to_owned(),
            empty_password: password.is_empty(),
        };
        let mut entry = Entry::new(Kind::Passwd, index + 1, Detail::Account(account));
        entry.user = Some(name.to_owned());
        parsed.entries.push(entry);
    }
    parsed
}

/// `etc/shadow`: `name:password:last change:min:max:warn:inactive:expire:`.
pub(crate) fn shadow(text: &str) -> Parsed {
    let mut parsed = Parsed::default();
    for (index, line) in records(text) {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() < 2 {
            parsed.problem(index + 1, "not a shadow line");
            continue;
        }
        let day = |at: usize| {
            fields
                .get(at)
                .and_then(|days| days.parse::<i64>().ok())
                .and_then(civil_date)
        };
        let password = Password {
            state: state(fields[1]),
            last_change: day(2),
            expires: day(7),
        };
        let mut entry = Entry::new(Kind::Shadow, index + 1, Detail::Password(password));
        entry.user = Some(fields[0].to_owned());
        parsed.entries.push(entry);
    }
    parsed
}

/// `etc/group`: `name:password:gid:member,member`; one entry per group
/// with members (who is in a group is the question; empty groups are
/// most of the file).
pub(crate) fn group(text: &str) -> Parsed {
    let mut parsed = Parsed::default();
    for (index, line) in records(text) {
        let fields: Vec<&str> = line.split(':').collect();
        let [name, _, gid, members] = fields[..] else {
            parsed.problem(index + 1, "not four fields");
            continue;
        };
        let members: Vec<String> = members
            .split(',')
            .map(str::trim)
            .filter(|m| !m.is_empty())
            .map(str::to_owned)
            .collect();
        if members.is_empty() {
            continue;
        }
        let detail = Detail::Group {
            name: name.to_owned(),
            gid: gid.parse().ok(),
            members,
        };
        parsed
            .entries
            .push(Entry::new(Kind::Group, index + 1, detail));
    }
    parsed
}

/// The lines that hold a record, with their index: not blank, not a
/// comment, not NIS's `+`/`-` includes.
fn records(text: &str) -> impl Iterator<Item = (usize, &str)> {
    text.lines()
        .enumerate()
        .map(|(index, line)| (index, line.trim_end_matches('\r')))
        .filter(|(_, line)| {
            !line.trim().is_empty() && !line.starts_with('#') && !line.starts_with(['+', '-'])
        })
}

fn state(field: &str) -> PasswordState {
    match field {
        "" => PasswordState::Empty,
        "*" | "!" | "!!" | "!*" | "*LK*" => PasswordState::NoPassword,
        locked if locked.starts_with('!') => PasswordState::Locked,
        hash => PasswordState::Hash(scheme(hash)),
    }
}

/// The scheme a crypt(3) hash's prefix names.
fn scheme(hash: &str) -> &'static str {
    let prefix = hash
        .strip_prefix('$')
        .and_then(|rest| rest.split('$').next())
        .unwrap_or("");
    match prefix {
        "y" => "yescrypt",
        "gy" => "gost-yescrypt",
        "7" => "scrypt",
        "2a" | "2b" | "2x" | "2y" => "bcrypt",
        "6" => "sha512crypt",
        "5" => "sha256crypt",
        "1" => "md5crypt",
        "" if hash.len() == 13 => "descrypt",
        _ => "other",
    }
}

/// Days since 1970-01-01 as a civil date (`2026-10-04`); `None` for 0 and
/// below (unset, or "change at next login") and absurd counts.
fn civil_date(days: i64) -> Option<String> {
    if !(1..=2_932_896).contains(&days) {
        return None;
    }
    // Howard Hinnant's days-from-civil, inverted.
    let z = days + DAYS_TO_EPOCH;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    Some(format!("{year:04}-{month:02}-{day:02}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn days_are_dates() {
        assert_eq!(civil_date(1).as_deref(), Some("1970-01-02"));
        assert_eq!(civil_date(20_000).as_deref(), Some("2024-10-04"));
        assert_eq!(civil_date(11_016).as_deref(), Some("2000-02-29"));
        assert_eq!(civil_date(0), None);
        assert_eq!(civil_date(-1), None);
    }

    #[test]
    fn password_states_never_keep_the_hash() {
        assert_eq!(state(""), PasswordState::Empty);
        assert_eq!(state("*"), PasswordState::NoPassword);
        assert_eq!(state("!$y$j9T$abc$def"), PasswordState::Locked);
        assert_eq!(state("$y$j9T$abc$def"), PasswordState::Hash("yescrypt"));
        assert_eq!(state("$6$salt$hash"), PasswordState::Hash("sha512crypt"));
        assert_eq!(state("abcdefghijklm"), PasswordState::Hash("descrypt"));
    }

    #[test]
    fn damaged_lines_are_problems() {
        let parsed = passwd("root:x:0:0:root:/root:/bin/bash\nbroken\n+::::::\n");
        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(parsed.problems.len(), 1);
        assert_eq!(group("sudo:x:27:\nadm:x:4:syslog,alice\n").entries.len(), 1);
    }
}
