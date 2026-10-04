//! A file's kind and account from its path on the host.

use crate::Kind;

/// Directories systemd reads units from, below the root.
const UNIT_DIRECTORIES: [&[&str]; 9] = [
    &["etc", "systemd", "system"],
    &["etc", "systemd", "user"],
    &["run", "systemd", "system"],
    &["run", "systemd", "user"],
    &["usr", "lib", "systemd", "system"],
    &["usr", "lib", "systemd", "user"],
    &["usr", "local", "lib", "systemd", "system"],
    &["lib", "systemd", "system"],
    &["lib", "systemd", "user"],
];
/// Directories systemd reads a user's units from, below their home.
const HOME_UNIT_DIRECTORIES: [&[&str]; 2] = [
    &[".config", "systemd", "user"],
    &[".local", "share", "systemd", "user"],
];
const UNIT_TYPES: [&str; 4] = ["service", "timer", "path", "socket"];
/// Directories of units another one pulls in (`multi-user.target.wants`).
const DEPENDENCY_DIRECTORIES: [&str; 3] = [".wants", ".requires", ".upholds"];

/// Start-up files in a home, and in `etc/skel` (copied to new homes).
const HOME_START_UP_FILES: [&str; 10] = [
    ".bashrc",
    ".bash_profile",
    ".bash_login",
    ".bash_logout",
    ".profile",
    ".zshrc",
    ".zshenv",
    ".zprofile",
    ".zlogin",
    ".zlogout",
];
/// System-wide start-up files in `etc`.
const ETC_START_UP_FILES: [&str; 7] = [
    "profile",
    "bash.bashrc",
    "bashrc",
    "zshrc",
    "zshenv",
    "zprofile",
    "zlogin",
];
/// Directories in `var/spool/cron` that aren't a crontab.
const CRON_SPOOL_DIRECTORIES: [&str; 5] = ["crontabs", "tabs", "atjobs", "atspool", "lastrun"];

/// A file's kind from its path on the host: relative to the root
/// (`etc/crontab`), absolute (`/etc/crontab`), or as a collection stores it
/// (`[root]/etc/crontab`, `uac/[root]/etc/crontab`); `/` or `\` separated.
/// `None` for files this crate doesn't read.
#[must_use]
pub fn detect(path: &str) -> Option<Kind> {
    let parts = components(path);
    let kind = match parts.as_slice() {
        ["etc", "crontab"] | ["etc", "cron.d", _] => Kind::SystemCrontab,
        ["var", "spool", "cron", "crontabs" | "tabs", _] | ["var", "cron" | "at", "tabs", _] => {
            Kind::Crontab
        }
        ["var", "spool", "cron", name] if !CRON_SPOOL_DIRECTORIES.contains(name) => Kind::Crontab,
        ["var", "spool", "cron", "atjobs", name]
        | ["var", "spool", "at", name]
        | ["var", "at", "jobs", name]
            if *name != ".SEQ" =>
        {
            Kind::AtJob
        }
        ["etc", "init.d", _] | ["etc", "rc.d", "init.d", _] => Kind::InitScript,
        ["etc", "pam.d", _] | ["etc", "pam.conf"] => Kind::Pam,
        ["etc", "ssh", "sshd_config"] | ["etc", "ssh", "sshd_config.d", _] => Kind::SshdConfig,
        ["etc" | "lib" | "run", "udev", "rules.d", name]
        | ["usr", "lib", "udev", "rules.d", name]
            if extension(name) == Some("rules") =>
        {
            Kind::Udev
        }
        ["etc", "xdg", "autostart", name] | [.., ".config", "autostart", name]
            if extension(name) == Some("desktop") =>
        {
            Kind::XdgAutostart
        }
        ["etc", "modules"] => Kind::ModulesLoad,
        ["etc" | "lib" | "run", "modules-load.d", name]
        | ["usr", "lib", "modules-load.d", name]
            if extension(name) == Some("conf") =>
        {
            Kind::ModulesLoad
        }
        ["etc" | "lib" | "run", "modprobe.d", name] | ["usr", "lib", "modprobe.d", name]
            if extension(name) == Some("conf") =>
        {
            Kind::Modprobe
        }
        ["etc", "anacrontab"] => Kind::Anacrontab,
        [.., ".ssh", "authorized_keys" | "authorized_keys2"] => Kind::AuthorizedKeys,
        ["etc", "rc.local"] | ["etc", "rc.d", "rc.local"] | ["etc", "rc.local.d", "local.sh"] => {
            Kind::RcLocal
        }
        ["etc", "ld.so.preload"] => Kind::LdSoPreload,
        ["etc", "sudoers"]
        | ["etc", "sudoers.d", _]
        | ["usr", "local", "etc", "sudoers"]
        | ["usr", "local", "etc", "sudoers.d", _] => Kind::Sudoers,
        _ if is_unit(&parts) => Kind::SystemdUnit,
        _ if is_start_up_file(&parts) => Kind::ShellInit,
        _ => return None,
    };
    Some(kind)
}

/// The account whose home `path` is in: `home/<user>/…` (macOS's
/// `Users/<user>/…`), or `root/…`.
pub(crate) fn account(path: &str) -> Option<&str> {
    match components(path).as_slice() {
        ["home" | "Users", user, _, ..] => Some(user),
        ["root", _, ..] => Some("root"),
        _ => None,
    }
}

/// The service a file in `etc/pam.d` configures: its name.
pub(crate) fn pam_service(path: &str) -> Option<&str> {
    match components(path).as_slice() {
        ["etc", "pam.d", service] => Some(service),
        _ => None,
    }
}

/// The last component of `path`.
pub(crate) fn file_name(path: &str) -> Option<&str> {
    components(path).last().copied()
}

/// The path's components below the host's root.
fn components(path: &str) -> Vec<&str> {
    let below_root = path.rfind("[root]").map_or(path, |at| &path[at + 6..]);
    below_root
        .split(['/', '\\'])
        .filter(|part| !part.is_empty() && *part != ".")
        .collect()
}

/// A unit or drop-in in one of systemd's directories: `<dir>/x.service`,
/// `<dir>/multi-user.target.wants/x.service`, `<dir>/x.service.d/y.conf`.
fn is_unit(parts: &[&str]) -> bool {
    let Some(within) = unit_directory_length(parts).map(|length| &parts[length..]) else {
        return false;
    };
    match within {
        [name] => is_unit_name(name),
        [directory, name]
            if DEPENDENCY_DIRECTORIES
                .iter()
                .any(|d| directory.ends_with(d)) =>
        {
            is_unit_name(name)
        }
        [directory, name] => directory
            .strip_suffix(".d")
            .is_some_and(|unit| is_unit_name(unit) && extension(name) == Some("conf")),
        _ => false,
    }
}

/// How many components name the unit directory `parts` starts with.
fn unit_directory_length(parts: &[&str]) -> Option<usize> {
    if let Some(directory) = UNIT_DIRECTORIES.iter().find(|d| parts.starts_with(d)) {
        return Some(directory.len());
    }
    let home = home_length(parts)?;
    HOME_UNIT_DIRECTORIES
        .iter()
        .find(|d| parts[home..].starts_with(d))
        .map(|d| home + d.len())
}

fn is_unit_name(name: &str) -> bool {
    extension(name)
        .is_some_and(|suffix| name.len() > suffix.len() + 1 && UNIT_TYPES.contains(&suffix))
}

/// What follows the last `.`, as written: systemd, the shells' start-up
/// scripts, udev, modprobe and desktop sessions match it case-sensitively.
fn extension(name: &str) -> Option<&str> {
    name.rsplit_once('.').map(|(_, extension)| extension)
}

/// How many components name the home `parts` starts with.
fn home_length(parts: &[&str]) -> Option<usize> {
    match parts {
        ["home" | "Users", _, ..] | ["etc", "skel", ..] => Some(2),
        ["root", ..] => Some(1),
        _ => None,
    }
}

fn is_start_up_file(parts: &[&str]) -> bool {
    match parts {
        ["etc", name] | ["etc", "zsh", name] => ETC_START_UP_FILES.contains(name),
        ["etc", "profile.d", name] => extension(name) == Some("sh"),
        _ => home_length(parts).is_some_and(|home| match &parts[home..] {
            [name] => HOME_START_UP_FILES.contains(name),
            _ => false,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_from_paths() {
        for (path, kind) in [
            ("etc/crontab", Some(Kind::SystemCrontab)),
            ("/etc/cron.d/e2scrub_all", Some(Kind::SystemCrontab)),
            ("[root]/var/spool/cron/crontabs/root", Some(Kind::Crontab)),
            ("var/spool/cron/alice", Some(Kind::Crontab)),
            ("var/spool/cron/crontabs", None),
            ("var/spool/cron/atjobs", None),
            ("etc/anacrontab", Some(Kind::Anacrontab)),
            ("etc/systemd/system/x.service", Some(Kind::SystemdUnit)),
            (
                "etc/systemd/system/multi-user.target.wants/x.service",
                Some(Kind::SystemdUnit),
            ),
            (
                "etc/systemd/system/ssh.service.d/override.conf",
                Some(Kind::SystemdUnit),
            ),
            ("lib/systemd/system/cron.timer", Some(Kind::SystemdUnit)),
            (
                "home/alice/.config/systemd/user/agent.service",
                Some(Kind::SystemdUnit),
            ),
            ("etc/systemd/system/default.target", None),
            ("etc/systemd/system/.service", None),
            ("etc/systemd/system.conf", None),
            (
                "home/alice/.ssh/authorized_keys",
                Some(Kind::AuthorizedKeys),
            ),
            ("root/.ssh/authorized_keys2", Some(Kind::AuthorizedKeys)),
            (
                "var/lib/postgresql/.ssh/authorized_keys",
                Some(Kind::AuthorizedKeys),
            ),
            ("home/alice/.ssh/known_hosts", None),
            ("etc/rc.local", Some(Kind::RcLocal)),
            ("etc/rc.d/rc.local", Some(Kind::RcLocal)),
            ("etc/rc.local.d/local.sh", Some(Kind::RcLocal)),
            ("etc/ld.so.preload", Some(Kind::LdSoPreload)),
            ("etc/sudoers", Some(Kind::Sudoers)),
            ("etc/sudoers.d/90-cloud-init-users", Some(Kind::Sudoers)),
            ("usr/local/etc/sudoers", Some(Kind::Sudoers)),
            ("etc/profile", Some(Kind::ShellInit)),
            ("etc/profile.d/update.sh", Some(Kind::ShellInit)),
            ("etc/profile.d/notes.txt", None),
            ("etc/bash.bashrc", Some(Kind::ShellInit)),
            ("etc/zsh/zshrc", Some(Kind::ShellInit)),
            ("home/alice/.bashrc", Some(Kind::ShellInit)),
            ("root/.profile", Some(Kind::ShellInit)),
            ("etc/skel/.bashrc", Some(Kind::ShellInit)),
            ("home/alice/docs/.bashrc", None),
            ("C:\\case\\[root]\\etc\\crontab", Some(Kind::SystemCrontab)),
            ("", None),
            ("[root]", None),
        ] {
            assert_eq!(detect(path), kind, "{path}");
        }
    }

    #[test]
    fn accounts_from_paths() {
        assert_eq!(account("home/alice/.ssh/authorized_keys"), Some("alice"));
        assert_eq!(account("[root]/root/.bashrc"), Some("root"));
        assert_eq!(account("Users/bob/.zshrc"), Some("bob"));
        assert_eq!(account("etc/skel/.bashrc"), None);
        assert_eq!(account("home/alice"), None);
        assert_eq!(file_name("var/spool/cron/crontabs/carol"), Some("carol"));
        assert_eq!(file_name("/"), None);
    }
}
