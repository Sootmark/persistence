//! A Debian 13 system's default files: every one detected from its path
//! and read without a problem, the values Debian wrote, and no flag raised
//! on a clean system. Entry counts were checked with `grep` (lines that
//! aren't blank or comments).
//!
//! The permissively licensed ones are vendored (`tests/fixtures/debian/`,
//! see its NOTICE). The rest are GPL-licensed, so not vendored: set
//! `SOOTMARK_PERSISTENCE_DEBIAN` to a folder `tests/debian/fetch.sh` filled
//! from a debian:trixie container, as CI does; without it, their tests are
//! skipped.

use std::fs;
use std::path::{Path, PathBuf};

use persistence::{detect, flags, parse, Detail, Entry, Kind, Parsed};

const FOLDER: &str = "SOOTMARK_PERSISTENCE_DEBIAN";

/// Vendored: path, kind and entry count.
const VENDORED: [(&str, Kind, usize); 4] = [
    ("etc/sudoers", Kind::Sudoers, 7),
    ("etc/sudoers.d/README", Kind::Sudoers, 0),
    ("usr/lib/systemd/system/ssh.service", Kind::SystemdUnit, 17),
    ("usr/lib/systemd/system/ssh.socket", Kind::SystemdUnit, 6),
];
/// Fetched by `tests/debian/fetch.sh`: path, kind and entry count.
const FETCHED: [(&str, Kind, usize); 31] = [
    ("etc/crontab", Kind::SystemCrontab, 6),
    ("etc/cron.d/anacron", Kind::SystemCrontab, 3),
    ("etc/cron.d/e2scrub_all", Kind::SystemCrontab, 2),
    ("etc/cron.d/sysstat", Kind::SystemCrontab, 3),
    ("etc/anacrontab", Kind::Anacrontab, 8),
    ("etc/profile", Kind::ShellInit, 27),
    ("etc/bash.bashrc", Kind::ShellInit, 22),
    ("etc/skel/.bashrc", Kind::ShellInit, 49),
    ("etc/skel/.profile", Kind::ShellInit, 11),
    (
        "usr/lib/systemd/system/anacron.service",
        Kind::SystemdUnit,
        11,
    ),
    ("usr/lib/systemd/system/anacron.timer", Kind::SystemdUnit, 5),
    (
        "usr/lib/systemd/system/apt-daily.timer",
        Kind::SystemdUnit,
        5,
    ),
    ("usr/lib/systemd/system/cron.service", Kind::SystemdUnit, 10),
    (
        "usr/lib/systemd/system/e2scrub_all.timer",
        Kind::SystemdUnit,
        5,
    ),
    (
        "usr/lib/systemd/system/logrotate.service",
        Kind::SystemdUnit,
        22,
    ),
    (
        "usr/lib/systemd/system/logrotate.timer",
        Kind::SystemdUnit,
        6,
    ),
    (
        "usr/lib/systemd/system/sysstat-collect.timer",
        Kind::SystemdUnit,
        3,
    ),
    ("etc/init.d/cron", Kind::InitScript, 55),
    ("etc/init.d/ssh", Kind::InitScript, 125),
    ("etc/init.d/sudo", Kind::InitScript, 26),
    ("etc/ssh/sshd_config", Kind::SshdConfig, 7),
    ("etc/pam.d/common-account", Kind::Pam, 3),
    ("etc/pam.d/common-auth", Kind::Pam, 3),
    ("etc/pam.d/common-password", Kind::Pam, 3),
    ("etc/pam.d/common-session", Kind::Pam, 6),
    ("etc/pam.d/cron", Kind::Pam, 7),
    ("etc/pam.d/login", Kind::Pam, 17),
    ("etc/pam.d/other", Kind::Pam, 4),
    ("etc/pam.d/sshd", Kind::Pam, 15),
    ("etc/pam.d/su", Kind::Pam, 8),
    ("etc/pam.d/sudo", Kind::Pam, 4),
];

fn read_in(folder: &Path, path: &str) -> Parsed {
    let data = fs::read(folder.join(path)).unwrap_or_else(|e| panic!("{path}: {e}"));
    parse(detect(path).unwrap(), &data, path)
}

/// A vendored file.
fn vendored(path: &str) -> Parsed {
    read_in(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/debian"),
        path,
    )
}

/// The folder of fetched files, or `None` (noted) when it isn't set.
fn fetched_folder() -> Option<PathBuf> {
    let folder = std::env::var_os(FOLDER).map(PathBuf::from);
    if folder.is_none() {
        eprintln!("{FOLDER} not set: Debian's GPL-licensed files skipped");
    }
    folder
}

/// Detected as `kind`, read with no problem, `entries` entries, no flag.
fn check_clean(path: &str, kind: Kind, entries: usize, parsed: &Parsed) {
    assert_eq!(detect(path), Some(kind), "{path}");
    assert!(parsed.problems.is_empty(), "{path}: {:?}", parsed.problems);
    assert_eq!(parsed.entries.len(), entries, "{path}");
    for entry in &parsed.entries {
        assert!(flags(entry).is_empty(), "{path}: {}", entry.summary());
    }
}

#[test]
fn vendored_files_read_cleanly() {
    for (path, kind, entries) in VENDORED {
        check_clean(path, kind, entries, &vendored(path));
    }
}

#[test]
fn fetched_files_read_cleanly() {
    let Some(folder) = fetched_folder() else {
        return;
    };
    for (path, kind, entries) in FETCHED {
        check_clean(path, kind, entries, &read_in(&folder, path));
    }
}

fn setting<'a>(parsed: &'a Parsed, wanted: &str) -> &'a Entry {
    parsed
        .entries
        .iter()
        .find(|entry| matches!(&entry.detail, Detail::UnitSetting { key, .. } if key == wanted))
        .unwrap()
}

#[test]
fn system_crontab() {
    let Some(folder) = fetched_folder() else {
        return;
    };
    let parsed = read_in(&folder, "etc/crontab");
    assert_eq!(
        parsed.entries[0].detail,
        Detail::Environment {
            name: "SHELL".to_owned(),
            value: "/bin/sh".to_owned()
        }
    );
    // Fields separated by tabs and spaces.
    let weekly = &parsed.entries[4];
    assert_eq!(weekly.line, 20);
    assert_eq!(weekly.schedule.as_deref(), Some("47 6 * * 7"));
    assert_eq!(weekly.user.as_deref(), Some("root"));
    assert_eq!(
        weekly.command.as_deref(),
        Some("test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }")
    );
    let sysstat = read_in(&folder, "etc/cron.d/sysstat");
    assert_eq!(
        sysstat.entries[1].schedule.as_deref(),
        Some("5-55/10 * * * *")
    );
}

#[test]
fn anacrontab() {
    let Some(folder) = fetched_folder() else {
        return;
    };
    let parsed = read_in(&folder, "etc/anacrontab");
    let monthly = &parsed.entries[6];
    assert_eq!(monthly.schedule.as_deref(), Some("@monthly"));
    assert_eq!(
        monthly.detail,
        Detail::AnacronJob {
            delay_minutes: 15,
            id: "cron.monthly".to_owned()
        }
    );
    assert_eq!(
        monthly.command.as_deref(),
        Some("run-parts --report /etc/cron.monthly")
    );
}

#[test]
fn sudoers() {
    let parsed = vendored("etc/sudoers");
    let Detail::SudoRule(rule) = &parsed.entries[5].detail else {
        panic!("{:?}", parsed.entries[5]);
    };
    assert_eq!(rule.users, ["%sudo"]);
    assert_eq!(rule.hosts, ["ALL"]);
    assert_eq!(rule.run_as.as_deref(), Some("ALL:ALL"));
    assert_eq!(rule.commands, ["ALL"]);
    assert_eq!(
        parsed.entries[2].detail,
        Detail::SudoDefaults {
            scope: None,
            settings:
                "secure_path=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\""
                    .to_owned()
        }
    );
    assert_eq!(
        parsed.entries[6].detail,
        Detail::SudoInclude {
            path: "/etc/sudoers.d".to_owned(),
            directory: true
        }
    );
}

#[test]
fn ssh_unit() {
    let ssh = vendored("usr/lib/systemd/system/ssh.service");
    let reloads: Vec<_> = ssh
        .entries
        .iter()
        .filter(|e| matches!(&e.detail, Detail::UnitSetting { key, .. } if key == "ExecReload"))
        .map(|e| e.command.as_deref().unwrap())
        .collect();
    assert_eq!(reloads, ["/usr/sbin/sshd -t", "/bin/kill -HUP $MAINPID"]);
    assert_eq!(
        setting(&ssh, "ExecStart").command.as_deref(),
        Some("/usr/sbin/sshd -D $SSHD_OPTS")
    );
    // No `User=`: whom it runs as isn't written.
    assert_eq!(setting(&ssh, "ExecStart").user, None);
    let Detail::UnitSetting { value, .. } = &setting(&ssh, "WantedBy").detail else {
        panic!()
    };
    assert_eq!(value, "multi-user.target");
}

#[test]
fn fetched_units() {
    let Some(folder) = fetched_folder() else {
        return;
    };
    let timer = read_in(&folder, "usr/lib/systemd/system/e2scrub_all.timer");
    assert_eq!(
        setting(&timer, "OnCalendar").schedule.as_deref(),
        Some("Sun *-*-* 03:10:00")
    );
    // A `-` prefix on a setting that isn't a command stays in its value.
    let cron = read_in(&folder, "usr/lib/systemd/system/cron.service");
    let Detail::UnitSetting {
        value,
        exec_prefixes,
        ..
    } = &setting(&cron, "EnvironmentFile").detail
    else {
        panic!()
    };
    assert_eq!(
        (value.as_str(), exec_prefixes.as_str()),
        ("-/etc/default/cron", "")
    );
}

#[test]
fn shell_start_up_files() {
    let Some(folder) = fetched_folder() else {
        return;
    };
    let parsed = read_in(&folder, "etc/profile");
    assert_eq!(parsed.entries[0].line, 4);
    assert_eq!(
        parsed.entries[0].command.as_deref(),
        Some("if [ \"$(id -u)\" -eq 0 ]; then")
    );
    // System-wide: no one account.
    assert_eq!(parsed.entries[0].user, None);
}

#[test]
fn pam_and_sshd_config() {
    let Some(folder) = fetched_folder() else {
        return;
    };
    let auth = read_in(&folder, "etc/pam.d/common-auth");
    assert_eq!(
        auth.entries[0].summary(),
        "common-auth: auth [success=1 default=ignore] pam_unix.so nullok"
    );
    let sshd = read_in(&folder, "etc/ssh/sshd_config");
    assert_eq!(
        sshd.entries[6].command.as_deref(),
        Some("/usr/lib/openssh/sftp-server")
    );
}
