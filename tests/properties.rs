//! Any input gives entries or problems, never a panic: arbitrary bytes,
//! text made of the formats' punctuation, and the fixtures damaged
//! anywhere, read as every kind.

use std::fs;
use std::path::Path;

use persistence::{detect, flags, parse, Kind};
use proptest::prelude::*;

const KINDS: [Kind; 17] = [
    Kind::Crontab,
    Kind::SystemCrontab,
    Kind::Anacrontab,
    Kind::SystemdUnit,
    Kind::AuthorizedKeys,
    Kind::RcLocal,
    Kind::ShellInit,
    Kind::LdSoPreload,
    Kind::Sudoers,
    Kind::AtJob,
    Kind::InitScript,
    Kind::Pam,
    Kind::SshdConfig,
    Kind::Udev,
    Kind::XdgAutostart,
    Kind::ModulesLoad,
    Kind::Modprobe,
];
/// A fixture of each kind, with the path it's read as.
const FIXTURES: [&str; 21] = [
    "synthetic/var/spool/cron/crontabs/alice",
    "synthetic/etc/crontab",
    "synthetic/etc/anacrontab",
    "synthetic/etc/systemd/system/sysupdate.service",
    "synthetic/home/alice/.ssh/authorized_keys",
    "synthetic/etc/rc.local",
    "synthetic/etc/rc.local.d/local.sh",
    "synthetic/etc/passwd",
    "synthetic/etc/shadow",
    "synthetic/etc/group",
    "synthetic/home/alice/.bashrc",
    "synthetic/etc/ld.so.preload",
    "synthetic/etc/sudoers.d/90-backdoor",
    "synthetic/var/spool/cron/atjobs/a0000201c79c28",
    "synthetic/etc/init.d/sysupdate",
    "synthetic/etc/pam.d/sshd",
    "synthetic/etc/ssh/sshd_config.d/99-tuning.conf",
    "synthetic/etc/udev/rules.d/99-usb-sync.rules",
    "synthetic/home/alice/.config/autostart/tracker-extract.desktop",
    "synthetic/etc/modules-load.d/kernel-helpers.conf",
    "synthetic/etc/modprobe.d/blacklist-local.conf",
];

/// Read `data` as every kind, and look at every entry.
fn read_as_everything(data: &[u8], path: &str) {
    for kind in KINDS {
        for entry in parse(kind, data, path).entries {
            let _ = (flags(&entry), entry.summary());
        }
    }
}

fn fixture(name: &str) -> Vec<u8> {
    fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name),
    )
    .unwrap()
}

/// Text made of what the formats are made of.
fn syntax() -> impl Strategy<Value = String> {
    proptest::string::string_regex(
        "([ \t\n\r#;=\\[\\]\\\\\",:@()%!*/.~-]|ALL|NOPASSWD:|Exec|ssh-rsa|AAAA|/tmp|curl|\\|sh|@reboot|[a-z0-9]){0,300}",
    )
    .unwrap()
}

proptest! {
    #[test]
    fn arbitrary_bytes(data in proptest::collection::vec(any::<u8>(), 0..2_000), path in ".{0,40}") {
        let _ = detect(&path);
        read_as_everything(&data, &path);
    }

    #[test]
    fn format_punctuation(text in syntax()) {
        read_as_everything(text.as_bytes(), "home/alice/.config/systemd/user/x.service");
    }

    #[test]
    fn damaged_fixtures(
        which in 0..FIXTURES.len(),
        flips in proptest::collection::vec((any::<usize>(), any::<u8>()), 1..20),
        keep in any::<usize>(),
    ) {
        let mut data = fixture(FIXTURES[which]);
        let length = data.len();
        for (at, byte) in flips {
            data[at % length] = byte;
        }
        data.truncate(keep % (length + 1));
        read_as_everything(&data, FIXTURES[which]);
    }
}

#[test]
fn every_kind_reads_empty_and_odd_files() {
    for data in [
        &b""[..],
        b"\n\n",
        b"\\",
        b"\"",
        b"[",
        b"#",
        b"=",
        b"\xff\xfe\x00",
        b"a\\\n",
    ] {
        read_as_everything(data, "");
    }
}
