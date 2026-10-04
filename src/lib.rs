//! Where Linux and Unix attackers keep access to a host: crontabs, `at`
//! jobs, systemd units, init scripts, SSH authorized keys and the SSH
//! server's configuration, `rc.local` and shell start-up files,
//! `/etc/ld.so.preload`, sudoers, PAM, udev rules, XDG autostart entries
//! and kernel modules, read from the host files of a triage collection.
//!
//! [`detect`] tells a file's [`Kind`] from its path on the host
//! (`etc/crontab`, `home/alice/.ssh/authorized_keys`, `[root]/etc/sudoers`,
//! …), and [`parse`] reads it into [`Entry`]s: one per job, setting, key,
//! command line, library or rule, with the line it's on, the account it
//! runs as or belongs to, what it runs and when. [`flags`] lists the traits
//! that look like an attacker's ([`Flag`]).
//!
//! Lines that can't be read are reported in `problems`, never fatal; no
//! input makes these functions panic.
//!
//! ```
//! use persistence::{detect, flags, parse, Flag};
//!
//! let path = "[root]/etc/cron.d/sysupdate";
//! let kind = detect(path).unwrap();
//! let parsed = parse(kind, b"@reboot root /dev/shm/.x/run\n", path);
//! let job = &parsed.entries[0];
//! assert_eq!(job.summary(), "@reboot as root: /dev/shm/.x/run");
//! assert_eq!(flags(job), [Flag::TemporaryDirectory, Flag::AtReboot]);
//! ```

mod at;
mod autostart;
mod base64;
mod cron;
mod flags;
mod modules;
mod pam;
mod path;
mod preload;
mod shell;
mod ssh;
mod sshd;
mod sudoers;
mod summary;
mod systemd;
mod text;
mod udev;

pub use flags::{flags, Flag};
pub use path::detect;

/// This crate's version, for records of what parsed them.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// A kind of file, each read its own way.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    /// A user's crontab (`var/spool/cron/crontabs/<user>`, RHEL's
    /// `var/spool/cron/<user>`): a schedule, then the command, run as the
    /// account the file is named after.
    Crontab,
    /// The system crontabs (`etc/crontab`, `etc/cron.d/*`): a schedule, the
    /// account, then the command.
    SystemCrontab,
    /// `etc/anacrontab`: period, delay, job id and command, run as root.
    Anacrontab,
    /// A systemd unit (`.service`, `.timer`, `.path`, `.socket`) or a
    /// drop-in (`<unit>.d/*.conf`), system-wide or a user's.
    SystemdUnit,
    /// `.ssh/authorized_keys` (and `authorized_keys2`): keys that may log in
    /// as the account whose home it's in.
    AuthorizedKeys,
    /// `etc/rc.local`, `etc/rc.d/rc.local`: run by root at boot.
    RcLocal,
    /// Shell start-up files, run when an account logs in or opens a shell:
    /// `etc/profile`, `etc/profile.d/*.sh`, `etc/bash.bashrc`, a home's
    /// `.bashrc`, `.profile`, `.zshrc`, ….
    ShellInit,
    /// `etc/ld.so.preload`: libraries loaded into every dynamically linked
    /// program.
    LdSoPreload,
    /// `etc/sudoers`, `etc/sudoers.d/*`: who may run what as whom.
    Sudoers,
    /// A job `at` queued (`var/spool/cron/atjobs/*`, `var/spool/at/*`,
    /// `var/at/jobs/*`): commands run once, later, as the account that
    /// queued them.
    AtJob,
    /// A System V init script (`etc/init.d/*`, `etc/rc.d/init.d/*`): run by
    /// root at boot, on systems that still start them.
    InitScript,
    /// PAM's configuration (`etc/pam.d/*`, `etc/pam.conf`): the modules
    /// every login goes through.
    Pam,
    /// The SSH server's configuration (`etc/ssh/sshd_config`,
    /// `etc/ssh/sshd_config.d/*`).
    SshdConfig,
    /// udev rules (`etc/udev/rules.d/*.rules`, `usr/lib/udev/rules.d`, …):
    /// commands run as root when a matching device appears.
    Udev,
    /// XDG autostart entries (`etc/xdg/autostart/*.desktop`, a home's
    /// `.config/autostart/*.desktop`): commands a desktop session starts at
    /// login.
    XdgAutostart,
    /// Kernel modules loaded at boot (`etc/modules`, `modules-load.d/*`).
    ModulesLoad,
    /// modprobe's configuration (`modprobe.d/*.conf`).
    Modprobe,
}

impl Kind {
    /// A short name: `crontab`, `system crontab`, `anacrontab`, `systemd
    /// unit`, `authorized keys`, `rc.local`, `shell init`, `ld.so.preload`,
    /// `sudoers`, `at job`, `init script`, `pam`, `sshd config`, `udev
    /// rule`, `xdg autostart`, `modules load`, `modprobe`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Crontab => "crontab",
            Self::SystemCrontab => "system crontab",
            Self::Anacrontab => "anacrontab",
            Self::SystemdUnit => "systemd unit",
            Self::AuthorizedKeys => "authorized keys",
            Self::RcLocal => "rc.local",
            Self::ShellInit => "shell init",
            Self::LdSoPreload => "ld.so.preload",
            Self::Sudoers => "sudoers",
            Self::AtJob => "at job",
            Self::InitScript => "init script",
            Self::Pam => "pam",
            Self::SshdConfig => "sshd config",
            Self::Udev => "udev rule",
            Self::XdgAutostart => "xdg autostart",
            Self::ModulesLoad => "modules load",
            Self::Modprobe => "modprobe",
        }
    }
}

/// One job, setting, key, command line, library or rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The kind of file it's in.
    pub kind: Kind,
    /// Its line number, from 1 (the first line, when continued).
    pub line: usize,
    /// The account it runs as (cron and at jobs, units' commands,
    /// `rc.local` and init scripts) or
    /// belongs to (a home's keys and start-up files); for a sudoers rule,
    /// the accounts and `%groups` it's granted to. `None` when the file
    /// doesn't say: a system unit without `User=` runs as root unless a
    /// drop-in says otherwise.
    pub user: Option<String>,
    /// What runs: the command; for a key, its forced command
    /// (`command="…"`); for ld.so.preload, the library; for a sudoers rule,
    /// the commands allowed; for a PAM rule, the module (`pam_exec.so`'s
    /// program); for an sshd setting, the command it runs, if any.
    pub command: Option<String>,
    /// When it runs: cron's five fields or `@reboot`…, anacron's period,
    /// a timer's `OnCalendar=`, `OnBootSec=`… value, as written; an at
    /// job's time, from its file name (`2026-10-07T07:14Z`, UTC).
    pub schedule: Option<String>,
    /// What else the line holds.
    pub detail: Detail,
}

impl Entry {
    fn new(kind: Kind, line: usize, detail: Detail) -> Self {
        Self {
            kind,
            line,
            user: None,
            command: None,
            schedule: None,
            detail,
        }
    }
}

/// What else a line holds, by what it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Detail {
    /// `NAME=value` in a crontab (`SHELL`, `PATH`, `MAILTO`, …), for the
    /// jobs after it.
    Environment {
        /// The variable.
        name: String,
        /// Its value, quotes removed.
        value: String,
    },
    /// A cron job: schedule, account and command are on the entry.
    CronJob,
    /// An anacron job: its period is the entry's schedule.
    AnacronJob {
        /// Minutes anacron waits before running it.
        delay_minutes: u32,
        /// The job's name (`cron.daily`), naming its timestamp file.
        id: String,
    },
    /// A `Key=value` line in a systemd unit.
    UnitSetting {
        /// `Unit`, `Service`, `Timer`, `Install`, ….
        section: String,
        /// `ExecStart`, `User`, `Description`, `WantedBy`, `OnCalendar`, ….
        key: String,
        /// The value as written, continuation lines joined.
        value: String,
        /// For `Exec…=`: the prefixes before the command (`-` failure
        /// ignored, `@` own argv\[0], `:` no variable expansion, `+` and
        /// `!` full privileges), removed from the entry's command.
        exec_prefixes: String,
    },
    /// A key in `authorized_keys`.
    AuthorizedKey(AuthorizedKey),
    /// A command line in `rc.local`, an init script or a shell start-up
    /// file.
    ShellCommand,
    /// A library in ld.so.preload, the entry's command.
    PreloadLibrary,
    /// A sudoers rule: who may run what, where, as whom.
    SudoRule(SudoRule),
    /// A sudoers alias, kept as written: rules name it, it isn't expanded.
    SudoAlias {
        /// `User_Alias`, `Runas_Alias`, `Host_Alias` or `Cmnd_Alias`.
        alias_kind: String,
        /// Its name.
        name: String,
        /// What it stands for.
        members: Vec<String>,
    },
    /// A sudoers `Defaults` line.
    SudoDefaults {
        /// Whom or what it applies to, with its sigil (`:alice`,
        /// `@host`, `>root`, `!/bin/sh`), `None` for everyone.
        scope: Option<String>,
        /// The settings (`env_reset`, `!authenticate`, …).
        settings: String,
    },
    /// `@include`, `@includedir`, `#include` or `#includedir`: more rules
    /// read from another file, or every file in a directory.
    SudoInclude {
        /// The file or directory.
        path: String,
        /// Whether it's a directory.
        directory: bool,
    },
    /// A command line of an at job; account, command and run time are on
    /// the entry.
    AtJob {
        /// The queue, from the file name (`a`, `b`, …; `=` while running).
        queue: Option<char>,
        /// The job number, from the file name.
        job: Option<u32>,
        /// The account's id, from the header (`# atrun uid=1000`).
        uid: Option<u32>,
    },
    /// A PAM rule.
    PamRule(PamRule),
    /// `@include`: the rules of another file in `etc/pam.d`.
    PamInclude(String),
    /// A setting of the SSH server.
    SshdSetting {
        /// The keyword, as written (`PermitRootLogin`).
        key: String,
        /// Its value, quotes removed.
        value: String,
        /// The `Match` criteria it applies under (`User backup`), `None`
        /// for every connection.
        condition: Option<String>,
    },
    /// A udev rule: its pairs in order; the entry's command is what it
    /// runs.
    UdevRule(Vec<UdevPair>),
    /// An XDG autostart entry's command.
    Autostart {
        /// Its `Name=`.
        name: Option<String>,
        /// `Hidden=true` or `X-GNOME-Autostart-enabled=false`: not started.
        disabled: bool,
    },
    /// A kernel module to load at boot, the entry's command (with its
    /// parameters, in `etc/modules`).
    KernelModule,
    /// A modprobe directive: `install`, `remove`, `options`, `blacklist`,
    /// `alias`, `softdep`, ….
    ModprobeDirective {
        /// The directive.
        directive: String,
        /// The module (or alias) it's about.
        module: String,
        /// The rest: for `install` and `remove`, the command run instead,
        /// also the entry's command.
        arguments: String,
    },
}

/// One `KEY{attribute}op"value"` pair of a udev rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdevPair {
    /// `ACTION`, `SUBSYSTEM`, `ATTR`, `RUN`, `ENV`, ….
    pub key: String,
    /// What's in the braces (`ATTR{idVendor}`, `RUN{builtin}`).
    pub attribute: Option<String>,
    /// `==` or `!=` (a match), or `=`, `+=`, `-=`, `:=` (an action).
    pub operator: String,
    /// The value, quotes removed and `\"` unescaped.
    pub value: String,
}

/// A key that may log in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedKey {
    /// Options before the key (`command="…"`, `from="…"`, `no-pty`), in
    /// order.
    pub options: Vec<KeyOption>,
    /// `ssh-ed25519`, `ssh-rsa`, `ecdsa-sha2-nistp256`, ….
    pub key_type: String,
    /// The key, base64 as written.
    pub key: String,
    /// `SHA256:…`, as `ssh-keygen -l` prints it; `None` when the key isn't
    /// valid base64.
    pub fingerprint: Option<String>,
    /// What follows the key, often `user@host`.
    pub comment: Option<String>,
}

/// An option before a key: `no-pty`, or `from="198.51.100.0/24"`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyOption {
    /// Its name, as written.
    pub name: String,
    /// Its value, quotes removed and `\"` unescaped.
    pub value: Option<String>,
}

/// A sudoers rule: `users hosts = (run-as) TAGS: commands`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SudoRule {
    /// Accounts, `%groups`, `#uids` and aliases it's granted to.
    pub users: Vec<String>,
    /// Hosts it applies on (`ALL`).
    pub hosts: Vec<String>,
    /// Whom the commands may run as, inside the parentheses
    /// (`ALL:ALL`); `None` when not written: root.
    pub run_as: Option<String>,
    /// Tags and options (`NOPASSWD`, `SETENV`, `CWD=/`), for every command
    /// they're written before.
    pub tags: Vec<String>,
    /// The commands, aliases or `ALL`.
    pub commands: Vec<String>,
}

/// A PAM rule: `type control module arguments`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PamRule {
    /// The service it's for: the file's name in `etc/pam.d`, the first
    /// word in `etc/pam.conf`.
    pub service: String,
    /// `auth`, `account`, `password` or `session`, as written (a leading
    /// `-` keeps a missing module out of the log).
    pub rule_type: String,
    /// `required`, `sufficient`, `include`, … or a bracketed list
    /// (`[success=1 default=ignore]`).
    pub control: String,
    /// The module: a name looked up in the module directory, or a path.
    pub module: String,
    /// The module's arguments.
    pub arguments: Vec<String>,
}

/// A file's entries.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Parsed {
    /// Entries in file order.
    pub entries: Vec<Entry>,
    /// Lines that couldn't be read.
    pub problems: Vec<String>,
}

impl Parsed {
    fn problem(&mut self, line: usize, what: &str) {
        self.problems.push(format!("line {line}: {what}"));
    }
}

/// Read a file of `kind` found at `path` on the host. The path names the
/// account for users' crontabs, keys, start-up files and units.
#[must_use]
pub fn parse(kind: Kind, data: &[u8], path: &str) -> Parsed {
    let text = String::from_utf8_lossy(data);
    let account = path::account(path);
    match kind {
        Kind::Crontab => cron::crontab(&text, cron::Form::User(path::file_name(path))),
        Kind::SystemCrontab => cron::crontab(&text, cron::Form::System),
        Kind::Anacrontab => cron::anacrontab(&text),
        Kind::SystemdUnit => systemd::unit(&text, account),
        Kind::AuthorizedKeys => ssh::authorized_keys(&text, account),
        Kind::RcLocal => shell::script(&text, Kind::RcLocal, Some("root")),
        Kind::ShellInit => shell::script(&text, Kind::ShellInit, account),
        Kind::LdSoPreload => preload::libraries(data),
        Kind::Sudoers => sudoers::rules(&text),
        Kind::AtJob => at::job(&text, path::file_name(path)),
        Kind::InitScript => shell::script(&text, Kind::InitScript, Some("root")),
        Kind::Pam => pam::rules(&text, path::pam_service(path)),
        Kind::SshdConfig => sshd::config(&text),
        Kind::Udev => udev::rules(&text),
        Kind::XdgAutostart => autostart::entry(&text, account),
        Kind::ModulesLoad => modules::load_list(&text),
        Kind::Modprobe => modules::modprobe(&text),
    }
}
