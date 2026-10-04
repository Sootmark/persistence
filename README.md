# persistence

The files Linux and Unix attackers use to keep access to a host (crontabs, systemd units, SSH authorized keys, `rc.local` and shell start-up files, `/etc/ld.so.preload` and sudoers), read into entries that say what runs, as whom and when, and what looks suspicious. Made for triage collections (UAC's `[root]/…`), works on any copy of a host's files. One dependency, its sibling `sootmark-common` (SHA-256).

```toml
[dependencies]
sootmark-persistence = "0.1"
```

```rust
let path = "[root]/etc/cron.d/sysupdate";
if let Some(kind) = persistence::detect(path) {
    let parsed = persistence::parse(kind, &std::fs::read(collection.join(path))?, path);
    for entry in &parsed.entries {
        println!("line {}: {} {:?}", entry.line, entry.summary(), persistence::flags(entry));
    }
}
```

## What you get

- `detect(path)`: the kind of file from its path on the host, relative (`etc/crontab`), absolute, or as a collection stores it (`uac/[root]/etc/crontab`).
- `parse(kind, bytes, path)`: one `Entry` per job, setting, key, command line, library or rule, with its line, the account it runs as or belongs to (`user`), what runs (`command`), when (`schedule`), and the rest in `detail`. Lines that can't be read go to `problems`.
  - **crontabs**: users' (`var/spool/cron/crontabs/<user>`, RHEL's `var/spool/cron/<user>`, run as the account the file is named after) and the system's (`etc/crontab`, `etc/cron.d/*`, with their account field): five time fields or `@reboot`, `@daily`…, the command as written, `SHELL=`, `PATH=`, `MAILTO=` kept. cron doesn't continue lines: a trailing backslash stays in the command, as cron leaves it. `etc/anacrontab`: period, delay, job id, command.
  - **systemd units** (`.service`, `.timer`, `.path`, `.socket`, and drop-ins `<unit>.d/*.conf`) in the system and user unit directories, homes' `.config/systemd/user` included: every setting with its section; `Exec…=` commands with their `-@:+!` prefixes removed and kept, run as `User=` or the home's owner; timers' `OnCalendar=`, `OnBootSec=`… as the schedule. Backslash continuations, `#` and `;` comments.
  - **authorized_keys** (any `.ssh/authorized_keys` or `authorized_keys2`): options (`command="…"` as the entry's command, `from="…"`, `no-pty`, …), key type, key, its `SHA256:` fingerprint as `ssh-keygen -l` prints it, comment; the account from the home. A key whose bytes name another type, or aren't base64, is reported.
  - **rc.local** and **shell start-up files** (`etc/profile`, `etc/profile.d/*.sh`, `etc/bash.bashrc`, `etc/bashrc`, zsh's, and homes' and `etc/skel`'s `.bashrc`, `.profile`, `.bash_profile`, `.zshrc`, …): each line that isn't blank or a comment, backslash continuations joined; the shell's grammar isn't read.
  - **ld.so.preload**: each library, read as glibc reads the file, its quirky comment handling included. Distributions ship none: any entry deserves a look.
  - **sudoers** (`etc/sudoers`, `etc/sudoers.d/*`): rules (users, hosts, run-as, tags such as `NOPASSWD`, commands), aliases kept as written, `Defaults` lines, `@include`/`@includedir`/`#include`/`#includedir`.
- `Entry::summary()`: a line saying what it does (`@reboot as root: /dev/shm/.x/run`).
- `flags(entry)`: leads, not verdicts. Commands run from `/tmp`, `/var/tmp` or `/dev/shm`; `curl`/`wget` piped to a shell; base64 decoding; `nc`, `ncat`, `socat` or bash's `/dev/tcp`; `@reboot` jobs; keys with a forced command; any ld.so.preload library; sudo `NOPASSWD: ALL` or `Defaults !authenticate`.

Not read here: `at` jobs, init.d scripts, udev rules, PAM, `sshd_config`, XDG autostart, kernel modules.

## How it's checked

- A Debian 13 system's default files: every one detected and read without a problem, values as Debian wrote them, entry counts, and not one flag raised. The permissively licensed ones (sudoers, OpenSSH's units) are vendored in `tests/fixtures/debian/` (see `NOTICE`); the rest are GPL-licensed, so CI copies them from a debian:trixie container (`tests/debian/fetch.sh <folder>`, then `SOOTMARK_PERSISTENCE_DEBIAN=<folder> cargo test --test debian`).
- Files written as an attacker might leave them (`tests/fixtures/synthetic/`, documentation addresses only), each format's syntax covered: what runs, as whom, when, and what's flagged. systemd 257's `systemd-analyze verify` accepts every unit in both sets, visudo the sudoers files, Debian's cron (`crontab -n`) the synthetic crontabs.
- Fingerprints as `ssh-keygen -lf` prints them (OpenSSH 10.0 and 10.3), for Ed25519, RSA and ECDSA keys made for the tests.
- ld.so.preload as glibc 2.41 reads it: the libraries it tried to load from the same files, and its comment loop transliterated and compared.
- Property tests: arbitrary bytes, text made of the formats' punctuation, and the fixtures damaged anywhere, read as every kind, give entries or problems, never a panic.

## Licence

MIT or Apache-2.0, at your option. The Debian files under `tests/fixtures/debian/` keep their packages' licences (ISC and OpenSSH's BSD-style).
