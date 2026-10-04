//! The SSH server's configuration (`etc/ssh/sshd_config`,
//! `etc/ssh/sshd_config.d/*.conf`): one entry per setting, with the
//! `Match` block it's in. Keywords are kept as written (sshd ignores their
//! case), `Keyword value` and `Keyword=value` alike.

use crate::text::{logical_lines, unquote, Continuation};
use crate::{Detail, Entry, Kind, Parsed};

/// Read an sshd configuration file.
pub(crate) fn config(text: &str) -> Parsed {
    let mut parsed = Parsed::default();
    let mut condition: Option<String> = None;
    for (number, line) in logical_lines(text, Continuation::Shell) {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = setting(line) else {
            parsed.problem(number, "a keyword without a value");
            continue;
        };
        if key.eq_ignore_ascii_case("Match") {
            // `Match all` applies to every connection again.
            condition = (!value.eq_ignore_ascii_case("all")).then(|| value.to_owned());
            continue;
        }
        let mut entry = Entry::new(
            Kind::SshdConfig,
            number,
            Detail::SshdSetting {
                key: key.to_owned(),
                value: value.to_owned(),
                condition: condition.clone(),
            },
        );
        entry.command = command(key, value).map(str::to_owned);
        parsed.entries.push(entry);
    }
    parsed
}

/// `Keyword value` or `Keyword=value`, the value unquoted.
fn setting(line: &str) -> Option<(&str, &str)> {
    let end = line.find(|c: char| c.is_whitespace() || c == '=')?;
    let (key, rest) = line.split_at(end);
    let rest = rest.trim_start();
    let value = rest.strip_prefix('=').unwrap_or(rest).trim();
    (!value.is_empty()).then(|| (key, unquote(value)))
}

/// What a setting runs: `ForceCommand`'s command, `AuthorizedKeysCommand`'s
/// and `AuthorizedPrincipalsCommand`'s, and a `Subsystem`'s (after its
/// name).
fn command<'v>(key: &str, value: &'v str) -> Option<&'v str> {
    let key = key.to_ascii_lowercase();
    match key.as_str() {
        "forcecommand" | "authorizedkeyscommand" | "authorizedprincipalscommand" => Some(value),
        "subsystem" => value
            .split_once(char::is_whitespace)
            .map(|(_, command)| command.trim()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_match_blocks_and_commands() {
        let parsed = config(
            "Include /etc/ssh/sshd_config.d/*.conf\n\
             PermitRootLogin=yes\n\
             Subsystem\tsftp\t/usr/lib/openssh/sftp-server\n\
             Match User backup Address 192.0.2.0/24\n\
             \tForceCommand \"/usr/local/bin/rrsync /srv\"\n\
             Match all\n\
             AuthorizedKeysFile .ssh/authorized_keys /var/tmp/.k\n\
             PrintMotd\n",
        );
        assert_eq!(parsed.problems, ["line 8: a keyword without a value"]);
        let read: Vec<_> = parsed
            .entries
            .iter()
            .map(|e| {
                let Detail::SshdSetting {
                    key,
                    value,
                    condition,
                } = &e.detail
                else {
                    panic!("a setting")
                };
                (
                    key.as_str(),
                    value.as_str(),
                    condition.as_deref(),
                    e.command.as_deref(),
                )
            })
            .collect();
        assert_eq!(
            read,
            [
                ("Include", "/etc/ssh/sshd_config.d/*.conf", None, None),
                ("PermitRootLogin", "yes", None, None),
                (
                    "Subsystem",
                    "sftp\t/usr/lib/openssh/sftp-server",
                    None,
                    Some("/usr/lib/openssh/sftp-server")
                ),
                (
                    "ForceCommand",
                    "/usr/local/bin/rrsync /srv",
                    Some("User backup Address 192.0.2.0/24"),
                    Some("/usr/local/bin/rrsync /srv")
                ),
                (
                    "AuthorizedKeysFile",
                    ".ssh/authorized_keys /var/tmp/.k",
                    None,
                    None
                ),
            ]
        );
    }
}
