//! OpenSSH's `authorized_keys`: `[options] key-type base64-key [comment]`
//! per line, as sshd(8) describes it.

use common::sha256::Sha256;

use crate::text::{numbered, split_word};
use crate::{base64, AuthorizedKey, Detail, Entry, KeyOption, Kind, Parsed};

/// Key types, without the certificate (`-cert-v01`) and `@openssh.com`
/// suffixes.
const KEY_TYPES: [&str; 8] = [
    "ssh-ed25519",
    "ssh-rsa",
    "ssh-dss",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519",
    "sk-ecdsa-sha2-nistp256",
];

/// Read `authorized_keys`. `owner` is the account whose home it's in.
pub(crate) fn authorized_keys(text: &str, owner: Option<&str>) -> Parsed {
    let mut parsed = Parsed::default();
    for (number, line) in numbered(text) {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut key = match key_line(line) {
            Ok(key) => key,
            Err(what) => {
                parsed.problem(number, what);
                continue;
            }
        };
        match base64::decode(&key.key) {
            Some(blob) => {
                key.fingerprint = Some(fingerprint(&blob));
                if let Err(what) = check_type(&blob, &key.key_type) {
                    parsed.problem(number, &what);
                }
            }
            None => parsed.problem(number, "a key that isn't base64"),
        }
        let command = forced_command(&key);
        let mut entry = Entry::new(Kind::AuthorizedKeys, number, Detail::AuthorizedKey(key));
        entry.user = owner.map(str::to_owned);
        entry.command = command;
        parsed.entries.push(entry);
    }
    parsed
}

fn key_line(line: &str) -> Result<AuthorizedKey, &'static str> {
    let (options, rest) = if is_key_type(split_word(line).0) {
        (Vec::new(), line)
    } else {
        let (options, rest) = split_options(line)?;
        (key_options(options), rest)
    };
    let (key_type, rest) = split_word(rest);
    if !is_key_type(key_type) {
        return Err("not a key");
    }
    let (key, comment) = split_word(rest);
    if key.is_empty() {
        return Err("a key type without a key");
    }
    Ok(AuthorizedKey {
        options,
        key_type: key_type.to_owned(),
        key: key.to_owned(),
        fingerprint: None,
        comment: Some(comment.trim_end().to_owned()).filter(|c| !c.is_empty()),
    })
}

fn is_key_type(word: &str) -> bool {
    let word = word.strip_suffix("@openssh.com").unwrap_or(word);
    let word = word.strip_suffix("-cert-v01").unwrap_or(word);
    KEY_TYPES.contains(&word)
}

/// The options (up to the first white space outside quotes) and the rest.
fn split_options(line: &str) -> Result<(&str, &str), &'static str> {
    let mut quoted = false;
    let mut escaped = false;
    for (at, c) in line.char_indices() {
        match c {
            _ if escaped => escaped = false,
            '\\' => escaped = true,
            '"' => quoted = !quoted,
            c if c.is_whitespace() && !quoted => return Ok((&line[..at], &line[at..])),
            _ => {}
        }
    }
    Err(if quoted {
        "an unterminated quote in a key's options"
    } else {
        "options without a key"
    })
}

/// `no-pty,command="a,b",from="…"`: each option, quotes removed.
fn key_options(text: &str) -> Vec<KeyOption> {
    let mut options = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' if quoted => match chars.next() {
                Some('"') => current.push('"'),
                Some(other) => {
                    current.push('\\');
                    current.push(other);
                }
                None => current.push('\\'),
            },
            '"' => quoted = !quoted,
            ',' if !quoted => options.push(key_option(&std::mem::take(&mut current))),
            _ => current.push(c),
        }
    }
    options.push(key_option(&current));
    options.retain(|option| !option.name.is_empty());
    options
}

fn key_option(text: &str) -> KeyOption {
    let (name, value) = text
        .split_once('=')
        .map_or((text, None), |(name, value)| (name, Some(value.to_owned())));
    KeyOption {
        name: name.to_owned(),
        value,
    }
}

/// `command="…"`: what runs whenever the key logs in.
fn forced_command(key: &AuthorizedKey) -> Option<String> {
    key.options
        .iter()
        .find(|option| option.name.eq_ignore_ascii_case("command"))
        .and_then(|option| option.value.clone())
}

/// `SHA256:` and the digest of the key's bytes, unpadded base64.
fn fingerprint(blob: &[u8]) -> String {
    format!("SHA256:{}", base64::encode_unpadded(&Sha256::digest(blob)))
}

/// The key's bytes start with its type, which should be the one written.
fn check_type(blob: &[u8], key_type: &str) -> Result<(), String> {
    let inner = blob
        .get(..4)
        .and_then(|length| {
            let length = u32::from_be_bytes(length.try_into().ok()?) as usize;
            blob.get(4..4usize.checked_add(length)?)
        })
        .map(String::from_utf8_lossy);
    match inner {
        Some(inner) if inner == key_type => Ok(()),
        Some(inner) => Err(format!(
            "a key written as {key_type} whose bytes say {inner}"
        )),
        None => Err("a key too short to hold its type".to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An Ed25519 public key made for these tests (`ssh-keygen -t ed25519`).
    const KEY: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIBFUzRDiRMlGfHEOJNfdaJrnqD6cTWARrmJ7CX4JPf4L";

    #[test]
    fn options_with_quotes_and_commas() {
        let line = format!(
            "from=\"198.51.100.0/24,203.0.113.7\",command=\"/bin/sh -c \\\"echo a,b\\\"\",no-pty ssh-ed25519 {KEY} ops@example.net laptop"
        );
        let parsed = authorized_keys(&line, Some("alice"));
        assert!(parsed.problems.is_empty(), "{:?}", parsed.problems);
        let entry = &parsed.entries[0];
        let Detail::AuthorizedKey(key) = &entry.detail else {
            panic!()
        };
        let options: Vec<_> = key
            .options
            .iter()
            .map(|o| (o.name.as_str(), o.value.as_deref()))
            .collect();
        assert_eq!(
            options,
            [
                ("from", Some("198.51.100.0/24,203.0.113.7")),
                ("command", Some("/bin/sh -c \"echo a,b\"")),
                ("no-pty", None),
            ]
        );
        assert_eq!(entry.command.as_deref(), Some("/bin/sh -c \"echo a,b\""));
        assert_eq!(entry.user.as_deref(), Some("alice"));
        assert_eq!(key.comment.as_deref(), Some("ops@example.net laptop"));
    }

    #[test]
    fn bad_keys_are_problems() {
        let parsed = authorized_keys(
            "ssh-rsa\nno-pty\nfrom=\"x ssh-rsa AAAA\n1024 35 1234 old@host\nssh-rsa !!!\nssh-rsa AAAAC3NzaC1lZDI1NTE5\n",
            None,
        );
        assert_eq!(
            parsed.problems,
            [
                "line 1: a key type without a key",
                "line 2: options without a key",
                "line 3: an unterminated quote in a key's options",
                "line 4: not a key",
                "line 5: a key that isn't base64",
                "line 6: a key written as ssh-rsa whose bytes say ssh-ed25519",
            ]
        );
        // Keys with damaged bytes are still listed.
        assert_eq!(parsed.entries.len(), 2);
        assert_eq!(parsed.entries[1].command, None);
    }

    #[test]
    fn certificate_and_security_key_types() {
        assert!(is_key_type("ssh-ed25519-cert-v01@openssh.com"));
        assert!(is_key_type("sk-ssh-ed25519@openssh.com"));
        assert!(!is_key_type("ssh-foo"));
    }
}
