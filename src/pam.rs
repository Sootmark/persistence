//! PAM's configuration (`etc/pam.d/<service>`, `etc/pam.conf`): which
//! modules authenticate, authorise and open sessions for each service.
//! Read as Linux-PAM reads it: `#` starts a comment anywhere on a line, a
//! backslash continues it, and a control may be a bracketed list
//! (`[success=1 default=ignore]`) holding spaces.

use crate::text::{logical_lines, split_word, Continuation};
use crate::{Detail, Entry, Kind, PamRule, Parsed};

/// What a rule's type may be, after an optional `-` (no log when the
/// module is missing).
const TYPES: [&str; 4] = ["auth", "account", "password", "session"];

/// Read a PAM file: `service` names the file's service (`sshd` for
/// `etc/pam.d/sshd`); `None` for `etc/pam.conf`, whose rules name theirs.
pub(crate) fn rules(text: &str, service: Option<&str>) -> Parsed {
    let mut parsed = Parsed::default();
    for (number, line) in logical_lines(text, Continuation::Shell) {
        let line = line.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        if let Some(file) = line.strip_prefix("@include") {
            let include = Detail::PamInclude(file.trim().to_owned());
            parsed.entries.push(Entry::new(Kind::Pam, number, include));
            continue;
        }
        let (service, rest) = match service {
            Some(service) => (service, line),
            None => split_word(line),
        };
        match rule(service, rest) {
            Some(rule) => {
                let program = rule.program().to_owned();
                let mut entry = Entry::new(Kind::Pam, number, Detail::PamRule(rule));
                entry.command = Some(program);
                parsed.entries.push(entry);
            }
            None => parsed.problem(number, "not a PAM rule"),
        }
    }
    parsed
}

/// `type control module [arguments]`.
fn rule(service: &str, text: &str) -> Option<PamRule> {
    let (rule_type, rest) = split_word(text);
    if !TYPES.contains(
        &rule_type
            .trim_start_matches('-')
            .to_ascii_lowercase()
            .as_str(),
    ) {
        return None;
    }
    let (control, rest) = if let Some(bracketed) = rest.strip_prefix('[') {
        let (inside, rest) = bracketed.split_once(']')?;
        (format!("[{}]", inside.trim()), rest.trim_start())
    } else {
        let (control, rest) = split_word(rest);
        (control.to_owned(), rest)
    };
    let (module, arguments) = split_word(rest);
    if control.is_empty() || module.is_empty() {
        return None;
    }
    Some(PamRule {
        service: service.to_owned(),
        rule_type: rule_type.to_owned(),
        control,
        module: module.to_owned(),
        arguments: arguments.split_whitespace().map(str::to_owned).collect(),
    })
}

impl PamRule {
    /// The rule's type without its `-`, in lower case: `auth`, `account`,
    /// `password` or `session`.
    #[must_use]
    pub fn kind(&self) -> String {
        self.rule_type.trim_start_matches('-').to_ascii_lowercase()
    }

    /// What the rule runs: for `pam_exec.so`, the program it starts (its
    /// first argument that isn't an option); otherwise the module.
    #[must_use]
    pub fn program(&self) -> &str {
        if self.module_name() == "pam_exec.so" {
            if let Some(program) = self.arguments.iter().find(|a| a.starts_with('/')) {
                return program;
            }
        }
        &self.module
    }

    /// The module's file name: `/lib/security/pam_unix.so` is
    /// `pam_unix.so`.
    #[must_use]
    pub fn module_name(&self) -> &str {
        self.module.rsplit('/').next().unwrap_or(&self.module)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(text: &str) -> Vec<PamRule> {
        let parsed = rules(text, Some("sshd"));
        assert!(parsed.problems.is_empty(), "{:?}", parsed.problems);
        parsed
            .entries
            .into_iter()
            .filter_map(|e| match e.detail {
                Detail::PamRule(rule) => Some(rule),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn controls_comments_and_continuations() {
        let rules = read(
            "auth\t[success=1 default=ignore]\tpam_unix.so nullok\n\
             session    optional     pam_mail.so standard noenv # [1]\n\
             -session optional pam_systemd.so\n\
             auth sufficient \\\n  pam_permit.so\n",
        );
        let summary: Vec<_> = rules
            .iter()
            .map(|r| {
                (
                    r.kind(),
                    r.control.as_str(),
                    r.module.as_str(),
                    r.arguments.len(),
                )
            })
            .collect();
        assert_eq!(
            summary,
            [
                (
                    "auth".to_owned(),
                    "[success=1 default=ignore]",
                    "pam_unix.so",
                    1
                ),
                ("session".to_owned(), "optional", "pam_mail.so", 2),
                ("session".to_owned(), "optional", "pam_systemd.so", 0),
                ("auth".to_owned(), "sufficient", "pam_permit.so", 0),
            ]
        );
    }

    #[test]
    fn pam_exec_runs_its_program() {
        let rules =
            read("session optional pam_exec.so quiet expose_authtok /usr/local/bin/log.sh a\n");
        assert_eq!(rules[0].program(), "/usr/local/bin/log.sh");
    }

    #[test]
    fn pam_conf_names_the_service_and_includes() {
        let parsed = rules(
            "login auth required pam_unix.so\n@include common-auth\nnonsense\n",
            None,
        );
        let Detail::PamRule(rule) = &parsed.entries[0].detail else {
            panic!("a rule")
        };
        assert_eq!(rule.service, "login");
        assert_eq!(
            parsed.entries[1].detail,
            Detail::PamInclude("common-auth".to_owned())
        );
        assert_eq!(parsed.problems, ["line 3: not a PAM rule"]);
    }
}
