//! One line saying what an entry does.

use crate::{AuthorizedKey, Detail, Entry, SudoRule};

impl Entry {
    /// What the entry does, in a line: `@reboot as root: /tmp/.x/run`,
    /// `ExecStart as svc: /usr/bin/agent`, `alice may run ALL as ALL:ALL
    /// (NOPASSWD)`, ….
    #[must_use]
    pub fn summary(&self) -> String {
        let command = self.command.as_deref().unwrap_or_default();
        let schedule = self.schedule.as_deref().unwrap_or_default();
        let as_user = self
            .user
            .as_deref()
            .map(|user| format!(" as {user}"))
            .unwrap_or_default();
        match &self.detail {
            Detail::Environment { name, value } => format!("{name}={value}"),
            Detail::CronJob => format!("{schedule}{as_user}: {command}"),
            Detail::AnacronJob { delay_minutes, id } => format!(
                "{id} {} after {delay_minutes} min{as_user}: {command}",
                anacron_period(schedule)
            ),
            Detail::UnitSetting {
                section,
                key,
                value,
                ..
            } => match &self.command {
                Some(command) => format!("{key}{as_user}: {command}"),
                None => format!("[{section}] {key}={value}"),
            },
            Detail::AuthorizedKey(key) => {
                key_summary(key, self.user.as_deref(), self.command.as_deref())
            }
            Detail::ShellCommand => format!("{command}{}", parenthesised(self.user.as_deref())),
            Detail::PreloadLibrary => format!("preloaded into every program: {command}"),
            Detail::SudoRule(rule) => rule_summary(rule),
            Detail::SudoAlias {
                alias_kind,
                name,
                members,
            } => format!("{alias_kind} {name} = {}", members.join(", ")),
            Detail::SudoDefaults { scope, settings } => {
                format!(
                    "Defaults{} {settings}",
                    scope.as_deref().unwrap_or_default()
                )
            }
            Detail::SudoInclude { path, directory } => {
                let what = if *directory { "every file in " } else { "" };
                format!("includes {what}{path}")
            }
        }
    }
}

fn key_summary(key: &AuthorizedKey, user: Option<&str>, command: Option<&str>) -> String {
    let fingerprint = key.fingerprint.as_deref().unwrap_or("(damaged key)");
    let mut summary = format!("{} {fingerprint}", key.key_type);
    if let Some(comment) = &key.comment {
        summary += " ";
        summary += comment;
    }
    if let Some(user) = user {
        summary += " may log in as ";
        summary += user;
    }
    if let Some(command) = command {
        summary += ", forced command: ";
        summary += command;
    }
    summary
}

fn rule_summary(rule: &SudoRule) -> String {
    let run_as = rule.run_as.as_deref().unwrap_or("root");
    let mut summary = format!(
        "{} may run {} as {run_as}",
        rule.users.join(", "),
        rule.commands.join(", ")
    );
    if rule.hosts.iter().any(|host| host != "ALL") {
        summary += " on ";
        summary += &rule.hosts.join(", ");
    }
    if !rule.tags.is_empty() {
        summary += " (";
        summary += &rule.tags.join(", ");
        summary += ")";
    }
    summary
}

/// `every 7 days`, `every day`, or the `@monthly` written.
fn anacron_period(period: &str) -> String {
    match period {
        "1" => "every day".to_owned(),
        _ if period.starts_with('@') => period.to_owned(),
        _ => format!("every {period} days"),
    }
}

fn parenthesised(user: Option<&str>) -> String {
    user.map(|user| format!(" ({user})")).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use crate::{parse, Kind};

    fn summaries(kind: Kind, text: &str, path: &str) -> Vec<String> {
        parse(kind, text.as_bytes(), path)
            .entries
            .iter()
            .map(crate::Entry::summary)
            .collect()
    }

    #[test]
    fn one_line_each() {
        assert_eq!(
            summaries(
                Kind::SystemCrontab,
                "PATH=/bin\n@reboot root /tmp/x\n",
                "etc/crontab"
            ),
            ["PATH=/bin", "@reboot as root: /tmp/x"]
        );
        assert_eq!(
            summaries(
                Kind::Anacrontab,
                "7 10 cron.weekly run-parts /etc/cron.weekly",
                "etc/anacrontab"
            ),
            ["cron.weekly every 7 days after 10 min as root: run-parts /etc/cron.weekly"]
        );
        assert_eq!(
            summaries(
                Kind::SystemdUnit,
                "[Service]\nUser=svc\nExecStart=-/opt/a\n",
                "etc/systemd/system/a.service"
            ),
            ["[Service] User=svc", "ExecStart as svc: /opt/a"]
        );
        assert_eq!(
            summaries(Kind::ShellInit, "alias ls='ls -la'\n", "home/alice/.bashrc"),
            ["alias ls='ls -la' (alice)"]
        );
        assert_eq!(
            summaries(Kind::LdSoPreload, "/usr/lib/libx.so\n", "etc/ld.so.preload"),
            ["preloaded into every program: /usr/lib/libx.so"]
        );
        assert_eq!(
            summaries(
                Kind::Sudoers,
                "%sudo ALL=(ALL:ALL) ALL\nbob web1 = NOPASSWD: /usr/bin/systemctl\nDefaults:bob !lecture\n@includedir /etc/sudoers.d\n",
                "etc/sudoers"
            ),
            [
                "%sudo may run ALL as ALL:ALL",
                "bob may run /usr/bin/systemctl as root on web1 (NOPASSWD)",
                "Defaults:bob !lecture",
                "includes every file in /etc/sudoers.d",
            ]
        );
    }
}
