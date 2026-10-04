//! Lines, words and quotes, shared by the readers.

/// Physical lines numbered from 1, without their line ending.
pub(crate) fn numbered(text: &str) -> impl Iterator<Item = (usize, &str)> {
    text.split('\n')
        .enumerate()
        .map(|(index, line)| (index + 1, line.strip_suffix('\r').unwrap_or(line)))
}

/// How a line ending in a backslash continues.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Continuation {
    /// The shell's (and sudoers'): backslash and line break are removed. A
    /// comment (`#`) doesn't continue.
    Shell,
    /// systemd's: backslash and line break become a space, and comment
    /// lines (`#`, `;`) inside the continuation are skipped.
    Systemd,
}

impl Continuation {
    fn is_comment(self, line: &str) -> bool {
        let line = line.trim_start();
        match self {
            Self::Shell => line.starts_with('#'),
            Self::Systemd => line.starts_with(['#', ';']),
        }
    }

    const fn joiner(self) -> &'static str {
        match self {
            Self::Shell => "",
            Self::Systemd => " ",
        }
    }
}

/// Lines with their continuations joined: the number of the first line,
/// and the text. Comment lines are kept, never continued.
pub(crate) fn logical_lines(text: &str, style: Continuation) -> Vec<(usize, String)> {
    let mut lines = Vec::new();
    let mut pending: Option<(usize, String)> = None;
    for (number, line) in numbered(text) {
        let (first, mut logical) = match pending.take() {
            Some(started) if style == Continuation::Systemd && style.is_comment(line) => {
                pending = Some(started);
                continue;
            }
            Some(started) => started,
            None if style.is_comment(line) => {
                lines.push((number, line.to_owned()));
                continue;
            }
            None => (number, String::new()),
        };
        if let Some(head) = continued(line) {
            logical.push_str(head);
            logical.push_str(style.joiner());
            pending = Some((first, logical));
        } else {
            logical.push_str(line);
            lines.push((first, logical));
        }
    }
    lines.extend(pending);
    lines
}

/// A line ending in an unescaped backslash, without it.
fn continued(line: &str) -> Option<&str> {
    let backslashes = line.bytes().rev().take_while(|&b| b == b'\\').count();
    (backslashes % 2 == 1).then(|| &line[..line.len() - 1])
}

/// The first word and the rest, white space between them dropped.
pub(crate) fn split_word(text: &str) -> (&str, &str) {
    let text = text.trim_start();
    text.split_once(char::is_whitespace)
        .map_or((text, ""), |(word, rest)| (word, rest.trim_start()))
}

/// `text` without the quotes around it, if it has a matching pair.
pub(crate) fn unquote(text: &str) -> &str {
    ['"', '\'']
        .iter()
        .find_map(|&quote| text.strip_prefix(quote)?.strip_suffix(quote))
        .unwrap_or(text)
}

/// `text` split at each comma not escaped with a backslash, parts trimmed,
/// empty ones dropped.
pub(crate) fn split_list(text: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut part = String::new();
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                part.push(c);
                part.extend(chars.next());
            }
            ',' => parts.push(std::mem::take(&mut part)),
            _ => part.push(c),
        }
    }
    parts.push(part);
    parts
        .iter()
        .map(|p| p.trim())
        .filter(|p| !p.is_empty())
        .map(str::to_owned)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_continuations() {
        let lines = logical_lines("a \\\n  b\n# c \\\nd\\\\\ne \\", Continuation::Shell);
        assert_eq!(
            lines,
            [
                (1, "a   b".to_owned()),
                (3, "# c \\".to_owned()),
                (4, "d\\\\".to_owned()),
                (5, "e ".to_owned()),
            ]
        );
    }

    #[test]
    fn systemd_continuations_skip_comments() {
        let lines = logical_lines("A=1 \\\n# note\n; note\n  2\n", Continuation::Systemd);
        assert_eq!(lines[0], (1, "A=1    2".to_owned()));
    }

    #[test]
    fn words_quotes_and_lists() {
        assert_eq!(split_word("  root\t cmd  x"), ("root", "cmd  x"));
        assert_eq!(split_word("alone"), ("alone", ""));
        assert_eq!(unquote("\"a b\""), "a b");
        assert_eq!(unquote("'x"), "'x");
        assert_eq!(unquote("\""), "\"");
        assert_eq!(split_list("a, b\\, c ,, d"), ["a", "b\\, c", "d"]);
    }
}
