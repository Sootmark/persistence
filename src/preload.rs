//! `/etc/ld.so.preload`: libraries the dynamic loader puts into every
//! program it starts, before anything else. Distributions ship none, so
//! any entry deserves a look: it's a classic way to hide files and
//! processes or to run code in every process.
//!
//! Read as glibc's loader reads it (checked against glibc 2.41): names are
//! separated by spaces, tabs, line breaks or `:`, and `#` starts a comment
//! to the end of the line, with a quirk: glibc looks for comments from the
//! start of the file, and each comment it blanks out shrinks, by its
//! offset and length, the span it looks in next. A comment late in the
//! file can stay unblanked, its words loaded as libraries; they're listed
//! as glibc would try them.

use crate::{Detail, Entry, Kind, Parsed};

const SEPARATORS: [u8; 4] = [b' ', b'\t', b'\n', b':'];

/// Read ld.so.preload: one entry per library, its path the command.
pub(crate) fn libraries(data: &[u8]) -> Parsed {
    let data = without_comments(data);
    let mut entries = Vec::new();
    for (index, line) in data.split(|&b| b == b'\n').enumerate() {
        for name in line
            .split(|b| SEPARATORS.contains(b))
            .filter(|n| !n.is_empty())
        {
            let mut entry = Entry::new(Kind::LdSoPreload, index + 1, Detail::PreloadLibrary);
            entry.command = Some(String::from_utf8_lossy(name).into_owned());
            entries.push(entry);
        }
    }
    Parsed {
        entries,
        problems: Vec::new(),
    }
}

/// The file with its comments blanked as glibc blanks them (`rtld.c`):
/// every search starts at the file's start, but only spans what's left
/// of a count that each blanked comment decreases. Searching on from the
/// last comment finds the same ones (nothing before it is a `#` any
/// more), in linear time.
fn without_comments(data: &[u8]) -> Vec<u8> {
    let mut data = data.to_vec();
    // glibc's count: it searches `data[..rest]`.
    let mut rest = data.len();
    let mut from = 0;
    while let Some(found) = data
        .get(from..rest)
        .and_then(|window| window.iter().position(|&b| b == b'#'))
    {
        let start = from + found;
        rest -= start;
        let mut at = start;
        loop {
            data[at] = b' ';
            rest -= 1;
            at += 1;
            if rest == 0 || data[at] == b'\n' {
                break;
            }
        }
        from = at;
    }
    data
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(text: &str) -> Vec<(usize, String)> {
        libraries(text.as_bytes())
            .entries
            .into_iter()
            .map(|e| (e.line, e.command.unwrap_or_default()))
            .collect()
    }

    #[test]
    fn separators() {
        assert_eq!(
            names("/lib/a.so:/lib/b.so\t/lib/c.so\n\n /lib/d.so"),
            [
                (1, "/lib/a.so".to_owned()),
                (1, "/lib/b.so".to_owned()),
                (1, "/lib/c.so".to_owned()),
                (3, "/lib/d.so".to_owned()),
            ]
        );
    }

    /// What glibc 2.41 tried to load from these files (Debian trixie, the
    /// "cannot be preloaded" errors in order).
    #[test]
    fn comments_as_glibc_reads_them() {
        let tried =
            |text: &str| -> Vec<String> { names(text).into_iter().map(|(_, n)| n).collect() };
        assert_eq!(
            tried("# a comment here\n/nonexist1.so:/nonexist2.so  /nonexist3.so # trailing\n"),
            [
                "/nonexist1.so",
                "/nonexist2.so",
                "/nonexist3.so",
                "#",
                "trailing"
            ]
        );
        assert_eq!(
            tried("/a1.so\n# mid comment\n  # indented\n/a2.so #tail words\n#x y\n/a3.so#z\n"),
            ["/a1.so", "/a2.so", "#tail", "words", "#x", "y", "/a3.so#z"]
        );
        assert_eq!(
            tried("#p1 p2\n# q1\n#\tr1\n#\n/s1 # s2\n/t1\t#t2\n"),
            ["#", "/s1", "#", "s2", "/t1", "#t2"]
        );
    }

    /// glibc's loop, transliterated: every search from the file's start.
    fn glibc_without_comments(data: &[u8]) -> Vec<u8> {
        let mut data = data.to_vec();
        let mut rest = data.len();
        while let Some(start) = data[..rest].iter().position(|&b| b == b'#') {
            rest -= start;
            let mut at = start;
            loop {
                data[at] = b' ';
                rest -= 1;
                at += 1;
                if rest == 0 || data[at] == b'\n' {
                    break;
                }
            }
        }
        data
    }

    proptest::proptest! {
        #[test]
        fn blanks_what_glibc_blanks(text in "[#\na :]{0,200}") {
            proptest::prop_assert_eq!(
                without_comments(text.as_bytes()),
                glibc_without_comments(text.as_bytes())
            );
        }
    }

    #[test]
    fn many_comments_in_linear_time() {
        let data = "#\n".repeat(500_000);
        assert!(!libraries(data.as_bytes()).entries.is_empty());
    }
}
