//! The matcher and line scanner behind `kit grep`.
//!
//! [`Matcher`] decides whether one line is selected. [`Scanner`] takes the
//! bytes of one file in pieces of any size, as an [`io::Write`], cuts them
//! into lines that may span pieces, and reports each selected line. So a
//! chunked file is searched one chunk at a time and a line that crosses a
//! chunk boundary is still one line.

use std::io;

use regex::bytes::{Regex, RegexBuilder};

/// How the patterns are read and lines selected.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // one flag each, as git has them
pub struct Options {
    /// `-i`: ignore case.
    pub ignore_case: bool,
    /// `-w`: a match counts only when it is a whole word.
    pub word: bool,
    /// `-v`: select the lines that do not match.
    pub invert: bool,
    /// `-F`: the patterns are literal strings.
    pub fixed: bool,
}

/// The bytes searched for a NUL to tell a binary file.
pub const BINARY_SNIFF: usize = 8 << 10;

/// Selects lines.
#[derive(Debug, Clone)]
pub struct Matcher {
    re: Regex,
    word: bool,
    invert: bool,
}

impl Matcher {
    /// A matcher for lines that match any of `patterns`.
    ///
    /// # Errors
    /// [`regex::Error`] when a pattern is not valid, or there is none.
    pub fn new<S: AsRef<str>>(patterns: &[S], options: Options) -> Result<Self, regex::Error> {
        if patterns.is_empty() {
            return Err(regex::Error::Syntax("no pattern".to_owned()));
        }
        let alternatives: Vec<String> = patterns
            .iter()
            .map(|p| {
                let p = p.as_ref();
                let p = if options.fixed {
                    regex::escape(p)
                } else {
                    p.to_owned()
                };
                format!("(?:{p})")
            })
            .collect();
        let re = RegexBuilder::new(&alternatives.join("|"))
            .case_insensitive(options.ignore_case)
            .multi_line(false)
            .build()?;
        Ok(Self {
            re,
            word: options.word,
            invert: options.invert,
        })
    }

    /// Whether `line`, without its newline, is selected.
    #[must_use]
    pub fn selects(&self, line: &[u8]) -> bool {
        self.matches(line) != self.invert
    }

    fn matches(&self, line: &[u8]) -> bool {
        if !self.word {
            return self.re.is_match(line);
        }
        // As git does: a match that is not a whole word is retried from the
        // next byte, so a later or shorter match can still count.
        let mut at = 0;
        while at <= line.len() {
            let Some(m) = self.re.find_at(line, at) else {
                return false;
            };
            let before = m.start() == 0 || !is_word_byte(line[m.start() - 1]);
            let after = m.end() == line.len() || !is_word_byte(line[m.end()]);
            if before && after && !m.is_empty() {
                return true;
            }
            at = m.start() + 1;
        }
        false
    }
}

fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Cuts the bytes of one file into lines and reports the selected ones.
///
/// Until it holds [`BINARY_SNIFF`] bytes, or the file ends, it reports
/// nothing, so it can tell a binary file first. A binary file reports no
/// line; [`Scanner::finish`] still counts its selected lines.
pub struct Scanner<'a> {
    matcher: &'a Matcher,
    on_line: &'a mut dyn FnMut(u64, &[u8]),
    head: Vec<u8>,
    binary: Option<bool>,
    pending: Vec<u8>,
    line: u64,
    selected: u64,
}

/// What [`Scanner::finish`] found in one file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Found {
    /// The file has a NUL byte in its first [`BINARY_SNIFF`] bytes.
    pub binary: bool,
    /// The number of selected lines.
    pub selected: u64,
}

impl<'a> Scanner<'a> {
    /// A scanner that calls `on_line` with the 1-based number and the bytes,
    /// without the newline, of each selected line of a text file.
    pub fn new(matcher: &'a Matcher, on_line: &'a mut dyn FnMut(u64, &[u8])) -> Self {
        Self {
            matcher,
            on_line,
            head: Vec::new(),
            binary: None,
            pending: Vec::new(),
            line: 0,
            selected: 0,
        }
    }

    /// Take the last line, which may have no newline, and report what the
    /// file held.
    #[must_use]
    pub fn finish(mut self) -> Found {
        if self.binary.is_none() {
            self.decide();
        }
        if !self.pending.is_empty() {
            let last = std::mem::take(&mut self.pending);
            self.line_done(&last);
        }
        Found {
            binary: self.binary == Some(true),
            selected: self.selected,
        }
    }

    fn decide(&mut self) {
        let head = std::mem::take(&mut self.head);
        let sniff = &head[..head.len().min(BINARY_SNIFF)];
        self.binary = Some(sniff.contains(&0));
        self.feed(&head);
    }

    fn feed(&mut self, mut data: &[u8]) {
        while let Some(i) = data.iter().position(|b| *b == b'\n') {
            if self.pending.is_empty() {
                self.line_done(&data[..i]);
            } else {
                self.pending.extend_from_slice(&data[..i]);
                let line = std::mem::take(&mut self.pending);
                self.line_done(&line);
            }
            data = &data[i + 1..];
        }
        self.pending.extend_from_slice(data);
    }

    fn line_done(&mut self, line: &[u8]) {
        self.line += 1;
        if self.matcher.selects(line) {
            self.selected += 1;
            if self.binary == Some(false) {
                (self.on_line)(self.line, line);
            }
        }
    }
}

impl std::fmt::Debug for Scanner<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Scanner")
            .field("binary", &self.binary)
            .field("line", &self.line)
            .field("selected", &self.selected)
            .finish_non_exhaustive()
    }
}

impl io::Write for Scanner<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.binary.is_some() {
            self.feed(buf);
        } else {
            self.head.extend_from_slice(buf);
            if self.head.len() >= BINARY_SNIFF {
                self.decide();
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::io::Write;

    use super::*;

    fn scan(m: &Matcher, pieces: &[&[u8]]) -> (Vec<(u64, Vec<u8>)>, Found) {
        let mut lines = Vec::new();
        let mut on_line = |n: u64, l: &[u8]| lines.push((n, l.to_vec()));
        let mut s = Scanner::new(m, &mut on_line);
        for p in pieces {
            s.write_all(p).unwrap();
        }
        let found = s.finish();
        (lines, found)
    }

    #[test]
    fn whole_words_retry_past_a_partial_match() {
        let m = Matcher::new(
            &["foo"],
            Options {
                word: true,
                ..Options::default()
            },
        )
        .unwrap();
        assert!(m.selects(b"foobar foo"));
        assert!(m.selects(b"(foo)"));
        assert!(!m.selects(b"foobar food"));
        assert!(!m.selects(b"foo_bar"));
    }

    #[test]
    fn fixed_strings_escape_and_several_patterns_alternate() {
        let m = Matcher::new(
            &["a.c", "(x"],
            Options {
                fixed: true,
                ..Options::default()
            },
        )
        .unwrap();
        assert!(m.selects(b"za.c"));
        assert!(m.selects(b"(x)"));
        assert!(!m.selects(b"abc"));
        assert!(Matcher::new(&["("], Options::default()).is_err());
        assert!(Matcher::new::<&str>(&[], Options::default()).is_err());
    }

    #[test]
    fn a_binary_file_counts_but_reports_no_line() {
        let m = Matcher::new(&["n"], Options::default()).unwrap();
        let (lines, found) = scan(&m, &[b"a\0n\nn"]);
        assert!(lines.is_empty());
        assert_eq!(
            found,
            Found {
                binary: true,
                selected: 2
            }
        );
    }

    proptest::proptest! {
        /// Cutting the input anywhere gives the lines of a whole-file scan.
        #[test]
        fn pieces_do_not_change_the_lines(
            text in "[ab\n]{0,64}",
            cuts in proptest::collection::vec(0usize..64, 0..6),
        ) {
            let m = Matcher::new(&["a"], Options::default()).unwrap();
            let bytes = text.as_bytes();
            let mut cuts: Vec<usize> = cuts.into_iter().map(|c| c.min(bytes.len())).collect();
            cuts.sort_unstable();
            let mut pieces = Vec::new();
            let mut start = 0;
            for c in cuts {
                pieces.push(&bytes[start..c]);
                start = c;
            }
            pieces.push(&bytes[start..]);
            let (lines, found) = scan(&m, &pieces);
            let expected: Vec<(u64, Vec<u8>)> = text
                .lines()
                .enumerate()
                .filter(|(_, l)| l.contains('a'))
                .map(|(i, l)| (u64::try_from(i).unwrap() + 1, l.as_bytes().to_vec()))
                .collect();
            proptest::prop_assert_eq!(found.selected, u64::try_from(expected.len()).unwrap());
            proptest::prop_assert_eq!(lines, expected);
        }
    }
}
