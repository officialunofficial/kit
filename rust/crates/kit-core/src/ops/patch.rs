//! Unified-diff patches (SPEC-PATCH): parse the text, reverse a file patch,
//! and apply one to the content of a file.
//!
//! Parsing takes hostile input. Every bound is checked before the memory it
//! limits is used, and a patch is accepted whole or refused.

use std::collections::HashSet;
use std::fmt;

/// The largest patch text kit reads (SPEC-PATCH §3).
pub const MAX_PATCH_BYTES: usize = 64 * 1024 * 1024;
/// The most file patches one patch holds.
pub const MAX_FILES: usize = 100_000;
/// The most hunks one patch holds.
pub const MAX_HUNKS: usize = 1_000_000;
/// The largest line number or count in a hunk header, 2^31 - 1.
const MAX_NUMBER: u64 = (1 << 31) - 1;

/// The mode of a file: a regular file or an executable one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// `100644`.
    Regular,
    /// `100755`.
    Executable,
}

/// One hunk. Each line keeps its newline, except a last line that has none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hunk {
    /// The 1-based line the old side starts at, or the line after which an
    /// empty old side goes.
    pub old_start: u32,
    /// As `old_start`, for the new side.
    pub new_start: u32,
    /// The context and removed lines.
    pub old: Vec<Vec<u8>>,
    /// The context and added lines.
    pub new: Vec<Vec<u8>>,
    /// The number of added lines.
    pub added: usize,
    /// The number of removed lines.
    pub removed: usize,
}

/// One file patch. A side that is `None` is `/dev/null`: the patch creates
/// or deletes the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilePatch {
    /// The path before the patch.
    pub old: Option<String>,
    /// The path after the patch.
    pub new: Option<String>,
    /// The mode before, when the patch names one.
    pub old_mode: Option<Mode>,
    /// The mode after, when the patch names one.
    pub new_mode: Option<Mode>,
    /// The hunks, in order.
    pub hunks: Vec<Hunk>,
}

impl FilePatch {
    /// The patch that undoes this one: the sides, the paths and the modes
    /// swap.
    #[must_use]
    pub fn reversed(&self) -> Self {
        Self {
            old: self.new.clone(),
            new: self.old.clone(),
            old_mode: self.new_mode,
            new_mode: self.old_mode,
            hunks: self
                .hunks
                .iter()
                .map(|h| Hunk {
                    old_start: h.new_start,
                    new_start: h.old_start,
                    old: h.new.clone(),
                    new: h.old.clone(),
                    added: h.removed,
                    removed: h.added,
                })
                .collect(),
        }
    }

    /// The added and the removed lines of all hunks.
    #[must_use]
    pub fn counts(&self) -> (usize, usize) {
        self.hunks
            .iter()
            .fold((0, 0), |(a, r), h| (a + h.added, r + h.removed))
    }
}

/// Why a patch text was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseErrorKind {
    /// The text is over [`MAX_PATCH_BYTES`].
    TooLarge,
    /// Over [`MAX_FILES`] file patches.
    TooManyFiles,
    /// Over [`MAX_HUNKS`] hunks.
    TooManyHunks,
    /// No file patch at all.
    NoPatch,
    /// A hunk body that holds fewer or more lines than its header counts.
    Count,
    /// A hunk body line with an unexpected first byte.
    BadLine,
    /// A hunk header that does not parse.
    BadHunkHeader,
    /// A line number or count over 2^31 - 1.
    Number,
    /// A hunk that no file patch header precedes.
    HunkOutsideFile,
    /// A path that is empty, absolute, holds `.` or `..`, or names the
    /// repository directory.
    Path(String),
    /// A path that two file patches name.
    DuplicatePath(String),
    /// A file patch whose paths cannot be found or disagree.
    MissingPath,
    /// A file patch that changes nothing.
    Empty,
    /// A mode other than `100644` or `100755`.
    Mode(String),
    /// A `GIT binary patch` or `Binary files ... differ`.
    Binary,
    /// A `copy from` or `copy to` line.
    Copy,
    /// Mode `120000`.
    Symlink,
}

/// A refused patch text, with the 1-based line where it was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    /// The line of the patch text.
    pub line: usize,
    /// What is wrong.
    pub kind: ParseErrorKind,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use ParseErrorKind as K;
        let what = match &self.kind {
            K::TooLarge => return write!(f, "the patch is over {MAX_PATCH_BYTES} bytes"),
            K::TooManyFiles => return write!(f, "the patch holds over {MAX_FILES} file patches"),
            K::TooManyHunks => return write!(f, "the patch holds over {MAX_HUNKS} hunks"),
            K::NoPatch => return write!(f, "no patch found"),
            K::Count => "the hunk body disagrees with the line count of its header".to_owned(),
            K::BadLine => "a hunk line starts with an unexpected byte".to_owned(),
            K::BadHunkHeader => "malformed hunk header".to_owned(),
            K::Number => "a line number or count is out of range".to_owned(),
            K::HunkOutsideFile => "a hunk is outside a file patch".to_owned(),
            K::Path(p) => format!("refused path '{p}'"),
            K::DuplicatePath(p) => format!("the patch names the path '{p}' twice"),
            K::MissingPath => "a file patch has no usable path".to_owned(),
            K::Empty => "a file patch changes nothing".to_owned(),
            K::Mode(m) => format!("mode {m} is not supported"),
            K::Binary => "binary patches are not supported".to_owned(),
            K::Copy => "copy patches are not supported".to_owned(),
            K::Symlink => "symlinks (mode 120000) are not supported".to_owned(),
        };
        write!(f, "line {}: {what}", self.line)
    }
}

impl std::error::Error for ParseError {}

/// Why a file patch does not apply to the content of a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyError {
    /// The patch creates a file that exists.
    Exists,
    /// The patch changes a file that does not exist.
    Missing,
    /// The hunk with this 0-based index matches no lines.
    Hunk(usize),
    /// The patch deletes a file that holds more than its old side.
    NotEmpty,
}

impl fmt::Display for ApplyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exists => write!(f, "already exists"),
            Self::Missing => write!(f, "does not exist"),
            Self::Hunk(i) => write!(f, "hunk {} does not apply", i + 1),
            Self::NotEmpty => write!(f, "holds lines the deletion does not name"),
        }
    }
}

impl std::error::Error for ApplyError {}

/// The content of `content` after `patch`, or `None` when the patch deletes
/// the file. `content` is `None` for a file that does not exist.
///
/// # Errors
/// [`ApplyError`] when the patch does not apply.
pub fn apply(content: Option<&[u8]>, patch: &FilePatch) -> Result<Option<Vec<u8>>, ApplyError> {
    let base = match (content, patch.old.is_some()) {
        (Some(_), false) => return Err(ApplyError::Exists),
        (None, true) => return Err(ApplyError::Missing),
        (Some(c), true) => c,
        (None, false) => &[],
    };
    let out = apply_hunks(base, &patch.hunks)?;
    if patch.new.is_none() {
        return if out.is_empty() {
            Ok(None)
        } else {
            Err(ApplyError::NotEmpty)
        };
    }
    Ok(Some(out))
}

/// Apply `hunks` in order. Each one goes where its old lines equal the
/// lines of the content, at the line its header names or the nearest line
/// that matches, and never before the end of the hunk before it.
fn apply_hunks(base: &[u8], hunks: &[Hunk]) -> Result<Vec<u8>, ApplyError> {
    let lines: Vec<&[u8]> = base.split_inclusive(|&b| b == b'\n').collect();
    let mut out = Vec::with_capacity(base.len());
    let mut cursor = 0usize;
    let mut offset = 0i64;
    for (k, h) in hunks.iter().enumerate() {
        let named = i64::from(h.old_start) - i64::from(!h.old.is_empty());
        let want = named + offset;
        let at = find(&lines, &h.old, want, cursor).ok_or(ApplyError::Hunk(k))?;
        offset = i64::try_from(at).unwrap_or(i64::MAX) - named;
        let end = at + h.old.len();
        // A new side that ends without a newline must end the file.
        if end < lines.len() && h.new.last().is_some_and(|l| !l.ends_with(b"\n")) {
            return Err(ApplyError::Hunk(k));
        }
        for l in &lines[cursor..at] {
            out.extend_from_slice(l);
        }
        for l in &h.new {
            out.extend_from_slice(l);
        }
        cursor = end;
    }
    for l in &lines[cursor..] {
        out.extend_from_slice(l);
    }
    Ok(out)
}

/// The first position nearest `want`, at or after `lo`, where `old` equals
/// the lines. kit tries `want`, then one line on each side, and so on.
fn find(lines: &[&[u8]], old: &[Vec<u8>], want: i64, lo: usize) -> Option<usize> {
    let hi = lines.len().checked_sub(old.len())?;
    if lo > hi {
        return None;
    }
    let matches = |p: usize| {
        lines[p..p + old.len()]
            .iter()
            .zip(old)
            .all(|(a, b)| *a == b.as_slice())
    };
    let lo_i = i64::try_from(lo).ok()?;
    let hi_i = i64::try_from(hi).ok()?;
    let start = want.clamp(lo_i, hi_i);
    for d in 0..=(hi_i - lo_i) {
        let below = start - d;
        let above = start + d;
        if below < lo_i && above > hi_i {
            break;
        }
        for p in [below, above] {
            if (lo_i..=hi_i).contains(&p) {
                let p = usize::try_from(p).ok()?;
                if matches(p) {
                    return Some(p);
                }
            }
            if d == 0 {
                break;
            }
        }
    }
    None
}

/// Parse a patch text into its file patches. Text around them is ignored.
///
/// # Errors
/// [`ParseError`] for a text that breaks SPEC-PATCH §2 or §3.
pub fn parse(text: &[u8]) -> Result<Vec<FilePatch>, ParseError> {
    if text.len() > MAX_PATCH_BYTES {
        return Err(ParseError {
            line: 0,
            kind: ParseErrorKind::TooLarge,
        });
    }
    let mut p = Parser {
        lines: text.split_inclusive(|&b| b == b'\n').collect(),
        at: 0,
        hunks: 0,
    };
    let mut out: Vec<FilePatch> = Vec::new();
    let mut seen = HashSet::new();
    while p.at < p.lines.len() {
        let start = p.at;
        let line = p.line(start);
        let file = if line.starts_with(b"diff --git ") {
            p.git_file()?
        } else if line.starts_with(b"--- ")
            && p.at + 1 < p.lines.len()
            && p.line(p.at + 1).starts_with(b"+++ ")
        {
            p.plain_file()?
        } else if line.starts_with(b"@@ ") {
            return Err(p.err(ParseErrorKind::HunkOutsideFile));
        } else {
            p.at += 1;
            continue;
        };
        if out.len() == MAX_FILES {
            return Err(err_at(start, ParseErrorKind::TooManyFiles));
        }
        let renamed = file.new.as_ref().filter(|n| file.old.as_ref() != Some(*n));
        for path in file.old.iter().chain(renamed) {
            if !seen.insert(path.clone()) {
                return Err(err_at(start, ParseErrorKind::DuplicatePath(path.clone())));
            }
        }
        out.push(file);
    }
    if out.is_empty() {
        return Err(ParseError {
            line: 0,
            kind: ParseErrorKind::NoPatch,
        });
    }
    Ok(out)
}

/// An error at the 0-based line `i`.
fn err_at(i: usize, kind: ParseErrorKind) -> ParseError {
    ParseError { line: i + 1, kind }
}

struct Parser<'a> {
    lines: Vec<&'a [u8]>,
    at: usize,
    hunks: usize,
}

/// The header lines of a `diff --git` file patch.
#[derive(Default)]
struct GitHeader {
    old_mode: Option<Mode>,
    new_mode: Option<Mode>,
    created: bool,
    deleted: bool,
    rename_from: Option<String>,
    rename_to: Option<String>,
}

impl<'a> Parser<'a> {
    /// Line `i` without its newline.
    fn line(&self, i: usize) -> &'a [u8] {
        let l = self.lines[i];
        l.strip_suffix(b"\n").unwrap_or(l)
    }

    fn err(&self, kind: ParseErrorKind) -> ParseError {
        err_at(self.at, kind)
    }

    /// A file patch that starts at `diff --git`.
    fn git_file(&mut self) -> Result<FilePatch, ParseError> {
        let start = self.at;
        let line_paths = git_line_paths(&self.line(start)[b"diff --git ".len()..]);
        self.at += 1;
        let mut h = GitHeader::default();
        let mut sides = None;
        while self.at < self.lines.len() {
            let l = self.line(self.at);
            if let Some(m) = l.strip_prefix(b"old mode ") {
                h.old_mode = Some(self.mode(m)?);
            } else if let Some(m) = l.strip_prefix(b"new mode ") {
                h.new_mode = Some(self.mode(m)?);
            } else if let Some(m) = l.strip_prefix(b"deleted file mode ") {
                h.deleted = true;
                h.old_mode = Some(self.mode(m)?);
            } else if let Some(m) = l.strip_prefix(b"new file mode ") {
                h.created = true;
                h.new_mode = Some(self.mode(m)?);
            } else if let Some(p) = l.strip_prefix(b"rename from ") {
                h.rename_from = Some(self.path(p, false)?);
            } else if let Some(p) = l.strip_prefix(b"rename to ") {
                h.rename_to = Some(self.path(p, false)?);
            } else if l.starts_with(b"similarity index ") || l.starts_with(b"dissimilarity index ")
            {
            } else if let Some(rest) = l.strip_prefix(b"index ") {
                if let Some((_, m)) = rest.split_once_byte(b' ') {
                    self.mode(m)?;
                }
            } else if l.starts_with(b"copy from ") || l.starts_with(b"copy to ") {
                return Err(self.err(ParseErrorKind::Copy));
            } else if l.starts_with(b"GIT binary patch") || l.starts_with(b"Binary files ") {
                return Err(self.err(ParseErrorKind::Binary));
            } else if l.starts_with(b"--- ") {
                sides = Some(self.sides()?);
                break;
            } else {
                break;
            }
            self.at += 1;
        }
        let hunks = self.hunks()?;
        let (old, new) = if let Some(s) = sides {
            s
        } else {
            let from_line = |second: bool| -> Result<String, ParseError> {
                let n = line_paths
                    .as_ref()
                    .ok_or_else(|| err_at(start, ParseErrorKind::MissingPath))?;
                self.path(if second { &n.1 } else { &n.0 }, true)
            };
            let old = match (h.created, h.rename_from.clone()) {
                (true, _) => None,
                (false, Some(p)) => Some(p),
                (false, None) => Some(from_line(false)?),
            };
            let new = match (h.deleted, h.rename_to.clone()) {
                (true, _) => None,
                (false, Some(p)) => Some(p),
                (false, None) => Some(from_line(true)?),
            };
            (old, new)
        };
        if (h.created && old.is_some())
            || (h.deleted && new.is_some())
            || (old.is_none() && new.is_none())
            || (h.rename_from.is_some() && h.rename_from != old)
            || (h.rename_to.is_some() && h.rename_to != new)
        {
            return Err(err_at(start, ParseErrorKind::MissingPath));
        }
        let file = FilePatch {
            old,
            new,
            old_mode: h.old_mode,
            new_mode: h.new_mode,
            hunks,
        };
        if file.old == file.new && file.hunks.is_empty() && file.old_mode == file.new_mode {
            return Err(err_at(start, ParseErrorKind::Empty));
        }
        Ok(file)
    }

    /// A file patch that starts at `---` with no `diff --git` line.
    fn plain_file(&mut self) -> Result<FilePatch, ParseError> {
        let start = self.at;
        let (old, new) = self.sides()?;
        let hunks = self.hunks()?;
        if hunks.is_empty() || (old.is_none() && new.is_none()) {
            return Err(err_at(start, ParseErrorKind::Empty));
        }
        Ok(FilePatch {
            old,
            new,
            old_mode: None,
            new_mode: None,
            hunks,
        })
    }

    /// The `---` and `+++` lines at the cursor.
    fn sides(&mut self) -> Result<(Option<String>, Option<String>), ParseError> {
        let old = self.side(self.line(self.at), b"--- ")?;
        self.at += 1;
        if self.at >= self.lines.len() || !self.line(self.at).starts_with(b"+++ ") {
            return Err(self.err(ParseErrorKind::MissingPath));
        }
        let new = self.side(self.line(self.at), b"+++ ")?;
        self.at += 1;
        Ok((old, new))
    }

    fn side(&self, line: &[u8], prefix: &[u8]) -> Result<Option<String>, ParseError> {
        let rest = &line[prefix.len()..];
        let raw = if rest.starts_with(b"\"") {
            rest
        } else {
            // git ends a path that holds a space with a tab; GNU diff puts
            // the date after one.
            rest.split(|&b| b == b'\t').next().unwrap_or(rest)
        };
        if raw == b"/dev/null" {
            return Ok(None);
        }
        self.path(raw, true).map(Some)
    }

    /// A path from the patch: unquoted, stripped of one component when
    /// `strip`, and checked.
    fn path(&self, raw: &[u8], strip: bool) -> Result<String, ParseError> {
        let shown = || String::from_utf8_lossy(raw).into_owned();
        let bytes = if raw.starts_with(b"\"") {
            match unquote(raw) {
                Some((b, rest)) if rest.is_empty() || rest.starts_with(b"\t") => b,
                _ => return Err(self.err(ParseErrorKind::Path(shown()))),
            }
        } else {
            raw.to_vec()
        };
        let stripped = if strip {
            match bytes.iter().position(|&b| b == b'/') {
                Some(i) => bytes[i + 1..].to_vec(),
                None => return Err(self.err(ParseErrorKind::Path(shown()))),
            }
        } else {
            bytes
        };
        match String::from_utf8(stripped) {
            Ok(s) if crate::index::validate_index_path(&s) => Ok(s),
            _ => Err(self.err(ParseErrorKind::Path(shown()))),
        }
    }

    fn mode(&self, m: &[u8]) -> Result<Mode, ParseError> {
        match m {
            b"100644" => Ok(Mode::Regular),
            b"100755" => Ok(Mode::Executable),
            b"120000" => Err(self.err(ParseErrorKind::Symlink)),
            other => Err(self.err(ParseErrorKind::Mode(
                String::from_utf8_lossy(other).into_owned(),
            ))),
        }
    }

    /// The hunks at the cursor, up to the first line that starts none.
    fn hunks(&mut self) -> Result<Vec<Hunk>, ParseError> {
        let mut out = Vec::new();
        while self.at < self.lines.len() {
            let l = self.line(self.at);
            if l.starts_with(b"GIT binary patch") || l.starts_with(b"Binary files ") {
                return Err(self.err(ParseErrorKind::Binary));
            }
            if !l.starts_with(b"@@ ") {
                break;
            }
            if self.hunks == MAX_HUNKS {
                return Err(self.err(ParseErrorKind::TooManyHunks));
            }
            self.hunks += 1;
            out.push(self.hunk()?);
        }
        Ok(out)
    }

    fn hunk(&mut self) -> Result<Hunk, ParseError> {
        let (old_start, old_len, new_start, new_len) =
            hunk_header(self.line(self.at)).map_err(|k| self.err(k))?;
        if (old_len > 0 && old_start == 0) || (new_len > 0 && new_start == 0) {
            return Err(self.err(ParseErrorKind::BadHunkHeader));
        }
        self.at += 1;
        let (old_len, new_len) = (old_len as usize, new_len as usize);
        let mut h = Hunk {
            old_start,
            new_start,
            old: Vec::new(),
            new: Vec::new(),
            added: 0,
            removed: 0,
        };
        let mut last = None;
        loop {
            let full = h.old.len() == old_len && h.new.len() == new_len;
            let Some(raw) = self.lines.get(self.at).copied() else {
                if full {
                    break;
                }
                return Err(self.err(ParseErrorKind::Count));
            };
            let first = raw.first().copied();
            if first == Some(b'\\') {
                self.no_newline(&mut h, last)?;
                last = None;
                self.at += 1;
                continue;
            }
            if full {
                break;
            }
            let mut body = raw[1..].to_vec();
            if !body.ends_with(b"\n") {
                body.push(b'\n');
            }
            let (to_old, to_new) = match first {
                Some(b' ') => (true, true),
                Some(b'-') => (true, false),
                Some(b'+') => (false, true),
                _ => return Err(self.err(ParseErrorKind::BadLine)),
            };
            if (to_old && h.old.len() == old_len) || (to_new && h.new.len() == new_len) {
                return Err(self.err(ParseErrorKind::Count));
            }
            for (go, side) in [(to_old, &mut h.old), (to_new, &mut h.new)] {
                if go {
                    if side.last().is_some_and(|l| !l.ends_with(b"\n")) {
                        return Err(self.err(ParseErrorKind::BadLine));
                    }
                    side.push(body.clone());
                }
            }
            h.removed += usize::from(to_old && !to_new);
            h.added += usize::from(to_new && !to_old);
            last = first;
            self.at += 1;
        }
        Ok(h)
    }

    /// `\ No newline at end of file`: the line before has no newline on its
    /// side.
    fn no_newline(&self, h: &mut Hunk, last: Option<u8>) -> Result<(), ParseError> {
        let sides: &mut [&mut Vec<Vec<u8>>] = match last {
            Some(b' ') => &mut [&mut h.old, &mut h.new],
            Some(b'-') => &mut [&mut h.old],
            Some(b'+') => &mut [&mut h.new],
            _ => return Err(self.err(ParseErrorKind::BadLine)),
        };
        for side in sides.iter_mut() {
            match side.last_mut() {
                Some(l) if l.ends_with(b"\n") => {
                    l.pop();
                }
                _ => return Err(self.err(ParseErrorKind::BadLine)),
            }
        }
        Ok(())
    }
}

trait SplitOnce {
    fn split_once_byte(&self, b: u8) -> Option<(&[u8], &[u8])>;
}

impl SplitOnce for [u8] {
    fn split_once_byte(&self, b: u8) -> Option<(&[u8], &[u8])> {
        let i = self.iter().position(|&c| c == b)?;
        Some((&self[..i], &self[i + 1..]))
    }
}

/// `@@ -<l>[,<s>] +<l>[,<s>] @@[ <text>]`.
fn hunk_header(line: &[u8]) -> Result<(u32, u32, u32, u32), ParseErrorKind> {
    let bad = || ParseErrorKind::BadHunkHeader;
    let rest = line.strip_prefix(b"@@ -").ok_or_else(bad)?;
    let (os, ol, rest) = range(rest)?;
    let rest = rest.strip_prefix(b" +").ok_or_else(bad)?;
    let (ns, nl, rest) = range(rest)?;
    let rest = rest.strip_prefix(b" @@").ok_or_else(bad)?;
    if !(rest.is_empty() || rest.starts_with(b" ")) {
        return Err(bad());
    }
    Ok((os, ol, ns, nl))
}

/// `<l>[,<s>]`, with a missing `<s>` read as 1.
fn range(s: &[u8]) -> Result<(u32, u32, &[u8]), ParseErrorKind> {
    let (start, rest) = number(s)?;
    match rest.strip_prefix(b",") {
        Some(r) => {
            let (len, rest) = number(r)?;
            Ok((start, len, rest))
        }
        None => Ok((start, 1, rest)),
    }
}

fn number(s: &[u8]) -> Result<(u32, &[u8]), ParseErrorKind> {
    let digits = s.iter().take_while(|b| b.is_ascii_digit()).count();
    if digits == 0 {
        return Err(ParseErrorKind::BadHunkHeader);
    }
    let mut n = 0u64;
    for &b in &s[..digits] {
        n = n * 10 + u64::from(b - b'0');
        if n > MAX_NUMBER {
            return Err(ParseErrorKind::Number);
        }
    }
    Ok((
        u32::try_from(n).map_err(|_| ParseErrorKind::Number)?,
        &s[digits..],
    ))
}

/// The two paths of a `diff --git` line, before one component is stripped.
/// Unquoted paths that hold a space are ambiguous: the split that gives the
/// same path on both sides wins, and with none the paths come from other
/// header lines.
fn git_line_paths(rest: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    if rest.starts_with(b"\"") {
        let (a, after) = unquote(rest)?;
        let after = after.strip_prefix(b" ")?;
        let b = if after.starts_with(b"\"") {
            let (b, tail) = unquote(after)?;
            if !tail.is_empty() {
                return None;
            }
            b
        } else {
            after.to_vec()
        };
        return Some((a, b));
    }
    if let Some(i) = rest.windows(2).position(|w| w == b" \"") {
        let (b, tail) = unquote(&rest[i + 1..])?;
        if !tail.is_empty() {
            return None;
        }
        return Some((rest[..i].to_vec(), b));
    }
    let tail = |p: &[u8]| {
        p.iter()
            .position(|&b| b == b'/')
            .map(|i| p[i + 1..].to_vec())
    };
    rest.iter()
        .enumerate()
        .filter(|(_, b)| **b == b' ')
        .map(|(i, _)| (&rest[..i], &rest[i + 1..]))
        .find(|(a, b)| tail(a).is_some() && tail(a) == tail(b))
        .map(|(a, b)| (a.to_vec(), b.to_vec()))
}

/// A path in double quotes with git's C escapes, and the bytes after the
/// closing quote.
fn unquote(s: &[u8]) -> Option<(Vec<u8>, &[u8])> {
    let mut out = Vec::new();
    let mut i = 1;
    loop {
        match *s.get(i)? {
            b'"' => return Some((out, &s[i + 1..])),
            b'\\' => {
                let c = *s.get(i + 1)?;
                let byte = match c {
                    b'\\' => b'\\',
                    b'"' => b'"',
                    b'a' => 0x07,
                    b'b' => 0x08,
                    b't' => b'\t',
                    b'n' => b'\n',
                    b'v' => 0x0b,
                    b'f' => 0x0c,
                    b'r' => b'\r',
                    b'0'..=b'3' => {
                        let d = s.get(i + 1..i + 4)?;
                        if !d.iter().all(|b| (b'0'..=b'7').contains(b)) {
                            return None;
                        }
                        i += 2;
                        (d[0] - b'0') * 64 + (d[1] - b'0') * 8 + (d[2] - b'0')
                    }
                    _ => return None,
                };
                out.push(byte);
                i += 2;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const EDIT: &str = "diff --git a/f.txt b/f.txt\nindex 1..2 100644\n--- a/f.txt\n+++ b/f.txt\n@@ -1,3 +1,3 @@\n a\n-b\n+B\n c\n";

    #[test]
    fn a_git_patch_parses_and_applies() {
        let files = parse(EDIT.as_bytes()).unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].old.as_deref(), Some("f.txt"));
        assert_eq!(files[0].counts(), (1, 1));
        let out = apply(Some(b"a\nb\nc\n"), &files[0]).unwrap();
        assert_eq!(out.as_deref(), Some(&b"a\nB\nc\n"[..]));
        let back = apply(Some(b"a\nB\nc\n"), &files[0].reversed()).unwrap();
        assert_eq!(back.as_deref(), Some(&b"a\nb\nc\n"[..]));
    }

    #[test]
    fn a_hunk_applies_at_the_nearest_match_and_never_with_fuzz() {
        let files = parse(EDIT.as_bytes()).unwrap();
        let out = apply(Some(b"x\ny\na\nb\nc\n"), &files[0]).unwrap();
        assert_eq!(out.as_deref(), Some(&b"x\ny\na\nB\nc\n"[..]));
        assert_eq!(
            apply(Some(b"a\nb\nC\n"), &files[0]),
            Err(ApplyError::Hunk(0))
        );
    }

    #[test]
    fn creation_deletion_and_existence() {
        let text =
            "diff --git a/n b/n\nnew file mode 100755\n--- /dev/null\n+++ b/n\n@@ -0,0 +1 @@\n+x\n";
        let f = &parse(text.as_bytes()).unwrap()[0];
        assert_eq!(
            (f.old.as_deref(), f.new_mode),
            (None, Some(Mode::Executable))
        );
        assert_eq!(apply(None, f).unwrap().as_deref(), Some(&b"x\n"[..]));
        assert_eq!(apply(Some(b""), f), Err(ApplyError::Exists));
        let r = f.reversed();
        assert_eq!(apply(Some(b"x\n"), &r), Ok(None));
        assert_eq!(apply(Some(b"x\ny\n"), &r), Err(ApplyError::NotEmpty));
        assert_eq!(apply(None, &r), Err(ApplyError::Missing));
    }

    #[test]
    fn no_newline_markers_strip_the_newline_of_their_side() {
        let text = "--- a/f\n+++ b/f\n@@ -1 +1 @@\n-a\n\\ No newline at end of file\n+a\n";
        let f = &parse(text.as_bytes()).unwrap()[0];
        assert_eq!(f.hunks[0].old, vec![b"a".to_vec()]);
        assert_eq!(f.hunks[0].new, vec![b"a\n".to_vec()]);
        assert_eq!(apply(Some(b"a"), f).unwrap().as_deref(), Some(&b"a\n"[..]));
    }

    #[test]
    fn renames_and_quoted_paths() {
        let text = "diff --git a/old b/\"sp ace\\303\\251\"\nsimilarity index 100%\nrename from old\nrename to \"sp ace\\303\\251\"\n";
        let f = &parse(text.as_bytes()).unwrap()[0];
        assert_eq!(f.old.as_deref(), Some("old"));
        assert_eq!(f.new.as_deref(), Some("sp aceé"));
        let text = "diff --git a/sp ace b/sp ace\nold mode 100644\nnew mode 100755\n";
        let f = &parse(text.as_bytes()).unwrap()[0];
        assert_eq!(f.old.as_deref(), Some("sp ace"));
        assert_eq!(f.new_mode, Some(Mode::Executable));
    }

    #[test]
    fn refusals() {
        let kind = |t: &str| parse(t.as_bytes()).unwrap_err().kind;
        assert_eq!(kind("hello\n"), ParseErrorKind::NoPatch);
        assert_eq!(
            kind("--- a/f\n+++ b/f\n@@ -1,2 +1,2 @@\n a\n"),
            ParseErrorKind::Count
        );
        assert_eq!(
            kind("--- a/f\n+++ b/f\n@@ -1 +1 @@\n*a\n"),
            ParseErrorKind::BadLine
        );
        assert_eq!(
            kind("--- a/f\n+++ b/f\n@@ -1 +1,99999999999 @@\n"),
            ParseErrorKind::Number
        );
        assert_eq!(kind("@@ -1 +1 @@\n a\n"), ParseErrorKind::HunkOutsideFile);
        assert!(matches!(
            kind("--- a/../x\n+++ b/../x\n@@ -0,0 +1 @@\n+x\n"),
            ParseErrorKind::Path(_)
        ));
        assert!(matches!(
            kind("--- a/.kit/x\n+++ b/.kit/x\n@@ -0,0 +1 @@\n+x\n"),
            ParseErrorKind::Path(_)
        ));
        assert!(matches!(
            kind("--- a//abs\n+++ b//abs\n@@ -0,0 +1 @@\n+x\n"),
            ParseErrorKind::Path(_)
        ));
        assert_eq!(
            kind("diff --git a/f b/f\nGIT binary patch\n"),
            ParseErrorKind::Binary
        );
        assert_eq!(
            kind("diff --git a/f b/f\nBinary files a/f and b/f differ\n"),
            ParseErrorKind::Binary
        );
        assert_eq!(
            kind("diff --git a/f b/g\ncopy from f\ncopy to g\n"),
            ParseErrorKind::Copy
        );
        assert_eq!(
            kind("diff --git a/f b/f\nnew file mode 120000\n"),
            ParseErrorKind::Symlink
        );
        assert!(matches!(
            kind("diff --git a/f b/f\nnew file mode 100600\n"),
            ParseErrorKind::Mode(_)
        ));
        let twice = format!("{EDIT}{EDIT}");
        assert!(matches!(kind(&twice), ParseErrorKind::DuplicatePath(_)));
    }

    /// Lines of a file from a small alphabet, so hunks collide often.
    fn content() -> impl Strategy<Value = Vec<u8>> {
        (proptest::collection::vec("[ab]{0,2}", 0..10), any::<bool>()).prop_map(|(lines, eol)| {
            let mut s = lines.join("\n");
            if eol && !lines.is_empty() {
                s.push('\n');
            }
            s.into_bytes()
        })
    }

    /// A unified diff of `a` to `b` with one hunk that covers both files.
    fn whole_file_patch(a: &[u8], b: &[u8]) -> String {
        let side = |c: &[u8], mark: char| {
            let mut s = String::new();
            let lines: Vec<&[u8]> = c.split_inclusive(|&x| x == b'\n').collect();
            for l in &lines {
                s.push(mark);
                s.push_str(std::str::from_utf8(l).unwrap());
                if !l.ends_with(b"\n") {
                    s.push_str("\n\\ No newline at end of file\n");
                }
            }
            (s, lines.len())
        };
        let (old, ol) = side(a, '-');
        let (new, nl) = side(b, '+');
        format!(
            "--- a/f\n+++ b/f\n@@ -{},{ol} +{},{nl} @@\n{old}{new}",
            usize::from(ol > 0),
            usize::from(nl > 0)
        )
    }

    proptest! {
        /// A patch of A to B turns A into B, and its reverse turns B into A.
        #[test]
        fn apply_and_reverse_round_trip(a in content(), b in content()) {
            prop_assume!(!a.is_empty() || !b.is_empty());
            let text = whole_file_patch(&a, &b);
            let f = &parse(text.as_bytes()).unwrap()[0];
            prop_assert_eq!(apply(Some(&a), f).unwrap(), Some(b.clone()));
            prop_assert_eq!(apply(Some(&b), &f.reversed()).unwrap(), Some(a));
        }

        /// The parser never panics, and a parsed patch respects the bounds.
        #[test]
        fn parse_never_panics(text in proptest::collection::vec(any::<u8>(), 0..400)) {
            if let Ok(files) = parse(&text) {
                prop_assert!(!files.is_empty());
                for f in &files {
                    for h in &f.hunks {
                        prop_assert_eq!(h.old.len() - h.removed, h.new.len() - h.added);
                    }
                }
            }
        }
    }
}
