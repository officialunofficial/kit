//! `.kitignore` / `.gitignore` glob patterns.
//!
//! Matching is **path-relative** (git-faithful), not basename-only: callers
//! pass a path relative to the repository root and the matcher honors the
//! gitignore anchoring rules below.
//!
//! Grammar (the implemented v1 subset of `gitignore`):
//! - One pattern per line; blank lines and `#`-prefixed lines are skipped
//!   (`\#` escapes a leading `#` to a literal).
//! - A leading `!` negates (last match wins, gitignore semantics); `\!`
//!   escapes a leading `!` to a literal.
//! - A trailing `/` makes the pattern match directories only.
//! - **Anchoring:** a pattern containing a `/` anywhere other than a trailing
//!   one is *anchored* to the repo root (a leading `/` is one way; `foo/bar`
//!   is another). A pattern with no such `/` matches at **any depth** (as if
//!   prefixed with `**/`), so `*.log` matches `a/b/c.log`.
//! - `*` matches any run of non-`/`; `?` matches a single non-`/`;
//!   `[abc]` / `[a-z]` / `[!abc]` are character classes (single non-`/`).
//!   `\` escapes the next character to a literal.
//! - `**` as a whole path segment crosses `/`: leading `**/` and middle
//!   `/**/` match zero or more directories; a trailing `/**` matches one or
//!   more (everything *inside* a directory). A `**` not isolated by slashes
//!   behaves like a single `*`.
//! - Trailing unescaped spaces are trimmed.
//!
//! `.kit` and `.git` are *always* ignored (matched on the path's basename,
//! ASCII case-insensitively, so `.KIT` can't bypass on case-insensitive
//! filesystems — the Git CVE-2021-21300 family).
//!
//! Both `.gitignore` and `.kitignore` are read from the repository root;
//! `.gitignore` patterns are applied first and `.kitignore` last, so a
//! repo's own `.kitignore` takes precedence under last-match-wins.
//!
//! **Deferred (documented non-goals for this pass):** nested per-directory
//! ignore files (only the root is read), global excludes
//! (`core.excludesFile`), and escaped trailing spaces.

use std::fs;
use std::io::{self, Read as _};
use std::path::Path;

/// Hard cap on a single ignore file (1 MiB).
pub const MAX_IGNORE_FILE_BYTES: u64 = 1024 * 1024;

/// Hard cap on the patterns one ignore file may hold. Every path check
/// walks the list, so the count bounds the work per file visited. Real
/// ignore files hold a few hundred lines.
pub const MAX_IGNORE_PATTERNS: usize = 10_000;

/// Hard cap on the length of one pattern line, in bytes. It matches the
/// longest path name most filesystems accept, so a longer pattern cannot
/// match a real path.
pub const MAX_IGNORE_PATTERN_BYTES: usize = 4096;

/// Errors returned by [`load`].
#[derive(Debug, thiserror::Error)]
pub enum IgnoreError {
    /// An ignore file exceeded [`MAX_IGNORE_FILE_BYTES`].
    #[error("ignore file too large (>{MAX_IGNORE_FILE_BYTES} bytes)")]
    FileTooLarge,
    /// The ignore files hold more than [`MAX_IGNORE_PATTERNS`] patterns.
    #[error("ignore file has more than {MAX_IGNORE_PATTERNS} patterns")]
    TooManyPatterns,
    /// A pattern line is longer than [`MAX_IGNORE_PATTERN_BYTES`].
    #[error("ignore pattern is longer than {MAX_IGNORE_PATTERN_BYTES} bytes")]
    PatternTooLong,
    /// Underlying I/O failure.
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// One path segment of a parsed pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Segment {
    /// A `**` segment — matches across `/` boundaries.
    DoubleStar,
    /// A single-level glob segment (`*`/`?`/`[...]`/literals, no `/`).
    Glob(String),
}

/// Fast-path classification for a non-anchored, single-glob-segment
/// pattern — the overwhelmingly common shape in real `.gitignore` files
/// (`*.log`, `node_modules`, `.DS_Store`, `build`, …). Precomputed once at
/// parse time (see `classify_basename_glob`) so [`Pattern::matches`] can
/// test the path's *basename* directly instead of going through
/// [`match_segments`]'s any-depth backtracking, which for this pattern
/// shape (`[DoubleStar, Glob(g)]`) always fails at every split point
/// except the last — a lone trailing `Glob` requires the remainder to be
/// empty. `Literal`/`Suffix`/`Prefix` additionally skip `segment_match`'s
/// own byte-by-byte backtracking in favor of a direct string op.
#[derive(Debug, Clone, PartialEq, Eq)]
enum BasenameKind {
    /// No metacharacters (`* ? [ \`): exact basename match.
    Literal(String),
    /// `*literal` (and no other metacharacters): `basename.ends_with`.
    Suffix(String),
    /// `literal*` (and no other metacharacters): `basename.starts_with`.
    Prefix(String),
    /// Any other non-anchored single-segment glob: run the general
    /// single-segment matcher against the basename only.
    Glob(String),
}

impl BasenameKind {
    fn matches(&self, base: &str) -> bool {
        match self {
            Self::Literal(s) => base == s,
            Self::Suffix(s) => base.ends_with(s.as_str()),
            Self::Prefix(s) => base.starts_with(s.as_str()),
            Self::Glob(g) => segment_match(g.as_bytes(), base.as_bytes()),
        }
    }
}

/// Classify a non-anchored single-segment glob body (`core`, already
/// known not to be `**`) for [`BasenameKind`]. Only ever falls back to
/// [`BasenameKind::Glob`] — never incorrect, just unclassified — so this
/// is always safe to extend with more cases later.
fn classify_basename_glob(g: &str) -> BasenameKind {
    fn has_special(s: &str) -> bool {
        s.bytes().any(|b| matches!(b, b'*' | b'?' | b'[' | b'\\'))
    }
    if !has_special(g) {
        return BasenameKind::Literal(g.to_string());
    }
    if let Some(rest) = g.strip_prefix('*')
        && !has_special(rest)
    {
        return BasenameKind::Suffix(rest.to_string());
    }
    if let Some(prefix) = g.strip_suffix('*')
        && !prefix.is_empty()
        && !has_special(prefix)
    {
        return BasenameKind::Prefix(prefix.to_string());
    }
    BasenameKind::Glob(g.to_string())
}

/// A single ignore pattern with its modifiers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pattern {
    /// Cleaned glob body, with `!`, the leading `/`, and the trailing `/`
    /// already stripped (e.g. `*.log`, `build`, `src/gen`).
    pub pattern: String,
    /// `true` if the pattern was prefixed with `!` (un-ignore).
    pub negated: bool,
    /// `true` if the pattern ended with `/` (directory-only).
    pub dir_only: bool,
    /// `true` if the pattern is anchored to the repo root (contained a
    /// non-trailing `/`); otherwise it matches at any depth.
    pub anchored: bool,
    /// Effective match segments. Non-anchored patterns carry a leading
    /// [`Segment::DoubleStar`] so they match at any depth.
    segments: Vec<Segment>,
    /// `Some` for the common non-anchored single-segment shape — see
    /// [`BasenameKind`]. `None` (anchored, or a pattern with an internal
    /// `/` or `**`) falls back to the general [`match_segments`] engine.
    ///
    /// Boxed so this field stays pointer-sized (niche-optimized, since
    /// `Box` is never null) regardless of `BasenameKind`'s payload —
    /// `IgnoreList::is_ignored` linearly scans `self.patterns`, so an
    /// inline `String`-bearing variant here would grow every `Pattern` by
    /// ~50%, hurting cache density for the (unaffected) general-engine
    /// scan even on repos with few or no basename-fast-path patterns.
    basename_kind: Option<Box<BasenameKind>>,
}

impl Pattern {
    /// Match this pattern against a slice of path segments.
    fn matches(&self, path: &[&str]) -> bool {
        if let Some(kind) = &self.basename_kind {
            return path.last().is_some_and(|base| kind.matches(base));
        }
        match_segments(&self.segments, path)
    }
}

/// Parsed ignore-list (the merged `.gitignore` + `.kitignore` patterns).
#[derive(Debug, Default, Clone)]
pub struct IgnoreList {
    patterns: Vec<Pattern>,
}

impl IgnoreList {
    /// Construct an empty list (matches nothing user-defined; the
    /// hard-coded `.kit` / `.git` ignores still apply).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            patterns: Vec::new(),
        }
    }

    /// Borrow the parsed patterns.
    #[must_use]
    pub fn patterns(&self) -> &[Pattern] {
        &self.patterns
    }

    /// Returns `true` if `rel_path` (relative to the repo root, `/`-separated)
    /// should be ignored. `is_dir` controls whether directory-only patterns
    /// apply.
    ///
    /// Callers walk top-down and skip ignored directories without descending,
    /// which is what gives directory-only patterns (`build/`) their
    /// "everything inside is ignored too" behavior — the contents are simply
    /// never visited.
    #[must_use]
    pub fn is_ignored(&self, rel_path: &str, is_dir: bool) -> bool {
        let trimmed = rel_path.trim_matches('/');
        // Hard-coded ignores key off the basename at any depth.
        let base = trimmed.rsplit('/').next().unwrap_or(trimmed);
        if base.eq_ignore_ascii_case(".kit") || base.eq_ignore_ascii_case(".git") {
            return true;
        }
        with_segments(trimmed, |path| {
            if path.is_empty() {
                return false;
            }
            // Last match wins, so walk in reverse and return the first
            // (highest-index) match — equivalent to scanning forward and
            // keeping the last, but skips every earlier pattern once a
            // deciding match is found instead of always paying for the full
            // list.
            for p in self.patterns.iter().rev() {
                if p.dir_only && !is_dir {
                    continue;
                }
                if p.matches(path) {
                    return !p.negated;
                }
            }
            false
        })
    }

    /// Like [`is_ignored`](Self::is_ignored), but also returns `true` when any
    /// **ancestor directory** of `rel_path` is ignored — git treats
    /// everything under an excluded directory as excluded.
    ///
    /// Use this for one-shot path tests (an explicit `add <path>`, the restore
    /// safety gate) where there is no top-down walk to carry the
    /// ancestor-ignored bit. Walkers that descend top-down should instead
    /// thread their own ancestor flag (cheaper) and skip ignored directories.
    #[must_use]
    pub fn is_ignored_with_ancestors(&self, rel_path: &str, is_dir: bool) -> bool {
        let trimmed = rel_path.trim_matches('/');
        if trimmed.is_empty() {
            return false;
        }
        // Each strict ancestor is a directory; if one is ignored, so is this.
        // An ancestor is the prefix before a `/`. Empty segments vanish in
        // `is_ignored`, so a prefix that ends in `/` tests the same ancestor.
        for (i, _) in trimmed.match_indices('/') {
            if self.is_ignored(&trimmed[..i], true) {
                return true;
            }
        }
        self.is_ignored(trimmed, is_dir)
    }
}

/// Path depth that [`with_segments`] keeps on the stack.
const STACK_SEGMENTS: usize = 16;

/// Split `trimmed` on `/`, drop empty segments, and pass them to `f`.
/// Paths up to [`STACK_SEGMENTS`] deep use a stack buffer. Deeper paths
/// spill to a `Vec`.
fn with_segments<R>(trimmed: &str, f: impl FnOnce(&[&str]) -> R) -> R {
    let mut buf = [""; STACK_SEGMENTS];
    let mut len = 0;
    for seg in trimmed.split('/').filter(|s| !s.is_empty()) {
        if len == STACK_SEGMENTS {
            let all: Vec<&str> = trimmed.split('/').filter(|s| !s.is_empty()).collect();
            return f(&all);
        }
        buf[len] = seg;
        len += 1;
    }
    f(&buf[..len])
}

/// Load and merge `.gitignore` then `.kitignore` from `dir`. Returns an
/// empty list if neither file is present.
///
/// `.gitignore` patterns come first so a repo's own `.kitignore` wins under
/// last-match-wins.
///
/// # Errors
/// - [`IgnoreError::FileTooLarge`] if either file exceeds 1 MiB.
/// - [`IgnoreError::TooManyPatterns`] or [`IgnoreError::PatternTooLong`] if
///   the files break the pattern limits. A skipped pattern would leave a
///   file unignored, so the load fails instead.
/// - [`IgnoreError::Io`] for other filesystem failures.
pub fn load(dir: &Path) -> Result<IgnoreList, IgnoreError> {
    let mut patterns = Vec::new();
    for name in [".gitignore", ".kitignore"] {
        if let Some(list) = load_one(&dir.join(name))? {
            patterns.extend(list.patterns);
        }
        if patterns.len() > MAX_IGNORE_PATTERNS {
            return Err(IgnoreError::TooManyPatterns);
        }
    }
    Ok(IgnoreList { patterns })
}

/// Read and parse a single ignore file, or `None` if it is absent.
///
/// The file must be a regular file. A symlink, device or FIFO is an
/// error: `/dev/zero` reports length 0 and would never end. The read
/// itself is capped, so a file that grows after the check stays bounded.
fn load_one(path: &Path) -> Result<Option<IgnoreList>, IgnoreError> {
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(IgnoreError::Io(e)),
    };
    if !meta.file_type().is_file() {
        return Err(IgnoreError::Io(io::Error::other(
            "ignore file is not a regular file",
        )));
    }
    if meta.len() > MAX_IGNORE_FILE_BYTES {
        return Err(IgnoreError::FileTooLarge);
    }
    let mut text = String::new();
    fs::File::open(path)?
        .take(MAX_IGNORE_FILE_BYTES + 1)
        .read_to_string(&mut text)?;
    if text.len() as u64 > MAX_IGNORE_FILE_BYTES {
        return Err(IgnoreError::FileTooLarge);
    }
    parse_checked(&text).map(Some)
}

/// Parse ignore-file content into a list of patterns. Never fails:
/// malformed-looking lines are silently skipped. It sets no limits, so
/// use [`parse_checked`] for content from a repository.
#[must_use]
pub fn parse(content: &str) -> IgnoreList {
    let mut patterns = Vec::new();
    for raw in content.split('\n') {
        // Strip a single trailing `\r` for Windows-style line endings.
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        if let Some(p) = parse_line(line) {
            patterns.push(p);
        }
    }
    IgnoreList { patterns }
}

/// Parse untrusted ignore-file content, refusing what [`parse`] would accept
/// without limit.
///
/// # Errors
/// - [`IgnoreError::PatternTooLong`] if a non-comment line is longer than
///   [`MAX_IGNORE_PATTERN_BYTES`].
/// - [`IgnoreError::TooManyPatterns`] if the content holds more than
///   [`MAX_IGNORE_PATTERNS`] patterns.
pub fn parse_checked(content: &str) -> Result<IgnoreList, IgnoreError> {
    let mut patterns = Vec::new();
    for raw in content.split('\n') {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        if line.len() > MAX_IGNORE_PATTERN_BYTES && !line.starts_with('#') {
            return Err(IgnoreError::PatternTooLong);
        }
        if let Some(p) = parse_line(line) {
            if patterns.len() == MAX_IGNORE_PATTERNS {
                return Err(IgnoreError::TooManyPatterns);
            }
            patterns.push(p);
        }
    }
    Ok(IgnoreList { patterns })
}

/// Parse one cleaned line into a [`Pattern`], or `None` for blanks/comments.
fn parse_line(line: &str) -> Option<Pattern> {
    if line.is_empty() || line.starts_with('#') {
        // Blank, or a leading unescaped `#` comment.
        return None;
    }
    // Trim trailing unescaped spaces (escaped trailing spaces are deferred).
    let line = line.trim_end_matches(' ');
    if line.is_empty() {
        return None;
    }
    // Negation (`!`) and leading-escape (`\!`, `\#`) handling.
    let (negated, body) = if let Some(rest) = line.strip_prefix('!') {
        (true, rest.to_string())
    } else if let Some(rest) = line.strip_prefix("\\!") {
        (false, format!("!{rest}"))
    } else if let Some(rest) = line.strip_prefix("\\#") {
        (false, format!("#{rest}"))
    } else {
        (false, line.to_string())
    };
    finish_pattern(&body, negated)
}

/// Build a [`Pattern`] from a (possibly negated) body after `#`/`!` handling.
fn finish_pattern(body: &str, negated: bool) -> Option<Pattern> {
    // Trailing `/` ⇒ directory-only.
    let (dir_only, body) = match body.strip_suffix('/') {
        Some(rest) => (true, rest),
        None => (false, body),
    };
    if body.is_empty() {
        return None;
    }

    // Anchored if there is a `/` anywhere (after the trailing one was
    // stripped). A leading `/` is stripped; it only signals anchoring.
    let anchored = body.contains('/');
    let core = body.strip_prefix('/').unwrap_or(body);
    if core.is_empty() {
        return None;
    }

    // `!anchored` means `core` has no `/` at all, i.e. it is already a
    // single segment — the shape `BasenameKind` fast-paths. `"**"` is
    // excluded: it becomes two `DoubleStar` segments (matches one-or-more
    // of *any* remaining segments), not a basename-only glob.
    let basename_kind = (!anchored && core != "**").then(|| Box::new(classify_basename_glob(core)));

    let mut segments: Vec<Segment> = core
        .split('/')
        .filter(|s| !s.is_empty())
        .map(|s| {
            if s == "**" {
                Segment::DoubleStar
            } else {
                Segment::Glob(s.to_string())
            }
        })
        .collect();
    if segments.is_empty() {
        return None;
    }
    // A non-anchored pattern matches at any depth (as if prefixed `**/`).
    if !anchored {
        segments.insert(0, Segment::DoubleStar);
    }

    Some(Pattern {
        pattern: core.to_string(),
        negated,
        dir_only,
        anchored,
        segments,
        basename_kind,
    })
}

/// Match a segment list against a path-segment slice (entire-path match).
///
/// Runs in `O(pattern segments * path segments)` glob calls. It tracks the
/// set of path positions reachable after each pattern segment, so nested
/// `**` segments cannot cause exponential backtracking.
fn match_segments(pat: &[Segment], path: &[&str]) -> bool {
    let n = path.len();
    let mut cur = vec![false; n + 1];
    cur[0] = true;
    for (i, seg) in pat.iter().enumerate() {
        let Some(first) = cur.iter().position(|&r| r) else {
            return false;
        };
        match seg {
            Segment::DoubleStar if i + 1 == pat.len() => {
                // A trailing `**` matches one or more remaining segments
                // (git's "everything inside" — not the directory itself).
                return first < n;
            }
            Segment::DoubleStar => {
                // Zero or more segments: every position from `first` on.
                for (j, r) in cur.iter_mut().enumerate() {
                    *r = j >= first;
                }
            }
            Segment::Glob(g) => {
                let mut next = vec![false; n + 1];
                for j in first..n {
                    if cur[j] && segment_match(g.as_bytes(), path[j].as_bytes()) {
                        next[j + 1] = true;
                    }
                }
                cur = next;
            }
        }
    }
    cur[n]
}

/// Match a single path segment against a single-level glob (`*`/`?`/`[...]`,
/// `\` escapes, literals). Never crosses `/` (segments contain none).
///
/// Every token except `*` consumes exactly one byte, so one backtrack point
/// (the latest `*`) is enough. The cost is `O(pattern * segment)`.
fn segment_match(p: &[u8], s: &[u8]) -> bool {
    let (mut pi, mut si) = (0, 0);
    // Pattern index after the latest `*`, and the segment index it resumes at.
    let mut star: Option<(usize, usize)> = None;
    loop {
        if pi == p.len() {
            if si == s.len() {
                return true;
            }
        } else if p[pi] == b'*' {
            while p.get(pi) == Some(&b'*') {
                pi += 1;
            }
            star = Some((pi, si));
            continue;
        } else if let Some(used) = match_one(&p[pi..], s.get(si).copied()) {
            pi += used;
            si += 1;
            continue;
        }
        // Mismatch: let the latest `*` absorb one more byte.
        match star {
            Some((spi, ssi)) if ssi < s.len() => {
                star = Some((spi, ssi + 1));
                pi = spi;
                si = ssi + 1;
            }
            _ => return false,
        }
    }
}

/// Match one non-`*` pattern token at the front of `p` against `ch`.
/// Returns the pattern bytes consumed when it matches one byte, else `None`.
fn match_one(p: &[u8], ch: Option<u8>) -> Option<usize> {
    let c = ch?;
    match p[0] {
        b'?' => Some(1),
        b'[' => match match_class(p, ch) {
            Some((matched, plen)) => matched.then_some(plen),
            // Malformed class (no closing `]`) is a literal `[`.
            None => (c == b'[').then_some(1),
        },
        b'\\' => match p.get(1) {
            Some(&e) => (c == e).then_some(2),
            None => (c == b'\\').then_some(1),
        },
        lit => (c == lit).then_some(1),
    }
}

/// Evaluate a `[...]` character class at the front of `p` against `ch`.
/// Returns `(matched, bytes_consumed_including_brackets)`, or `None` if the
/// class has no closing `]`.
fn match_class(p: &[u8], ch: Option<u8>) -> Option<(bool, usize)> {
    debug_assert_eq!(p.first(), Some(&b'['));
    let mut i = 1;
    let negate = matches!(p.get(i), Some(&b'!' | &b'^'));
    if negate {
        i += 1;
    }
    let start = i;
    let mut matched = false;
    while i < p.len() {
        // A `]` after the first class char closes it; as the first char it is
        // a literal member.
        if p[i] == b']' && i > start {
            // Negation inverts only on a real character (an empty `ch`, i.e.
            // end-of-segment, never matches).
            let result = ch.is_some() && (matched ^ negate);
            return Some((result, i + 1));
        }
        // Range `a-z` (but `-` as the last char before `]` is literal).
        if i + 2 < p.len() && p[i + 1] == b'-' && p[i + 2] != b']' {
            if let Some(c) = ch
                && p[i] <= c
                && c <= p[i + 2]
            {
                matched = true;
            }
            i += 3;
        } else {
            if ch == Some(p[i]) {
                matched = true;
            }
            i += 1;
        }
    }
    None
}

/// Match a basename `name` against a single-level glob `pattern`. Supports
/// `*` (any run of non-`/`), `?` (one non-`/`), `[...]` classes, and `\`
/// escapes. Retained as a small public helper; the [`IgnoreList`] matcher
/// uses the richer path-aware engine above.
#[must_use]
pub fn glob_match(pattern: &str, name: &str) -> bool {
    // Reject any name containing `/`, mirroring the single-level contract.
    if name.contains('/') {
        return false;
    }
    segment_match(pattern.as_bytes(), name.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deep_paths_match_at_and_beyond_the_stack_buffer() {
        let list = parse("*.log\nbuild/\n/top\n");
        for depth in [
            1,
            STACK_SEGMENTS - 1,
            STACK_SEGMENTS,
            STACK_SEGMENTS + 1,
            40,
        ] {
            let dirs = vec!["d"; depth].join("/");
            assert!(
                list.is_ignored(&format!("{dirs}/x.log"), false),
                "depth {depth}"
            );
            assert!(
                !list.is_ignored(&format!("{dirs}/x.rs"), false),
                "depth {depth}"
            );
            assert!(
                list.is_ignored(&format!("{dirs}/build"), true),
                "depth {depth}"
            );
            assert!(
                !list.is_ignored(&format!("{dirs}/top"), false),
                "depth {depth}"
            );
        }
        assert!(list.is_ignored("//d///x.log//", false));
    }
    use tempfile::TempDir;

    #[test]
    fn empty_patterns_match_nothing_user_defined() {
        let il = parse("");
        assert!(!il.is_ignored("anything.txt", false));
        assert!(!il.is_ignored("somedir", true));
    }

    #[test]
    fn exact_filename_match() {
        let il = parse("secret.key");
        assert!(il.is_ignored("secret.key", false));
        assert!(!il.is_ignored("other.key", false));
    }

    #[test]
    fn glob_star_pattern() {
        let il = parse("*.log");
        assert!(il.is_ignored("debug.log", false));
        assert!(!il.is_ignored("debug.txt", false));
    }

    #[test]
    fn directory_pattern_trailing_slash() {
        let il = parse("build/");
        assert!(il.is_ignored("build", true));
        assert!(!il.is_ignored("build", false));
    }

    #[test]
    fn negation_pattern() {
        let il = parse("*.log\n!important.log");
        assert!(il.is_ignored("debug.log", false));
        assert!(!il.is_ignored("important.log", false));
    }

    #[test]
    fn comment_lines_ignored() {
        let il = parse("# this is a comment\n*.tmp");
        assert_eq!(il.patterns().len(), 1);
    }

    #[test]
    fn blank_lines_ignored() {
        let il = parse("\n\n*.tmp\n\n");
        assert_eq!(il.patterns().len(), 1);
    }

    #[test]
    fn glob_question_mark() {
        let il = parse("file?.txt");
        assert!(il.is_ignored("file1.txt", false));
        assert!(!il.is_ignored("file12.txt", false));
    }

    #[test]
    fn default_ignores() {
        let il = parse("");
        assert!(il.is_ignored(".kit", true));
        assert!(il.is_ignored(".git", true));
        assert!(il.is_ignored(".kit", false));
        assert!(il.is_ignored(".git", false));
        // ...at any depth.
        assert!(il.is_ignored("sub/.git", true));
    }

    // --- path-relative / anchoring -------------------------------------

    #[test]
    fn non_anchored_matches_at_any_depth() {
        let il = parse("*.log");
        assert!(il.is_ignored("a/b/c.log", false));
        assert!(il.is_ignored("c.log", false));
    }

    #[test]
    fn anchored_leading_slash_matches_root_only() {
        let il = parse("/foo.txt");
        assert!(il.is_ignored("foo.txt", false));
        assert!(!il.is_ignored("sub/foo.txt", false));
    }

    #[test]
    fn anchored_multi_segment() {
        let il = parse("src/gen");
        assert!(il.is_ignored("src/gen", true));
        assert!(!il.is_ignored("other/src/gen", true));
        assert!(!il.is_ignored("gen", true));
    }

    #[test]
    fn dir_only_matches_dir_at_any_depth() {
        let il = parse("build/");
        assert!(il.is_ignored("a/b/build", true));
        assert!(!il.is_ignored("a/b/build", false));
    }

    // --- `**` ----------------------------------------------------------

    #[test]
    fn leading_double_star() {
        let il = parse("**/foo");
        assert!(il.is_ignored("foo", false));
        assert!(il.is_ignored("a/foo", false));
        assert!(il.is_ignored("a/b/foo", false));
        assert!(!il.is_ignored("a/foobar", false));
    }

    #[test]
    fn middle_double_star() {
        let il = parse("a/**/b");
        assert!(il.is_ignored("a/b", false));
        assert!(il.is_ignored("a/x/b", false));
        assert!(il.is_ignored("a/x/y/b", false));
        assert!(!il.is_ignored("a/b/c", false));
    }

    #[test]
    fn trailing_double_star_matches_inside_not_self() {
        let il = parse("abc/**");
        assert!(il.is_ignored("abc/x", false));
        assert!(il.is_ignored("abc/x/y", false));
        // `abc` itself is not matched by a trailing `/**`.
        assert!(!il.is_ignored("abc", true));
    }

    // --- char classes / escapes ----------------------------------------

    #[test]
    fn char_class_range_and_negation() {
        let il = parse("file[0-9].txt");
        assert!(il.is_ignored("file3.txt", false));
        assert!(!il.is_ignored("filex.txt", false));
        let neg = parse("file[!0-9].txt");
        assert!(neg.is_ignored("filex.txt", false));
        assert!(!neg.is_ignored("file3.txt", false));
    }

    #[test]
    fn escaped_hash_and_bang_are_literal() {
        let il = parse("\\#notacomment\n\\!notnegated");
        assert_eq!(il.patterns().len(), 2);
        assert!(il.is_ignored("#notacomment", false));
        assert!(il.is_ignored("!notnegated", false));
    }

    #[test]
    fn trailing_spaces_trimmed() {
        let il = parse("foo.txt   ");
        assert!(il.is_ignored("foo.txt", false));
    }

    // --- negation across anchored / nested -----------------------------

    #[test]
    fn negation_reincludes_specific_file() {
        let il = parse("*.log\n!keep/important.log");
        assert!(il.is_ignored("a/debug.log", false));
        assert!(!il.is_ignored("keep/important.log", false));
    }

    // --- dual-file load / precedence -----------------------------------

    #[test]
    fn comment_lines_count() {
        let il = parse("# this is a comment\n*.tmp");
        assert_eq!(il.patterns().len(), 1);
        assert_eq!(il.patterns()[0].pattern, "*.tmp");
    }

    #[test]
    fn windows_line_endings_stripped() {
        let il = parse("*.log\r\n*.tmp\r\n");
        assert_eq!(il.patterns().len(), 2);
        assert_eq!(il.patterns()[0].pattern, "*.log");
        assert_eq!(il.patterns()[1].pattern, "*.tmp");
    }

    #[test]
    fn load_missing_file_returns_empty() {
        let dir = TempDir::new().unwrap();
        let il = load(dir.path()).unwrap();
        assert!(il.patterns().is_empty());
    }

    #[test]
    fn load_with_kitignore() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join(".kitignore"), "*.log\nbuild/\n").unwrap();
        let il = load(dir.path()).unwrap();
        assert_eq!(il.patterns().len(), 2);
        assert!(il.is_ignored("test.log", false));
        assert!(il.is_ignored("build", true));
    }

    #[test]
    fn load_reads_gitignore_too() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join(".gitignore"), "*.log\n").unwrap();
        let il = load(dir.path()).unwrap();
        assert!(il.is_ignored("debug.log", false));
    }

    #[test]
    fn kitignore_overrides_gitignore_last_match_wins() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join(".gitignore"), "*.log\n").unwrap();
        // .kitignore is applied last, so its re-include wins.
        std::fs::write(dir.path().join(".kitignore"), "!keep.log\n").unwrap();
        let il = load(dir.path()).unwrap();
        assert!(il.is_ignored("other.log", false));
        assert!(!il.is_ignored("keep.log", false));
    }

    #[test]
    fn load_rejects_oversize_file() {
        let dir = TempDir::new().unwrap();
        let oversized = vec![b'#'; usize::try_from(MAX_IGNORE_FILE_BYTES + 1).unwrap()];
        std::fs::write(dir.path().join(".kitignore"), oversized).unwrap();
        let err = load(dir.path()).unwrap_err();
        assert!(matches!(err, IgnoreError::FileTooLarge));
    }

    #[test]
    fn load_rejects_too_many_patterns() {
        let dir = TempDir::new().unwrap();
        let text = "a\n".repeat(MAX_IGNORE_PATTERNS + 1);
        std::fs::write(dir.path().join(".kitignore"), text).unwrap();
        let err = load(dir.path()).unwrap_err();
        assert!(matches!(err, IgnoreError::TooManyPatterns), "got {err:?}");
    }

    #[test]
    fn load_counts_patterns_across_both_files() {
        let dir = TempDir::new().unwrap();
        let half = "a\n".repeat(MAX_IGNORE_PATTERNS / 2 + 1);
        std::fs::write(dir.path().join(".gitignore"), &half).unwrap();
        std::fs::write(dir.path().join(".kitignore"), &half).unwrap();
        let err = load(dir.path()).unwrap_err();
        assert!(matches!(err, IgnoreError::TooManyPatterns), "got {err:?}");
    }

    #[test]
    fn load_accepts_the_pattern_count_limit() {
        let dir = TempDir::new().unwrap();
        let text = "a\n".repeat(MAX_IGNORE_PATTERNS);
        std::fs::write(dir.path().join(".kitignore"), text).unwrap();
        assert_eq!(
            load(dir.path()).unwrap().patterns().len(),
            MAX_IGNORE_PATTERNS
        );
    }

    #[test]
    fn load_rejects_a_long_pattern() {
        let dir = TempDir::new().unwrap();
        let text = format!("{}\n", "a".repeat(MAX_IGNORE_PATTERN_BYTES + 1));
        std::fs::write(dir.path().join(".kitignore"), text).unwrap();
        let err = load(dir.path()).unwrap_err();
        assert!(matches!(err, IgnoreError::PatternTooLong), "got {err:?}");
    }

    #[test]
    fn a_long_comment_is_not_a_pattern() {
        let text = format!("#{}\nkeep\n", "a".repeat(MAX_IGNORE_PATTERN_BYTES * 2));
        assert_eq!(parse_checked(&text).unwrap().patterns().len(), 1);
    }

    #[test]
    fn a_pattern_at_the_length_limit_is_accepted() {
        let text = "a".repeat(MAX_IGNORE_PATTERN_BYTES);
        assert_eq!(parse_checked(&text).unwrap().patterns().len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn load_rejects_symlinked_file() {
        let dir = TempDir::new().unwrap();
        std::os::unix::fs::symlink("/dev/zero", dir.path().join(".kitignore")).unwrap();
        let err = load(dir.path()).unwrap_err();
        assert!(matches!(err, IgnoreError::Io(_)));
    }

    // --- glob_match public helper --------------------------------------

    #[test]
    fn is_ignored_with_ancestors_skips_empty_segments() {
        let il = parse("build/\n");
        assert!(il.is_ignored_with_ancestors("build//out/x.o", false));
        assert!(il.is_ignored_with_ancestors("/src//build/x.o", false));
        assert!(!il.is_ignored_with_ancestors("src//lib/x.o", false));
    }

    #[test]
    fn is_ignored_with_ancestors_catches_files_under_ignored_dir() {
        let il = parse("node_modules/\n");
        // The directory itself and any descendant (file or dir).
        assert!(il.is_ignored_with_ancestors("node_modules", true));
        assert!(il.is_ignored_with_ancestors("node_modules/pkg/index.js", false));
        // Unrelated paths are unaffected.
        assert!(!il.is_ignored_with_ancestors("src/main.rs", false));
        // The plain matcher does NOT catch the descendant (no walk context).
        assert!(!il.is_ignored("node_modules/pkg/index.js", false));
    }

    #[test]
    fn glob_match_exact() {
        assert!(glob_match("hello", "hello"));
        assert!(!glob_match("hello", "world"));
    }

    #[test]
    fn glob_match_star() {
        assert!(glob_match("*.rs", "main.rs"));
        assert!(!glob_match("*.rs", "main.txt"));
        assert!(glob_match("test*", "testing"));
        assert!(glob_match("*", "anything"));
        // Single-level: `*` never crosses `/`.
        assert!(!glob_match("*", "a/b"));
    }

    // --- BasenameKind fast path ----------------------------------------

    #[test]
    fn basename_kind_classifies_common_shapes() {
        assert_eq!(
            classify_basename_glob("node_modules"),
            BasenameKind::Literal("node_modules".to_string())
        );
        assert_eq!(
            classify_basename_glob("*.log"),
            BasenameKind::Suffix(".log".to_string())
        );
        assert_eq!(
            classify_basename_glob("build*"),
            BasenameKind::Prefix("build".to_string())
        );
        // Bare `*` is a degenerate suffix: matches every basename.
        assert_eq!(
            classify_basename_glob("*"),
            BasenameKind::Suffix(String::new())
        );
        // Multiple/mixed metacharacters fall back to the general glob.
        assert_eq!(
            classify_basename_glob("*foo*"),
            BasenameKind::Glob("*foo*".to_string())
        );
        assert_eq!(
            classify_basename_glob("file?.txt"),
            BasenameKind::Glob("file?.txt".to_string())
        );
        assert_eq!(
            classify_basename_glob("file[0-9].txt"),
            BasenameKind::Glob("file[0-9].txt".to_string())
        );
    }

    #[test]
    fn basename_kind_fast_path_is_used_for_non_anchored_single_segment() {
        let il = parse("node_modules\n*.log\nbuild*\nsrc/gen\n");
        assert!(il.patterns()[0].basename_kind.is_some());
        assert!(il.patterns()[1].basename_kind.is_some());
        assert!(il.patterns()[2].basename_kind.is_some());
        // Anchored (contains `/`) — must fall back to the general engine.
        assert!(il.patterns()[3].basename_kind.is_none());
    }

    proptest::proptest! {
        /// `Pattern::matches`' `BasenameKind` fast path must always agree
        /// with the general `match_segments` engine it is short-circuiting
        /// — for arbitrary non-anchored single-segment glob bodies against
        /// arbitrary multi-segment paths. Guards the classification in
        /// `classify_basename_glob` (and the algebraic fact it relies on:
        /// `[DoubleStar, Glob(g)]` can only ever match a path's last
        /// segment) against a future edge case being misclassified.
        #[test]
        fn proptest_basename_fast_path_matches_general_engine(
            glob in "[a-zA-Z0-9_.*?-]{0,8}",
            path_segs in proptest::collection::vec("[a-zA-Z0-9_.-]{0,6}", 1..4),
        ) {
            proptest::prop_assume!(!glob.is_empty() && glob != "**");
            if let Some(pat) = finish_pattern(&glob, false) {
                let path: Vec<&str> = path_segs.iter().map(String::as_str).collect();
                let fast = pat.matches(&path);
                let general = match_segments(&pat.segments, &path);
                proptest::prop_assert_eq!(fast, general, "glob={:?} path={:?}", glob, path);
            }
        }
    }

    #[test]
    fn pathological_globs_finish_fast() {
        let name = "a".repeat(200);
        let il = parse("*a*a*a*a*a*a*a*a*a*a*b");
        assert!(!il.is_ignored(&name, false));
        let il = parse("a/**/a/**/a/**/a/**/a/**/b");
        let path = vec!["a"; 200].join("/");
        assert!(!il.is_ignored(&path, false));
        assert!(glob_match("*a*a*b", "xaxab"));
        assert!(!glob_match("*a*a*b", "xaxac"));
    }
}
