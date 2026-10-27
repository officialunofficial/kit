//! Line attribution.
//!
//! [`blame`] finds the commit that last changed each line of one file. A
//! [`Request`] holds the file, the revision, and the switches of `kit blame`.
//! The result is a [`BlameResult`] with one entry per line.
//!
//! Two walks exist:
//!
//! - The default walk starts at one revision, or at `HEAD`, and goes back
//!   through the history. A line gets the commit that wrote it.
//! - The `reverse` walk starts at the first revision of a `<start>..<end>`
//!   range and goes forward. A line gets the last commit of the range in
//!   which it still existed. An empty `<end>` means `HEAD`.
//!
//! The `reverse` walk does not detect moves or copies, and it does not skip
//! commits. The request is an error if it asks for both.
//!
//! The `lines` field of the request keeps a part of the result. The syntax is
//! in [`line_range`]. A kept line keeps its own line number in the file.

use std::collections::HashSet;
use std::io::Read;
use std::sync::Arc;

use kit_core::hash::{self, Hash};
use kit_core::ops::blame::{BlameError, BlameOptions, blame_file_reverse, blame_file_with};
use kit_core::refs::{self, RefError};

use crate::{Repo, revspec};

pub use kit_core::ops::blame::{BlameLine, BlameResult, CopyDetection, MoveDetection};

pub mod line_range;

/// The most bytes that the library reads from one file of commit names.
/// A larger file is an error. The limit holds about 250 000 names.
const MAX_IGNORE_REVS_FILE_LEN: u64 = 16 * 1024 * 1024;

/// Errors from blaming a file.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// `reverse` is set, and the request also asks to detect moves or copies,
    /// or to skip commits.
    #[error("--reverse cannot be combined with -M/-C or --ignore-rev/--ignore-revs-file")]
    ReverseWithDetection,
    /// `ignore_rev_precise` is set, and the request names no commit to skip.
    #[error("--ignore-rev-precise requires --ignore-rev or --ignore-revs-file")]
    PreciseWithoutIgnore,
    /// A commit to skip does not resolve.
    #[error("cannot find revision {0} to ignore")]
    IgnoreRevNotFound(String),
    /// A file of commit names cannot be read as text.
    #[error("could not open object name list: {0}")]
    IgnoreFileUnreadable(String),
    /// A file of commit names is longer than the limit.
    #[error("object name list {path} is longer than {max} bytes")]
    IgnoreFileTooLong {
        /// The path that the caller gave.
        path: String,
        /// The limit.
        max: u64,
    },
    /// A line of a file of commit names is not a full hex object name.
    #[error("invalid object name: {0}")]
    InvalidObjectName(String),
    /// `reverse` is set, the revision is missing, and the file looks like the
    /// range.
    #[error("--reverse: missing <file> (got only '{0}', which looks like the range)")]
    ReverseMissingFile(String),
    /// `reverse` is set and the request has no revision.
    #[error("--reverse requires a <start>..<end> revision range")]
    ReverseNeedsRange,
    /// `reverse` is set and the revision has no `..`.
    #[error("--reverse requires a <start>..<end> range, got '{0}'")]
    ReverseNotARange(String),
    /// `reverse` is set and the revision has more than one `..`, or a `...`.
    #[error("--reverse requires a single <start>..<end> range, got '{0}'")]
    ReverseNotASingleRange(String),
    /// `reverse` is set and the range has no `<start>`.
    #[error("--reverse requires an explicit <start> revision")]
    ReverseNeedsStart,
    /// `reverse` is set and the two ends of the range are the same commit.
    #[error("--reverse: empty revision range '{0}'")]
    ReverseEmptyRange(String),
    /// A revision does not resolve.
    #[error(transparent)]
    Revision(revspec::Error),
    /// `HEAD` has no commit.
    #[error("no commits yet")]
    HeadWithoutCommit,
    /// `HEAD` could not be read.
    #[error("resolve HEAD: {0}")]
    ResolveHead(RefError),
    /// The attribution failed.
    #[error("blame: {0}")]
    Blame(BlameError),
    /// The range of lines is not valid for the file.
    #[error(transparent)]
    Lines(#[from] line_range::Error),
}

/// What to blame. See the module documentation for the walks.
#[derive(Debug, Clone, Copy)]
// Each bool is an independent switch of `kit blame`.
#[allow(clippy::struct_excessive_bools)]
pub struct Request<'a> {
    /// The path of the file in the tree.
    pub file: &'a str,
    /// The revision to blame at. With `reverse`, the `<start>..<end>` range.
    /// `None` means `HEAD`.
    pub revision: Option<&'a str>,
    /// Walk forward over a range.
    pub reverse: bool,
    /// Ignore white space when a line is matched with an older version.
    pub ignore_whitespace: bool,
    /// Credit lines that moved inside the file to the commit that wrote them.
    pub moves: MoveDetection,
    /// Credit lines that were copied from other files to the commit that
    /// wrote them.
    pub copies: CopyDetection,
    /// Revisions of commits to skip.
    pub ignore_revs: &'a [String],
    /// Paths of files that list commits to skip. A file holds one full hex
    /// object name on each line. A `#` starts a comment.
    pub ignore_revs_files: &'a [String],
    /// Match the lines of a skipped commit by content, not by position.
    pub ignore_rev_precise: bool,
    /// Follow only the first parent of each commit.
    pub first_parent: bool,
    /// The part of the result to keep, in the syntax of [`line_range`].
    pub lines: Option<&'a str>,
}

/// Blame the file that `request` names.
///
/// # Errors
/// [`Error`], with one variant per failed step. Arguments that contradict
/// each other fail before the library reads a revision.
pub fn blame(repo: &Repo, request: &Request<'_>) -> Result<BlameResult, Error> {
    check_switches(request)?;
    let options = BlameOptions {
        ignore_whitespace: request.ignore_whitespace,
        moves: request.moves,
        copies: request.copies,
        ignore_revs: Arc::new(collect_ignore_revs(repo, request)?),
        ignore_rev_precise: request.ignore_rev_precise,
        first_parent: request.first_parent,
    };

    let mut result = if request.reverse {
        let (start, end) = resolve_reverse_range(repo, request)?;
        blame_file_reverse(repo.store(), start, end, request.file, &options)
    } else {
        let head = match request.revision {
            Some(spec) => revspec::resolve_revision(repo.store(), repo.layout(), spec)
                .map_err(Error::Revision)?,
            None => resolve_head(repo)?,
        };
        blame_file_with(repo.store(), head, request.file, &options)
    }
    .map_err(Error::Blame)?;

    if let Some(spec) = request.lines {
        let (first, last) = line_range::parse(spec, result.lines.len(), request.file)?;
        result.lines.truncate(last);
        result.lines.drain(..first - 1);
    }
    Ok(result)
}

/// Reject switches that contradict each other.
fn check_switches(request: &Request<'_>) -> Result<(), Error> {
    let skips = !request.ignore_revs.is_empty() || !request.ignore_revs_files.is_empty();
    // The reverse walk matches lines only. It does not detect moves or copies,
    // and it does not skip commits. An error is better than a silent no-op.
    if request.reverse
        && (request.moves != MoveDetection::Off || request.copies != CopyDetection::Off || skips)
    {
        return Err(Error::ReverseWithDetection);
    }
    if request.ignore_rev_precise && !skips {
        return Err(Error::PreciseWithoutIgnore);
    }
    Ok(())
}

/// The commit of `HEAD`.
fn resolve_head(repo: &Repo) -> Result<Hash, Error> {
    match refs::resolve_head(repo.layout()) {
        Ok(Some(head)) => Ok(head),
        Ok(None) => Err(Error::HeadWithoutCommit),
        Err(e) => Err(Error::ResolveHead(e)),
    }
}

/// The set of commits to skip. A revision can be any form that
/// [`revspec::resolve_revision`] reads. A line of a file must be a full hex
/// object name, the same as in git. A line ends at its first `#`, and white
/// space around it does not count.
fn collect_ignore_revs(repo: &Repo, request: &Request<'_>) -> Result<HashSet<Hash>, Error> {
    let mut set = HashSet::new();
    for spec in request.ignore_revs {
        let commit = revspec::resolve_revision(repo.store(), repo.layout(), spec)
            .map_err(|_| Error::IgnoreRevNotFound(spec.clone()))?;
        set.insert(commit);
    }
    for path in request.ignore_revs_files {
        let contents = read_bounded_text(path)?;
        for raw in contents.lines() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let commit =
                hash::from_hex(line).map_err(|_| Error::InvalidObjectName(line.to_owned()))?;
            set.insert(commit);
        }
    }
    Ok(set)
}

/// Read a text file of at most [`MAX_IGNORE_REVS_FILE_LEN`] bytes. The check
/// of the length comes before the allocation of the text.
fn read_bounded_text(path: &str) -> Result<String, Error> {
    let unreadable = || Error::IgnoreFileUnreadable(path.to_owned());
    let file = std::fs::File::open(path).map_err(|_| unreadable())?;
    let mut bytes = Vec::new();
    file.take(MAX_IGNORE_REVS_FILE_LEN + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| unreadable())?;
    if bytes.len() as u64 > MAX_IGNORE_REVS_FILE_LEN {
        return Err(Error::IgnoreFileTooLong {
            path: path.to_owned(),
            max: MAX_IGNORE_REVS_FILE_LEN,
        });
    }
    String::from_utf8(bytes).map_err(|_| unreadable())
}

/// The two commits of the `<start>..<end>` range of a reverse walk. An empty
/// `<end>` is `HEAD`.
///
/// A request without a revision gets a sharper error when the file looks like
/// the range, because the caller probably left out the file.
fn resolve_reverse_range(repo: &Repo, request: &Request<'_>) -> Result<(Hash, Hash), Error> {
    let Some(spec) = request.revision else {
        if request.file.contains("..") {
            return Err(Error::ReverseMissingFile(request.file.to_owned()));
        }
        return Err(Error::ReverseNeedsRange);
    };
    let Some((start_text, end_text)) = spec.split_once("..") else {
        return Err(Error::ReverseNotARange(spec.to_owned()));
    };
    // A symmetric range `a...b` splits to the end `.b`. A range `a..b..c`
    // splits to the end `b..c`. Blame takes one two-dot range.
    if end_text.starts_with('.') || end_text.contains("..") {
        return Err(Error::ReverseNotASingleRange(spec.to_owned()));
    }
    if start_text.is_empty() {
        return Err(Error::ReverseNeedsStart);
    }
    let start = revspec::resolve_revision(repo.store(), repo.layout(), start_text)
        .map_err(Error::Revision)?;
    let end = if end_text.is_empty() {
        resolve_head(repo)?
    } else {
        revspec::resolve_revision(repo.store(), repo.layout(), end_text).map_err(Error::Revision)?
    };
    if start == end {
        return Err(Error::ReverseEmptyRange(spec.to_owned()));
    }
    Ok((start, end))
}
