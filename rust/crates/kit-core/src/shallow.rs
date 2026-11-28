//! The shallow boundary record and the rules a walk follows at it
//! (SPEC-SHALLOW §4 and §5).
//!
//! `.kit/shallow` lists the commits whose parents a shallow repository does
//! not hold. The file is canonical: sorted 64-character lowercase hex lines
//! with no duplicates, each ending in `\n`, at most 1 MiB, and never empty.
//! An empty boundary is the absence of the file. [`parse`] refuses any other
//! bytes, so two readers of one file always agree on the boundary.
//!
//! A writer holds [`SHALLOW_LOCK`] in the common directory and replaces the
//! file by an atomic rename ([`write_locked`]).
//!
//! [`Boundary::parents`] is the one rule every history walk applies: a commit
//! in the record has no parents. [`check`] tests the exactness rule SH2 over
//! a parents callback, and [`exact_record`] computes the record SH2 demands.

mod window;

pub use window::{
    MAX_DEPTH, MAX_WINDOW_COMMITS, MAX_WINDOW_TIPS, ReceivedError, Window, WindowError,
    check_received, window, window_in, window_objects, window_packs,
};

use std::collections::{BTreeSet, HashSet};
use std::fs;
use std::io;
use std::time::Duration;

use crate::bounded_read;
use crate::durable::Parents;
use crate::hash::{HEX_LEN, Hash, to_hex};
use crate::layout::RepoLayout;
use crate::refs::parse_lowercase_hash;
use crate::repo_lock::{self, LockError, RepoLock};

/// The lock a writer of the record holds, in the common directory.
pub const SHALLOW_LOCK: &str = "shallow.lock";

/// The largest record a reader accepts.
pub const MAX_RECORD_BYTES: u64 = 1024 * 1024;

/// How long a writer waits for [`SHALLOW_LOCK`].
const LOCK_TIMEOUT: Duration = Duration::from_secs(30);

/// The commits whose parents a repository does not hold. Empty for a full
/// repository.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Boundary(BTreeSet<Hash>);

impl Boundary {
    /// The record of a repository that is not shallow.
    pub const EMPTY: Self = Self(BTreeSet::new());

    /// The boundary of `commits`.
    #[must_use]
    pub fn new(commits: impl IntoIterator<Item = Hash>) -> Self {
        Self(commits.into_iter().collect())
    }

    /// Whether the repository is full.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The number of commits in the record.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether `commit` is in the record.
    #[must_use]
    pub fn contains(&self, commit: &Hash) -> bool {
        self.0.contains(commit)
    }

    /// The commits of the record, in byte order.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = &Hash> {
        self.0.iter()
    }

    /// The parents a walk follows from `commit`: none for a commit in the
    /// record, otherwise `parents`.
    #[must_use]
    pub fn parents<'a>(&self, commit: &Hash, parents: &'a [Hash]) -> &'a [Hash] {
        if self.contains(commit) { &[] } else { parents }
    }

    /// How a history walk follows the edges of object `id`: a commit in the
    /// record keeps its tree and drops its parents.
    #[must_use]
    pub fn mode(&self, id: &Hash) -> crate::ops::graph::ClosureMode {
        if self.contains(id) {
            crate::ops::graph::ClosureMode::Snapshot
        } else {
            crate::ops::graph::ClosureMode::History
        }
    }
}

/// Why the record cannot be read or written.
#[derive(Debug, thiserror::Error)]
pub enum ShallowError {
    /// The file is longer than [`MAX_RECORD_BYTES`].
    #[error("the shallow record .kit/shallow is larger than 1 MiB")]
    TooLarge,
    /// The file exists but is empty, which is not canonical.
    #[error("the shallow record .kit/shallow is empty")]
    Empty,
    /// Line `line` (from 1) is not 64 lowercase hex digits and a newline.
    #[error("line {line} of the shallow record .kit/shallow is not a commit id")]
    BadLine {
        /// The line, counted from 1.
        line: usize,
    },
    /// Line `line` does not sort after the line before it.
    #[error("line {line} of the shallow record .kit/shallow is out of order or repeated")]
    NotSorted {
        /// The line, counted from 1.
        line: usize,
    },
    /// The record lock could not be taken.
    #[error("cannot lock the shallow record: {0}")]
    Lock(#[from] LockError),
    /// The file cannot be read or written.
    #[error("cannot access the shallow record: {0}")]
    Io(#[from] io::Error),
}

/// The boundary that canonical record bytes name.
///
/// # Errors
/// [`ShallowError::TooLarge`], [`ShallowError::Empty`],
/// [`ShallowError::BadLine`] or [`ShallowError::NotSorted`] for bytes that
/// are not a canonical record.
pub fn parse(bytes: &[u8]) -> Result<Boundary, ShallowError> {
    if bytes.len() as u64 > MAX_RECORD_BYTES {
        return Err(ShallowError::TooLarge);
    }
    if bytes.is_empty() {
        return Err(ShallowError::Empty);
    }
    let mut out = BTreeSet::new();
    let mut last: Option<Hash> = None;
    for (n, line) in bytes.chunks(HEX_LEN + 1).enumerate() {
        let number = n + 1;
        let id = match line.split_last() {
            Some((b'\n', hex)) if hex.len() == HEX_LEN => parse_lowercase_hash(hex),
            _ => None,
        }
        .ok_or(ShallowError::BadLine { line: number })?;
        if last.is_some_and(|prev| prev >= id) {
            return Err(ShallowError::NotSorted { line: number });
        }
        last = Some(id);
        out.insert(id);
    }
    Ok(Boundary(out))
}

/// The canonical bytes of `boundary`: empty for an empty boundary, which a
/// writer stores as no file.
#[must_use]
pub fn encode(boundary: &Boundary) -> Vec<u8> {
    let mut out = Vec::with_capacity(boundary.len() * (HEX_LEN + 1));
    for id in boundary.iter() {
        out.extend_from_slice(to_hex(id).as_bytes());
        out.push(b'\n');
    }
    out
}

/// The boundary of the repository: empty when it has no record.
///
/// # Errors
/// The errors of [`parse`], or [`ShallowError::Io`] when the file exists but
/// cannot be read.
pub fn read(layout: &RepoLayout) -> Result<Boundary, ShallowError> {
    match bounded_read::read_capped(&layout.shallow_file(), MAX_RECORD_BYTES) {
        Ok(bytes) => parse(&bytes),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Boundary::default()),
        Err(e) if e.kind() == io::ErrorKind::InvalidData => Err(ShallowError::TooLarge),
        Err(e) => Err(ShallowError::Io(e)),
    }
}

/// Take [`SHALLOW_LOCK`], which a writer of the record holds.
///
/// # Errors
/// [`ShallowError::Lock`] when the lock is busy or cannot be made.
pub fn lock(layout: &RepoLayout) -> Result<RepoLock, ShallowError> {
    Ok(repo_lock::acquire(
        layout.common_dir(),
        SHALLOW_LOCK,
        LOCK_TIMEOUT,
    )?)
}

/// Replace the record with `boundary`: write a temporary file, sync it and
/// rename it over the record, or remove the record when `boundary` is
/// empty. The caller holds the guard [`lock`] returned.
///
/// # Errors
/// [`ShallowError::Io`] when the file cannot be written or removed.
pub fn write_locked(
    layout: &RepoLayout,
    _held: &RepoLock,
    boundary: &Boundary,
) -> Result<(), ShallowError> {
    let path = layout.shallow_file();
    if boundary.is_empty() {
        return match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        };
    }
    crate::durable::write_pointer(&path, &encode(boundary), Parents::Existing)?;
    Ok(())
}

/// A commit that breaks SH2, the rule that the record names exactly the
/// reachable commits with a missing parent.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Violation {
    /// A commit reachable inside the window is not in the store.
    #[error("commit {} is reachable but missing", to_hex(.0))]
    Missing(Hash),
    /// A commit in the record has every parent present.
    #[error("commit {} is in the shallow record but has all its parents", to_hex(.0))]
    Whole(Hash),
    /// A commit outside the record has a missing parent.
    #[error("commit {} is missing parent {}, and the shallow record does not name it", to_hex(.commit), to_hex(.parent))]
    Unrecorded {
        /// The commit.
        commit: Hash,
        /// Its missing parent.
        parent: Hash,
    },
}

/// Check SH2 for the history that `tips` reach: walking from each tip and
/// following no parent of a commit in `boundary`, every commit is present,
/// and a commit is in `boundary` exactly when one of its parents is absent.
/// `parents` returns the parents of a present commit and `None` for an
/// absent one. Entries of `boundary` that the walk never reaches are not
/// checked: a later `gc` may drop them.
///
/// # Errors
/// The first [`Violation`] the walk meets.
pub fn check(
    tips: &[Hash],
    boundary: &Boundary,
    mut parents: impl FnMut(&Hash) -> Option<Vec<Hash>>,
) -> Result<(), Violation> {
    let mut seen: HashSet<Hash> = HashSet::new();
    let mut stack: Vec<Hash> = tips.to_vec();
    while let Some(commit) = stack.pop() {
        if !seen.insert(commit) {
            continue;
        }
        let Some(ps) = parents(&commit) else {
            return Err(Violation::Missing(commit));
        };
        let absent = ps.iter().find(|p| parents(p).is_none()).copied();
        match (boundary.contains(&commit), absent) {
            (true, Some(_)) => {}
            (true, None) => return Err(Violation::Whole(commit)),
            (false, Some(parent)) => return Err(Violation::Unrecorded { commit, parent }),
            (false, None) => stack.extend(ps),
        }
    }
    Ok(())
}

/// The record SH2 demands for the present commits that `tips` reach: each
/// one with an absent parent, where the walk stops. `parents` is as for
/// [`check`]; an absent tip is left out.
#[must_use]
pub fn exact_record(
    tips: &[Hash],
    mut parents: impl FnMut(&Hash) -> Option<Vec<Hash>>,
) -> Boundary {
    let mut seen: HashSet<Hash> = HashSet::new();
    let mut stack: Vec<Hash> = tips.to_vec();
    let mut out = BTreeSet::new();
    while let Some(commit) = stack.pop() {
        if !seen.insert(commit) {
            continue;
        }
        let Some(ps) = parents(&commit) else {
            continue;
        };
        if ps.iter().any(|p| parents(p).is_none()) {
            out.insert(commit);
        } else {
            stack.extend(ps);
        }
    }
    Boundary(out)
}

/// [`parse`] for the fuzz target: the boundary, or `None` for bytes that are
/// not canonical.
#[cfg(feature = "fuzzing")]
#[must_use]
pub fn fuzz_parse(bytes: &[u8]) -> Option<Boundary> {
    parse(bytes).ok()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::collections::HashMap;

    fn id(n: u8) -> Hash {
        [n; 32]
    }

    #[test]
    fn a_record_round_trips_and_sorts() {
        let b = Boundary::new([id(3), id(1), id(2), id(1)]);
        let bytes = encode(&b);
        assert_eq!(bytes.len(), 3 * 65);
        assert_eq!(parse(&bytes).unwrap(), b);
        assert!(encode(&Boundary::default()).is_empty());
    }

    #[test]
    fn a_record_that_is_not_canonical_is_refused() {
        let line = |n: u8| format!("{}\n", to_hex(&id(n)));
        let cases: Vec<(Vec<u8>, &str)> = vec![
            (Vec::new(), "empty"),
            (format!("{}{}", line(2), line(1)).into_bytes(), "order"),
            (format!("{}{}", line(1), line(1)).into_bytes(), "repeat"),
            (line(0xab).to_uppercase().into_bytes(), "upper"),
            (line(1).trim_end().as_bytes().to_vec(), "no newline"),
            (format!("{}\r\n", to_hex(&id(1))).into_bytes(), "crlf"),
            (format!("{}x", line(1)).into_bytes(), "tail"),
        ];
        for (bytes, what) in cases {
            assert!(parse(&bytes).is_err(), "{what}");
        }
        let big = line(1).repeat(usize::try_from(MAX_RECORD_BYTES).unwrap() / 65 + 1);
        assert!(matches!(parse(big.as_bytes()), Err(ShallowError::TooLarge)));
    }

    #[test]
    fn a_walk_follows_no_parent_of_a_boundary_commit() {
        let b = Boundary::new([id(1)]);
        assert!(b.parents(&id(1), &[id(0)]).is_empty());
        assert_eq!(b.parents(&id(2), &[id(1)]), &[id(1)]);
    }

    /// A random DAG over commits 1..=n where each commit's parents are
    /// lower numbers, and a random set of present commits.
    fn graph() -> impl Strategy<Value = (HashMap<Hash, Vec<Hash>>, Vec<bool>)> {
        (2usize..24).prop_flat_map(|n| {
            (
                proptest::collection::vec(
                    proptest::collection::vec(any::<prop::sample::Index>(), 0..3),
                    n,
                ),
                proptest::collection::vec(any::<bool>(), n),
            )
                .prop_map(move |(edges, present)| {
                    let mut g = HashMap::new();
                    for (i, ps) in edges.iter().enumerate() {
                        let parents: Vec<Hash> = if i == 0 {
                            Vec::new()
                        } else {
                            let mut v: Vec<Hash> = ps
                                .iter()
                                .map(|ix| id(u8::try_from(ix.index(i)).unwrap()))
                                .collect();
                            v.dedup();
                            v
                        };
                        g.insert(id(u8::try_from(i).unwrap()), parents);
                    }
                    (g, present)
                })
        })
    }

    proptest! {
        /// SH2: the exact record passes the check, and adding or removing
        /// any reachable commit breaks it.
        #[test]
        fn the_exact_record_is_the_only_one_that_passes((g, present) in graph()) {
            let n = present.len();
            let tip = id(u8::try_from(n - 1).unwrap());
            let mut present = present;
            present[n - 1] = true;
            let parents = |c: &Hash| {
                let i = usize::from(c[0]);
                (i < n && present[i]).then(|| g[c].clone())
            };
            let record = exact_record(&[tip], parents);
            prop_assert!(check(&[tip], &record, parents).is_ok());
            // The commits the walk reaches.
            let mut reached = BTreeSet::new();
            let mut stack = vec![tip];
            while let Some(c) = stack.pop() {
                if reached.insert(c) && !record.contains(&c) {
                    stack.extend(parents(&c).unwrap());
                }
            }
            for c in &reached {
                let mut changed: BTreeSet<Hash> = record.iter().copied().collect();
                if !changed.insert(*c) {
                    changed.remove(c);
                }
                let changed = Boundary(changed);
                prop_assert!(check(&[tip], &changed, parents).is_err());
            }
            // A full history has an empty record (SH4).
            let full = |c: &Hash| g.get(c).cloned();
            prop_assert!(exact_record(&[tip], full).is_empty());
        }

        /// The parser accepts exactly what the encoder writes.
        #[test]
        fn the_parser_inverts_the_encoder(ids in proptest::collection::btree_set(any::<[u8; 32]>(), 1..8)) {
            let b = Boundary(ids);
            prop_assert_eq!(parse(&encode(&b)).unwrap(), b);
        }

        /// Any bytes the parser accepts are the encoding of what it returns.
        #[test]
        fn accepted_bytes_are_canonical(bytes in proptest::collection::vec(any::<u8>(), 0..200)) {
            if let Ok(b) = parse(&bytes) {
                prop_assert_eq!(encode(&b), bytes);
            }
        }
    }
}
