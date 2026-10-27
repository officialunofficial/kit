//! The state of the tree against `HEAD` and the index.
//!
//! [`compute`] lists the staged changes, the changes that are not staged and
//! the untracked paths. A move shows as one rename when both sides were staged
//! with the same content. [`records`] folds the list into one record for each
//! path, the way a porcelain listing needs it. [`Detail`] adds the modes and
//! object ids that the long porcelain listing shows.
//!
//! [`compute`] also writes the stat cache of the index back, as a courtesy to
//! the next call. It does that only for an index in the current format, and
//! only when no other writer holds the worktree lock.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use kit_core::hash::{Hash, ZERO};
use kit_core::index::{self, EntryStatus, Index, IndexError};
use kit_core::layout::RepoLayout;
use kit_core::observer::Observer;
use kit_core::ops::{
    DiffEntry, DiffError, DiffKind, StatusEntry, StatusStaging, detect_content_renames,
    status_diff_observed,
};
use kit_core::refs::{self, Head};
use kit_core::repo_lock;
use kit_core::store::{ObjectStore, StoreError};
use kit_core::worktree::StatObservation;
use kit_sync::worktree::{current_head_tree, read_or_seed_index_from_head};

use crate::lock;

/// Errors from [`compute`] and [`Detail::load`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The object store cannot be opened.
    #[error("not a kit repo: {0}")]
    NotARepository(StoreError),
    /// The tree of `HEAD` cannot be found.
    #[error("status: {0}")]
    HeadTree(String),
    /// The index cannot be read.
    #[error("read index: {0}")]
    ReadIndex(IndexError),
    /// The rename threshold is not a number.
    #[error("invalid --find-renames value: {0}")]
    InvalidRenameThreshold(String),
    /// The tree cannot be compared with `HEAD` and the index.
    #[error("status: {0}")]
    Compare(DiffError),
    /// The renames cannot be found.
    #[error("status: {0}")]
    Renames(StoreError),
    /// The tree of `HEAD` cannot be read.
    #[error("read HEAD tree: {0}")]
    ReadHeadTree(IndexError),
    /// The index cannot be seeded from `HEAD`.
    #[error("{0}")]
    SeedIndex(String),
}

/// What [`compute`] reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// The tree of `HEAD`. `None` before the first commit.
    pub head_tree: Option<Hash>,
    /// The changes, ordered by path with the staged one first.
    pub entries: Vec<StatusEntry>,
}

/// How [`compute`] reads the tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Request<'a> {
    /// Pair a staged deletion and a staged addition of the same content into
    /// one rename.
    pub renames: bool,
    /// The rename threshold the caller gave, such as `50` or `50%`. The
    /// operation checks that it is a number and no more, because it pairs
    /// exact content only, and any threshold up to 100 selects the same pairs.
    pub rename_threshold: Option<&'a str>,
}

/// List the changes of the tree at `root` against `HEAD` and the index.
///
/// An absent or empty index means that nothing is staged, and the tree is
/// compared with `HEAD` alone. A damaged index is an error, so it never turns
/// into that comparison.
///
/// # Errors
/// [`Error`], with one variant for each failed step.
pub fn compute(
    layout: &RepoLayout,
    root: &Path,
    request: &Request<'_>,
    observer: &dyn Observer<lock::Event>,
) -> Result<Report, Error> {
    let store = ObjectStore::open(layout).map_err(Error::NotARepository)?;

    // A remix at `HEAD` counts by its tree, like it does in every command.
    let head_tree = current_head_tree(layout, &store).map_err(Error::HeadTree)?;

    let idx = match index::read_index(layout) {
        Ok(idx) if idx.entries.is_empty() => None,
        Ok(idx) => Some(idx),
        Err(e) => return Err(Error::ReadIndex(e)),
    };

    if let Some(threshold) = request.rename_threshold {
        let number = threshold.trim_end_matches('%');
        if !number.is_empty() && number.parse::<u8>().is_err() {
            return Err(Error::InvalidRenameThreshold(threshold.to_owned()));
        }
    }

    let (mut entries, observations) =
        status_diff_observed(&store, head_tree.as_ref(), root, idx.as_ref())
            .map_err(Error::Compare)?;

    if idx.is_some() {
        refresh_stat_cache(layout, &observations, observer);
    }

    if request.renames {
        entries = detect_renames(&store, entries).map_err(Error::Renames)?;
    }
    Ok(Report { head_tree, entries })
}

/// Record the stat fields of the walk in the index. The walk hashed these
/// files again because their stat data was too new to trust.
///
/// - Each observation holds the stat of the opened file, taken before the
///   content was read. A change after that stat has a newer time, so the
///   record can claim too little and never hide an edit.
/// - The rewrite happens under the worktree lock, against an index that is
///   read again. It matches the path and the hash, so a concurrent `add` is
///   not lost.
/// - An index in an older format stays as it is. A query does not upgrade the
///   format under the feet of an older program.
///
/// The refresh only saves work. A busy lock or any error skips it.
fn refresh_stat_cache(
    layout: &RepoLayout,
    observations: &[StatObservation],
    observer: &dyn Observer<lock::Event>,
) {
    if observations.is_empty() {
        return;
    }
    match std::fs::File::open(index::index_path(layout)) {
        Ok(mut f) => {
            use std::io::Read as _;
            let mut header = [0u8; 5];
            if f.read_exact(&mut header).is_err() || header[4] != index::FORMAT_VERSION {
                return;
            }
        }
        Err(_) => return,
    }
    // A short wait and no report: a concurrent writer wins.
    let Ok(_lock) = repo_lock::acquire(
        layout.worktree_state_dir(),
        lock::WORKTREE_LOCK,
        Duration::from_millis(10),
    ) else {
        return;
    };
    lock::warn_if_served(layout, observer);
    let Ok(mut fresh) = index::read_index(layout) else {
        return;
    };
    let by_path: HashMap<&str, &StatObservation> =
        observations.iter().map(|o| (o.path.as_str(), o)).collect();
    let mut updated = false;
    for e in &mut fresh.entries {
        let Some(obs) = by_path.get(e.path.as_str()) else {
            continue;
        };
        // Heal a stat cache that is stale and still clean. A touch that
        // changed the metadata only leaves fields that are not zero and no
        // longer match, and every later call would hash the file again.
        if e.object_hash == obs.object_hash
            && (e.mtime_ns != obs.mtime_ns
                || e.size != obs.size
                || e.ino != obs.ino
                || e.ctime_ns != obs.ctime_ns)
        {
            e.mtime_ns = obs.mtime_ns;
            e.size = obs.size;
            e.ino = obs.ino;
            e.ctime_ns = obs.ctime_ns;
            updated = true;
        }
    }
    if updated {
        let _ = index::write_index(layout, &fresh);
    }
}

/// Pair a staged deletion and a staged addition of the same content into one
/// rename.
///
/// Only the staged side takes part. `mv` stages both sides, so the content is
/// compared in one state. A move that is not staged leaves an untracked
/// destination, and that never turns into a rename.
fn detect_renames(
    store: &ObjectStore,
    entries: Vec<StatusEntry>,
) -> Result<Vec<StatusEntry>, StoreError> {
    let (staged, others): (Vec<StatusEntry>, Vec<StatusEntry>) = entries
        .into_iter()
        .partition(|e| e.staging == StatusStaging::Staged);
    let mut staged_diffs: Vec<DiffEntry> = staged.into_iter().map(|e| e.diff).collect();
    detect_content_renames(store, &mut staged_diffs)?;
    let mut out: Vec<StatusEntry> = staged_diffs
        .into_iter()
        .map(|d| StatusEntry {
            diff: d,
            staging: StatusStaging::Staged,
        })
        .chain(others)
        .collect();
    // The order of the listing: by path, and the staged entry first.
    out.sort_by(|a, b| {
        a.diff
            .path
            .cmp(&b.diff.path)
            .then_with(|| staging_rank(a.staging).cmp(&staging_rank(b.staging)))
    });
    Ok(out)
}

fn staging_rank(s: StatusStaging) -> u8 {
    match s {
        StatusStaging::Staged => 0,
        StatusStaging::Unstaged => 1,
    }
}

/// What `HEAD` points at. `None` when `HEAD` cannot be read.
///
/// `unborn` is true when `HEAD` names a branch that has no commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeadState {
    /// `HEAD` as the ref store has it.
    pub head: Head,
    /// The branch has no commit yet.
    pub unborn: bool,
}

/// Read `HEAD` for the banner of a listing.
#[must_use]
pub fn head_state(layout: &RepoLayout) -> Option<HeadState> {
    let head = refs::read_head(layout).ok()?;
    let unborn =
        matches!(head, Head::Branch(_)) && refs::resolve_head(layout).ok().flatten().is_none();
    Some(HeadState { head, unborn })
}

/// One path of a porcelain listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record<'a> {
    /// The two status columns: the staged side, then the side that is not
    /// staged. Each is an ASCII letter or a space. `??` is untracked.
    pub xy: [u8; 2],
    /// The path.
    pub path: &'a str,
    /// The source of a rename.
    pub old_path: Option<&'a str>,
}

/// Fold the entries into one record for each path.
///
/// A path that is staged and changed again in the tree gets one code, such as
/// `MM` or `AM`. An untracked path is never folded into a tracked one. A path
/// can be staged for deletion and present in the tree, such as after
/// `rm --cached`. It then gets `D ` and `??` as two records, and the second
/// does not hide the first. The tracked records come first in the order in
/// which they appear, then the untracked ones.
#[must_use]
pub fn records(entries: &[StatusEntry]) -> Vec<Record<'_>> {
    let mut tracked_order: Vec<&str> = Vec::new();
    let mut tracked: HashMap<&str, ([u8; 2], Option<&str>)> = HashMap::new();
    let mut untracked: Vec<&str> = Vec::new();
    for e in entries {
        if e.staging == StatusStaging::Unstaged && e.diff.kind == DiffKind::Added {
            untracked.push(&e.diff.path);
            continue;
        }
        let c = code(e.staging, e.diff.kind).as_bytes();
        let slot = tracked.entry(&e.diff.path).or_insert_with(|| {
            tracked_order.push(&e.diff.path);
            (*b"  ", None)
        });
        // Each column comes from the entry that sets it.
        if c[0] != b' ' {
            slot.0[0] = c[0];
        }
        if c[1] != b' ' {
            slot.0[1] = c[1];
        }
        // A rename is keyed by its destination and carries its source.
        if e.diff.kind == DiffKind::Renamed {
            slot.1 = e.diff.old_path.as_deref();
        }
    }
    let mut out: Vec<Record<'_>> = tracked_order
        .into_iter()
        .map(|path| {
            let (xy, old_path) = tracked[path];
            Record { xy, path, old_path }
        })
        .collect();
    out.extend(untracked.into_iter().map(|path| Record {
        xy: *b"??",
        path,
        old_path: None,
    }));
    out
}

/// The two status columns of one entry. A mode change is `T`, which git has
/// no column for.
fn code(staging: StatusStaging, kind: DiffKind) -> &'static str {
    match (staging, kind) {
        (StatusStaging::Staged, DiffKind::Added) => "A ",
        (StatusStaging::Staged, DiffKind::Removed) => "D ",
        (StatusStaging::Staged, DiffKind::Modified) => "M ",
        (StatusStaging::Staged, DiffKind::ModeChanged) => "T ",
        // A path in the tree that the index does not know is untracked.
        (StatusStaging::Unstaged, DiffKind::Added) => "??",
        (StatusStaging::Unstaged, DiffKind::Removed) => " D",
        (StatusStaging::Unstaged, DiffKind::Modified) => " M",
        (StatusStaging::Unstaged, DiffKind::ModeChanged) => " T",
        // A rename is found for each side, so it is a clean move.
        (StatusStaging::Staged, DiffKind::Renamed) => "R ",
        (StatusStaging::Unstaged, DiffKind::Renamed) => " R",
    }
}

/// The modes and the object ids of one path, for the long porcelain listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathDetail {
    /// The octal mode in `HEAD`, or `000000`.
    pub head_mode: &'static str,
    /// The object id in `HEAD`, or all zero.
    pub head_hash: Hash,
    /// The octal mode in the index, or `000000`.
    pub index_mode: &'static str,
    /// The object id in the index, or all zero.
    pub index_hash: Hash,
    /// The octal mode in the tree, or `000000`.
    pub worktree_mode: &'static str,
}

/// The sources of [`PathDetail`]: `HEAD`, the index and the tree.
#[derive(Debug)]
pub struct Detail {
    head: Index,
    staged: Index,
    root: PathBuf,
}

impl Detail {
    /// Load `HEAD` and the effective index. The index is seeded from `HEAD`
    /// when no index file exists.
    ///
    /// # Errors
    /// [`Error::NotARepository`], [`Error::ReadHeadTree`] or
    /// [`Error::SeedIndex`].
    pub fn load(layout: &RepoLayout, head_tree: Option<&Hash>) -> Result<Self, Error> {
        let store = ObjectStore::open(layout).map_err(Error::NotARepository)?;
        let head = match head_tree {
            Some(tree) => index::from_tree(&store, *tree).map_err(Error::ReadHeadTree)?,
            None => Index::new(),
        };
        let staged = read_or_seed_index_from_head(layout, &store).map_err(Error::SeedIndex)?;
        Ok(Self {
            head,
            staged,
            root: layout.worktree_root().to_path_buf(),
        })
    }

    /// The detail of `record`. For a rename the `HEAD` side describes the
    /// source, and the index side describes the destination.
    #[must_use]
    pub fn of(&self, record: &Record<'_>) -> PathDetail {
        let (head_mode, head_hash) =
            mode_and_id(&self.head, record.old_path.unwrap_or(record.path));
        let (index_mode, index_hash) = mode_and_id(&self.staged, record.path);
        PathDetail {
            head_mode,
            head_hash,
            index_mode,
            index_hash,
            worktree_mode: worktree_mode(&self.root, record.path),
        }
    }
}

/// The octal mode and the object id of `path` in `index`. A path that is
/// absent or removed has the mode `000000` and the id zero.
fn mode_and_id(index: &Index, path: &str) -> (&'static str, Hash) {
    match index.find_entry(path) {
        Some(i) if index.entries[i].status != EntryStatus::Removed => {
            let e = &index.entries[i];
            (git_mode(e.status), e.object_hash)
        }
        _ => ("000000", ZERO),
    }
}

fn git_mode(status: EntryStatus) -> &'static str {
    match status {
        EntryStatus::Executable => "100755",
        EntryStatus::Symlink => "120000",
        _ => "100644",
    }
}

/// The octal mode of `path` in the tree. It is `000000` unless the path is a
/// regular file or a symlink, the two kinds that can be staged. A directory
/// at a tracked file path is not that file, and the listing shows the file as
/// deleted.
fn worktree_mode(root: &Path, path: &str) -> &'static str {
    let Ok(meta) = std::fs::symlink_metadata(root.join(path)) else {
        return "000000";
    };
    if meta.is_symlink() {
        "120000"
    } else if meta.is_file() {
        if is_executable(&meta) {
            "100755"
        } else {
            "100644"
        }
    } else {
        "000000"
    }
}

#[cfg(unix)]
fn is_executable(meta: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_executable(_meta: &std::fs::Metadata) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(path: &str, staging: StatusStaging, kind: DiffKind) -> StatusEntry {
        StatusEntry {
            diff: DiffEntry {
                path: path.to_owned(),
                kind,
                old_hash: None,
                new_hash: None,
                old_mode: None,
                new_mode: None,
                old_path: None,
            },
            staging,
        }
    }

    fn folded(entries: &[StatusEntry]) -> Vec<(String, String)> {
        records(entries)
            .into_iter()
            .map(|r| {
                (
                    std::str::from_utf8(&r.xy).unwrap().to_owned(),
                    r.path.to_owned(),
                )
            })
            .collect()
    }

    #[test]
    fn the_code_matrix_has_two_columns_for_every_pair() {
        use DiffKind::{Added, ModeChanged, Modified, Removed, Renamed};
        use StatusStaging::{Staged, Unstaged};
        for s in [Staged, Unstaged] {
            for k in [Added, Removed, Modified, ModeChanged, Renamed] {
                assert_eq!(code(s, k).len(), 2, "{s:?} + {k:?}");
            }
        }
        assert_eq!(code(Staged, Added), "A ");
        assert_eq!(code(Staged, Removed), "D ");
        assert_eq!(code(Staged, Modified), "M ");
        assert_eq!(code(Unstaged, Added), "??");
        assert_eq!(code(Unstaged, Modified), " M");
        assert_eq!(code(Unstaged, Removed), " D");
    }

    #[test]
    fn a_staged_and_a_further_change_fold_into_one_record() {
        use DiffKind::Modified;
        use StatusStaging::{Staged, Unstaged};
        let entries = [
            entry("a.txt", Staged, Modified),
            entry("a.txt", Unstaged, Modified),
        ];
        assert_eq!(folded(&entries), vec![("MM".into(), "a.txt".into())]);
        let entries = [
            entry("n.txt", Staged, DiffKind::Added),
            entry("n.txt", Unstaged, Modified),
        ];
        assert_eq!(folded(&entries), vec![("AM".into(), "n.txt".into())]);
    }

    #[test]
    fn a_staged_deletion_and_an_untracked_file_stay_two_records() {
        use DiffKind::{Added, Modified, Removed};
        use StatusStaging::{Staged, Unstaged};
        let entries = [
            entry("a.txt", Staged, Removed),
            entry("a.txt", Unstaged, Added),
            entry("m.txt", Unstaged, Modified),
            entry("b.txt", Unstaged, Added),
        ];
        assert_eq!(
            folded(&entries),
            vec![
                ("D ".into(), "a.txt".into()),
                (" M".into(), "m.txt".into()),
                ("??".into(), "a.txt".into()),
                ("??".into(), "b.txt".into()),
            ]
        );
    }

    #[test]
    fn a_rename_record_carries_its_source() {
        let mut renamed = entry("new.txt", StatusStaging::Staged, DiffKind::Renamed);
        renamed.diff.old_path = Some("old.txt".to_owned());
        let entries = [renamed];
        let got = records(&entries);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].xy, *b"R ");
        assert_eq!(got[0].old_path, Some("old.txt"));
    }
}
