//! Restore.
//!
//! Materialises a stored [`Tree`](crate::object::Tree) into a target
//! directory: writes blobs as files, recurses into subtrees as
//! directories, creates symlinks for symlink entries, and (when
//! `clean=true`) deletes anything in the target dir that is not in the
//! tree (preserving `.kit/` and `.git/`).
//!
//! ### Symlink invariant
//!
//! Like `worktree::build_tree`, this module **never follows external
//! symlinks**. Symlinks created here always have a relative,
//! `..`-free target — checked by [`worktree::validate_symlink_target`]
//! before the symlink is materialised.
//!
//! ### Sparse checkout
//!
//! When `RestoreOptions.sparse_patterns` is set, only files whose
//! computed full path (relative to the root) matches the pattern set
//! are restored. Pattern grammar:
//!
//! - Lines beginning with `#` are comments. Empty lines are skipped.
//! - Leading `!` negates the pattern.
//! - Trailing `/` makes the pattern dir-only.
//! - Patterns are evaluated in order; **last match wins**. No match =
//!   excluded.
//! - Bare names without a `/` also match against the basename of
//!   nested files.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::hash::Hash;
use crate::ignore::{self, IgnoreList};
use crate::layout::RepoLayout;
use crate::object::{self, EntryMode, Object, TreeEntry};
use crate::store::{MAX_TREE_DEPTH, ObjectStore};
use crate::worktree;

const MAX_SPARSE_BYTES: u64 = 1024 * 1024;

/// Chunk-count bound per `read_chunks` batch when materialising a
/// [`Object::ChunkedBlob`] — mirrors `worktree::STREAM_HASH_BATCH` (16
/// MiB at the current 256 KiB max chunk size) so the read side of a
/// large-file checkout bounds in-flight memory the same way the write
/// side already does. Public so a caller-supplied `read_chunks`'s own
/// fan-out threshold (e.g. `kit-bin`'s `restore_fanout`) can be capped
/// against the same number: a threshold above this value could never be
/// reached by any batch this module ever hands `read_chunks`, silently
/// disabling that caller's parallel path on a high-core-count host.
pub const RESTORE_CHUNK_BATCH: usize = 64;

static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Errors raised by this module.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RestoreError {
    #[error("requested object is not a tree")]
    NotATree,
    #[error("requested object is not a blob or chunked-blob")]
    NotABlob,
    #[error("symlink target '{0}' is invalid (absolute or contains '..')")]
    InvalidSymlinkTarget(String),
    #[error("path '{0}' is occupied by something other than a directory")]
    NotADirectory(PathBuf),
    #[error("path component is not valid UTF-8")]
    InvalidUtf8,
    #[error("tree nesting exceeds {} levels", MAX_TREE_DEPTH)]
    TreeTooDeep,
    #[error(transparent)]
    Object(#[from] object::KitError),
    #[error(transparent)]
    Store(#[from] crate::store::StoreError),
    #[error(transparent)]
    Io(#[from] io::Error),
    /// An I/O error while restoring `path`, relative to the restore root.
    #[error("{path}: {source}")]
    File {
        path: String,
        #[source]
        source: io::Error,
    },
    /// A `read_chunks` callback passed to
    /// [`restore_tree_to_worktree_with`] returned a different number of
    /// chunk buffers than the batch it was given — a contract violation
    /// by the caller (mirrors [`crate::worktree::WorktreeError::ChunkBatchLengthMismatch`]
    /// on the ingest side), never a normal runtime condition.
    #[error("read_chunks callback returned {actual} buffers for a {expected}-chunk batch")]
    ChunkBatchLengthMismatch { expected: usize, actual: usize },
}

/// Result alias.
pub type RestoreResult<T> = Result<T, RestoreError>;

/// One sparse-checkout pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SparsePattern {
    pub pattern: String,
    pub negated: bool,
    pub dir_only: bool,
}

/// Options for [`restore_tree`].
#[derive(Debug, Clone)]
pub struct RestoreOptions {
    /// If `true`, delete anything in the target dir that is not in the
    /// tree (preserving `.kit/` and `.git/`). Default `true`.
    pub clean: bool,
    /// If `Some`, only restore entries whose path matches the patterns.
    pub sparse_patterns: Option<Vec<SparsePattern>>,
}

impl Default for RestoreOptions {
    fn default() -> Self {
        Self {
            clean: true,
            sparse_patterns: None,
        }
    }
}

/// Parse the contents of a `.kit/sparse-checkout` file into patterns.
#[must_use]
pub fn parse_sparse_patterns(content: &str) -> Vec<SparsePattern> {
    let mut out = Vec::new();
    for raw in content.split('\n') {
        let line = raw.trim_end_matches(['\r', ' ']);
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (negated, rest) = if let Some(stripped) = line.strip_prefix('!') {
            (true, stripped)
        } else {
            (false, line)
        };
        let (dir_only, pat) = if let Some(stripped) = rest.strip_suffix('/') {
            (true, stripped)
        } else {
            (false, rest)
        };
        if pat.is_empty() {
            continue;
        }
        out.push(SparsePattern {
            pattern: pat.to_string(),
            negated,
            dir_only,
        });
    }
    out
}

/// True iff `path` matches at least one (non-negated, last-match-wins)
/// pattern in `patterns`.
#[must_use]
pub fn matches_sparse(patterns: &[SparsePattern], path: &str, is_dir: bool) -> bool {
    let mut matched = false;
    for pat in patterns {
        if path_matches_pattern(&pat.pattern, path) {
            if pat.dir_only && !is_dir {
                let pat_stripped = pat.pattern.strip_suffix('/').unwrap_or(&pat.pattern);
                if pat_stripped == path {
                    continue;
                }
            }
            matched = !pat.negated;
        }
    }
    matched
}

/// True iff a directory at `dir_prefix` could contain matched
/// descendants. Used to short-circuit recursion under sparse mode.
#[must_use]
pub fn could_match_descendant(patterns: &[SparsePattern], dir_prefix: &str) -> bool {
    for pat in patterns {
        if pat.negated {
            continue;
        }
        if pat.pattern.starts_with(dir_prefix) {
            return true;
        }
        if dir_prefix.starts_with(&pat.pattern) {
            return true;
        }
        if !dir_prefix.is_empty()
            && !dir_prefix.ends_with('/')
            && pat.pattern.len() > dir_prefix.len()
            && pat.pattern.starts_with(dir_prefix)
            && pat.pattern.as_bytes()[dir_prefix.len()] == b'/'
        {
            return true;
        }
    }
    false
}

/// Load patterns from `<repo_root>/.kit/sparse-checkout`. Returns
/// `Ok(None)` if the file does not exist or has zero patterns.
///
/// # Errors
/// - [`RestoreError::Io`] for filesystem failures other than "not found".
pub fn load_sparse_checkout(layout: &RepoLayout) -> RestoreResult<Option<Vec<SparsePattern>>> {
    let path = layout.sparse_checkout_file();
    let raw = match crate::bounded_read::read_capped_string(&path, MAX_SPARSE_BYTES) {
        Ok(raw) => raw,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(RestoreError::Io(e)),
    };
    let patterns = parse_sparse_patterns(&raw);
    if patterns.is_empty() {
        Ok(None)
    } else {
        Ok(Some(patterns))
    }
}

/// Write a sparse-checkout file (one pattern per line). Atomic on the
/// destination.
///
/// # Errors
/// - [`RestoreError::Io`] for filesystem failures.
pub fn write_sparse_checkout(layout: &RepoLayout, lines: &[&str]) -> RestoreResult<()> {
    let kit_dir = layout.worktree_state_dir().to_path_buf();
    fs::create_dir_all(&kit_dir)?;
    let mut buf = String::new();
    for l in lines {
        buf.push_str(l);
        buf.push('\n');
    }
    let path = layout.sparse_checkout_file();
    crate::atomic::write_atomic(&path, buf.as_bytes(), true)?;
    Ok(())
}

fn path_matches_pattern(pattern: &str, path: &str) -> bool {
    let pat = pattern.strip_suffix('/').unwrap_or(pattern);
    if pat == path {
        return true;
    }
    if path.len() > pat.len() && path.starts_with(pat) && path.as_bytes()[pat.len()] == b'/' {
        return true;
    }
    if !pat.contains('/')
        && let Some(last) = path.rfind('/')
    {
        let basename = &path[last + 1..];
        if basename == pat {
            return true;
        }
    }
    false
}

/// Summary of a [`restore_tree_to_worktree`] call. The counts are no
/// longer printed by any caller (`kit checkout` emits a git-shaped
/// switch confirmation instead); they are retained for programmatic
/// callers and asserted by this module's own unit tests.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RestoreReport {
    /// Number of regular / executable files materialised.
    pub files_written: u32,
    /// Number of symlinks materialised.
    pub symlinks_written: u32,
    /// Number of directories created (or that already existed as dirs).
    pub directories_created: u32,
}

/// Materialise `tree_hash` into `root` as a working tree.
///
/// Thin wrapper around [`restore_tree`] that additionally:
/// 1. Loads `<root>/.gitignore` + `<root>/.kitignore`. Ignore rules do NOT
///    gate which tree entries are materialised — tracked content is always
///    written (git parity) — they only protect *untracked* worktree files
///    (editor swapfiles, local-only build artefacts, …) from the
///    `clean=true` sweep.
/// 2. Returns a [`RestoreReport`] with counts of what was materialised
///    (consumed by programmatic callers and this module's tests; not
///    printed by the CLI).
///
/// Symlink safety is inherited from [`restore_tree`] /
/// [`worktree::validate_symlink_target`]: targets are validated BEFORE
/// the symlink is created, and any target that is absolute or contains
/// `..` is rejected with [`RestoreError::InvalidSymlinkTarget`]. The
/// net effect is that no symlink produced by this function can point
/// outside `root`.
///
/// # Errors
///
/// Same variants as [`restore_tree`]. [`RestoreError::InvalidSymlinkTarget`]
/// on a rejected target is the load-bearing "outside-of-root" check.
pub fn restore_tree_to_worktree(
    store: &ObjectStore,
    tree: &Hash,
    root: &Path,
    opts: &RestoreOptions,
) -> RestoreResult<RestoreReport> {
    // Batch size 1, not `RESTORE_CHUNK_BATCH`: `sequential_read_chunks`
    // never fans anything out, so batching it would only raise peak
    // memory from one chunk to a full batch for zero benefit — the same
    // regression `restore_blob` (the `restore_tree`/stash path) avoids
    // by not batching at all. `restore_tree_to_worktree_with` below is
    // the path real (parallel-capable) `read_chunks` callers want.
    restore_tree_to_worktree_impl(
        store,
        tree,
        root,
        opts,
        1,
        None,
        &sequential_read_chunks,
        None,
    )
}

/// [`restore_tree_to_worktree`], parameterised over how a
/// [`Object::ChunkedBlob`]'s chunk objects are read back during
/// materialisation.
///
/// `read_chunks` receives up to [`RESTORE_CHUNK_BATCH`] chunk hashes at a
/// time, in file order, and MUST return exactly one chunk's raw bytes per
/// input hash, **in the same order** — this function only verifies the
/// returned count against the input batch's length (surfacing a
/// mismatch as [`RestoreError::ChunkBatchLengthMismatch`]); a same-length
/// but reordered result is undetectable here (each chunk's *content* is
/// separately BLAKE3-verified against its own hash inside
/// [`ObjectStore::read_object`], but nothing at this layer ties a
/// returned buffer back to *which* input hash it answered, so a
/// transposed pair of same-length chunks would silently produce a
/// byte-swapped file instead of an error). This is the exact same trust
/// boundary [`worktree::store_large_file_streaming_with`]'s `hash_chunks`
/// callback already documents on the write side (also length-checked
/// only, via its own `ChunkBatchLengthMismatch`) — order is a documented
/// caller contract on both sides, not a runtime-verified one, because
/// verifying it here would mean re-hashing every chunk a second time
/// after `read_chunks` already did the real, expensive read; that would
/// undo most of the point of fanning the read out in the first place.
/// Both of this crate's own `read_chunks` implementations satisfy the
/// contract by construction: `sequential_read_chunks`'s plain
/// `iter().map().collect()` and `kit-sync`'s `rayon::par_iter().map().collect()`
/// (the latter relies on rayon's `IndexedParallelIterator` guarantee that
/// collecting into a `Vec` preserves input order regardless of which
/// worker finishes a given index first) are both order-preserving, so
/// this gap has no live exploit through any code path this crate or
/// `kit-bin` ships — it is a contract a *hand-written, buggy or hostile*
/// third-party `read_chunks` could violate, same as an equally
/// third-party `hash_chunks` already could on the write side.
/// `kit-core` has no thread-pool dependency of its own — it stays
/// usable from wasm targets, which have no OS threads — so the fan-out
/// decision lives with the caller instead of living in this function.
/// Reading each chunk (open + integrity-verify + decode) is independent
/// of every other chunk in a batch, so `kit-bin`'s native
/// checkout/clone/reset/restore paths pass a rayon-backed `read_chunks`,
/// the read-side counterpart of `add`'s ingest-side chunk-hashing
/// fan-out.
///
/// # Skipping unchanged entries
/// If `base_tree` is `Some`, every entry (file, symlink, or whole subtree)
/// whose mode and object hash are identical in `base_tree` is skipped
/// instead of re-read and rewritten, so e.g. switching branches rewrites
/// only what differs. The worktree's tracked content MUST already equal
/// `base_tree` for the paths this restore covers: `checkout` establishes
/// that with its destructive-restore safety gate, and so passes `None`
/// under `--force`, where local edits are meant to be discarded. Skipped
/// entries are not counted in the returned [`RestoreReport`]. The skip is
/// disabled when `opts.sparse_patterns` is `Some` (a sparse worktree doesn't
/// necessarily mirror `base_tree`).
///
/// With `opts.clean`, the sweep visits only the directories the restore
/// enters, so a skipped subtree is not swept. The caller must also have
/// proved that the worktree holds no untracked path outside the ignore rules,
/// as the safety gate of a destructive restore does.
///
/// # Errors
/// Same variants as [`restore_tree_to_worktree`], plus
/// [`RestoreError::ChunkBatchLengthMismatch`] if `read_chunks` returns a
/// different number of buffers than the batch it was given (see above
/// for what this check does and does not catch).
pub fn restore_tree_to_worktree_with<F>(
    store: &ObjectStore,
    tree: &Hash,
    base_tree: Option<Hash>,
    root: &Path,
    opts: &RestoreOptions,
    read_chunks: &F,
) -> RestoreResult<RestoreReport>
where
    F: Fn(&ObjectStore, &[Hash]) -> RestoreResult<Vec<Vec<u8>>> + Sync,
{
    restore_tree_to_worktree_observed(store, tree, base_tree, root, opts, read_chunks, None)
}

/// [`restore_tree_to_worktree_with`] that also pushes one
/// [`worktree::StatObservation`] per regular file it writes onto
/// `observed`, when `observed` is `Some`. A caller that rebuilds the
/// index from the tree records these as the stat cache, so the next
/// command does not re-hash files the restore just wrote.
///
/// An observation is pushed only when the file at its final path is
/// still the inode this restore wrote, with the same size and mtime as
/// the open handle reported after the last write. Its fields are read
/// from the final path after the rename, because a rename moves the
/// ctime. A later edit that leaves size, mtime and ctime unchanged is
/// invisible to it, as to every stat observation; the index's racy-clean
/// rule bounds that window.
///
/// # Errors
/// Same as [`restore_tree_to_worktree_with`].
pub fn restore_tree_to_worktree_observed<F>(
    store: &ObjectStore,
    tree: &Hash,
    base_tree: Option<Hash>,
    root: &Path,
    opts: &RestoreOptions,
    read_chunks: &F,
    observed: Option<&mut Vec<worktree::StatObservation>>,
) -> RestoreResult<RestoreReport>
where
    F: Fn(&ObjectStore, &[Hash]) -> RestoreResult<Vec<Vec<u8>>> + Sync,
{
    let base = if opts.sparse_patterns.is_some() {
        None
    } else {
        base_tree
    };
    restore_tree_to_worktree_impl(
        store,
        tree,
        root,
        opts,
        RESTORE_CHUNK_BATCH,
        base,
        read_chunks,
        observed,
    )
}

/// Shared implementation behind [`restore_tree_to_worktree`] and
/// [`restore_tree_to_worktree_with`]. `batch_size` is not part of either
/// public signature — it is 1 for the sequential default (see
/// [`restore_tree_to_worktree`]'s doc) and [`RESTORE_CHUNK_BATCH`] for a
/// caller-supplied `read_chunks`.
#[allow(clippy::too_many_arguments)]
fn restore_tree_to_worktree_impl<F>(
    store: &ObjectStore,
    tree: &Hash,
    root: &Path,
    opts: &RestoreOptions,
    batch_size: usize,
    base_tree: Option<Hash>,
    read_chunks: &F,
    observed: Option<&mut Vec<worktree::StatObservation>>,
) -> RestoreResult<RestoreReport>
where
    F: Fn(&ObjectStore, &[Hash]) -> RestoreResult<Vec<Vec<u8>>> + Sync,
{
    // Load the root-level ignore list. Missing = empty list.
    let ignore_list = match ignore::load(root) {
        Ok(il) => il,
        Err(_) => IgnoreList::new(),
    };
    fs::create_dir_all(root)?;
    let mut report = RestoreReport::default();
    restore_tree_to_worktree_inner(
        store,
        *tree,
        root,
        opts,
        "",
        &ignore_list,
        &mut report,
        0,
        batch_size,
        base_tree,
        read_chunks,
        observed,
    )?;
    Ok(report)
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)] // one arm per entry mode
fn restore_tree_to_worktree_inner<F>(
    store: &ObjectStore,
    tree_hash: Hash,
    target_dir: &Path,
    options: &RestoreOptions,
    path_prefix: &str,
    ignore: &IgnoreList,
    report: &mut RestoreReport,
    depth: usize,
    batch_size: usize,
    base_tree: Option<Hash>,
    read_chunks: &F,
    mut observed: Option<&mut Vec<worktree::StatObservation>>,
) -> RestoreResult<()>
where
    F: Fn(&ObjectStore, &[Hash]) -> RestoreResult<Vec<Vec<u8>>> + Sync,
{
    if depth > MAX_TREE_DEPTH {
        return Err(RestoreError::TreeTooDeep);
    }
    let obj = store.read_object(&tree_hash)?;
    let Object::Tree(tree) = obj else {
        return Err(RestoreError::NotATree);
    };
    // Entries of the already-materialised tree at this level, by name.
    // An unreadable/non-tree base just disables skipping here.
    let base_obj = base_tree.and_then(|b| store.read_object(&b).ok());
    let base_entries: std::collections::HashMap<&[u8], &crate::object::TreeEntry> = match &base_obj
    {
        Some(Object::Tree(bt)) => bt.entries.iter().map(|e| (e.name.as_slice(), e)).collect(),
        _ => std::collections::HashMap::new(),
    };

    if options.clean {
        clean_directory(
            target_dir,
            &tree.entries,
            options.sparse_patterns.as_deref(),
            path_prefix,
            Some(ignore),
        )?;
    }

    for entry in &tree.entries {
        if !crate::object::TreeEntry::validate_name(&entry.name) {
            continue;
        }
        let name = std::str::from_utf8(&entry.name).map_err(|_| RestoreError::InvalidUtf8)?;
        let base_entry = base_entries.get(entry.name.as_slice());
        // Identical to what the worktree already holds (see
        // `restore_tree_to_worktree_with`'s `base_tree`): nothing to write.
        if base_entry.is_some_and(|b| b.mode == entry.mode && b.object_hash == entry.object_hash) {
            continue;
        }
        let full_path = if path_prefix.is_empty() {
            name.to_string()
        } else {
            format!("{path_prefix}/{name}")
        };
        // NOTE: ignore rules do NOT gate materialization. Tree entries are
        // tracked content and must always be written (git parity — skipping
        // them would desync the index from the worktree). Ignore rules only
        // protect *untracked* worktree files during the ignore-aware
        // `clean_directory` sweep below.
        match entry.mode {
            EntryMode::Blob | EntryMode::Executable => {
                if let Some(patterns) = options.sparse_patterns.as_deref()
                    && !matches_sparse(patterns, &full_path, false)
                {
                    continue;
                }
                let stat = at_path(
                    restore_blob_with(
                        store,
                        target_dir,
                        name,
                        entry.object_hash,
                        entry.mode == EntryMode::Executable,
                        batch_size,
                        read_chunks,
                        observed.is_some(),
                    ),
                    &full_path,
                )?;
                report.files_written += 1;
                if let (Some(out), Some(stat)) = (observed.as_deref_mut(), stat) {
                    out.push(observation(full_path, entry.object_hash, stat));
                }
            }
            EntryMode::Tree => {
                if let Some(patterns) = options.sparse_patterns.as_deref()
                    && !could_match_descendant(patterns, &full_path)
                {
                    continue;
                }
                let dir_path = target_dir.join(name);
                let dir_meta = ensure_directory_at(target_dir, name, &full_path)?;
                report.directories_created += 1;
                if !dir_meta.is_dir() {
                    return Err(RestoreError::NotADirectory(dir_path));
                }
                restore_tree_to_worktree_inner(
                    store,
                    entry.object_hash,
                    &dir_path,
                    options,
                    &full_path,
                    ignore,
                    report,
                    depth + 1,
                    batch_size,
                    base_entry
                        .filter(|b| b.mode == EntryMode::Tree)
                        .map(|b| b.object_hash),
                    read_chunks,
                    observed.as_deref_mut(),
                )?;
            }
            EntryMode::Symlink => {
                if let Some(patterns) = options.sparse_patterns.as_deref()
                    && !matches_sparse(patterns, &full_path, false)
                {
                    continue;
                }
                at_path(
                    restore_symlink(store, target_dir, name, entry.object_hash),
                    &full_path,
                )?;
                report.symlinks_written += 1;
            }
        }
    }
    Ok(())
}

/// Materialise `tree_hash` into `target_dir`. See module docs for the
/// invariants.
///
/// This function applies no ignore rules, so with `clean: true` its sweep
/// removes ignored files. A caller that may face ignored files must pass
/// `clean: false` or use [`restore_tree_to_worktree`]. `stash save` restores
/// HEAD with `clean: false`. Chunks are read sequentially.
///
/// # Errors
/// - [`RestoreError::NotATree`] if `tree_hash` is not a tree object.
/// - [`RestoreError::InvalidSymlinkTarget`] if a symlink entry's target
///   is absolute or contains `..`.
pub fn restore_tree(
    store: &ObjectStore,
    tree_hash: Hash,
    target_dir: &Path,
    options: &RestoreOptions,
) -> RestoreResult<()> {
    fs::create_dir_all(target_dir)?;
    restore_tree_inner(store, tree_hash, target_dir, options, "")
}

fn restore_tree_inner(
    store: &ObjectStore,
    tree_hash: Hash,
    target_dir: &Path,
    options: &RestoreOptions,
    path_prefix: &str,
) -> RestoreResult<()> {
    let obj = store.read_object(&tree_hash)?;
    let Object::Tree(tree) = obj else {
        return Err(RestoreError::NotATree);
    };

    if options.clean {
        clean_directory(
            target_dir,
            &tree.entries,
            options.sparse_patterns.as_deref(),
            path_prefix,
            None,
        )?;
    }

    for entry in &tree.entries {
        if !crate::object::TreeEntry::validate_name(&entry.name) {
            continue;
        }
        let name = std::str::from_utf8(&entry.name).map_err(|_| RestoreError::InvalidUtf8)?;
        let full_path = if path_prefix.is_empty() {
            name.to_string()
        } else {
            format!("{path_prefix}/{name}")
        };
        match entry.mode {
            EntryMode::Blob | EntryMode::Executable => {
                if let Some(patterns) = options.sparse_patterns.as_deref()
                    && !matches_sparse(patterns, &full_path, false)
                {
                    continue;
                }
                at_path(
                    restore_blob(
                        store,
                        target_dir,
                        name,
                        entry.object_hash,
                        entry.mode == EntryMode::Executable,
                    ),
                    &full_path,
                )?;
            }
            EntryMode::Tree => {
                if let Some(patterns) = options.sparse_patterns.as_deref()
                    && !could_match_descendant(patterns, &full_path)
                {
                    continue;
                }
                let dir_path = target_dir.join(name);
                // Refuse to follow a symlink that took the place of the dir.
                let dir_meta = ensure_directory_at(target_dir, name, &full_path)?;
                if !dir_meta.is_dir() {
                    return Err(RestoreError::NotADirectory(dir_path));
                }
                restore_tree_inner(store, entry.object_hash, &dir_path, options, &full_path)?;
            }
            EntryMode::Symlink => {
                if let Some(patterns) = options.sparse_patterns.as_deref()
                    && !matches_sparse(patterns, &full_path, false)
                {
                    continue;
                }
                at_path(
                    restore_symlink(store, target_dir, name, entry.object_hash),
                    &full_path,
                )?;
            }
        }
    }
    Ok(())
}

/// Sequential blob restore: reads each chunk of a [`Object::ChunkedBlob`]
/// one at a time on the calling thread, straight into the open tmp file.
/// Used by [`restore_tree`] (the non-worktree, `stash`-facing path,
/// which has no parallel-capable `read_chunks` to offer). Kept as its
/// own true one-chunk-at-a-time loop rather than delegating to
/// [`restore_blob_with`] with [`sequential_read_chunks`]: batching
/// chunks before writing them (as `restore_blob_with` does, to give a
/// parallel `read_chunks` something to fan out) would raise this path's
/// peak memory from one chunk (≤256 KiB) to a full [`RESTORE_CHUNK_BATCH`]
/// batch (≤16 MiB) for no benefit, regressing the original
/// "reassemble without ever holding more than one chunk" guarantee on a
/// path that can never use the extra batch size for anything.
fn restore_blob(
    store: &ObjectStore,
    dir: &Path,
    name: &str,
    blob_hash: Hash,
    executable: bool,
) -> RestoreResult<()> {
    let obj = store.read_object(&blob_hash)?;
    match obj {
        Object::Blob(b) => {
            write_file_atomic(dir, name, &b.data, executable, false)?;
        }
        Object::ChunkedBlob(cb) => {
            let (tmp_path, final_path, mut tmp) = create_tmp_for_write(dir, name)?;
            let result = (|| -> RestoreResult<()> {
                let mut written: u64 = 0;
                for ch in &cb.chunks {
                    let buf = read_chunk_bytes(store, ch)?;
                    written += buf.len() as u64;
                    if written > cb.total_size {
                        break;
                    }
                    tmp.write_all(&buf)?;
                }
                cb.check_reassembled_size(usize::try_from(written).unwrap_or(usize::MAX))?;
                Ok(())
            })();
            #[cfg(not(target_arch = "wasm32"))] // wasm File has no destructor
            drop(tmp);
            finish_or_discard_tmp(result, &tmp_path, &final_path, executable)?;
        }
        _ => return Err(RestoreError::NotABlob),
    }
    Ok(())
}

/// Materialise `blob_hash` (a [`Object::Blob`] or [`Object::ChunkedBlob`])
/// as `dir/name`. For a `ChunkedBlob`, `read_chunks` reads back each
/// batch of up to `batch_size` chunk hashes (at most [`RESTORE_CHUNK_BATCH`]
/// — see [`restore_tree_to_worktree_with`]'s doc for the callback
/// contract; `batch_size` itself is `restore_tree_to_worktree_impl`'s
/// internal knob, 1 for the sequential default or `RESTORE_CHUNK_BATCH`
/// for a caller-supplied `read_chunks`, never part of either public
/// entry point's own signature).
///
/// With `observe`, returns the written file's stat fields when
/// [`observe_written`] can prove them; see
/// [`restore_tree_to_worktree_observed`].
///
/// # Panics
/// If `batch_size` is 0 (`[T]::chunks` itself panics on that) — never
/// true for either internal caller.
#[allow(clippy::too_many_arguments)]
fn restore_blob_with<F>(
    store: &ObjectStore,
    dir: &Path,
    name: &str,
    blob_hash: Hash,
    executable: bool,
    batch_size: usize,
    read_chunks: &F,
    observe: bool,
) -> RestoreResult<Option<StatFields>>
where
    F: Fn(&ObjectStore, &[Hash]) -> RestoreResult<Vec<Vec<u8>>> + Sync,
{
    let obj = store.read_object(&blob_hash)?;
    match obj {
        Object::Blob(b) => write_file_atomic(dir, name, &b.data, executable, observe),
        Object::ChunkedBlob(cb) => {
            // Stream each batch straight to the open tmp file instead of
            // concatenating the whole reassembled file into memory first.
            // Peak memory is one `batch_size`-chunk batch
            // (bounded, see this function's doc), not the file's total
            // size. Batching (rather than one chunk at a time) lets a
            // parallel-capable `read_chunks` fan a batch's independent
            // reads out across threads — see this function's and
            // `restore_tree_to_worktree_with`'s docs.
            let (tmp_path, final_path, mut tmp) = create_tmp_for_write(dir, name)?;
            let result = write_chunk_batches(
                store,
                &cb.chunks,
                cb.total_size,
                batch_size,
                read_chunks,
                &mut tmp,
            )
            .and_then(|written| {
                cb.check_reassembled_size(usize::try_from(written).unwrap_or(usize::MAX))
                    .map_err(RestoreError::from)
            });
            let written = if observe && result.is_ok() {
                tmp.metadata().ok()
            } else {
                None
            };
            #[cfg(not(target_arch = "wasm32"))] // wasm File has no destructor
            drop(tmp);
            finish_or_discard_tmp(result, &tmp_path, &final_path, executable)?;
            Ok(written.and_then(|meta| observe_written(&meta, &final_path)))
        }
        _ => Err(RestoreError::NotABlob),
    }
}

/// Stat-cache fields in [`worktree::stat_cache_fields`] order:
/// `(mtime_ns, size, ino, ctime_ns)`.
type StatFields = (u64, u64, u64, u64);

fn observation(path: String, object_hash: Hash, stat: StatFields) -> worktree::StatObservation {
    let (mtime_ns, size, ino, ctime_ns) = stat;
    worktree::StatObservation {
        path,
        object_hash,
        mtime_ns,
        size,
        ino,
        ctime_ns,
    }
}

/// Stat-cache fields of `final_path`, if it is still the file a restore
/// just wrote. `written` is the open handle's metadata after the last
/// write. The final path must be a regular file with the same inode,
/// size and mtime; any later write that moved the mtime fails the check.
/// The fields come from the final path, because the rename moved the
/// ctime.
fn observe_written(written: &fs::Metadata, final_path: &Path) -> Option<StatFields> {
    let now = fs::symlink_metadata(final_path).ok()?;
    let (mtime, size, ino, _) = worktree::stat_cache_fields(written);
    let fields = worktree::stat_cache_fields(&now);
    (now.is_file() && mtime != 0 && fields.0 == mtime && fields.1 == size && fields.2 == ino)
        .then_some(fields)
}

/// Rename the tmp file into place when `result` is `Ok`. When the write,
/// the mode change or the rename fails, remove the tmp file this call was
/// given, and only that file, and return the error. A failed restore then
/// leaves no partial file behind. A failure to remove the tmp file never
/// replaces the error.
fn finish_or_discard_tmp(
    result: RestoreResult<()>,
    tmp_path: &Path,
    final_path: &Path,
    executable: bool,
) -> RestoreResult<()> {
    let result = result.and_then(|()| Ok(finish_atomic_write(tmp_path, final_path, executable)?));
    if result.is_err() {
        let _ = fs::remove_file(tmp_path);
    }
    result
}

/// Read `chunks` in batches of `batch_size` via `read_chunks` and append
/// each batch to `out`, returning the total bytes written. A batch that
/// would take the running total past `limit` is not written and fails
/// with [`object::KitError::ChunkedBlobSizeMismatch`], so a manifest
/// cannot make the restore write more than its declared `total_size`.
///
/// With more than one batch on a threaded target, the write of batch N
/// is overlapped with the read of batch N+1: a scoped writer thread
/// drains a rendezvous channel, so at most two batches are ever in
/// flight (one being written, one being read) and peak memory stays
/// bounded at `2 * batch_size` chunks. A single-batch file (or wasm,
/// which has no threads) takes the plain sequential loop.
fn write_chunk_batches<F>(
    store: &ObjectStore,
    chunks: &[Hash],
    limit: u64,
    batch_size: usize,
    read_chunks: &F,
    out: &mut fs::File,
) -> RestoreResult<u64>
where
    F: Fn(&ObjectStore, &[Hash]) -> RestoreResult<Vec<Vec<u8>>> + Sync,
{
    let read_batch = |batch: &[Hash]| -> RestoreResult<Vec<Vec<u8>>> {
        let bufs = read_chunks(store, batch)?;
        if bufs.len() != batch.len() {
            return Err(RestoreError::ChunkBatchLengthMismatch {
                expected: batch.len(),
                actual: bufs.len(),
            });
        }
        Ok(bufs)
    };

    #[cfg(not(target_arch = "wasm32"))]
    if batch_size > 1 && chunks.len() > batch_size {
        return std::thread::scope(|scope| {
            let (tx, rx) = std::sync::mpsc::sync_channel::<Vec<Vec<u8>>>(0);
            let writer = scope.spawn(move || -> RestoreResult<u64> {
                let mut written: u64 = 0;
                for bufs in rx {
                    written += write_batch_within(out, &bufs, written, limit)?;
                }
                Ok(written)
            });
            let mut read_err = None;
            for batch in chunks.chunks(batch_size) {
                match read_batch(batch) {
                    // A failed send means the writer already hit an I/O
                    // error; stop reading and surface it from the join.
                    Ok(bufs) => {
                        if tx.send(bufs).is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        read_err = Some(e);
                        break;
                    }
                }
            }
            drop(tx);
            let written = match writer.join() {
                Ok(r) => r,
                Err(panic) => std::panic::resume_unwind(panic),
            };
            match (read_err, written) {
                (Some(e), _) => Err(e),
                (None, w) => w,
            }
        });
    }

    let mut written: u64 = 0;
    for batch in chunks.chunks(batch_size) {
        let bufs = read_batch(batch)?;
        written += write_batch_within(out, &bufs, written, limit)?;
    }
    Ok(written)
}

/// Append `bufs` to `out` unless `written` plus their length passes
/// `limit`. An overrun writes nothing and returns the length it would
/// have reached.
fn write_batch_within(
    out: &mut fs::File,
    bufs: &[Vec<u8>],
    written: u64,
    limit: u64,
) -> RestoreResult<u64> {
    let reached = written.saturating_add(bufs.iter().map(|b| b.len() as u64).sum::<u64>());
    if reached > limit {
        return Err(object::KitError::ChunkedBlobSizeMismatch {
            expected: limit,
            actual: reached,
        }
        .into());
    }
    Ok(write_batch_vectored(out, bufs)?)
}

/// Append every buffer in `bufs` to `out` with gathered `writev` calls
/// (one syscall per batch in the common case instead of one per chunk),
/// returning the total bytes written.
fn write_batch_vectored(out: &mut fs::File, bufs: &[Vec<u8>]) -> io::Result<u64> {
    use std::io::IoSlice;
    let mut slices: Vec<IoSlice<'_>> = bufs.iter().map(|b| IoSlice::new(b)).collect();
    let mut rest: &mut [IoSlice<'_>] = &mut slices;
    let mut written: u64 = 0;
    // Drop leading empty buffers so an all-empty batch isn't a `WriteZero`.
    IoSlice::advance_slices(&mut rest, 0);
    while !rest.is_empty() {
        match out.write_vectored(rest) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(n) => {
                written += n as u64;
                IoSlice::advance_slices(&mut rest, n);
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(written)
}

/// Default `read_chunks`: reads and type-checks each chunk hash in
/// `hashes` one at a time via [`ObjectStore::read_object`] (which
/// integrity-verifies the bytes against the hash).
fn sequential_read_chunks(store: &ObjectStore, hashes: &[Hash]) -> RestoreResult<Vec<Vec<u8>>> {
    hashes.iter().map(|h| read_chunk_bytes(store, h)).collect()
}

fn read_chunk_bytes(store: &ObjectStore, h: &Hash) -> RestoreResult<Vec<u8>> {
    match store.read_object(h)? {
        Object::Blob(b) => Ok(b.data),
        _ => Err(RestoreError::NotABlob),
    }
}

fn restore_symlink(
    store: &ObjectStore,
    dir: &Path,
    name: &str,
    blob_hash: Hash,
) -> RestoreResult<()> {
    let obj = store.read_object(&blob_hash)?;
    let Object::Blob(b) = obj else {
        return Err(RestoreError::NotABlob);
    };
    let target = std::str::from_utf8(&b.data).map_err(|_| RestoreError::InvalidUtf8)?;
    if !worktree::validate_symlink_target(target) {
        return Err(RestoreError::InvalidSymlinkTarget(target.to_string()));
    }
    let final_path = dir.join(name);
    let tmp_path = loop {
        let tmp_path = dir.join(make_tmp_name());
        match create_symlink(target, &tmp_path) {
            Ok(()) => break tmp_path,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
    };
    let result =
        prepare_path_for_rename(&final_path).and_then(|()| fs::rename(&tmp_path, &final_path));
    if result.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }
    Ok(result?)
}

#[cfg(unix)]
fn create_symlink(target: &str, link: &Path) -> io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(windows)]
fn create_symlink(target: &str, link: &Path) -> io::Result<()> {
    // Symlinks on Windows require either Developer Mode or admin
    // privileges. We pick `symlink_file` because every blob is a file
    // when materialised through this code path.
    std::os::windows::fs::symlink_file(target, link)
}

#[cfg(not(any(unix, windows)))]
fn create_symlink(_target: &str, _link: &Path) -> io::Result<()> {
    // Targets without a filesystem (notably `wasm32-unknown-unknown`)
    // cannot materialise symlinks. The demo wasm crate does not exercise
    // the restore path; this stub exists so the crate still compiles.
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "symlink creation is not supported on this target",
    ))
}

/// Write a restored worktree file via tmp + rename so concurrent
/// readers never observe a torn file.
///
/// Deliberately NOT flushed: worktree contents are not part of the
/// store's durability invariant (SPEC-OBJECTS §10.1) — the object
/// store is the source of truth and checkout is re-runnable after a
/// crash. Flushing every restored file made checkout O(files) full
/// flushes (`F_FULLFSYNC` each on macOS) for no recoverable state; git
/// likewise does not flush checked-out files.
///
/// With `observe`, returns the file's stat fields when
/// [`observe_written`] can prove them.
fn write_file_atomic(
    dir: &Path,
    name: &str,
    data: &[u8],
    executable: bool,
    observe: bool,
) -> RestoreResult<Option<StatFields>> {
    let (tmp_path, final_path, mut tmp) = create_tmp_for_write(dir, name)?;
    let result = tmp.write_all(data).map_err(RestoreError::from);
    let written = if observe { tmp.metadata().ok() } else { None };
    #[cfg(not(target_arch = "wasm32"))] // wasm File has no destructor
    drop(tmp);
    finish_or_discard_tmp(result, &tmp_path, &final_path, executable)?;
    Ok(written.and_then(|meta| observe_written(&meta, &final_path)))
}

/// Create a fresh tmp file in `dir`. The tmp name is new: a name that is
/// already taken, by a file, a directory or a symlink, is skipped for the
/// next counter value and never opened or removed. Returns the tmp path,
/// final path, and the open handle so a caller can write incrementally
/// (see [`restore_blob`]'s `ChunkedBlob` arm) instead of buffering the
/// whole file first — pair with [`finish_or_discard_tmp`] to apply the
/// executable bit and atomically rename into place, or to remove the tmp
/// file when a step fails.
fn create_tmp_for_write(dir: &Path, name: &str) -> io::Result<(PathBuf, PathBuf, fs::File)> {
    loop {
        let tmp_path = dir.join(make_tmp_name());
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)
        {
            Ok(tmp) => return Ok((tmp_path, dir.join(name), tmp)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
    }
}

/// Apply the executable bit (if requested) and atomically rename the
/// tmp file from [`create_tmp_for_write`] into its final path. The tmp
/// file's handle must already be closed/dropped before calling this
/// (renaming an open handle is unreliable on some platforms).
fn finish_atomic_write(tmp_path: &Path, final_path: &Path, executable: bool) -> io::Result<()> {
    if executable {
        apply_executable_bit(tmp_path)?;
    }
    prepare_path_for_rename(final_path)?;
    fs::rename(tmp_path, final_path)?;
    Ok(())
}

#[cfg(unix)]
fn apply_executable_bit(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perm = fs::metadata(path)?.permissions();
    perm.set_mode(0o755);
    fs::set_permissions(path, perm)
}

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
fn apply_executable_bit(_path: &Path) -> io::Result<()> {
    Ok(())
}

/// Create directory `name` under `parent` and return its metadata, read
/// without following a symlink. An I/O error names `full_path`.
fn ensure_directory_at(parent: &Path, name: &str, full_path: &str) -> RestoreResult<fs::Metadata> {
    at_path(
        ensure_directory(parent, name)
            .and_then(|()| fs::symlink_metadata(parent.join(name)))
            .map_err(RestoreError::from),
        full_path,
    )
}

fn ensure_directory(parent: &Path, name: &str) -> io::Result<()> {
    let path = parent.join(name);
    match fs::symlink_metadata(&path) {
        Ok(meta) if meta.is_dir() => return Ok(()),
        Ok(_) => fs::remove_file(&path)?,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    match fs::create_dir_all(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            let meta = fs::symlink_metadata(&path)?;
            if meta.is_dir() {
                Ok(())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "expected directory",
                ))
            }
        }
        Err(e) => Err(e),
    }
}

fn prepare_path_for_rename(final_path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(final_path) {
        Ok(meta) if meta.is_dir() => fs::remove_dir_all(final_path),
        Ok(_) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Prefix of every restore temporary name, `<prefix>.<pid>.<counter>`.
const TMP_PREFIX: &str = ".kit-restore-tmp";

/// A short temporary name for a restore write. It does not contain the
/// file name, so it stays within the file system's name limit for any
/// name the file system accepts. The process id and a process-wide
/// counter make it unique per process and call.
fn make_tmp_name() -> String {
    let pid = process::id();
    let counter = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{TMP_PREFIX}.{pid}.{counter}")
}

/// Whether `name` is exactly a restore temporary name: the prefix, then
/// a process id and a counter, both nonempty ASCII digits. The caller
/// must also verify that the entry is an untracked regular file before
/// treating it as an interrupted write.
#[must_use]
pub fn is_restore_temp_name(name: &str) -> bool {
    let Some(rest) = name
        .strip_prefix(TMP_PREFIX)
        .and_then(|rest| rest.strip_prefix('.'))
    else {
        return false;
    };
    let Some((pid, counter)) = rest.split_once('.') else {
        return false;
    };
    [pid, counter]
        .iter()
        .all(|field| !field.is_empty() && field.bytes().all(|b| b.is_ascii_digit()))
}

/// Attach `path` to an I/O error from `result`.
fn at_path<T>(result: RestoreResult<T>, path: &str) -> RestoreResult<T> {
    result.map_err(|e| match e {
        RestoreError::Io(source) => RestoreError::File {
            path: path.to_string(),
            source,
        },
        other => other,
    })
}

/// Sweep `target_dir` of untracked entries before re-materialising a
/// tree. Entries present in `tree_entries`, the repo-metadata dirs
/// (`.kit`/`.git`, ASCII case-insensitive so case-insensitive
/// filesystems can't smuggle a `.KIT`/`.Git` entry past the sweep — Git
/// CVE-2021-21300 family), and `.kitignore` are always preserved.
///
/// When `ignore` is `Some`, this is the worktree-checkout path: entries
/// matching the ignore list are additionally preserved (ancestor-aware,
/// so an untracked file *under* an ignored directory survives too), and
/// `.gitignore` is preserved as well.
fn clean_directory(
    target_dir: &Path,
    tree_entries: &[TreeEntry],
    sparse_patterns: Option<&[SparsePattern]>,
    path_prefix: &str,
    ignore: Option<&IgnoreList>,
) -> RestoreResult<()> {
    struct CleanItem {
        name: String,
        is_dir: bool,
    }
    let mut to_delete: Vec<CleanItem> = Vec::new();

    let read = match fs::read_dir(target_dir) {
        Ok(r) => r,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(RestoreError::Io(e)),
    };
    for entry in read {
        let entry = entry?;
        let file_name = entry.file_name();
        let name_str = file_name
            .to_str()
            .ok_or(RestoreError::InvalidUtf8)?
            .to_string();
        if name_str.eq_ignore_ascii_case(".kit") || name_str.eq_ignore_ascii_case(".git") {
            continue;
        }
        if name_str == ".kitignore" {
            continue;
        }
        // The ignore-aware checkout path also preserves `.gitignore`.
        if ignore.is_some() && name_str == ".gitignore" {
            continue;
        }
        let mut found = false;
        for te in tree_entries {
            if te.name.as_slice() == name_str.as_bytes() {
                found = true;
                break;
            }
        }
        if found {
            continue;
        }
        let meta = entry.metadata()?;
        let is_dir = meta.is_dir();
        let full_path = if path_prefix.is_empty() {
            name_str.clone()
        } else {
            format!("{path_prefix}/{name_str}")
        };
        // Respect ignore rules — don't touch locally-ignored files. Use
        // ancestor-aware matching so an untracked file *under* an ignored
        // directory is preserved too (the safety gate exempts it, so the
        // sweep must not delete it).
        if let Some(ignore) = ignore
            && ignore.is_ignored_with_ancestors(&full_path, is_dir)
        {
            continue;
        }
        if let Some(patterns) = sparse_patterns {
            let allow = matches_sparse(patterns, &full_path, is_dir)
                || (is_dir && could_match_descendant(patterns, &full_path));
            if !allow {
                continue;
            }
        }
        to_delete.push(CleanItem {
            name: name_str,
            is_dir,
        });
    }

    for item in to_delete {
        let path = target_dir.join(&item.name);
        if item.is_dir
            && let Some(ignore) = ignore
        {
            // Keep ignored descendants and the directories that hold them.
            let prefix = if path_prefix.is_empty() {
                item.name.clone()
            } else {
                format!("{path_prefix}/{}", item.name)
            };
            sweep_unlisted_dir(&path, &prefix, ignore);
        } else if item.is_dir {
            let _ = fs::remove_dir_all(&path);
        } else {
            let _ = fs::remove_file(&path);
        }
    }
    Ok(())
}

/// Remove everything under `dir` (repo-relative `prefix`) that the ignore
/// rules do not match, then `dir` itself if nothing is left. A symlink is
/// removed, never followed.
fn sweep_unlisted_dir(dir: &Path, prefix: &str, ignore: &IgnoreList) {
    let Ok(read) = fs::read_dir(dir) else {
        return;
    };
    for entry in read.flatten() {
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        let rel = format!("{prefix}/{name}");
        if ignore.is_ignored_with_ancestors(&rel, meta.is_dir()) {
            continue;
        }
        if meta.is_dir() {
            sweep_unlisted_dir(&entry.path(), &rel, ignore);
        } else {
            let _ = fs::remove_file(entry.path());
        }
    }
    let _ = fs::remove_dir(dir);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::{Tree, TreeEntry};
    use crate::serialize;
    use tempfile::TempDir;

    fn fresh_store() -> (TempDir, ObjectStore) {
        let dir = TempDir::new().unwrap();
        let store = ObjectStore::init(&RepoLayout::single(dir.path())).unwrap();
        (dir, store)
    }

    fn put_blob(store: &ObjectStore, data: &[u8]) -> Hash {
        let bytes = serialize::serialize(&Object::Blob(crate::object::Blob {
            data: data.to_vec(),
        }))
        .unwrap();
        store.write(&bytes).unwrap()
    }

    fn put_tree_with(store: &ObjectStore, entries: Vec<TreeEntry>) -> Hash {
        let bytes = serialize::serialize(&Object::Tree(Tree { entries })).unwrap();
        store.write(&bytes).unwrap()
    }

    #[test]
    fn restore_temporary_names_are_exact() {
        for name in [
            ".kit-restore-tmp.1.2",
            ".kit-restore-tmp.00.0",
            ".kit-restore-tmp.123.456",
        ] {
            assert!(is_restore_temp_name(name), "{name}");
        }
        for name in [
            "kit-restore-tmp.1.2",
            ".kit-restore-tmp..2",
            ".kit-restore-tmp.1.",
            ".kit-restore-tmp.1",
            ".kit-restore-tmp.-1.2",
            ".kit-restore-tmp.+1.2",
            ".kit-restore-tmp.１.2",
            ".kit-restore-tmp.1.2.extra",
            ".kit-restore-tmp.1.x",
            "../.kit-restore-tmp.1.2",
            ".a.tmp.1.2",
        ] {
            assert!(!is_restore_temp_name(name), "{name}");
        }
    }

    #[test]
    fn restore_temporary_names_are_short_and_unique() {
        let first = make_tmp_name();
        let second = make_tmp_name();
        assert_ne!(first, second);
        assert!(is_restore_temp_name(&first));
        assert!(first.len() < 64);
    }

    fn tree_of_one_file(store: &ObjectStore, name: &[u8], data: &[u8]) -> Hash {
        let blob = put_blob(store, data);
        put_tree_with(
            store,
            vec![TreeEntry {
                name: name.to_vec(),
                mode: EntryMode::Blob,
                object_hash: blob,
            }],
        )
    }

    #[cfg(unix)]
    #[test]
    fn restore_sets_the_executable_bit_only_for_executable_entries() {
        use std::os::unix::fs::PermissionsExt;
        let (_d, store) = fresh_store();
        let blob = put_blob(&store, b"data");
        let tree = put_tree_with(
            &store,
            vec![
                TreeEntry {
                    name: b"plain".to_vec(),
                    mode: EntryMode::Blob,
                    object_hash: blob,
                },
                TreeEntry {
                    name: b"run".to_vec(),
                    mode: EntryMode::Executable,
                    object_hash: blob,
                },
            ],
        );
        let sequential = TempDir::new().unwrap();
        restore_tree(&store, tree, sequential.path(), &RestoreOptions::default()).unwrap();
        let worktree = TempDir::new().unwrap();
        restore_tree_to_worktree(&store, &tree, worktree.path(), &RestoreOptions::default())
            .unwrap();
        for target in [&sequential, &worktree] {
            let mode = |name: &str| {
                fs::metadata(target.path().join(name))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777
            };
            assert_eq!(mode("run"), 0o755);
            assert_eq!(mode("plain") & 0o111, 0);
        }
    }

    /// Names a restore could pick for its next temporary files, planted
    /// before the restore runs. `make` creates one.
    fn plant_temp_names(dir: &Path, make: impl Fn(&Path)) -> Vec<PathBuf> {
        let start = TMP_COUNTER.load(Ordering::Relaxed);
        (start..start + 1000)
            .map(|n| {
                let path = dir.join(format!("{TMP_PREFIX}.{}.{n}", process::id()));
                make(&path);
                path
            })
            .collect()
    }

    #[test]
    fn restore_never_removes_a_file_at_a_temporary_name() {
        let (_d, store) = fresh_store();
        let keep_untracked = RestoreOptions {
            clean: false,
            sparse_patterns: None,
        };
        let mut trees = vec![tree_of_one_file(&store, b"a", b"restored")];
        #[cfg(unix)]
        trees.push(put_tree_with(
            &store,
            vec![TreeEntry {
                name: b"a".to_vec(),
                mode: EntryMode::Symlink,
                object_hash: put_blob(&store, b"restored"),
            }],
        ));
        // Each restore step meets every planted name before it finds a free one.
        for tree in trees {
            for worktree in [false, true] {
                let target = TempDir::new().unwrap();
                let planted = plant_temp_names(target.path(), |path| {
                    fs::write(path, b"keep").unwrap();
                });
                if worktree {
                    restore_tree_to_worktree(&store, &tree, target.path(), &keep_untracked)
                        .unwrap();
                } else {
                    restore_tree(&store, tree, target.path(), &keep_untracked).unwrap();
                }
                assert!(fs::symlink_metadata(target.path().join("a")).is_ok());
                for path in planted {
                    assert_eq!(fs::read(&path).unwrap(), b"keep", "{}", path.display());
                }
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn restore_never_writes_through_a_symlink_at_a_temporary_name() {
        let (_d, store) = fresh_store();
        let keep_untracked = RestoreOptions {
            clean: false,
            sparse_patterns: None,
        };
        let tree = tree_of_one_file(&store, b"a", b"restored");
        let target = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let victim = outside.path().join("victim");
        fs::write(&victim, b"untouched").unwrap();
        let planted = plant_temp_names(target.path(), |path| {
            std::os::unix::fs::symlink(&victim, path).unwrap();
        });
        restore_tree(&store, tree, target.path(), &keep_untracked).unwrap();
        assert_eq!(fs::read(target.path().join("a")).unwrap(), b"restored");
        assert_eq!(fs::read(&victim).unwrap(), b"untouched");
        for path in planted {
            assert_eq!(fs::read_link(&path).unwrap(), victim);
        }
    }

    #[test]
    fn restore_writes_a_file_with_a_maximum_length_name() {
        let (_d, store) = fresh_store();
        let name = "n".repeat(255);
        let tree = tree_of_one_file(&store, name.as_bytes(), b"data");
        let sequential = TempDir::new().unwrap();
        restore_tree(&store, tree, sequential.path(), &RestoreOptions::default()).unwrap();
        let worktree = TempDir::new().unwrap();
        restore_tree_to_worktree(&store, &tree, worktree.path(), &RestoreOptions::default())
            .unwrap();
        for target in [&sequential, &worktree] {
            assert_eq!(fs::read(target.path().join(&name)).unwrap(), b"data");
            assert_eq!(fs::read_dir(target.path()).unwrap().count(), 1);
        }
    }

    #[cfg(unix)]
    #[test]
    fn restore_io_error_names_the_file() {
        use std::os::unix::fs::PermissionsExt;
        let (_d, store) = fresh_store();
        let link = put_blob(&store, b"target");
        let inners = [
            (
                "dir/file.txt",
                tree_of_one_file(&store, b"file.txt", b"data"),
            ),
            (
                "dir/link",
                put_tree_with(
                    &store,
                    vec![TreeEntry {
                        name: b"link".to_vec(),
                        mode: EntryMode::Symlink,
                        object_hash: link,
                    }],
                ),
            ),
        ];
        for (expected, inner) in inners {
            let outer = put_tree_with(
                &store,
                vec![TreeEntry {
                    name: b"dir".to_vec(),
                    mode: EntryMode::Tree,
                    object_hash: inner,
                }],
            );
            for worktree in [false, true] {
                let target = TempDir::new().unwrap();
                let dir = target.path().join("dir");
                fs::create_dir(&dir).unwrap();
                fs::set_permissions(&dir, fs::Permissions::from_mode(0o555)).unwrap();
                if fs::File::create(dir.join("probe")).is_ok() {
                    // Permissions do not apply, for example when running as root.
                    return;
                }
                let err = if worktree {
                    let options = RestoreOptions::default();
                    restore_tree_to_worktree(&store, &outer, target.path(), &options).unwrap_err()
                } else {
                    let options = RestoreOptions::default();
                    restore_tree(&store, outer, target.path(), &options).unwrap_err()
                };
                fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
                assert!(
                    matches!(&err, RestoreError::File { path, .. } if path == expected),
                    "{err:?}"
                );
                assert!(
                    err.to_string().starts_with(&format!("{expected}: ")),
                    "{err}"
                );
            }
        }
    }

    /// A target directory in which a restore of the entry `x` fails after
    /// it wrote its temporary file: `x` is a directory that holds a file in
    /// a read-only subdirectory, so the restore cannot remove it to make
    /// room. Also holds `victim`, a sibling file the restore must not touch.
    #[cfg(unix)]
    struct LockedTarget {
        root: TempDir,
    }

    #[cfg(unix)]
    impl LockedTarget {
        /// `None` when permissions do not apply, for example when running as root.
        fn new() -> Option<Self> {
            use std::os::unix::fs::PermissionsExt;
            let root = TempDir::new().unwrap();
            let sub = root.path().join("x/sub");
            fs::create_dir_all(&sub).unwrap();
            fs::write(sub.join("f"), b"keep").unwrap();
            fs::write(root.path().join("victim"), b"untouched").unwrap();
            fs::set_permissions(&sub, fs::Permissions::from_mode(0o555)).unwrap();
            let locked = Self { root };
            fs::File::create(sub.join("probe"))
                .is_err()
                .then_some(locked)
        }

        fn path(&self) -> &Path {
            self.root.path()
        }

        fn assert_untouched(&self) {
            assert_eq!(fs::read(self.path().join("x/sub/f")).unwrap(), b"keep");
            assert_eq!(fs::read(self.path().join("victim")).unwrap(), b"untouched");
        }
    }

    #[cfg(unix)]
    impl Drop for LockedTarget {
        fn drop(&mut self) {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(
                self.root.path().join("x/sub"),
                fs::Permissions::from_mode(0o755),
            );
        }
    }

    /// Entries a restore writes through a temporary file: the mode and the
    /// object of each, named for the failure message.
    #[cfg(unix)]
    fn temporary_file_entries(store: &ObjectStore) -> Vec<(&'static str, EntryMode, Hash)> {
        let plain = put_blob(store, b"data");
        let chunks = vec![put_blob(store, b"da"), put_blob(store, b"ta")];
        let chunked = Object::ChunkedBlob(crate::object::ChunkedBlob {
            total_size: 4,
            chunk_size: 2,
            chunks,
        });
        let chunked = store
            .write(&serialize::serialize(&chunked).unwrap())
            .unwrap();
        vec![
            ("plain", EntryMode::Blob, plain),
            ("executable", EntryMode::Executable, plain),
            ("chunked", EntryMode::Blob, chunked),
            ("chunked executable", EntryMode::Executable, chunked),
            ("symlink", EntryMode::Symlink, put_blob(store, b"victim")),
        ]
    }

    /// Restore the one entry `x` into `target` and return the error.
    #[cfg(unix)]
    fn failed_restore_of_x(
        store: &ObjectStore,
        mode: EntryMode,
        object_hash: Hash,
        target: &Path,
        worktree: bool,
    ) -> RestoreError {
        let tree = put_tree_with(
            store,
            vec![TreeEntry {
                name: b"x".to_vec(),
                mode,
                object_hash,
            }],
        );
        let keep_untracked = RestoreOptions {
            clean: false,
            sparse_patterns: None,
        };
        if worktree {
            restore_tree_to_worktree(store, &tree, target, &keep_untracked).unwrap_err()
        } else {
            restore_tree(store, tree, target, &keep_untracked).unwrap_err()
        }
    }

    /// Names in `dir` with the shape of a restore temporary name.
    #[cfg(unix)]
    fn temp_shaped_names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .filter(|name| is_restore_temp_name(name))
            .collect();
        names.sort();
        names
    }

    #[cfg(unix)]
    #[test]
    fn a_failed_restore_removes_its_temporary_file() {
        let (_d, store) = fresh_store();
        for (label, mode, object_hash) in temporary_file_entries(&store) {
            for worktree in [false, true] {
                let Some(target) = LockedTarget::new() else {
                    return;
                };
                let err = failed_restore_of_x(&store, mode, object_hash, target.path(), worktree);
                assert!(
                    matches!(&err, RestoreError::File { path, .. } if path == "x"),
                    "{label}: {err:?}"
                );
                assert!(err.to_string().starts_with("x: "), "{label}: {err}");
                assert_eq!(
                    temp_shaped_names(target.path()),
                    Vec::<String>::new(),
                    "{label}, worktree {worktree}"
                );
                target.assert_untouched();
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_failed_restore_keeps_temporary_names_it_did_not_create() {
        let (_d, store) = fresh_store();
        let entries = temporary_file_entries(&store);
        let outside = TempDir::new().unwrap();
        let outside_victim = outside.path().join("victim");
        fs::write(&outside_victim, b"untouched").unwrap();
        for label in ["plain", "symlink"] {
            let (_, mode, object_hash) = *entries.iter().find(|e| e.0 == label).unwrap();
            for planted_symlinks in [false, true] {
                let Some(target) = LockedTarget::new() else {
                    return;
                };
                let planted = plant_temp_names(target.path(), |path| {
                    if planted_symlinks {
                        std::os::unix::fs::symlink(&outside_victim, path).unwrap();
                    } else {
                        fs::write(path, b"keep").unwrap();
                    }
                });
                let err = failed_restore_of_x(&store, mode, object_hash, target.path(), false);
                assert!(
                    matches!(&err, RestoreError::File { path, .. } if path == "x"),
                    "{label}: {err:?}"
                );
                let mut expected: Vec<String> = planted
                    .iter()
                    .map(|path| path.file_name().unwrap().to_str().unwrap().to_string())
                    .collect();
                expected.sort();
                assert_eq!(
                    temp_shaped_names(target.path()),
                    expected,
                    "{label}, planted symlinks {planted_symlinks}"
                );
                for path in planted {
                    if planted_symlinks {
                        assert_eq!(fs::read_link(&path).unwrap(), outside_victim);
                    } else {
                        assert_eq!(fs::read(&path).unwrap(), b"keep");
                    }
                }
                assert_eq!(fs::read(&outside_victim).unwrap(), b"untouched");
                target.assert_untouched();
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_failed_removal_does_not_replace_the_restore_error() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let tmp_path = dir.path().join(".kit-restore-tmp.1.2");
        fs::write(&tmp_path, b"partial").unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o555)).unwrap();
        let can_remove = fs::File::create(dir.path().join("probe")).is_ok();
        let err = finish_or_discard_tmp(
            Err(RestoreError::NotABlob),
            &tmp_path,
            &dir.path().join("final"),
            false,
        )
        .unwrap_err();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
        if can_remove {
            // Permissions do not apply, for example when running as root.
            return;
        }
        assert!(matches!(err, RestoreError::NotABlob), "{err:?}");
        assert!(tmp_path.exists());
    }

    #[test]
    fn parse_sparse_basic() {
        let content = "# comment line\nsrc\n!tests\ndocs/\n\nREADME.md\n";
        let p = parse_sparse_patterns(content);
        assert_eq!(p.len(), 4);
        assert_eq!(p[0].pattern, "src");
        assert!(!p[0].negated);
        assert!(!p[0].dir_only);
        assert_eq!(p[1].pattern, "tests");
        assert!(p[1].negated);
        assert_eq!(p[2].pattern, "docs");
        assert!(p[2].dir_only);
        assert_eq!(p[3].pattern, "README.md");
    }

    #[test]
    fn matches_sparse_exact_and_prefix() {
        let p = vec![SparsePattern {
            pattern: "src".to_string(),
            negated: false,
            dir_only: false,
        }];
        assert!(matches_sparse(&p, "src/main.rs", false));
        assert!(matches_sparse(&p, "src/lib/util.rs", false));
        assert!(!matches_sparse(&p, "tests/foo", false));
    }

    #[test]
    fn matches_sparse_negation() {
        let p = vec![
            SparsePattern {
                pattern: "src".to_string(),
                negated: false,
                dir_only: false,
            },
            SparsePattern {
                pattern: "src/secret".to_string(),
                negated: true,
                dir_only: false,
            },
        ];
        assert!(matches_sparse(&p, "src/main.rs", false));
        assert!(!matches_sparse(&p, "src/secret/key.pem", false));
    }

    #[test]
    fn matches_sparse_dir_only() {
        let p = vec![SparsePattern {
            pattern: "build".to_string(),
            negated: false,
            dir_only: true,
        }];
        assert!(matches_sparse(&p, "build", true));
        assert!(!matches_sparse(&p, "build", false));
    }

    #[test]
    fn matches_sparse_last_match_wins() {
        let p = vec![
            SparsePattern {
                pattern: "src".to_string(),
                negated: false,
                dir_only: false,
            },
            SparsePattern {
                pattern: "src".to_string(),
                negated: true,
                dir_only: false,
            },
        ];
        assert!(!matches_sparse(&p, "src/main.rs", false));
    }

    #[test]
    fn matches_sparse_bare_basename() {
        let p = vec![SparsePattern {
            pattern: "Makefile".to_string(),
            negated: false,
            dir_only: false,
        }];
        assert!(matches_sparse(&p, "Makefile", false));
        assert!(matches_sparse(&p, "sub/Makefile", false));
        assert!(!matches_sparse(&p, "Makefile.bak", false));
    }

    #[test]
    fn could_match_descendant_basic() {
        let p = vec![SparsePattern {
            pattern: "src/lib".to_string(),
            negated: false,
            dir_only: false,
        }];
        assert!(could_match_descendant(&p, "src"));
        assert!(could_match_descendant(&p, "src/lib"));
        assert!(!could_match_descendant(&p, "tests"));
    }

    #[test]
    fn restore_empty_tree_creates_no_files() {
        let (_d, store) = fresh_store();
        let target = TempDir::new().unwrap();
        let tree_h = put_tree_with(&store, vec![]);
        restore_tree(&store, tree_h, target.path(), &RestoreOptions::default()).unwrap();
        let count = fs::read_dir(target.path()).unwrap().count();
        assert_eq!(count, 0);
    }

    #[test]
    fn restore_single_file() {
        let (_d, store) = fresh_store();
        let target = TempDir::new().unwrap();
        let blob = put_blob(&store, b"hello");
        let tree = put_tree_with(
            &store,
            vec![TreeEntry {
                name: b"file.txt".to_vec(),
                mode: EntryMode::Blob,
                object_hash: blob,
            }],
        );
        restore_tree(&store, tree, target.path(), &RestoreOptions::default()).unwrap();
        let content = fs::read(target.path().join("file.txt")).unwrap();
        assert_eq!(content, b"hello");
    }

    #[test]
    fn restore_nested_directories() {
        let (_d, store) = fresh_store();
        let target = TempDir::new().unwrap();
        let blob = put_blob(&store, b"const main = 0;");
        let inner = put_tree_with(
            &store,
            vec![TreeEntry {
                name: b"main.rs".to_vec(),
                mode: EntryMode::Blob,
                object_hash: blob,
            }],
        );
        let root = put_tree_with(
            &store,
            vec![TreeEntry {
                name: b"src".to_vec(),
                mode: EntryMode::Tree,
                object_hash: inner,
            }],
        );
        restore_tree(&store, root, target.path(), &RestoreOptions::default()).unwrap();
        let content = fs::read(target.path().join("src/main.rs")).unwrap();
        assert_eq!(content, b"const main = 0;");
    }

    #[test]
    fn restore_overwrites_existing_files() {
        let (_d, store) = fresh_store();
        let target = TempDir::new().unwrap();
        fs::write(target.path().join("file.txt"), b"old").unwrap();
        let blob = put_blob(&store, b"new");
        let tree = put_tree_with(
            &store,
            vec![TreeEntry {
                name: b"file.txt".to_vec(),
                mode: EntryMode::Blob,
                object_hash: blob,
            }],
        );
        restore_tree(&store, tree, target.path(), &RestoreOptions::default()).unwrap();
        assert_eq!(fs::read(target.path().join("file.txt")).unwrap(), b"new");
    }

    #[test]
    fn incremental_restore_skips_unchanged_and_writes_changed() {
        let (_d, store) = fresh_store();
        let target = TempDir::new().unwrap();
        let entry = |n: &str, h| TreeEntry {
            name: n.as_bytes().to_vec(),
            mode: EntryMode::Blob,
            object_hash: h,
        };
        let (same, a1, a2) = (
            put_blob(&store, b"same"),
            put_blob(&store, b"a-old"),
            put_blob(&store, b"a-new"),
        );
        let sub1 = put_tree_with(&store, vec![entry("x", same), entry("y", a1)]);
        let sub2 = put_tree_with(&store, vec![entry("x", same), entry("y", a2)]);
        let mk = |sub, a| {
            put_tree_with(
                &store,
                vec![
                    entry("a", a),
                    TreeEntry {
                        name: b"d".to_vec(),
                        mode: EntryMode::Tree,
                        object_hash: sub,
                    },
                    entry("same", same),
                ],
            )
        };
        let (base, next) = (mk(sub1, a1), mk(sub2, a2));
        let opts = RestoreOptions {
            clean: false,
            sparse_patterns: None,
        };
        let rd = |s: &ObjectStore, h: &[Hash]| sequential_read_chunks(s, h);
        restore_tree_to_worktree_with(&store, &base, None, target.path(), &opts, &rd).unwrap();
        // Tamper with unchanged files: an incremental restore must leave
        // them alone, a full one would overwrite them.
        fs::write(target.path().join("same"), b"sentinel").unwrap();
        fs::write(target.path().join("d/x"), b"sentinel").unwrap();
        let report =
            restore_tree_to_worktree_with(&store, &next, Some(base), target.path(), &opts, &rd)
                .unwrap();
        assert_eq!(report.files_written, 2);
        assert_eq!(fs::read(target.path().join("a")).unwrap(), b"a-new");
        assert_eq!(fs::read(target.path().join("d/y")).unwrap(), b"a-new");
        assert_eq!(fs::read(target.path().join("same")).unwrap(), b"sentinel");
        assert_eq!(fs::read(target.path().join("d/x")).unwrap(), b"sentinel");
        // No base => full restore.
        restore_tree_to_worktree_with(&store, &next, None, target.path(), &opts, &rd).unwrap();
        assert_eq!(fs::read(target.path().join("same")).unwrap(), b"same");
    }

    /// With `clean`, an incremental restore still rewrites what changed and
    /// sweeps what the tip dropped, and leaves an unchanged subtree alone.
    #[test]
    fn incremental_restore_with_clean_skips_unchanged_and_sweeps_dropped() {
        let (_d, store) = fresh_store();
        let target = TempDir::new().unwrap();
        let entry = |n: &str, h| TreeEntry {
            name: n.as_bytes().to_vec(),
            mode: EntryMode::Blob,
            object_hash: h,
        };
        let dir = |n: &str, h| TreeEntry {
            name: n.as_bytes().to_vec(),
            mode: EntryMode::Tree,
            object_hash: h,
        };
        let same = put_blob(&store, b"same");
        let (a1, a2) = (put_blob(&store, b"a-old"), put_blob(&store, b"a-new"));
        let gone = put_blob(&store, b"gone");
        let kept = put_tree_with(&store, vec![entry("x", same)]);
        let doomed = put_tree_with(&store, vec![entry("y", gone)]);
        let base = put_tree_with(
            &store,
            vec![
                entry("a", a1),
                dir("doomed", doomed),
                entry("gone", gone),
                dir("kept", kept),
            ],
        );
        let next = put_tree_with(&store, vec![entry("a", a2), dir("kept", kept)]);
        let opts = RestoreOptions::default();
        assert!(opts.clean);
        let rd = |s: &ObjectStore, h: &[Hash]| sequential_read_chunks(s, h);
        restore_tree_to_worktree_with(&store, &base, None, target.path(), &opts, &rd).unwrap();
        fs::write(target.path().join("kept/x"), b"sentinel").unwrap();

        let report =
            restore_tree_to_worktree_with(&store, &next, Some(base), target.path(), &opts, &rd)
                .unwrap();

        assert_eq!(report.files_written, 1);
        assert_eq!(fs::read(target.path().join("a")).unwrap(), b"a-new");
        assert_eq!(fs::read(target.path().join("kept/x")).unwrap(), b"sentinel");
        assert!(!target.path().join("gone").exists());
        assert!(!target.path().join("doomed").exists());
    }

    /// Without `observe`, a restored file reports no stat fields, chunked
    /// or not. With it, the same restore proves them.
    #[test]
    fn an_unobserved_restore_reports_no_stat_fields() {
        let (_d, store) = fresh_store();
        let target = TempDir::new().unwrap();
        let cb = Object::ChunkedBlob(crate::object::ChunkedBlob {
            total_size: 8,
            chunk_size: 0,
            chunks: vec![put_blob(&store, b"big-"), put_blob(&store, b"file")],
        });
        let big = store.write(&serialize::serialize(&cb).unwrap()).unwrap();
        let plain = put_blob(&store, b"plain");
        let rd = |s: &ObjectStore, h: &[Hash]| sequential_read_chunks(s, h);
        for (name, hash) in [("big", big), ("plain", plain)] {
            let off =
                restore_blob_with(&store, target.path(), name, hash, false, 1, &rd, false).unwrap();
            assert_eq!(off, None, "{name} without observe");
            let on =
                restore_blob_with(&store, target.path(), name, hash, false, 1, &rd, true).unwrap();
            assert!(on.is_some(), "{name} with observe");
        }
    }

    /// Every file an observed restore writes gets an observation that
    /// stat-matches the file on disk, chunked and executable files
    /// included. Entries an incremental restore skips get none.
    #[test]
    fn observed_restore_records_stat_matching_observations() {
        use crate::index::{EntryStatus, IndexEntry};
        let (_d, store) = fresh_store();
        let target = TempDir::new().unwrap();
        let entry = |n: &str, mode, h| TreeEntry {
            name: n.as_bytes().to_vec(),
            mode,
            object_hash: h,
        };
        let (same, a1, a2, run) = (
            put_blob(&store, b"same"),
            put_blob(&store, b"a-old"),
            put_blob(&store, b"a-new"),
            put_blob(&store, b"#!/bin/sh\n"),
        );
        let cb = Object::ChunkedBlob(crate::object::ChunkedBlob {
            total_size: 8,
            chunk_size: 0,
            chunks: vec![put_blob(&store, b"big-"), put_blob(&store, b"file")],
        });
        let big = store.write(&serialize::serialize(&cb).unwrap()).unwrap();
        let sub = put_tree_with(&store, vec![entry("big", EntryMode::Blob, big)]);
        let mk = |a| {
            put_tree_with(
                &store,
                vec![
                    entry("a", EntryMode::Blob, a),
                    entry("d", EntryMode::Tree, sub),
                    entry("run", EntryMode::Executable, run),
                    entry("same", EntryMode::Blob, same),
                ],
            )
        };
        let (base, next) = (mk(a1), mk(a2));
        let opts = RestoreOptions {
            clean: false,
            sparse_patterns: None,
        };
        let rd = |s: &ObjectStore, h: &[Hash]| sequential_read_chunks(s, h);
        let check = |observed: &[worktree::StatObservation], want: &[(&str, Hash)]| {
            let got: Vec<(&str, Hash)> = observed
                .iter()
                .map(|o| (o.path.as_str(), o.object_hash))
                .collect();
            assert_eq!(got, want);
            for o in observed {
                let status = if o.path == "run" {
                    EntryStatus::Executable
                } else {
                    EntryStatus::Blob
                };
                let ie = IndexEntry {
                    path: o.path.clone(),
                    status,
                    object_hash: o.object_hash,
                    mtime_ns: o.mtime_ns,
                    size: o.size,
                    ino: o.ino,
                    ctime_ns: o.ctime_ns,
                };
                let meta = fs::symlink_metadata(target.path().join(&o.path)).unwrap();
                assert!(worktree::stat_matches(&ie, &meta), "{}", o.path);
            }
        };

        let mut observed = Vec::new();
        restore_tree_to_worktree_observed(
            &store,
            &base,
            None,
            target.path(),
            &opts,
            &rd,
            Some(&mut observed),
        )
        .unwrap();
        check(
            &observed,
            &[("a", a1), ("d/big", big), ("run", run), ("same", same)],
        );
        assert_eq!(fs::read(target.path().join("d/big")).unwrap(), b"big-file");

        let mut observed = Vec::new();
        restore_tree_to_worktree_observed(
            &store,
            &next,
            Some(base),
            target.path(),
            &opts,
            &rd,
            Some(&mut observed),
        )
        .unwrap();
        check(&observed, &[("a", a2)]);
    }

    /// An observation is refused when the final path no longer holds the
    /// file the handle wrote: another inode renamed over it, or a write
    /// that changed its size.
    #[test]
    fn observe_written_refuses_a_replaced_or_changed_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("f");
        let mut file = fs::File::create(&path).unwrap();
        file.write_all(b"restored").unwrap();
        let written = file.metadata().unwrap();
        drop(file);
        assert!(observe_written(&written, &path).is_some());

        fs::write(dir.path().join("g"), b"restored").unwrap();
        fs::rename(dir.path().join("g"), &path).unwrap();
        #[cfg(unix)]
        assert!(observe_written(&written, &path).is_none());

        let mut file = fs::File::create(&path).unwrap();
        file.write_all(b"restored").unwrap();
        let written = file.metadata().unwrap();
        file.write_all(b" and edited").unwrap();
        drop(file);
        assert!(observe_written(&written, &path).is_none());
        fs::remove_file(&path).unwrap();
        assert!(observe_written(&written, &path).is_none());
    }

    #[test]
    fn restore_removes_untracked_when_clean() {
        let (_d, store) = fresh_store();
        let target = TempDir::new().unwrap();
        fs::write(target.path().join("extra.txt"), b"gone").unwrap();
        let blob = put_blob(&store, b"keep");
        let tree = put_tree_with(
            &store,
            vec![TreeEntry {
                name: b"tracked.txt".to_vec(),
                mode: EntryMode::Blob,
                object_hash: blob,
            }],
        );
        restore_tree(&store, tree, target.path(), &RestoreOptions::default()).unwrap();
        assert!(!target.path().join("extra.txt").exists());
        assert_eq!(
            fs::read(target.path().join("tracked.txt")).unwrap(),
            b"keep"
        );
    }

    #[test]
    fn restore_clean_false_keeps_untracked() {
        let (_d, store) = fresh_store();
        let target = TempDir::new().unwrap();
        fs::write(target.path().join("extra.txt"), b"survive").unwrap();
        let blob = put_blob(&store, b"keep");
        let tree = put_tree_with(
            &store,
            vec![TreeEntry {
                name: b"tracked.txt".to_vec(),
                mode: EntryMode::Blob,
                object_hash: blob,
            }],
        );
        restore_tree(
            &store,
            tree,
            target.path(),
            &RestoreOptions {
                clean: false,
                sparse_patterns: None,
            },
        )
        .unwrap();
        assert_eq!(
            fs::read(target.path().join("extra.txt")).unwrap(),
            b"survive"
        );
    }

    #[test]
    fn restore_preserves_kit_directory() {
        let (_d, store) = fresh_store();
        let target = TempDir::new().unwrap();
        fs::create_dir_all(target.path().join(".kit")).unwrap();
        fs::write(target.path().join(".kit/config"), b"important").unwrap();
        let tree = put_tree_with(&store, vec![]);
        restore_tree(&store, tree, target.path(), &RestoreOptions::default()).unwrap();
        assert_eq!(
            fs::read(target.path().join(".kit/config")).unwrap(),
            b"important"
        );
    }

    #[test]
    fn clean_directory_preserves_case_variant_kit_and_git() {
        // Regression for Git CVE-2021-21300 family: on case-insensitive
        // filesystems a worktree directory named `.KIT` or `.Git` must
        // never be swept by `clean_directory`, otherwise a hostile tree
        // entry could trick restore into deleting repo metadata.
        let target = TempDir::new().unwrap();
        fs::create_dir_all(target.path().join(".KIT")).unwrap();
        fs::write(target.path().join(".KIT/config"), b"meta").unwrap();
        fs::create_dir_all(target.path().join(".Git")).unwrap();
        fs::write(target.path().join(".Git/HEAD"), b"ref").unwrap();
        // Empty tree — without the case-insensitive guard, everything
        // unknown is removed.
        clean_directory(target.path(), &[], None, "", None).unwrap();
        assert!(
            target.path().join(".KIT/config").exists(),
            ".KIT swept by clean_directory (case-fold bypass)"
        );
        assert!(
            target.path().join(".Git/HEAD").exists(),
            ".Git swept by clean_directory (case-fold bypass)"
        );
    }

    #[test]
    fn clean_directory_with_ignore_list_preserves_case_variant_kit_and_git() {
        let target = TempDir::new().unwrap();
        fs::create_dir_all(target.path().join(".KIT")).unwrap();
        fs::write(target.path().join(".KIT/config"), b"meta").unwrap();
        fs::create_dir_all(target.path().join(".GIT")).unwrap();
        fs::write(target.path().join(".GIT/HEAD"), b"ref").unwrap();
        let ignore = crate::ignore::IgnoreList::new();
        clean_directory(target.path(), &[], None, "", Some(&ignore)).unwrap();
        assert!(
            target.path().join(".KIT/config").exists(),
            ".KIT swept by clean_directory (ignore-aware, case-fold bypass)"
        );
        assert!(
            target.path().join(".GIT/HEAD").exists(),
            ".GIT swept by clean_directory (ignore-aware, case-fold bypass)"
        );
    }

    #[test]
    fn restore_chunked_blob_reassembled() {
        let (_d, store) = fresh_store();
        let target = TempDir::new().unwrap();
        let c0 = put_blob(&store, b"Hello, ");
        let c1 = put_blob(&store, b"chunked ");
        let c2 = put_blob(&store, b"world!");
        let cb = Object::ChunkedBlob(crate::object::ChunkedBlob {
            total_size: 7 + 8 + 6,
            chunk_size: 8,
            chunks: vec![c0, c1, c2],
        });
        let cb_h = store.write(&serialize::serialize(&cb).unwrap()).unwrap();
        let tree = put_tree_with(
            &store,
            vec![TreeEntry {
                name: b"out.txt".to_vec(),
                mode: EntryMode::Blob,
                object_hash: cb_h,
            }],
        );
        restore_tree(&store, tree, target.path(), &RestoreOptions::default()).unwrap();
        let content = fs::read(target.path().join("out.txt")).unwrap();
        assert_eq!(content, b"Hello, chunked world!");
    }

    /// Mirrors `worktree`'s
    /// `streaming_rejects_miscounted_hashes_in_full_and_partial_batches`
    /// on the read side: a `read_chunks` callback that returns fewer
    /// buffers than its input batch must surface as
    /// [`RestoreError::ChunkBatchLengthMismatch`], not a panic or a
    /// silently short/garbled restored file.
    #[test]
    fn restore_tree_to_worktree_with_rejects_miscounted_chunks() {
        let (_d, store) = fresh_store();
        let target = TempDir::new().unwrap();
        let c0 = put_blob(&store, b"Hello, ");
        let c1 = put_blob(&store, b"chunked ");
        let c2 = put_blob(&store, b"world!");
        let cb = Object::ChunkedBlob(crate::object::ChunkedBlob {
            total_size: 7 + 8 + 6,
            chunk_size: 0,
            chunks: vec![c0, c1, c2],
        });
        let cb_h = store.write(&serialize::serialize(&cb).unwrap()).unwrap();
        let tree = put_tree_with(
            &store,
            vec![TreeEntry {
                name: b"out.txt".to_vec(),
                mode: EntryMode::Blob,
                object_hash: cb_h,
            }],
        );
        let err = restore_tree_to_worktree_with(
            &store,
            &tree,
            None,
            target.path(),
            &RestoreOptions::default(),
            &|_store, batch| Ok(vec![Vec::new(); batch.len() - 1]),
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                RestoreError::ChunkBatchLengthMismatch {
                    expected: 3,
                    actual: 2
                }
            ),
            "unexpected error: {err:?}"
        );
    }

    /// Mirrors `worktree`'s
    /// `hash_file_with_metadata_with_batch_fanout_matches_sequential`: a
    /// `read_chunks` callback that processes a batch out of order
    /// internally (simulating a rayon fan-out) but returns results in
    /// input order — the documented contract — must still reassemble the
    /// exact same bytes as the sequential default. Pins the `_with`
    /// contract `kit-bin`'s `restore_fanout::read_chunks_fanout` relies
    /// on.
    #[test]
    fn restore_tree_to_worktree_with_out_of_order_processing_matches_sequential() {
        let (_d, store) = fresh_store();
        let chunk_data: Vec<Vec<u8>> = (0..10)
            .map(|i| format!("chunk-{i:02}-").into_bytes())
            .collect();
        let total_size: u64 = chunk_data.iter().map(|c| c.len() as u64).sum();
        let chunks: Vec<Hash> = chunk_data.iter().map(|c| put_blob(&store, c)).collect();
        let cb = Object::ChunkedBlob(crate::object::ChunkedBlob {
            total_size,
            chunk_size: 0,
            chunks: chunks.clone(),
        });
        let cb_h = store.write(&serialize::serialize(&cb).unwrap()).unwrap();
        let tree = put_tree_with(
            &store,
            vec![TreeEntry {
                name: b"out.txt".to_vec(),
                mode: EntryMode::Blob,
                object_hash: cb_h,
            }],
        );

        let sequential_target = TempDir::new().unwrap();
        restore_tree_to_worktree(
            &store,
            &tree,
            sequential_target.path(),
            &RestoreOptions::default(),
        )
        .unwrap();
        let sequential_content = fs::read(sequential_target.path().join("out.txt")).unwrap();

        let fanout_target = TempDir::new().unwrap();
        restore_tree_to_worktree_with(
            &store,
            &tree,
            None,
            fanout_target.path(),
            &RestoreOptions::default(),
            &|store, batch| {
                // Read in reverse, then un-reverse before returning —
                // proves the contract cares about the *returned* order,
                // not the order chunks are actually processed in.
                let mut out: Vec<Vec<u8>> = batch
                    .iter()
                    .rev()
                    .map(|h| read_chunk_bytes(store, h))
                    .collect::<RestoreResult<_>>()?;
                out.reverse();
                Ok(out)
            },
        )
        .unwrap();
        let fanout_content = fs::read(fanout_target.path().join("out.txt")).unwrap();

        assert_eq!(
            sequential_content, fanout_content,
            "an out-of-order-processing read_chunks callback must still match \
             the sequential default when it returns results in input order"
        );
    }

    /// SPEC-OBJECTS §7: "The concatenated length MUST equal `total_size`."
    /// A manifest whose forged `total_size` disagrees with its (valid)
    /// chunks must fail restore instead of writing wrong-length content.
    #[test]
    fn restore_rejects_chunked_total_size_mismatch() {
        let (_d, store) = fresh_store();
        let target = TempDir::new().unwrap();
        let c0 = put_blob(&store, b"Hello, ");
        let c1 = put_blob(&store, b"world!");
        let cb = Object::ChunkedBlob(crate::object::ChunkedBlob {
            total_size: 7 + 6 + 1,
            chunk_size: 0,
            chunks: vec![c0, c1],
        });
        let cb_h = store.write(&serialize::serialize(&cb).unwrap()).unwrap();
        let tree = put_tree_with(
            &store,
            vec![TreeEntry {
                name: b"out.txt".to_vec(),
                mode: EntryMode::Blob,
                object_hash: cb_h,
            }],
        );
        let err =
            restore_tree(&store, tree, target.path(), &RestoreOptions::default()).unwrap_err();
        assert!(
            matches!(
                err,
                RestoreError::Object(object::KitError::ChunkedBlobSizeMismatch {
                    expected: 14,
                    actual: 13,
                })
            ),
            "expected ChunkedBlobSizeMismatch, got {err:?}"
        );
        assert!(!target.path().join("out.txt").exists());
    }

    /// Chunks that total more than the manifest's `total_size` must fail
    /// restore without leaving a temp file in the target directory.
    #[test]
    fn restore_rejects_chunked_overrun_and_leaves_no_tmp_file() {
        let (_d, store) = fresh_store();
        let target = TempDir::new().unwrap();
        let big = put_blob(&store, &[7u8; 64]);
        let cb = Object::ChunkedBlob(crate::object::ChunkedBlob {
            total_size: 10,
            chunk_size: 10,
            chunks: vec![big],
        });
        let cb_h = store.write(&serialize::serialize(&cb).unwrap()).unwrap();
        let tree = put_tree_with(
            &store,
            vec![TreeEntry {
                name: b"out.bin".to_vec(),
                mode: EntryMode::Blob,
                object_hash: cb_h,
            }],
        );
        let err =
            restore_tree(&store, tree, target.path(), &RestoreOptions::default()).unwrap_err();
        assert!(
            matches!(
                err,
                RestoreError::Object(object::KitError::ChunkedBlobSizeMismatch { .. })
            ),
            "got {err:?}"
        );
        assert_eq!(fs::read_dir(target.path()).unwrap().count(), 0);
    }

    /// The worktree restore path reports an overrun with the length the
    /// write would have reached, not a placeholder, and removes its temp file.
    /// The sequential and threaded writers must agree.
    #[test]
    fn worktree_restore_overrun_error_reports_the_length_it_would_reach() {
        for chunk_count in [1usize, 2 * RESTORE_CHUNK_BATCH + 1] {
            let declared = chunk_count as u64 + 9;
            let (_d, store) = fresh_store();
            let target = TempDir::new().unwrap();
            let big = put_blob(&store, &[7u8; 64]);
            let cb = Object::ChunkedBlob(crate::object::ChunkedBlob {
                total_size: declared,
                chunk_size: 0,
                chunks: vec![big; chunk_count],
            });
            let cb_h = store.write(&serialize::serialize(&cb).unwrap()).unwrap();
            let tree = put_tree_with(
                &store,
                vec![TreeEntry {
                    name: b"out.bin".to_vec(),
                    mode: EntryMode::Blob,
                    object_hash: cb_h,
                }],
            );
            let err = restore_tree_to_worktree_with(
                &store,
                &tree,
                None,
                target.path(),
                &RestoreOptions::default(),
                &sequential_read_chunks,
            )
            .unwrap_err();
            assert!(
                matches!(
                    err,
                    RestoreError::Object(object::KitError::ChunkedBlobSizeMismatch {
                        expected,
                        actual
                    }) if expected == declared && actual > declared && actual < u64::MAX / 2
                ),
                "got {err:?}"
            );
            assert_eq!(fs::read_dir(target.path()).unwrap().count(), 0);
        }
    }

    #[cfg(unix)]
    #[test]
    fn restore_with_symlink() {
        let (_d, store) = fresh_store();
        let target = TempDir::new().unwrap();
        let link_target = put_blob(&store, b"target.txt");
        let file = put_blob(&store, b"real");
        let tree = put_tree_with(
            &store,
            vec![
                TreeEntry {
                    name: b"link".to_vec(),
                    mode: EntryMode::Symlink,
                    object_hash: link_target,
                },
                TreeEntry {
                    name: b"target.txt".to_vec(),
                    mode: EntryMode::Blob,
                    object_hash: file,
                },
            ],
        );
        restore_tree(&store, tree, target.path(), &RestoreOptions::default()).unwrap();
        let read = fs::read_link(target.path().join("link")).unwrap();
        assert_eq!(read.to_str().unwrap(), "target.txt");
        assert_eq!(fs::read(target.path().join("target.txt")).unwrap(), b"real");
    }

    #[cfg(unix)]
    #[test]
    fn restore_rejects_invalid_symlink_targets() {
        let (_d, store) = fresh_store();
        let target = TempDir::new().unwrap();
        let bad = put_blob(&store, b"/etc/passwd");
        let tree = put_tree_with(
            &store,
            vec![TreeEntry {
                name: b"link".to_vec(),
                mode: EntryMode::Symlink,
                object_hash: bad,
            }],
        );
        let err =
            restore_tree(&store, tree, target.path(), &RestoreOptions::default()).unwrap_err();
        assert!(matches!(err, RestoreError::InvalidSymlinkTarget(_)));
    }

    #[test]
    fn sparse_restore_only_restores_matched() {
        let (_d, store) = fresh_store();
        let target = TempDir::new().unwrap();
        let main = put_blob(&store, b"pub fn main(){}");
        let test = put_blob(&store, b"test {}");
        let readme = put_blob(&store, b"# Project");
        let src = put_tree_with(
            &store,
            vec![TreeEntry {
                name: b"main.rs".to_vec(),
                mode: EntryMode::Blob,
                object_hash: main,
            }],
        );
        let tests = put_tree_with(
            &store,
            vec![TreeEntry {
                name: b"test.rs".to_vec(),
                mode: EntryMode::Blob,
                object_hash: test,
            }],
        );
        let root = put_tree_with(
            &store,
            vec![
                TreeEntry {
                    name: b"README.md".to_vec(),
                    mode: EntryMode::Blob,
                    object_hash: readme,
                },
                TreeEntry {
                    name: b"src".to_vec(),
                    mode: EntryMode::Tree,
                    object_hash: src,
                },
                TreeEntry {
                    name: b"tests".to_vec(),
                    mode: EntryMode::Tree,
                    object_hash: tests,
                },
            ],
        );
        let opts = RestoreOptions {
            clean: true,
            sparse_patterns: Some(vec![SparsePattern {
                pattern: "src".to_string(),
                negated: false,
                dir_only: false,
            }]),
        };
        restore_tree(&store, root, target.path(), &opts).unwrap();
        assert!(target.path().join("src/main.rs").exists());
        assert!(!target.path().join("tests/test.rs").exists());
        assert!(!target.path().join("README.md").exists());
    }

    #[test]
    fn sparse_restore_with_negation_excludes_subtree() {
        let (_d, store) = fresh_store();
        let target = TempDir::new().unwrap();
        let main = put_blob(&store, b"main");
        let key = put_blob(&store, b"secret");
        let secret_tree = put_tree_with(
            &store,
            vec![TreeEntry {
                name: b"key.pem".to_vec(),
                mode: EntryMode::Blob,
                object_hash: key,
            }],
        );
        let src = put_tree_with(
            &store,
            vec![
                TreeEntry {
                    name: b"main.rs".to_vec(),
                    mode: EntryMode::Blob,
                    object_hash: main,
                },
                TreeEntry {
                    name: b"secret".to_vec(),
                    mode: EntryMode::Tree,
                    object_hash: secret_tree,
                },
            ],
        );
        let root = put_tree_with(
            &store,
            vec![TreeEntry {
                name: b"src".to_vec(),
                mode: EntryMode::Tree,
                object_hash: src,
            }],
        );
        let opts = RestoreOptions {
            clean: true,
            sparse_patterns: Some(vec![
                SparsePattern {
                    pattern: "src".to_string(),
                    negated: false,
                    dir_only: false,
                },
                SparsePattern {
                    pattern: "src/secret".to_string(),
                    negated: true,
                    dir_only: false,
                },
            ]),
        };
        restore_tree(&store, root, target.path(), &opts).unwrap();
        assert!(target.path().join("src/main.rs").exists());
        assert!(!target.path().join("src/secret/key.pem").exists());
    }

    #[test]
    fn sparse_checkout_roundtrip() {
        let target = TempDir::new().unwrap();
        let layout = RepoLayout::single(target.path());
        write_sparse_checkout(&layout, &["src", "!src/secret", "docs/"]).unwrap();
        let p = load_sparse_checkout(&layout).unwrap().unwrap();
        assert_eq!(p.len(), 3);
        assert_eq!(p[0].pattern, "src");
        assert!(p[1].negated);
        assert!(p[2].dir_only);
    }

    #[test]
    fn load_sparse_checkout_rejects_an_oversize_file() {
        let target = TempDir::new().unwrap();
        let layout = RepoLayout::single(target.path());
        fs::create_dir_all(target.path().join(".kit")).unwrap();
        let big = vec![b'a'; usize::try_from(MAX_SPARSE_BYTES).unwrap() + 1];
        fs::write(layout.sparse_checkout_file(), big).unwrap();
        assert!(matches!(
            load_sparse_checkout(&layout),
            Err(RestoreError::Io(_))
        ));
    }

    #[test]
    fn load_sparse_checkout_returns_none_when_missing() {
        let target = TempDir::new().unwrap();
        fs::create_dir_all(target.path().join(".kit")).unwrap();
        let p = load_sparse_checkout(&RepoLayout::single(target.path())).unwrap();
        assert!(p.is_none());
    }

    // =================================================================
    // restore_tree_to_worktree — checkout-facing wrapper.
    // =================================================================

    #[test]
    fn worktree_restore_counts_files_and_dirs() {
        let (_d, store) = fresh_store();
        let target = TempDir::new().unwrap();
        let blob_a = put_blob(&store, b"a");
        let blob_b = put_blob(&store, b"b");
        let sub = put_tree_with(
            &store,
            vec![TreeEntry {
                name: b"b.txt".to_vec(),
                mode: EntryMode::Blob,
                object_hash: blob_b,
            }],
        );
        let root = put_tree_with(
            &store,
            vec![
                TreeEntry {
                    name: b"a.txt".to_vec(),
                    mode: EntryMode::Blob,
                    object_hash: blob_a,
                },
                TreeEntry {
                    name: b"sub".to_vec(),
                    mode: EntryMode::Tree,
                    object_hash: sub,
                },
            ],
        );
        let report =
            restore_tree_to_worktree(&store, &root, target.path(), &RestoreOptions::default())
                .unwrap();
        assert_eq!(report.files_written, 2);
        assert_eq!(report.directories_created, 1);
        assert!(target.path().join("a.txt").exists());
        assert!(target.path().join("sub/b.txt").exists());
    }

    #[test]
    fn worktree_restore_writes_tracked_entries_and_keeps_untracked_ignored() {
        let (_d, store) = fresh_store();
        let target = TempDir::new().unwrap();
        // Pre-seed an ignore file, an UNTRACKED ignored file (must survive the
        // clean sweep), and a tracked path that happens to match the ignore
        // pattern but IS in the target tree (must be written — git parity).
        fs::write(target.path().join(".kitignore"), "*.tmp\nsecret.txt\n").unwrap();
        fs::write(target.path().join("scratch.tmp"), b"local-only").unwrap();
        fs::write(target.path().join("secret.txt"), b"OLD-LOCAL").unwrap();
        let secret_blob = put_blob(&store, b"COMMITTED-SECRET");
        let ok_blob = put_blob(&store, b"ok");
        let root = put_tree_with(
            &store,
            vec![
                TreeEntry {
                    name: b"ok.txt".to_vec(),
                    mode: EntryMode::Blob,
                    object_hash: ok_blob,
                },
                TreeEntry {
                    name: b"secret.txt".to_vec(),
                    mode: EntryMode::Blob,
                    object_hash: secret_blob,
                },
            ],
        );
        let report =
            restore_tree_to_worktree(&store, &root, target.path(), &RestoreOptions::default())
                .unwrap();
        // Both tracked entries materialise — ignore rules never gate writes.
        assert_eq!(report.files_written, 2);
        assert_eq!(
            fs::read(target.path().join("secret.txt")).unwrap(),
            b"COMMITTED-SECRET",
            "a tracked tree entry is written even if it matches an ignore rule"
        );
        assert_eq!(fs::read(target.path().join("ok.txt")).unwrap(), b"ok");
        // The UNTRACKED ignored file is preserved by the clean sweep.
        assert_eq!(
            fs::read(target.path().join("scratch.tmp")).unwrap(),
            b"local-only",
            "an untracked ignored file must survive the clean sweep"
        );
    }

    #[test]
    fn worktree_restore_clean_keeps_untracked_under_ignored_dir() {
        // The clean sweep must not delete an untracked file that lives *under*
        // an ignored directory, even when that directory is part of the
        // target tree (so it gets recursed into).
        let (_d, store) = fresh_store();
        let target = TempDir::new().unwrap();
        fs::write(target.path().join(".kitignore"), "dist/\n").unwrap();
        fs::create_dir(target.path().join("dist")).unwrap();
        fs::write(target.path().join("dist/local.tmp"), b"local").unwrap();
        // Target tree: dist/ (tree) holding a tracked app.js.
        let app_blob = put_blob(&store, b"APP");
        let dist_tree = put_tree_with(
            &store,
            vec![TreeEntry {
                name: b"app.js".to_vec(),
                mode: EntryMode::Blob,
                object_hash: app_blob,
            }],
        );
        let root = put_tree_with(
            &store,
            vec![TreeEntry {
                name: b"dist".to_vec(),
                mode: EntryMode::Tree,
                object_hash: dist_tree,
            }],
        );
        restore_tree_to_worktree(&store, &root, target.path(), &RestoreOptions::default()).unwrap();
        // Tracked content materialised...
        assert_eq!(fs::read(target.path().join("dist/app.js")).unwrap(), b"APP");
        // ...and the untracked file under the ignored dir is preserved.
        assert_eq!(
            fs::read(target.path().join("dist/local.tmp")).unwrap(),
            b"local",
            "an untracked file under an ignored dir must survive the clean sweep"
        );
    }

    #[test]
    fn worktree_restore_clean_keeps_ignored_files_in_an_unlisted_directory() {
        // `build/` is not in the target tree. The sweep removes its plain
        // file and keeps the ignored file and the directory that holds it. A
        // directory with nothing ignored goes away whole.
        let (_d, store) = fresh_store();
        let target = TempDir::new().unwrap();
        fs::write(target.path().join(".kitignore"), "*.log\n").unwrap();
        fs::create_dir_all(target.path().join("build/deep")).unwrap();
        fs::write(target.path().join("build/x.log"), b"keep").unwrap();
        fs::write(target.path().join("build/deep/y.log"), b"keep deep").unwrap();
        fs::write(target.path().join("build/plain.txt"), b"drop").unwrap();
        fs::create_dir(target.path().join("gone")).unwrap();
        fs::write(target.path().join("gone/f.txt"), b"drop").unwrap();
        let root = put_tree_with(&store, Vec::new());
        restore_tree_to_worktree(&store, &root, target.path(), &RestoreOptions::default()).unwrap();
        assert_eq!(
            fs::read(target.path().join("build/x.log")).unwrap(),
            b"keep"
        );
        assert_eq!(
            fs::read(target.path().join("build/deep/y.log")).unwrap(),
            b"keep deep"
        );
        assert!(!target.path().join("build/plain.txt").exists());
        assert!(!target.path().join("gone").exists());
    }

    #[cfg(unix)]
    #[test]
    fn worktree_restore_rejects_escaping_symlink() {
        let (_d, store) = fresh_store();
        let target = TempDir::new().unwrap();
        let bad = put_blob(&store, b"../outside");
        let root = put_tree_with(
            &store,
            vec![TreeEntry {
                name: b"link".to_vec(),
                mode: EntryMode::Symlink,
                object_hash: bad,
            }],
        );
        let err =
            restore_tree_to_worktree(&store, &root, target.path(), &RestoreOptions::default())
                .unwrap_err();
        assert!(matches!(err, RestoreError::InvalidSymlinkTarget(_)));
    }
}

#[cfg(test)]
mod random_input_tests {
    #![allow(clippy::unwrap_used, clippy::cast_possible_truncation)] // bounded random values

    use super::*;
    use crate::object::{Blob, Tree, TreeEntry};
    use crate::serialize;
    use tempfile::TempDir;

    struct Rng(u64);

    impl Rng {
        fn below(&mut self, bound: u64) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0 % bound
        }
    }

    fn put(store: &ObjectStore, object: &Object) -> Hash {
        store.write(&serialize::serialize(object).unwrap()).unwrap()
    }

    fn blob(store: &ObjectStore, data: &[u8]) -> Hash {
        put(
            store,
            &Object::Blob(Blob {
                data: data.to_vec(),
            }),
        )
    }

    /// A random tree over a small pool of names, contents and kinds, so two
    /// draws often share a path with the same or another kind.
    fn random_tree(store: &ObjectStore, rng: &mut Rng, depth: u64) -> Hash {
        let mut entries = Vec::new();
        for name in ["a", "b", "c", "d", "e"] {
            if rng.below(3) == 0 {
                continue;
            }
            let content = [b"one".as_slice(), b"two", b"three"][rng.below(3) as usize];
            let (mode, object_hash) = match rng.below(if depth < 3 { 6 } else { 4 }) {
                0 | 1 => (EntryMode::Blob, blob(store, content)),
                2 => (EntryMode::Executable, blob(store, content)),
                3 => (
                    EntryMode::Symlink,
                    blob(store, [b"a".as_slice(), b"b/c"][rng.below(2) as usize]),
                ),
                _ => (EntryMode::Tree, random_tree(store, rng, depth + 1)),
            };
            entries.push(TreeEntry {
                name: name.as_bytes().to_vec(),
                mode,
                object_hash,
            });
        }
        if entries.is_empty() {
            entries.push(TreeEntry {
                name: b"a".to_vec(),
                mode: EntryMode::Blob,
                object_hash: blob(store, b"one"),
            });
        }
        put(store, &Object::Tree(Tree { entries }))
    }

    /// Every path under `dir` with its kind, mode and bytes.
    fn listing(dir: &Path, prefix: &str, out: &mut Vec<String>) {
        use std::os::unix::fs::PermissionsExt;
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        for name in names {
            let path = dir.join(&name);
            let rel = format!("{prefix}/{name}");
            let meta = fs::symlink_metadata(&path).unwrap();
            if meta.file_type().is_symlink() {
                out.push(format!(
                    "{rel} -> {}",
                    fs::read_link(&path).unwrap().display()
                ));
            } else if meta.is_dir() {
                out.push(format!("{rel}/"));
                listing(&path, &rel, out);
            } else {
                let executable = meta.permissions().mode() & 0o111 != 0;
                out.push(format!(
                    "{rel} x={executable} {:?}",
                    fs::read(&path).unwrap()
                ));
            }
        }
    }

    /// A worktree at `base` restored to `next` with `base` as the base tree
    /// equals a fresh restore of `next`, for random pairs of trees.
    #[cfg(unix)]
    #[test]
    fn an_incremental_restore_equals_a_fresh_one_for_random_trees() {
        let dir = TempDir::new().unwrap();
        let store = ObjectStore::init(&crate::layout::RepoLayout::single(dir.path())).unwrap();
        let opts = RestoreOptions::default();
        assert!(opts.clean);
        let rd = |s: &ObjectStore, h: &[Hash]| sequential_read_chunks(s, h);
        let mut rng = Rng(0x2545_f491_4f6c_dd1d);
        for round in 0..60 {
            let base = random_tree(&store, &mut rng, 0);
            let next = random_tree(&store, &mut rng, 0);
            let incremental = TempDir::new().unwrap();
            restore_tree_to_worktree_with(&store, &base, None, incremental.path(), &opts, &rd)
                .unwrap();
            restore_tree_to_worktree_with(
                &store,
                &next,
                Some(base),
                incremental.path(),
                &opts,
                &rd,
            )
            .unwrap();
            let fresh = TempDir::new().unwrap();
            restore_tree_to_worktree_with(&store, &next, None, fresh.path(), &opts, &rd).unwrap();
            let (mut got, mut want) = (Vec::new(), Vec::new());
            listing(incremental.path(), "", &mut got);
            listing(fresh.path(), "", &mut want);
            assert_eq!(got, want, "round {round}");
        }
    }
}
