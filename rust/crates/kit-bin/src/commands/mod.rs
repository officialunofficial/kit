//! Subcommand implementations. Each top-level command is its own
//! module.
//!
//! Dispatch lives in `main.rs`; business logic lives in library
//! crates; this module is the thin presentation layer.

pub mod add;
pub mod attest;
pub mod attest_factory;
pub mod bisect;
pub mod blame;
pub mod branch;
pub mod cat;
pub mod cat_file;
pub mod checkout;
pub mod cherry_pick;
pub mod clean;
pub mod clone;
pub mod closure;
pub mod commit;
pub mod config_cmd;
pub mod conflict;
pub mod diff;
pub mod epoch;
pub mod fetch;
pub mod for_each_ref;
pub mod gc;
#[cfg(feature = "git-bridge")]
pub mod git;
#[cfg(feature = "git-bridge")]
pub mod git_import;
#[cfg(feature = "git-bridge")]
pub mod git_tools;
pub mod grant;
pub mod hash_cmd;
pub mod init;
pub mod key;
pub mod keygen;
pub mod log;
pub mod ls_files;
pub mod ls_tree;
pub mod mcp;
#[cfg(feature = "mcp-v2")]
pub mod mcp_v2;
pub mod merge;
pub mod merge_base;
pub mod mv;
pub mod prove;
pub mod pull;
pub mod push;
pub mod rebase;
pub mod ref_cmd;
pub mod reflog;
pub mod remote;
pub mod reset;
pub mod restore;
pub mod rev_list;
pub mod rev_parse;
pub mod revert;
pub mod rm;
pub mod self_update;
pub mod serve;
pub mod show;
pub mod show_ref;
pub mod signing;
pub mod sparse_checkout;
pub mod stash;
pub mod status;
pub mod summary;
pub mod switch;
pub mod symbolic_ref;
pub mod tag;
pub mod tree;
pub mod trust;
pub mod trust_roots;
pub mod update_ref;
pub mod verify;
pub mod verify_attest;
pub mod verify_proof;
pub mod visibility;
pub mod worktree;

use crate::exit;
use kit_core::hash::Hash;
use kit_core::index::EntryStatus;
use kit_core::layout::RepoLayout;
use kit_core::object::Object;
use kit_core::ops::diff::{DiffKind, diff_trees};
use kit_core::ops::recovery::{self, RecoveryEntry};
use kit_core::refs::{self, Head, RefError, RefWriteCondition};
use kit_core::store::ObjectStore;
use kit_core::worktree as core_worktree;
use std::fs;
use std::io::Write;
use std::path::Path;

// The restore-safety, index and history-aware ref-write primitives live in
// `kit-sync` (a pull's fast-forward is built on them); every command keeps
// reaching them through this module.
pub(crate) use kit_sync::worktree::{
    current_head_tree, fanout_read_batch, index_path_descends_from, index_path_matches_or_descends,
    index_tracks_path_or_descendant, restore_affects_path,
};
pub use kit_sync::worktree::{
    ensure_restore_safe, ensure_restore_safe_with_options, read_or_seed_index_from_head,
    restore_worktree_and_index, sync_index_to_tree, sync_index_to_tree_observed,
    write_ref_recording_history,
};

/// [`refs::list_refs`], with the per-ref read-and-decode step fanned out
/// across rayon's global thread pool once there's enough work to amortize
/// dispatch — the directory walk itself stays sequential either way (see
/// [`refs::list_refs_with`]'s docs). Same sequential-vs-rayon crossover
/// shape as the hashing fan-outs of `libkit::add` and the pack, delta and
/// signature fan-outs of `kit_sync` (`kit_sync::fanout`). Measured ~2x faster at
/// 1k-10k refs and still faster, not a wash, even at 100 (`cargo bench -p
/// kit-benches --bench refs_ops -- list_refs_fanout`).
pub(crate) fn list_refs_parallel(layout: &RepoLayout) -> Result<Vec<refs::Ref>, RefError> {
    refs::list_refs_with(layout, fanout_read_batch)
}

/// [`refs::list_tags`], fanned out the same way as [`list_refs_parallel`]
/// — a command that lists heads and tags together (e.g. `for-each-ref`,
/// `show-ref`, `ref list`) gets the parallel win on both namespaces, not
/// just the one that happened to be wired up first.
pub(crate) fn list_tags_parallel(layout: &RepoLayout) -> Result<Vec<refs::Ref>, RefError> {
    refs::list_tags_with(layout, fanout_read_batch)
}

/// [`refs::list_remote_refs`], fanned out the same way as
/// [`list_refs_parallel`].
pub(crate) fn list_remote_refs_parallel(
    layout: &RepoLayout,
    remote: &str,
) -> Result<Vec<refs::Ref>, RefError> {
    refs::list_remote_refs_with(layout, remote, fanout_read_batch)
}

/// Run `f` with the store settings of the current command: its environment,
/// and the config warnings on stderr.
pub(crate) fn with_store_config<T>(f: impl FnOnce(&libkit::repo::StoreConfig<'_>) -> T) -> T {
    let environment = crate::environment::current();
    f(&libkit::repo::StoreConfig {
        environment: &environment,
        observer: &crate::config::StderrWarnings,
    })
}

/// Open the object store for a mutating command, honoring the repo's
/// configured durability schedule (`durability.objects`, see
/// [`crate::config::Config::object_sync_policy`]). Falls back to the
/// batched default when the config cannot be read — a broken config
/// must not change write semantics silently, and Batch is the default
/// contract.
pub fn open_store_configured(
    layout: &RepoLayout,
) -> Result<ObjectStore, kit_core::store::StoreError> {
    with_store_config(|config| config.open(layout))
}

/// Resolve the [`RepoLayout`] a command operates on:
/// pointer-following discovery. A `.kit` DIRECTORY (or none at all)
/// resolves to the classic single-worktree layout exactly as before; a
/// `.kit` pointer FILE resolves to the linked tree's split layout. On
/// a broken pointer the error has already been printed and the
/// returned code is the exit status to propagate — a broken linked
/// tree must never silently operate on the wrong directory. Command
/// code must obtain its layout HERE and never construct one ad hoc.
pub fn resolve_layout(cwd: &Path) -> Result<RepoLayout, u8> {
    kit_core::layout::discover(cwd)
        .map_err(|e| error(&format!("worktree discovery: {e}"), exit::DATAERR))
}

/// Open the repository at `cwd` through the library. On failure the error
/// has already been printed, and the returned code is the exit status to
/// propagate. [`crate::exit_map`] decides both the text and the code.
///
/// The library does not read the `-c` overrides when it opens a
/// repository, so the environment carries none.
pub(crate) fn open_repo(cwd: &Path) -> Result<libkit::Repo, u8> {
    let environment = crate::environment::from_process(Vec::new());
    libkit::Repo::open(cwd, &environment).map_err(|e| {
        let e = libkit::Error::from(e);
        error(
            &crate::exit_map::message(&e),
            crate::exit_map::exit_code(&e),
        )
    })
}

/// Shared helper: emit a "not yet wired" notice and return the
/// tempfail exit code. Commands whose backing state-machines haven't
/// been wired into the CLI yet say so honestly rather than pretending
/// to work.
#[must_use]
pub fn not_yet_ported(cmd: &str) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: `kit {cmd}` is not yet wired");
    exit::TEMPFAIL
}

/// Shared helper: print a usage error and return the USAGE exit code.
#[must_use]
pub fn usage_error(msg: &str) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    exit::USAGE
}

/// Shared helper: print `error: <msg>` to stderr and return `code`.
///
/// This is the single source of truth for the `error: …`-prefixed
/// stderr channel used by every subcommand. It generalises
/// [`usage_error`] (which hardcodes [`exit::USAGE`]) to an arbitrary
/// exit code so command modules don't each carry their own copy.
#[must_use]
pub(crate) fn error(msg: &str, code: u8) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    code
}

/// Load the tree hash of a commit object, surfacing a CLI error code.
///
/// Shared by the `cherry-pick`/`revert`/`merge` replay+rollback paths,
/// which all need the tree of a resolved commit before restoring it.
///
/// # Errors
/// Returns [`exit::DATAERR`] if the object is not a commit, or
/// [`exit::GENERAL_ERROR`] if it cannot be read.
pub(crate) fn load_tree_hash(store: &ObjectStore, commit_hash: Hash) -> Result<Hash, u8> {
    match store.read_object(&commit_hash) {
        Ok(Object::Commit(c)) => Ok(c.tree_hash),
        Ok(_) => Err(error("object is not a commit", exit::DATAERR)),
        Err(e) => Err(error(&format!("read commit: {e}"), exit::GENERAL_ERROR)),
    }
}

/// The message and exit code for a failed HEAD move. [`crate::exit_map`] owns
/// both.
pub(crate) fn head_failure(failure: libkit::head::Error) -> (String, u8) {
    let failure = libkit::Error::from(failure);
    (
        crate::exit_map::message(&failure),
        crate::exit_map::exit_code(&failure),
    )
}

/// Point the current branch (or detached HEAD) at `new_head`, without a
/// condition on the old tip.
///
/// Shared by `cherry-pick`, `revert` and `merge`. An unreadable HEAD is an
/// error: the helper never guesses a branch name.
///
/// # Errors
/// Returns a human-readable message if HEAD cannot be read or the write
/// fails.
pub(crate) fn advance_head(layout: &RepoLayout, new_head: &Hash) -> Result<(), String> {
    libkit::head::advance(layout, new_head, RefWriteCondition::Any).map_err(|e| head_failure(e).0)
}

/// Restore the current branch (or detached HEAD) to `target` as the
/// final step of a conflict `--abort` or rollback.
///
/// # Errors
/// Returns a CLI exit code (already printed via [`error`]) on failure.
pub(crate) fn restore_head_ref(layout: &RepoLayout, target: &Hash) -> Result<(), u8> {
    libkit::head::advance(layout, target, RefWriteCondition::Any).map_err(|e| {
        let (message, code) = head_failure(e);
        error(&message, code)
    })
}

/// Print `failure` as `error: <text>` and return its exit code.
/// [`crate::exit_map`] decides both.
pub(crate) fn fail(failure: impl Into<libkit::Error>) -> u8 {
    let failure = failure.into();
    error(
        &crate::exit_map::message(&failure),
        crate::exit_map::exit_code(&failure),
    )
}

pub use libkit::lock::{SERVE_LOCK, WORKTREE_LOCK, WORKTREES_REGISTRY_LOCK};

/// The message and exit code for a failed lock.
fn lock_failure(failure: libkit::lock::Error) -> u8 {
    let failure = libkit::Error::from(failure);
    error(
        &crate::exit_map::message(&failure),
        crate::exit_map::exit_code(&failure),
    )
}

/// Acquire the shared worktree/index lock for this worktree.
///
/// Hold the returned guard across the whole read-modify-write so a
/// second mutating `kit` blocks (then times out) instead of racing on
/// the worktree + `.kit/index`. On failure, the lock message has
/// already been printed to stderr and the returned [`u8`] is the exit
/// code to propagate. The lock scope is the caller's decision: the guard
/// is [`libkit::lock::RepoLock`], and dropping it releases the lock.
///
/// # Errors
/// Returns [`exit::TEMPFAIL`] when the lock cannot be taken within the
/// default timeout (another `kit` holds it, or a stale lockfile is
/// present).
pub fn acquire_worktree_lock(layout: &RepoLayout) -> Result<libkit::lock::RepoLock, u8> {
    libkit::lock::acquire_worktree(layout, &crate::progress::ServedWarning).map_err(lock_failure)
}

/// Acquire the shared worktree-registry lock (common dir).
///
/// # Errors
/// [`exit::TEMPFAIL`] when the lock cannot be taken (message already
/// printed), mirroring [`acquire_worktree_lock`].
pub fn acquire_worktrees_registry_lock(layout: &RepoLayout) -> Result<libkit::lock::RepoLock, u8> {
    libkit::lock::acquire_registry(layout, &crate::progress::ServedWarning).map_err(lock_failure)
}

/// C-style-quote `path` the way Git does for porcelain / `--name-*`
/// output when a path contains bytes that need escaping. Returns `None`
/// when the path is "plain" (all printable ASCII except `"`/`\`) and can
/// be emitted as-is. Shared by `status` and `diff --name-only/-status`.
///
/// Quoting rule (matches Git's `quote_c_style` with the default
/// `core.quotePath=true`): quote if any byte is a control char (`< 0x20`),
/// `"`, `\`, or non-printable / non-ASCII (`>= 0x7f`). Inside the quotes,
/// the common control chars use their `\a\b\t\n\v\f\r` escapes, `"` and
/// `\` are backslash-escaped, printable ASCII is literal, and everything
/// else is a 3-digit `\NNN` octal escape (per UTF-8 byte).
pub(crate) fn c_quote_path(path: &str) -> Option<String> {
    let bytes = path.as_bytes();
    let needs = bytes
        .iter()
        .any(|&b| b < 0x20 || b == b'"' || b == b'\\' || b >= 0x7f);
    if !needs {
        return None;
    }
    let mut out = String::with_capacity(bytes.len() + 2);
    out.push('"');
    for &b in bytes {
        match b {
            0x07 => out.push_str("\\a"),
            0x08 => out.push_str("\\b"),
            0x09 => out.push_str("\\t"),
            0x0a => out.push_str("\\n"),
            0x0b => out.push_str("\\v"),
            0x0c => out.push_str("\\f"),
            0x0d => out.push_str("\\r"),
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            0x20..=0x7e => out.push(b as char),
            other => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\{other:03o}");
            }
        }
    }
    out.push('"');
    Some(out)
}

/// Resolve a CLI path argument to a repo-relative, `/`-separated index
/// path, validating it. Shared by `rm` and `mv` so both resolve and
/// validate pathspecs identically. The rules are in
/// [`libkit::pathspec::index_path_for_arg`].
pub(crate) fn index_path_for_arg(root: &Path, arg: &Path) -> Result<String, String> {
    libkit::pathspec::index_path_for_arg(root, arg).map_err(|e| e.to_string())
}

/// The worktree's current staged representation `(status, hash)` for
/// `path`: a regular file (with its exec bit), a symlink (blob of its
/// target), or `None` when the path is missing or not a stageable type
/// (e.g. a directory). Mirrors how `add` stages one entry, so a caller can
/// compare a worktree path to an index entry by **content AND mode/type** —
/// catching symlink-target and chmod-only changes that a content-only hash
/// would miss.
pub(crate) fn worktree_entry_state(
    root: &Path,
    store: &dyn kit_core::store::ObjectSink,
    path: &str,
) -> Result<Option<(EntryStatus, Hash)>, String> {
    let abs = root.join(path);
    let meta = match abs.symlink_metadata() {
        Ok(m) => m,
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ) =>
        {
            return Ok(None);
        }
        Err(e) => return Err(format!("metadata {}: {e}", abs.display())),
    };
    if meta.file_type().is_file() {
        let (opened_meta, bytes) = core_worktree::read_regular_file_bounded(&abs)
            .map_err(|e| format!("read {}: {e}", abs.display()))?;
        let h =
            core_worktree::store_file_object(store, &bytes).map_err(|e| format!("store: {e}"))?;
        Ok(Some((file_exec_status(&opened_meta), h)))
    } else if meta.file_type().is_symlink() {
        let target =
            fs::read_link(&abs).map_err(|e| format!("read link {}: {e}", abs.display()))?;
        let target_str = target
            .to_str()
            .ok_or_else(|| "symlink target is not valid UTF-8".to_string())?;
        if !core_worktree::validate_symlink_target(target_str) {
            return Err(format!("invalid symlink target: {target_str}"));
        }
        let blob = Object::Blob(kit_core::object::Blob {
            data: target_str.as_bytes().to_vec(),
        });
        let ser = kit_core::serialize::serialize(&blob).map_err(|e| format!("serialize: {e}"))?;
        let h = store.put(&ser).map_err(|e| format!("store: {e}"))?;
        Ok(Some((EntryStatus::Symlink, h)))
    } else {
        Ok(None)
    }
}

#[cfg(unix)]
fn file_exec_status(meta: &fs::Metadata) -> EntryStatus {
    use std::os::unix::fs::PermissionsExt;
    if meta.permissions().mode() & 0o111 != 0 {
        EntryStatus::Executable
    } else {
        EntryStatus::Blob
    }
}

#[cfg(not(unix))]
fn file_exec_status(_meta: &fs::Metadata) -> EntryStatus {
    EntryStatus::Blob
}

/// Current branch name for recovery logging — empty for a detached HEAD
/// or an unreadable/symbolic-only HEAD.
#[must_use]
pub fn head_branch_name(layout: &RepoLayout) -> String {
    match refs::read_head(layout) {
        Ok(Head::Branch(name)) => name,
        _ => String::new(),
    }
}

/// Record `superseded` (the old branch tip a history-rewriting op is
/// about to replace) in the recovery log so `kit gc` keeps it
/// recoverable.
///
/// Call this **before** moving the ref and while holding the worktree
/// lock (every caller does both): recording first guarantees that a
/// persisted ref move always has a persisted recovery entry, and the
/// lock keeps a concurrent `recovery::expire` from clobbering the append.
/// On failure the caller MUST abort the rewrite (propagate the returned
/// error) rather than orphan an unrecoverable commit. The zero hash is a
/// no-op inside [`recovery::record`].
pub fn record_superseded(
    layout: &RepoLayout,
    op: &str,
    branch: &str,
    superseded: Hash,
) -> Result<(), (String, u8)> {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let entry = RecoveryEntry {
        timestamp,
        op: op.to_owned(),
        superseded,
        branch: branch.to_owned(),
    };
    recovery::record(layout, &entry).map_err(|e| (format!("recovery log: {e}"), exit::CANTCREAT))
}

/// Tracked paths present in the current index but absent from the target
/// tree, each paired with its index entry's `(status, hash)` — for
/// destructive worktree moves (`reset --hard`, `checkout`) these files
/// are deleted explicitly (`restore_tree_to_worktree` with `clean =
/// false` writes/overwrites but never deletes). The `(status, hash)`
/// lets the caller detect local edits by content AND mode/type.
pub(crate) fn dropped_tracked_paths(
    layout: &RepoLayout,
    store: &ObjectStore,
    target_tree: Hash,
) -> Result<Vec<(String, EntryStatus, Hash)>, String> {
    let idx = read_or_seed_index_from_head(layout, store)?;
    let snapshot = kit_core::store::EphemeralSink::new(store);
    let index_tree = core_worktree::build_tree_from_index_with(store, &snapshot, &idx, false)
        .map_err(|e| format!("index tree: {e}"))?;
    let mut out = Vec::new();
    for e in diff_trees(&snapshot, Some(index_tree), Some(target_tree))
        .map_err(|e| format!("diff index vs target: {e}"))?
        .entries
        .into_iter()
        .filter(|e| e.kind == DiffKind::Removed)
    {
        if let Some(entry) = idx
            .entries
            .iter()
            .find(|ie| ie.path == e.path && ie.status != EntryStatus::Removed)
        {
            out.push((e.path, entry.status, entry.object_hash));
        }
    }
    Ok(out)
}

/// The first dropped path whose worktree entry differs from its indexed
/// `(status, hash)` — a local edit to content, mode (exec bit), or symlink
/// target. `None` if every dropped path is unmodified, missing, or a
/// directory (no file to lose). This is a direct per-dropped-path check, so
/// destructive moves never silently discard a local edit — independent of
/// how the shared worktree-snapshot guard treats ignored files.
pub(crate) fn locally_modified_dropped_path(
    cwd: &Path,
    store: &ObjectStore,
    dropped: &[(String, EntryStatus, Hash)],
) -> Result<Option<String>, String> {
    let snapshot = kit_core::store::EphemeralSink::new(store);
    for (path, idx_status, idx_hash) in dropped {
        if let Some((wt_status, wt_hash)) = worktree_entry_state(cwd, &snapshot, path)?
            && (wt_status != *idx_status
                || !core_worktree::content_eq(&snapshot, &wt_hash, idx_hash)
                    .map_err(|e| e.to_string())?)
        {
            return Ok(Some(path.clone()));
        }
    }
    Ok(None)
}

/// Delete a dropped tracked path from the worktree. A regular file or
/// symlink is removed; a directory (untracked content that replaced the
/// tracked file) is LEFT in place rather than recursively deleted, and a
/// missing path is a no-op — so this never crashes on `IsADirectory` and
/// never nukes untracked directories.
pub(crate) fn remove_dropped_path(abs: &Path) -> std::io::Result<()> {
    match fs::symlink_metadata(abs) {
        Ok(meta) if meta.is_dir() => Ok(()),
        Ok(_) => fs::remove_file(abs),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::{advance_head, c_quote_path, restore_head_ref};
    use kit_core::hash::Hash;

    #[test]
    fn c_quote_leaves_plain_paths_alone() {
        assert_eq!(c_quote_path("a.txt"), None);
        assert_eq!(c_quote_path("dir/with space.txt"), None); // space is plain
        assert_eq!(c_quote_path("weird-but-ascii_!@#$%.rs"), None);
    }

    #[test]
    fn c_quote_escapes_special_bytes() {
        assert_eq!(c_quote_path("a\tb.txt").as_deref(), Some(r#""a\tb.txt""#));
        assert_eq!(
            c_quote_path("line\nfeed").as_deref(),
            Some(r#""line\nfeed""#)
        );
        assert_eq!(c_quote_path("q\"x").as_deref(), Some(r#""q\"x""#));
        assert_eq!(
            c_quote_path("back\\slash").as_deref(),
            Some(r#""back\\slash""#)
        );
    }

    #[test]
    fn c_quote_octal_escapes_non_ascii() {
        // "é" is UTF-8 0xC3 0xA9 → \303\251 (matches git core.quotePath).
        assert_eq!(c_quote_path("é").as_deref(), Some(r#""\303\251""#));
        // Combined with ASCII: only the non-ASCII bytes are octal-escaped.
        assert_eq!(c_quote_path("x-é").as_deref(), Some(r#""x-\303\251""#));
    }

    // Regression: the shared replay helpers must NOT fabricate
    // `Head::Branch("main")` when HEAD is unreadable/missing. A missing
    // HEAD previously caused cherry-pick/revert/merge (and especially the
    // `--abort` recovery path) to silently write the commit pointer to
    // `refs/heads/main`, clobbering or creating a `main` branch the user
    // never had. Both helpers must surface the read error instead.

    #[test]
    fn advance_head_errors_when_head_missing_instead_of_writing_main() {
        let td = tempfile::tempdir().unwrap();
        let layout = kit_core::layout::RepoLayout::single(td.path());
        // No HEAD file exists → refs::read_head returns NoHead.
        let new_head: Hash = [0x11; 32];
        let err = advance_head(&layout, &new_head).expect_err("missing HEAD must error");
        assert!(err.contains("read HEAD"), "unexpected error: {err}");
        // Crucially, no `main` ref was fabricated.
        assert!(
            !layout.heads_dir().join("main").exists(),
            "advance_head must not write refs/heads/main when HEAD is unreadable"
        );
    }

    #[test]
    fn restore_head_ref_errors_when_head_missing_instead_of_writing_main() {
        let td = tempfile::tempdir().unwrap();
        let layout = kit_core::layout::RepoLayout::single(td.path());
        let target: Hash = [0x22; 32];
        let code = restore_head_ref(&layout, &target).expect_err("missing HEAD must error");
        assert_eq!(code, crate::exit::DATAERR);
        assert!(
            !layout.heads_dir().join("main").exists(),
            "restore_head_ref must not write refs/heads/main when HEAD is unreadable"
        );
    }
}
