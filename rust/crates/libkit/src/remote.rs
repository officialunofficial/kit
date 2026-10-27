//! Remotes: add, change, remove, rename and list.
//!
//! A remote is a name and an address in the config of the repository. The
//! flat default remote has the reserved name `default`. The operations that
//! change a remote take the repo layer of the config and write it back, so a
//! user-scoped value never reaches `.kit/config`. [`url_of`] and [`list`] take
//! the merged config.
//!
//! An address must start with `kit+<scheme>://` for a native transport, or
//! with `git+<scheme>://` for a git bridge. A name must be a ref-safe name
//! without a dot. The check of both runs before any write, and it rejects
//! control characters, because the config writer emits values as they are.
//!
//! [`remove`] and [`rename`] also tidy the state that belongs to the remote
//! name: the remote-tracking refs, the git-bridge state and the applied-packs
//! record. A failure in that step does not fail the operation. The config
//! change has happened by then, so the step reports the failure to the
//! [`Observer`] and goes on.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use kit_core::layout::RepoLayout;
use kit_core::observer::Observer;
use kit_core::refs;
use kit_sync::AppliedPacks;

use crate::config::{self, Config, ConfigError, DEFAULT_REMOTE_NAME, RemoteEntry};

/// The URL prefixes that a remote accepts, with the transport of each.
///
/// The `git+` schemes name a git bridge. The native push, pull, fetch and
/// clone refuse them, because the two kinds of transport are not
/// interchangeable.
const ACCEPTED_SCHEMES: &[(&str, &str)] = &[
    ("kit+file://", "file"),
    ("kit+https://", "http"),
    ("kit+s3://", "s3"),
    ("kit+ssh://", "ssh"),
    ("kit+memory://", "memory"),
    ("git+https://", "git"),
    ("git+ssh://", "git"),
    ("git+file://", "git"),
];

/// Errors from a remote operation.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The address has a control character.
    #[error("invalid remote URL '{0}': contains control characters")]
    UrlControlCharacters(String),
    /// The address does not start with an accepted scheme.
    #[error("invalid remote URL '{0}': must start with 'kit+<scheme>://'")]
    UnsupportedScheme(String),
    /// The name has a control character.
    #[error("invalid remote name '{0}': contains control characters")]
    NameControlCharacters(String),
    /// The name is not a dot-free ref-safe name, or it is `default`.
    #[error(
        "invalid remote name '{0}': must be a dot-free ref-safe name (and not the reserved `default`)"
    )]
    InvalidName(String),
    /// A rename names the reserved `default` remote.
    #[error("cannot rename the reserved `default` remote; use `remote add`/`remote remove`")]
    RenameDefault,
    /// The flat default remote is not set.
    #[error("no default remote configured")]
    NoDefault,
    /// The remote does not exist.
    #[error("remote '{0}' not found")]
    NotFound(String),
    /// A remote of the new name exists already.
    #[error("remote '{0}' already exists")]
    AlreadyExists(String),
    /// The config could not be written.
    #[error("write: {0}")]
    Write(ConfigError),
}

/// A failure of the tidy step of [`remove`] or [`rename`], or a fact about the
/// state that stays.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Event {
    /// The remote-tracking refs did not move to the new name. A fetch
    /// repopulates them.
    TrackingRefsNotMoved {
        /// The old name.
        old: String,
        /// The new name.
        new: String,
        /// Why the move failed.
        error: String,
    },
    /// The git-bridge state did not move to the new name.
    BridgeStateNotMoved {
        /// The old name.
        old: String,
        /// The new name.
        new: String,
        /// Why the move failed.
        error: String,
    },
    /// The applied-packs record did not move to the new name. The next fetch
    /// rebuilds it with one full download.
    AppliedPacksNotMoved {
        /// The old name.
        old: String,
        /// The new name.
        new: String,
        /// Why the move failed.
        error: String,
    },
    /// The applied-packs record of a removed remote stays.
    AppliedPacksNotRemoved {
        /// The removed name.
        name: String,
        /// Why the removal failed.
        error: String,
    },
    /// The remote-tracking refs of a removed remote stay.
    TrackingRefsNotRemoved {
        /// The removed name.
        name: String,
        /// Why the removal failed.
        error: String,
    },
    /// The git-bridge state of a removed remote stays on purpose. It holds
    /// the staging mirror and the provenance, which are durable.
    BridgeStateRemains {
        /// The removed name.
        name: String,
    },
}

/// One configured remote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Remote {
    /// The name.
    pub name: String,
    /// The address.
    pub url: String,
    /// The transport, as `add` derived it from the scheme.
    pub transport: String,
}

/// The configured remotes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listing {
    /// The flat default remote, when it is set. Its name is `default`.
    pub default: Option<Remote>,
    /// The named remotes, in name order.
    pub named: Vec<Remote>,
}

/// The transport that the scheme of `url` selects, after the control
/// character check.
///
/// # Errors
/// [`Error::UrlControlCharacters`] or [`Error::UnsupportedScheme`].
pub fn validate_url(url: &str) -> Result<&'static str, Error> {
    if config::validate_value(url).is_err() {
        return Err(Error::UrlControlCharacters(url.to_owned()));
    }
    ACCEPTED_SCHEMES
        .iter()
        .find(|(prefix, _)| url.starts_with(prefix))
        .map(|&(_, transport)| transport)
        .ok_or_else(|| Error::UnsupportedScheme(url.to_owned()))
}

/// Check a name for a named remote. A dot would collide with the
/// `remote.<name>.<field>` config key grammar.
///
/// # Errors
/// [`Error::NameControlCharacters`] or [`Error::InvalidName`].
pub fn validate_name(name: &str) -> Result<(), Error> {
    if config::validate_value(name).is_err() {
        return Err(Error::NameControlCharacters(name.to_owned()));
    }
    if !refs::validate_ref_name(name) || name.contains('.') || name == DEFAULT_REMOTE_NAME {
        return Err(Error::InvalidName(name.to_owned()));
    }
    Ok(())
}

fn write(layout: &RepoLayout, repo: &Config) -> Result<(), Error> {
    config::write(layout, repo).map_err(Error::Write)
}

/// Add or replace a remote. With no `name`, set the flat default remote.
///
/// `repo` is the repo layer of the config. The operation changes it and writes
/// it back.
///
/// # Errors
/// [`Error::UrlControlCharacters`], [`Error::UnsupportedScheme`],
/// [`Error::NameControlCharacters`], [`Error::InvalidName`] or
/// [`Error::Write`].
pub fn add(
    layout: &RepoLayout,
    repo: &mut Config,
    name: Option<&str>,
    url: &str,
) -> Result<(), Error> {
    let transport = validate_url(url)?;
    if let Some(name) = name {
        validate_name(name)?;
        repo.remotes.insert(
            name.to_owned(),
            RemoteEntry {
                url: url.to_owned(),
                remote_type: transport.to_owned(),
            },
        );
    } else {
        url.clone_into(&mut repo.remote_endpoint);
        transport.clone_into(&mut repo.remote_type);
    }
    write(layout, repo)
}

/// Change the address of a remote. The name `default` selects the flat
/// default remote.
///
/// # Errors
/// [`Error::UrlControlCharacters`] or [`Error::UnsupportedScheme`] for the
/// address. [`Error::NoDefault`] or [`Error::NotFound`] when the remote does
/// not exist. [`Error::Write`].
pub fn set_url(layout: &RepoLayout, repo: &mut Config, name: &str, url: &str) -> Result<(), Error> {
    let transport = validate_url(url)?;
    if name == DEFAULT_REMOTE_NAME {
        if repo.remote_endpoint.is_empty() {
            return Err(Error::NoDefault);
        }
        url.clone_into(&mut repo.remote_endpoint);
        transport.clone_into(&mut repo.remote_type);
    } else {
        let entry = repo
            .remotes
            .get_mut(name)
            .ok_or_else(|| Error::NotFound(name.to_owned()))?;
        url.clone_into(&mut entry.url);
        transport.clone_into(&mut entry.remote_type);
    }
    write(layout, repo)
}

/// The address of a remote. The name `default` selects the flat default
/// remote. `merged` is the merged config, because a default address can be
/// user-scoped.
///
/// # Errors
/// [`Error::NotFound`].
pub fn url_of(merged: &Config, name: &str) -> Result<String, Error> {
    let url = if name == DEFAULT_REMOTE_NAME {
        (!merged.remote_endpoint.is_empty()).then(|| merged.remote_endpoint.clone())
    } else {
        merged.remotes.get(name).map(|entry| entry.url.clone())
    };
    url.ok_or_else(|| Error::NotFound(name.to_owned()))
}

/// The remotes of the merged config.
#[must_use]
pub fn list(merged: &Config) -> Listing {
    Listing {
        default: (!merged.remote_endpoint.is_empty()).then(|| Remote {
            name: DEFAULT_REMOTE_NAME.to_owned(),
            url: merged.remote_endpoint.clone(),
            transport: merged.remote_type.clone(),
        }),
        named: merged
            .remotes
            .iter()
            .map(|(name, entry)| Remote {
                name: name.clone(),
                url: entry.url.clone(),
                transport: entry.remote_type.clone(),
            })
            .collect(),
    }
}

/// Remove a remote. The name `default` clears the flat default remote.
///
/// The remote-tracking refs and the applied-packs record go too. The
/// objects stay, because `gc` owns them. The git-bridge state stays, and the
/// operation says so. The trust of an address belongs to the user config and
/// is keyed by the address, so a removal does not touch it.
///
/// # Errors
/// [`Error::NoDefault`] or [`Error::NotFound`] when the remote does not
/// exist. [`Error::Write`].
pub fn remove(
    layout: &RepoLayout,
    repo: &mut Config,
    name: &str,
    observer: &dyn Observer<Event>,
) -> Result<(), Error> {
    if name == DEFAULT_REMOTE_NAME {
        if repo.remote_endpoint.is_empty() {
            return Err(Error::NoDefault);
        }
        repo.remote_endpoint.clear();
        repo.remote_type.clear();
        repo.remote_bucket.clear();
    } else if repo.remotes.remove(name).is_none() {
        return Err(Error::NotFound(name.to_owned()));
    }
    // Remotes nested under `name` keep their ref and bridge-state subtrees,
    // although those share the directory prefix of `name`.
    let siblings = nested_sibling_names(&repo.remotes, name);
    write(layout, repo)?;
    // A stale tracking ref would shadow a future remote of the same name.
    remove_tracking_refs(layout, name, &siblings, observer);
    if let Err(e) = AppliedPacks::remove_record(layout, name) {
        observer.event(&Event::AppliedPacksNotRemoved {
            name: name.to_owned(),
            error: e.to_string(),
        });
    }
    if layout.git_state_dir().join(name).is_dir() {
        observer.event(&Event::BridgeStateRemains {
            name: name.to_owned(),
        });
    }
    Ok(())
}

/// Rename a remote. Every branch upstream that names `old` follows the new
/// name. The tracking refs, the git-bridge state and the applied-packs record
/// follow it too.
///
/// # Errors
/// [`Error::RenameDefault`], [`Error::NameControlCharacters`],
/// [`Error::InvalidName`], [`Error::NotFound`], [`Error::AlreadyExists`] or
/// [`Error::Write`].
pub fn rename(
    layout: &RepoLayout,
    repo: &mut Config,
    old: &str,
    new: &str,
    observer: &dyn Observer<Event>,
) -> Result<(), Error> {
    if old == DEFAULT_REMOTE_NAME || new == DEFAULT_REMOTE_NAME {
        return Err(Error::RenameDefault);
    }
    validate_name(new)?;
    if !repo.remotes.contains_key(old) {
        return Err(Error::NotFound(old.to_owned()));
    }
    if repo.remotes.contains_key(new) {
        return Err(Error::AlreadyExists(new.to_owned()));
    }
    // Remotes nested under `old`, found before `new` joins the map, so that
    // `new` is never one of them even when it extends `old` (`rename a a/sub`).
    let siblings = nested_sibling_names(&repo.remotes, old);
    if let Some(entry) = repo.remotes.remove(old) {
        repo.remotes.insert(new.to_owned(), entry);
    }
    for upstream in repo.branch_upstreams.values_mut() {
        if upstream.remote == old {
            new.clone_into(&mut upstream.remote);
        }
    }
    write(layout, repo)?;

    let tracking = layout.remotes_dir();
    let protected: Vec<PathBuf> = siblings.iter().map(|s| tracking.join(s)).collect();
    if let Err(e) = move_state_dir(&tracking, old, new, &protected) {
        observer.event(&Event::TrackingRefsNotMoved {
            old: old.to_owned(),
            new: new.to_owned(),
            error: e.to_string(),
        });
    }
    let bridge = layout.git_state_dir();
    let protected: Vec<PathBuf> = siblings.iter().map(|s| bridge.join(s)).collect();
    if let Err(e) = move_state_dir(&bridge, old, new, &protected) {
        observer.event(&Event::BridgeStateNotMoved {
            old: old.to_owned(),
            new: new.to_owned(),
            error: e.to_string(),
        });
    }
    if let Err(e) = AppliedPacks::rename_record(layout, old, new) {
        observer.event(&Event::AppliedPacksNotMoved {
            old: old.to_owned(),
            new: new.to_owned(),
            error: e.to_string(),
        });
    }
    Ok(())
}

/// Move the per-remote state directory for `old` to `new` under `root`,
/// tolerating multi-segment remote names (which map to nested
/// subdirectories) on both sides, *including* the case where one name is
/// a path-prefix of the other (`a` <-> `a/b`), and *including* the case
/// where a configured sibling remote nests inside `old`'s own directory
/// prefix (`a/b` configured while `a` is renamed or removed) and
/// must not be dragged along or deleted with it. `protected` (built by
/// the caller via `nested_sibling_names` + its own root) lists the
/// absolute paths of those siblings' state directories; empty in the
/// overwhelmingly common case.
///
/// A direct `fs::rename(src, dst)` breaks on the prefix case in both
/// directions: renaming `a` to `a/b` asks the OS to move a directory into
/// its own subtree (EINVAL), and renaming `a/b` to `a` lands on the
/// non-empty old ancestor (ENOTEMPTY). Both names are valid remote names,
/// so the move has to handle them.
///
/// # Mechanism: one two-phase move through a temp sibling
///
/// The move goes through a dot-named temp directory directly under
/// `root`, `.rename.tmp.<pid>.0` — one path, no prefix-nesting or
/// protected-sibling case analysis at the call site.
///
/// Step 1 extracts `src`'s content into `tmp`:
/// - `protected.is_empty()` (no sibling in the way): a single
///   whole-directory `fs::rename(&src, &tmp)` — always legal, since
///   renaming a directory to a fresh sibling of `root` is never a move
///   into its own subtree. The common case takes exactly two renames.
/// - otherwise: `tmp` is created empty and `walk_unprotected` extracts
///   every unprotected entry under `src` into it one at a time (skipping
///   protected roots whole, recursing through their ancestors), leaving
///   each protected subtree exactly where it is — still under `src`, not
///   dragged to the equivalent position under `dst`.
///
/// Either way `tmp` ends up holding exactly what should land at `dst`.
/// Step 2 (`prune_empty_parents`) tidies `src`'s now-empty ancestors —
/// `src` itself may legitimately remain non-empty when protected content
/// stayed behind, which is the point. Step 3 creates `dst`'s parents
/// (`fs::rename` won't). Step 4 is the single `fs::rename(&tmp, &dst)`
/// that completes the move.
///
/// A missing source directory is a no-op (nothing to move).
///
/// # Restore / "parked at" contract — covers every phase, not just the
/// final rename
///
/// If anything from step 1 through step 4 fails after content has
/// actually reached `tmp`, the move backs out on a best-effort basis
/// before the error is returned, so a failed move is a clean no-op
/// rather than stranding state — the caller's existing warning then
/// fires as before, and a follow-up fetch self-heals. If `tmp` never
/// received any content (step 1 itself failed outright — `create_dir`
/// or the whole-dir rename never succeeded), there is nothing to restore
/// and the original error is returned unadorned.
///
/// The restore is one helper for both shapes: try `fs::rename(&tmp,
/// &src)` first — this succeeds outright when `src` vanished entirely
/// (the fast-path case, where nothing remains at `src` to collide with).
/// If that fails (the selective case, where `src` still exists holding
/// retained protected content, so a whole-directory rename onto it is
/// rejected), fall back to `merge_tree_into(&tmp, &src)`, which merges
/// `tmp`'s entries back into `src` one at a time, recursing into any
/// like-named retained ancestor directory instead of clobbering it.
///
/// When the restore succeeds — by either path — the original error is
/// returned as-is. The `"; state parked at <tmp>"` annotation is added
/// ONLY when the restore itself also fails, since that's the one case
/// where the plain error text says nothing about where the content
/// actually went. A `merge_tree_into` success followed by a failed
/// best-effort `remove_dir(&tmp)` cleanup does NOT count as a restore
/// failure and must NOT trigger the annotation: the
/// content is home, and a leftover (near-)empty `tmp` husk is inert
/// debris, not stranded state.
///
/// Parent creation/pruning (steps 2 and 3) are themselves best-effort:
/// a creation failure falls through to the following `rename`, which
/// then fails and is handled by the same restore path; a prune failure
/// is silent since it's tidiness, not correctness.
///
/// # Crash safety
///
/// A crash between phases leaves a `.rename.tmp.<pid>.0` directory
/// orphaned directly under `root` (the same temp-name convention as
/// `atomic::write_atomic` of `kit-core`, so crash debris is
/// grep-able by one pattern across the codebase). Unlike an empty
/// directory that this warn-only path can leave, this one may be
/// fully populated — but a dot-leading path component is invalid per
/// `validate_ref_name` (`refs::validate_ref_name`, SPEC-REFS §3), so
/// every listing enumerator (`show-ref`, `for-each-ref`,
/// `list_remote_names`) and the git-bridge `state_names` scan treat it
/// as inert rather than a phantom remote or ref namespace. The temp name
/// can't collide with any live remote's state directory either, since
/// remote names are validated dot-free (`validate_remote_name`). The
/// "name" component is the fixed literal `rename` rather than
/// `old`/`new`: those may be multi-segment remote names
/// (`team/upstream`), and embedding a `/` into a single path component
/// here would make `root.join(...)` build a *nested* path instead of a
/// flat sibling, defeating the one-temp-dir-directly-under-`root`
/// invariant this whole function relies on. The suffix is fixed at `.0`
/// rather than reusing `atomic`'s process-wide counter (private to
/// `kit-core`, unreachable from this crate) because a single call
/// creates and consumes at most one temp dir before returning, so
/// nothing within one call can collide with it.
///
/// # Adopted edge case
///
/// A protected root that exists as a plain *file* (a branch-path /
/// remote-name collision inherent to the directory-keyed layout) is adopted into the protection set by
/// `walk_unprotected`'s exact-path check and left untouched — the safe
/// direction for an input this function doesn't otherwise reason about.
///
/// # Destination-side nesting boundary
///
/// `protected` is always computed by the caller from `old`
/// (`nested_sibling_names(remotes, old)`), never from `new`. When a
/// configured sibling instead nests under the DESTINATION — `rename a/b
/// a` while `a/x` is configured, or `rename a a/b` while `a/b/c` is
/// configured — this function has no way to see that from `old` alone,
/// so it takes the ordinary fast or selective path as if no sibling were
/// involved, and the final `fs::rename(&tmp, &dst)` lands on `dst`'s
/// already-occupied directory and fails closed: the restore contract
/// above fires, the caller's standard warning is emitted, and the
/// source state is intact rather than merged into the sibling's
/// directory or dragging it along. This is a deliberate boundary, not a
/// bug. Destination-side protection (siblings of `new` too) is out of
/// scope, and a unit test pins this shape.
fn move_state_dir(root: &Path, old: &str, new: &str, protected: &[PathBuf]) -> std::io::Result<()> {
    let (src, dst) = (root.join(old), root.join(new));
    if !src.is_dir() {
        return Ok(());
    }
    let tmp = root.join(format!(".rename.tmp.{}.0", std::process::id()));

    let extracted = if protected.is_empty() {
        std::fs::rename(&src, &tmp)
    } else {
        std::fs::create_dir(&tmp).and_then(|()| {
            walk_unprotected(&src, protected, &mut |entry: &Path| {
                // `entry` always came from `read_dir(src)` (directly, or
                // via a recursive `walk_unprotected` call rooted at an
                // ancestor under `src`), so it is always under `src` —
                // never leave an entry behind on the strength of a
                // silently-ignored mismatch here.
                let rel = entry
                    .strip_prefix(&src)
                    .expect("walk_unprotected only ever yields entries located under src");
                let target = tmp.join(rel);
                if let Some(parent) = target.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::rename(entry, &target)
            })
        })
    };

    let result = extracted.and_then(|()| {
        prune_empty_parents(&src, root);
        if let Some(parent) = dst.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        std::fs::rename(&tmp, &dst)
    });

    let Err(e) = result else {
        return Ok(());
    };
    if !tmp.exists() {
        // Step 1 never got as far as creating/populating `tmp`: `src`
        // is untouched, so there is nothing to restore.
        return Err(e);
    }
    let _ = std::fs::create_dir_all(&src);
    if std::fs::rename(&tmp, &src).is_ok() {
        return Err(e);
    }
    if merge_tree_into(&tmp, &src).is_err() {
        // The restore itself failed too: state is now parked at `tmp`,
        // not `src`. Say so — the original error alone doesn't tell the
        // caller (and its warning) where the state actually ended up.
        return Err(std::io::Error::new(
            e.kind(),
            format!("{e}; state parked at {}", tmp.display()),
        ));
    }
    // Merge succeeded: the state is home. `tmp` is now an inert
    // (near-)empty husk; best-effort cleanup only — its failure is
    // tidiness debris, not stranded state, so the annotation above must
    // not fire for it.
    let _ = std::fs::remove_dir(&tmp);
    Err(e)
}

/// Walk up from `dir`, removing empty directories, until `root` is
/// reached or a removal fails (a non-empty directory is the natural
/// terminator — no need to distinguish that from other errors).
fn prune_empty_parents(dir: &Path, root: &Path) {
    let mut dir = dir.parent();
    while let Some(d) = dir {
        if d == root || std::fs::remove_dir(d).is_err() {
            break;
        }
        dir = d.parent();
    }
}

/// Configured remote names that are proper extensions of `name`
/// (`name + "/"` prefix): the subtrees under `name`'s state directories
/// that actually belong to OTHER configured remotes and must survive a
/// rename/remove of `name`. Empty in the overwhelmingly common
/// case, in which callers take the whole-directory fast path.
fn nested_sibling_names(remotes: &BTreeMap<String, RemoteEntry>, name: &str) -> Vec<String> {
    let prefix = format!("{name}/");
    remotes
        .keys()
        .filter(|k| k.starts_with(&prefix))
        .cloned()
        .collect()
}

/// Visit the entries of `dir` bottom-up, skipping any entry that IS a
/// protected root (left untouched — not handed to `f`, not recursed
/// into) and recursing into any entry that is an ANCESTOR of a
/// protected root; every other entry is handed to `f` whole, since its
/// subtree cannot contain a protected path. After visiting, `dir`
/// itself is opportunistically removed via `remove_dir`: success means
/// every unprotected entry left and no protected subtree remains
/// beneath it; failure (non-empty) is the natural terminator, not an
/// error, mirroring `prune_empty_parents`.
///
/// The entry list is snapshotted with one `read_dir` before any
/// mutation happens, so a destination created inside `dir` by `f`
/// itself (a rename into `dir`'s own subtree) is never iterated.
///
/// A missing `dir` is a no-op, matching the fast paths this is an
/// alternative to. Like every other helper on these rename/remove
/// paths, failure is best-effort: the first error from `f` (or from
/// `read_dir`) aborts the walk immediately and propagates to the
/// caller's existing warn-only handling — partial state is acceptable
/// here and self-heals on the next fetch.
fn walk_unprotected(
    dir: &Path,
    protected: &[PathBuf],
    f: &mut dyn FnMut(&Path) -> std::io::Result<()>,
) -> std::io::Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }
    let entries: Vec<PathBuf> = std::fs::read_dir(dir)?
        .map(|e| e.map(|e| e.path()))
        .collect::<std::io::Result<_>>()?;
    for entry in entries {
        if protected.iter().any(|p| p == &entry) {
            // `entry` IS a protected root: leave it, and everything
            // beneath it, entirely alone.
            continue;
        }
        if protected.iter().any(|p| p.starts_with(&entry)) {
            // `entry` is an ancestor of some protected root: recurse so
            // its unprotected children are still visited individually.
            walk_unprotected(&entry, protected, f)?;
        } else {
            // No protected path can live under `entry` — hand it to `f`
            // whole.
            f(&entry)?;
        }
    }
    let _ = std::fs::remove_dir(dir);
    Ok(())
}

/// Restore helper for `move_state_dir`'s occupied-destination /
/// mid-extraction failure: moves every entry under `from` into `into`,
/// recursing into any like-named directory that already exists at the
/// destination (needed because `into` — `src` — may have retained
/// ancestor directories of protected content that a moved entry's
/// relative path nests under) and renaming everything
/// else directly. Not a general merge utility: used only to put
/// `move_state_dir`'s temp contents back where they came from.
fn merge_tree_into(from: &Path, into: &Path) -> std::io::Result<()> {
    // Snapshot the entry list before any mutation, the same discipline
    // as `walk_unprotected`: recursing into a
    // like-named destination directory below mutates `into`, and a
    // naive un-snapshotted `read_dir(from)` iterator is only required to
    // reflect entries present at some unspecified point during the
    // scan, not to ignore ones renamed away out from under it mid-walk.
    let entries: Vec<PathBuf> = std::fs::read_dir(from)?
        .map(|e| e.map(|e| e.path()))
        .collect::<std::io::Result<_>>()?;
    for path in entries {
        let name = path
            .file_name()
            .expect("read_dir entries always have a file name");
        let target = into.join(name);
        if path.is_dir() && target.is_dir() {
            merge_tree_into(&path, &target)?;
            std::fs::remove_dir(&path)?;
        } else {
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::rename(&path, &target)?;
        }
    }
    Ok(())
}

/// Remove `refs/remotes/<name>/`.
///
/// `siblings` lists the configured remote names nested under `name`. When it
/// is empty, the whole directory goes. Otherwise a selective walk deletes the
/// entries that are not on the path of a sibling, so the refs of `a/b` survive
/// the removal of `a`.
fn remove_tracking_refs(
    layout: &RepoLayout,
    name: &str,
    siblings: &[String],
    observer: &dyn Observer<Event>,
) {
    let root = layout.remotes_dir();
    let dir = root.join(name);
    let protected: Vec<PathBuf> = siblings.iter().map(|s| root.join(s)).collect();
    let result = if protected.is_empty() {
        if dir.is_dir() {
            std::fs::remove_dir_all(&dir)
        } else {
            Ok(())
        }
    } else {
        walk_unprotected(&dir, &protected, &mut |entry: &Path| {
            if entry.is_dir() {
                std::fs::remove_dir_all(entry)
            } else {
                std::fs::remove_file(entry)
            }
        })
    };
    if let Err(e) = result {
        observer.event(&Event::TrackingRefsNotRemoved {
            name: name.to_owned(),
            error: e.to_string(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::{PathBuf, walk_unprotected};

    fn touch(path: &std::path::Path) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, b"x").unwrap();
    }

    #[test]
    fn protected_root_is_left_untouched() {
        let td = tempfile::tempdir().unwrap();
        let root = td.path();
        touch(&root.join("keep/marker.txt"));
        touch(&root.join("drop.txt"));
        let protected = vec![root.join("keep")];
        let mut visited = Vec::new();
        walk_unprotected(root, &protected, &mut |p| {
            visited.push(p.to_path_buf());
            if p.is_dir() {
                std::fs::remove_dir_all(p)
            } else {
                std::fs::remove_file(p)
            }
        })
        .unwrap();
        assert!(
            root.join("keep/marker.txt").exists(),
            "protected subtree must survive whole"
        );
        assert!(
            !root.join("drop.txt").exists(),
            "unprotected entry must be visited and removed"
        );
        assert_eq!(visited, vec![root.join("drop.txt")]);
    }

    #[test]
    fn ancestor_of_protected_root_is_recursed_not_removed_whole() {
        let td = tempfile::tempdir().unwrap();
        let root = td.path();
        touch(&root.join("a/b/c/marker.txt")); // protected root is a/b/c
        touch(&root.join("a/other.txt")); // unprotected sibling under ancestor `a`
        let protected = vec![root.join("a/b/c")];
        let mut visited = Vec::new();
        walk_unprotected(root, &protected, &mut |p| {
            visited.push(p.to_path_buf());
            if p.is_dir() {
                std::fs::remove_dir_all(p)
            } else {
                std::fs::remove_file(p)
            }
        })
        .unwrap();
        assert!(
            root.join("a/b/c/marker.txt").exists(),
            "deeply nested protected root must survive"
        );
        assert!(
            !root.join("a/other.txt").exists(),
            "unprotected file under the ancestor must be removed"
        );
        assert_eq!(visited, vec![root.join("a/other.txt")]);
        // `a` and `a/b` survive only because `a/b/c` remains beneath them
        // — proof the ancestor dirs were recursed into, not deleted
        // whole, and that they are NOT force-pruned once emptied of
        // unprotected content.
        assert!(root.join("a").is_dir());
        assert!(root.join("a/b").is_dir());
    }

    #[test]
    fn snapshot_is_taken_before_any_mutation() {
        // Mirrors a rename into the walked directory's own subtree:
        // `f` creates a NEW entry inside `dir` as a side effect. That
        // entry must never be visited by this same walk, since the
        // entry list was snapshotted up front.
        let td = tempfile::tempdir().unwrap();
        let root = td.path();
        touch(&root.join("existing.txt"));
        let protected: Vec<PathBuf> = Vec::new();
        let mut visited = Vec::new();
        walk_unprotected(root, &protected, &mut |p| {
            visited.push(p.to_path_buf());
            std::fs::write(root.join("created-during-walk.txt"), b"new").unwrap();
            std::fs::remove_file(p)
        })
        .unwrap();
        assert_eq!(visited, vec![root.join("existing.txt")]);
        assert!(
            root.join("created-during-walk.txt").exists(),
            "entry created mid-walk must not be picked up by the same walk"
        );
    }

    #[test]
    fn dir_is_removed_bottom_up_after_its_entries_are_individually_processed() {
        let td = tempfile::tempdir().unwrap();
        let root = td.path();
        let sub = root.join("a");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(sub.join("one.txt"), b"1").unwrap();
        std::fs::write(sub.join("two.txt"), b"2").unwrap();
        let protected: Vec<PathBuf> = Vec::new();
        walk_unprotected(&sub, &protected, &mut |p| {
            assert!(
                p.is_file(),
                "each entry is handed to f individually, never the dir itself"
            );
            std::fs::remove_file(p)
        })
        .unwrap();
        // `f` only ever saw the two files; `sub`'s own removal is the
        // walker's bottom-up cleanup once it is empty, not something
        // `f` did.
        assert!(
            !sub.exists(),
            "now-empty dir must be removed by the walk itself"
        );
    }
}
