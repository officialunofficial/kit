//! Import of a git upstream under an importer key (SPEC-GIT-IMPORT).
//!
//! An import clones a bare staging repository under
//! `.kit/git/<remote>/repo.git` and translates it through the bridge under a
//! dedicated import key. The key is pinned in the state directory. Branches
//! land in `refs/remotes/<remote>/*`. The fresh-clone form also makes
//! `refs/heads/<default>` and checks it out. The import keeps the raw commit
//! and tag bytes and mints one `git-import/v1` attestation for each head.
//!
//! [`fetch`] updates the tracking refs only. With its `pull` flag it also
//! fast-forwards the current branch. Local work joins the imported history
//! through a native `kit merge <remote>/<branch>`.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use kit_attest::Signer as _;
use kit_attest::{Envelope, PAYLOAD_TYPE_IN_TOTO, Sig, statement, store as attest_store};
use kit_core::layout::{self, RepoLayout};
use kit_core::object::{Object, ObjectType};
use kit_core::observer::Observer;
use kit_core::refs::{self, RefWriteCondition};
use kit_core::sign::{KeyPair, sign_commit, sign_tag};
use kit_core::store::BulkWriter;
use kit_core::{Hash, ObjectStore};
use kit_git_bridge::error::BridgeError;
use kit_git_bridge::gitobj::{Sha1Id, bytes_hex, sha1_hex};
use kit_git_bridge::gitsrc::{self, CatFileBatch};
use kit_git_bridge::import::{
    DepthMemo, IMPORT_SPEC_VERSION, ImportOptions, ImportSigner, Importer, MAX_TAG_CHAIN,
    ObjectSink,
};
use kit_git_bridge::map::{self, Direction};
use kit_git_bridge::remoteid::{attestation_remote, remote_identity};

use super::state::read_stamp;
use super::{
    Class, Error, Event, LockEvents, Skipped, git_in, git_version, json_escape, lock_state, plain,
    step, validate_url,
};

/// The predicate type of an import attestation (SPEC-GIT-IMPORT §5).
pub const PREDICATE_TYPE: &str = "https://kit.storage/spec/predicate/git-import/v1";

/// The default import key file, under the common directory
/// (SPEC-GIT-IMPORT §4).
const IMPORT_KEY_FILE: &str = "keys/git-import.key";

/// Crash marker: present while a bulk import session is open; found
/// at start ⇒ the previous session crashed ⇒ discard the map cache
/// (objects may be torn; the map must not vouch for them).
const IMPORTING_MARKER: &str = "importing";

/// What to import.
#[derive(Debug, Clone, Copy)]
pub struct Request<'a> {
    /// The git URL or the local path of the upstream.
    pub url: &'a str,
    /// The remote name of the state directory.
    pub remote_name: &'a str,
    /// The import key file. With none, the key of the repository, which the
    /// first import makes.
    pub key: Option<&'a Path>,
}

/// What to fetch again.
#[derive(Debug, Clone, Copy)]
pub struct FetchRequest<'a> {
    /// The remote name of the state directory.
    pub remote_name: &'a str,
    /// The import key file. With none, the pinned key of the repository.
    pub key: Option<&'a Path>,
}

/// One ref of the upstream after the import.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Imported {
    /// The upstream ref name.
    pub ref_name: String,
    /// The git id of the head.
    pub git_id: Sha1Id,
    /// The kit hash of the head.
    pub kit_hash: Hash,
}

/// The result of an import.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary {
    /// The refs that the import translated or found unchanged.
    pub imported: Vec<Imported>,
    /// The refs that the import skipped.
    pub skipped: Vec<Skipped>,
    /// Whether the import normalized historic tree modes.
    pub normalized: bool,
    /// The branch that the fresh clone checked out.
    pub checked_out: Option<String>,
    /// The branch that a pull fast-forwarded.
    pub pulled: Option<String>,
}

/// Import into a new repository at `dir` and check out the default branch of
/// the upstream.
///
/// A failure removes what this call made, so a corrected retry does not meet
/// "destination already exists". The call removes the directory itself only
/// when it made the directory.
///
/// # Errors
/// An error when `dir` is not empty, when the request or the recorded state
/// contradict each other, or when `git` or the translation fails.
pub fn clone(
    dir: &Path,
    request: &Request<'_>,
    observer: &dyn Observer<Event>,
) -> Result<Summary, Error> {
    validate_url(request.url)?;
    if dir.exists() && std::fs::read_dir(dir).map_or(true, |mut d| d.next().is_some()) {
        return Err(Error::DestinationExists(dir.display().to_string()));
    }
    let created = !dir.exists();
    std::fs::create_dir_all(dir).map_err(|e| step(Class::CannotCreate, "mkdir", e))?;
    let layout = layout::discover(dir).map_err(Error::Discover)?;
    ObjectStore::init(&layout).map_err(|e| step(Class::CannotCreate, "init", e))?;
    refs::init(&layout).map_err(|e| step(Class::CannotCreate, "refs init", e))?;
    let mut summary = match import_into(&layout, request, false, observer) {
        Ok(summary) => summary,
        Err(e) => {
            // The directory itself may carry meaning when it existed:
            // ownership, mode, a mount point. Remove its contents only.
            if created {
                let _ = std::fs::remove_dir_all(dir);
            } else if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let p = entry.path();
                    let _ = if p.is_dir() {
                        std::fs::remove_dir_all(&p)
                    } else {
                        std::fs::remove_file(&p)
                    };
                }
            }
            return Err(e);
        }
    };

    // Check out the upstream default branch.
    let staging = map::state_dir(&layout, request.remote_name)
        .map_err(|e| plain(Class::Usage, e))?
        .join("repo.git");
    let default = gitsrc::default_branch(&staging)
        .map_err(|e| step(Class::General, "default branch", e))?
        .and_then(|r| r.strip_prefix("refs/heads/").map(str::to_owned));
    if let Some(branch) = default
        && let Some(head) = refs::read_remote_ref(&layout, request.remote_name, &branch)
            .map_err(|e| step(Class::General, "read tracking ref", e))?
    {
        checkout_initial(&layout, &branch, &head)?;
        summary.checked_out = Some(branch);
    }
    Ok(summary)
}

/// Import into the repository at `layout`. The import writes tracking refs
/// and tags only.
///
/// # Errors
/// An error when the request or the recorded state contradict each other, or
/// when `git` or the translation fails.
pub fn import(
    layout: &RepoLayout,
    request: &Request<'_>,
    observer: &dyn Observer<Event>,
) -> Result<Summary, Error> {
    import_into(layout, request, true, observer)
}

/// Fetch the new commits of an upstream that an import recorded. With `pull`,
/// also fast-forward the current branch from its tracking ref.
///
/// # Errors
/// An error when the remote name has no import state, when `git` or the
/// translation fails, or when the pull would not fast-forward.
pub fn fetch(
    layout: &RepoLayout,
    request: &FetchRequest<'_>,
    pull: bool,
    observer: &dyn Observer<Event>,
) -> Result<Summary, Error> {
    let state = map::state_dir(layout, request.remote_name).map_err(|e| plain(Class::Usage, e))?;
    if read_source(&state)?.is_none() {
        return Err(Error::NoImportState(request.remote_name.to_owned()));
    }
    // Re-fetch through the staging mirror's own recorded origin (the
    // canonical identity strips `.git`, so it is NOT a fetch URL).
    let origin = git_in(
        &state.join("repo.git"),
        &["config", "--get", "remote.origin.url"],
    )
    .map(|s| s.trim().to_owned())
    .map_err(|e| step(Class::General, "staging origin", e))?;
    let mut summary = import_into(
        layout,
        &Request {
            url: &origin,
            remote_name: request.remote_name,
            key: request.key,
        },
        true,
        observer,
    )?;
    if pull {
        summary.pulled = fast_forward_current(layout, request.remote_name, observer)?;
    }
    Ok(summary)
}

fn checkout_initial(layout: &RepoLayout, branch: &str, head: &Hash) -> Result<(), Error> {
    let store = ObjectStore::open(layout).map_err(|e| step(Class::General, "open store", e))?;
    let tree = match store.read_object(head) {
        Ok(Object::Commit(c)) => c.tree_hash,
        _ => return Err(plain(Class::Data, "imported head is not a commit")),
    };
    refs::write_ref_recording_history(layout, branch, RefWriteCondition::Missing, head)
        .map_err(|e| step(Class::CannotCreate, "write branch", e))?;
    refs::write_head_branch(layout, branch)
        .map_err(|e| step(Class::CannotCreate, "write HEAD", e))?;
    kit_sync::worktree::restore_worktree_and_index(layout, &store, tree)
        .map_err(|e| step(Class::General, "checkout", e))?;
    Ok(())
}

/// Import/refresh into an existing repo: tracking refs + tags only.
fn import_into(
    layout: &RepoLayout,
    request: &Request<'_>,
    require_repo: bool,
    observer: &dyn Observer<Event>,
) -> Result<Summary, Error> {
    if require_repo {
        ObjectStore::open(layout).map_err(Error::OpenRepository)?;
    }
    git_version()?;

    validate_url(request.url)?;

    let state = map::state_dir(layout, request.remote_name).map_err(|e| plain(Class::Usage, e))?;
    // One bridge operation per state dir at a time: concurrent runs
    // would race the crash marker / map discard / bulk session.
    let _state_lock = lock_state(layout, request.remote_name)?;
    // VALIDATE existing bindings before any network/disk work, but
    // RECORD new ones only after the clone + sha256 check succeed: a
    // typo'd URL must not permanently burn the state name (there is
    // no CLI command to unbind it).
    validate_import_bindings(layout, &state, request.url)?;
    let kp = load_or_create_import_key(layout, request.key, observer)?;
    if let Some(pinned) = map::read_signer(&state).map_err(|e| plain(Class::Config, e))?
        && pinned != kp.public.0
    {
        // Surface the §4 designated-importer refusal before the clone.
        // Deliberately NOT an unconditional bind_signer call: that
        // would WRITE a fresh pin pre-clone, violating the
        // validate-then-bind contract (the pin is recorded with the
        // other bindings only after the clone succeeds).
        map::bind_signer(&state, &kp.public.0).map_err(|e| plain(Class::Config, e))?;
    }

    // Staging mirror: clone once, fetch thereafter. Local paths must
    // be absolutized — the clone runs `git -C <state>`, which would
    // resolve a relative path against the state dir.
    let clone_url = absolutize_clone_url(request.url);
    let staging = state.join("repo.git");
    // The state dir itself is just a directory (bindings come after a
    // successful clone); `git -C <state>` needs it to exist.
    std::fs::create_dir_all(&state)
        .map_err(|e| step(Class::CannotCreate, "create state dir", e))?;
    if staging.join("objects").is_dir() {
        // Explicit refspecs (not the mirror's +refs/*:refs/*) so
        // --prune is scoped to upstream namespaces: fork-mode export
        // state living in this repo (refs/kit-export/*, the
        // attestation chain ref) must survive an upstream fetch.
        git_in(
            &staging,
            &[
                "fetch",
                "--quiet",
                "--prune",
                "origin",
                "+refs/heads/*:refs/heads/*",
                "+refs/tags/*:refs/tags/*",
            ],
        )
        .map_err(|e| step(Class::Unavailable, "fetch upstream", e))?;
    } else {
        git_in(
            state.as_path(),
            &["clone", "--bare", "--quiet", &clone_url, "repo.git"],
        )
        .map_err(|e| step(Class::Unavailable, "clone upstream", e))?;
    }
    if gitsrc::is_sha256_repo(&staging).map_err(|e| plain(Class::General, e))? {
        return Err(plain(
            Class::Data,
            "SHA-256 repositories are out of scope for git-import v1 (SPEC-GIT-IMPORT §2)",
        ));
    }
    // Clone validated — NOW record the bindings.
    bind_import_state(layout, &state, request.url)?;
    map::bind_signer(&state, &kp.public.0).map_err(|e| plain(Class::Config, e))?;
    translate_upstream(layout, &state, &staging, request, &kp, observer)
}

/// Read-only twin of [`bind_import_state`]: refuse direction/source
/// mismatches without writing anything.
fn validate_import_bindings(layout: &RepoLayout, state: &Path, url: &str) -> Result<(), Error> {
    match map::read_direction(state).map_err(|e| plain(Class::General, e))? {
        None | Some(Direction::Import | Direction::Fork) => {}
        Some(other) => {
            return Err(plain(
                Class::Usage,
                format!(
                    "state dir is bound to direction '{}' (one direction per state dir)",
                    other.as_str()
                ),
            ));
        }
    }
    let identity = remote_identity(url);
    match read_stamp(&state.join("source")) {
        Ok(recorded) if recorded.trim() != identity => Err(state_bound(state, &recorded, url)),
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if let Some(other) = other_state_with_source(layout, state, &identity) {
                return Err(Error::DuplicateImport {
                    url: url.to_owned(),
                    other,
                });
            }
            Ok(())
        }
        Err(e) => Err(step(Class::General, "read source binding", e)),
    }
}

fn state_bound(state: &Path, recorded: &str, url: &str) -> Error {
    Error::StateBound {
        name: state
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned(),
        recorded: recorded.trim().to_owned(),
        target: url.to_owned(),
    }
}

/// FF the current branch from its tracking ref (native machinery).
fn fast_forward_current(
    layout: &RepoLayout,
    remote: &str,
    observer: &dyn Observer<Event>,
) -> Result<Option<String>, Error> {
    let store = ObjectStore::open(layout).map_err(|e| step(Class::General, "open store", e))?;
    let Ok(refs::Head::Branch(branch)) = refs::read_head(layout) else {
        return Ok(None); // detached/unborn: fetch-only semantics
    };
    let Some(target) = refs::read_remote_ref(layout, remote, &branch)
        .map_err(|e| step(Class::General, "read tracking ref", e))?
    else {
        return Ok(None);
    };
    let Some(current) =
        refs::read_ref(layout, &branch).map_err(|e| step(Class::General, "read branch", e))?
    else {
        return Ok(None);
    };
    if current == target {
        return Ok(None);
    }
    // A missing commit would read as "not a fast-forward", so the walk reads
    // every commit and names the one it cannot read.
    let ancestor = kit_core::ops::merge::is_ancestor_strict(&store, current, target)
        .map_err(|e| step(Class::Data, "ancestry", e))?;
    if !ancestor {
        return Err(Error::PullNotFastForward {
            branch,
            remote: remote.to_owned(),
        });
    }
    let tree = match store.read_object(&target) {
        Ok(Object::Commit(c)) => c.tree_hash,
        _ => return Err(plain(Class::Data, "tracking ref is not a commit")),
    };
    // Same discipline as native pull: the worktree lock spans safety
    // check → ref write → restore, so a concurrent commit/checkout
    // cannot interleave after the safety check; a failed restore rolls
    // the branch ref back instead of leaving it advanced over a stale
    // worktree.
    let _wt_lock = crate::lock::acquire_worktree(layout, &LockEvents(observer))
        .map_err(Error::WorktreeBusy)?;
    kit_sync::worktree::ensure_restore_safe(layout, &store, tree)
        .map_err(|e| plain(Class::General, e))?;
    refs::write_ref_recording_history(layout, &branch, RefWriteCondition::Match(current), &target)
        .map_err(|e| step(Class::CannotCreate, "advance branch", e))?;
    if let Err(e) = kit_sync::worktree::restore_worktree_and_index(layout, &store, tree) {
        let rollback = refs::write_ref_recording_history(
            layout,
            &branch,
            RefWriteCondition::Match(target),
            &current,
        );
        let extra = match rollback {
            Ok(()) => String::new(),
            Err(rb) => format!("; additionally failed to roll back the branch ref: {rb}"),
        };
        return Err(plain(Class::General, format!("{e}{extra}")));
    }
    Ok(Some(branch))
}

/// Bulk sink: deferred-fsync writes + the kind probe the tag path
/// needs (without `kind_of`, chunked tag targets
/// misclassify and fork hashes between sink choices).
struct BulkSink<'a> {
    bw: BulkWriter<'a>,
    store: &'a ObjectStore,
}

impl ObjectSink for BulkSink<'_> {
    fn write_object(&mut self, bytes: &[u8]) -> Result<Hash, BridgeError> {
        self.bw
            .write(bytes)
            .map_err(|e| BridgeError::Source(format!("bulk write: {e}")))
    }

    fn reuse_object(&mut self, h: &Hash) -> Result<Vec<Hash>, BridgeError> {
        self.bw
            .reuse_object(h)
            .map_err(|e| BridgeError::Source(format!("bulk reuse: {e}")))
    }

    fn kind_of(&self, h: &Hash) -> Option<ObjectType> {
        self.store.read_object(h).ok().map(|o| o.object_type())
    }
}

#[allow(clippy::too_many_lines)] // linear pipeline; stages are commented
fn translate_upstream(
    layout: &RepoLayout,
    state: &Path,
    staging: &Path,
    request: &Request<'_>,
    kp: &KeyPair,
    observer: &dyn Observer<Event>,
) -> Result<Summary, Error> {
    let store = ObjectStore::open(layout).map_err(|e| step(Class::General, "open store", e))?;

    // Crash marker: a leftover marker means torn objects may exist
    // that the (durably-fsynced) map still vouches for — discard the
    // map and re-translate EVERY ref from scratch (per-key determinism
    // reproduces the exact same hashes, SPEC-GIT-IMPORT §1.2).
    // refs-import is KEPT: its hashes are reproducible (it cannot
    // vouch for torn objects) and it carries memory the surrounding
    // logic needs — tag ownership for the clobber guard and the prune
    // baseline for upstream deletions. The recovery pass instead
    // bypasses its unchanged-ref short-circuit and rev-list
    // exclusions below, so the map is fully rebuilt.
    let marker = state.join(IMPORTING_MARKER);
    let mut recovering = marker.exists();
    if recovering {
        let _ = std::fs::remove_file(state.join("map"));
        observer.event(&Event::ImportInterrupted);
    }

    let mut sha_map =
        map::load_map_inverse(state).map_err(|e| step(Class::General, "load map", e))?;
    let prior_state =
        map::load_import_ref_state(state).map_err(|e| step(Class::General, "load ref state", e))?;
    // The map is a DISPOSABLE cache (§12.3): refs recorded with a
    // missing OR partially-corrupt map behind them (no crash marker)
    // must trigger the full rebuild — surviving lines of a corrupt
    // file are not evidence the rest exists, and the unchanged-ref
    // short-circuit would otherwise leave holes a later passthrough
    // export turns into re-translated history.
    let map_intact = map::map_is_intact(state).map_err(|e| plain(Class::General, e))?;
    // Tip-presence check: every recorded ref tip is appended to the
    // map BEFORE the ref state persists, so a recorded tip with no
    // map entry means the map tail was lost (truncation at a clean
    // line boundary parses as intact).
    let tips_mapped = prior_state
        .iter()
        .all(|st| sha_map.contains_key(&st.git_id));
    if !recovering
        && (!map_intact || !tips_mapped || (sha_map.is_empty() && !prior_state.is_empty()))
    {
        recovering = true;
        let _ = std::fs::remove_file(state.join("map"));
        sha_map.clear();
        observer.event(&Event::MapRebuilt);
    }

    let upstream_refs = gitsrc::list_refs(staging).map_err(|e| plain(Class::General, e))?;

    // In-store divergence probe (SPEC-GIT-IMPORT §6.1, content side):
    // bounded walk-back digests vs existing commits under other keys.
    // Only on FIRST contact (empty map = fresh import or post-crash
    // rebuild): afterwards the pinned key + bound source already
    // guarantee consistency, and the probe scans the whole store —
    // too heavy for every routine fetch.
    if sha_map.is_empty() {
        divergence_probe(&store, staging, &upstream_refs, &kp.public.0)?;
    }

    // Written only now, after the read-only probe: the marker brackets
    // exactly the window where torn objects can exist (store writes
    // until the map/ref-state commit below).
    write_durable(&marker, b"").map_err(|e| step(Class::CannotCreate, "marker", e))?;

    let direction = map::read_direction(state)
        .map_err(|e| plain(Class::General, e))?
        .unwrap_or(Direction::Import);
    let fork_mode = direction == Direction::Fork;

    let mut batch = CatFileBatch::open(staging).map_err(|e| plain(Class::Unavailable, e))?;
    let mut sink = BulkSink {
        bw: store.bulk_writer(),
        store: &store,
    };
    let raw_dir = state.join("raw");
    let mut raw_dirs: HashSet<PathBuf> = HashSet::new();
    let mut retain = |id: &Sha1Id, raw: &[u8]| -> Result<(), BridgeError> {
        let hex = sha1_hex(id);
        let dir = raw_dir.join(&hex[..2]);
        std::fs::create_dir_all(&dir)?;
        let path = dir.join(&hex[2..]);
        // Temp + content-fsync + rename: a torn final file would be
        // permanent (the exists() short-circuit is what makes re-runs
        // cheap, so the final path must never hold partial bytes).
        if !path.exists() {
            let tmp = dir.join(format!(".{}.tmp", &hex[2..]));
            {
                use std::io::Write as _;
                let mut f = std::fs::File::create(&tmp)?;
                f.write_all(raw)?;
                f.sync_all()?;
            }
            std::fs::rename(&tmp, &path)?;
        }
        // Collect the dir even when the file already existed: a
        // previous crashed run may have renamed it without ever
        // reaching the batch dir-fsync.
        raw_dirs.insert(dir);
        Ok(())
    };
    let public = kp.public.0;
    let mut sc = |c: &kit_core::object::Commit| {
        Ok(sign_commit(c, kp)
            .map_err(|e| BridgeError::Source(e.to_string()))?
            .0)
    };
    let mut st = |t: &kit_core::object::Tag| {
        Ok(sign_tag(t, kp)
            .map_err(|e| BridgeError::Source(e.to_string()))?
            .0)
    };

    let prior_by_ref: HashMap<&str, &map::RefState> = prior_state
        .iter()
        .map(|s| (s.ref_name.as_str(), s))
        .collect();
    // Exclusions must still exist in the mirror: after an upstream
    // force-push plus gc, a pruned old tip would make `rev-list ^tip`
    // abort every future fetch ("fatal: bad object"). A recovery pass
    // excludes nothing — the discarded map must be rebuilt over the
    // FULL history (and the empty exclusion set keeps rev-list's
    // parents-first order covering every commit, recursion depth 1).
    let exclude: Vec<Sha1Id> = if recovering {
        Vec::new()
    } else {
        prior_state
            .iter()
            .map(|s| s.git_id)
            .filter(|id| gitsrc::object_exists(staging, id).unwrap_or(false))
            .collect()
    };

    let mut imported: Vec<Imported> = Vec::new();
    let mut skipped: Vec<Skipped> = Vec::new();
    let mut all_pairs: Vec<(Sha1Id, Hash)> = Vec::new();
    let mut normalized = false;
    let mut depth_memo = DepthMemo::default();

    for uref in &upstream_refs {
        // Ref-name legality on the kit side (grammar + tags).
        let kit_legal = if let Some(b) = uref.name.strip_prefix("refs/heads/") {
            refs::validate_ref_name(b)
        } else if let Some(t) = uref.name.strip_prefix("refs/tags/") {
            refs::validate_ref_name(t)
        } else {
            false
        };
        if !kit_legal {
            let reason = format!("ref name {:?} is outside the kit ref grammar", uref.name);
            skip(observer, &mut skipped, &uref.name, reason);
            continue;
        }
        // Unchanged since last import? (Never during recovery: the
        // recorded tip is fine but the discarded map must be rebuilt
        // by actually re-translating the ref's closure.)
        if !recovering
            && let Some(prev) = prior_by_ref.get(uref.name.as_str())
            && prev.git_id == uref.id
        {
            imported.push(Imported {
                ref_name: uref.name.clone(),
                git_id: uref.id,
                kit_hash: prev.kit_hash,
            });
            continue;
        }
        // Translate: commits in topo order (no deep recursion), then
        // the tip object itself (tag objects ride on top).
        let commit_tip = uref.peeled.unwrap_or(uref.id);
        let order = gitsrc::rev_list(staging, &[commit_tip], &exclude)
            .map_err(|e| plain(Class::General, e))?;
        let mut imp = Importer {
            source: &mut batch,
            sink: &mut sink,
            signer: ImportSigner {
                public,
                sign_commit: &mut sc,
                sign_tag: &mut st,
            },
            map: &mut sha_map,
            retain_raw: &mut retain,
            options: ImportOptions { fork_mode },
            depth_memo: std::mem::take(&mut depth_memo),
        };
        // Pairs are caller-owned and persisted EVEN when the ref
        // refuses: the sink already wrote those objects, and a later
        // ref sharing the history memo-hits without re-emitting them.
        let mut ref_pairs: Vec<(Sha1Id, Hash)> = Vec::new();
        let result = imp.import_commits(&order, &uref.id, &mut ref_pairs, &mut normalized);
        depth_memo = imp.depth_memo;
        all_pairs.extend_from_slice(&ref_pairs);
        match result {
            Ok(head) if uref.name.starts_with("refs/heads/") && !peels_to_commit(&store, &head) => {
                let reason = "branch tip is not a commit or a tag of a commit".to_owned();
                skip(observer, &mut skipped, &uref.name, reason);
            }
            Ok(head) => imported.push(Imported {
                ref_name: uref.name.clone(),
                git_id: uref.id,
                kit_hash: head,
            }),
            Err(BridgeError::Refused(r)) => {
                skip(observer, &mut skipped, &uref.name, r.to_string());
            }
            Err(e) => return Err(step(Class::General, format!("import {}", uref.name), e)),
        }
    }
    drop(batch);

    // Durability order: objects (dir fsync) → map (file fsync) →
    // tracking refs → marker removal.
    sink.bw
        .commit()
        .map_err(|e| step(Class::CannotCreate, "commit bulk writes", e))?;
    for dir in &raw_dirs {
        if let Ok(d) = std::fs::File::open(dir) {
            let _ = d.sync_all();
        }
    }
    map::append_map_import(state, &all_pairs)
        .map_err(|e| step(Class::General, "persist map", e))?;

    let mut new_state: Vec<map::RefState> = Vec::new();
    for Imported {
        ref_name: name,
        git_id,
        kit_hash,
    } in &imported
    {
        if let Some(branch) = name.strip_prefix("refs/heads/") {
            // Force-push detection: tracking refs move with a warning
            // when the old tip is no longer an ancestor of the new.
            if let Some(prev) = prior_by_ref.get(name.as_str())
                && prev.git_id != *git_id
                && !gitsrc::is_ancestor(staging, &prev.git_id, git_id).unwrap_or(true)
            {
                observer.event(&Event::UpstreamForcePushed {
                    ref_name: name.clone(),
                });
            }
            refs::write_remote_ref(layout, request.remote_name, branch, kit_hash)
                .map_err(|e| step(Class::CannotCreate, format!("tracking ref {name}"), e))?;
        } else if let Some(tag) = name.strip_prefix("refs/tags/") {
            // Never clobber a locally-moved tag: only write when the
            // tag is absent or still where THIS import last put it
            // (mirrors git fetch's would-clobber refusal).
            let existing = refs::read_tag(layout, tag)
                .map_err(|e| step(Class::General, format!("tag ref {name}"), e))?;
            let ours_before = prior_by_ref.get(name.as_str()).map(|p| p.kit_hash);
            match existing {
                Some(cur) if cur != *kit_hash && Some(cur) != ours_before => {
                    observer.event(&Event::TagKeptLocal {
                        tag: tag.to_owned(),
                    });
                }
                Some(cur) if cur == *kit_hash => {}
                _ => {
                    refs::update_tag(layout, tag, RefWriteCondition::Any, kit_hash)
                        .map_err(|e| step(Class::CannotCreate, format!("tag ref {name}"), e))?;
                }
            }
        }
        new_state.push(map::RefState {
            ref_name: name.clone(),
            kit_hash: *kit_hash,
            git_id: *git_id,
        });
    }
    // Upstream deletions propagate to the tracking refs (like
    // `git fetch --prune` for refs/remotes); local TAGS are kept,
    // matching git's default (no --prune-tags).
    let current: HashSet<&str> = upstream_refs.iter().map(|u| u.name.as_str()).collect();
    for prev in &prior_state {
        if let Some(branch) = prev.ref_name.strip_prefix("refs/heads/")
            && !current.contains(prev.ref_name.as_str())
        {
            match refs::delete_remote_ref(layout, request.remote_name, branch) {
                Ok(()) => observer.event(&Event::TrackingRefRemoved {
                    ref_name: prev.ref_name.clone(),
                    remote: request.remote_name.to_owned(),
                    branch: branch.to_owned(),
                }),
                Err(refs::RefError::NotFound(_)) => {}
                Err(e) => {
                    return Err(step(
                        Class::CannotCreate,
                        format!("prune tracking ref {branch}"),
                        e,
                    ));
                }
            }
        }
    }

    if normalized {
        // Sticky, and recorded BEFORE the marker can be removed: a
        // crash here re-runs the (idempotent) stamp; losing it would
        // permanently unblock a fork upgrade §3.3 forbids.
        map::mark_normalized(state).map_err(|e| plain(Class::CannotCreate, e))?;
    }

    // Attestations BEFORE the ref-state persist: minting is
    // idempotent (content-addressed envelopes), but the
    // "claim already exists" skip keys on recorded-state equality —
    // a crash between persist and mint would skip those heads
    // forever on re-run.
    mint_attestations(
        layout,
        request.url,
        request.remote_name,
        &imported,
        &prior_by_ref,
        kp,
    )?;

    map::store_import_ref_state(state, &new_state)
        .map_err(|e| step(Class::General, "persist ref state", e))?;
    std::fs::remove_file(&marker).map_err(|e| step(Class::General, "marker", e))?;

    Ok(Summary {
        imported,
        skipped,
        normalized,
        checked_out: None,
        pulled: None,
    })
}

/// Whether the kit object `head` is a commit, or a chain of at most
/// [`MAX_TAG_CHAIN`] tags that ends in a commit.
fn peels_to_commit(store: &ObjectStore, head: &Hash) -> bool {
    let mut current = *head;
    for _ in 0..=MAX_TAG_CHAIN {
        match store.read_object(&current) {
            Ok(Object::Commit(_)) => return true,
            Ok(Object::Tag(tag)) => current = tag.target,
            _ => return false,
        }
    }
    false
}

fn skip(
    observer: &dyn Observer<Event>,
    skipped: &mut Vec<Skipped>,
    ref_name: &str,
    reason: String,
) {
    observer.event(&Event::RefSkipped {
        ref_name: ref_name.to_owned(),
        reason: reason.clone(),
    });
    skipped.push(Skipped {
        ref_name: ref_name.to_owned(),
        reason,
    });
}

/// `std::fs::write` + content fsync + parent-dir fsync — for tiny
/// state files whose EXISTENCE is the signal (the crash marker).
fn write_durable(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    {
        use std::io::Write as _;
        let mut f = std::fs::File::create(path)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    if let Some(parent) = path.parent()
        && let Ok(d) = std::fs::File::open(parent)
    {
        let _ = d.sync_all();
    }
    Ok(())
}

/// SPEC-GIT-IMPORT §5: subject = kit head, predicate carries the git
/// locator + canonical remote identity, signed with the import key.
fn mint_attestations(
    layout: &RepoLayout,
    url: &str,
    remote_name: &str,
    imported: &[Imported],
    prior: &HashMap<&str, &map::RefState>,
    kp: &KeyPair,
) -> Result<(), Error> {
    let identity = remote_identity(url);
    let remote_url = attestation_remote(&identity);
    let obj_store =
        ObjectStore::open(layout).map_err(|e| step(Class::General, "not a kit repo", e))?;
    for Imported {
        ref_name: name,
        git_id,
        kit_hash,
    } in imported
    {
        if let Some(prev) = prior.get(name.as_str())
            && prev.kit_hash == *kit_hash
        {
            continue; // unchanged head: claim already exists
        }
        // §5: subject/refName carry the FULL KIT ref — imported
        // branches live under refs/remotes/<name>/, not refs/heads/.
        let kit_ref = name.strip_prefix("refs/heads/").map_or_else(
            || name.clone(),
            |branch| format!("refs/remotes/{remote_name}/{branch}"),
        );
        let predicate = format!(
            "{{\"gitCommit\":\"{}\",\"refName\":\"{}\",\"remoteUrl\":\"{}\",\"schemaVersion\":1,\"specVersion\":1}}",
            sha1_hex(git_id),
            json_escape(&kit_ref),
            json_escape(remote_url)
        );
        let head_bytes = obj_store.read(kit_hash).map_err(|e| {
            step(
                Class::General,
                format!("read {}", kit_core::hash::to_hex(kit_hash)),
                e,
            )
        })?;
        let stmt = statement::encode(&statement::Statement {
            subjects: vec![statement::Subject {
                name: Some(kit_ref),
                digest_blake3_hex: kit_core::to_hex(kit_hash),
                digest_sha256_hex: statement::sha256_hex(&head_bytes),
            }],
            predicate_type: PREDICATE_TYPE.to_owned(),
            predicate_jcs: predicate.as_bytes(),
        })
        .map_err(|e| step(Class::General, "encode statement", e))?;
        let pae = kit_attest::pae_of(PAYLOAD_TYPE_IN_TOTO, stmt.as_bytes());
        let mut signer = kit_attest::RepoKeySigner::new(KeyPair {
            public: kp.public,
            secret: kit_core::sign::SecretSeed(kp.secret.0),
        });
        let sig = signer
            .sign(&pae)
            .map_err(|e| step(Class::General, "sign attestation", e))?;
        let keyid = signer
            .keyid()
            .map_err(|e| step(Class::General, "attestation keyid", e))?;
        let envelope = Envelope {
            payload_type: PAYLOAD_TYPE_IN_TOTO.to_owned(),
            payload: stmt.into_bytes(),
            signatures: vec![Sig { keyid, sig }],
        };
        let encoded = envelope
            .encode()
            .map_err(|e| step(Class::General, "encode envelope", e))?;
        attest_store::save(layout, kit_hash, encoded.as_bytes())
            .map_err(|e| step(Class::CannotCreate, "save attestation", e))?;
    }
    Ok(())
}

// ─── state, keys, probes ────────────────────────────────────────────

/// Bind direction=import (or accept fork) + record the canonical
/// source identity; refuse a different source for this state name.
fn bind_import_state(layout: &RepoLayout, state: &Path, url: &str) -> Result<(), Error> {
    map::bind_direction(state, Direction::Import)
        .or_else(|_| {
            // fork is the allowed superset (import + passthrough).
            match map::read_direction(state) {
                Ok(Some(Direction::Fork)) => Ok(()),
                _ => Err(BridgeError::Source(
                    "state dir direction conflict (one direction per state dir)".into(),
                )),
            }
        })
        .map_err(|e| plain(Class::Usage, e))?;
    let identity = remote_identity(url);
    let src_file = state.join("source");
    match read_stamp(&src_file) {
        Ok(recorded) if recorded.trim() != identity => Err(state_bound(state, &recorded, url)),
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // SPEC-GIT-IMPORT §6.1 check 1: one upstream, one state
            // dir. A second state for the same canonical source would
            // duplicate the whole history under (possibly) another
            // key — almost always a mistake.
            if let Some(other) = other_state_with_source(layout, state, &identity) {
                return Err(Error::DuplicateImport {
                    url: url.to_owned(),
                    other,
                });
            }
            map::write_binding(state, "source", &identity)
                .map_err(|e| step(Class::CannotCreate, "record source", e))
        }
        Err(e) => Err(step(Class::General, "read source binding", e)),
    }?;
    map::bind_import_spec(state, IMPORT_SPEC_VERSION).map_err(|e| plain(Class::Usage, e))
}

/// Absolutize a local-path clone URL verbatim (no `.git` stripping —
/// that is identity normalization, not path resolution).
fn absolutize_clone_url(url: &str) -> String {
    let looks_like_url = url.contains("://")
        || url
            .split('/')
            .next()
            .is_some_and(|first| first.contains(':'));
    if looks_like_url {
        return url.to_owned();
    }
    let p = Path::new(url);
    p.canonicalize()
        .map_or_else(|_| url.to_owned(), |c| c.to_string_lossy().into_owned())
}

fn read_source(state: &Path) -> Result<Option<String>, Error> {
    match read_stamp(&state.join("source")) {
        Ok(s) => Ok(Some(s.trim().to_owned())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(step(Class::General, "read source", e)),
    }
}

/// The name of another state dir already bound to `identity`, if any.
fn other_state_with_source(
    layout: &RepoLayout,
    this_state: &Path,
    identity: &str,
) -> Option<String> {
    for entry in std::fs::read_dir(layout.git_state_dir()).ok()?.flatten() {
        if entry.path() == this_state {
            continue;
        }
        if let Ok(src) = read_stamp(&entry.path().join("source"))
            && src.trim() == identity
        {
            return Some(entry.file_name().to_string_lossy().into_owned());
        }
    }
    None
}

/// SPEC-GIT-IMPORT §4: a dedicated import key by default, generated
/// on first use with a loud notice.
fn load_or_create_import_key(
    layout: &RepoLayout,
    flag: Option<&Path>,
    observer: &dyn Observer<Event>,
) -> Result<KeyPair, Error> {
    let path = flag.map_or_else(
        || layout.common_dir().join(IMPORT_KEY_FILE),
        Path::to_path_buf,
    );
    match kit_core::sign::load_key(&path) {
        Ok(kp) => {
            // §4: say which key signs this import (operators juggling
            // several imports need to see a key mixup immediately).
            observer.event(&Event::SigningKey {
                key_prefix: kit_core::to_hex(&kp.public.0)[..16].to_owned(),
                path,
            });
            Ok(kp)
        }
        // Generate ONLY when the file is truly absent: any other load
        // failure (symlink, truncation, transient IO) must surface —
        // overwriting an existing-but-unreadable key would destroy
        // the seed the pinned state depends on, irreversibly.
        Err(_) if flag.is_none() && !path.exists() => {
            // The default key file is shared by every remote-name, but
            // the bridge locks are per-state — two concurrent
            // first-time imports would each generate a key and the
            // rename-replacing save would orphan one pinned signer
            // forever. Serialize generation and re-check under the
            // lock.
            let _key_lock =
                kit_core::repo_lock::acquire_default(layout.common_dir(), "git-import-key.lock")
                    .map_err(|e| step(Class::TempFail, "import key generation busy", e))?;
            if let Ok(kp) = kit_core::sign::load_key(&path) {
                return Ok(kp);
            }
            let kp =
                KeyPair::generate().map_err(|e| step(Class::General, "generate import key", e))?;
            kit_core::sign::save_key(&path, &kp)
                .map_err(|e| step(Class::CannotCreate, "save import key", e))?;
            observer.event(&Event::KeyGenerated { path });
            Ok(kp)
        }
        Err(e) => Err(step(
            Class::NoInput,
            format!("load import key {}", path.display()),
            e,
        )),
    }
}

/// SPEC-GIT-IMPORT §6.1 content probe: walk back from each upstream
/// head (bounded) and refuse when a commit with the same framed-bytes
/// digest exists locally under a DIFFERENT signer key.
fn divergence_probe(
    store: &ObjectStore,
    staging: &Path,
    upstream_refs: &[gitsrc::UpstreamRef],
    our_key: &[u8; 32],
) -> Result<(), Error> {
    // Collect candidate digests: heads + up to 32 first-parents back.
    let mut batch = CatFileBatch::open(staging).map_err(|e| plain(Class::Unavailable, e))?;
    let mut digests: HashMap<Hash, Sha1Id> = HashMap::new();
    for uref in upstream_refs {
        let mut cur = uref.peeled.unwrap_or(uref.id);
        for _ in 0..32 {
            let Ok((kind, body)) = batch.read(&cur) else {
                break;
            };
            if kind != gitsrc::GitObjKind::Commit {
                break;
            }
            let mut framed = format!("commit {}\0", body.len()).into_bytes();
            framed.extend_from_slice(&body);
            digests.insert(kit_core::hash::hash(&framed), cur);
            let Ok(parsed) = kit_git_bridge::gitparse::parse_commit(&body) else {
                break;
            };
            match parsed.parents.first() {
                Some(p) => cur = *p,
                None => break,
            }
        }
    }
    if digests.is_empty() {
        return Ok(());
    }
    // Linear scan (imports are rare interactive operations).
    let hashes = store
        .iter_object_hashes()
        .map_err(|e| step(Class::General, "scan store", e))?;
    for h in hashes {
        let Ok(Object::Commit(c)) = store.read_object(&h) else {
            continue;
        };
        if digests.contains_key(&c.content_digest) && c.signer != *our_key {
            return Err(Error::OtherImporter {
                key: bytes_hex(&c.signer)[..16].to_owned(),
            });
        }
    }
    Ok(())
}
