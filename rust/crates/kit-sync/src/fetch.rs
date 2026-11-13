//! Fetching: reconstruct every remote branch from its packmap chain and
//! publish remote-tracking refs.
//!
//! A fetch holds no repository lock while it downloads and applies packs.
//! Each pack is downloaded, checked, unpacked and recorded as it arrives, in
//! chain order, so `add`, `commit` and `checkout` run during a clone of any
//! size. The lock a fetch takes is `worktree.lock`, and only around the
//! tracking-ref write and the checkpoint.
//!
//! What keeps gc away from the objects a fetch has written but not yet
//! published is the [`kit_core::store::PruneGuard`] that [`fetch_objects`]
//! takes first and holds until its last ref publish. gc deletes objects only
//! through `ObjectStore::prune_if_old`, which keeps every object while any
//! guard is held, so a fetch is safe at any grace period. A fetch that dies
//! leaves the packs it applied as unreferenced objects, recorded as applied;
//! the next fetch skips them, or heals if a gc removed them meanwhile.

use kit_core::hash::Hash;
use kit_core::layout::RepoLayout;
use kit_core::refs;
use kit_core::store::{ObjectStore, StoreError};

use crate::applied_packs::AppliedPacks;
use crate::checkpoint::{self, Checkpoint};

use crate::SyncOptions;
use crate::error::SyncError;
use crate::lock::wait_for_worktree_lock;
use crate::observer::{Observer, SyncEvent};
use crate::packmap::{
    MAX_FETCH_PACKS, MAX_PACK_CHAIN_DEPTH, flatten_oldest_first, packmap_ref, resolve_pack_chain,
    walk_pack_chain_until,
};
use crate::source::RemoteSource;
use crate::stage::{ChainApplied, apply_pack_chain};

/// What a fetch did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct FetchReport {
    /// Branches whose remote-tracking ref was published.
    pub branches_fetched: usize,
    /// Branches skipped because the listing was stale (deleted since).
    pub branches_skipped: Vec<String>,
    /// Remote-tracking refs deleted because the remote no longer has the
    /// branch. Empty unless the fetch pruned.
    pub branches_pruned: Vec<String>,
    /// Packs downloaded and applied from the remote. Like the other counters,
    /// this covers the attempt that published each branch (a branch retried
    /// after a concurrent re-baseline reports only its successful second
    /// attempt).
    pub packs_downloaded: usize,
    /// Packs already recorded as applied, so neither downloaded nor unpacked.
    pub packs_already_applied: usize,
    /// Objects written to the object store.
    pub objects_unpacked: usize,
    /// The remote's cursor equalled the one the last complete fetch saw,
    /// and the remote-tracking refs were as that fetch left them, so the
    /// fetch made no other request (SPEC-TRANSPORT §1.2).
    pub remote_unchanged: bool,
}

/// One branch's pack chain, resolved over the network. Consumed by
/// [`apply_and_verify_chain`].
pub(crate) struct ResolvedChain {
    /// Oldest-first flattened chain of the packs past the checkpoint's
    /// verified prefix. An omitted prefix is resolved in full only on
    /// self-heal.
    chain: Vec<Hash>,
    head: Hash,
    /// Counts for the complete chain, including its verified prefix.
    packs: usize,
    nodes: usize,
    prefix_packs: usize,
}

/// Step 1 of a branch fetch: walk `branch`'s packmap chain from `head_key`
/// and check its length limits. Pure network I/O: it downloads only packlist
/// nodes, never packs, and touches neither the object store nor any lock.
///
/// A matching checkpoint skips the immutable prefix. Missing or unrelated
/// checkpoints leave the full walk unchanged.
pub(crate) fn resolve_chain(
    source: &dyn RemoteSource,
    observer: &dyn Observer<SyncEvent>,
    branch: &str,
    head_key: Hash,
    checkpoint: Option<Checkpoint>,
) -> Result<ResolvedChain, SyncError> {
    let (nodes, reached) = walk_pack_chain_until(
        source,
        observer,
        branch,
        head_key,
        checkpoint.map(|c| c.head),
    )?;
    let prefix = checkpoint.filter(|_| reached);
    let node_count = nodes.len() + prefix.map_or(0, |c| c.nodes);
    let chain = flatten_oldest_first(nodes);
    let prefix_packs = prefix.map_or(0, |c| c.packs);
    let packs = chain.len() + prefix_packs;
    if node_count > MAX_PACK_CHAIN_DEPTH || packs > MAX_FETCH_PACKS {
        return Err(SyncError::PackChainInvalid {
            branch: branch.to_owned(),
            source: None,
        });
    }
    Ok(ResolvedChain {
        chain,
        head: head_key,
        packs,
        nodes: node_count,
        prefix_packs,
    })
}

/// What [`apply_and_verify_chain`] did, for the report.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct Applied {
    pub(crate) packs_downloaded: usize,
    pub(crate) packs_skipped: usize,
    pub(crate) objects_unpacked: usize,
}

/// Step 2 of a branch fetch: download and unpack each pack of `resolved`
/// into `store` as it arrives, recording each one, then verify the closure at
/// `tip` is complete, running the applied-pack self-heal retry on a stale
/// record.
///
/// **The caller MUST hold a [`kit_core::store::PruneGuard`] across this call
/// and through the branch's subsequent ref publish.** Unpacking writes
/// objects to the local store before this branch's ref makes them reachable,
/// and a gc that deleted them meanwhile would leave the fetch with a ref to a
/// broken closure. No repository lock is needed.
///
/// # Self-heal
///
/// The record may name packs whose objects the store no longer holds, for
/// example after `.kit/objects` was wiped while `applied-packs/` survived, or
/// after a gc pruned the objects of a fetch that died. So when this run
/// skipped at least one pack, whether recorded or inside the checkpoint's
/// verified prefix, and then either a delta base is missing or the closure
/// check reports [`SyncError::RemoteMissingObject`], `applied` is cleared and
/// the whole chain is resolved if necessary and retried once with no skips.
/// Every other failure propagates without triggering self-heal, because none
/// is evidence the local store is stale: a corrupt pack, a remote missing a
/// pack, a transport error, a closure too large to verify, an interruption,
/// or a failed signature.
///
/// # Signature verification
///
/// When `require_signed` is `true` every commit, remix and tag in each
/// freshly unpacked pack is verified before the pack is recorded as applied.
/// On the self-heal path every re-downloaded object is re-verified.
#[allow(clippy::too_many_arguments)]
pub(crate) fn apply_and_verify_chain(
    store: &ObjectStore,
    source: &dyn RemoteSource,
    observer: &dyn Observer<SyncEvent>,
    remote: &str,
    branch: &str,
    resolved: ResolvedChain,
    tip: Hash,
    applied: &mut AppliedPacks,
    require_signed: bool,
) -> Result<Applied, SyncError> {
    let ResolvedChain {
        mut chain,
        head,
        prefix_packs,
        ..
    } = resolved;
    let mut done = ChainApplied::default();
    let first = apply_pack_chain(
        store,
        source,
        observer,
        remote,
        branch,
        &chain,
        applied,
        require_signed,
        &mut done,
    )
    // Closure completeness. With skips this is the sole guarantee the store
    // is whole.
    .and_then(|()| verify_closure_present(store, &tip));
    let skipped = done.skipped + prefix_packs;
    let stats = Applied {
        packs_downloaded: done.packs,
        packs_skipped: skipped,
        objects_unpacked: done.objects,
    };
    let stale = match first {
        Ok(()) => return Ok(stats),
        Err(
            e @ (SyncError::RemoteMissingObject(_)
            | SyncError::Pack(kit_core::pack::PackError::DeltaBaseMissing(_))),
        ) if skipped > 0 => e,
        Err(e) => return Err(e),
    };
    observer.event(&SyncEvent::AppliedPacksStale {
        remote: remote.to_owned(),
        branch: branch.to_owned(),
        cause: stale.to_string(),
    });
    // Clear the suspected-stale record and retry the whole chain with no
    // skips. Clearing intentionally discards digests inserted by other
    // branches earlier in this same fetch: the store wipe or gc that trips
    // self-heal makes those entries just as stale. The cleared record goes to
    // disk at once, so a retry that dies does not leave the stale lines to
    // be read again.
    applied.clear();
    persist_record(applied, observer, remote);
    if prefix_packs > 0 {
        // Release suffix metadata before allocating the complete walk.
        drop(chain);
        chain = resolve_pack_chain(source, observer, branch, head)?;
    }
    let mut retry = ChainApplied::default();
    apply_pack_chain(
        store,
        source,
        observer,
        remote,
        branch,
        &chain,
        applied,
        require_signed,
        &mut retry,
    )?;
    verify_closure_present(store, &tip)?;
    // The report covers the attempt that published.
    Ok(Applied {
        packs_downloaded: retry.packs,
        packs_skipped: retry.skipped,
        objects_unpacked: retry.objects,
    })
}

/// Rewrite the applied-packs record atomically. The record is a cache, so a
/// failure is reported and never fails the fetch.
fn persist_record(applied: &mut AppliedPacks, observer: &dyn Observer<SyncEvent>, remote: &str) {
    if let Err(e) = applied.persist() {
        observer.event(&SyncEvent::AppliedPacksPersistFailed {
            remote: remote.to_owned(),
            error: e.to_string(),
        });
    }
}

/// Assert that every object reachable from `tip` is already present in the
/// local store after the packmap chain has been unpacked. A pure integrity
/// check with no network access: a reachable object the chain failed to
/// deliver surfaces as [`SyncError::RemoteMissingObject`], so the fetch aborts
/// loudly rather than publishing a ref to a closure it cannot reconstruct.
///
/// The check retains no chunk of a chunked blob, so the
/// [`kit_core::ops::graph::MAX_REACHABLE`] cap counts commits, trees, blobs
/// and manifests only. A closure exceeding it leaves objects past the cap
/// unchecked, which over a partially wiped store could hide missing objects,
/// so truncation is a hard [`SyncError::ClosureTooLarge`] (deliberately not a
/// self-heal trigger).
pub(crate) fn verify_closure_present(store: &ObjectStore, tip: &Hash) -> Result<(), SyncError> {
    match kit_core::ops::check_closure_present(store, std::iter::once(tip)) {
        Ok(false) => Ok(()),
        Ok(true) => Err(SyncError::ClosureTooLarge(
            kit_core::ops::graph::MAX_REACHABLE,
        )),
        Err(StoreError::ObjectNotFound(hex)) => Err(SyncError::RemoteMissingObject(hex)),
        Err(e) => Err(e.into()),
    }
}

/// Reconstruct every remote `refs/heads/*` from its packmap chain and publish
/// the remote-tracking refs. `target_branch` (a `clone -b` or `pull` target)
/// is fetched even when an eventual listing has not caught up with it: the
/// branch is strongly read by name, fetched if present, and
/// [`SyncError::RemoteBranchMissing`] if absent.
///
/// For every advertised branch the flow is exactly:
///
/// 1. read the branch's packmap ref (`refs/kit/packmap/<branch>`),
/// 2. walk its chain oldest-first, then download, check, unpack and record
///    each pack the applied-pack record does not already have, one at a time,
///    with no repo lock held, and assert the tip's closure is fully present,
/// 3. acquire the repo lock, publish the remote-tracking ref and its
///    checkpoint, and release the lock.
///
/// Step 2's unpack and closure check are one call so a closure failure
/// counts toward the applied-pack self-heal retry. An absent packmap beside a
/// present head is [`SyncError::PackmapMissing`]; a head absent too is a stale
/// listing, and the branch is skipped. A tracking ref is never published for
/// a closure that could not be fully materialised.
///
/// # Protection from gc
///
/// The first statement takes the store's [`kit_core::store::PruneGuard`], and
/// the function holds it on every return path, after its last ref publish.
/// While it is held, gc deletes nothing, so the objects of step 2, which no
/// ref names yet, survive any grace period. The guard comes before the
/// applied-packs record is read: a gc that ran between reading the record and
/// taking the guard could delete an object of a pack the record names.
///
/// # Concurrent re-baseline
///
/// Branch tips are listed BEFORE each branch's packmap is read, so a
/// concurrent push that resets the packmap in between can leave an old tip
/// verified against a packmap that only covers the new one, surfacing as
/// [`SyncError::RemoteMissingObject`]. That is transient, so on that error
/// the branch's current tip and packmap are re-read and the chain retried
/// once. A second failure, or a vanished branch, propagates.
///
/// # Applied-packs record
///
/// The record is keyed by remote, so this function owns its lifecycle for the
/// whole fetch: loaded once before the branch loop, appended to as each pack
/// is applied, and rewritten atomically once after, unconditionally and
/// best-effort (a pure performance cache whose own I/O must never fail a
/// fetch whose objects durably landed).
pub(crate) fn fetch_objects(
    store: &ObjectStore,
    layout: &RepoLayout,
    source: &dyn RemoteSource,
    observer: &dyn Observer<SyncEvent>,
    remote: &str,
    options: &SyncOptions,
) -> Result<FetchReport, SyncError> {
    let _prune_guard = store.prune_guard()?;
    let mut applied = AppliedPacks::load_or_empty(layout, remote, observer);
    let mut report = FetchReport::default();
    let result = fetch_objects_inner(
        store,
        layout,
        source,
        observer,
        remote,
        options,
        &mut applied,
        &mut report,
    );
    persist_record(&mut applied, observer, remote);
    result.map(|()| report)
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn fetch_objects_inner(
    store: &ObjectStore,
    layout: &RepoLayout,
    source: &dyn RemoteSource,
    observer: &dyn Observer<SyncEvent>,
    remote: &str,
    options: &SyncOptions,
    applied: &mut AppliedPacks,
    report: &mut FetchReport,
) -> Result<(), SyncError> {
    let target_branch = options.target_branch.as_deref();
    let require_signed = options.verify_signatures;
    // The cursor is read before the listing, so a write the listing misses
    // changes a later cursor.
    let cursor = source
        .repo_cursor()
        .map_err(|error| source.repository_error(error))?;
    let cursor_path = crate::cursor::path(layout, source, remote);
    // A pruning fetch lists the remote even when its cursor is unchanged: a
    // tracking ref can outlive its branch from an earlier fetch that did not
    // prune.
    if !options.prune
        && let Some(cursor) = &cursor
        && remote_unchanged(
            store,
            layout,
            &cursor_path,
            cursor,
            remote,
            require_signed,
            target_branch,
        )?
    {
        report.remote_unchanged = true;
        return Ok(());
    }
    let mut remote_refs = source
        .list_branches()
        .map_err(|error| source.repository_error(error))?;
    if let Some(branch) = target_branch
        && !remote_refs.iter().any(|r| r.name == branch)
    {
        // The listing may be stale (eventual): a strong read by name decides
        // whether the branch exists. A transport error here propagates; only
        // `Ok(None)` is the "no such branch" verdict.
        match source.read_ref(&format!("refs/heads/{branch}"))? {
            Some(hash) => remote_refs.push(refs::Ref {
                name: branch.to_owned(),
                hash: Some(hash),
            }),
            None => return Err(SyncError::RemoteBranchMissing(branch.to_owned())),
        }
    }
    let listed: std::collections::HashSet<String> =
        remote_refs.iter().map(|r| r.name.clone()).collect();
    // Unidentified sources retain batched tracking writes. Checkpoints need
    // each tracking rename durable before the checkpoint is published.
    let mut tracking = refs::RemoteRefBatch::new(layout, remote)?;
    let result: Result<(), SyncError> = (|| {
        for r in remote_refs {
            if observer.cancelled() {
                return Err(SyncError::Interrupted);
            }
            let Some(h) = r.hash else { continue };
            // A branch tip without a packmap is a corrupt or incomplete
            // remote, not a format to degrade to: the push path ALWAYS
            // advertises a packmap before moving the branch ref. A real
            // transport error propagates unchanged; only `Ok(None)` is the
            // explicit "no packmap" verdict.
            //
            // The one exception is a stale listing: a branch deleted since
            // the listing can still be named. Re-read the head strongly:
            // absent too means the listing is stale, so skip the branch and
            // write no tracking ref; present means corruption, which stays
            // `PackmapMissing`.
            let Some(chain_head) = source.read_ref(&packmap_ref(&r.name))? else {
                if source
                    .read_ref(&format!("refs/heads/{}", r.name))?
                    .is_none()
                {
                    observer.event(&SyncEvent::BranchSkippedStale {
                        branch: r.name.clone(),
                    });
                    report.branches_skipped.push(r.name.clone());
                    continue;
                }
                return Err(SyncError::PackmapMissing(r.name.clone()));
            };

            let checkpoint_path = checkpoint::path(layout, source, remote, &r.name);
            // The immutable prefix remains verified even if tracking moved.
            // Always check the listed tip's closure before publishing,
            // including when the head matches but that tip changed.
            let checkpoint = checkpoint_path.as_deref().and_then(Checkpoint::load);

            // Step 1: resolve this branch's chain.
            let resolved = resolve_chain(source, observer, &r.name, chain_head, checkpoint)?;
            let completed = Checkpoint {
                head: chain_head,
                tip: h,
                packs: resolved.packs,
                nodes: resolved.nodes,
            };

            // Step 2: download, unpack and record each pack as it arrives,
            // then verify the closure. No repo lock is held. The prune guard
            // that `fetch_objects` holds keeps gc from deleting the objects
            // that no ref names yet.
            let (completed, applied_stats) = match apply_and_verify_chain(
                store,
                source,
                observer,
                remote,
                &r.name,
                resolved,
                h,
                applied,
                require_signed,
            ) {
                Ok(stats) => (completed, stats),
                Err(e @ SyncError::RemoteMissingObject(_)) => {
                    // Re-read the branch's CURRENT tip and packmap. If either
                    // is gone (branch deleted mid-fetch) the original error
                    // stands. Otherwise retry the chain ONCE with the fresh
                    // pair; a second failure propagates via `?`.
                    let (Some(fresh_h), Some(fresh_head)) = (
                        source.read_ref(&format!("refs/heads/{}", r.name))?,
                        source.read_ref(&packmap_ref(&r.name))?,
                    ) else {
                        return Err(e);
                    };
                    let fresh = resolve_chain(source, observer, &r.name, fresh_head, None)?;
                    let completed = Checkpoint {
                        head: fresh_head,
                        tip: fresh_h,
                        packs: fresh.packs,
                        nodes: fresh.nodes,
                    };
                    let stats = apply_and_verify_chain(
                        store,
                        source,
                        observer,
                        remote,
                        &r.name,
                        fresh,
                        fresh_h,
                        applied,
                        require_signed,
                    )?;
                    (completed, stats)
                }
                Err(e) => return Err(e),
            };

            // Step 3: publish under a repo lock acquired fresh for this
            // branch and released once this loop iteration ends. The wait
            // has no deadline: the work above is done, and an interrupt
            // ends it. The fetch holds only the shared lock of the prune
            // guard, and no process blocks on the exclusive one, so this
            // wait cannot deadlock.
            let _lock = wait_for_worktree_lock(layout, observer)?;
            // Make the tracking rename durable before its checkpoint; a
            // crash between them leaves the old record.
            tracking.write(&r.name, &completed.tip)?;
            if require_signed && let Some(path) = &checkpoint_path {
                let batch =
                    std::mem::replace(&mut tracking, refs::RemoteRefBatch::new(layout, remote)?);
                batch.commit()?;
                // Like applied-packs, this is a disposable performance cache.
                let _ = completed.persist(path);
            }
            report.branches_fetched += 1;
            report.packs_downloaded += applied_stats.packs_downloaded;
            report.packs_already_applied += applied_stats.packs_skipped;
            report.objects_unpacked += applied_stats.objects_unpacked;
        }
        Ok(())
    })();
    // Persist the successful batched prefix even if a later branch failed.
    tracking.commit()?;
    result?;
    if options.prune {
        prune_tracking(layout, source, observer, remote, &listed, report)?;
    }
    if let Some(cursor) = cursor {
        // A disposable cache: failing to write it costs the next fetch a
        // full walk, never this fetch.
        let record = crate::cursor::CursorRecord {
            cursor,
            tracking: crate::cursor::tracking_digest(layout, remote)?,
            signed: require_signed,
        };
        let _ = record.persist(&cursor_path);
    }
    Ok(())
}

/// Delete the tracking refs of `remote` whose branch the listing lacks. It
/// runs only after every listed branch was fetched and verified. The listing
/// may be stale, so a strong read of each candidate decides: only an absent
/// head is pruned, and a failed read fails the fetch and prunes nothing more.
/// It touches no local branch and no tag.
fn prune_tracking(
    layout: &RepoLayout,
    source: &dyn RemoteSource,
    observer: &dyn Observer<SyncEvent>,
    remote: &str,
    listed: &std::collections::HashSet<String>,
    report: &mut FetchReport,
) -> Result<(), SyncError> {
    let mut gone = Vec::new();
    for tracked in refs::list_remote_refs(layout, remote)? {
        if !listed.contains(&tracked.name)
            && source
                .read_ref(&format!("refs/heads/{}", tracked.name))?
                .is_none()
        {
            gone.push(tracked.name);
        }
    }
    if gone.is_empty() {
        return Ok(());
    }
    let _lock = wait_for_worktree_lock(layout, observer)?;
    for name in gone {
        match refs::delete_remote_ref(layout, remote, &name) {
            Ok(()) | Err(refs::RefError::NotFound(_)) => report.branches_pruned.push(name),
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

/// Whether the last complete fetch saw `cursor`, the remote-tracking refs
/// are as it left them, and the object of every tracked tip is in the store
/// (a wiped store still heals). A fetch that verifies signatures does not
/// trust a fetch that did not, and a fetch of a named branch needs its
/// tracking ref.
fn remote_unchanged(
    store: &ObjectStore,
    layout: &RepoLayout,
    path: &std::path::Path,
    cursor: &kit_core::protocol::RepoCursor,
    remote: &str,
    require_signed: bool,
    target_branch: Option<&str>,
) -> Result<bool, SyncError> {
    let Some(record) = crate::cursor::CursorRecord::load(path) else {
        return Ok(false);
    };
    if record.cursor != *cursor || (require_signed && !record.signed) {
        return Ok(false);
    }
    if let Some(branch) = target_branch
        && refs::read_remote_ref(layout, remote, branch)?.is_none()
    {
        return Ok(false);
    }
    let mut tracked = refs::list_remote_refs(layout, remote)?;
    if record.tracking != crate::cursor::digest_of(&mut tracked) {
        return Ok(false);
    }
    Ok(tracked
        .iter()
        .all(|r| r.hash.is_some_and(|tip| store.contains(&tip))))
}
