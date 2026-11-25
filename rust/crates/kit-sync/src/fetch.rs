//! Fetching: reconstruct every remote branch from its packmap chain and
//! publish remote-tracking refs.
//!
//! Fetch downloads and authenticates packs in chain order. It records
//! completed packs as publication windows seal. Fetch takes the worktree
//! lock only around the tracking-ref write and the checkpoint, so add,
//! commit, and checkout can run during the transfer.
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
use kit_core::object::ObjectType;
use kit_core::pack::FetchDecodeBudget;
use kit_core::refs;
use kit_core::store::{ClosureSource, ObjectStore, PruneGuard};

use crate::applied_packs::AppliedPacks;
use crate::checkpoint::{self, Checkpoint};
use crate::closure::{self, Anchors};

use crate::SyncOptions;
use crate::apply::{ChainApplied, apply_pack_chain};
use crate::error::SyncError;
use crate::lock::{LockWait, wait_for_worktree_lock};
use crate::observer::{Observer, SyncEvent};
use crate::packmap::{
    MAX_FETCH_PACKS, MAX_PACK_CHAIN_DEPTH, chain_label, flatten_oldest_first, packmap_ref,
    resolve_pack_chain, walk_pack_chain_until,
};
use crate::source::RemoteSource;
use crate::tags::{StopSet, TagPhase, TagRejection, TagWarning};
use crate::verify::{VerifiedHistory, verify_history_signatures};

/// Download work a fetch did not repeat.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct DownloadSavings {
    /// Bytes an interrupted download did not fetch again, because the
    /// transport asked the remote for the rest of the pack.
    pub bytes_resumed: u64,
    /// Interrupted downloads whose remote could not continue, so the pack
    /// was read again from its start.
    pub resumes_restarted: usize,
    /// Bytes of verified packs that came from disk, kept after a failed
    /// apply, instead of from the remote.
    pub bytes_reused: u64,
}

impl DownloadSavings {
    pub(crate) fn add(&mut self, other: &Self) {
        self.bytes_resumed += other.bytes_resumed;
        self.resumes_restarted += other.resumes_restarted;
        self.bytes_reused += other.bytes_reused;
    }
}

/// What a fetch did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct FetchReport {
    /// Best-effort maintenance after publishing the fetch.
    pub maintenance: Option<crate::MaintenanceReport>,
    /// Branches whose remote-tracking ref was published.
    pub branches_fetched: usize,
    /// Envelopes saved after validating their pack and local subject.
    pub attestations_stored: usize,
    /// Envelopes discarded because their subjects are absent locally.
    pub attestations_dropped: usize,
    /// Invalid attestation packs rejected without failing code fetch.
    pub attestations_rejected: usize,
    /// Attestation failures, displayed as warnings by command-line callers.
    pub attestation_warnings: Vec<String>,
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
    /// Download work the fetch did not repeat after an interruption or a
    /// failed apply.
    pub savings: DownloadSavings,
    /// The remote's cursor equalled the one the last complete fetch saw,
    /// and the remote-tracking refs and local tags were as that fetch left
    /// them, so the fetch made no other request (SPEC-TRANSPORT §1.2).
    pub remote_unchanged: bool,
    /// Remote tags the fetch published as local tags, in listing order.
    pub tags_fetched: Vec<String>,
    /// Remote tags the fetch refused. A refusal does not fail the fetch: the
    /// branches and the other tags are published, the cursor is not
    /// recorded, and the next fetch tries the tag again.
    pub tags_rejected: Vec<TagRejection>,
    /// Remote tags skipped because their name is not one a client can push
    /// or fetch. A warning only: it does not block the cursor record.
    pub tag_warnings: Vec<TagWarning>,
    /// The tag or tag map listing failed, so the tag phase stopped there. The
    /// branches are published and the cursor is not recorded.
    pub tag_listing_failed: Option<String>,
}

impl FetchReport {
    /// Whether the tag phase left something for the user to act on: a
    /// refused tag or a failed listing. A caller exits non-zero on it.
    #[must_use]
    pub fn tags_incomplete(&self) -> bool {
        !self.tags_rejected.is_empty() || self.tag_listing_failed.is_some()
    }
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
    /// The nodes walked, and the checkpoint's head when the walk stopped
    /// there: once the chain is applied and checked, a tag chain's walk
    /// stops at any of them.
    keys: Vec<Hash>,
}

/// Step 1 of a branch fetch: walk the packmap chain of `head_ref` from
/// `head_key` and check its length limits. Pure network I/O: it downloads only packlist
/// nodes, never packs, and touches neither the object store nor any lock.
///
/// A matching checkpoint skips the immutable prefix. Missing or unrelated
/// checkpoints leave the full walk unchanged.
pub(crate) fn resolve_chain(
    source: &dyn RemoteSource,
    observer: &dyn Observer<SyncEvent>,
    head_ref: &str,
    head_key: Hash,
    checkpoint: Option<Checkpoint>,
) -> Result<ResolvedChain, SyncError> {
    let walk = walk_pack_chain_until(source, observer, head_ref, head_key, &|key| {
        checkpoint.is_some_and(|c| c.head == *key)
    })?;
    let prefix = checkpoint.filter(|_| walk.stopped);
    let node_count = walk.nodes.len() + prefix.map_or(0, |c| c.nodes);
    let mut keys = walk.keys;
    keys.extend(prefix.map(|c| c.head));
    let chain = flatten_oldest_first(walk.nodes);
    let prefix_packs = prefix.map_or(0, |c| c.packs);
    let packs = chain.len() + prefix_packs;
    if node_count > MAX_PACK_CHAIN_DEPTH || packs > MAX_FETCH_PACKS {
        return Err(SyncError::PackChainInvalid {
            branch: chain_label(head_ref).to_owned(),
            source: None,
        });
    }
    Ok(ResolvedChain {
        chain,
        head: head_key,
        packs,
        nodes: node_count,
        prefix_packs,
        keys,
    })
}

/// What [`apply_and_verify_chain`] did, for the report.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct Applied {
    pub(crate) packs_downloaded: usize,
    pub(crate) packs_skipped: usize,
    pub(crate) objects_unpacked: usize,
    pub(crate) savings: DownloadSavings,
}

/// Step 2 of a branch fetch: download and unpack each pack of `resolved`
/// into `store` as it arrives, recording each one, then verify the closure at
/// `tip` is complete down to `anchors` ([`crate::closure`]), running the
/// applied-pack self-heal retry on a stale record.
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
/// or a failed signature. The retry checks the whole closure, ignoring
/// `anchors`, as the store is suspect.
///
/// # Signature verification
///
/// When `require_signed` is `true` every commit, remix and tag in each
/// freshly unpacked pack is verified before the pack is recorded as applied.
/// On the self-heal path every re-downloaded object is re-verified. This
/// covers only the packs a run applies: [`fetch_objects`] checks the history
/// of the tip itself before it publishes it.
#[allow(clippy::too_many_arguments)]
pub(crate) fn apply_and_verify_chain(
    store: &ObjectStore,
    source: &dyn RemoteSource,
    observer: &dyn Observer<SyncEvent>,
    remote: &str,
    head_ref: &str,
    resolved: ResolvedChain,
    tip: Hash,
    applied: &mut AppliedPacks,
    require_signed: bool,
    anchors: &Anchors,
    guard: &PruneGuard,
    verified: &mut VerifiedHistory,
    decoded: &mut FetchDecodeBudget,
) -> Result<Applied, SyncError> {
    let ResolvedChain {
        mut chain,
        head,
        prefix_packs,
        ..
    } = resolved;
    let mut done = ChainApplied::default();
    // A retry decodes the chain again, so it starts from what the first try
    // started from: one honest fetch is not charged twice for its packs.
    let before = *decoded;
    let first = apply_pack_chain(
        store,
        source,
        observer,
        remote,
        head_ref,
        &chain,
        applied,
        require_signed,
        &mut done,
        guard,
        decoded,
        |view| check_tip(view, observer, &tip, anchors, require_signed, verified),
    );
    let skipped = done.skipped + prefix_packs;
    let stats = Applied {
        packs_downloaded: done.packs,
        packs_skipped: skipped,
        objects_unpacked: done.objects,
        savings: done.savings,
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
        branch: chain_label(head_ref).to_owned(),
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
        chain = resolve_pack_chain(source, observer, head_ref, head)?;
    }
    let mut retry = ChainApplied::default();
    *decoded = before;
    apply_pack_chain(
        store,
        source,
        observer,
        remote,
        head_ref,
        &chain,
        applied,
        require_signed,
        &mut retry,
        guard,
        decoded,
        |view| {
            check_tip(
                view,
                observer,
                &tip,
                &Anchors::default(),
                require_signed,
                verified,
            )
        },
    )?;
    // The report covers the attempt that published. Savings count both
    // attempts: the first one's downloads, resumed or kept, are the reason the
    // retry reads less.
    let mut savings = stats.savings;
    savings.add(&retry.savings);
    Ok(Applied {
        packs_downloaded: retry.packs,
        packs_skipped: retry.skipped,
        objects_unpacked: retry.objects,
        savings,
    })
}

fn check_tip(
    view: &dyn ClosureSource,
    observer: &dyn Observer<SyncEvent>,
    tip: &Hash,
    anchors: &Anchors,
    require_signed: bool,
    verified: &mut VerifiedHistory,
) -> Result<(), SyncError> {
    verify_closure_above(view, observer, tip, anchors)?;
    if require_signed {
        verify_history_signatures(view, observer, tip, verified)?;
    }
    Ok(())
}

/// Refuse to publish a tracking ref for a branch whose fetched tip is not a
/// commit or a remix. The closure check and the signature walk treat a tree
/// or a blob as a leaf and pass it, so a remote could otherwise make a tree
/// the tip of `origin/main`, and the commands that read the branch later
/// would fail on it one by one.
fn ensure_commit_tip(store: &ObjectStore, branch: &str, tip: &Hash) -> Result<(), SyncError> {
    let found = match store.object_type(tip)? {
        ObjectType::Commit | ObjectType::Remix => return Ok(()),
        ObjectType::Blob => "blob",
        ObjectType::Tree => "tree",
        ObjectType::ChunkedBlob => "chunked blob",
        ObjectType::Delta => "delta",
        ObjectType::Tag => "tag",
    };
    Err(SyncError::BranchTipNotCommit {
        branch: branch.to_owned(),
        found,
    })
}

/// Flush the applied-pack record or publish its pending rewrite. A write
/// failure warns at most once per fetch.
pub(crate) fn persist_record(
    applied: &mut AppliedPacks,
    observer: &dyn Observer<SyncEvent>,
    remote: &str,
) {
    if let Err(e) = applied.persist()
        && applied.first_failure()
    {
        observer.event(&SyncEvent::AppliedPacksPersistFailed {
            remote: remote.to_owned(),
            error: e.to_string(),
        });
    }
}

/// Check presence down to `anchors`, or in full when there are
/// none.
fn verify_closure_above(
    store: &dyn ClosureSource,
    observer: &dyn Observer<SyncEvent>,
    tip: &Hash,
    anchors: &Anchors,
) -> Result<(), SyncError> {
    let done = std::cell::Cell::new(0usize);
    let last = std::cell::Cell::new(std::time::Instant::now());
    observer.event(&SyncEvent::ClosureProgress { done: 0 });
    let poll = || {
        if last.get().elapsed() >= std::time::Duration::from_millis(100) {
            observer.event(&SyncEvent::ClosureProgress { done: done.get() });
            last.set(std::time::Instant::now());
        }
        observer.cancelled()
    };
    if anchors.is_empty() {
        let result =
            kit_core::ops::graph::check_closure_present_observed_from(store, tip, &|count| {
                done.set(count);
                poll();
            });
        observer.event(&SyncEvent::ClosureProgress { done: done.get() });
        return match result {
            Ok(false) => Ok(()),
            Ok(true) => Err(SyncError::ClosureTooLarge(
                kit_core::ops::graph::MAX_REACHABLE,
            )),
            Err(error) => Err(closure::closure_error(error)),
        };
    }
    let result = closure::check_above_observed(store, tip, anchors, &poll, &|count| {
        done.set(count);
        poll();
    });
    if let Ok(count) = &result {
        observer.event(&SyncEvent::ClosureProgress { done: *count });
    }
    result.map(drop)
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
#[cfg(test)]
pub(crate) fn verify_closure_present(store: &ObjectStore, tip: &Hash) -> Result<(), SyncError> {
    match kit_core::ops::check_closure_present(store, std::iter::once(tip)) {
        Ok(false) => Ok(()),
        Ok(true) => Err(SyncError::ClosureTooLarge(
            kit_core::ops::graph::MAX_REACHABLE,
        )),
        Err(e) => Err(closure::closure_error(e)),
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
///    down to the tracking tips a signed fetch recorded and the tips this call
///    published ([`crate::closure`]),
/// 3. when signatures are required, verify every commit, remix and tag in
///    the tip's history, whether or not this run downloaded it,
/// 4. acquire the repo lock, publish the remote-tracking ref and its
///    checkpoint, and release the lock.
///
/// Then, unless [`SyncOptions::tags`] is off, the tag phase publishes the
/// remote's tags ([`crate::tags`]): each tag's closure is checked down to what
/// local refs reach, and its signatures down to what is verified, before it
/// is published. A tag that fails is refused alone and reported in
/// [`FetchReport::tags_rejected`].
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
/// While it is held, gc cannot delete objects, so the objects of step 2,
/// which no ref names yet, survive any grace period. The guard comes before the
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
///
/// # Signed history
///
/// With signatures required, the history of each tip is verified before it
/// is published, down to the tips earlier signed fetches recorded (see
/// [`crate::anchor`]), and each tip it publishes is recorded in turn. So a
/// fetch verifies only the commits between a new tip and what an earlier
/// signed fetch verified. Branches that share history walk it once.
pub(crate) fn fetch_objects(
    store: &ObjectStore,
    layout: &RepoLayout,
    source: &dyn RemoteSource,
    observer: &dyn Observer<SyncEvent>,
    remote: &str,
    options: &SyncOptions,
    lock_wait: &LockWait,
) -> Result<FetchReport, SyncError> {
    // The cursor must predate the listing so a write the listing misses
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
        && remote_unchanged(store, layout, source, &cursor_path, cursor, remote, options)?
    {
        return Ok(FetchReport {
            remote_unchanged: true,
            ..FetchReport::default()
        });
    }
    // Take the attestation head before the branch listing so a later head
    // cannot be mistaken for one covered by the ref snapshot.
    let _ = std::fs::remove_file(&cursor_path);
    let mut report = FetchReport::default();
    let snapshot = crate::fetch_attestations::snapshot(source, options, &mut report);
    let mut remote_refs = source
        .list_branches()
        .map_err(|error| source.repository_error(error))?;
    if let Some(branch) = options.target_branch.as_deref()
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
    // The activation try comes before this process takes its own shared guard,
    // which would make it miss.
    store.ensure_packed_once()?;
    let guard = store.prune_guard()?;
    kit_core::pack::sweep_spool_dir(&store.spool_dir());
    let mut applied = AppliedPacks::load_or_empty(layout, remote, observer);
    let result = fetch_objects_inner(
        store,
        layout,
        source,
        observer,
        remote,
        options,
        lock_wait,
        &guard,
        &mut applied,
        &mut report,
        cursor,
        &cursor_path,
        remote_refs,
        snapshot,
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
    lock_wait: &LockWait,
    guard: &PruneGuard,
    applied: &mut AppliedPacks,
    report: &mut FetchReport,
    cursor: Option<kit_core::protocol::RepoCursor>,
    cursor_path: &std::path::Path,
    remote_refs: Vec<refs::Ref>,
    snapshot: crate::fetch_attestations::Snapshot,
) -> Result<(), SyncError> {
    let require_signed = options.verify_signatures;
    let mut verified = if require_signed {
        crate::anchor::load_all(layout)
    } else {
        VerifiedHistory::default()
    };
    let listed: std::collections::HashSet<String> =
        remote_refs.iter().map(|r| r.name.clone()).collect();
    // Unidentified sources retain batched tracking writes. Checkpoints need
    // each tracking rename durable before the checkpoint is published.
    let mut tracking = refs::RemoteRefBatch::new(layout, remote)?;
    // The tracking refs this fetch published, with the tip it gave each.
    let mut published: Vec<(String, Hash)> = Vec::new();
    // The tips a closure check stops at. Read under the prune guard.
    let mut anchors = Anchors::load(store, layout, remote, require_signed)?;
    // The nodes of the chains this fetch applied and checked.
    let mut stop = StopSet::default();
    // What every pack of this fetch, tags included, may decode in total.
    let mut decoded = FetchDecodeBudget::new();
    let result: Result<(), SyncError> = (|| {
        for r in remote_refs {
            if observer.cancelled() {
                return Err(SyncError::Interrupted);
            }
            let Some(h) = r.hash else { continue };
            let head_ref = format!("refs/heads/{}", r.name);
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
            // including when the head matches but that tip changed. The check
            // stops at the anchors.
            let checkpoint = checkpoint_path.as_deref().and_then(Checkpoint::load);

            // Step 1: resolve this branch's chain.
            let mut resolved = resolve_chain(source, observer, &head_ref, chain_head, checkpoint)?;
            let mut keys = std::mem::take(&mut resolved.keys);
            let completed = Checkpoint {
                head: chain_head,
                tip: h,
                packs: resolved.packs,
                nodes: resolved.nodes,
            };

            // Apply the branch's chain, check the tip, and finish sealing
            // its windows before taking the worktree lock. The retry below
            // starts from the same budget as this try.
            let before = decoded;
            let (completed, applied_stats) = match apply_and_verify_chain(
                store,
                source,
                observer,
                remote,
                &head_ref,
                resolved,
                h,
                applied,
                require_signed,
                &anchors,
                guard,
                &mut verified,
                &mut decoded,
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
                    let mut fresh = resolve_chain(source, observer, &head_ref, fresh_head, None)?;
                    keys = std::mem::take(&mut fresh.keys);
                    let completed = Checkpoint {
                        head: fresh_head,
                        tip: fresh_h,
                        packs: fresh.packs,
                        nodes: fresh.nodes,
                    };
                    decoded = before;
                    let stats = apply_and_verify_chain(
                        store,
                        source,
                        observer,
                        remote,
                        &head_ref,
                        fresh,
                        fresh_h,
                        applied,
                        require_signed,
                        &anchors,
                        guard,
                        &mut verified,
                        &mut decoded,
                    )?;
                    (completed, stats)
                }
                Err(e) => return Err(e),
            };

            stop.extend(keys);
            ensure_commit_tip(store, &r.name, &completed.tip)?;

            // Publish under a worktree lock acquired fresh for this
            // branch and released once this loop iteration ends. The wait
            // has a deadline only when `lock_wait` sets one: the work above
            // is done, and an interrupt ends it. The fetch holds only the shared lock of the prune
            // guard, and no process blocks on the exclusive one, so this
            // wait cannot deadlock.
            let _lock = wait_for_worktree_lock(layout, observer, lock_wait)?;
            // Make the tracking rename durable before its checkpoint; a
            // crash between them leaves the old record.
            tracking.write(&r.name, &completed.tip)?;
            published.push((r.name.clone(), completed.tip));
            anchors.insert(completed.tip);
            if require_signed {
                // The history of the tip was verified above. Like the
                // checkpoint, the record is a disposable cache: losing it
                // makes a later walk longer, never shorter.
                let _ = crate::anchor::persist(
                    &crate::anchor::path(layout, remote, &r.name),
                    &completed.tip,
                );
            }
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
            report.savings.add(&applied_stats.savings);
        }
        Ok(())
    })();
    // Persist the successful batched prefix even if a later branch failed.
    tracking.commit()?;
    result?;
    if options.prune {
        prune_tracking(layout, source, observer, remote, &listed, lock_wait, report)?;
    }
    // The local tags the tag phase compares with the remote. The phase only
    // adds tags. So if the local tags at the end are these plus the ones it
    // published, with their values, no tag changed while the fetch ran.
    let mut matched_tags = match cursor {
        Some(_) => refs::list_tags(layout)?,
        None => Vec::new(),
    };
    if options.tags {
        TagPhase {
            store,
            layout,
            source,
            observer,
            remote,
            require_signed,
            lock_wait,
            guard,
            applied: &mut *applied,
            verified: &mut verified,
            decoded: &mut decoded,
            stop,
            report: &mut *report,
            published: &mut matched_tags,
        }
        .run()?;
    }
    let attestation_complete = crate::fetch_attestations::run(
        store, layout, source, observer, remote, options, lock_wait, snapshot, report,
    )?;
    if !attestation_complete || report.tags_incomplete() {
        // A refused tag is tried and reported again by the next fetch.
        return Ok(());
    }
    if let Some(cursor) = cursor {
        // A disposable cache: failing to write it costs the next fetch a
        // full walk, never this fetch.
        let tracking_digest = crate::cursor::tracking_digest(layout, remote)?;
        let tag_digest = crate::cursor::tag_digest(layout)?;
        // Another fetch of this remote may have moved a ref this fetch
        // published, for example back to the tip of an older listing. The
        // digest above then describes refs that do not match the cursor, so
        // no record is written and the next fetch lists the remote again. The
        // refs are read after the digest: a ref that still holds its tip now
        // held it when the digest was taken, or the digest no longer matches
        // the refs on disk. Likewise a tag made, moved or deleted while the
        // fetch ran leaves local tags the fetch never compared.
        if tips_still_published(layout, remote, &published)
            && tag_digest == crate::cursor::digest_of(&mut matched_tags)
        {
            let record = crate::cursor::CursorRecord {
                cursor,
                tracking: tracking_digest,
                signed: require_signed,
                tags: options.tags,
                tag_digest,
                attestations: options.attestations && source.supports_attestations(),
                attestmap_head: snapshot.head(),
            };
            let _ = record.persist(cursor_path);
        }
    }
    Ok(())
}

/// Whether every ref in `published` still holds the tip this fetch gave it.
fn tips_still_published(layout: &RepoLayout, remote: &str, published: &[(String, Hash)]) -> bool {
    published.iter().all(|(name, tip)| {
        matches!(refs::read_remote_ref(layout, remote, name), Ok(Some(held)) if held == *tip)
    })
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
    lock_wait: &LockWait,
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
    let _lock = wait_for_worktree_lock(layout, observer, lock_wait)?;
    for name in gone {
        match refs::delete_remote_ref(layout, remote, &name) {
            Ok(()) | Err(refs::RefError::NotFound(_)) => {
                let _ = std::fs::remove_file(crate::anchor::path(layout, remote, &name));
                report.branches_pruned.push(name);
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

/// Whether the last complete fetch saw `cursor`, the remote-tracking refs
/// and local tags are as it left them, and the object of every tracked tip
/// and tag is in the store (a wiped store still heals). A fetch that
/// verifies signatures does not trust a fetch that did not, nor a tracking
/// ref whose tip no signed fetch recorded, such as one a fetch with the
/// opt-out left for a branch the remote no longer lists. A fetch that takes
/// tags does not trust one that did not, nor the reverse. A fetch of a named
/// branch needs its tracking ref.
#[allow(clippy::too_many_arguments)]
fn remote_unchanged(
    store: &ObjectStore,
    layout: &RepoLayout,
    source: &dyn RemoteSource,
    path: &std::path::Path,
    cursor: &kit_core::protocol::RepoCursor,
    remote: &str,
    options: &SyncOptions,
) -> Result<bool, SyncError> {
    let require_signed = options.verify_signatures;
    let target_branch = options.target_branch.as_deref();
    let Some(record) = crate::cursor::CursorRecord::load(path) else {
        return Ok(false);
    };
    if options.refetch_attestations
        || record.attestations != (options.attestations && source.supports_attestations())
    {
        return Ok(false);
    }
    if options.attestations && source.supports_attestations() {
        let path =
            crate::attestation_records::path(layout, source, remote, &options.remote_url, false);
        let attestation = crate::fetch_attestations::load_record(&path);
        if attestation.head != record.attestmap_head
            || attestation
                .pending
                .values()
                .any(|subjects| subjects.iter().any(|subject| store.contains(subject)))
        {
            return Ok(false);
        }
    }
    if record.cursor != *cursor || (require_signed && !record.signed) || record.tags != options.tags
    {
        return Ok(false);
    }
    let mut tags = refs::list_tags(layout)?;
    if record.tag_digest != crate::cursor::digest_of(&mut tags)
        || !tags
            .iter()
            .all(|t| t.hash.is_some_and(|value| store.contains(&value)))
    {
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
    Ok(tracked.iter().all(|r| {
        r.hash.is_some_and(|tip| {
            store.contains(&tip)
                && (!require_signed || crate::anchor::names(layout, remote, &r.name, &tip))
        })
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kit_core::object::{
        Blob, ChunkedBlob, Commit, EntryMode, Identity, KitError, Object, Tree, TreeEntry,
    };
    use kit_core::sign::{self, KeyPair};

    fn put(store: &ObjectStore, object: &Object) -> Hash {
        store
            .write(&kit_core::serialize::serialize(object).unwrap())
            .unwrap()
    }

    /// A signed commit over a tree whose file `big` is `manifest`.
    fn commit_over_file(store: &ObjectStore, manifest: Hash) -> Hash {
        let tree = put(
            store,
            &Object::Tree(Tree {
                entries: vec![TreeEntry {
                    name: b"big".to_vec(),
                    mode: EntryMode::Blob,
                    object_hash: manifest,
                }],
            }),
        );
        let kp = KeyPair::from_seed([0x31; 32]);
        let mut commit = Commit {
            tree_hash: tree,
            parents: vec![],
            author: Identity::ed25519(kp.public.0),
            signer: kp.public.0,
            message: b"chunked".to_vec(),
            timestamp: 1,
            message_hash: [0; 32],
            content_digest: [0; 32],
            signature: [0; 64],
        };
        commit.signature = sign::sign_commit(&commit, &kp).unwrap().0;
        put(store, &Object::Commit(commit))
    }

    fn store() -> (tempfile::TempDir, ObjectStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = ObjectStore::init(&RepoLayout::single(dir.path())).unwrap();
        (dir, store)
    }

    #[test]
    fn a_chunk_of_another_length_than_its_span_is_a_remote_object_error() {
        let (_dir, store) = store();
        let one = put(
            &store,
            &Object::Blob(Blob {
                data: b"12345".to_vec(),
            }),
        );
        let two = put(
            &store,
            &Object::Blob(Blob {
                data: b"1234567".to_vec(),
            }),
        );
        let file = |first_end: u64| {
            let manifest =
                ChunkedBlob::new(first_end + 7, 0, [(one, first_end), (two, first_end + 7)])
                    .unwrap();
            put(&store, &Object::ChunkedBlob(manifest))
        };
        let good = commit_over_file(&store, file(5));
        verify_closure_present(&store, &good).unwrap();

        // The first chunk holds 5 bytes, and its span says 6.
        let bad = commit_over_file(&store, file(6));
        assert!(matches!(
            verify_closure_present(&store, &bad),
            Err(SyncError::RemoteObject(KitError::ChunkLengthMismatch {
                index: 0,
                expected: 6,
                actual: 5
            }))
        ));
    }

    /// A closure that passed the check, and whose chunk file was damaged in
    /// the local store afterwards, is not blamed on the remote: the check
    /// reads the whole closure of the tip, not only what the fetch received.
    #[test]
    fn a_chunk_damaged_in_the_local_store_is_not_blamed_on_the_remote() {
        let (dir, store) = store();
        let one = put(
            &store,
            &Object::Blob(Blob {
                data: b"12345".to_vec(),
            }),
        );
        let two = put(
            &store,
            &Object::Blob(Blob {
                data: b"1234567".to_vec(),
            }),
        );
        let manifest = put(
            &store,
            &Object::ChunkedBlob(ChunkedBlob::new(12, 0, [(one, 5), (two, 12)]).unwrap()),
        );
        let tip = commit_over_file(&store, manifest);
        verify_closure_present(&store, &tip).unwrap();

        // Flip one bit of the length field of the first chunk's file.
        let hex = kit_core::hash::to_hex(&one);
        let path = RepoLayout::single(dir.path())
            .objects_dir()
            .join(&hex[..2])
            .join(&hex[2..]);
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[6] ^= 0x01;
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        perms.set_readonly(false);
        std::fs::set_permissions(&path, perms).unwrap();
        std::fs::write(&path, &bytes).unwrap();

        let error = verify_closure_present(&store, &tip).unwrap_err();
        assert!(
            matches!(
                error,
                SyncError::RemoteObject(KitError::ChunkLengthMismatch { .. })
            ),
            "{error:?}"
        );
        assert_eq!(
            error.to_string(),
            "fetched history has a chunk that does not fit its manifest: chunk 0 holds 4 bytes, but its span is 5 bytes"
        );
        assert!(!error.to_string().contains("remote sent"));
    }

    #[test]
    fn a_chunk_that_is_not_a_blob_is_a_remote_object_error() {
        let (_dir, store) = store();
        let tree = put(&store, &Object::Tree(Tree { entries: vec![] }));
        let manifest = put(
            &store,
            &Object::ChunkedBlob(ChunkedBlob::new(4, 0, [(tree, 4)]).unwrap()),
        );
        let tip = commit_over_file(&store, manifest);
        assert!(matches!(
            verify_closure_present(&store, &tip),
            Err(SyncError::RemoteObject(KitError::ChunkNotBlob { index: 0 }))
        ));
    }
}
