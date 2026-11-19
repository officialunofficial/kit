//! Native repository push: bounded packs and conditioned ref publication.
use crate::packmap::packmap_ref;
use crate::{Observer, RemoteSource, SourceError, SyncError, SyncEvent};
use kit_core::hash::{HASH_LEN, Hash};
use kit_core::pack::{self, Incoming, PackFill, PackWriter, PreparedDelta, PreparedRaw};
use kit_core::protocol::{self, PackKey, UploadLimits};
use kit_core::refs;
use kit_core::store::{ObjectStore, StoreError};
use kit_core::transfer;
use rayon::prelude::*;
use std::path::Path;
mod attestations;
mod delete;
mod deltas;
mod error;
mod force;
mod packmap;
mod split;
mod tags;
pub use delete::{DeleteError, DeleteTarget, DeletedRef};
use deltas::DeltaEncoder;
#[cfg(test)]
use deltas::encode_delta_candidates_batch;
#[cfg(test)]
use deltas::{DELTA_CANDIDATE_BATCH_CAP, cache_delta_bases, delta_plan_fanout_threshold};
pub use error::PushError;
use packmap::{PACKMAP_CAS_ATTEMPTS, advance_packmap, commit_head};
pub use split::{MAX_CHAIN_COMMITS, MAX_SPLIT_STEPS, PushControl, StepAuthority, plan_push_steps};
pub use tags::{
    MAX_BASE_WALK_COMMITS, MAX_TAG_LISTING_BYTES, TagPushOutcome, TagPushRejection, TagPushResult,
    TagSelection,
};

struct PreparedPlan {
    pack: transfer::PackPlan,
    force: Option<force::Snapshot>,
}

struct PushContext<'a> {
    source: &'a dyn RemoteSource,
    observer: &'a dyn Observer<SyncEvent>,
    /// The push's delta spool and pack spools live in this store's spool
    /// directory.
    deltas: DeltaEncoder,
    spool_dir: std::path::PathBuf,
}
impl<'a> PushContext<'a> {
    fn new(
        source: &'a dyn RemoteSource,
        observer: &'a dyn Observer<SyncEvent>,
        store: &ObjectStore,
    ) -> Self {
        let spool_dir = store.spool_dir();
        pack::sweep_spool_dir(&spool_dir);
        Self {
            source,
            observer,
            deltas: DeltaEncoder::new(spool_dir.clone()),
            spool_dir,
        }
    }

    /// A context for tests that build no pack.
    #[cfg(test)]
    fn unspooled(source: &'a dyn RemoteSource, observer: &'a dyn Observer<SyncEvent>) -> Self {
        let spool_dir = std::env::temp_dir();
        Self {
            source,
            observer,
            deltas: DeltaEncoder::new(spool_dir.clone()),
            spool_dir,
        }
    }
}
impl PushContext<'_> {
    /// Whether force pushes take the guarded force driver. It needs only a
    /// serialized advance: it appends, and it re-plans when a concurrent
    /// reset drops the chain its plan depends on, which an ordered force
    /// append could not see.
    fn guards_force(&self) -> bool {
        self.supports_atomic_advance() || self.supports_serialized_advance()
    }
}
impl<'a> std::ops::Deref for PushContext<'a> {
    type Target = dyn RemoteSource + 'a;
    fn deref(&self) -> &Self::Target {
        self.source
    }
}
fn repository_operation_error(tx: &PushContext<'_>, error: SourceError) -> PushError {
    tx.repository_error(error).into()
}

/// How the tracking lease is used for a branch push.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushLease {
    /// Overwrite the remote head even if the new tip does not fast-forward it.
    Force,
    /// Require the last locally tracked remote tip, allowing divergence.
    WithLease,
    /// Require both ancestry from the tracked tip and its live CAS lease. A
    /// branch the remote no longer holds is created.
    FastForward,
}
/// Repository refs to publish.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum PushTarget {
    All {
        force: bool,
    },
    Branch {
        local: String,
        remote: String,
        lease: PushLease,
    },
    /// Local tags, and no branch. Without `force`, a remote tag that holds
    /// another value is refused; with it, the tag moves from the value the
    /// push read.
    Tags {
        selection: TagSelection,
        force: bool,
    },
    /// Delete one remote branch or tag, with its chain ref, under `Match`
    /// (SPEC-TRANSPORT §7.3). A deleted branch's tracking ref goes too.
    Delete(DeleteTarget),
}
/// Caller-supplied policy. Nothing is loaded from config or the environment.
#[derive(Debug)]
#[non_exhaustive]
pub struct PushOptions<'a> {
    /// Publish locally authored attestations after code refs succeed.
    pub attestations: bool,
    /// Resolved endpoint, included in the disposable push cache key.
    pub remote_url: String,
    /// Branch mapping or mirror selection.
    pub target: PushTarget,
    /// Local tracking-ref namespace.
    pub remote_name: &'a str,
    /// Object-store durability schedule.
    pub sync_policy: kit_core::store::SyncPolicy,
    /// Pushes re-baseline a chain past this depth into one node that lists
    /// every pack of the chain; zero disables it.
    pub rebaseline_threshold: usize,
    /// Preferred per-pack payload bound, further limited by the remote and
    /// format. It defaults to [`DEFAULT_PACK_PAYLOAD_CAP`]; the format allows
    /// up to [`pack::MAX_TOTAL_PAYLOAD`]. A push uses larger packs only when a
    /// single commit cannot fit a ticketed advance otherwise, and then only as
    /// large as that commit needs, up to what the format and the remote allow.
    pub pack_payload_cap: u64,
    /// Observer, split bounds and host authority hook.
    pub control: PushControl<'a>,
}

/// The default payload bound of one pushed pack, 256 MiB. A push spools each
/// pack to disk, so the bound sets the size of each upload, not the memory
/// the push itself needs; a transport that buffers the body (SPEC-TRANSPORT
/// §1.1) holds the whole pack: this size by default, more when the cap is
/// raised or one object is larger.
pub const DEFAULT_PACK_PAYLOAD_CAP: u64 = 256 * 1024 * 1024;

impl PushOptions<'_> {
    /// Select a branch mapping or mirror push.
    #[must_use]
    pub fn with_target(mut self, target: PushTarget) -> Self {
        self.target = target;
        self
    }
}
impl Default for PushOptions<'_> {
    fn default() -> Self {
        Self {
            attestations: false,
            remote_url: String::new(),
            target: PushTarget::All { force: false },
            remote_name: "default",
            sync_policy: kit_core::store::SyncPolicy::Batch,
            rebaseline_threshold: 64,
            pack_payload_cap: DEFAULT_PACK_PAYLOAD_CAP,
            control: PushControl::default(),
        }
    }
}
/// Completed branches, advances, the selected single-branch tip, the
/// result of each pushed tag, and the ref a delete removed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PushReport {
    /// Published envelope count.
    pub attestations_pushed: usize,
    /// Nonfatal attestation diagnostics.
    pub attestation_warnings: Vec<String>,
    /// Completed branches.
    pub refs: usize,
    /// Published advances across completed branches. A branch push whose
    /// remote already held the tip publishes none.
    pub steps: usize,
    /// Tip of a selected single branch; absent for a mirror push.
    pub tip: Option<Hash>,
    /// One result per tag of a tag push, sorted by name.
    pub tags: Vec<TagPushResult>,
    /// The ref a delete removed.
    pub deleted: Option<DeletedRef>,
}

impl PushReport {
    /// Whether the push refused any tag.
    #[must_use]
    pub fn tags_rejected(&self) -> bool {
        self.tags
            .iter()
            .any(|tag| matches!(tag.outcome, TagPushOutcome::Rejected(_)))
    }
}
/// Push repository refs and durably record each published tracking ref.
/// The observer is supplied through `options.control.observer`.
pub fn push(
    dir: &Path,
    source: &dyn RemoteSource,
    options: &PushOptions<'_>,
) -> Result<PushReport, PushError> {
    if !source.supports_push() {
        return Err(SourceError::ProtocolError.into());
    }
    let layout = kit_core::layout::discover(dir)?;
    let mut store = ObjectStore::open(&layout)?;
    store.set_sync_policy(options.sync_policy);
    let tx = PushContext::new(source, options.control.observer, &store);
    let mut report = {
        // Held until the last tracking ref is written, as a fetch holds it:
        // a gc that runs during the push deletes nothing, so a tracking ref
        // never names a tip gc removed (see `ObjectStore::prune_guard`).
        let _prune_guard = store.prune_guard()?;
        push_refs(&layout, &store, &tx, options)?
    };
    if options.attestations {
        attestations::run(&layout, &store, &tx, options, &mut report)?;
        tx.observer.event(&SyncEvent::AttestationsPushed {
            count: report.attestations_pushed,
        });
        // The permanence warning is delivered before the first ref publication.
        for message in report
            .attestation_warnings
            .iter()
            .filter(|message| message.as_str() != attestations::PERMANENCE_WARNING)
        {
            tx.observer.event(&SyncEvent::AttestationWarning {
                message: message.clone(),
            });
        }
    }
    Ok(report)
}
#[allow(clippy::too_many_lines)] // one arm per push target
fn push_refs(
    layout: &kit_core::layout::RepoLayout,
    store: &ObjectStore,
    tx: &PushContext<'_>,
    options: &PushOptions<'_>,
) -> Result<PushReport, PushError> {
    match &options.target {
        PushTarget::All { force } => {
            let refs_list = refs::list_refs_with(layout, crate::worktree::fanout_read_batch)?;
            let mut tracking = refs::RemoteRefBatch::new(layout, options.remote_name)?;
            let mut report = PushReport {
                attestations_pushed: 0,
                attestation_warnings: Vec::new(),
                refs: 0,
                steps: 0,
                tip: None,
                tags: Vec::new(),
                deleted: None,
            };
            // The branches the remote holds, read once: a branch it lost is
            // created, as the push of one branch creates it. A listing gone
            // stale can only refuse a push: the remote checks the condition.
            let held: std::collections::HashSet<String> = if *force {
                std::collections::HashSet::new()
            } else {
                tx.list_branches()?
                    .into_iter()
                    .filter(|b| b.hash.is_some())
                    .map(|b| b.name)
                    .collect()
            };
            let result: Result<(), PushError> = (|| {
                for r in refs_list {
                    if tx.observer.cancelled() {
                        return Err(SyncError::Interrupted.into());
                    }
                    let Some(tip) = r.hash else { continue };
                    let condition = if *force {
                        refs::RefWriteCondition::Any
                    } else {
                        match lease(layout, options.remote_name, &r.name)? {
                            refs::RefWriteCondition::Match(_) if !held.contains(&r.name) => {
                                refs::RefWriteCondition::Missing
                            }
                            condition => condition,
                        }
                    };
                    tx.observer.event(&SyncEvent::PushBranchStarted {
                        branch: r.name.clone(),
                    });
                    report.steps += run_steps(
                        tx,
                        store,
                        &r.name,
                        tip,
                        condition,
                        options.rebaseline_threshold,
                        options.pack_payload_cap,
                        &options.control,
                        &mut |published| {
                            publish_tracking(layout, tx, || {
                                Ok(tracking.write(&r.name, &published)?)
                            })
                        },
                    )?;
                    report.refs += 1;
                }
                Ok(())
            })();
            tracking.commit()?;
            result?;
            Ok(report)
        }
        PushTarget::Branch {
            local,
            remote,
            lease: policy,
        } => {
            let tip = refs::read_ref(layout, local)?
                .ok_or_else(|| SyncError::RemoteBranchMissing(local.clone()))?;
            refs::check_pushable_branch(remote)?;
            // Read once: the fast-forward check and the lease must use the
            // same value. A fetch that moved the tracking ref between two
            // reads could pass the check against one tip and lease another,
            // so a plain push would replace a head it never checked.
            let tracked = refs::read_remote_ref(layout, options.remote_name, remote)?;
            // The remote's head decides, not the tracking ref: the remote
            // may have lost the branch since this repository last saw it.
            let head = tx.read_ref(&format!("refs/heads/{remote}"))?;
            let at_tip = head == Some(tip);
            if at_tip && tx.read_ref(&packmap_ref(remote))?.is_some() {
                publish_tracking(layout, tx, || {
                    Ok(refs::write_remote_ref(
                        layout,
                        options.remote_name,
                        remote,
                        &tip,
                    )?)
                })?;
                return Ok(PushReport {
                    attestations_pushed: 0,
                    attestation_warnings: Vec::new(),
                    refs: 1,
                    steps: 0,
                    tip: Some(tip),
                    tags: Vec::new(),
                    deleted: None,
                });
            }
            if !at_tip
                && matches!(policy, PushLease::FastForward)
                && head.is_some()
                && let Some(tracked) = tracked
                && !kit_core::ops::merge::is_ancestor(store, tracked, tip)?
            {
                return Err(PushError::NonFastForwardPush {
                    branch: remote.clone(),
                });
            }
            let condition = if at_tip {
                // Rebuild the missing packmap only for the head we saw.
                refs::RefWriteCondition::Match(tip)
            } else {
                let lease = tracked.map_or(
                    refs::RefWriteCondition::Missing,
                    refs::RefWriteCondition::Match,
                );
                match (policy, lease) {
                    (PushLease::Force, _) => refs::RefWriteCondition::Any,
                    // A fast-forward push of a branch the remote does not hold
                    // creates it: there is nothing on the remote to overwrite.
                    (PushLease::FastForward, refs::RefWriteCondition::Match(_))
                        if head.is_none() =>
                    {
                        refs::RefWriteCondition::Missing
                    }
                    (_, condition) => condition,
                }
            };
            tx.observer.event(&SyncEvent::PushBranchStarted {
                branch: remote.clone(),
            });
            let steps = run_steps(
                tx,
                store,
                remote,
                tip,
                condition,
                options.rebaseline_threshold,
                options.pack_payload_cap,
                &options.control,
                &mut |published| {
                    publish_tracking(layout, tx, || {
                        Ok(refs::write_remote_ref(
                            layout,
                            options.remote_name,
                            remote,
                            &published,
                        )?)
                    })
                },
            )?;
            Ok(PushReport {
                attestations_pushed: 0,
                attestation_warnings: Vec::new(),
                refs: 1,
                steps,
                tip: Some(tip),
                tags: Vec::new(),
                deleted: None,
            })
        }
        PushTarget::Tags { selection, force } => {
            push_tag_report(layout, store, tx, options, selection, *force)
        }
        PushTarget::Delete(target) => Ok(PushReport {
            attestations_pushed: 0,
            attestation_warnings: Vec::new(),
            refs: 0,
            steps: 0,
            tip: None,
            tags: Vec::new(),
            deleted: Some(delete::delete(layout, tx, options.remote_name, target)?),
        }),
    }
}

fn push_tag_report(
    layout: &kit_core::layout::RepoLayout,
    store: &ObjectStore,
    tx: &PushContext<'_>,
    options: &PushOptions<'_>,
    selection: &TagSelection,
    force: bool,
) -> Result<PushReport, PushError> {
    let tags = tags::push_tags(
        layout,
        store,
        tx,
        options.remote_name,
        selection,
        force,
        options.pack_payload_cap,
    )?;
    Ok(PushReport {
        attestations_pushed: 0,
        attestation_warnings: Vec::new(),
        refs: 0,
        steps: 0,
        tip: None,
        tags,
        deleted: None,
    })
}
/// Write a tracking ref under the worktree lock, as a fetch publishes one.
/// gc holds that lock across its mark and sweep, so it either marks from
/// the new ref or finishes before the ref exists; the prune guard the push
/// holds keeps its sweep from deleting anything meanwhile.
fn publish_tracking(
    layout: &kit_core::layout::RepoLayout,
    tx: &PushContext<'_>,
    write: impl FnOnce() -> Result<(), PushError>,
) -> Result<(), PushError> {
    let _lock = crate::lock::wait_for_lock(
        layout.worktree_state_dir(),
        kit_core::repo_lock::WORKTREE_LOCK,
        tx.observer,
        &crate::lock::LockWait::new(None),
    )?;
    write()
}

fn lease(
    layout: &kit_core::layout::RepoLayout,
    remote: &str,
    branch: &str,
) -> Result<refs::RefWriteCondition, PushError> {
    Ok(refs::read_remote_ref(layout, remote, branch)?.map_or(
        refs::RefWriteCondition::Missing,
        refs::RefWriteCondition::Match,
    ))
}
/// Push an already selected tip; the host records each published step.
#[allow(clippy::too_many_arguments)]
pub fn push_branch_steps(
    source: &dyn RemoteSource,
    store: &ObjectStore,
    branch: &str,
    tip: Hash,
    condition: refs::RefWriteCondition,
    rebaseline_threshold: usize,
    pack_payload_cap: u64,
    control: &PushControl<'_>,
    on_step: &mut dyn FnMut(Hash) -> Result<(), PushError>,
) -> Result<usize, PushError> {
    if !source.supports_push() {
        return Err(SourceError::ProtocolError.into());
    }
    let tx = PushContext::new(source, control.observer, store);
    run_steps(
        &tx,
        store,
        branch,
        tip,
        condition,
        rebaseline_threshold,
        pack_payload_cap,
        control,
        on_step,
    )
}

/// Why an advance was re-planned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RetryReason {
    /// The server no longer holds a delta base the plan relied on.
    #[error(
        "the server no longer holds a delta base this push relied on, so it must be re-sent as a full closure (ask the operator whether the repository was restored from an older copy)"
    )]
    LostDeltaBase,
    /// The upload ticket or packlist was rejected, so the push was planned
    /// again against the remote's current head, which may have moved.
    #[error(
        "the upload was rejected and the push was re-planned against the remote's current head, which may have moved (fetch and merge, then push again)"
    )]
    Replanned,
    /// A concurrent writer replaced the chain used by a force-push plan.
    #[error("the pack map changed under this force push and its transfer was re-planned")]
    PackmapChanged,
}

#[allow(clippy::too_many_arguments)]
fn run_steps(
    tx: &PushContext<'_>,
    store: &ObjectStore,
    branch: &str,
    tip: Hash,
    condition: refs::RefWriteCondition,
    rebaseline_threshold: usize,
    pack_payload_cap: u64,
    control: &PushControl<'_>,
    on_step: &mut dyn FnMut(Hash) -> Result<(), PushError>,
) -> Result<usize, PushError> {
    let limits = force::checked_upload_limits(tx, condition)?;
    let mut single = |plan, pack_payload_cap| {
        push_step_recovering(
            tx,
            store,
            branch,
            tip,
            condition,
            rebaseline_threshold,
            pack_payload_cap,
            plan,
        )?;
        on_step(tip)?;
        Ok(1)
    };
    let Some(budget) = limits.data_packs_per_advance else {
        return single(None, pack_payload_cap);
    };
    refs::check_pushable_branch(branch)?;
    let LeaseHead::Holds(remote_tip) = lease_head(tx, branch, condition, tip)? else {
        // A repair must rebuild the current tip in one advance. Publishing
        // an intermediate commit would rewind the branch.
        return single(None, pack_payload_cap);
    };
    tx.observer.event(&SyncEvent::PushPlanning { done: 0 });
    let plan = tx.deltas.plan(store, tip, remote_tip)?;
    tx.observer.event(&SyncEvent::PushPlanning {
        done: plan.raw.len() + plan.deltas.len(),
    });
    let cap = effective_payload_cap(pack_payload_cap, limits.max_pack_bytes)?;
    // The total, not the ticketed count: compression can merge packs and carry
    // one past the ticket threshold, and only the exact dry seal below knows.
    if estimate_pack_sizes(store, &plan, cap, limits.max_pack_bytes)?.len() <= budget {
        let force = force::snapshot(tx, branch, remote_tip, condition)?;
        return single(Some(PreparedPlan { pack: plan, force }), pack_payload_cap);
    }
    // The estimate is uncompressed: a push that compresses into the budget
    // is not split (exact dry seal), and one against a remote tip this store
    // lacks is left to the head CAS rather than walking all of history.
    if remote_tip.is_some_and(|remote| !store.contains(&remote)) {
        return single(None, pack_payload_cap);
    }
    match dry_seal(store, plan, cap, limits, tx.observer) {
        Err(PushError::PushTooLarge { .. }) => {}
        Err(error @ PushError::Sync(SyncError::Interrupted)) => return Err(error),
        _ => return single(None, pack_payload_cap),
    }
    // The split fixes the pack size for the whole push: larger than the
    // preferred one only when a single commit needs it.
    let split::SplitPlan {
        steps,
        payload_cap: pack_payload_cap,
    } = split::plan_split(
        store,
        &tx.deltas,
        tip,
        remote_tip,
        limits,
        pack_payload_cap,
        control,
        condition,
        branch,
    )?;
    if steps.len() == 1 {
        return single(None, pack_payload_cap);
    }
    publish_steps(
        tx,
        store,
        branch,
        steps,
        condition,
        rebaseline_threshold,
        pack_payload_cap,
        on_step,
    )
}

/// Advance the remote head through `steps` one after another, each a `Match`
/// on the previous, and report how the push stopped if one fails.
#[allow(clippy::too_many_arguments)]
fn publish_steps(
    tx: &PushContext<'_>,
    store: &ObjectStore,
    branch: &str,
    steps: Vec<Hash>,
    condition: refs::RefWriteCondition,
    rebaseline_threshold: usize,
    pack_payload_cap: u64,
    on_step: &mut dyn FnMut(Hash) -> Result<(), PushError>,
) -> Result<usize, PushError> {
    let total = steps.len();
    let mut published: Option<Hash> = None;
    for (index, step_tip) in steps.into_iter().enumerate() {
        let step_condition = published.map_or(condition, refs::RefWriteCondition::Match);
        let mut landed = false;
        let outcome = (|| {
            if tx.observer.cancelled() {
                return Err(PushError::Sync(SyncError::Interrupted));
            }
            tx.observer.event(&SyncEvent::PushStep {
                index: index + 1,
                total,
            });
            push_step_recovering(
                tx,
                store,
                branch,
                step_tip,
                step_condition,
                rebaseline_threshold,
                pack_payload_cap,
                None,
            )?;
            landed = true;
            on_step(step_tip)?;
            tx.observer.event(&SyncEvent::PushStepCommitted {
                index: index + 1,
                total,
                tip: step_tip,
            });
            Ok(())
        })();
        if landed {
            published = Some(step_tip);
        }
        if let Err(cause) = outcome {
            return Err(match published {
                Some(head) => PushError::SplitInterrupted {
                    branch: branch.to_owned(),
                    head: kit_core::hash::to_hex(&head),
                    published: index + usize::from(landed),
                    total,
                    cause: Box::new(cause),
                },
                None => cause,
            });
        }
    }
    Ok(total)
}

/// One advance to `tip` with the restart-once recovery: a rejected ticket or
/// packlist re-plans the same way, a missing delta base re-plans as the full
/// closure. `plan` is an already-computed plan against the remote's current
/// tip, used for the first attempt only.
#[allow(clippy::too_many_arguments)]
fn push_step_recovering(
    tx: &PushContext<'_>,
    store: &ObjectStore,
    branch: &str,
    tip: Hash,
    condition: refs::RefWriteCondition,
    rebaseline_threshold: usize,
    pack_payload_cap: u64,
    plan: Option<PreparedPlan>,
) -> Result<(), PushError> {
    if matches!(condition, refs::RefWriteCondition::Any) && tx.guards_force() {
        refs::check_pushable_branch(branch)?;
        return force::push_step(
            tx,
            store,
            branch,
            tip,
            rebaseline_threshold,
            pack_payload_cap,
            plan,
        );
    }
    let once = |condition, retry, plan| {
        push_branch_once(
            tx,
            store,
            branch,
            tip,
            condition,
            rebaseline_threshold,
            pack_payload_cap,
            retry,
            plan,
        )
    };
    let recovering = |condition, plan| match once(condition, None, plan) {
        Err(PushError::TicketRejected | PushError::PacklistNotInRepository) => {
            once(condition, Some(RetryReason::Replanned), None)
        }
        Err(PushError::DeltaBaseUnavailable) => {
            once(condition, Some(RetryReason::LostDeltaBase), None)
        }
        result => result,
    };
    if !matches!(condition, refs::RefWriteCondition::Any) {
        return recovering(condition, plan.map(|prepared| prepared.pack));
    }

    // On an ordered transport a delete can remove both refs between the
    // packmap write and the head write. Lease the observed head so this
    // write cannot recreate it from a plan based on the deleted packmap.
    refs::check_pushable_branch(branch)?;
    let head_ref = crate::packmap::branch_head_ref(branch);
    for _ in 0..PACKMAP_CAS_ATTEMPTS {
        if tx.observer.cancelled() {
            return Err(SyncError::Interrupted.into());
        }
        let condition = tx.read_ref(&head_ref)?.map_or(
            refs::RefWriteCondition::Missing,
            refs::RefWriteCondition::Match,
        );
        match recovering(condition, None) {
            Err(PushError::NonFastForwardPush { .. }) => {}
            result => return result,
        }
    }
    Err(PushError::NonFastForwardPush {
        branch: branch.to_owned(),
    })
}

/// The remote head a push plans against, read before it plans.
enum LeaseHead {
    /// The head, which the push's head condition holds for.
    Holds(Option<Hash>),
    /// The lease holds for the tip, but a repair must send its entire closure.
    MissingPackmap,
    /// The head is already the tip and has a packmap: an earlier attempt landed.
    Landed,
}

/// Read the head a push of `tip` plans against, and refuse a lease that
/// does not hold for it.
///
/// A plan leaves out what the head it reads holds, so the head write must
/// condition on that head. A lease that differs could hold again later,
/// after the head moved away and back and a reset dropped what the plan
/// left out; the head write would then publish a tip the packmap cannot
/// rebuild. Such a push would fail its head condition at once, so it is
/// refused before it plans. A head at `tip` with a packmap can also be
/// the result of an earlier attempt that landed.
fn lease_head(
    tx: &PushContext<'_>,
    branch: &str,
    condition: refs::RefWriteCondition,
    tip: Hash,
) -> Result<LeaseHead, PushError> {
    let head = tx.read_ref(&format!("refs/heads/{branch}"))?;
    let holds = match condition {
        refs::RefWriteCondition::Any => true,
        refs::RefWriteCondition::Missing => head.is_none(),
        refs::RefWriteCondition::Match(lease) => head == Some(lease),
    };
    if head == Some(tip) {
        let has_packmap = tx.read_ref(&packmap_ref(branch))?.is_some();
        if holds && !has_packmap {
            return Ok(LeaseHead::MissingPackmap);
        }
        if !holds && has_packmap {
            return Ok(LeaseHead::Landed);
        }
    }
    if holds {
        Ok(LeaseHead::Holds(head))
    } else {
        Err(PushError::NonFastForwardPush {
            branch: branch.to_owned(),
        })
    }
}

#[allow(clippy::too_many_arguments)]
fn push_branch_once(
    tx: &PushContext<'_>,
    store: &ObjectStore,
    branch: &str,
    tip: Hash,
    condition: refs::RefWriteCondition,
    rebaseline_threshold: usize,
    pack_payload_cap: u64,
    retry: Option<RetryReason>,
    preplanned: Option<transfer::PackPlan>,
) -> Result<(), PushError> {
    let force_self_contained = retry == Some(RetryReason::LostDeltaBase);
    // Both wire names must fit SPEC-REFS §3's bound; a local branch named
    // before `MAX_BRANCH_NAME_BYTES` existed may not. Say so by name
    // rather than as a transport's "invalid ref name".
    refs::check_pushable_branch(branch)?;
    // Diff against the remote's CURRENT tip so we send only what it lacks
    // and can delta against bases it already holds. Planning is an
    // optimization; the head CAS below remains authoritative.
    // A caller that already planned against the remote's current tip (the
    // split decision does) passes its plan, so it is diffed once.
    let Some(plan) = plan_branch(
        tx,
        store,
        branch,
        tip,
        condition,
        force_self_contained,
        preplanned,
    )?
    else {
        return Ok(());
    };

    let limits = tx.upload_limits();
    // Payload and serialized-byte limits are checked separately. Framing
    // overhead grows with the entry count, so a fixed margin is insufficient.
    let effective_cap = effective_payload_cap(pack_payload_cap, limits.max_pack_bytes)?;

    if plan.is_empty() {
        // Nothing to send — the remote already holds the closure; just move
        // the head (no packmap change needed, so no chain walk and no atomic
        // two-ref advance).
        return commit_head(tx, &format!("refs/heads/{branch}"), condition, &tip, branch);
    }

    if tx.observer.cancelled() {
        return Err(PushError::Sync(SyncError::Interrupted));
    }

    // A retry re-planned the push: make sure the new plan still fits before
    // uploading any of it, so the failure leaves no half-uploaded advance.
    if let Some(reason) = retry
        && let Some(budget) = limits.data_packs_per_advance
        // The packs the estimate counts, not only its ticketed ones: a real
        // seal can merge two estimated packs into one that is ticketed.
        && estimate_pack_sizes(store, &plan, effective_cap, limits.max_pack_bytes)?.len() > budget
        && let Err(PushError::PushTooLarge { packs, limit, .. }) = dry_seal(
            store,
            plan.clone(),
            effective_cap,
            limits,
            tx.observer,
        )
    {
        return Err(PushError::RetryTooLarge {
            reason,
            packs,
            limit,
        });
    }

    // No pre-flight PushTooLarge: the estimate uses uncompressed sizes, so it
    // would refuse pushes that compress into the budget. The seal-time gate is
    // exact and still stops before the BeginUpload of the first pack past the
    // data-pack budget.

    // Build the plan into one or more payload-bounded packs (splitting
    // when the plan exceeds `pack_payload_cap`) and upload
    // each as it's sealed. Raws first (non-blobs before blobs), then
    // deltas (their bases are external — resolved from the fetcher's
    // store via earlier packs, never a base introduced earlier in THIS
    // push — so no in-pack ordering is required across the split,
    // SPEC-PACKFILE §4).
    //
    // `self_contained` is read out before `plan` moves into
    // `build_and_upload_packs` (which consumes it by value so its
    // delta streams can be handed to the compression fan-out without
    // an extra clone — see that function's doc comment).
    let self_contained = plan.self_contained;
    let head_ref = format!("refs/heads/{branch}");
    let pack_keys = build_and_upload_packs(tx, &head_ref, store, plan, effective_cap, limits)?;

    // Chain the packs onto the packmap and move the head together. A
    // transactional transport applies both atomically; the default writes
    // the packmap, then the head. Either way the head never lands past a
    // packmap that cannot reconstruct it. `self_contained` lets a
    // full-closure push reset a broken chain. A failed advance leaves the
    // head untouched.
    advance_packmap(
        tx,
        branch,
        &pack_keys,
        self_contained,
        rebaseline_threshold,
        condition,
        tip,
    )
}

/// The plan for `tip`, or `None` when an earlier attempt already landed it.
fn plan_branch(
    tx: &PushContext<'_>,
    store: &ObjectStore,
    branch: &str,
    tip: Hash,
    condition: refs::RefWriteCondition,
    force_self_contained: bool,
    preplanned: Option<transfer::PackPlan>,
) -> Result<Option<transfer::PackPlan>, PushError> {
    if let Some(plan) = preplanned {
        return Ok(Some(plan));
    }
    // A full closure depends on no remote head, so it reads none.
    let remote_tip = if force_self_contained {
        None
    } else {
        match lease_head(tx, branch, condition, tip)? {
            LeaseHead::Holds(head) => head,
            LeaseHead::MissingPackmap => None,
            LeaseHead::Landed => return Ok(None),
        }
    };
    // Plan FIRST, against the remote's current tip (for speed): a no-op push
    // (the remote already holds this closure) yields an empty plan and takes
    // the cheap head-only path below WITHOUT walking the packmap chain. Only
    // a push that actually has objects to send pays the O(depth) chain probe.
    Ok(Some(tx.deltas.plan(store, tip, remote_tip)?))
}

/// The per-pack payload cap: `requested`, bounded by the pack format and
/// by the limit the remote advertises. A cap of zero is an error.
fn effective_payload_cap(requested: u64, advertised: Option<u64>) -> Result<u64, PushError> {
    // The serialized limit's overhead margin is exact and dynamic: header,
    // trailer and one frame per entry. `PackFill::seals_before` applies it on each add.
    let cap = requested
        .min(pack::MAX_TOTAL_PAYLOAD)
        .min(advertised.unwrap_or(pack::MAX_TOTAL_PAYLOAD));
    if cap == 0 {
        return Err(PushError::from(SourceError::PayloadTooLarge(0)));
    }
    Ok(cap)
}

fn ticketed_pack(limits: UploadLimits, serialized_size: u64) -> bool {
    limits.data_packs_per_advance.is_some()
        && serialized_size >= limits.ticket_threshold_bytes.unwrap_or(0)
}

fn estimate_pack_sizes(
    store: &ObjectStore,
    plan: &transfer::PackPlan,
    payload_cap: u64,
    max_pack_bytes: Option<u64>,
) -> Result<Vec<u64>, PushError> {
    estimate_pack_sizes_with(store, plan, payload_cap, max_pack_bytes, usize::MAX)
}

/// [`estimate_pack_sizes`] with the entry bound a pack holds, so a test can
/// reach it without a million entries.
fn estimate_pack_sizes_with(
    store: &ObjectStore,
    plan: &transfer::PackPlan,
    payload_cap: u64,
    max_pack_bytes: Option<u64>,
    max_entries: usize,
) -> Result<Vec<u64>, PushError> {
    let mut packs = Vec::new();
    let mut fill = PackFill::default();
    let raw = plan
        .raw
        .iter()
        .map(|hash| {
            store
                .object_metadata(hash)
                .map(|meta| Incoming::raw(meta.len(), meta.len()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    // An entry may compress on the wire, and then a reader counts its whole
    // length as decoded. The estimate counts every raw object and every delta
    // stream as compressed, so it never counts fewer packs than a real seal
    // needs. It may count more. The plan lists the deltas of one base next to
    // each other, so none of them brings a base back.
    let deltas = plan
        .deltas
        .iter()
        .map(|delta| {
            Ok(Incoming::delta(
                (HASH_LEN + delta.stream.len()) as u64,
                &delta.stream.bytes().map_err(StoreError::Io)?,
                true,
                0,
            ))
        })
        .collect::<Result<Vec<_>, PushError>>()?;
    for add in raw.into_iter().chain(deltas) {
        if fill.seals_before(
            add,
            payload_cap,
            protocol::max_pack_bytes(max_pack_bytes),
            max_entries,
        ) {
            packs.push(fill.serialized_bound());
            fill = PackFill::default();
        }
        fill = fill.with(add);
    }
    if fill.entries() > 0 {
        packs.push(fill.serialized_bound());
    }
    Ok(packs)
}

/// Where sealed packs go: to the remote, or nowhere (an exact local dry run of
/// the seal, for the split's pre-flight check).
#[derive(Clone, Copy, PartialEq, Eq)]
enum SealKind {
    Upload,
    Count,
}

/// Bytes of raw objects (or delta streams) read into memory and compressed
/// for one batch of entries, 64 MiB. A single larger object is a batch of its
/// own. The pack itself is spooled to disk, so the push holds one batch, not
/// a pack; a transport that buffers the body still holds the pack.
pub const PUSH_BATCH_BYTES: u64 = 64 << 20;

/// Build `plan`'s entries into one or more packs, each staying under
/// `payload_cap` bytes of wire payload, uploading each pack to `tx` as
/// soon as it's sealed. Returns the ordered pack keys — build order is
/// apply order, threaded straight into [`advance_packmap`].
///
/// Each pack is written to an unnamed spool file in the store's spool
/// directory as its entries are added, sealed there, and uploaded from the
/// file: its key and length come from the sealed spool before the first byte
/// is sent, and every upload attempt reads that same file. The spool is
/// dropped once the upload succeeds or fails.
///
/// A single linear left-to-right pass over the plan's already-ordered
/// `raw ++ deltas` sequence is enough: [`transfer::plan_pack_with`] never
/// deltas an entry against a base introduced earlier in THIS push
/// (every delta's base is already on the remote from a prior push), so
/// packs can be sealed independently the instant one would exceed the
/// cap — no intra-push base-ordering hazard to preserve across the
/// split.
///
/// Sizing uses a conservative *uncompressed* upper bound per entry
/// (`bytes.len()` for a raw, `HASH_LEN + stream.len()` for a delta)
/// checked against [`PackWriter::total_payload`]'s real (compressed)
/// running total, so a sealed pack never exceeds `payload_cap` — it may
/// under-fill when compression bites, yielding more packs than the
/// theoretical minimum, never fewer. One object larger than the cap still
/// goes into a pack of its own, and that pack is the only kind that can
/// exceed the cap. Entries are read and compressed in batches of at most
/// [`PUSH_BATCH_BYTES`] and [`pack_fanout_threshold`] entries, so the memory
/// the push itself holds is one batch (twice, raw bytes and frames), whatever
/// the pack size; a transport that buffers the body also holds the pack.
///
/// Takes `plan` BY VALUE: each batch drains its deltas out of `plan.deltas`.
/// The caller reads whatever it needs off `plan` (just `self_contained`)
/// before making this call.
fn build_and_upload_packs(
    tx: &PushContext<'_>,
    head_ref: &str,
    store: &ObjectStore,
    plan: transfer::PackPlan,
    payload_cap: u64,
    limits: UploadLimits,
) -> Result<Vec<Hash>, PushError> {
    let mut pack_keys = Vec::new();
    build_packs(
        SealKind::Upload,
        || PackWriter::spool(&tx.spool_dir).map_err(PushError::from),
        |writer, ticketed| {
            let spooled = writer.finish_spool()?;
            let is_ticketed = check_sealed(spooled.len(), limits, ticketed)?;
            tx.upload_pack(&spooled, &PackKey::from_hash(spooled.key()), head_ref)
                .map_err(|error| repository_operation_error(tx, error))?;
            // Upload is complete — report the real byte count handed to the
            // transport, not an estimate.
            tx.observer.event(&SyncEvent::PackUploaded {
                bytes: spooled.len(),
            });
            pack_keys.push(spooled.key());
            Ok(is_ticketed)
        },
        store,
        plan,
        limits,
        payload_cap,
        tx.observer,
    )?;
    Ok(pack_keys)
}

/// The exact seal of `plan` that [`build_and_upload_packs`] would make, with
/// nothing stored or sent: each pack goes into a writer that only counts its
/// bytes. Returns how many packs the seal makes, or the error the real seal
/// would return before its first upload past a limit.
fn dry_seal(
    store: &ObjectStore,
    plan: transfer::PackPlan,
    payload_cap: u64,
    limits: UploadLimits,
    observer: &dyn Observer<SyncEvent>,
) -> Result<usize, PushError> {
    let mut packs = 0;
    build_packs(
        SealKind::Count,
        || Ok(pack::CountingWriter::counting()),
        |writer, ticketed| {
            let is_ticketed = check_sealed(writer.finish_count()?, limits, ticketed)?;
            packs += 1;
            Ok(is_ticketed)
        },
        store,
        plan,
        limits,
        payload_cap,
        observer,
    )?;
    Ok(packs)
}

/// Check a sealed pack of `len` bytes against the remote's limits before it
/// is uploaded, `ticketed` being the ticketed packs sealed before it.
/// Returns whether it takes a ticket.
fn check_sealed(len: u64, limits: UploadLimits, ticketed: usize) -> Result<bool, PushError> {
    let is_ticketed = ticketed_pack(limits, len);
    if let Some(budget) = limits.data_packs_per_advance
        && is_ticketed
        && ticketed >= budget
    {
        return Err(PushError::PushTooLarge {
            packs: ticketed + 1,
            limit: budget,
            commit: None,
            holds_remote_head: false,
        });
    }
    if len > protocol::max_pack_bytes(limits.max_pack_bytes) {
        return Err(PushError::from(SourceError::PayloadTooLarge(
            kit_core::protocol::saturating_usize(len),
        )));
    }
    Ok(is_ticketed)
}

/// The seal loop of [`build_and_upload_packs`] and [`dry_seal`]: `fresh`
/// makes each pack's writer, and `seal` finishes one and returns whether it
/// took a ticket, given the ticketed packs sealed before it.
#[allow(clippy::too_many_arguments)]
fn build_packs<W: std::io::Write>(
    kind: SealKind,
    mut fresh: impl FnMut() -> Result<PackWriter<W>, PushError>,
    mut seal: impl FnMut(PackWriter<W>, usize) -> Result<bool, PushError>,
    store: &ObjectStore,
    plan: transfer::PackPlan,
    limits: UploadLimits,
    payload_cap: u64,
    observer: &dyn Observer<SyncEvent>,
) -> Result<(), PushError> {
    let mut ticketed = 0;
    let mut seal_one = |w: PackWriter<W>, ticketed: &mut usize| {
        if observer.cancelled() {
            return Err(PushError::Sync(SyncError::Interrupted));
        }
        if seal(w, *ticketed)? {
            *ticketed += 1;
        }
        Ok(())
    };
    let mut w = fresh()?;
    let max_entries = pack_fanout_threshold().max(1);
    let transfer::PackPlan {
        raw, mut deltas, ..
    } = plan;

    // Raw entries: size each via a metadata `stat` (cheap — no content
    // read) so batches can be capped by real bytes, not just count,
    // *before* any object's content is actually read into memory.
    let raw_sizes: Vec<u64> = raw
        .iter()
        .map(|h| Ok(store.object_metadata(h)?.len()))
        .collect::<Result<_, PushError>>()?;
    let mut start = 0;
    for len in size_capped_batch_lens(&raw_sizes, PUSH_BATCH_BYTES, max_entries) {
        let chunk = &raw[start..start + len];
        let parallel = batch_fans_out(len, raw_sizes[start..start + len].iter().sum());
        start += len;
        for entry in prepare_raw_batch(store, chunk, parallel)? {
            if should_seal(
                &w,
                entry.incoming(),
                payload_cap,
                limits.max_pack_bytes,
                usize::MAX,
            ) {
                seal_one(std::mem::replace(&mut w, fresh()?), &mut ticketed)?;
            }
            w.push_prepared_raw(entry)?;
            // Honest progress: one real object just got staged into
            // the outgoing pack. Never git's
            // Enumerating/Counting/Compressing lines — see `SyncEvent`.
            report_packed(kind, observer);
        }
    }

    // Delta entries: sizes are known from the plan with no I/O, so batch
    // lengths are computed directly off them; `drain` then moves each
    // batch's `PlannedDelta`s out of `deltas`, and each batch reads its
    // streams back from the push's delta spool.
    let delta_sizes: Vec<u64> = deltas
        .iter()
        .map(|d| (HASH_LEN + d.stream.len()) as u64)
        .collect();
    let mut start = 0;
    for len in size_capped_batch_lens(&delta_sizes, PUSH_BATCH_BYTES, max_entries) {
        let chunk: Vec<transfer::PlannedDelta> = deltas.drain(..len).collect();
        let parallel = batch_fans_out(len, delta_sizes[start..start + len].iter().sum());
        start += len;
        for entry in prepare_delta_batch(chunk, parallel)? {
            if should_seal(
                &w,
                entry.incoming(&w),
                payload_cap,
                limits.max_pack_bytes,
                usize::MAX,
            ) {
                seal_one(std::mem::replace(&mut w, fresh()?), &mut ticketed)?;
            }
            w.push_prepared_delta(entry)?;
            report_packed(kind, observer);
        }
    }

    seal_one(w, &mut ticketed)
}

/// Honest progress: one real object just got staged into the outgoing
/// pack. Never git's Enumerating/Counting/Compressing lines — see
/// `SyncEvent`. A dry seal stages nothing to send and reports nothing.
fn report_packed(kind: SealKind, observer: &dyn Observer<SyncEvent>) {
    if kind == SealKind::Upload {
        observer.event(&SyncEvent::ObjectsPacked { count: 1 });
    }
}

/// Split `sizes` (each item's conservative uncompressed byte size, in
/// original order) into batch lengths such that each batch's summed
/// size stays at-or-under `byte_cap` bytes AND at-or-under
/// `max_entries` items — whichever limit a batch hits first ends it.
/// Mirrors [`should_seal`]'s "never true for an empty writer" escape
/// hatch: a single item over `byte_cap` on its own still gets a
/// one-item batch of its own rather than looping forever or being
/// silently dropped.
///
/// [`build_packs`] passes [`PUSH_BATCH_BYTES`]: the batch is what a push
/// reads and compresses at once, so the byte cap bounds its memory
/// whatever the pack size, and the entry cap keeps a batch of many small
/// objects within `pack_fanout_threshold`'s parallel-dispatch sizing and
/// progress reporting timely.
fn size_capped_batch_lens(sizes: &[u64], byte_cap: u64, max_entries: usize) -> Vec<usize> {
    let mut lens = Vec::new();
    let mut running: u64 = 0;
    let mut count = 0usize;
    for &size in sizes {
        if count > 0 && (running.saturating_add(size) > byte_cap || count >= max_entries) {
            lens.push(count);
            running = 0;
            count = 0;
        }
        running += size;
        count += 1;
    }
    if count > 0 {
        lens.push(count);
    }
    lens
}

/// Entries-per-thread budget below which [`prepare_raw_batch`] /
/// [`prepare_delta_batch`] read + zstd-compress sequentially instead of
/// fanning out across rayon's thread pool, for a pool of a given size.
/// Same crossover shape as `add.rs`'s `HASH_FANOUT_FILES_PER_THREAD`
/// — rayon's pool-dispatch overhead loses to a plain loop
/// below a few entries per thread and wins clearly above it — measured
/// for the pack-build path specifically with `cargo bench -p
/// kit-benches --bench pack_build_fanout`.
///
/// Also doubles as one of [`size_capped_batch_lens`]'s two caps: a
/// batch that isn't cut short by [`PUSH_BATCH_BYTES`] first comes out exactly
/// this many entries long (until the final, possibly-shorter
/// remainder), so such a batch always takes the parallel path. A batch the
/// byte cap cuts short fans out by [`PACK_FANOUT_MIN_BYTES`] instead.
const PACK_FANOUT_ENTRIES_PER_THREAD: usize = 8;

/// The per-batch entry count [`build_and_upload_packs`] fans out across
/// rayon at — see [`PACK_FANOUT_ENTRIES_PER_THREAD`].
fn pack_fanout_threshold() -> usize {
    crate::fanout::threshold(PACK_FANOUT_ENTRIES_PER_THREAD)
}

/// Bytes from which a batch of two or more entries fans out whatever its
/// entry count, 4 MiB. Reading and compressing that much takes milliseconds,
/// far more than handing the entries to the pool costs.
const PACK_FANOUT_MIN_BYTES: u64 = 4 << 20;

/// Whether a batch of `len` entries and `bytes` uncompressed bytes is read and
/// compressed on rayon's pool: when it reaches [`pack_fanout_threshold`], or
/// when it holds two or more entries and [`PACK_FANOUT_MIN_BYTES`]. A batch
/// of large objects is cut by [`PUSH_BATCH_BYTES`] long before it reaches
/// the entry threshold, and it is the batch that gains most from the pool.
/// The batch's bytes are bounded either way, so fanning out does not change
/// what the push holds in memory.
fn batch_fans_out(len: usize, bytes: u64) -> bool {
    len >= pack_fanout_threshold() || (len >= 2 && bytes >= PACK_FANOUT_MIN_BYTES)
}

/// Read + compression-prepare one chunk of raw object hashes — on rayon's
/// global thread pool when `parallel` (see [`batch_fans_out`]), sequentially
/// otherwise. Output mirrors `chunk`'s order 1:1
/// either way: `plan.raw` is already ordered (non-blobs before blobs,
/// each group in BLAKE3 order — see [`transfer::PackPlan`]'s doc
/// comment), and that order is the wire order the pack is built in, so
/// a parallel fan-out must not reshuffle it.
fn prepare_raw_batch(
    store: &ObjectStore,
    chunk: &[Hash],
    parallel: bool,
) -> Result<Vec<PreparedRaw>, PushError> {
    let prepare = |h: &Hash| Ok(PackWriter::prepare_raw(*h, store.read(h)?));
    if parallel {
        chunk.par_iter().map(prepare).collect()
    } else {
        chunk.iter().map(prepare).collect()
    }
}

/// The delta-entry counterpart of [`prepare_raw_batch`]: reads each
/// stream of `chunk` back from the push's delta spool and fans out the
/// zstd compression step. Takes `chunk` by value — `build_packs` drains
/// it straight out of `plan.deltas`.
fn prepare_delta_batch(
    chunk: Vec<transfer::PlannedDelta>,
    parallel: bool,
) -> Result<Vec<PreparedDelta>, PushError> {
    let prepare = |d: transfer::PlannedDelta| {
        Ok(PackWriter::prepare_delta(
            d.base,
            d.stream.into_vec().map_err(StoreError::Io)?,
        ))
    };
    if parallel {
        chunk.into_par_iter().map(prepare).collect()
    } else {
        chunk.into_iter().map(prepare).collect()
    }
}

/// [`PackFill::seals_before`] for the pack `w` is building.
fn should_seal<W>(
    w: &PackWriter<W>,
    add: Incoming,
    payload_cap: u64,
    max_pack_bytes: Option<u64>,
    max_entries: usize,
) -> bool {
    PackFill::of(w).seals_before(
        add,
        payload_cap,
        protocol::max_pack_bytes(max_pack_bytes),
        max_entries,
    )
}

#[cfg(test)]
mod packmap_tests;
#[cfg(test)]
mod rebaseline_tests;
#[cfg(test)]
mod tests {
    use super::*;
    use kit_core::layout::RepoLayout;
    use kit_core::pack::{DecodeLimits, serialized_bound};
    use kit_core::protocol::PACK_BODY_LIMIT;

    #[test]
    fn a_pack_holds_at_most_256_mib_unless_the_caller_says_otherwise() {
        let cap = PushOptions::default().pack_payload_cap;
        assert_eq!(cap, DEFAULT_PACK_PAYLOAD_CAP);
        assert_eq!(cap, 268_435_456);
        assert!(cap < pack::MAX_TOTAL_PAYLOAD);
        // The option still reaches the format limit and no further.
        assert_eq!(
            effective_payload_cap(pack::MAX_TOTAL_PAYLOAD, None).unwrap(),
            pack::MAX_TOTAL_PAYLOAD
        );
        assert_eq!(effective_payload_cap(cap, Some(1 << 20)).unwrap(), 1 << 20);
        assert_eq!(
            effective_payload_cap(u64::MAX, None).unwrap(),
            pack::MAX_TOTAL_PAYLOAD
        );
    }
    fn blob_hashes(store: &ObjectStore, count: usize) -> Vec<Hash> {
        (0..count)
            .map(|i| {
                let blob = kit_core::object::Object::Blob(kit_core::object::Blob {
                    data: format!("entry {i}").into_bytes(),
                });
                store
                    .write(&kit_core::serialize::serialize(&blob).unwrap())
                    .unwrap()
            })
            .collect()
    }

    fn blob(data: &[u8]) -> (Hash, Vec<u8>) {
        let bytes = kit_core::serialize::serialize(&kit_core::object::Object::Blob(
            kit_core::object::Blob {
                data: data.to_vec(),
            },
        ))
        .unwrap();
        (kit_core::hash::hash(&bytes), bytes)
    }

    /// Push `entries` through the sealing rule, reading back each pack it
    /// seals. Returns the number of packs.
    fn push_and_read_back(
        entries: impl Iterator<Item = (Hash, Vec<u8>)>,
        payload_cap: u64,
        max_pack_bytes: Option<u64>,
    ) -> usize {
        let (_dir, store) = store();
        let mut packs = 0;
        let mut w = PackWriter::new();
        let mut seal = |w: &mut PackWriter| {
            let pack = std::mem::replace(w, PackWriter::new()).finish().unwrap();
            let read = kit_core::pack::PackReader::read(&pack, &store).map(|_| ());
            assert!(
                read.is_ok(),
                "a sealed pack of {} bytes: {read:?}",
                pack.len()
            );
            assert!(pack.len() as u64 <= protocol::max_pack_bytes(max_pack_bytes));
            packs += 1;
        };
        for (id, bytes) in entries {
            let entry = PackWriter::prepare_raw(id, bytes);
            if should_seal(
                &w,
                entry.incoming(),
                payload_cap,
                max_pack_bytes,
                usize::MAX,
            ) {
                seal(&mut w);
            }
            w.push_prepared_raw(entry).unwrap();
        }
        seal(&mut w);
        packs
    }

    #[test]
    #[ignore = "reads back packs of 1.2 million entries; several minutes in a debug build"]
    fn a_pack_of_tiny_blobs_the_push_seals_is_read_back() {
        let count = u32::try_from(pack::MAX_WRITE_ENTRIES).unwrap() + 100_000;
        let packs = push_and_read_back(
            (0..count).map(|i| blob(&i.to_le_bytes())),
            DEFAULT_PACK_PAYLOAD_CAP,
            None,
        );
        assert_eq!(packs, 2);
    }

    #[test]
    #[ignore = "compresses 3 GiB; minutes in a debug build"]
    fn a_pack_of_compressible_objects_the_push_seals_is_read_back() {
        // Each object decodes to 128 MiB and takes a few kilobytes on the
        // wire. Seven of them and the framing of each spend the decoded budget of
        // the smallest reader (1 GiB), so the push seals before the eighth.
        let mut data = vec![0_u8; 128 << 20];
        let packs = push_and_read_back(
            (0..24_u64).map(|i| {
                data[..8].copy_from_slice(&i.to_le_bytes());
                blob(&data)
            }),
            DEFAULT_PACK_PAYLOAD_CAP,
            None,
        );
        assert_eq!(packs, 4);
    }

    #[test]
    #[ignore = "builds a pack of about 4 GiB and needs about 9 GiB of memory"]
    fn a_pack_sealed_at_the_format_payload_cap_fits_the_fetch_body_limit() {
        let cap = effective_payload_cap(pack::MAX_TOTAL_PAYLOAD, None).unwrap();
        let size = 64_usize << 20;
        let overhead = blob(&vec![0; size - 64]).1.len() - (size - 64);
        // Content that does not compress.
        let mut data = vec![0_u8; size - overhead];
        let mut state = 0x1234_5678_9abc_def0_u64;
        for word in data.chunks_mut(8) {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let n = word.len();
            word.copy_from_slice(&state.to_le_bytes()[..n]);
        }
        let mut w = PackWriter::new();
        for i in 0..80_u64 {
            data[..8].copy_from_slice(&i.to_le_bytes());
            let (id, bytes) = blob(&data);
            assert_eq!(bytes.len(), size);
            if should_seal(
                &w,
                Incoming::raw(bytes.len() as u64, 0),
                cap,
                None,
                usize::MAX,
            ) {
                break;
            }
            w.push_raw(id, &bytes).unwrap();
        }
        let pack = w.finish().unwrap();
        assert!(pack.len() as u64 <= PACK_BODY_LIMIT, "{} bytes", pack.len());
    }

    #[test]
    fn a_pack_seals_when_it_holds_the_most_entries_it_may() {
        let (_dir, store) = store();
        let hashes = blob_hashes(&store, 3);
        let mut w = PackWriter::new();
        let entry = Incoming::raw(1, 0);
        // An empty writer never seals, whatever the bound.
        assert!(!should_seal(&w, entry, u64::MAX, None, 0));
        for hash in &hashes {
            w.push_raw(*hash, &store.read(hash).unwrap()).unwrap();
        }
        assert!(!should_seal(&w, entry, u64::MAX, None, 4));
        assert!(should_seal(&w, entry, u64::MAX, None, 3));
        assert!(should_seal(&w, entry, u64::MAX, None, 2));
        // The format's own bound applies whatever the caller passes.
        assert!(!should_seal(&w, entry, u64::MAX, None, usize::MAX));
    }

    #[test]
    fn the_pack_estimate_of_an_empty_plan_is_no_packs() {
        let (_dir, store) = store();
        let plan = transfer::PackPlan {
            raw: Vec::new(),
            deltas: Vec::new(),
            self_contained: true,
        };
        assert!(
            estimate_pack_sizes(&store, &plan, u64::MAX, None)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn the_pack_estimate_splits_at_the_entry_bound() {
        let (_dir, store) = store();
        let hashes = blob_hashes(&store, 5);
        let plan = transfer::PackPlan {
            raw: hashes,
            deltas: Vec::new(),
            self_contained: true,
        };
        let packs = |max_entries| {
            estimate_pack_sizes_with(&store, &plan, u64::MAX, None, max_entries)
                .unwrap()
                .len()
        };
        assert_eq!(packs(5), 1);
        assert_eq!(packs(4), 2);
        assert_eq!(packs(2), 3);
        assert_eq!(packs(1), 5);
        // A plan that lists one object twice counts it twice.
        let twice = transfer::PackPlan {
            raw: vec![plan.raw[0], plan.raw[0], plan.raw[0]],
            deltas: Vec::new(),
            self_contained: true,
        };
        assert_eq!(
            estimate_pack_sizes_with(&store, &twice, u64::MAX, None, 2)
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            estimate_pack_sizes(&store, &plan, u64::MAX, None)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn the_pack_estimate_splits_at_the_payload_and_serialized_limits() {
        let (_dir, store) = store();
        let hashes = blob_hashes(&store, 3);
        let size = store.object_metadata(&hashes[0]).unwrap().len();
        assert!(
            hashes
                .iter()
                .all(|h| store.object_metadata(h).unwrap().len() == size)
        );
        let plan = transfer::PackPlan {
            raw: hashes,
            deltas: Vec::new(),
            self_contained: true,
        };
        let packs = |payload_cap, max_pack_bytes| {
            estimate_pack_sizes_with(&store, &plan, payload_cap, max_pack_bytes, usize::MAX)
                .unwrap()
                .len()
        };
        // The payload cap: three entries fill it exactly.
        assert_eq!(packs(3 * size, None), 1);
        assert_eq!(packs(3 * size - 1, None), 2);
        assert_eq!(packs(2 * size, None), 2);
        assert_eq!(packs(2 * size - 1, None), 3);
        // The serialized limit counts each entry's frame, the header and the
        // trailer.
        let bound = |entries: usize| serialized_bound(entries as u64 * size, entries);
        assert_eq!(packs(u64::MAX, Some(bound(3))), 1);
        assert_eq!(packs(u64::MAX, Some(bound(3) - 1)), 2);
        assert_eq!(packs(u64::MAX, Some(bound(2))), 2);
        assert_eq!(packs(u64::MAX, Some(bound(2) - 1)), 3);
        // The body limit applies when the remote advertises none.
        assert_eq!(packs(u64::MAX, Some(u64::MAX)), 1);
    }

    /// The pack a push uploads from its spool, with its deltas read from the
    /// delta spool, has the bytes and key of the same pack built in memory
    /// with the deltas held inline.
    #[test]
    #[allow(clippy::too_many_lines)] // the fixture, both builds and the comparison
    fn a_spooled_push_pack_has_the_bytes_and_key_of_the_in_memory_pack() {
        use kit_core::object::{Blob, Commit, EntryMode, Identity, Object, Tree, TreeEntry};
        let (_dir, store) = store();
        let write = |object: &Object| {
            store
                .write(&kit_core::serialize::serialize(object).unwrap())
                .unwrap()
        };
        let data = |seed: u8, edited: bool| {
            let mut out = Vec::new();
            for block in 0u32..2048 {
                out.extend_from_slice(&kit_core::hash::hash(
                    &[&block.to_le_bytes()[..], &[seed]].concat(),
                ));
            }
            if edited {
                out[1000] ^= 1;
                out[40_000] ^= 1;
            }
            out
        };
        let commit = |files: Vec<(String, Vec<u8>)>, parents: Vec<Hash>| {
            let mut entries: Vec<TreeEntry> = files
                .into_iter()
                .map(|(name, data)| TreeEntry {
                    name: name.into_bytes(),
                    mode: EntryMode::Blob,
                    object_hash: write(&Object::Blob(Blob { data })),
                })
                .collect();
            entries.sort_by(|a, b| a.name.cmp(&b.name));
            let tree = write(&Object::Tree(Tree { entries }));
            write(&Object::Commit(Commit::new_unannotated(
                tree,
                parents,
                Identity::ed25519([1; 32]),
                [1; 32],
                b"files".to_vec(),
                1_700_000_000,
                [0u8; 64],
            )))
        };
        let base = commit(
            (0..6).map(|i| (format!("f{i}"), data(i, false))).collect(),
            vec![],
        );
        let mut files: Vec<_> = (0..6).map(|i| (format!("f{i}"), data(i, true))).collect();
        files.push(("new".to_owned(), data(9, false)));
        let tip = commit(files, vec![base]);

        let inline =
            transfer::plan_pack_with(&store, tip, Some(base), encode_delta_candidates_batch)
                .unwrap();
        assert_eq!(inline.deltas.len(), 6);
        let mut expected = Vec::new();
        build_packs(
            SealKind::Count,
            || Ok(PackWriter::new()),
            |w, _| {
                expected.push(w.finish()?);
                Ok(false)
            },
            &store,
            inline,
            UploadLimits::default(),
            DEFAULT_PACK_PAYLOAD_CAP,
            &crate::observer::NoopObserver,
        )
        .unwrap();

        let remote = kit_transport_memory::MemoryTransport::new();
        let source = crate::source::TransportSource::new(&remote);
        let tx = PushContext::new(&source, &crate::observer::NoopObserver, &store);
        let spooled = tx.deltas.plan(&store, tip, Some(base)).unwrap();
        assert!(
            spooled
                .deltas
                .iter()
                .all(|d| matches!(d.stream, transfer::DeltaBytes::Spooled { .. }))
        );
        let keys = build_and_upload_packs(
            &tx,
            "refs/heads/main",
            &store,
            spooled,
            DEFAULT_PACK_PAYLOAD_CAP,
            UploadLimits::default(),
        )
        .unwrap();

        let sent: Vec<Vec<u8>> = keys
            .iter()
            .map(|key| {
                kit_core::protocol::Transport::download_blob(
                    &remote,
                    &PackKey::from_hash(*key),
                    None,
                    u64::MAX,
                )
                .unwrap()
            })
            .collect();
        assert_eq!(sent, expected);
        let expected_keys: Vec<Hash> = expected.iter().map(|p| pack::pack_key(p)).collect();
        assert_eq!(keys, expected_keys);
    }

    #[test]
    fn a_sealed_pack_longer_than_the_advertised_limit_is_refused() {
        let (id, bytes) = blob(&vec![7; 300]);
        let seal = |max_pack_bytes| {
            let mut w = PackWriter::new_raw_only();
            w.push_raw(id, &bytes).unwrap();
            let limits = UploadLimits {
                max_pack_bytes: Some(max_pack_bytes),
                ..UploadLimits::default()
            };
            check_sealed(w.finish().unwrap().len() as u64, limits, 0)
        };
        let exact = serialized_bound(bytes.len() as u64, 1);
        assert!(seal(exact).is_ok());
        assert!(matches!(
            seal(exact - 1),
            Err(PushError::Sync(SyncError::Source(
                SourceError::PayloadTooLarge(_)
            )))
        ));
    }

    #[test]
    fn a_first_entry_over_every_limit_is_one_pack_and_never_an_empty_one() {
        let (_dir, store) = store();
        let hashes = blob_hashes(&store, 2);
        let plan = transfer::PackPlan {
            raw: hashes,
            deltas: Vec::new(),
            self_contained: true,
        };
        // Each entry alone is over the payload cap, so each is a pack of its own.
        let sizes = estimate_pack_sizes_with(&store, &plan, 1, None, usize::MAX).unwrap();
        assert_eq!(sizes.len(), 2);
        assert!(sizes.iter().all(|&size| size > serialized_bound(0, 0)));
    }

    /// A delta over `base` whose stream is a header alone, claiming a base of
    /// `base_len` bytes and a result of `result` bytes.
    fn header_delta(salt: u8, base: Hash, base_len: u32, result: u32) -> transfer::PlannedDelta {
        let mut stream = vec![0_u8; kit_core::delta::HEADER_LEN];
        stream[1..5].copy_from_slice(&base_len.to_le_bytes());
        stream[5..9].copy_from_slice(&result.to_le_bytes());
        transfer::PlannedDelta {
            target: [salt; 32],
            base,
            stream: stream.into(),
        }
    }

    fn estimated_packs(store: &ObjectStore, deltas: Vec<transfer::PlannedDelta>) -> usize {
        let plan = transfer::PackPlan {
            raw: Vec::new(),
            deltas,
            self_contained: false,
        };
        estimate_pack_sizes_with(store, &plan, u64::MAX, None, usize::MAX)
            .unwrap()
            .len()
    }

    /// The estimate counts every entry as compressed, so a pack seals no later
    /// in the real seal than in the estimate: the real packs are never more.
    #[test]
    fn a_real_seal_never_makes_more_packs_than_the_estimate_counts() {
        // A fixed generator: the property holds for every sequence.
        let mut state = 0x2545_F491_4F6C_DD1D_u64;
        let mut next = move |bound: u64| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state % bound
        };
        let packs = |entries: &[(u64, u64)], real: bool| {
            let mut fill = PackFill::default();
            let mut count = 0;
            for &(len, actual) in entries {
                let add = Incoming::raw(len, if real { actual } else { len });
                if fill.seals_before(add, 3 << 30, protocol::PACK_BODY_LIMIT, 7) {
                    count += 1;
                    fill = PackFill::default();
                }
                fill = fill.with(add);
            }
            count + usize::from(fill.entries() > 0)
        };
        for _ in 0..2000 {
            let entries: Vec<(u64, u64)> = (0..next(40))
                .map(|_| {
                    let len = 1 + next(600 << 20);
                    // A real entry decodes to its length when it compresses,
                    // and to nothing when it is stored plain.
                    let actual = if next(2) == 0 { len } else { 0 };
                    (len, actual)
                })
                .collect();
            assert!(packs(&entries, true) <= packs(&entries, false));
        }
    }

    #[test]
    fn the_pack_estimate_splits_before_the_decoded_budget_of_the_default_reader() {
        let (_dir, store) = store();
        // A delta stream that claims a result of 256 MiB. The estimate counts
        // the result and the stream as decoded bytes, against 1 GiB.
        let plan = |count: u8| {
            (0..count)
                .map(|salt| header_delta(salt, [0; 32], 0, 1 << 28))
                .collect::<Vec<_>>()
        };
        // The wire size of a pack is its deltas' bases and streams, framed.
        let one = estimate_pack_sizes_with(
            &store,
            &transfer::PackPlan {
                raw: Vec::new(),
                deltas: plan(1),
                self_contained: false,
            },
            u64::MAX,
            None,
            usize::MAX,
        )
        .unwrap();
        let stream = kit_core::delta::HEADER_LEN as u64;
        assert_eq!(one, [serialized_bound(HASH_LEN as u64 + stream, 1)]);
        // Three of them (768 MiB) fit, a fourth reaches 1 GiB and a little more.
        assert_eq!(estimated_packs(&store, plan(3)), 1);
        assert_eq!(estimated_packs(&store, plan(4)), 2);
        assert_eq!(estimated_packs(&store, plan(6)), 2);
        assert_eq!(estimated_packs(&store, plan(7)), 3);
    }

    #[test]
    fn the_pack_estimate_fits_a_pack_that_decodes_to_exactly_the_default_budget() {
        let (_dir, store) = store();
        // A result and a stream that together decode to half the budget.
        let result = u32::try_from(DecodeLimits::DEFAULT_MAX_DECODED_BYTES / 2).unwrap()
            - u32::try_from(kit_core::delta::HEADER_LEN).unwrap();
        let packs = |count: u8| {
            estimated_packs(
                &store,
                (0..count)
                    .map(|salt| header_delta(salt, [0; 32], 0, result))
                    .collect(),
            )
        };
        assert_eq!(packs(2), 1);
        assert_eq!(packs(3), 2);
    }

    #[test]
    fn the_pack_estimate_counts_the_longest_base_and_not_every_base() {
        let (_dir, store) = store();
        // Each delta decodes to 256 MiB, with its 9-byte stream, and takes its own
        // 128 MiB base. Bases are listed one after the other, so a reader holds
        // one at a time: three deltas and the longest base reach 896 MiB, and
        // a fourth delta passes 1 GiB.
        let delta = |salt: u8| header_delta(salt, [salt; 32], 1 << 27, 1 << 28);
        let packs = |count: u8| estimated_packs(&store, (0..count).map(delta).collect());
        assert_eq!(packs(3), 1);
        assert_eq!(packs(4), 2);
        // With 256 MiB bases, two deltas and one base reach 768 MiB, and a
        // third delta passes 1 GiB. If a pack counted every base, two would
        // not fit.
        let big = |salt: u8| header_delta(salt, [salt; 32], 1 << 28, 1 << 28);
        assert_eq!(estimated_packs(&store, (0..2).map(big).collect()), 1);
        assert_eq!(estimated_packs(&store, (0..3).map(big).collect()), 2);
    }

    #[test]
    fn only_packs_from_the_threshold_up_are_ticketed() {
        let limits = |budget, threshold| UploadLimits {
            max_pack_bytes: None,
            data_packs_per_advance: budget,
            ticket_threshold_bytes: threshold,
        };
        // No tickets, no ticketed packs.
        assert!(!ticketed_pack(limits(None, Some(0)), 1_000));
        assert!(ticketed_pack(limits(Some(6), None), 0));
        assert!(!ticketed_pack(limits(Some(6), Some(100)), 99));
        assert!(ticketed_pack(limits(Some(6), Some(100)), 100));
    }

    #[test]
    fn batch_lens_empty_input_is_no_batches() {
        assert_eq!(
            super::size_capped_batch_lens(&[], 1000, 10),
            Vec::<usize>::new()
        );
    }

    #[test]
    fn batch_lens_fits_one_batch_under_both_caps() {
        assert_eq!(
            super::size_capped_batch_lens(&[10, 10, 10], 1000, 10),
            vec![3]
        );
    }

    #[test]
    fn batch_lens_splits_on_byte_cap() {
        // Each item is 40 bytes; a 100-byte cap fits 2 per batch (80 <=
        // 100), not 3 (120 > 100) — entry cap (10) never binds here.
        assert_eq!(
            super::size_capped_batch_lens(&[40, 40, 40, 40, 40], 100, 10),
            vec![2, 2, 1]
        );
    }

    #[test]
    fn batch_lens_splits_on_entry_cap() {
        // Every item is tiny (1 byte), so the byte cap (10_000) never
        // binds — only the entry cap (2) does.
        assert_eq!(
            super::size_capped_batch_lens(&[1, 1, 1, 1, 1], 10_000, 2),
            vec![2, 2, 1]
        );
    }

    #[test]
    fn batch_lens_single_oversized_item_gets_its_own_batch() {
        // A lone item over `payload_cap` must not loop forever or be
        // dropped — mirrors `should_seal`'s "never true for an empty
        // writer" escape hatch.
        assert_eq!(super::size_capped_batch_lens(&[500], 100, 10), vec![1]);
        assert_eq!(
            super::size_capped_batch_lens(&[500, 10, 10], 100, 10),
            vec![1, 2]
        );
    }

    #[test]
    fn a_batch_fans_out_by_entries_or_by_bytes() {
        let threshold = super::pack_fanout_threshold();
        let min = super::PACK_FANOUT_MIN_BYTES;
        assert!(super::batch_fans_out(threshold, 0));
        assert!(!super::batch_fans_out(threshold - 1, min - 1));
        // A batch the byte cap cut short: 255 objects of 256 KiB on 32
        // threads stay one entry under the entry threshold.
        assert!(super::batch_fans_out(
            threshold - 1,
            super::PUSH_BATCH_BYTES
        ));
        assert!(super::batch_fans_out(2, min));
        // One entry has nothing to share with another thread.
        assert!(!super::batch_fans_out(1, super::PUSH_BATCH_BYTES));
    }

    // =================================================================
    // `prepare_raw_batch` / `prepare_delta_batch` — order preservation
    // and error propagation across BOTH the sequential and the rayon
    // branch, for one entry and for several.
    // =================================================================

    fn store() -> (tempfile::TempDir, ObjectStore) {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = RepoLayout::single(dir.path());
        let store = ObjectStore::init(&layout).expect("init store");
        (dir, store)
    }

    #[test]
    fn prepare_raw_batch_preserves_order_sequential_and_parallel() {
        let (_dir, store) = store();
        for (n, parallel) in [(1usize, false), (1, true), (5, false), (5, true)] {
            let hashes: Vec<kit_core::hash::Hash> = (0..n)
                .map(|i| store.write(format!("raw entry #{i}").as_bytes()).unwrap())
                .collect();
            let prepared =
                super::prepare_raw_batch(&store, &hashes, parallel).expect("prepare raw batch");
            assert_eq!(
                prepared.iter().map(PreparedRaw::hash).collect::<Vec<_>>(),
                hashes,
                "prepare_raw_batch must preserve input order at n={n}"
            );
        }
    }

    #[test]
    fn prepare_raw_batch_propagates_a_missing_object_error_sequential_and_parallel() {
        let (_dir, store) = store();
        for (n, parallel) in [(1usize, false), (1, true), (5, false), (5, true)] {
            let mut hashes: Vec<kit_core::hash::Hash> = (0..n.saturating_sub(1))
                .map(|i| store.write(format!("raw entry #{i}").as_bytes()).unwrap())
                .collect();
            // A hash of content never written to the store — `store.read`
            // must fail with `ObjectNotFound`, and that failure must
            // surface through `prepare_raw_batch` rather than being
            // silently dropped or panicking on either branch.
            hashes.push(kit_core::hash::hash(b"never written"));
            let err = super::prepare_raw_batch(&store, &hashes, parallel).expect_err(
                "a missing object must fail prepare_raw_batch instead of being dropped",
            );
            assert!(matches!(
                err,
                super::PushError::Sync(crate::SyncError::Store(
                    kit_core::store::StoreError::ObjectNotFound(_)
                ))
            ));
        }
    }

    #[test]
    fn prepare_delta_batch_preserves_order_sequential_and_parallel() {
        use kit_core::transfer::PlannedDelta;
        for (n, parallel) in [(1usize, false), (1, true), (5, false), (5, true)] {
            let deltas: Vec<PlannedDelta> = (0..n)
                .map(|i| PlannedDelta {
                    target: kit_core::hash::hash(format!("target #{i}").as_bytes()),
                    base: kit_core::hash::hash(format!("base #{i}").as_bytes()),
                    stream: format!("delta stream #{i}").into_bytes().into(),
                })
                .collect();
            let expected_bases: Vec<_> = deltas.iter().map(|d| d.base).collect();
            let prepared = super::prepare_delta_batch(deltas, parallel).unwrap();
            assert_eq!(
                prepared.iter().map(PreparedDelta::base).collect::<Vec<_>>(),
                expected_bases,
                "prepare_delta_batch must preserve input order at n={n}"
            );
        }
    }

    #[test]
    fn encode_delta_candidates_batch_preserves_order_sequential_and_parallel() {
        let (_dir, store) = store();
        for &n in &[
            1usize,
            super::delta_plan_fanout_threshold(),
            super::DELTA_CANDIDATE_BATCH_CAP * 2 + 1,
        ] {
            // Each candidate's base/target pair is a small, localized edit
            // of distinct-per-index content — a real delta candidate (the
            // encoded stream is smaller than the raw target), and distinct
            // across candidates so no candidate's result could accidentally
            // match another's and mask an ordering bug.
            let candidates: Vec<transfer::DeltaCandidate> = (0..n)
                .map(|i| {
                    let mut base_bytes =
                        format!("encode-delta-candidates-batch fixture #{i}\n").into_bytes();
                    base_bytes.extend_from_slice(
                        b"the quick brown fox jumps over the lazy dog\n"
                            .repeat(4)
                            .as_slice(),
                    );
                    let base = store.write(&base_bytes).unwrap();
                    let mut target_bytes = base_bytes.clone();
                    target_bytes.extend_from_slice(b"-- edited --\n");
                    let target = store.write(&target_bytes).unwrap();
                    transfer::DeltaCandidate { target, base }
                })
                .collect();

            // Ground truth: encode each candidate one at a time, in order.
            let expected: Vec<Option<Vec<u8>>> = candidates
                .iter()
                .map(|&c| {
                    transfer::encode_delta_candidate(&store, c)
                        .expect("encode delta candidate")
                        .map(|p| p.stream.into_vec().unwrap())
                })
                .collect();
            assert!(
                expected.iter().all(Option::is_some),
                "every fixture candidate must actually delta-encode smaller than raw"
            );

            let actual: Vec<Option<Vec<u8>>> =
                super::encode_delta_candidates_batch(&store, &candidates)
                    .expect("encode delta candidates batch")
                    .into_iter()
                    .map(|r| r.map(|p| p.stream.into_vec().unwrap()))
                    .collect();
            assert_eq!(
                actual, expected,
                "encode_delta_candidates_batch must preserve input order at n={n}"
            );
        }
    }

    #[test]
    fn encode_delta_candidates_batch_propagates_a_missing_object_error_sequential_and_parallel() {
        let (_dir, store) = store();
        for &n in &[
            1usize,
            super::delta_plan_fanout_threshold(),
            super::DELTA_CANDIDATE_BATCH_CAP * 2 + 1,
        ] {
            let mut candidates: Vec<transfer::DeltaCandidate> = (0..n.saturating_sub(1))
                .map(|i| {
                    let base = store
                        .write(format!("present base #{i}").as_bytes())
                        .unwrap();
                    let target = store
                        .write(format!("present target #{i}").as_bytes())
                        .unwrap();
                    transfer::DeltaCandidate { target, base }
                })
                .collect();
            // A target hash never written to the store — `store.read` must
            // fail with `ObjectNotFound`, surfaced through
            // `encode_delta_candidates_batch` rather than dropped or
            // panicking, on either branch.
            candidates.push(transfer::DeltaCandidate {
                target: kit_core::hash::hash(b"never written target"),
                base: kit_core::hash::hash(b"never written base"),
            });
            let err = super::encode_delta_candidates_batch(&store, &candidates).expect_err(
                "a missing object must fail encode_delta_candidates_batch instead of being dropped",
            );
            assert!(matches!(
                err,
                kit_core::store::StoreError::ObjectNotFound(_)
            ));
        }
    }

    #[test]
    fn delta_base_cache_respects_bytes_and_skips_single_use_bases() {
        let (_dir, store) = store();
        let mut candidates = Vec::new();
        for (value, size, uses) in [
            (b'a', 128usize, 2usize),
            (b'b', 128, 2),
            (b'c', 1024, 2),
            (b'd', 64, 1),
        ] {
            let base_bytes = vec![value; size];
            let base = store.write(&base_bytes).unwrap();
            let mut target_bytes = base_bytes;
            target_bytes.extend_from_slice(b"edited");
            let target = store.write(&target_bytes).unwrap();
            candidates.extend(std::iter::repeat_n(
                transfer::DeltaCandidate { target, base },
                uses,
            ));
        }
        // Only one of the two repeated 128-byte bases fits. The 1 KiB
        // base exceeds the budget and the 64-byte base is used only once.
        let cache = super::cache_delta_bases(&store, &candidates, 192).unwrap();
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.values().map(Vec::len).sum::<usize>(), 128);
    }

    #[test]
    fn delta_base_cache_does_not_read_past_a_failed_batch() {
        let (_dir, store) = store();
        let base = store.write(b"present base").unwrap();
        let missing_target = kit_core::hash::hash(b"missing first-batch target");
        let mut candidates = vec![
            transfer::DeltaCandidate {
                target: missing_target,
                base,
            };
            super::DELTA_CANDIDATE_BATCH_CAP
        ];
        // If all bases are prefetched for the whole push, this missing base
        // fails first. Bounded processing must encounter the first batch's
        // missing target before it even tries to read the later base.
        candidates.extend(
            [transfer::DeltaCandidate {
                target: missing_target,
                base: kit_core::hash::hash(b"missing later-batch base"),
            }; 2],
        );
        let err = super::encode_delta_candidates_batch(&store, &candidates).unwrap_err();
        assert!(matches!(
            err,
            kit_core::store::StoreError::ObjectNotFound(h) if h == kit_core::hash::to_hex(&missing_target)
        ));
    }
}
