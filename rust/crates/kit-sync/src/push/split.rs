//! Splitting an oversized ticketed push along first-parent history.
//!
//! A Connect advance may consume at most the advertised number of tickets
//! (seven unless the server says otherwise), one of them for the packmap node,
//! so a push whose new data needs more packs than that cannot land in one
//! advance. This module chooses intermediate first-parent commits
//! ("cuts") so that each advance carries a closure that fits, and the caller
//! (`push_branch_steps`) publishes them one after another.
//!
//! The cuts are a pure function of (store, tip, remote head, limits): a
//! resumed push recomputes them from the new remote head and regenerates
//! identical packs for the interrupted step, unless a commit that raised the
//! pack size is already published; the resumed push then builds that step's
//! packs at the smaller size.
//!
//! * [`walk_chain`] walks the tip's first parents back to the first commit the
//!   remote already holds.
//! * [`cumulative_weights`] makes one forward pass that sizes, on its own, what
//!   each chain commit adds, in serialized bytes (raw size plus one frame per
//!   object). The sizes bound where to look; they are not trusted to say what
//!   fits, because the plan of a step can send more than they say (a file that
//!   returns at a path, a chunked file reached by another path) or less (a
//!   moved directory).
//! * [`Cutter::cut`] cuts the chain: it finds the furthest commit whose real
//!   plan fits the budget, by binary search over real plans, up to the commit
//!   the weights say would fill the budget at best. The least step, a single
//!   commit or the first advance forced to hold the remote head, is checked
//!   with the real plan and, if its estimate is over budget, an exact local
//!   dry seal.
//!
//! The caller's pack payload cap is a preferred size. When one commit (or the
//! first advance, forced to hold the remote head) weighs more than the budget
//! can carry at that size, [`plan_split`] raises the cap for the whole push to
//! what that commit needs (again, up to a few times, when a cut finds a step the
//! weights missed), never past the format maximum or the
//! largest pack the remote accepts. Every cut, probe and upload then uses the
//! same value.

use std::collections::HashSet;

use kit_core::hash::{Hash, to_hex};
use kit_core::object::Object;
use kit_core::ops::merge::is_ancestor;
use kit_core::pack;
use kit_core::protocol::UploadLimits;
use kit_core::refs::RefWriteCondition;
use kit_core::store::{ObjectStore, StoreError};
use kit_core::transfer::walk::{ChunkMemory, HeldCommits, PushWalk};
use kit_core::transfer::{self, MAX_PUSH_WALK, PUSH_WALK_LIMIT, PackPlan, WalkLimits};

use super::{
    PackSink, PushError, build_and_upload_packs, effective_payload_cap,
    encode_delta_candidates_batch, estimate_pack_sizes,
};

/// Most advances one push may be split into.
pub const MAX_SPLIT_STEPS: usize = 1_000;

/// Most first-parent commits the chain walk visits before it gives up.
pub const MAX_CHAIN_COMMITS: usize = 1_000_000;

/// Grants a caller can check for every advance of a split push before
/// anything is uploaded.
pub trait StepAuthority: Send + Sync {
    /// Refuse the push unless the caller may perform the first advance under
    /// `first` and, when `later_steps` is set, every following advance, each
    /// of which is a `Match` on the previous step's commit.
    ///
    /// # Errors
    /// The reason authority is missing, phrased for the user.
    fn authorize(
        &self,
        branch: &str,
        first: RefWriteCondition,
        later_steps: bool,
    ) -> Result<(), String>;
}

/// The knobs and hooks of one branch push. The default is the production one.
pub struct PushControl<'a> {
    /// Progress and cancellation checkpoints for this push.
    pub observer: &'a dyn crate::Observer<crate::SyncEvent>,
    /// Checked before the first upload of a split push. `None` skips it.
    pub authority: Option<&'a dyn StepAuthority>,
    /// Refuse a split into more advances than this.
    pub max_steps: usize,
    /// Refuse a first-parent walk longer than this.
    pub max_chain: usize,
    /// Commits whose parents are not part of this repository (the shallow
    /// boundary): the chain walk stops at them.
    pub shallow: HashSet<Hash>,
}

impl std::fmt::Debug for PushControl<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PushControl")
            .field("checks_grants", &self.authority.is_some())
            .field("max_steps", &self.max_steps)
            .field("max_chain", &self.max_chain)
            .field("shallow", &self.shallow.len())
            .finish()
    }
}

impl Default for PushControl<'_> {
    fn default() -> Self {
        Self {
            observer: &crate::NoopObserver,
            authority: None,
            max_steps: MAX_SPLIT_STEPS,
            max_chain: MAX_CHAIN_COMMITS,
            shallow: HashSet::new(),
        }
    }
}

/// Data packs one advance may carry: the ticket allowance minus the packmap
/// node's ticket. Six unless the transport advertises another allowance, and
/// never less than one.
pub(super) fn data_pack_budget(limits: UploadLimits) -> usize {
    limits
        .tickets_per_advance
        .map_or(6, |tickets| tickets.saturating_sub(1).max(1))
}

/// The first-parent commits between the remote's history and the tip.
struct Chain {
    /// Oldest first; the last is the tip.
    commits: Vec<Hash>,
    /// The commits the remote holds: the ancestors of its head, which this
    /// store knows (none for a new branch, or a head it lacks).
    held: HeldCommits,
}

fn first_parent(obj: &Object) -> Option<Hash> {
    match obj {
        Object::Commit(c) => c.parents.first().copied(),
        Object::Remix(r) => r.parents.first().copied(),
        _ => None,
    }
}

fn too_large_to_split() -> PushError {
    PushError::PushSplitLimit(format!(
        "the history is too large to split ({MAX_PUSH_WALK} objects or more); no advance of this branch was published"
    ))
}

/// A walk failure as a push error: the cap on the walk is the split's own
/// limit, which is refused before anything is published.
fn walk_error(error: StoreError) -> PushError {
    match error {
        StoreError::OperationLimitExceeded(PUSH_WALK_LIMIT) => too_large_to_split(),
        other => other.into(),
    }
}

/// Walk `tip`'s first parents down to the first commit `remote_tip`'s history
/// contains. Never enters a second-parent side: a merge is one chain commit.
fn walk_chain(
    store: &ObjectStore,
    tip: Hash,
    remote_tip: Option<Hash>,
    ctl: &PushControl<'_>,
) -> Result<Chain, PushError> {
    walk_chain_capped(store, tip, remote_tip, ctl, MAX_PUSH_WALK)
}

/// [`walk_chain`] with the cap on the held set, so a test can reach it.
fn walk_chain_capped(
    store: &ObjectStore,
    tip: Hash,
    remote_tip: Option<Hash>,
    ctl: &PushControl<'_>,
    cap: usize,
) -> Result<Chain, PushError> {
    let held = HeldCommits::collect(store, remote_tip, cap).map_err(walk_error)?;
    let mut commits = Vec::new();
    let mut cursor = tip;
    loop {
        if held.contains(&cursor) {
            break;
        }
        if commits.len() >= ctl.max_chain {
            return Err(PushError::PushSplitLimit(format!(
                "the first-parent history between the remote and the local tip is longer than {} commits, too long to split; no advance of this branch was published",
                ctl.max_chain
            )));
        }
        if ctl.observer.cancelled() {
            return Err(PushError::Sync(crate::SyncError::Interrupted));
        }
        commits.push(cursor);
        if ctl.shallow.contains(&cursor) {
            break;
        }
        match first_parent(&store.read_object(&cursor)?) {
            Some(parent) => cursor = parent,
            None => break,
        }
    }
    commits.reverse();
    Ok(Chain { commits, held })
}

/// What a pass over the chain measured.
struct Weights {
    /// `cumulative[j]` is what the first `j` chain commits contribute beyond
    /// what the remote holds, in serialized bytes. It sizes the search for a
    /// cut; the plan of a step can send more or less, and a real plan decides
    /// whether the step fits.
    cumulative: Vec<u64>,
}

/// The serialized weight of one object: its raw size plus one pack frame.
fn weight_of(store: &ObjectStore, hash: &Hash) -> Result<u64, StoreError> {
    Ok(store
        .object_metadata(hash)?
        .len()
        .saturating_add(pack::ENTRY_FRAME_LEN as u64))
}

/// Size what `id` brings against its parents alone. An object that two new
/// commits each bring is counted for both, because a step that starts after
/// the first sends it again. A chunk is sized once per commit and is never put
/// into a set the walk counts.
///
/// `seen` holds every object any commit has brought so far, which is what the
/// cap on the walk counts together with the held commits.
fn weigh_one(
    store: &ObjectStore,
    held: &HeldCommits,
    shallow: &HashSet<Hash>,
    id: Hash,
    limits: WalkLimits,
    seen: &mut HashSet<Hash>,
) -> Result<u64, PushError> {
    let walk = PushWalk::run_one(store, id, held, shallow, limits).map_err(walk_error)?;
    let mut total = 0_u64;
    let mut add = |object: &Hash| -> Result<(), StoreError> {
        total = total.saturating_add(weight_of(store, object)?);
        Ok(())
    };
    for object in walk.objects() {
        if seen.insert(*object) && held.len() + seen.len() > limits.objects {
            return Err(too_large_to_split());
        }
        add(object).map_err(walk_error)?;
    }
    walk.for_each_chunk(
        store,
        &mut ChunkMemory::new(limits.chunk_memory),
        |_, chunk| add(&chunk),
    )
    .map_err(walk_error)?;
    Ok(total)
}

/// Serialized bytes each chain prefix adds, as a size for the search for a
/// cut. Each new commit is sized on its own, against its parents, and each
/// chain commit then takes the new commits that no earlier chain commit
/// reaches. A step the remote head's history does not cover can send more than
/// this, and a moved directory sends less: a real plan decides what fits.
fn cumulative_weights(
    store: &ObjectStore,
    chain: &Chain,
    ctl: &PushControl<'_>,
) -> Result<Weights, PushError> {
    cumulative_weights_capped(store, chain, ctl, WalkLimits::default())
}

/// [`cumulative_weights`] with the walk's bounds, so a test can reach them.
fn cumulative_weights_capped(
    store: &ObjectStore,
    chain: &Chain,
    ctl: &PushControl<'_>,
    limits: WalkLimits,
) -> Result<Weights, PushError> {
    if chain.commits.is_empty() {
        return Ok(Weights {
            cumulative: vec![0],
        });
    }
    let held = &chain.held;
    let mut cumulative = Vec::with_capacity(chain.commits.len() + 1);
    let mut total = 0_u64;
    let mut taken: HashSet<Hash> = HashSet::new();
    let mut seen: HashSet<Hash> = HashSet::new();
    cumulative.push(0);
    for commit in &chain.commits {
        if ctl.observer.cancelled() {
            return Err(PushError::Sync(crate::SyncError::Interrupted));
        }
        let mut stack = vec![*commit];
        while let Some(hash) = stack.pop() {
            if held.contains(&hash) || !taken.insert(hash) {
                continue;
            }
            total = total.saturating_add(weigh_one(
                store,
                held,
                &ctl.shallow,
                hash,
                limits,
                &mut seen,
            )?);
            // A shallow-boundary commit's parents are not in this repository.
            if ctl.shallow.contains(&hash) {
                continue;
            }
            match store.read_object(&hash)? {
                Object::Commit(commit) => stack.extend(commit.parents),
                Object::Remix(remix) => stack.extend(remix.parents),
                _ => {}
            }
        }
        cumulative.push(total);
    }
    Ok(Weights { cumulative })
}

/// The largest total weight (payload plus frames) after which a pack must
/// seal: either the payload cap, or the serialized limit net of header and
/// trailer. Two consecutive packs always weigh more than this together.
fn pack_weight_cap(payload_cap: u64, max_pack_bytes: Option<u64>) -> u64 {
    let serialized = max_pack_bytes.map_or(u64::MAX, |limit| {
        limit.saturating_sub((pack::HEADER_LEN + pack::TRAILER_LEN) as u64)
    });
    payload_cap.min(serialized).max(1)
}

/// What the real plan of a step weighs, in serialized bytes, and its largest
/// object.
#[derive(Debug, Clone, Copy, Default)]
struct StepWeight {
    total: u64,
    largest: u64,
}

fn plan_weight(store: &ObjectStore, plan: &PackPlan) -> Result<StepWeight, PushError> {
    let mut weight = StepWeight::default();
    let mut add = |size: u64| {
        weight.total = weight.total.saturating_add(size);
        weight.largest = weight.largest.max(size);
    };
    for object in &plan.raw {
        add(weight_of(store, object)?);
    }
    for delta in &plan.deltas {
        add((delta.stream.len() as u64).saturating_add(pack::ENTRY_FRAME_LEN as u64));
    }
    Ok(weight)
}

/// A step no cut can divide that does not fit the budget at the current cap.
struct Overflow {
    weight: StepWeight,
    /// The refusal to give when no larger pack helps.
    error: PushError,
}

/// How a step ends.
enum Cut {
    To(usize),
    TooBig(Overflow),
}

struct Cutter<'a> {
    observer: &'a dyn crate::Observer<crate::SyncEvent>,
    store: &'a ObjectStore,
    chain: &'a Chain,
    weights: &'a [u64],
    remote_tip: Option<Hash>,
    limits: UploadLimits,
    cap: u64,
    budget: usize,
    /// Chain positions the first advance must reach (0: no constraint).
    must_reach: usize,
}

impl Cutter<'_> {
    /// The real plan for advancing from chain position `from` to `to`, with
    /// its estimated pack count. `from == 0` diffs against the remote head.
    fn probe(&self, from: usize, to: usize) -> Result<(PackPlan, usize), PushError> {
        if self.observer.cancelled() {
            return Err(PushError::Sync(crate::SyncError::Interrupted));
        }
        let base = match from {
            0 => self.remote_tip,
            from => Some(self.chain.commits[from - 1]),
        };
        let plan = transfer::plan_pack_with(
            self.store,
            self.chain.commits[to - 1],
            base,
            encode_delta_candidates_batch,
        )
        .map_err(walk_error)?;
        let packs =
            estimate_pack_sizes(self.store, &plan, self.cap, self.limits.max_pack_bytes)?.len();
        Ok((plan, packs))
    }

    /// What the real plan of the step from `from` to `to`, which no cut can
    /// divide, weighs when it needs more than the budget's packs at this
    /// cutter's cap, and `None` when it fits. A step that weighs little is not
    /// probed: the weights size the search, and [`Cutter::cut`] checks every
    /// step it chooses.
    fn forced(&self, from: usize, to: usize) -> Result<Option<StepWeight>, PushError> {
        let weight = self.weights[to] - self.weights[from];
        let wcap = pack_weight_cap(self.cap, self.limits.max_pack_bytes);
        if weight <= wcap.saturating_mul((self.budget / 2) as u64) {
            return Ok(None);
        }
        let (plan, packs) = self.probe(from, to)?;
        if packs <= self.budget {
            return Ok(None);
        }
        Ok(Some(plan_weight(self.store, &plan)?))
    }

    /// The furthest position after `from` whose cumulative weight stays within
    /// `limit`, at least `from + 1`.
    fn furthest(&self, from: usize, limit: u64) -> usize {
        let bound = self.weights[from].saturating_add(limit);
        let count = self.weights.partition_point(|&weight| weight <= bound);
        count
            .saturating_sub(1)
            .max(from + 1)
            .min(self.weights.len() - 1)
    }

    /// The end position of the step that starts at `from`: the furthest one
    /// whose real plan fits the budget. The weights bound where to look, and
    /// each probe is a real plan, so a step is never trusted to fit. The least
    /// step cannot be divided; it is checked exactly, and `Cut::TooBig` says
    /// what it weighs when it does not fit.
    fn cut(&self, from: usize) -> Result<Cut, PushError> {
        let wcap = pack_weight_cap(self.cap, self.limits.max_pack_bytes);
        let natural = self.furthest(from, wcap.saturating_mul((self.budget / 2) as u64));
        // The first advance must already contain the remote head, or the
        // published branch would leave commits the remote holds (a merge of
        // the remote head reaches it through a second parent).
        let least = if from == 0 {
            (from + 1).max(self.must_reach)
        } else {
            from + 1
        };
        let ceiling = self
            .furthest(from, wcap.saturating_mul(self.budget as u64))
            .max(least);
        let (mut fits, mut over) = (least, ceiling);
        while fits < over {
            let mid = fits + (over - fits).div_ceil(2);
            if self.probe(from, mid)?.1 <= self.budget {
                fits = mid;
            } else {
                over = mid - 1;
            }
        }
        if fits > least {
            return Ok(Cut::To(fits));
        }
        Ok(
            match self.verify_forced(from, fits, from == 0 && least > natural)? {
                None => Cut::To(fits),
                Some(overflow) => Cut::TooBig(overflow),
            },
        )
    }

    /// A step that cannot be split further must fit in the budget once
    /// compressed: run the exact seal without uploading.
    /// `holds_remote_head`: the step was forced to reach the remote head, which
    /// the refusal then says.
    fn verify_forced(
        &self,
        from: usize,
        to: usize,
        holds_remote_head: bool,
    ) -> Result<Option<Overflow>, PushError> {
        let (plan, packs) = self.probe(from, to)?;
        if packs <= self.budget {
            return Ok(None);
        }
        let weight = plan_weight(self.store, &plan)?;
        match build_and_upload_packs(
            PackSink::Count,
            self.store,
            plan,
            self.cap,
            self.limits,
            self.observer,
        ) {
            Ok(_) => Ok(None),
            Err(PushError::PushTooLarge { packs, limit, .. }) => Ok(Some(Overflow {
                weight,
                error: PushError::PushTooLarge {
                    packs,
                    limit,
                    commit: Some(self.describe(self.chain.commits[to - 1])),
                    holds_remote_head,
                },
            })),
            Err(other) => Err(other),
        }
    }

    fn describe(&self, commit: Hash) -> String {
        match self.store.read_object(&commit) {
            Ok(Object::Commit(c)) if c.parents.len() > 1 => format!(
                "merge commit {} (second parent {})",
                to_hex(&commit),
                to_hex(&c.parents[1])
            ),
            _ => format!("commit {}", to_hex(&commit)),
        }
    }
}

/// The fewest chain commits after which the branch descends from the remote
/// head, or 0 when the remote head is not an ancestor of the tip (a forced
/// overwrite, which has nothing to preserve). Descent is monotonic along the
/// chain, so a binary search finds it.
fn positions_to_reach(
    store: &ObjectStore,
    chain: &Chain,
    remote_tip: Option<Hash>,
) -> Result<usize, PushError> {
    let Some(remote) = remote_tip.filter(|remote| store.contains(remote)) else {
        return Ok(0);
    };
    let (mut low, mut high) = (1, chain.commits.len());
    if !is_ancestor(store, remote, chain.commits[high - 1])? {
        return Ok(0);
    }
    while low < high {
        let mid = low + (high - low) / 2;
        if is_ancestor(store, remote, chain.commits[mid - 1])? {
            high = mid;
        } else {
            low = mid + 1;
        }
    }
    Ok(low)
}

/// The steps of a push and the pack payload cap they are cut and uploaded at.
pub(super) struct SplitPlan {
    /// The commits to advance the remote head through, oldest first, ending
    /// at the tip.
    pub steps: Vec<Hash>,
    /// The preferred pack payload cap for every upload of this push: the
    /// caller's, or a larger one when a single commit cannot fit otherwise.
    pub payload_cap: u64,
}

/// The payload cap at which a commit of `commit` serialized bytes, and a
/// first advance forced to hold the remote head of `first` bytes (zero when
/// nothing forces it), fit `budget` packs: the smallest that always does,
/// never past what the format and the remote allow.
///
/// Under next-fit each sealed pack weighs more than the cap less the largest
/// object, so `weight / budget` plus that object suffices. `None` when the
/// commit cannot fit even at the ceiling. A forced first advance that cannot
/// is clamped to it and left to the cut, whose refusal tells how to avoid
/// holding the remote head.
fn raised_payload_cap(
    limits: UploadLimits,
    budget: usize,
    commit: u64,
    first: u64,
    largest_object: u64,
) -> Result<Option<u64>, PushError> {
    let budget = budget as u64;
    let ceiling = effective_payload_cap(u64::MAX, limits.max_pack_bytes)?;
    let ceiling_weight = pack_weight_cap(ceiling, limits.max_pack_bytes);
    if commit > ceiling_weight.saturating_mul(budget) {
        return Ok(None);
    }
    Ok(Some(
        commit
            .max(first)
            .div_ceil(budget)
            .saturating_add(largest_object)
            .saturating_add(1)
            .min(ceiling_weight),
    ))
}

/// The commits to advance the remote head through, oldest first, ending at
/// `tip`. One entry means the push is not split.
///
/// Refuses, before anything is uploaded, a push that would need more than
/// `ctl.max_steps` advances, one whose grants do not cover every advance, and
/// one containing a single commit that cannot fit in an advance.
///
/// # Errors
/// [`PushError::PushSplitLimit`], [`PushError::PushNotAuthorized`],
/// [`PushError::PushTooLarge`], or a store or planning failure.
#[allow(clippy::too_many_arguments)]
pub fn plan_push_steps(
    store: &ObjectStore,
    tip: Hash,
    remote_tip: Option<Hash>,
    limits: UploadLimits,
    pack_payload_cap: u64,
    ctl: &PushControl<'_>,
    condition: RefWriteCondition,
    branch: &str,
) -> Result<Vec<Hash>, PushError> {
    plan_split(
        store,
        tip,
        remote_tip,
        limits,
        pack_payload_cap,
        ctl,
        condition,
        branch,
    )
    .map(|plan| plan.steps)
}

/// [`plan_push_steps`] with the payload cap the steps are uploaded at.
#[allow(clippy::too_many_arguments)]
pub(super) fn plan_split(
    store: &ObjectStore,
    tip: Hash,
    remote_tip: Option<Hash>,
    limits: UploadLimits,
    pack_payload_cap: u64,
    ctl: &PushControl<'_>,
    condition: RefWriteCondition,
    branch: &str,
) -> Result<SplitPlan, PushError> {
    let chain = walk_chain(store, tip, remote_tip, ctl)?;
    if chain.commits.is_empty() {
        return Ok(SplitPlan {
            steps: vec![tip],
            payload_cap: pack_payload_cap,
        });
    }
    if let Some(authority) = ctl.authority {
        authority
            .authorize(branch, condition, chain.commits.len() > 1)
            .map_err(PushError::PushNotAuthorized)?;
    }
    let Weights {
        cumulative: weights,
    } = cumulative_weights(store, &chain, ctl)?;
    let budget = data_pack_budget(limits);
    let mut cutter = Cutter {
        observer: ctl.observer,
        store,
        chain: &chain,
        weights: &weights,
        remote_tip,
        limits,
        cap: effective_payload_cap(pack_payload_cap, limits.max_pack_bytes)?,
        budget,
        must_reach: positions_to_reach(store, &chain, remote_tip)?,
    };
    // The pack size is fixed here, once: every cut, probe and upload of this
    // push uses it. It grows past the preferred size only when something no
    // cut can divide, a single commit or the first advance (forced to hold
    // the remote head), needs more than the budget's packs. The heavy steps
    // are found by their weights; a step the weights miss is found by the cut
    // that checks it, and the cut starts again at the larger size.
    let mut payload_cap = pack_payload_cap;
    let mut forced_first = StepWeight::default();
    let mut needs_more = false;
    if cutter.must_reach > 0
        && let Some(weight) = cutter.forced(0, cutter.must_reach)?
    {
        forced_first = weight;
        needs_more = true;
    }
    let mut heaviest = (0, StepWeight::default());
    for commit in 0..chain.commits.len() {
        if let Some(weight) = cutter.forced(commit, commit + 1)? {
            needs_more = true;
            if weight.total > heaviest.1.total {
                heaviest = (commit, weight);
            }
        }
    }
    if needs_more {
        let (commit, weight) = heaviest;
        let raised = raised_payload_cap(
            limits,
            budget,
            weight.total,
            forced_first.total,
            weight.largest.max(forced_first.largest),
        )?
        .ok_or_else(|| too_heavy(&cutter, budget, commit))?;
        payload_cap = raised.max(cutter.cap);
        cutter.cap = effective_payload_cap(payload_cap, limits.max_pack_bytes)?;
    }
    let mut attempts = 0;
    'cut: loop {
        let mut steps = Vec::new();
        let mut from = 0;
        while from < chain.commits.len() {
            if steps.len() >= ctl.max_steps {
                return Err(PushError::PushSplitLimit(format!(
                    "this push would need more than {} advances; no advance of this branch was published. Ask the operator to raise the tickets per advance (or max_pack_bytes), or push an ancestor commit first",
                    ctl.max_steps
                )));
            }
            match cutter.cut(from)? {
                Cut::To(to) => {
                    from = to;
                    steps.push(chain.commits[from - 1]);
                }
                Cut::TooBig(overflow) => {
                    let raised = raised_payload_cap(
                        limits,
                        budget,
                        overflow.weight.total,
                        0,
                        overflow.weight.largest,
                    )?
                    .map(|cap| effective_payload_cap(cap.max(cutter.cap), limits.max_pack_bytes))
                    .transpose()?;
                    match raised {
                        Some(cap) if cap > cutter.cap && attempts < MAX_RAISES => {
                            attempts += 1;
                            payload_cap = cap;
                            cutter.cap = cap;
                            continue 'cut;
                        }
                        _ => return Err(overflow.error),
                    }
                }
            }
        }
        return Ok(SplitPlan { steps, payload_cap });
    }
}

/// The refusal of a commit that adds more than the budget's packs of the
/// largest size the format and the remote allow.
fn too_heavy(cutter: &Cutter<'_>, budget: usize, commit: usize) -> PushError {
    PushError::PushSplitLimit(format!(
        "{} adds more than {budget} packs of the largest size the format and the remote allow; no advance of this branch was published",
        cutter.describe(cutter.chain.commits[commit])
    ))
}

/// Most times the pack size is raised after a cut finds a step the weights
/// missed.
const MAX_RAISES: usize = 8;

#[cfg(test)]
mod tests {
    use super::*;
    use kit_core::layout::RepoLayout;
    use kit_core::object::{Blob, Commit, EntryMode, Identity, Tree, TreeEntry};
    use kit_core::ops::graph::reachable_objects;
    use kit_core::serialize;
    use proptest::prelude::*;
    use tempfile::TempDir;

    fn store() -> (TempDir, ObjectStore) {
        let dir = TempDir::new().unwrap();
        let store = ObjectStore::init(&RepoLayout::single(dir.path())).unwrap();
        (dir, store)
    }

    fn put(store: &ObjectStore, obj: &Object) -> Hash {
        store.write(&serialize::serialize(obj).unwrap()).unwrap()
    }

    /// Deterministic bytes: incompressible, or one repeated byte.
    fn bytes(seed: u64, len: usize, compressible: bool) -> Vec<u8> {
        if compressible {
            return vec![seed.to_le_bytes()[0]; len];
        }
        let mut out = vec![0; len];
        let mut state = seed | 1;
        for chunk in out.chunks_mut(8) {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            chunk.copy_from_slice(&state.to_le_bytes()[..chunk.len()]);
        }
        out
    }

    /// A commit whose tree holds every blob in `files`.
    fn commit(store: &ObjectStore, files: &[Hash], parents: Vec<Hash>, seed: u8) -> Hash {
        let mut entries: Vec<TreeEntry> = files
            .iter()
            .enumerate()
            .map(|(i, hash)| TreeEntry {
                name: format!("f{i:04}").into_bytes(),
                mode: EntryMode::Blob,
                object_hash: *hash,
            })
            .collect();
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        let tree = put(store, &Object::Tree(Tree { entries }));
        put(
            store,
            &Object::Commit(Commit::new_unannotated(
                tree,
                parents,
                Identity::ed25519([7; 32]),
                [0; 32],
                vec![seed],
                u64::from(seed),
                [0; 64],
            )),
        )
    }

    fn commit_tree(store: &ObjectStore, tree: Hash, parents: Vec<Hash>, seed: u8) -> Hash {
        put(
            store,
            &Object::Commit(Commit::new_unannotated(
                tree,
                parents,
                Identity::ed25519([7; 32]),
                [0; 32],
                vec![seed],
                u64::from(seed),
                [0; 64],
            )),
        )
    }

    fn blob(store: &ObjectStore, seed: u64, len: usize) -> Hash {
        put(
            store,
            &Object::Blob(Blob {
                data: bytes(seed, len, false),
            }),
        )
    }

    /// A linear history of `n` commits, each adding one 100-byte file.
    fn line(store: &ObjectStore, n: u8) -> Vec<Hash> {
        let mut files = Vec::new();
        let mut commits: Vec<Hash> = Vec::new();
        for i in 0..n {
            files.push(blob(store, u64::from(i) + 1, 100));
            let parents = commits.last().copied().into_iter().collect();
            commits.push(commit(store, &files, parents, i));
        }
        commits
    }

    #[test]
    fn the_budget_is_the_advertised_allowance_minus_the_packmap_ticket() {
        let budget = |tickets_per_advance| {
            data_pack_budget(UploadLimits {
                tickets_per_advance,
                ..UploadLimits::default()
            })
        };
        assert_eq!(budget(None), 6);
        assert_eq!(budget(Some(2)), 1);
        assert_eq!(budget(Some(3)), 2);
        assert_eq!(budget(Some(7)), 6);
        assert_eq!(budget(Some(8)), 7);
        assert_eq!(budget(Some(1024)), 1023);
        // A limits value built by hand never gives a budget of zero.
        assert_eq!(budget(Some(1)), 1);
        assert_eq!(budget(Some(0)), 1);
    }

    #[test]
    fn the_walk_stops_at_the_commit_the_remote_holds() {
        let (_dir, store) = store();
        let c = line(&store, 6);
        let chain = walk_chain(&store, c[5], Some(c[2]), &PushControl::default()).unwrap();
        assert_eq!(chain.commits, [c[3], c[4], c[5]]);
        assert_eq!(chain.held.len(), 3);
        assert!(c[..3].iter().all(|held| chain.held.contains(held)));

        // A new branch walks to the root.
        let chain = walk_chain(&store, c[5], None, &PushControl::default()).unwrap();
        assert_eq!(chain.commits, c);
        assert!(chain.held.is_empty());
    }

    #[test]
    fn a_diverged_remote_seeds_the_shared_ancestor_not_its_own_tip() {
        let (_dir, store) = store();
        let c = line(&store, 6);
        let other = blob(&store, 900, 100);
        let theirs = commit(&store, &[other], vec![c[1]], 90);
        let chain = walk_chain(&store, c[5], Some(theirs), &PushControl::default()).unwrap();
        assert_eq!(chain.commits, [c[2], c[3], c[4], c[5]]);
        // The remote's history is its tip and the shared ancestors.
        assert_eq!(chain.held.len(), 3);
        assert!(chain.held.contains(&theirs) && chain.held.contains(&c[1]));
        assert!(!chain.held.contains(&c[2]));
    }

    #[test]
    fn the_walk_never_enters_a_second_parent_side() {
        let (_dir, store) = store();
        let c = line(&store, 4);
        let side_file = blob(&store, 500, 100);
        let side = commit(&store, &[side_file], vec![c[0]], 50);
        let merge = commit(&store, &[side_file], vec![c[3], side], 60);
        let chain = walk_chain(&store, merge, None, &PushControl::default()).unwrap();
        assert_eq!(chain.commits, [c[0], c[1], c[2], c[3], merge]);
        // The side branch's objects are weighed with the merge that brings them.
        let weights = cumulative_weights(&store, &chain, &PushControl::default())
            .unwrap()
            .cumulative;
        let brought = weights[5] - weights[4];
        let lone = weights[4] - weights[3];
        assert!(brought > lone, "{weights:?}");
    }

    fn chunked(store: &ObjectStore, chunks: &[Hash]) -> Hash {
        put(
            store,
            &Object::ChunkedBlob(kit_core::object::ChunkedBlob {
                total_size: 100 * chunks.len() as u64,
                chunk_size: 0,
                chunks: chunks.to_vec(),
            }),
        )
    }

    #[test]
    fn the_walk_cap_is_the_split_limit() {
        let (_dir, store) = store();
        // Distinct files: every new commit brings a commit, a tree and a blob.
        let mut files = Vec::new();
        let mut c: Vec<Hash> = Vec::new();
        for i in 0..6_u8 {
            files.push(blob(&store, 2 * u64::from(i) + 1, 100));
            let parents = c.last().copied().into_iter().collect();
            c.push(commit(&store, &files, parents, i));
        }
        let ctl = PushControl::default();
        // Three held commits pass a cap of three and fail a cap of two.
        walk_chain_capped(&store, c[5], Some(c[2]), &ctl, 3).unwrap();
        assert!(matches!(
            walk_chain_capped(&store, c[5], Some(c[2]), &ctl, 2),
            Err(PushError::PushSplitLimit(_))
        ));

        // Held commits, new commits and kept objects share the cap.
        let chain = walk_chain(&store, c[5], Some(c[2]), &ctl).unwrap();
        let counted = |objects| {
            cumulative_weights_capped(
                &store,
                &chain,
                &ctl,
                WalkLimits {
                    objects,
                    ..WalkLimits::default()
                },
            )
        };
        let exact = 3 + 3 * 3;
        counted(exact).unwrap();
        assert!(matches!(
            counted(exact - 1),
            Err(PushError::PushSplitLimit(_))
        ));

        assert!(matches!(
            walk_error(StoreError::OperationLimitExceeded(PUSH_WALK_LIMIT)),
            PushError::PushSplitLimit(_)
        ));
        assert!(!matches!(
            walk_error(StoreError::OperationLimitExceeded("another limit")),
            PushError::PushSplitLimit(_)
        ));
    }

    #[test]
    fn a_chunk_weighs_once_and_a_renamed_chunked_file_weighs_as_if_sent() {
        let (_dir, store) = store();
        let chunk = blob(&store, 7, 1000);
        let other = blob(&store, 8, 1000);
        let big = chunked(&store, &[chunk, other]);
        let tree = |name: &[u8], file: Hash| {
            put(
                &store,
                &Object::Tree(Tree {
                    entries: vec![TreeEntry {
                        name: name.to_vec(),
                        mode: EntryMode::Blob,
                        object_hash: file,
                    }],
                }),
            )
        };
        let remote = commit_tree(&store, tree(b"a", big), Vec::new(), 1);
        let renamed = commit_tree(&store, tree(b"b", big), vec![remote], 2);
        let ctl = PushControl::default();
        let chain = walk_chain(&store, renamed, Some(remote), &ctl).unwrap();
        let weights = cumulative_weights(&store, &chain, &ctl).unwrap();
        // Sized against its parents alone, the renamed file weighs what a step
        // that starts in front of the rename would have to send. The plan of
        // the push itself, which sees the remote's snapshot, sends none of it.
        assert!(weights.cumulative[1] >= 2000, "{:?}", weights.cumulative);
        let plan = transfer::plan_pack_with(&store, renamed, Some(remote), |_, candidates| {
            Ok(vec![None; candidates.len()])
        })
        .unwrap();
        assert!(plan.raw.iter().all(|h| ![big, chunk, other].contains(h)));

        // A chunk that a file lists many times is weighed once.
        let repeated = chunked(&store, &[chunk; 50]);
        let tree_c = tree(b"c", repeated);
        let once = commit_tree(&store, tree_c, Vec::new(), 3);
        let chain = walk_chain(&store, once, None, &ctl).unwrap();
        let weights = cumulative_weights(&store, &chain, &ctl).unwrap();
        let weight = |hash| weight_of(&store, &hash).unwrap();
        let expected = weight(once) + weight(tree_c) + weight(repeated) + weight(chunk);
        assert_eq!(weights.cumulative[1], expected);
    }

    #[test]
    fn a_shallow_boundary_ends_the_walk_and_its_parents_are_not_followed() {
        let (_dir, store) = store();
        let c = line(&store, 6);
        let control = PushControl {
            shallow: std::iter::once(c[3]).collect(),
            ..PushControl::default()
        };
        let chain = walk_chain(&store, c[5], None, &control).unwrap();
        assert_eq!(chain.commits, [c[3], c[4], c[5]]);
        // The boundary commit weighs its own tree closure only.
        let weights = cumulative_weights(&store, &chain, &control)
            .unwrap()
            .cumulative;
        let everything = cumulative_weights(&store, &chain, &PushControl::default())
            .unwrap()
            .cumulative;
        assert!(weights[1] < everything[1]);
    }

    #[test]
    fn a_too_long_walk_is_refused() {
        let (_dir, store) = store();
        let c = line(&store, 6);
        let control = PushControl {
            max_chain: 4,
            ..PushControl::default()
        };
        let error = walk_chain(&store, c[5], None, &control).err().unwrap();
        assert!(matches!(error, PushError::PushSplitLimit(_)), "{error:?}");
    }

    #[test]
    fn cumulative_weights_add_up_to_the_new_objects() {
        let (_dir, store) = store();
        // Distinct files: two seeds can make the same bytes, and a blob that two
        // commits bring is weighed for both.
        let mut files = Vec::new();
        let mut c: Vec<Hash> = Vec::new();
        for i in 0..6_u8 {
            files.push(blob(&store, 2 * u64::from(i) + 1, 100));
            let parents = c.last().copied().into_iter().collect();
            c.push(commit(&store, &files, parents, i));
        }
        let chain = walk_chain(&store, c[5], Some(c[1]), &PushControl::default()).unwrap();
        let weights = cumulative_weights(&store, &chain, &PushControl::default())
            .unwrap()
            .cumulative;
        assert_eq!(weights.len(), chain.commits.len() + 1);
        assert!(weights.windows(2).all(|w| w[0] < w[1]));
        let held = reachable_objects(&store, &c[1]).unwrap();
        let expected: u64 = reachable_objects(&store, &c[5])
            .unwrap()
            .difference(&held)
            .map(|h| store.object_metadata(h).unwrap().len() + pack::ENTRY_FRAME_LEN as u64)
            .sum();
        assert_eq!(*weights.last().unwrap(), expected);
    }

    #[test]
    fn a_step_never_weighs_more_than_its_weights_say() {
        let (_dir, store) = store();
        let blobs = |first: u64, count: u64| -> Vec<Hash> {
            (first..first + count)
                .map(|i| blob(&store, i, 3000))
                .collect()
        };
        let a = blobs(1, 5);
        let b = blobs(100, 5);
        let e = blobs(200, 2);
        let d = blobs(300, 1);
        let c1 = commit(&store, &a, Vec::new(), 1);
        let c2 = commit(&store, &b, vec![c1], 2);
        // The same paths return to the first files, and two files are added.
        let with = |parts: &[&[Hash]]| -> Vec<Hash> { parts.concat() };
        let c3 = commit(&store, &with(&[&a, &e]), vec![c2], 3);
        let c4 = commit(&store, &with(&[&a, &e, &d]), vec![c3], 4);
        let chain = walk_chain(&store, c4, None, &PushControl::default()).unwrap();
        let weights = cumulative_weights(&store, &chain, &PushControl::default())
            .unwrap()
            .cumulative;
        // A step that starts after c2 sends the first files again.
        let plan = transfer::plan_pack_with(&store, c4, Some(c2), |_, candidates| {
            Ok(vec![None; candidates.len()])
        })
        .unwrap();
        let sent: u64 = plan.raw.iter().map(|h| weight_of(&store, h).unwrap()).sum();
        assert!(plan.raw.contains(&a[0]));
        assert!(
            sent <= weights[4] - weights[2],
            "{sent} > {}",
            weights[4] - weights[2]
        );
    }

    /// The data packs an exact dry seal of the plan that advances `base` to
    /// `tip` makes at `cap`.
    fn step_packs(
        store: &ObjectStore,
        tip: Hash,
        base: Option<Hash>,
        limits: UploadLimits,
        cap: u64,
    ) -> usize {
        let plan = transfer::plan_pack_with(store, tip, base, |_, candidates| {
            Ok(vec![None; candidates.len()])
        })
        .unwrap();
        let cap = effective_payload_cap(cap, limits.max_pack_bytes).unwrap();
        build_and_upload_packs(
            PackSink::Count,
            store,
            plan,
            cap,
            limits,
            &crate::NoopObserver,
        )
        .map_or(usize::MAX, |keys| keys.len())
    }

    #[test]
    fn a_forced_overwrite_that_merges_a_remote_commit_still_fits_every_step() {
        let (_dir, store) = store();
        let tree = |entries: &[(String, Hash, EntryMode)]| {
            let mut entries: Vec<TreeEntry> = entries
                .iter()
                .map(|(name, hash, mode)| TreeEntry {
                    name: name.clone().into_bytes(),
                    mode: *mode,
                    object_hash: *hash,
                })
                .collect();
            entries.sort_by(|a, b| a.name.cmp(&b.name));
            put(&store, &Object::Tree(Tree { entries }))
        };
        let shared = ("s".to_string(), blob(&store, 1, 100), EntryMode::Blob);
        let big_files: Vec<(String, Hash, EntryMode)> = (0..20)
            .map(|i| {
                (
                    format!("b{i:02}"),
                    blob(&store, 100 + i, 3000),
                    EntryMode::Blob,
                )
            })
            .collect();
        let big = ("big".to_string(), tree(&big_files), EntryMode::Tree);
        let r0 = commit_tree(&store, tree(std::slice::from_ref(&shared)), Vec::new(), 1);
        // The remote holds a commit the local history reaches only by a merge.
        let with_big = tree(&[shared.clone(), big.clone()]);
        let x = commit_tree(&store, with_big, vec![r0], 2);
        let remote = commit_tree(&store, with_big, vec![x], 3);
        let mut tip = r0;
        let mut local = vec![shared.clone()];
        for i in 0..12_u8 {
            let file = blob(&store, 1000 + u64::from(i), 3000);
            local.push((format!("l{i:02}"), file, EntryMode::Blob));
            tip = commit_tree(&store, tree(&local), vec![tip], 10 + i);
        }
        local.push(big);
        let merged = commit_tree(&store, tree(&local), vec![tip, x], 40);
        let limits = ticketed(None);
        let plan = plan_split(
            &store,
            merged,
            Some(remote),
            limits,
            4096,
            &PushControl::default(),
            RefWriteCondition::Any,
            "main",
        )
        .unwrap();
        let mut base = Some(remote);
        for step in &plan.steps {
            assert!(
                step_packs(&store, *step, base, limits, plan.payload_cap)
                    <= data_pack_budget(limits),
                "a step needs more packs than an advance may carry"
            );
            base = Some(*step);
        }
    }

    #[test]
    fn a_moved_directory_does_not_raise_the_pack_size_or_refuse_the_push() {
        let (_dir, store) = store();
        let blobs: Vec<Hash> = (0..20).map(|i| blob(&store, i + 1, 3000)).collect();
        let dir = |files: &[Hash]| {
            put(
                &store,
                &Object::Tree(Tree {
                    entries: files
                        .iter()
                        .enumerate()
                        .map(|(i, hash)| TreeEntry {
                            name: format!("f{i:04}").into_bytes(),
                            mode: EntryMode::Blob,
                            object_hash: *hash,
                        })
                        .collect(),
                }),
            )
        };
        let moved_dir = dir(&blobs);
        let top = |name: &[u8], sub: Hash, extra: &[(String, Hash)]| {
            let mut entries = vec![TreeEntry {
                name: name.to_vec(),
                mode: EntryMode::Tree,
                object_hash: sub,
            }];
            entries.extend(extra.iter().map(|(n, h)| TreeEntry {
                name: n.clone().into_bytes(),
                mode: EntryMode::Blob,
                object_hash: *h,
            }));
            entries.sort_by(|a, b| a.name.cmp(&b.name));
            put(&store, &Object::Tree(Tree { entries }))
        };
        let remote = commit_tree(&store, top(b"a", moved_dir, &[]), Vec::new(), 1);
        let mut tip = commit_tree(&store, top(b"b", moved_dir, &[]), vec![remote], 2);
        let mut extra = Vec::new();
        for i in 0..12_u8 {
            extra.push((format!("z{i:02}"), blob(&store, 500 + u64::from(i), 3000)));
            tip = commit_tree(&store, top(b"b", moved_dir, &extra), vec![tip], 10 + i);
        }
        for max in [None, Some(8192)] {
            let limits = ticketed(max);
            let plan = plan_split(
                &store,
                tip,
                Some(remote),
                limits,
                4096,
                &PushControl::default(),
                RefWriteCondition::Any,
                "main",
            )
            .unwrap();
            assert_eq!(plan.payload_cap, 4096, "{max:?}");
        }
    }

    /// The refusal of a lone commit that only fits by containing the remote
    /// head carries the rebase-or-merge-earlier advice.
    #[test]
    fn a_step_forced_to_reach_the_remote_head_says_how_to_avoid_it() {
        let (_dir, store) = store();
        // Four commits of eight files each, then a merge of the remote head
        // with twenty more. The merge fits the remote's largest (8 KiB) packs
        // on its own, but the first advance must hold the whole prefix.
        let mut a: Vec<Hash> = Vec::new();
        let mut files = Vec::new();
        for i in 0..4_u8 {
            for j in 0..8_u64 {
                files.push(blob(&store, 1000 + u64::from(i) * 8 + j, 2048));
            }
            let parents = a.last().copied().into_iter().collect();
            a.push(commit(&store, &files, parents, i));
        }
        let their_file = blob(&store, 900, 100);
        let theirs = commit(&store, &[their_file], Vec::new(), 90);
        let big: Vec<Hash> = (0..20).map(|i| blob(&store, 300 + i, 2048)).collect();
        let merge = commit(&store, &big, vec![a[3], theirs], 91);
        let limits = UploadLimits {
            max_pack_bytes: Some(8192),
            tickets_per_advance: Some(7),
            ticket_threshold_bytes: Some(0),
        };
        let error = plan_push_steps(
            &store,
            merge,
            Some(theirs),
            limits,
            4096,
            &PushControl::default(),
            RefWriteCondition::Match(theirs),
            "main",
        )
        .unwrap_err();
        assert!(
            matches!(
                &error,
                PushError::PushTooLarge {
                    holds_remote_head: true,
                    ..
                }
            ),
            "{error:?}"
        );
        assert!(
            error.to_string().contains("rebase onto the remote head"),
            "{error}"
        );
    }

    fn ticketed(max_pack_bytes: Option<u64>) -> UploadLimits {
        UploadLimits {
            max_pack_bytes,
            tickets_per_advance: Some(7),
            ticket_threshold_bytes: Some(0),
        }
    }

    fn split(
        store: &ObjectStore,
        tip: Hash,
        limits: UploadLimits,
        cap: u64,
    ) -> Result<SplitPlan, PushError> {
        plan_split(
            store,
            tip,
            None,
            limits,
            cap,
            &PushControl::default(),
            RefWriteCondition::Missing,
            "main",
        )
    }

    /// The packs an exact dry seal of `tip`'s whole closure makes at `cap`.
    fn sealed_packs(store: &ObjectStore, tip: Hash, limits: UploadLimits, cap: u64) -> usize {
        let plan = transfer::plan_pack_with(store, tip, None, |_, candidates| {
            Ok(vec![None; candidates.len()])
        })
        .unwrap();
        let cap = effective_payload_cap(cap, limits.max_pack_bytes).unwrap();
        build_and_upload_packs(
            PackSink::Count,
            store,
            plan,
            cap,
            limits,
            &crate::NoopObserver,
        )
        .map_or(usize::MAX, |keys| keys.len())
    }

    #[test]
    fn the_raised_cap_is_what_the_commit_needs() {
        let limits = ticketed(None);
        let cap = raised_payload_cap(limits, 6, 60_000, 0, 3_005)
            .unwrap()
            .unwrap();
        assert_eq!(cap, 10_000 + 3_005 + 1);
        // A larger budget needs a smaller raise.
        let wider = raised_payload_cap(limits, 15, 60_000, 0, 3_005)
            .unwrap()
            .unwrap();
        assert!(wider < cap, "{wider} {cap}");
        // The first advance, forced to hold the remote head, counts too.
        let forced = raised_payload_cap(limits, 6, 1_000, 60_000, 3_005)
            .unwrap()
            .unwrap();
        assert_eq!(forced, cap);
    }

    #[test]
    fn the_raised_cap_never_passes_the_format_or_the_advertised_maximum() {
        // The weight fits only by filling every pack: clamped, not refused.
        let ceiling = pack::MAX_TOTAL_PAYLOAD;
        let limits = ticketed(None);
        assert_eq!(
            raised_payload_cap(limits, 6, 6 * ceiling, 0, 1 << 20).unwrap(),
            Some(ceiling)
        );
        assert_eq!(
            raised_payload_cap(limits, 6, 6 * ceiling + 1, 0, 0).unwrap(),
            None
        );

        let advertised = 100_000;
        let limits = ticketed(Some(advertised));
        let weight_cap = pack_weight_cap(advertised, Some(advertised));
        let cap = raised_payload_cap(limits, 6, 6 * weight_cap, 0, 1 << 20)
            .unwrap()
            .unwrap();
        assert_eq!(cap, weight_cap);
        assert!(cap <= advertised);
        assert_eq!(
            raised_payload_cap(limits, 6, 6 * weight_cap + 1, 0, 0).unwrap(),
            None
        );
    }

    #[test]
    fn a_forced_first_advance_past_the_ceiling_is_left_to_the_cut() {
        let ceiling = pack::MAX_TOTAL_PAYLOAD;
        // Clamped to the ceiling, not refused: the cut names the remedy.
        let cap = raised_payload_cap(ticketed(None), 6, 1, 7 * ceiling, 0)
            .unwrap()
            .unwrap();
        assert_eq!(cap, ceiling);
    }

    #[test]
    fn one_commit_that_needs_more_than_the_budget_pushes_with_larger_packs() {
        let (_dir, store) = store();
        let files: Vec<Hash> = (0..20).map(|i| blob(&store, i + 1, 3000)).collect();
        let tip = commit(&store, &files, Vec::new(), 1);
        let limits = ticketed(None);
        // 60 KB over 4 KiB packs is at least fifteen packs: far over six.
        assert!(sealed_packs(&store, tip, limits, 4096) > 6);

        let plan = split(&store, tip, limits, 4096).unwrap();
        assert_eq!(plan.steps, [tip]);
        assert!(plan.payload_cap > 4096, "{}", plan.payload_cap);
        assert!(plan.payload_cap <= pack::MAX_TOTAL_PAYLOAD);
        assert!(sealed_packs(&store, tip, limits, plan.payload_cap) <= 6);
    }

    #[test]
    fn the_same_objects_over_many_commits_keep_the_preferred_cap() {
        let (_dir, store) = store();
        let mut files = Vec::new();
        let mut commits: Vec<Hash> = Vec::new();
        for i in 0..20_u8 {
            files.push(blob(&store, u64::from(i) + 1, 3000));
            let parents = commits.last().copied().into_iter().collect();
            commits.push(commit(&store, &files, parents, i));
        }
        let plan = split(&store, commits[19], ticketed(None), 4096).unwrap();
        assert_eq!(plan.payload_cap, 4096);
        assert!(plan.steps.len() > 1, "{}", plan.steps.len());
    }

    #[test]
    fn a_commit_too_large_even_at_the_ceiling_is_refused_before_any_upload() {
        let (_dir, store) = store();
        let files: Vec<Hash> = (0..40).map(|i| blob(&store, i + 1, 3000)).collect();
        let tip = commit(&store, &files, Vec::new(), 1);
        // The remote takes 8 KiB packs at most: six hold under 49 KB.
        let error = split(&store, tip, ticketed(Some(8192)), 4096)
            .err()
            .unwrap();
        assert!(matches!(error, PushError::PushSplitLimit(_)), "{error:?}");
        assert!(error.to_string().contains("no advance"), "{error}");
        assert!(error.to_string().contains(&to_hex(&tip)), "{error}");
    }

    #[test]
    fn a_commit_that_fits_by_weight_but_not_by_packing_pushes_with_larger_packs() {
        let (_dir, store) = store();
        // Each blob is about 1.7 KB stored, so two fit a 4 KiB pack and a
        // third does not: 13 blobs weigh under six caps but need seven packs.
        let files: Vec<Hash> = (0..13).map(|i| blob(&store, i + 1, 3000)).collect();
        let tip = commit(&store, &files, Vec::new(), 1);
        let limits = ticketed(None);
        let chain = walk_chain(&store, tip, None, &PushControl::default()).unwrap();
        let weight = *cumulative_weights(&store, &chain, &PushControl::default())
            .unwrap()
            .cumulative
            .last()
            .unwrap();
        assert!(weight < 6 * 4096, "{weight}");
        assert!(sealed_packs(&store, tip, limits, 4096) > 6);

        let plan = split(&store, tip, limits, 4096).unwrap();
        assert!(plan.payload_cap > 4096, "{}", plan.payload_cap);
        assert!(sealed_packs(&store, tip, limits, plan.payload_cap) <= 6);
    }

    #[test]
    fn a_first_step_forced_to_reach_the_remote_head_counts_toward_the_cap() {
        let (_dir, store) = store();
        let theirs = commit(&store, &[blob(&store, 900, 100)], Vec::new(), 90);
        let files: Vec<Hash> = (0..14).map(|i| blob(&store, i + 1, 3000)).collect();
        // Each commit alone fits six 4 KiB packs (seven blobs make four), but
        // the first advance must hold the remote head, which only the merge
        // reaches: both together need seven.
        let first = commit(&store, &files[..7], Vec::new(), 1);
        let merge = commit(&store, &files, vec![first, theirs], 2);
        let split_at = |remote: Option<Hash>, condition| {
            plan_split(
                &store,
                merge,
                remote,
                ticketed(None),
                4096,
                &PushControl::default(),
                condition,
                "main",
            )
            .unwrap()
        };
        let forced = split_at(Some(theirs), RefWriteCondition::Match(theirs));
        assert!(forced.payload_cap > 4096, "{}", forced.payload_cap);
        // With no remote head to hold, the same commits split at the preferred
        // size.
        let free = split_at(None, RefWriteCondition::Missing);
        assert_eq!(free.payload_cap, 4096);
        assert!(free.steps.len() > 1, "{}", free.steps.len());
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// The real sealed pack count never exceeds the conservative estimate,
        /// and a push whose weight is within three pack caps always fits the
        /// budget: the two facts the cut selection rests on. Entries stay below
        /// the server's pack limit, and half the cases send deltas against a
        /// base the remote holds.
        #[test]
        fn estimate_bounds_the_real_pack_count_and_three_caps_always_fit(
            sizes in prop::collection::vec((16_usize..1500, any::<bool>()), 1..12),
            payload_cap in 512_u64..16_384,
            max_pack in prop::option::of(2048_u64..12_000),
            with_deltas in any::<bool>(),
        ) {
            let (_dir, store) = store();
            let files: Vec<Hash> = sizes
                .iter()
                .enumerate()
                .map(|(i, (len, compressible))| {
                    put(&store, &Object::Blob(Blob { data: bytes(i as u64 + 1, *len, *compressible) }))
                })
                .collect();
            let (tip, base) = if with_deltas {
                // The tip edits every file a little, so each is sent as a delta.
                let base = commit(&store, &files, Vec::new(), 1);
                let edited: Vec<Hash> = sizes
                    .iter()
                    .enumerate()
                    .map(|(i, (len, compressible))| {
                        let mut data = bytes(i as u64 + 1, *len, *compressible);
                        let middle = data.len() / 2;
                        data[middle] ^= 0xff;
                        put(&store, &Object::Blob(Blob { data }))
                    })
                    .collect();
                let tip = commit(&store, &edited, vec![base], 2);
                (tip, Some(base))
            } else {
                (commit(&store, &files, Vec::new(), 1), None)
            };
            let plan = if with_deltas {
                transfer::plan_pack_with(&store, tip, base, encode_delta_candidates_batch).unwrap()
            } else {
                transfer::plan_pack_with(&store, tip, None, |_, candidates| {
                    Ok(vec![None; candidates.len()])
                })
                .unwrap()
            };
            // No ticket gate: count every pack the seal produces.
            let limits = UploadLimits {
                max_pack_bytes: max_pack,
                tickets_per_advance: None,
                ticket_threshold_bytes: None,
            };
            let cap = effective_payload_cap(payload_cap, max_pack).unwrap();
            let estimate = estimate_pack_sizes(&store, &plan, cap, max_pack).unwrap().len();
            let keys = build_and_upload_packs(PackSink::Count, &store, plan, cap, limits, &crate::NoopObserver)
                .map_err(|e| TestCaseError::fail(format!("{e:?}")))?;
            prop_assert!(keys.len() <= estimate, "{} > {estimate}", keys.len());
            let held = HeldCommits::collect(&store, base, MAX_PUSH_WALK).unwrap();
            let chain = Chain { commits: vec![tip], held };
            let weight = *cumulative_weights(&store, &chain, &PushControl::default())
                .unwrap()
                .cumulative
                .last()
                .unwrap();
            if weight <= 3 * pack_weight_cap(cap, max_pack) {
                prop_assert!(estimate <= 6, "{estimate} packs for weight {weight}");
            }
        }
    }
}

/// Splits whose steps the weights cannot size: the plan of a step is checked
/// against the real packs it makes.
#[cfg(test)]
mod step_fit_tests {
    use super::*;
    use kit_core::layout::RepoLayout;
    use kit_core::object::{
        Blob, ChunkedBlob, Commit, EntryMode, Identity, ObjectType, Tree, TreeEntry,
    };
    use kit_core::serialize;
    use tempfile::TempDir;

    fn store() -> (TempDir, ObjectStore) {
        let dir = TempDir::new().unwrap();
        let store = ObjectStore::init(&RepoLayout::single(dir.path())).unwrap();
        (dir, store)
    }

    fn put(store: &ObjectStore, obj: &Object) -> Hash {
        store.write(&serialize::serialize(obj).unwrap()).unwrap()
    }

    /// Incompressible bytes, different for every seed.
    fn blob(store: &ObjectStore, seed: u64, len: usize) -> Hash {
        let mut data = vec![0; len];
        let mut state = seed.wrapping_mul(2).wrapping_add(1);
        for chunk in data.chunks_mut(8) {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            chunk.copy_from_slice(&state.to_le_bytes()[..chunk.len()]);
        }
        put(store, &Object::Blob(Blob { data }))
    }

    fn chunked(store: &ObjectStore, chunks: &[Hash]) -> Hash {
        put(
            store,
            &Object::ChunkedBlob(ChunkedBlob {
                total_size: 3000 * chunks.len() as u64,
                chunk_size: 0,
                chunks: chunks.to_vec(),
            }),
        )
    }

    fn tree(store: &ObjectStore, entries: &[(&str, Hash)]) -> Hash {
        let named: Vec<(String, Hash)> = entries
            .iter()
            .map(|(name, hash)| ((*name).to_string(), *hash))
            .collect();
        tree_of(store, &named)
    }

    fn tree_of(store: &ObjectStore, entries: &[(String, Hash)]) -> Hash {
        let mut entries: Vec<TreeEntry> = entries
            .iter()
            .map(|(name, hash)| TreeEntry {
                name: name.clone().into_bytes(),
                mode: if store.object_type(hash).unwrap() == ObjectType::Tree {
                    EntryMode::Tree
                } else {
                    EntryMode::Blob
                },
                object_hash: *hash,
            })
            .collect();
        entries.sort_by(|left, right| left.name.cmp(&right.name));
        put(store, &Object::Tree(Tree { entries }))
    }

    fn commit(store: &ObjectStore, tree: Hash, parents: Vec<Hash>, seed: u8) -> Hash {
        put(
            store,
            &Object::Commit(Commit::new_unannotated(
                tree,
                parents,
                Identity::ed25519([7; 32]),
                [0; 32],
                vec![seed],
                u64::from(seed),
                [0; 64],
            )),
        )
    }

    fn ticketed(max_pack_bytes: Option<u64>) -> UploadLimits {
        UploadLimits {
            max_pack_bytes,
            tickets_per_advance: Some(7),
            ticket_threshold_bytes: Some(0),
        }
    }

    /// The data packs an exact dry seal of the plan from `base` to `tip` makes.
    fn step_packs(
        store: &ObjectStore,
        tip: Hash,
        base: Option<Hash>,
        limits: UploadLimits,
        cap: u64,
    ) -> usize {
        let plan =
            transfer::plan_pack_with(store, tip, base, encode_delta_candidates_batch).unwrap();
        let cap = effective_payload_cap(cap, limits.max_pack_bytes).unwrap();
        build_and_upload_packs(
            PackSink::Count,
            store,
            plan,
            cap,
            limits,
            &crate::NoopObserver,
        )
        .map_or(usize::MAX, |keys| keys.len())
    }

    fn split(
        store: &ObjectStore,
        tip: Hash,
        remote: Hash,
        limits: UploadLimits,
        condition: RefWriteCondition,
    ) -> Result<SplitPlan, PushError> {
        plan_split(
            store,
            tip,
            Some(remote),
            limits,
            4096,
            &PushControl::default(),
            condition,
            "main",
        )
    }

    fn assert_every_step_seals(
        store: &ObjectStore,
        plan: &SplitPlan,
        remote: Hash,
        limits: UploadLimits,
    ) {
        let mut base = remote;
        for step in &plan.steps {
            assert!(
                step_packs(store, *step, Some(base), limits, plan.payload_cap)
                    <= data_pack_budget(limits),
                "a step needs more packs than an advance may carry"
            );
            base = *step;
        }
    }

    /// A chunked file with one chunk changed, kept as `m` in a directory, and
    /// an unchanged copy of it.
    fn pair(store: &ObjectStore) -> (Hash, Hash) {
        let chunks: Vec<Hash> = (0..20).map(|i| blob(store, 1000 + i, 3000)).collect();
        let mut changed = chunks.clone();
        changed[19] = blob(store, 5000, 3000);
        (chunked(store, &chunks), chunked(store, &changed))
    }

    #[test]
    fn a_merge_that_reaches_a_chunked_file_by_another_path_still_fits_every_step() {
        let (_dir, store) = store();
        let (whole, nearly) = pair(&store);
        let (first, second, third, fourth) = (
            blob(&store, 1, 100),
            blob(&store, 2, 100),
            blob(&store, 3, 100),
            blob(&store, 4, 100),
        );
        let side_dir = tree(&store, &[("m", nearly), ("y", second)]);
        // The remote head holds the file in two versions.
        let remote_dir = tree(&store, &[("m", whole), ("y", first)]);
        let remote = commit(
            &store,
            tree(&store, &[("b", remote_dir), ("c", side_dir)]),
            vec![],
            1,
        );
        let mut main_files: Vec<(String, Hash)> = vec![("c".to_string(), side_dir)];
        let mut tip = commit(&store, tree_of(&store, &main_files), vec![remote], 2);
        for i in 0..30_u8 {
            main_files.push((format!("f{i:02}"), blob(&store, 100 + u64::from(i), 3000)));
            tip = commit(&store, tree_of(&store, &main_files), vec![tip], 10 + i);
        }
        // A side branch edits one file of the directory and keeps the rest.
        let edited = tree(&store, &[("m", whole), ("y", third)]);
        let side = commit(&store, tree(&store, &[("b", edited)]), vec![remote], 3);
        let merged_dir = tree(&store, &[("m", whole), ("x", fourth)]);
        main_files[0] = ("c".to_string(), edited);
        main_files.push(("a".to_string(), merged_dir));
        let merge = commit(&store, tree_of(&store, &main_files), vec![tip, side], 99);
        let limits = ticketed(None);
        let plan = split(
            &store,
            merge,
            remote,
            limits,
            RefWriteCondition::Match(remote),
        )
        .unwrap();
        assert_every_step_seals(&store, &plan, remote, limits);
    }

    #[test]
    fn a_forced_overwrite_that_reaches_a_chunked_file_by_another_path_fits_or_raises_the_pack() {
        let (_dir, store) = store();
        let (whole, nearly) = pair(&store);
        let (first, second, third, fourth) = (
            blob(&store, 1, 100),
            blob(&store, 2, 100),
            blob(&store, 3, 100),
            blob(&store, 4, 100),
        );
        let base_dir = tree(&store, &[("m", nearly), ("y", second)]);
        let base = commit(
            &store,
            tree(
                &store,
                &[
                    ("b", tree(&store, &[("m", whole), ("y", first)])),
                    ("c", base_dir),
                ],
            ),
            vec![],
            1,
        );
        let remote = commit(
            &store,
            tree(&store, &[("r", blob(&store, 9, 100))]),
            vec![base],
            2,
        );
        let edited = tree(&store, &[("m", whole), ("y", third)]);
        let side = commit(
            &store,
            tree(&store, &[("b", edited), ("c", base_dir)]),
            vec![base],
            3,
        );
        let merged_dir = tree(&store, &[("m", whole), ("x", fourth)]);
        let tip = commit(
            &store,
            tree(&store, &[("a", merged_dir), ("c", edited)]),
            vec![side],
            4,
        );
        let limits = ticketed(None);
        let plan = split(&store, tip, remote, limits, RefWriteCondition::Any).unwrap();
        assert_every_step_seals(&store, &plan, remote, limits);
    }

    #[test]
    fn a_moved_directory_next_to_a_heavy_commit_does_not_decide_the_raised_pack() {
        let (_dir, store) = store();
        let files: Vec<(String, Hash)> = (0..40)
            .map(|i| (format!("g{i:02}"), blob(&store, 200 + i, 3000)))
            .collect();
        let moved = tree_of(&store, &files);
        let added: Vec<(String, Hash)> = (0..10)
            .map(|i| (format!("h{i:02}"), blob(&store, 900 + i, 3000)))
            .collect();
        let added = tree_of(&store, &added);
        let remote = commit(&store, tree(&store, &[("d", moved)]), vec![], 1);
        let limits = ticketed(Some(8192));
        let rename = commit(&store, tree(&store, &[("e", moved)]), vec![remote], 2);
        let heavy = commit(
            &store,
            tree(&store, &[("e", moved), ("n", added)]),
            vec![rename],
            3,
        );
        let plan = split(
            &store,
            heavy,
            remote,
            limits,
            RefWriteCondition::Match(remote),
        )
        .unwrap();
        assert_every_step_seals(&store, &plan, remote, limits);
    }
}
