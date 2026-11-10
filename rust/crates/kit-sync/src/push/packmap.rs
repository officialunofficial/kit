use super::{PushContext, PushError};
use crate::packmap::{flatten_oldest_first, packmap_ref, walk_pack_chain};
use crate::{SourceError, SyncError};
use kit_core::{
    hash::Hash,
    protocol::{AdvanceOutcome, CommitOutcome, PackKey},
    refs,
    transfer::packmap::{ChainState, PlanError, plan_advance},
};
pub(super) const PACKMAP_CAS_ATTEMPTS: u32 = 8;
/// Walk a branch's packlist chain from `head_key` once. Return its depth in
/// nodes and its pack keys, oldest first. See
/// [`crate::packmap::walk_pack_chain`] for the walk and its integrity checks.
pub(crate) fn probe_chain(
    tx: &PushContext<'_>,
    branch: &str,
    head_key: Hash,
) -> Result<(usize, Vec<Hash>), PushError> {
    let nodes = walk_pack_chain(tx.source, tx.observer, branch, head_key)?;
    Ok((nodes.len(), flatten_oldest_first(nodes)))
}

/// Advertise new packs in apply order and then move the branch head.
///
/// The shared planner validates idempotency, encodes the node, and supplies its
/// CAS condition. This driver owns chain reads, uploads and eight CAS attempts.
/// A transactional transport commits both refs together; the ordered default
/// commits packmap first, so the head never precedes its reconstructing packs.
///
/// Every attempt validates the entire prior chain. A broken chain permits a
/// reset only for self-contained packs; deltas need its bases and fail with the
/// original error. Transient failures propagate.
///
/// A chain that the new node would make deeper than `rollover_threshold` rolls
/// over: one node with no predecessor lists every pack of the chain and then
/// the new packs. The node advertises a superset of the chain it replaces, so
/// it is as safe as an append on every transport and under every head
/// condition. No pack is uploaded again, and a fetcher that holds the old
/// packs downloads only the new ones. Each attempt decides again from the
/// chain it read. A threshold of zero never rolls over.
///
/// An idempotent retry only writes the head. Force pushes on an atomic or
/// serialized advance use the separate guarded driver, including this
/// idempotent case. Lost-response conflicts are disambiguated by reading the head.
pub(crate) fn advance_packmap(
    tx: &PushContext<'_>,
    branch: &str,
    pack_keys: &[Hash],
    self_contained: bool,
    rollover_threshold: usize,
    head_condition: refs::RefWriteCondition,
    tip: Hash,
) -> Result<(), PushError> {
    debug_assert!(
        !pack_keys.is_empty(),
        "advance_packmap requires at least one pack key — callers only reach this with a \
         non-empty plan"
    );
    let packmap_name = packmap_ref(branch);
    let head_name = format!("refs/heads/{branch}");
    for _ in 0..PACKMAP_CAS_ATTEMPTS {
        if tx.observer.cancelled() {
            return Err(PushError::Sync(SyncError::Interrupted));
        }
        let prior = tx.read_ref(&packmap_name)?;
        let state = match prior {
            None => ChainState::Missing,
            Some(head) => match probe_chain(tx, branch, head) {
                Ok((depth, packs)) => {
                    ChainState::validated(head, depth, packs, pack_keys.len(), rollover_threshold)
                }
                // Broken chain: a self-contained pack can reset to escape it;
                // a delta push must block (its bases live in the broken tail).
                // Transient transport errors propagate (don't reset on a blip).
                Err(PushError::Sync(SyncError::PackChainInvalid { .. })) if self_contained => {
                    ChainState::Reset { prior }
                }
                Err(e) => return Err(e),
            },
        };
        let node = plan_advance(state, pack_keys, None).map_err(|error| match error {
            PlanError::Packlist(error) => PushError::from(error),
            PlanError::NodeTooLarge => unreachable!("no node-size limit configured"),
        })?;
        let Some(node) = node else {
            return commit_head(tx, &head_name, head_condition, &tip, branch);
        };
        tx.upload_blob_via_ref(&node.bytes, &PackKey::from_hash(node.key), &head_name)
            .map_err(|error| super::repository_operation_error(tx, error))?;
        let commit_keys: Vec<PackKey> = pack_keys
            .iter()
            .copied()
            .map(PackKey::from_hash)
            .chain(std::iter::once(PackKey::from_hash(node.key)))
            .collect();
        // Commit the packmap AND the head together. A transactional
        // transport applies both atomically; the default does packmap-then-
        // head — still safe, the head never lands past an unadvanced packmap.
        match tx
            .advance_refs_committing(
                &head_name,
                head_condition,
                &tip,
                &packmap_name,
                node.condition,
                &node.key,
                &commit_keys,
            )
            .map_err(|error| super::repository_operation_error(tx, error))?
        {
            CommitOutcome::Advanced(AdvanceOutcome::Committed) => return Ok(()),
            // Another pusher advanced the packmap under us — re-read and retry.
            CommitOutcome::Advanced(AdvanceOutcome::PackmapConflict) => {}
            // The head precondition failed. Either the branch moved under
            // us (the push is stale) or the retry ladder re-issued a write
            // that had already landed (SPEC-TRANSPORT §7) — disambiguate.
            CommitOutcome::Advanced(AdvanceOutcome::HeadConflict) => {
                return head_conflict(tx, &head_name, &tip, branch);
            }
            CommitOutcome::TicketRejected => {
                if tx.read_ref(&head_name)? == Some(tip) {
                    return Ok(());
                }
                return Err(PushError::TicketRejected);
            }
            CommitOutcome::PacklistNotInRepository => {
                if tx.read_ref(&head_name)? == Some(tip) {
                    return Ok(());
                }
                return Err(PushError::PacklistNotInRepository);
            }
            CommitOutcome::DeltaBaseUnavailable => return Err(PushError::DeltaBaseUnavailable),
            _ => return Err(PushError::from(SourceError::InvalidResponse)),
        }
    }
    Err(PushError::PackmapContended {
        branch: branch.to_owned(),
    })
}

/// Move just the branch head under its CAS condition, mapping a conflict to
/// the actionable non-fast-forward error. Used when the packmap already
/// advertises the pack (idempotent retry) or a push has nothing to send.
pub(crate) fn commit_head(
    tx: &PushContext<'_>,
    head_name: &str,
    condition: refs::RefWriteCondition,
    tip: &Hash,
    branch: &str,
) -> Result<(), PushError> {
    match tx.update_ref(head_name, condition, tip) {
        Ok(()) => Ok(()),
        Err(SourceError::RefConflict) => head_conflict(tx, head_name, tip, branch),
        Err(e) => Err(super::repository_operation_error(tx, e)),
    }
}

/// Resolve a failed head precondition (`RefConflict` from `update_ref`,
/// `HeadConflict` from `advance_refs`) per SPEC-TRANSPORT §7: the retry
/// ladder may have re-issued a write whose first attempt landed, so the
/// conflict can be our own write. Re-read the head; if it already holds
/// `tip` the push landed, otherwise it is a genuine non-fast-forward.
///
/// Only the head is checked. Whoever moved the head to `tip` also advanced
/// the packmap to reconstruct it first (packmap-then-head, or both at once),
/// so a head at `tip` already satisfies the push's invariant even if a later
/// pusher has since moved the packmap past our node.
fn head_conflict(
    tx: &PushContext<'_>,
    head_name: &str,
    tip: &Hash,
    branch: &str,
) -> Result<(), PushError> {
    let current = tx
        .read_ref(head_name)
        .map_err(|error| super::repository_operation_error(tx, error))?;
    if current == Some(*tip) {
        return Ok(());
    }
    Err(PushError::NonFastForwardPush {
        branch: branch.to_owned(),
    })
}
