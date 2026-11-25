use super::{PushContext, PushError};
use crate::packmap::{
    MAX_FETCH_PACKS, MAX_PACK_CHAIN_DEPTH, branch_head_ref, flatten_oldest_first, packmap_ref,
    walk_pack_chain,
};
use crate::{SourceError, SyncError};
use kit_core::{
    hash::Hash,
    pack::pack_key,
    protocol::{AdvanceOutcome, CommitOutcome, PackKey},
    refs,
    transfer::{
        decode_packlist, encode_packlist,
        packmap::{ChainState, Node, PlanError, plan_advance},
    },
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
    let nodes = walk_pack_chain(tx.source, tx.observer, &branch_head_ref(branch), head_key)?;
    Ok((nodes.len(), flatten_oldest_first(nodes)))
}

/// The size of a chain as a fetch counts it: its nodes, and the packs they
/// list, a pack listed twice counted twice.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct ChainSize {
    pub(super) nodes: usize,
    pub(super) packs: usize,
}

/// Refuse `node` when it links onto a chain of `chain`'s size and the two
/// together are more than a fetch walks: [`MAX_PACK_CHAIN_DEPTH`] nodes or
/// [`MAX_FETCH_PACKS`] listed packs. Publishing it would leave the branch
/// that no client without its tip can fetch. A node with no predecessor
/// starts a new chain and is never refused.
pub(super) fn check_fetchable(
    branch: &str,
    chain: ChainSize,
    node: &Node,
) -> Result<(), PushError> {
    let planned = decode_packlist(&node.bytes)?;
    if planned.prev.is_some()
        && (chain.nodes >= MAX_PACK_CHAIN_DEPTH
            || chain.packs.saturating_add(planned.packs.len()) > MAX_FETCH_PACKS)
    {
        return Err(PushError::PackChainTooLong {
            branch: branch.to_owned(),
        });
    }
    Ok(())
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
/// An idempotent retry can write just an existing head. A recreated branch
/// must move its packmap so a delete that observed the old map loses its CAS.
/// Force pushes on an atomic or
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
        let (state, chain) = match prior {
            // A delete may remove the base chain between CAS attempts.
            // Dependent packs cannot serve as a new root, even if the
            // head CAS would refuse the push after writing that root.
            None if !self_contained => {
                return Err(PushError::NonFastForwardPush {
                    branch: branch.to_owned(),
                });
            }
            None => (ChainState::Missing, ChainSize::default()),
            Some(head) => match probe_chain(tx, branch, head) {
                Ok((depth, packs)) => {
                    let chain = ChainSize {
                        nodes: depth,
                        packs: packs.len(),
                    };
                    let state = ChainState::validated(
                        head,
                        depth,
                        packs,
                        pack_keys.len(),
                        rollover_threshold,
                    );
                    (state, chain)
                }
                // Broken chain: a self-contained pack can reset to escape it;
                // a delta push must block (its bases live in the broken tail).
                // Transient transport errors propagate (don't reset on a blip).
                Err(PushError::Sync(SyncError::PackChainInvalid { .. })) if self_contained => {
                    (ChainState::Reset { prior }, ChainSize::default())
                }
                Err(e) => return Err(e),
            },
        };
        let creating = matches!(head_condition, refs::RefWriteCondition::Missing);
        let node =
            plan_branch_node(state, pack_keys, prior, creating).map_err(|error| match error {
                PlanError::Packlist(error) => PushError::from(error),
                PlanError::NodeTooLarge => unreachable!("no node-size limit configured"),
            })?;
        let Some(node) = node else {
            return commit_head(tx, &head_name, head_condition, &tip, branch);
        };
        check_fetchable(branch, chain, &node)?;
        tx.upload_blob(&node.bytes, &PackKey::from_hash(node.key), &head_name)
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
                if tip_has_packmap(tx, &head_name, &packmap_name, &tip)? {
                    return Ok(());
                }
                return Err(PushError::TicketRejected);
            }
            CommitOutcome::PacklistNotInRepository => {
                if tip_has_packmap(tx, &head_name, &packmap_name, &tip)? {
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

/// A recreating push must publish a different packmap even when it adds
/// no packs to the existing chain. Link to that chain under its ref CAS.
pub(super) fn plan_branch_node(
    state: ChainState,
    packs: &[Hash],
    prior: Option<Hash>,
    creating: bool,
) -> Result<Option<Node>, PlanError> {
    let node = plan_advance(state, packs, None)?;
    if let (None, Some(prior), true) = (&node, prior, creating) {
        let bytes = encode_packlist(Some(prior), &[])?;
        return Ok(Some(Node {
            key: pack_key(&bytes),
            bytes,
            condition: refs::RefWriteCondition::Match(prior),
        }));
    }
    Ok(node)
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
/// The tip must still have a packmap: the head value alone also matches
/// when a repair was trying to restore a missing packmap.
fn head_conflict(
    tx: &PushContext<'_>,
    head_name: &str,
    tip: &Hash,
    branch: &str,
) -> Result<(), PushError> {
    if tip_has_packmap(tx, head_name, &packmap_ref(branch), tip)
        .map_err(|error| super::repository_operation_error(tx, error))?
    {
        return Ok(());
    }
    Err(PushError::NonFastForwardPush {
        branch: branch.to_owned(),
    })
}

pub(super) fn tip_has_packmap(
    tx: &PushContext<'_>,
    head_name: &str,
    packmap_name: &str,
    tip: &Hash,
) -> Result<bool, SourceError> {
    Ok(tx.read_ref(head_name)? == Some(*tip) && tx.read_ref(packmap_name)?.is_some())
}
