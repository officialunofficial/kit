//! Pure packmap planning shared by native and runtime-independent push drivers.
//! Callers validate/walk chains, classify failures, and do I/O.

use std::collections::HashSet;

use super::{PackListError, encode_packlist};
use crate::{hash::Hash, pack::pack_key, refs::RefWriteCondition};

/// Resolved state for one CAS attempt. Re-read and resolve after a conflict.
#[derive(Debug)]
pub enum ChainState {
    /// No packmap ref exists.
    Missing,
    /// A validated chain; `packs` contains every pack in it.
    /// Consumed so the set is dropped before encoding or uploading the node.
    Append { head: Hash, packs: HashSet<Hash> },
    /// A validated chain that one node replaces. `packs` lists every pack
    /// in it, oldest first. The new node has no predecessor and lists them
    /// all before the new packs, so it advertises a superset of the chain.
    Rollover { head: Hash, packs: Vec<Hash> },
    /// An authorized self-contained reset, including a broken-chain escape.
    /// `prior` is the live ref value, even though the new node has no predecessor.
    Reset { prior: Option<Hash> },
}

/// The most packs a rollover node lists (SPEC-TRANSPORT-CONNECT §7.4). A node of
/// this many packs is 131,080 bytes, far under the 1 MiB a reader downloads.
pub const ROLLOVER_MAX_PACKS: usize = 4096;

impl ChainState {
    /// The state for a validated chain of `depth` nodes that lists `packs`,
    /// oldest first, before a push adds `new` packs.
    ///
    /// The chain rolls over when the new node would make it deeper than
    /// `threshold` and one node can list every pack. A `threshold` of zero
    /// never rolls over. A chain that holds too many packs keeps appending.
    #[must_use]
    pub fn validated(
        head: Hash,
        depth: usize,
        packs: Vec<Hash>,
        new: usize,
        threshold: usize,
    ) -> Self {
        if threshold > 0
            && depth >= threshold
            && packs.len().saturating_add(new) <= ROLLOVER_MAX_PACKS
        {
            Self::Rollover { head, packs }
        } else {
            Self::Append {
                head,
                packs: packs.into_iter().collect(),
            }
        }
    }
}

/// A packmap ref move and the content-addressed node it advertises.
#[derive(Debug, PartialEq, Eq)]
pub struct Node {
    pub bytes: Vec<u8>,
    pub key: Hash,
    pub condition: RefWriteCondition,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PlanError {
    #[error(transparent)]
    Packlist(#[from] PackListError),
    #[error("packmap node exceeds byte limit")]
    NodeTooLarge,
}

/// Plan one attempt without I/O. `None` means only the head needs to move:
/// every new pack is already advertised by the validated chain. Otherwise,
/// upload the returned node before advancing its ref and the caller's head.
/// New packs retain their exact apply order, including partial overlaps.
///
/// A rollover lists the chain's packs, then each new pack the chain does not
/// hold, and CAS-es against the head it replaces. Resets always produce a
/// node and CAS against `prior`. `max_node_bytes = None` preserves drivers
/// without a separate node-size limit. The codec entry cap applies when encoding a node.
///
/// # Errors
/// Returns a codec error or [`PlanError::NodeTooLarge`].
pub fn plan_advance(
    state: ChainState,
    packs: &[Hash],
    max_node_bytes: Option<u64>,
) -> Result<Option<Node>, PlanError> {
    let rolled;
    let (prior, prev, packs) = match state {
        ChainState::Missing => (None, None, packs),
        ChainState::Append { head, packs: held } => {
            if packs.iter().all(|key| held.contains(key)) {
                return Ok(None);
            }
            drop(held);
            (Some(head), Some(head), packs)
        }
        ChainState::Rollover {
            head,
            packs: mut listed,
        } => {
            let held: HashSet<Hash> = listed.iter().copied().collect();
            if packs.iter().all(|key| held.contains(key)) {
                return Ok(None);
            }
            listed.extend(packs.iter().filter(|key| !held.contains(*key)));
            rolled = listed;
            (Some(head), None, rolled.as_slice())
        }
        ChainState::Reset { prior } => (prior, None, packs),
    };
    let bytes = encode_packlist(prev, packs)?;
    if max_node_bytes.is_some_and(|limit| bytes.len() as u64 > limit) {
        return Err(PlanError::NodeTooLarge);
    }
    Ok(Some(Node {
        key: pack_key(&bytes),
        bytes,
        condition: prior.map_or(RefWriteCondition::Missing, RefWriteCondition::Match),
    }))
}
