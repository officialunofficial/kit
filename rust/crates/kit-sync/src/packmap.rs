//! Walking the pack chain of a branch or a tag.
//!
//! A branch's transfer history is a content-addressed singly-linked list of
//! packlist nodes, advertised through the `refs/kit/packmap/<branch>`
//! metadata ref. Each push appends one node (a `prev` pointer plus the packs
//! it added); a fetch walks the chain oldest-first so every delta's base is
//! already in the store when its pack is unpacked. A tag's chain is the same
//! list under `refs/kit/tagmap/<tag>`, and its oldest nodes may be those of a
//! branch chain. Every walker takes the full head ref (`refs/heads/<b>` or
//! `refs/tags/<t>`), which it also sends as the download hint.

use kit_core::hash::Hash;
use kit_core::protocol::PackKey;
use kit_core::refs::{BRANCH_REF_PREFIX, PACKMAP_REF_PREFIX, TAG_REF_PREFIX, TAGMAP_REF_PREFIX};
use kit_core::transfer;

use crate::error::SyncError;
use crate::observer::{Observer, SyncEvent};
use crate::source::RemoteSource;

/// Ref under which a branch's transfer packlist key is advertised. The value
/// is the BLAKE3 of the packlist chain head, an auxiliary content-addressed
/// blob (not a packfile). It lives in the `refs/kit/` metadata namespace so
/// it never collides with real heads or tags. See [`kit_core::transfer`].
#[must_use]
pub fn packmap_ref(branch: &str) -> String {
    format!("{PACKMAP_REF_PREFIX}{branch}")
}

/// The chain ref of a head ref: `refs/heads/<b>` has `refs/kit/packmap/<b>`
/// and `refs/tags/<t>` has `refs/kit/tagmap/<t>`. `None` for any other name.
#[must_use]
pub fn chain_ref(head_ref: &str) -> Option<String> {
    if let Some(branch) = head_ref.strip_prefix(BRANCH_REF_PREFIX) {
        Some(format!("{PACKMAP_REF_PREFIX}{branch}"))
    } else {
        head_ref
            .strip_prefix(TAG_REF_PREFIX)
            .map(|tag| format!("{TAGMAP_REF_PREFIX}{tag}"))
    }
}

/// The full head ref of a push caller's branch, which may be a short branch
/// name or its full ref name.
pub(crate) fn branch_head_ref(branch: &str) -> String {
    format!(
        "{BRANCH_REF_PREFIX}{}",
        branch.strip_prefix(BRANCH_REF_PREFIX).unwrap_or(branch)
    )
}

/// How an error names the ref of a chain: a branch by its short name, any
/// other head by its full ref.
pub(crate) fn chain_label(head_ref: &str) -> &str {
    head_ref.strip_prefix(BRANCH_REF_PREFIX).unwrap_or(head_ref)
}

/// Hard cap on packmap **chain length** (number of linked nodes), distinct
/// from [`transfer::PACKLIST_MAX_ENTRIES`], which caps the packs recorded in
/// a single node.
///
/// A `prev`-linked chain is attacker-influenced: a malicious or corrupt
/// remote can advertise an arbitrarily long (or cyclic) chain to make the
/// fetcher walk forever issuing one blob download per node. The walk is
/// bounded so such a remote surfaces as [`SyncError::PackChainInvalid`]
/// instead of hanging. (A cycle is already caught by the `seen` set; this
/// bound additionally caps an acyclic but pathologically long chain.)
pub(crate) const MAX_PACK_CHAIN_DEPTH: usize = 100_000;

/// Bounds retained chain metadata across all nodes, not only
/// within one packlist. At most one million pack keys plus one hundred
/// thousand nodes.
pub(crate) const MAX_FETCH_PACKS: usize = 1_000_000;

/// Download and decode one packlist node by key. Packlist nodes are
/// auxiliary transfer metadata, not packfiles, so they travel over the
/// blob verb, with the head ref as the hint.
pub(crate) fn download_packlist_node(
    source: &dyn RemoteSource,
    key: Hash,
    ref_name: &str,
) -> Result<transfer::PackListNode, SyncError> {
    let requested = PackKey::from_hash(key);
    let bytes = source.download_blob_via_ref(&requested, ref_name)?;
    requested
        .verify_bytes(&bytes)
        .map_err(crate::SourceError::from)?;
    Ok(transfer::decode_packlist(&bytes)?)
}

/// Walk the packlist chain of `head_ref` from `head_key` (newest node)
/// following `prev` pointers, applying the shared cycle and runaway-depth
/// guard, and return every node visited in newest-to-oldest order.
///
/// This is the one place the chain walk is written. It walks the WHOLE chain,
/// so it doubles as the push-side integrity check: a node the chain
/// references but the remote cannot deliver or decode, a cycle, or an
/// over-deep chain all surface as [`SyncError::PackChainInvalid`]. A
/// transient transport error propagates unchanged so it is never mistaken for
/// corruption.
pub fn walk_pack_chain(
    source: &dyn RemoteSource,
    observer: &dyn Observer<SyncEvent>,
    head_ref: &str,
    head_key: Hash,
) -> Result<Vec<transfer::PackListNode>, SyncError> {
    Ok(walk_pack_chain_until(source, observer, head_ref, head_key, &|_| false)?.nodes)
}

/// What [`walk_pack_chain_until`] walked.
pub(crate) struct ChainWalk {
    /// The nodes it downloaded, newest first.
    pub(crate) nodes: Vec<transfer::PackListNode>,
    /// The key of each node in `nodes`, in the same order.
    pub(crate) keys: Vec<Hash>,
    /// Whether the walk ended at a node `stop` accepted, which it did not
    /// download.
    pub(crate) stopped: bool,
}

/// Walk the chain of `head_ref` as [`walk_pack_chain`] does, but stop before
/// downloading a node `stop` accepts: an immutable node whose chain is already
/// applied, such as a checkpoint's head. A walk that meets no such node
/// returns the full chain.
pub(crate) fn walk_pack_chain_until(
    source: &dyn RemoteSource,
    observer: &dyn Observer<SyncEvent>,
    head_ref: &str,
    head_key: Hash,
    stop: &dyn Fn(&Hash) -> bool,
) -> Result<ChainWalk, SyncError> {
    let label = chain_label(head_ref);
    let invalid = || SyncError::PackChainInvalid {
        branch: label.to_owned(),
        source: None,
    };
    let mut nodes = Vec::new();
    let mut keys = Vec::new();
    let mut pack_count = 0usize;
    let mut seen = std::collections::HashSet::new();
    let mut cursor = Some(head_key);
    while let Some(key) = cursor {
        if observer.cancelled() {
            return Err(SyncError::Interrupted);
        }
        if stop(&key) {
            return Ok(ChainWalk {
                nodes,
                keys,
                stopped: true,
            });
        }
        // Cycle / runaway-depth guard.
        if !seen.insert(key) || seen.len() > MAX_PACK_CHAIN_DEPTH {
            return Err(invalid());
        }
        let node = match download_packlist_node(source, key, head_ref) {
            Ok(n) => n,
            // A referenced-but-undeliverable / undecodable node = broken
            // chain (distinct from a transient transport error).
            Err(SyncError::Source(error))
                if error.is_not_found() || error.is_invalid_response() =>
            {
                return Err(SyncError::PackChainInvalid {
                    branch: label.to_owned(),
                    source: Some(error),
                });
            }
            Err(SyncError::PackList(_)) => return Err(invalid()),
            Err(e) => return Err(e),
        };
        pack_count = pack_count
            .checked_add(node.packs.len())
            .ok_or_else(invalid)?;
        if pack_count > MAX_FETCH_PACKS {
            return Err(invalid());
        }
        cursor = node.prev;
        nodes.push(node);
        keys.push(key);
    }
    Ok(ChainWalk {
        nodes,
        keys,
        stopped: false,
    })
}

/// Flatten nodes returned by [`walk_pack_chain`] into the pack keys in
/// **oldest-first** order, the order a fetcher must unpack so each delta's
/// base is already present.
#[must_use]
pub fn flatten_oldest_first(mut nodes: Vec<transfer::PackListNode>) -> Vec<Hash> {
    nodes.reverse();
    nodes.into_iter().flat_map(|n| n.packs).collect()
}

/// Walk the packlist chain of `head_ref` from `head_key` and return the flat
/// oldest-first list of pack keys it references.
pub fn resolve_pack_chain(
    source: &dyn RemoteSource,
    observer: &dyn Observer<SyncEvent>,
    head_ref: &str,
    head_key: Hash,
) -> Result<Vec<Hash>, SyncError> {
    Ok(flatten_oldest_first(walk_pack_chain(
        source, observer, head_ref, head_key,
    )?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_ref_pairs_heads_with_packmaps_and_tags_with_tagmaps() {
        assert_eq!(
            chain_ref("refs/heads/a/b").as_deref(),
            Some("refs/kit/packmap/a/b")
        );
        assert_eq!(
            chain_ref("refs/tags/v1.0").as_deref(),
            Some("refs/kit/tagmap/v1.0")
        );
        assert_eq!(chain_ref("refs/kit/packmap/main"), None);
        assert_eq!(chain_ref("main"), None);
        assert_eq!(branch_head_ref("main"), "refs/heads/main");
        assert_eq!(branch_head_ref("refs/heads/main"), "refs/heads/main");
        assert_eq!(chain_label("refs/heads/main"), "main");
        assert_eq!(chain_label("refs/tags/v1"), "refs/tags/v1");
    }
}
