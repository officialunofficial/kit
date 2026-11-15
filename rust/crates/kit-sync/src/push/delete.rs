//! `push --delete`: remove a remote branch or tag together with its chain
//! ref (SPEC-TRANSPORT §7.3).
//!
//! The head goes first, under `Match`, then its chain ref
//! (`refs/kit/packmap/<b>` or `refs/kit/tagmap/<t>`), under `Match` on the
//! value just read. A branch's lease is its tracking ref, as for a push. A tag
//! has no tracking ref, so its expected value is the one just read: the `Match`
//! still stops the delete from removing a value written in between.
//!
//! Once the head is gone the delete has happened. A crash before the chain
//! ref goes, or a lost CAS on it, leaves a chain ref without its head, which
//! a fetch reads as a stale listing and the next push of that name appends
//! to. A transport that deletes both refs in one transaction reports a moved
//! chain ref instead, with nothing deleted; the chain ref is read again and
//! the delete retried, at most [`PACKMAP_CAS_ATTEMPTS`] times.

use kit_core::hash::Hash;
use kit_core::layout::RepoLayout;
use kit_core::protocol::AdvanceOutcome;
use kit_core::refs::{self, BRANCH_REF_PREFIX, TAG_REF_PREFIX};

use super::packmap::PACKMAP_CAS_ATTEMPTS;
use super::{PushContext, PushError};
use crate::packmap::chain_ref;
use crate::{SourceError, SyncError};

/// What `push --delete` removes.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeleteTarget {
    /// `refs/heads/<b>`, under the lease of its tracking ref.
    Branch(String),
    /// `refs/tags/<t>`, under the value read just before.
    Tag(String),
    /// A short name: the remote's branch or tag of that name, whichever it
    /// holds. A name the remote holds as both is refused.
    Name(String),
}

/// A remote ref that `push --delete` removed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DeletedRef {
    /// The full name, `refs/heads/<b>` or `refs/tags/<t>`.
    pub name: String,
    /// The value removed, or `None` when the ref was already gone.
    pub value: Option<Hash>,
}

/// Why `push --delete` deleted nothing.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DeleteError {
    /// A branch delete needs the tracking ref as its lease.
    #[error(
        "there is no tracking ref for '{branch}' of '{remote}' to lease the delete on; fetch '{remote}' first"
    )]
    NoLease { remote: String, branch: String },
    /// The remote holds no ref of that name.
    #[error("the remote has no {0}")]
    NotOnRemote(String),
    /// The remote holds a branch and a tag of that name.
    #[error("the remote has both refs/heads/{0} and refs/tags/{0}; name the one to delete in full")]
    Ambiguous(String),
    /// The remote ref holds another value than the delete expected.
    #[error(
        "{0} on the remote is not at the value this delete expected, so nothing was deleted; fetch, then delete again"
    )]
    Stale(String),
    /// The chain ref kept moving under concurrent pushes.
    #[error("could not delete {0} under concurrent pushes, so nothing was deleted; retry")]
    Contended(String),
    /// The remote refused the delete, or it failed on the way.
    #[error("deleting `{name}` failed: {source}")]
    Failed {
        name: String,
        #[source]
        source: SourceError,
    },
}

/// Delete `target` on the remote, and the tracking ref of a deleted branch.
pub(super) fn delete(
    layout: &RepoLayout,
    tx: &PushContext<'_>,
    remote: &str,
    target: &DeleteTarget,
) -> Result<DeletedRef, PushError> {
    let head = match target {
        DeleteTarget::Branch(branch) => format!("{BRANCH_REF_PREFIX}{branch}"),
        DeleteTarget::Tag(tag) => format!("{TAG_REF_PREFIX}{tag}"),
        DeleteTarget::Name(name) => resolve(layout, tx, remote, name)?,
    };
    if !refs::validate_ref_name(&head) {
        return Err(SourceError::InvalidRef(head).into());
    }
    let branch = head.strip_prefix(BRANCH_REF_PREFIX);
    // A tag whose tag map name is no valid ref has no tag map (W3). It stays
    // deletable, alone.
    let map = chain_ref(&head).filter(|map| refs::validate_ref_name(map));
    let expected = match branch {
        Some(branch) => {
            refs::read_remote_ref(layout, remote, branch)?.ok_or_else(|| DeleteError::NoLease {
                remote: remote.to_owned(),
                branch: branch.to_owned(),
            })?
        }
        None => tx
            .read_ref(&head)?
            .ok_or_else(|| DeleteError::NotOnRemote(head.clone()))?,
    };
    for _ in 0..PACKMAP_CAS_ATTEMPTS {
        if tx.observer.cancelled() {
            return Err(SyncError::Interrupted.into());
        }
        let map_value = match &map {
            Some(map) => tx.read_ref(map)?,
            None => None,
        };
        let outcome = tx
            .delete_refs(
                &head,
                &expected,
                map.as_deref().unwrap_or_default(),
                map_value.as_ref(),
            )
            .map_err(|source| DeleteError::Failed {
                name: head.clone(),
                source,
            })?;
        let value = match outcome {
            AdvanceOutcome::Committed => Some(expected),
            // A retried delete that landed, or another writer's, leaves the
            // head absent: it is gone, as asked. Any other value is not the
            // one this delete may remove.
            AdvanceOutcome::HeadConflict if tx.read_ref(&head)?.is_none() => None,
            AdvanceOutcome::HeadConflict => return Err(DeleteError::Stale(head).into()),
            AdvanceOutcome::PackmapConflict => continue,
        };
        if let Some(branch) = branch {
            forget_tracking(layout, remote, branch)?;
        }
        return Ok(DeletedRef { name: head, value });
    }
    Err(DeleteError::Contended(head).into())
}

/// The full name of the remote ref `name` names: its branch or its tag. A
/// name the remote holds as neither is still a branch when a tracking ref
/// names it, so that the delete clears that tracking ref.
fn resolve(
    layout: &RepoLayout,
    tx: &PushContext<'_>,
    remote: &str,
    name: &str,
) -> Result<String, PushError> {
    let branch = format!("{BRANCH_REF_PREFIX}{name}");
    let tag = format!("{TAG_REF_PREFIX}{name}");
    for full in [&branch, &tag] {
        if !refs::validate_ref_name(full) {
            return Err(SourceError::InvalidRef(full.clone()).into());
        }
    }
    match (tx.read_ref(&branch)?, tx.read_ref(&tag)?) {
        (Some(_), Some(_)) => Err(DeleteError::Ambiguous(name.to_owned()).into()),
        (None, Some(_)) => Ok(tag),
        (Some(_), None) => Ok(branch),
        (None, None) if refs::read_remote_ref(layout, remote, name)?.is_some() => Ok(branch),
        (None, None) => Err(DeleteError::NotOnRemote(format!("branch or tag '{name}'")).into()),
    }
}

/// Remove the tracking ref of a deleted branch and its fetch record, as a
/// prune does.
fn forget_tracking(layout: &RepoLayout, remote: &str, branch: &str) -> Result<(), PushError> {
    match refs::delete_remote_ref(layout, remote, branch) {
        Ok(()) | Err(refs::RefError::NotFound(_)) => {}
        Err(error) => return Err(error.into()),
    }
    let _ = std::fs::remove_file(crate::anchor::path(layout, remote, branch));
    Ok(())
}
