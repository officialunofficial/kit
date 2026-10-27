//! The error type of the library.

use crate::{attest_signer, blame, branch, diff, head, lock, log, repo, revspec, worktrees};
#[cfg(feature = "sync")]
use crate::{conflict, merge, rebase};

/// An error from any library operation.
///
/// Each variant wraps the error enum of one module. A caller matches on the
/// variant to find the module, then on the inner value to find the cause.
/// `Display` and `source` forward to the inner error, so a chain walk shows
/// each cause once.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A repository could not be opened or discovered.
    #[error(transparent)]
    Repo(#[from] repo::Error),
    /// A revision could not be resolved.
    #[error(transparent)]
    Revspec(#[from] revspec::Error),
    /// A repository lock could not be taken.
    #[error(transparent)]
    Lock(#[from] lock::Error),
    /// HEAD could not be moved.
    #[error(transparent)]
    Head(#[from] head::Error),
    /// The trees of the repository could not be read.
    #[error(transparent)]
    Worktrees(#[from] worktrees::Error),
    /// The history could not be walked.
    #[error(transparent)]
    Log(#[from] log::Error),
    /// A diff could not be computed.
    #[error(transparent)]
    Diff(#[from] diff::Error),
    /// A file could not be blamed.
    #[error(transparent)]
    Blame(#[from] blame::Error),
    /// A branch could not be created, deleted, renamed or listed.
    #[error(transparent)]
    Branch(#[from] branch::Error),
    /// A linked tree could not be added, listed, removed or pruned.
    #[cfg(feature = "sync")]
    #[cfg_attr(docsrs, doc(cfg(feature = "sync")))]
    #[error(transparent)]
    Linked(#[from] crate::linked::Error),
    /// Tracked paths could not be moved.
    #[cfg(feature = "sync")]
    #[cfg_attr(docsrs, doc(cfg(feature = "sync")))]
    #[error(transparent)]
    Mv(#[from] crate::mv::Error),
    /// The state of the tree could not be read.
    #[cfg(feature = "sync")]
    #[cfg_attr(docsrs, doc(cfg(feature = "sync")))]
    #[error(transparent)]
    Status(#[from] crate::status::Error),
    /// Files could not be staged.
    #[cfg(feature = "sync")]
    #[cfg_attr(docsrs, doc(cfg(feature = "sync")))]
    #[error(transparent)]
    Add(#[from] crate::add::Error),
    /// A signing key could not be loaded or could not sign.
    #[error(transparent)]
    Signer(#[from] crate::signer::Error),
    /// A commit could not be made.
    #[cfg(feature = "sync")]
    #[cfg_attr(docsrs, doc(cfg(feature = "sync")))]
    #[error(transparent)]
    Commit(#[from] crate::commit::Error),
    /// A conflict could not be written, checked or undone.
    #[cfg(feature = "sync")]
    #[error(transparent)]
    Conflict(#[from] conflict::Error),
    /// A merge could not be run.
    #[cfg(feature = "sync")]
    #[error(transparent)]
    Merge(#[from] merge::Error),
    /// A rebase could not be run.
    #[cfg(feature = "sync")]
    #[error(transparent)]
    Rebase(#[from] rebase::Error),
    /// A signer of an attestation could not be built.
    #[error(transparent)]
    AttestSigner(#[from] attest_signer::Error),
}
