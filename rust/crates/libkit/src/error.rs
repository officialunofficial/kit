//! The error type of the library.

use crate::{diff, head, lock, log, repo, revspec, worktrees};

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
}
