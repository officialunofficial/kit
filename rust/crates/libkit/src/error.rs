//! The error type of the library.

use crate::repo;

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
}
