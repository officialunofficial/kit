//! The signature of a commit that an operation writes.
//!
//! The library never loads a key. The caller does, because the key can live
//! in a file, in a keystore or behind a prompt. An operation that writes a
//! commit asks the [`Signing`] of the caller for a [`Signer`] at the moment
//! it needs one. Then the operation builds the commit and gives it to the
//! signer. A failure to load a key therefore comes at the same point of the
//! operation as the failure of any other step.

use kit_core::hash::Hash;
use kit_core::layout::RepoLayout;
use kit_core::object::{Commit, Identity, KitError, Object};
use kit_core::serialize;
use kit_core::store::{ObjectStore, StoreError};

/// What went wrong with a key. The kind decides the exit code of a program.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorKind {
    /// A setting is wrong, or the configuration cannot be read.
    Config,
    /// The key does not exist.
    MissingInput,
    /// The key exists, but the program may not use it.
    Denied,
    /// The key backend is not available.
    Unavailable,
    /// The key, the signature or the data to sign is malformed.
    Data,
    /// The signature could not be made.
    Failed,
}

/// A failure to load a key, to read an identity or to sign.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct Error {
    kind: ErrorKind,
    message: String,
}

impl Error {
    /// A failure of `kind`, described by `message`. The message must not
    /// hold key material.
    #[must_use]
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    /// What went wrong.
    #[must_use]
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }
}

/// Opens the key that signs the commits of one operation.
pub trait Signing {
    /// Load the key of the repository at `layout`.
    ///
    /// # Errors
    /// [`Error`] when the key or its settings cannot be loaded.
    fn open(&self, layout: &RepoLayout) -> Result<Box<dyn Signer>, Error>;
}

/// A loaded key.
pub trait Signer {
    /// The Ed25519 public key.
    ///
    /// # Errors
    /// [`Error`] when the key has no usable public part.
    fn public_key(&self) -> Result<[u8; 32], Error>;

    /// The identity that a commit of this signer names as its author.
    ///
    /// # Errors
    /// [`Error`] when the configured identity is malformed.
    fn author(&self) -> Result<Identity, Error>;

    /// Sign `commit`. The signature field of `commit` is not part of the
    /// signed bytes.
    ///
    /// # Errors
    /// [`Error`] when the signature cannot be made.
    fn sign_commit(&mut self, commit: &Commit) -> Result<[u8; 64], Error>;
}

/// Who a new commit names as its author.
pub(crate) enum Author {
    /// The identity of the signer.
    Signer,
    /// An identity that the caller chose, such as the author of a replayed
    /// commit.
    Given(Identity),
}

/// Why a commit could not be written.
pub(crate) enum WriteError {
    Signing(Error),
    Serialize(KitError),
    Store(StoreError),
}

/// Build a commit, sign it and write it to the store.
pub(crate) fn write_signed(
    store: &ObjectStore,
    signer: &mut dyn Signer,
    tree: Hash,
    parents: Vec<Hash>,
    author: Author,
    message: Vec<u8>,
    timestamp: u64,
) -> Result<Hash, WriteError> {
    let public_key = signer.public_key().map_err(WriteError::Signing)?;
    let author = match author {
        Author::Signer => signer.author().map_err(WriteError::Signing)?,
        Author::Given(identity) => identity,
    };
    let mut commit = Commit::new_unannotated(
        tree, parents, author, public_key, message, timestamp, [0u8; 64],
    );
    commit.signature = signer.sign_commit(&commit).map_err(WriteError::Signing)?;
    let bytes = serialize::serialize(&Object::Commit(commit)).map_err(WriteError::Serialize)?;
    store.write(&bytes).map_err(WriteError::Store)
}
