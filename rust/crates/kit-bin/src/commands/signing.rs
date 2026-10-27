//! The key that signs the commits of `merge` and `rebase`.
//!
//! The library asks for a [`Signer`] when it is about to write a commit. This
//! module loads the key from the configuration, the same way `kit commit`
//! does, and gives it to the library.

use kit_core::layout::RepoLayout;
use kit_core::object::{Commit, Identity};
use libkit::signing::{Error, ErrorKind, Signer, Signing};

use super::commit::{CommitSigner, load_commit_signer, resolve_author};
use crate::config;
use crate::exit;

/// Loads the signer that the configuration names.
#[derive(Debug)]
pub struct Configured;

impl Signing for Configured {
    fn open(&self, layout: &RepoLayout) -> Result<Box<dyn Signer>, Error> {
        let cfg = config::read_or_default(layout)
            .map_err(|e| Error::new(ErrorKind::Config, format!("config: {e}")))?;
        let signer = load_commit_signer(layout, &cfg).map_err(failure)?;
        Ok(Box::new(Loaded {
            signer,
            user_identity: cfg.user_identity,
        }))
    }
}

struct Loaded {
    signer: CommitSigner,
    user_identity: String,
}

impl Signer for Loaded {
    fn public_key(&self) -> Result<[u8; 32], Error> {
        self.signer.public_key().map_err(failure)
    }

    fn author(&self) -> Result<Identity, Error> {
        let public = self.public_key()?;
        resolve_author(None, &self.user_identity, &public)
            .map_err(|e| Error::new(ErrorKind::Config, format!("author: {e}")))
    }

    fn sign_commit(&mut self, commit: &Commit) -> Result<[u8; 64], Error> {
        self.signer.sign_commit(commit).map_err(failure)
    }
}

/// Turn a message and an exit code of the signer into a library error.
fn failure((message, code): (String, u8)) -> Error {
    let kind = match code {
        exit::CONFIG_ERROR => ErrorKind::Config,
        exit::NOINPUT => ErrorKind::MissingInput,
        exit::NOPERM => ErrorKind::Denied,
        exit::UNAVAILABLE => ErrorKind::Unavailable,
        exit::DATAERR => ErrorKind::Data,
        _ => ErrorKind::Failed,
    };
    Error::new(kind, message)
}
