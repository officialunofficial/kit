//! The key that signs commits and tags.
//!
//! [`load`] opens the key that the config names. The `signer` setting picks a
//! file key or a keystore key. [`Signer`] signs a commit or a tag under the
//! domain of that object, whichever way the key is kept.
//!
//! A missing key is an error. The operation never makes a key. A key made on
//! the way could replace the identity of the user after an interrupted write,
//! and a wrong key path would hide behind it. A user makes the key once with
//! `kit keygen`.

use std::path::PathBuf;

use kit_core::layout::RepoLayout;
use kit_core::object::{Commit, Tag};
use kit_core::sign::{self, KeyPair};
use kit_keystore::{KeyRef, KeySelector, KeySigner, open_backend};

use crate::Environment;
use crate::config::{Config, ConfigError};

/// Errors from loading a key or from signing.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The key path of the config is not allowed.
    #[error("{0}")]
    KeyPath(ConfigError),
    /// The key file does not exist.
    #[error("no signing key at {} — run `kit keygen` to create one", .0.display())]
    NoKeyFile(PathBuf),
    /// The key file cannot be loaded.
    #[error("load key: {0}")]
    LoadKey(kit_core::KitError),
    /// The `signer` setting is not `file` or `keystore`.
    #[error("unknown signer `{0}` — expected `file` or `keystore`")]
    UnknownSigner(String),
    /// The `key.ed25519_ref` setting is not a key reference.
    #[error("key.ed25519_ref: {0}")]
    KeyRef(kit_keystore::Error),
    /// The keystore backend cannot be opened.
    #[error("keystore backend: {0}")]
    Backend(kit_keystore::Error),
    /// The backend cannot open keys.
    #[error("keystore backend `{0}` does not support opening keys")]
    CannotOpen(String),
    /// The keystore has no key under the label.
    #[error(
        "missing keystore signing key for algorithm ed25519 — run `kit key generate --backend {backend} --algorithm ed25519 --label <label>` first, or set `signer = file` and use `kit keygen`: {source}"
    )]
    MissingKey {
        /// The backend of the key reference.
        backend: String,
        /// The error of the backend.
        source: kit_keystore::Error,
    },
    /// The key cannot be opened.
    #[error("keystore signing key for algorithm ed25519: {0}")]
    OpenKey(kit_keystore::Error),
    /// The public key cannot be read from the keystore.
    #[error("keystore public key: {0}")]
    PublicKey(kit_keystore::Error),
    /// The public key has the wrong length.
    #[error("keystore Ed25519 public key must be 32 bytes, got {0}")]
    PublicKeyLength(usize),
    /// The signing hash of a commit cannot be made.
    #[error("commit signing hash: {0}")]
    CommitHash(kit_core::KitError),
    /// The signing hash of a tag cannot be made.
    #[error("tag signing hash: {0}")]
    TagHash(kit_core::KitError),
    /// A file key cannot sign the object.
    #[error("sign: {0}")]
    Sign(kit_core::KitError),
    /// The keystore cannot sign.
    #[error("keystore sign: {0}")]
    KeystoreSign(kit_keystore::Error),
    /// The signature has the wrong length.
    #[error("keystore Ed25519 signature must be 64 bytes, got {0}")]
    SignatureLength(usize),
}

/// A key that signs commits and tags.
pub enum Signer {
    /// A key pair in a file.
    File(KeyPair),
    /// A key in a keystore. The secret does not leave the keystore.
    Keystore(Box<dyn KeySigner>),
}

impl std::fmt::Debug for Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The debug form names the kind and never shows a key.
        match self {
            Self::File(_) => f.write_str("Signer::File(..)"),
            Self::Keystore(_) => f.write_str("Signer::Keystore(..)"),
        }
    }
}

/// Open the key that `config` names.
///
/// # Errors
/// [`Error`], with one variant for each failed step.
pub fn load(
    layout: &RepoLayout,
    environment: &Environment,
    config: &Config,
) -> Result<Signer, Error> {
    match config.signer.as_str() {
        "" | "file" => load_file(layout, environment, &config.signing_key).map(Signer::File),
        "keystore" => load_keystore(config),
        other => Err(Error::UnknownSigner(other.to_owned())),
    }
}

fn load_file(
    layout: &RepoLayout,
    environment: &Environment,
    signing_key: &str,
) -> Result<KeyPair, Error> {
    let key_path = crate::config::resolve_key_path(layout, environment, signing_key)
        .map_err(Error::KeyPath)?;
    if !key_path.exists() {
        return Err(Error::NoKeyFile(key_path));
    }
    sign::load_key(&key_path).map_err(Error::LoadKey)
}

fn load_keystore(config: &Config) -> Result<Signer, Error> {
    let key_ref = config
        .key
        .ed25519_ref_or_fallback()
        .parse::<KeyRef>()
        .map_err(Error::KeyRef)?;
    let store = open_backend(key_ref.backend()).map_err(Error::Backend)?;
    let selector = KeySelector::new(
        key_ref.label().to_owned(),
        Some(kit_keystore::Algorithm::Ed25519),
    )
    .map_err(Error::KeyRef)?;
    let opener = store
        .opener()
        .ok_or_else(|| Error::CannotOpen(key_ref.backend().to_string()))?;
    let signer = opener.open(&selector).map_err(|error| match error {
        kit_keystore::Error::KeyNotFound(_) => Error::MissingKey {
            backend: key_ref.backend().to_string(),
            source: error,
        },
        other => Error::OpenKey(other),
    })?;
    Ok(Signer::Keystore(signer))
}

impl Signer {
    /// The Ed25519 public key.
    ///
    /// # Errors
    /// [`Error::PublicKey`] or [`Error::PublicKeyLength`] for a keystore key.
    pub fn public_key(&self) -> Result<[u8; 32], Error> {
        match self {
            Self::File(kp) => Ok(kp.public.0),
            Self::Keystore(signer) => {
                let public = signer.public_key().map_err(Error::PublicKey)?;
                public
                    .as_bytes()
                    .try_into()
                    .map_err(|_| Error::PublicKeyLength(public.len()))
            }
        }
    }

    /// Sign a [`Tag`] under the domain of tags.
    ///
    /// # Errors
    /// [`Error`] when the hash, the signature or its length fails.
    pub fn sign_tag(&mut self, tag: &Tag) -> Result<[u8; 64], Error> {
        match self {
            Self::File(kp) => sign::sign_tag(tag, kp)
                .map(|signature| signature.0)
                .map_err(Error::Sign),
            Self::Keystore(signer) => {
                let digest = sign::tag_signing_hash(tag).map_err(Error::TagHash)?;
                keystore_signature(signer.as_mut(), &digest)
            }
        }
    }

    /// Sign a [`Commit`] under the domain of commits.
    ///
    /// # Errors
    /// [`Error`] when the hash, the signature or its length fails.
    pub fn sign_commit(&mut self, commit: &Commit) -> Result<[u8; 64], Error> {
        match self {
            Self::File(kp) => sign::sign_commit(commit, kp)
                .map(|signature| signature.0)
                .map_err(Error::Sign),
            Self::Keystore(signer) => {
                let digest = sign::commit_signing_hash(commit).map_err(Error::CommitHash)?;
                keystore_signature(signer.as_mut(), &digest)
            }
        }
    }
}

fn keystore_signature(signer: &mut dyn KeySigner, digest: &[u8; 32]) -> Result<[u8; 64], Error> {
    let signature = signer.sign(digest).map_err(Error::KeystoreSign)?;
    signature
        .try_into()
        .map_err(|signature: Vec<u8>| Error::SignatureLength(signature.len()))
}

#[cfg(test)]
mod tests {
    use kit_core::object::Identity;
    use kit_keystore::Keystore;

    use super::*;

    #[test]
    fn the_debug_form_does_not_show_a_key() {
        let signer = Signer::File(KeyPair::from_seed([7; 32]));
        assert_eq!(format!("{signer:?}"), "Signer::File(..)");
    }

    #[test]
    fn a_keystore_signature_matches_the_signature_of_a_file_key() {
        let seed = [0x5a; 32];
        let kp = KeyPair::from_seed(seed);
        let store_root = tempfile::tempdir().unwrap();
        let store = kit_keystore::SoftwareRawKeystore::with_root(store_root.path().join("keys"));
        store
            .importer()
            .unwrap()
            .import(
                &kit_keystore::KeyLabel::new("committer").unwrap(),
                kit_keystore::SecretKey::new(kit_keystore::Algorithm::Ed25519, seed),
                kit_keystore::KeyAttrs::default(),
                kit_keystore::ImportOptions::default(),
            )
            .unwrap();
        let selector =
            KeySelector::new("committer", Some(kit_keystore::Algorithm::Ed25519)).unwrap();
        let mut signer = Signer::Keystore(store.opener().unwrap().open(&selector).unwrap());
        let public = signer.public_key().unwrap();
        assert_eq!(public, kp.public.0);
        let commit = Commit::new_unannotated(
            [1; 32],
            vec![[2; 32]],
            Identity::ed25519(public),
            public,
            b"same commit".to_vec(),
            123,
            [0; 64],
        );

        let keystore_signature = signer.sign_commit(&commit).unwrap();
        let file_signature = sign::sign_commit(&commit, &kp).unwrap().0;
        assert_eq!(keystore_signature, file_signature);
    }

    #[test]
    fn an_unknown_signer_is_refused_before_any_key_is_read() {
        let dir = tempfile::tempdir().unwrap();
        let layout = RepoLayout::single(dir.path());
        let environment = Environment::default();
        let config = Config {
            signer: "cloud".to_owned(),
            ..Config::default()
        };
        let error = load(&layout, &environment, &config).unwrap_err();
        assert!(
            matches!(error, Error::UnknownSigner(ref s) if s == "cloud"),
            "{error:?}"
        );
        assert_eq!(
            error.to_string(),
            "unknown signer `cloud` — expected `file` or `keystore`"
        );
    }

    #[test]
    fn a_missing_key_file_is_an_error_and_the_library_makes_no_key() {
        let dir = tempfile::tempdir().unwrap();
        let layout = RepoLayout::single(dir.path());
        let environment = Environment::default();
        let config = Config {
            signing_key: crate::config::DEFAULT_SIGNING_KEY.to_owned(),
            ..Config::default()
        };
        let error = load(&layout, &environment, &config).unwrap_err();
        assert!(matches!(error, Error::NoKeyFile(_)), "{error:?}");
        assert!(
            error
                .to_string()
                .ends_with("run `kit keygen` to create one")
        );
        assert!(!dir.path().join(".kit").exists());
    }
}
