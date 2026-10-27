//! Signers for attestations.
//!
//! [`build`] turns an algorithm, a signer [`Kind`] and a [`Config`] into a
//! [`Signer`]. One function holds the mapping from algorithm to signer, so
//! one place needs an audit.
//!
//! Key material layout on disk, per `docs/specs/SPEC-ATTESTATIONS.md` §6.1:
//!
//! - Ed25519: the path in `signing_key`, which is `.kit/keys/default.key`
//!   by default. The commit signer shares it.
//! - secp256k1 and p256: the path in `attest.secp256k1_key_path` or
//!   `attest.p256_key_path`. Only the user config can set them. The default
//!   is `.kit/keys/<algorithm>.key`. The file holds a raw 32-byte secret.
//!
//! No function here creates a key. A missing key is an error that names the
//! command that creates it. A config value must never make a command write
//! a key file at a path that the config chose.
//!
//! The `external` kind handles all three algorithms through one
//! subprocess. The `keystore` kind opens the key that `key.*_ref` names.

use std::str::FromStr;

use kit_attest::{Algorithm, ExternalSigner, Signer};
use kit_core::layout::RepoLayout;
use kit_keystore::{KeyRef, KeySelector, open_backend};
use zeroize::Zeroizing;

use crate::Environment;
use crate::config::{self, AttestConfig, Config};

/// Errors from building a signer.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The algorithm name is not `ed25519`, `secp256k1` or `p256`.
    #[error("unknown algorithm '{0}' — expected one of: ed25519, secp256k1, p256")]
    UnknownAlgorithm(String),
    /// The signer kind is not `repo-key`, `external` or `keystore`.
    #[error("unknown signer '{0}' — expected one of: repo-key, external, keystore")]
    UnknownSignerKind(String),
    /// The key file of the algorithm does not exist.
    #[error(
        "{algorithm} key file not found at '{path}' — run `kit keygen --algorithm {algorithm}` first"
    )]
    MissingKeyFile {
        /// The algorithm that needs the key.
        algorithm: Algorithm,
        /// The path that was checked.
        path: String,
    },
    /// The selected keystore key does not exist.
    #[error(
        "missing keystore signing key for algorithm {algorithm} — run `kit key generate --backend {backend} --algorithm {algorithm} --label <label>` first: {reason}"
    )]
    MissingKeystoreKey {
        /// The algorithm that needs the key.
        algorithm: Algorithm,
        /// The backend that was searched.
        backend: String,
        /// Why the keystore reported no key.
        reason: String,
    },
    /// The key file exists but is not a usable key.
    #[error("invalid key file '{path}': {reason}")]
    InvalidKeyFile {
        /// The path of the key file.
        path: String,
        /// Why the key file is not usable.
        reason: String,
    },
    /// `attest.external_signer_path` is empty, relative or unusable.
    #[error("attest.external_signer_path: {0}")]
    ExternalSignerPath(String),
    /// The signer itself failed to start.
    #[error("signer: {0}")]
    Signer(String),
    /// The keystore failed.
    #[error("keystore: {0}")]
    Keystore(String),
}

/// Where the secret of a signer lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A key file in the repository.
    RepoKey,
    /// An external signer program.
    External,
    /// A key in a keystore backend.
    Keystore,
}

impl Kind {
    /// The name of the kind in config and on the command line.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RepoKey => "repo-key",
            Self::External => "external",
            Self::Keystore => "keystore",
        }
    }
}

impl FromStr for Kind {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        match s {
            "repo-key" => Ok(Self::RepoKey),
            "external" => Ok(Self::External),
            "keystore" => Ok(Self::Keystore),
            other => Err(Error::UnknownSignerKind(other.to_owned())),
        }
    }
}

/// Parse `ed25519`, `secp256k1` or `p256` into an [`Algorithm`].
///
/// # Errors
/// [`Error::UnknownAlgorithm`] for any other text.
pub fn parse_algorithm(s: &str) -> Result<Algorithm, Error> {
    s.parse::<Algorithm>()
        .map_err(|_| Error::UnknownAlgorithm(s.to_owned()))
}

/// Build a signer that is ready to sign PAE bytes.
///
/// `layout` locates the key files. `environment` resolves a relative key
/// path. `config` is the merged config.
///
/// # Errors
/// - [`Error::MissingKeyFile`] and [`Error::MissingKeystoreKey`] when the
///   key does not exist.
/// - [`Error::InvalidKeyFile`] when the key path is refused or the file is
///   not a 32-byte secret.
/// - [`Error::ExternalSignerPath`] when the external signer is unusable.
/// - [`Error::Signer`] and [`Error::Keystore`] for a failure of the signer
///   or the keystore.
pub fn build(
    layout: &RepoLayout,
    environment: &Environment,
    algorithm: Algorithm,
    kind: Kind,
    config: &Config,
) -> Result<Box<dyn Signer>, Error> {
    match kind {
        Kind::RepoKey => build_repo_key(layout, environment, algorithm, config),
        Kind::External => build_external(algorithm, &config.attest),
        Kind::Keystore => build_keystore(algorithm, config),
    }
}

fn build_keystore(algorithm: Algorithm, config: &Config) -> Result<Box<dyn Signer>, Error> {
    let key_ref = configured_key_ref(config, algorithm)
        .parse::<KeyRef>()
        .map_err(|error| Error::Keystore(format!("key ref: {error}")))?;
    let store =
        open_backend(key_ref.backend()).map_err(|error| Error::Keystore(error.to_string()))?;
    let backend = key_ref.backend().to_string();
    let selector = KeySelector::new(
        key_ref.label().to_owned(),
        Some(to_keystore_algorithm(algorithm)),
    )
    .map_err(|error| Error::Keystore(error.to_string()))?;
    let opener = store
        .opener()
        .ok_or_else(|| Error::Keystore(format!("backend {backend} cannot open keys")))?;
    let signer = opener.open(&selector).map_err(|error| match error {
        kit_keystore::Error::KeyNotFound(_) => Error::MissingKeystoreKey {
            algorithm,
            backend,
            reason: error.to_string(),
        },
        other => Error::Keystore(other.to_string()),
    })?;
    Ok(Box::new(KeystoreSigner { algorithm, signer }))
}

fn configured_key_ref(config: &Config, algorithm: Algorithm) -> &str {
    match algorithm {
        Algorithm::Ed25519 => config.key.ed25519_ref_or_fallback(),
        Algorithm::Secp256k1 => config.key.secp256k1_ref_or_fallback(),
        Algorithm::P256 => config.key.p256_ref_or_fallback(),
    }
}

fn to_keystore_algorithm(algorithm: Algorithm) -> kit_keystore::Algorithm {
    match algorithm {
        Algorithm::Ed25519 => kit_keystore::Algorithm::Ed25519,
        Algorithm::Secp256k1 => kit_keystore::Algorithm::Secp256k1,
        Algorithm::P256 => kit_keystore::Algorithm::P256,
    }
}

/// A keystore key that signs attestations.
struct KeystoreSigner {
    algorithm: Algorithm,
    signer: Box<dyn kit_keystore::KeySigner>,
}

impl std::fmt::Debug for KeystoreSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeystoreSigner")
            .field("algorithm", &self.algorithm)
            .field("signer", &"<keystore>")
            .finish()
    }
}

impl Signer for KeystoreSigner {
    fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    fn keyid(&self) -> Result<String, kit_attest::Error> {
        self.signer
            .keyid()
            .map(kit_keystore::KeyId::into_string)
            .map_err(|error| kit_attest::Error::ExternalSignerBadResponse(error.to_string()))
    }

    fn sign(&mut self, pae: &[u8]) -> Result<Vec<u8>, kit_attest::Error> {
        self.signer
            .sign(pae)
            .map_err(|error| kit_attest::Error::ExternalSignerBadResponse(error.to_string()))
    }
}

fn build_repo_key(
    layout: &RepoLayout,
    environment: &Environment,
    algorithm: Algorithm,
    config: &Config,
) -> Result<Box<dyn Signer>, Error> {
    match algorithm {
        Algorithm::Ed25519 => {
            let rel = config.signing_key.as_str();
            let path = config::resolve_key_path(layout, environment, rel).map_err(|e| {
                Error::InvalidKeyFile {
                    path: rel.to_owned(),
                    reason: e.to_string(),
                }
            })?;
            if !path.exists() {
                return Err(Error::MissingKeyFile {
                    algorithm,
                    path: path.display().to_string(),
                });
            }
            let key = kit_core::sign::load_key(&path).map_err(|e| Error::InvalidKeyFile {
                path: path.display().to_string(),
                reason: e.to_string(),
            })?;
            Ok(Box::new(kit_attest::RepoKeySigner::new(key)))
        }
        Algorithm::Secp256k1 => {
            let rel = config.attest.secp256k1_key_path_or_default();
            let secret = load_raw_secret(layout, environment, rel, algorithm)?;
            let signer = kit_attest::signer_k256::Secp256k1Signer::from_seed_zeroizing(&secret)
                .map_err(|e| Error::Signer(e.to_string()))?;
            Ok(Box::new(signer))
        }
        Algorithm::P256 => {
            let rel = config.attest.p256_key_path_or_default();
            let secret = load_raw_secret(layout, environment, rel, algorithm)?;
            let signer = kit_attest::signer_p256::P256Signer::from_seed_zeroizing(&secret)
                .map_err(|e| Error::Signer(e.to_string()))?;
            Ok(Box::new(signer))
        }
    }
}

fn build_external(algorithm: Algorithm, config: &AttestConfig) -> Result<Box<dyn Signer>, Error> {
    if config.external_signer_path.is_empty() {
        return Err(Error::ExternalSignerPath(
            "empty — set `attest.external_signer_path` in user-scoped \
             config ($XDG_CONFIG_HOME/kit/config). Per-repo .kit/config \
             cannot set this key (security)."
                .into(),
        ));
    }
    let mut signer = ExternalSigner::with_algorithm(&config.external_signer_path, algorithm)
        .map_err(|e| Error::ExternalSignerPath(e.to_string()))?
        .with_args(config.external_signer_args.clone());
    // Without a user-scoped timeout, the crate default stays in effect. A
    // value of 0 means fail fast: the deadline has passed already.
    if let Some(secs) = config.external_signer_timeout_secs {
        signer = signer.with_timeout(std::time::Duration::from_secs(secs));
    }
    Ok(Box::new(signer))
}

fn load_raw_secret(
    layout: &RepoLayout,
    environment: &Environment,
    rel_path: &str,
    algorithm: Algorithm,
) -> Result<Zeroizing<[u8; 32]>, Error> {
    let path = config::resolve_key_path(layout, environment, rel_path).map_err(|e| {
        Error::InvalidKeyFile {
            path: rel_path.to_owned(),
            reason: e.to_string(),
        }
    })?;
    if !path.exists() {
        // The resolved path matches the Ed25519 arm, so the error reads the
        // same for every algorithm.
        return Err(Error::MissingKeyFile {
            algorithm,
            path: path.display().to_string(),
        });
    }
    kit_core::sign::load_raw_32(&path).map_err(|e| Error::InvalidKeyFile {
        path: rel_path.to_owned(),
        reason: e.to_string(),
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)] // unwrap is the assertion in tests

    use std::fs;
    use std::path::Path;

    use super::*;

    fn environment(dir: &Path) -> Environment {
        Environment::new(dir)
    }

    /// Set the permission bits that `load_key` and `load_raw_32` require.
    #[cfg(unix)]
    fn set_secure_mode(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        let mut perm = fs::metadata(path).unwrap().permissions();
        perm.set_mode(mode);
        fs::set_permissions(path, perm).unwrap();
    }

    #[cfg(not(unix))]
    fn set_secure_mode(_path: &Path, _mode: u32) {}

    fn write_key(path: &Path, bytes: &[u8]) {
        let parent = path.parent().unwrap();
        fs::create_dir_all(parent).unwrap();
        set_secure_mode(parent, 0o700);
        fs::write(path, bytes).unwrap();
        set_secure_mode(path, 0o600);
    }

    fn build_in(
        dir: &Path,
        algorithm: Algorithm,
        kind: Kind,
        config: &Config,
    ) -> Result<Box<dyn Signer>, Error> {
        build(
            &RepoLayout::single(dir),
            &environment(dir),
            algorithm,
            kind,
            config,
        )
    }

    /// The error of a build that must fail. `Box<dyn Signer>` has no `Debug`.
    fn build_err(dir: &Path, algorithm: Algorithm, kind: Kind, config: &Config) -> Error {
        build_in(dir, algorithm, kind, config).err().unwrap()
    }

    #[test]
    fn algorithms_parse_and_an_unknown_one_names_itself() {
        assert_eq!(parse_algorithm("ed25519").unwrap(), Algorithm::Ed25519);
        assert_eq!(parse_algorithm("secp256k1").unwrap(), Algorithm::Secp256k1);
        assert_eq!(parse_algorithm("p256").unwrap(), Algorithm::P256);
        let err = parse_algorithm("rsa").unwrap_err();
        assert!(matches!(err, Error::UnknownAlgorithm(ref s) if s == "rsa"));
        assert_eq!(
            err.to_string(),
            "unknown algorithm 'rsa' — expected one of: ed25519, secp256k1, p256"
        );
    }

    #[test]
    fn kinds_parse_and_round_trip_their_names() {
        for kind in [Kind::RepoKey, Kind::External, Kind::Keystore] {
            assert_eq!(kind.as_str().parse::<Kind>().unwrap(), kind);
        }
        let err = "sigstore".parse::<Kind>().unwrap_err();
        assert!(matches!(err, Error::UnknownSignerKind(ref s) if s == "sigstore"));
    }

    #[test]
    fn a_missing_ed25519_key_is_an_error_and_is_never_created() {
        let dir = tempfile::tempdir().unwrap();
        let err = build_err(
            dir.path(),
            Algorithm::Ed25519,
            Kind::RepoKey,
            &Config::with_defaults(),
        );
        assert!(
            matches!(err, Error::MissingKeyFile { algorithm: Algorithm::Ed25519, ref path } if path.contains("default.key")),
            "{err:?}"
        );
        assert!(!dir.path().join(".kit/keys/default.key").exists());
    }

    #[test]
    fn an_existing_ed25519_key_loads() {
        let dir = tempfile::tempdir().unwrap();
        write_key(&dir.path().join(".kit/keys/default.key"), &[0xCD; 32]);
        let signer = build_in(
            dir.path(),
            Algorithm::Ed25519,
            Kind::RepoKey,
            &Config::with_defaults(),
        )
        .unwrap();
        assert_eq!(signer.algorithm(), Algorithm::Ed25519);
    }

    #[test]
    fn the_signing_key_setting_moves_the_ed25519_key() {
        let dir = tempfile::tempdir().unwrap();
        write_key(&dir.path().join(".kit/keys/custom.key"), &[0xEF; 32]);
        let mut config = Config::with_defaults();
        config.signing_key = ".kit/keys/custom.key".into();
        let signer = build_in(dir.path(), Algorithm::Ed25519, Kind::RepoKey, &config).unwrap();
        assert_eq!(signer.algorithm(), Algorithm::Ed25519);
    }

    #[test]
    fn a_key_path_with_a_parent_component_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = Config::with_defaults();
        config.signing_key = "../escape.key".into();
        let err = build_err(dir.path(), Algorithm::Ed25519, Kind::RepoKey, &config);
        assert!(matches!(err, Error::InvalidKeyFile { .. }), "{err:?}");
    }

    #[test]
    fn a_missing_secp256k1_key_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let err = build_err(
            dir.path(),
            Algorithm::Secp256k1,
            Kind::RepoKey,
            &Config::with_defaults(),
        );
        assert!(
            matches!(err, Error::MissingKeyFile { algorithm: Algorithm::Secp256k1, ref path } if path.contains("secp256k1")),
            "{err:?}"
        );
    }

    #[test]
    fn a_p256_raw_secret_loads() {
        let dir = tempfile::tempdir().unwrap();
        let mut secret = [0u8; 32];
        secret[31] = 3;
        write_key(&dir.path().join(".kit/keys/p256.key"), &secret);
        let signer = build_in(
            dir.path(),
            Algorithm::P256,
            Kind::RepoKey,
            &Config::with_defaults(),
        )
        .unwrap();
        assert_eq!(signer.algorithm(), Algorithm::P256);
    }

    #[test]
    fn a_raw_secret_of_the_wrong_length_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        write_key(&dir.path().join(".kit/keys/secp256k1.key"), b"short");
        let err = build_err(
            dir.path(),
            Algorithm::Secp256k1,
            Kind::RepoKey,
            &Config::with_defaults(),
        );
        assert!(
            matches!(err, Error::InvalidKeyFile { ref reason, .. } if reason.contains("32 bytes")),
            "{err:?}"
        );
    }

    #[test]
    fn an_external_signer_needs_a_path() {
        let dir = tempfile::tempdir().unwrap();
        let err = build_err(
            dir.path(),
            Algorithm::Ed25519,
            Kind::External,
            &Config::with_defaults(),
        );
        assert!(matches!(err, Error::ExternalSignerPath(_)), "{err:?}");
    }
}
