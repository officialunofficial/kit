//! The signer of a Connect request envelope.
//!
//! The envelope authenticates with the Ed25519 identity that signs commits.
//! `cfg.signer` picks the source: `""` or `"file"` is the repo key file at
//! `cfg.signing_key`, and `"keystore"` is `cfg.key.ed25519_ref_or_fallback()`
//! in `kit-keystore`. Both signers sign the raw 32-byte envelope digest with no
//! SPEC-SIGNING domain prefix. This is the contract of
//! `kit-transport-connect::envelope`. The file signer reuses
//! `kit_attest::RepoKeySigner`, which signs the bytes it gets as they are.
//! The keystore signer uses `KeySigner::sign`, which returns the 64-byte
//! RFC 8032 signature over the message.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use kit_attest::{RepoKeySigner, Signer as AttestSigner};
use kit_core::hash::to_hex_bytes;
use kit_core::layout::RepoLayout;
use kit_core::protocol::TransportError;
use kit_core::sign::KeyPair;
use kit_keystore::{KeyRef, KeySelector, KeySigner, open_backend};
use kit_transport_connect::EnvelopeSigner;

use super::Error;
use crate::Environment;
use crate::config::{Config, ConfigError, resolve_key_path};

/// Why no signer could be built from the config.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SignerError {
    /// The path of the signing key does not resolve.
    #[error("signing_key: {0}")]
    SigningKeyPath(ConfigError),
    /// The key file does not exist.
    #[error("no signing key at {} — run `kit keygen` first", .0.display())]
    MissingKey(PathBuf),
    /// The key file is not a key.
    #[error("load key: {0}")]
    LoadKey(String),
    /// The keystore does not hold a usable Ed25519 key.
    #[error("{0}")]
    Keystore(String),
    /// `cfg.signer` names no known source.
    #[error("unknown signer `{0}` — expected `file` or `keystore`")]
    UnknownSigner(String),
}

/// `cfg.signer = ""` / `"file"`: the repo key file `KeyPair`, signed through
/// `kit_attest::RepoKeySigner`. Its `sign` signs the bytes as they are. "The
/// PAE's own `"DSSEv1 "` prefix is the domain separator" says its doc, so the
/// signer adds no prefix. That is the plain Ed25519 over the digest that the
/// write envelope needs.
struct RepoKeyEnvelopeSigner {
    public_key_hex: String,
    // `Signer::sign` takes `&mut self`; `EnvelopeSigner::sign_hex` (called
    // through `Arc<dyn EnvelopeSigner>` from an async transport) only
    // gets `&self` — the `Mutex` bridges the two. `RepoKeySigner` itself
    // has no real mutable state (each `sign` call constructs a fresh
    // `SigningKey` from the held seed), so contention here is never
    // meaningful.
    inner: Mutex<RepoKeySigner>,
}

impl RepoKeyEnvelopeSigner {
    fn new(kp: KeyPair) -> Self {
        let public_key_hex = to_hex_bytes(&kp.public.0);
        Self {
            public_key_hex,
            inner: Mutex::new(RepoKeySigner::new(kp)),
        }
    }
}

impl EnvelopeSigner for RepoKeyEnvelopeSigner {
    fn public_key_hex(&self) -> String {
        self.public_key_hex.clone()
    }

    fn sign_hex(&self, message: &[u8; 32]) -> Result<String, String> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| "repo-key signer mutex poisoned".to_owned())?;
        let sig = guard.sign(message).map_err(|e| e.to_string())?;
        Ok(to_hex_bytes(&sig))
    }
}

/// `cfg.signer = "keystore"`: the key at `cfg.key.ed25519_ref_or_fallback()`
/// opened through `kit-keystore`.
///
/// `KeySigner::sign` takes `&mut self`, but `EnvelopeSigner::sign_hex` only
/// gets `&self` because the transport calls it through an
/// `Arc<dyn EnvelopeSigner>`. A `Mutex` bridges the two.
struct KeystoreEnvelopeSigner {
    public_key_hex: String,
    signer: Mutex<Box<dyn KeySigner>>,
}

impl KeystoreEnvelopeSigner {
    fn open(cfg: &Config) -> Result<Self, String> {
        let key_ref = cfg
            .key
            .ed25519_ref_or_fallback()
            .parse::<KeyRef>()
            .map_err(|e| format!("key.ed25519_ref: {e}"))?;
        let store =
            open_backend(key_ref.backend()).map_err(|e| format!("keystore backend: {e}"))?;
        let selector = KeySelector::new(
            key_ref.label().to_owned(),
            Some(kit_keystore::Algorithm::Ed25519),
        )
        .map_err(|e| format!("key.ed25519_ref: {e}"))?;
        let opener = store.opener().ok_or_else(|| {
            format!(
                "keystore backend `{}` does not support opening keys",
                key_ref.backend()
            )
        })?;
        let signer = opener.open(&selector).map_err(|e| match e {
            kit_keystore::Error::KeyNotFound(_) => format!(
                "missing keystore signing key for algorithm ed25519 — run `kit key generate --backend {} --algorithm ed25519 --label <label>` first: {e}",
                key_ref.backend()
            ),
            other => format!("keystore signing key for algorithm ed25519: {other}"),
        })?;
        let public = signer
            .public_key()
            .map_err(|e| format!("keystore public key: {e}"))?;
        if public.as_bytes().len() != 32 {
            return Err(format!(
                "keystore Ed25519 public key must be 32 bytes, got {}",
                public.as_bytes().len()
            ));
        }
        Ok(Self {
            public_key_hex: to_hex_bytes(public.as_bytes()),
            signer: Mutex::new(signer),
        })
    }
}

impl EnvelopeSigner for KeystoreEnvelopeSigner {
    fn public_key_hex(&self) -> String {
        self.public_key_hex.clone()
    }

    fn sign_hex(&self, message: &[u8; 32]) -> Result<String, String> {
        let mut guard = self
            .signer
            .lock()
            .map_err(|_| "keystore signer mutex poisoned".to_owned())?;
        // `KeySigner::sign`'s own contract: "Ed25519 signers return the
        // 64-byte RFC 8032 signature over `msg`" — raw sign, no domain
        // digest applied, exactly what the envelope needs.
        let sig = guard.sign(message).map_err(|e| e.to_string())?;
        if sig.len() != 64 {
            return Err(format!(
                "keystore Ed25519 signature must be 64 bytes, got {}",
                sig.len()
            ));
        }
        Ok(to_hex_bytes(&sig))
    }
}

/// The configured signing key as a signer for the grant owner commands
/// (`kit grant`, `kit epoch` and `kit visibility`). It does not check
/// `transport_auth`, because the owner asked for the signature.
///
/// # Errors
/// The key path does not resolve, the key is missing or unusable, or
/// `cfg.signer` is unknown.
pub fn owner_signer(
    cfg: &Config,
    layout: &RepoLayout,
    env: &Environment,
) -> Result<Arc<dyn EnvelopeSigner>, SignerError> {
    match cfg.signer.as_str() {
        "" | "file" => {
            let key_path = resolve_key_path(layout, env, &cfg.signing_key)
                .map_err(SignerError::SigningKeyPath)?;
            if !key_path.exists() {
                return Err(SignerError::MissingKey(key_path));
            }
            let key = kit_core::sign::load_key(&key_path)
                .map_err(|error| SignerError::LoadKey(error.to_string()))?;
            Ok(Arc::new(RepoKeyEnvelopeSigner::new(key)))
        }
        "keystore" => Ok(Arc::new(
            KeystoreEnvelopeSigner::open(cfg).map_err(SignerError::Keystore)?,
        )),
        other => Err(SignerError::UnknownSigner(other.to_owned())),
    }
}

/// The signer of the request envelope, when `cfg.transport_auth_envelope()` is
/// set. `None` is the default: the bearer token alone authenticates.
///
/// # Errors
/// [`owner_signer`] fails. The text names `transport_auth = envelope`.
pub fn envelope_signer(
    cfg: &Config,
    layout: &RepoLayout,
    env: &Environment,
) -> Result<Option<Arc<dyn EnvelopeSigner>>, Error> {
    if !cfg.transport_auth_envelope() {
        return Ok(None);
    }
    let remote_error = |message: String| Error::Transport(TransportError::RemoteError(message));
    owner_signer(cfg, layout, env)
        .map(Some)
        .map_err(|error| match error {
            SignerError::MissingKey(path) => remote_error(format!(
                "transport_auth = envelope requires a signing key at {} — run `kit keygen` first",
                path.display()
            )),
            other => remote_error(format!("transport_auth = envelope: {other}")),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use kit_core::sign::{KeyPair, save_key};

    fn config(signer: &str, key: &str) -> Config {
        Config {
            signer: signer.into(),
            signing_key: key.into(),
            ..Config::default()
        }
    }

    fn envelope_config(signer: &str, key: &str) -> Config {
        Config {
            transport_auth: "envelope".into(),
            ..config(signer, key)
        }
    }

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn the_file_signer_signs_the_raw_digest() {
        let dir = tempfile::tempdir().unwrap();
        let layout = RepoLayout::single(dir.path());
        let key = KeyPair::generate().unwrap();
        let path = dir.path().join(".kit/keys/signing-key");
        let keys = path.parent().unwrap();
        std::fs::create_dir_all(keys).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            // A key directory broader than 0700 is refused.
            std::fs::set_permissions(keys, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        save_key(&path, &key).unwrap();
        let env = Environment::new(dir.path());

        let signer = owner_signer(&config("file", ".kit/keys/signing-key"), &layout, &env).unwrap();
        assert_eq!(signer.public_key_hex(), to_hex_bytes(&key.public.0));
        let digest = [7u8; 32];
        let signature = signer.sign_hex(&digest).unwrap();
        let public: [u8; 32] = hex_to_bytes(&signer.public_key_hex()).try_into().unwrap();
        let signature: [u8; 64] = hex_to_bytes(&signature).try_into().unwrap();
        kit_core::sign::verify_ed25519(&public, &digest, &signature)
            .expect("the signature covers the raw digest");
    }

    #[test]
    fn a_missing_key_names_its_path_and_the_fix() {
        let dir = tempfile::tempdir().unwrap();
        let layout = RepoLayout::single(dir.path());
        let env = Environment::new(dir.path());
        let error = owner_signer(&config("", ".kit/keys/absent"), &layout, &env)
            .err()
            .unwrap();
        assert!(matches!(error, SignerError::MissingKey(_)), "{error}");
        let message = error.to_string();
        assert!(message.starts_with("no signing key at "), "{message}");
        assert!(message.ends_with("run `kit keygen` first"), "{message}");
    }

    #[test]
    fn an_unknown_signer_and_a_bad_key_path_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let layout = RepoLayout::single(dir.path());
        let env = Environment::new(dir.path());
        let error = owner_signer(&config("hsm", ".kit/keys/k"), &layout, &env)
            .err()
            .unwrap();
        assert_eq!(
            error.to_string(),
            "unknown signer `hsm` — expected `file` or `keystore`"
        );
        let error = owner_signer(&config("file", "../outside"), &layout, &env)
            .err()
            .unwrap();
        assert!(matches!(error, SignerError::SigningKeyPath(_)), "{error}");
        assert!(error.to_string().starts_with("signing_key: "), "{error}");
    }

    #[test]
    fn the_envelope_signer_is_off_unless_the_config_asks_for_it() {
        let dir = tempfile::tempdir().unwrap();
        let layout = RepoLayout::single(dir.path());
        let env = Environment::new(dir.path());
        assert!(
            envelope_signer(&config("hsm", ".kit/keys/k"), &layout, &env)
                .unwrap()
                .is_none(),
            "a bearer-token config builds no signer, so it reads no key"
        );
    }

    #[test]
    fn the_envelope_signer_prefixes_every_failure_with_the_setting() {
        let dir = tempfile::tempdir().unwrap();
        let layout = RepoLayout::single(dir.path());
        let env = Environment::new(dir.path());
        let cases = [
            (
                envelope_config("file", ".kit/keys/absent"),
                "transport_auth = envelope requires a signing key at ",
            ),
            (
                envelope_config("hsm", ".kit/keys/k"),
                "transport_auth = envelope: unknown signer `hsm`",
            ),
            (
                envelope_config("file", "../outside"),
                "transport_auth = envelope: signing_key: ",
            ),
        ];
        for (cfg, prefix) in cases {
            let error = envelope_signer(&cfg, &layout, &env).err().unwrap();
            assert!(
                matches!(&error, Error::Transport(TransportError::RemoteError(_))),
                "{error:?}"
            );
            assert!(error.to_string().contains(prefix), "{error}");
        }
    }
}
