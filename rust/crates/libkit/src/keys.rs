//! Signing keys in a keystore backend.
//!
//! [`select`] picks the backend and the label of a key from explicit values
//! and the `key.*` settings. [`open`] opens the backend. [`generate`],
//! [`import`], [`list`], [`export`] and [`delete`] then work on the opened
//! [`Keystore`]. A caller can pass any [`Keystore`], so a test needs no
//! system keychain.
//!
//! Secret bytes live in a [`SecretKey`], which wipes them on drop and never
//! shows them in `Debug`. No error in this module holds secret material.

use std::path::Path;

use kit_core::object::KitError;
use kit_keystore::{
    Algorithm, BackendKind, GenerateOptions, ImportOptions, KeyAttrs, KeyLabel, KeyMetadata,
    KeyRef, KeySelector, Keystore, SecretKey, open_backend,
};
use zeroize::Zeroizing;

use crate::config::Config;

/// The length of a secret key in bytes.
const SECRET_BYTES: usize = 32;

/// Errors from a key operation.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The text is not the name of a backend.
    #[error("key backend: {0}")]
    Backend(kit_keystore::Error),
    /// A configured key reference is malformed.
    #[error("config key ref: {0}")]
    ConfigKeyRef(kit_keystore::Error),
    /// The backend cannot be opened here.
    #[error("keystore backend: {0}")]
    OpenBackend(kit_keystore::Error),
    /// The keystore refused or failed the operation.
    #[error("keystore: {0}")]
    Keystore(#[from] kit_keystore::Error),
    /// A hex secret has the wrong length.
    #[error("--hex must be exactly 64 hex characters")]
    SecretHexLength,
    /// A hex secret holds a character that is not a hex digit.
    #[error("invalid hex character")]
    SecretHexDigit,
    /// The key file cannot be read.
    #[error("read key file: {0}")]
    ReadKeyFile(KitError),
}

/// The backend and the label of a key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selection {
    /// The backend that holds the key.
    pub backend: BackendKind,
    /// The label of the key in the backend.
    pub label: String,
}

/// Parse the name of a backend.
///
/// # Errors
/// [`Error::Backend`] when the name is unknown.
pub fn parse_backend(name: &str) -> Result<BackendKind, Error> {
    name.parse::<BackendKind>().map_err(Error::Backend)
}

/// The backend to use: `backend` when given, else `key.backend`.
///
/// # Errors
/// [`Error::Backend`] when the name is unknown.
pub fn backend(config: &Config, backend: Option<&str>) -> Result<BackendKind, Error> {
    parse_backend(backend.unwrap_or_else(|| config.key.backend_or_fallback()))
}

/// Pick the backend and the label of a key.
///
/// - `backend` wins over `key.backend`.
/// - `label` wins over every reference. With a label, the backend is
///   `backend` or `key.backend`.
/// - Without a label, the reference for `algorithm` names the label. The
///   algorithm is Ed25519 when `None`. The per-algorithm reference wins over
///   `key.default_ref`, which wins over the built-in default. A reference
///   from the config also names a backend, and `backend` still wins over it.
///
/// # Errors
/// - [`Error::Backend`] when a backend name is unknown.
/// - [`Error::ConfigKeyRef`] when the reference is malformed.
pub fn select(
    config: &Config,
    backend: Option<&str>,
    label: Option<String>,
    algorithm: Option<Algorithm>,
) -> Result<Selection, Error> {
    let explicit = backend.map(parse_backend).transpose()?;
    if let Some(label) = label {
        let backend = match explicit {
            Some(backend) => backend,
            None => parse_backend(config.key.backend_or_fallback())?,
        };
        return Ok(Selection { backend, label });
    }
    let algorithm = algorithm.unwrap_or(Algorithm::Ed25519);
    let configured = configured_ref(config, algorithm);
    let key_ref = configured
        .unwrap_or_else(|| ref_or_fallback(config, algorithm))
        .parse::<KeyRef>()
        .map_err(Error::ConfigKeyRef)?;
    let backend = match explicit {
        Some(backend) => backend,
        None if configured.is_some() => key_ref.backend(),
        None => parse_backend(config.key.backend_or_fallback())?,
    };
    Ok(Selection {
        backend,
        label: key_ref.label().to_owned(),
    })
}

/// The reference that the config sets for `algorithm`, if it sets one.
fn configured_ref(config: &Config, algorithm: Algorithm) -> Option<&str> {
    let key = &config.key;
    match algorithm {
        Algorithm::Ed25519 if !key.ed25519_ref.is_empty() => Some(key.ed25519_ref.as_str()),
        Algorithm::Secp256k1 if !key.secp256k1_ref.is_empty() => Some(key.secp256k1_ref.as_str()),
        Algorithm::P256 if !key.p256_ref.is_empty() => Some(key.p256_ref.as_str()),
        _ if !key.default_ref.is_empty() => Some(key.default_ref.as_str()),
        _ => None,
    }
}

fn ref_or_fallback(config: &Config, algorithm: Algorithm) -> &str {
    match algorithm {
        Algorithm::Ed25519 => config.key.ed25519_ref_or_fallback(),
        Algorithm::Secp256k1 => config.key.secp256k1_ref_or_fallback(),
        Algorithm::P256 => config.key.p256_ref_or_fallback(),
    }
}

/// Open a backend.
///
/// # Errors
/// [`Error::OpenBackend`] when the backend is not built in or not usable.
pub fn open(backend: BackendKind) -> Result<Box<dyn Keystore>, Error> {
    open_backend(backend).map_err(Error::OpenBackend)
}

/// Generate a key. `overwrite` replaces a key that exists.
///
/// # Errors
/// [`Error::Keystore`] when the label is invalid, when the backend cannot
/// generate keys or when it refuses.
pub fn generate(
    store: &dyn Keystore,
    label: &str,
    algorithm: Algorithm,
    attrs: KeyAttrs,
    overwrite: bool,
) -> Result<KeyMetadata, Error> {
    let label = KeyLabel::new(label)?;
    let generator = store
        .generator()
        .ok_or(kit_keystore::Error::UnsupportedOperation("generate"))?;
    let signer = generator.generate(&label, algorithm, attrs, GenerateOptions { overwrite })?;
    Ok(signer.metadata()?)
}

/// Import a secret key. `overwrite` replaces a key that exists.
///
/// # Errors
/// [`Error::Keystore`] when the label is invalid, when the backend cannot
/// import keys or when it refuses.
pub fn import(
    store: &dyn Keystore,
    label: &str,
    secret: SecretKey,
    attrs: KeyAttrs,
    overwrite: bool,
) -> Result<KeyMetadata, Error> {
    let label = KeyLabel::new(label)?;
    let importer = store
        .importer()
        .ok_or(kit_keystore::Error::UnsupportedOperation("import"))?;
    let signer = importer.import(&label, secret, attrs, ImportOptions { overwrite })?;
    Ok(signer.metadata()?)
}

/// List the keys that the backend shows, ordered by backend, label and
/// algorithm.
///
/// # Errors
/// [`Error::Keystore`] when the backend cannot list keys or fails.
pub fn list(store: &dyn Keystore) -> Result<Vec<KeyMetadata>, Error> {
    let lister = store
        .lister()
        .ok_or(kit_keystore::Error::UnsupportedOperation("list"))?;
    let mut keys = lister.list()?;
    keys.sort_by(|left, right| {
        (left.backend(), left.label(), left.algorithm()).cmp(&(
            right.backend(),
            right.label(),
            right.algorithm(),
        ))
    });
    Ok(keys)
}

/// Export the secret of one key. The caller decides where the secret goes.
///
/// # Errors
/// [`Error::Keystore`] when the label is invalid, when the backend cannot
/// export keys, or when it refuses.
pub fn export(
    store: &dyn Keystore,
    label: String,
    algorithm: Option<Algorithm>,
) -> Result<SecretKey, Error> {
    let selector = KeySelector::new(label, algorithm)?;
    let exporter = store
        .exporter()
        .ok_or(kit_keystore::Error::UnsupportedOperation("export"))?;
    Ok(exporter.export(&selector)?)
}

/// Delete exactly one key.
///
/// # Errors
/// [`Error::Keystore`] when the label is invalid, when the backend cannot
/// delete keys, or when it refuses.
pub fn delete(
    store: &dyn Keystore,
    label: String,
    algorithm: Option<Algorithm>,
) -> Result<(), Error> {
    let selector = KeySelector::new(label, algorithm)?;
    let deleter = store
        .deleter()
        .ok_or(kit_keystore::Error::UnsupportedOperation("delete"))?;
    Ok(deleter.delete(&selector)?)
}

/// Decode a secret key from exactly 64 hex digits, in either case.
///
/// # Errors
/// - [`Error::SecretHexLength`] when the text is not 64 bytes long.
/// - [`Error::SecretHexDigit`] when a character is not a hex digit.
pub fn parse_secret_hex(algorithm: Algorithm, hex: &str) -> Result<SecretKey, Error> {
    if hex.len() != SECRET_BYTES * 2 {
        return Err(Error::SecretHexLength);
    }
    let mut bytes = Zeroizing::new([0u8; SECRET_BYTES]);
    for (byte, pair) in bytes.iter_mut().zip(hex.as_bytes().chunks_exact(2)) {
        *byte = (hex_value(pair[0])? << 4) | hex_value(pair[1])?;
    }
    Ok(SecretKey::from_zeroizing(algorithm, bytes))
}

fn hex_value(digit: u8) -> Result<u8, Error> {
    match digit {
        b'0'..=b'9' => Ok(digit - b'0'),
        b'a'..=b'f' => Ok(digit - b'a' + 10),
        b'A'..=b'F' => Ok(digit - b'A' + 10),
        _ => Err(Error::SecretHexDigit),
    }
}

/// Read a secret key from a file of 32 raw bytes.
///
/// The file must not be a symlink and must not be readable by others. See
/// [`kit_core::sign::load_raw_32`].
///
/// # Errors
/// [`Error::ReadKeyFile`] when the file is refused or unreadable.
pub fn read_secret_file(algorithm: Algorithm, path: &Path) -> Result<SecretKey, Error> {
    kit_core::sign::load_raw_32(path)
        .map(|bytes| SecretKey::from_zeroizing(algorithm, bytes))
        .map_err(Error::ReadKeyFile)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)] // unwrap is the assertion in tests

    use super::*;

    #[test]
    fn a_hex_secret_decodes_in_either_case() {
        let lower = parse_secret_hex(Algorithm::Ed25519, &"0a".repeat(32)).unwrap();
        let upper = parse_secret_hex(Algorithm::Ed25519, &"0A".repeat(32)).unwrap();
        assert_eq!(lower.expose_secret(), &[0x0a; 32]);
        assert_eq!(upper.expose_secret(), lower.expose_secret());
        assert_eq!(lower.algorithm(), Algorithm::Ed25519);
    }

    #[test]
    fn a_hex_secret_of_the_wrong_length_is_refused() {
        for hex in ["", "00", &"0".repeat(63), &"0".repeat(65), &"0".repeat(128)] {
            let err = parse_secret_hex(Algorithm::Ed25519, hex).unwrap_err();
            assert!(matches!(err, Error::SecretHexLength), "{hex:?}: {err:?}");
        }
    }

    #[test]
    fn a_hex_secret_with_a_bad_digit_is_refused() {
        for bad in ['g', ' ', '-', '+'] {
            let hex = format!("{}0{bad}", "00".repeat(31));
            let err = parse_secret_hex(Algorithm::Ed25519, &hex).unwrap_err();
            assert!(matches!(err, Error::SecretHexDigit), "{bad:?}: {err:?}");
        }
        // A two-byte character makes the text one byte too long.
        let hex = format!("{}0é", "00".repeat(31));
        let err = parse_secret_hex(Algorithm::Ed25519, &hex).unwrap_err();
        assert!(matches!(err, Error::SecretHexLength));
    }

    #[test]
    fn an_error_never_shows_the_secret() {
        let secret = "ab".repeat(31) + "zz";
        let err = parse_secret_hex(Algorithm::Ed25519, &secret).unwrap_err();
        assert!(!err.to_string().contains("abab"));
        assert!(!format!("{err:?}").contains("abab"));
    }

    #[test]
    fn a_backend_name_must_be_known() {
        assert_eq!(
            parse_backend("software-raw").unwrap(),
            BackendKind::SoftwareRaw
        );
        let err = parse_backend("vault").unwrap_err();
        assert!(matches!(err, Error::Backend(_)));
        assert!(err.to_string().starts_with("key backend: "));
    }

    #[test]
    fn the_config_backend_applies_without_an_explicit_one() {
        let mut config = Config::with_defaults();
        assert_eq!(backend(&config, None).unwrap(), BackendKind::Software);
        config.key.backend = "software-raw".into();
        assert_eq!(backend(&config, None).unwrap(), BackendKind::SoftwareRaw);
        assert_eq!(
            backend(&config, Some("software")).unwrap(),
            BackendKind::Software
        );
    }

    #[test]
    fn a_label_wins_and_takes_the_default_backend() {
        let config = Config::with_defaults();
        let selection = select(&config, None, Some("ci".to_owned()), None).unwrap();
        assert_eq!(
            selection,
            Selection {
                backend: BackendKind::Software,
                label: "ci".to_owned()
            }
        );
        let selection = select(&config, Some("software-raw"), Some("ci".to_owned()), None).unwrap();
        assert_eq!(selection.backend, BackendKind::SoftwareRaw);
    }

    #[test]
    fn without_a_label_the_reference_of_the_algorithm_decides() {
        let config = Config::with_defaults();
        let ed = select(&config, None, None, None).unwrap();
        assert_eq!(ed.label, "default");
        let k1 = select(&config, None, None, Some(Algorithm::Secp256k1)).unwrap();
        assert_eq!(k1.label, "default-secp256k1");
        let p256 = select(&config, None, None, Some(Algorithm::P256)).unwrap();
        assert_eq!(p256.label, "default-p256");
    }

    #[test]
    fn a_configured_reference_names_the_backend_and_an_explicit_backend_wins() {
        let mut config = Config::with_defaults();
        config.key.ed25519_ref = "software-raw:release".into();
        let selection = select(&config, None, None, Some(Algorithm::Ed25519)).unwrap();
        assert_eq!(selection.backend, BackendKind::SoftwareRaw);
        assert_eq!(selection.label, "release");
        let selection = select(&config, Some("software"), None, Some(Algorithm::Ed25519)).unwrap();
        assert_eq!(selection.backend, BackendKind::Software);
        assert_eq!(selection.label, "release");
    }

    #[test]
    fn the_generic_reference_applies_to_an_algorithm_without_its_own() {
        let mut config = Config::with_defaults();
        config.key.default_ref = "software-raw:shared".into();
        let selection = select(&config, None, None, Some(Algorithm::P256)).unwrap();
        assert_eq!(selection.backend, BackendKind::SoftwareRaw);
        assert_eq!(selection.label, "shared");
    }

    #[test]
    fn a_malformed_reference_is_a_config_error() {
        let mut config = Config::with_defaults();
        config.key.default_ref = "no-colon".into();
        let err = select(&config, None, None, None).unwrap_err();
        assert!(matches!(err, Error::ConfigKeyRef(_)), "{err:?}");
        assert!(err.to_string().starts_with("config key ref: "));
    }
}
