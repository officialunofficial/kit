//! Generate, import, list, export and delete keys in a keystore.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in tests

use libkit::keys::{self, Error};
use libkit::keystore::{
    Algorithm, BackendKind, KeyAttrs, Keystore, SoftwareRawKeystore, open_backend,
};

fn store() -> (tempfile::TempDir, SoftwareRawKeystore) {
    let dir = tempfile::tempdir().unwrap();
    let store = SoftwareRawKeystore::with_root(dir.path());
    (dir, store)
}

fn extractable() -> KeyAttrs {
    KeyAttrs {
        extractable: true,
        ..KeyAttrs::default()
    }
}

fn hex_secret(pair: &str) -> libkit::keystore::SecretKey {
    keys::parse_secret_hex(Algorithm::Ed25519, &pair.repeat(32)).unwrap()
}

#[test]
fn a_generated_key_shows_in_the_listing() {
    let (_dir, store) = store();
    let metadata =
        keys::generate(&store, "ci", Algorithm::Ed25519, KeyAttrs::default(), false).unwrap();
    assert_eq!(metadata.label(), "ci");
    assert_eq!(metadata.algorithm(), Algorithm::Ed25519);
    assert!(metadata.keyid().starts_with("ed25519:"));

    let listed = keys::list(&store).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].keyid(), metadata.keyid());
}

#[test]
fn generating_a_key_twice_needs_overwrite() {
    let (_dir, store) = store();
    let first =
        keys::generate(&store, "ci", Algorithm::Ed25519, KeyAttrs::default(), false).unwrap();
    let err =
        keys::generate(&store, "ci", Algorithm::Ed25519, KeyAttrs::default(), false).unwrap_err();
    assert!(matches!(err, Error::Keystore(_)), "{err:?}");
    assert!(err.to_string().starts_with("keystore: "));

    let second =
        keys::generate(&store, "ci", Algorithm::Ed25519, KeyAttrs::default(), true).unwrap();
    assert_ne!(first.keyid(), second.keyid());
}

#[test]
fn a_label_that_the_keystore_refuses_is_a_keystore_error() {
    let (_dir, store) = store();
    let err =
        keys::generate(&store, "", Algorithm::Ed25519, KeyAttrs::default(), false).unwrap_err();
    assert!(matches!(err, Error::Keystore(_)), "{err:?}");
}

#[test]
fn an_imported_key_exports_the_same_secret() {
    let (_dir, store) = store();
    keys::import(&store, "imp", hex_secret("03"), extractable(), false).unwrap();

    let exported = keys::export(&store, "imp".to_owned(), Some(Algorithm::Ed25519)).unwrap();
    assert_eq!(exported.expose_secret(), &[3u8; 32]);
}

#[test]
fn importing_over_a_key_needs_overwrite() {
    let (_dir, store) = store();
    keys::import(&store, "imp", hex_secret("03"), extractable(), false).unwrap();
    let err = keys::import(&store, "imp", hex_secret("04"), extractable(), false).unwrap_err();
    assert!(matches!(err, Error::Keystore(_)), "{err:?}");

    keys::import(&store, "imp", hex_secret("04"), extractable(), true).unwrap();
    let exported = keys::export(&store, "imp".to_owned(), None).unwrap();
    assert_eq!(exported.expose_secret(), &[4u8; 32]);
}

#[test]
fn a_deleted_key_is_gone() {
    let (_dir, store) = store();
    keys::generate(&store, "ci", Algorithm::Ed25519, KeyAttrs::default(), false).unwrap();
    keys::delete(&store, "ci".to_owned(), Some(Algorithm::Ed25519)).unwrap();
    assert!(keys::list(&store).unwrap().is_empty());
    let err = keys::delete(&store, "ci".to_owned(), Some(Algorithm::Ed25519)).unwrap_err();
    assert!(matches!(err, Error::Keystore(_)), "{err:?}");
}

#[test]
fn the_listing_is_ordered_by_label() {
    let (_dir, store) = store();
    for label in ["b", "a", "c"] {
        keys::generate(
            &store,
            label,
            Algorithm::Ed25519,
            KeyAttrs::default(),
            false,
        )
        .unwrap();
    }
    let labels: Vec<_> = keys::list(&store)
        .unwrap()
        .iter()
        .map(|key| key.label().to_owned())
        .collect();
    assert_eq!(labels, ["a", "b", "c"]);
}

#[test]
fn a_secret_file_loads_and_a_missing_one_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secret.key");
    std::fs::write(&path, [5u8; 32]).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let secret = keys::read_secret_file(Algorithm::Ed25519, &path).unwrap();
    assert_eq!(secret.expose_secret(), &[5u8; 32]);

    let err = keys::read_secret_file(Algorithm::Ed25519, &dir.path().join("absent.key"))
        .err()
        .unwrap();
    assert!(matches!(err, Error::ReadKeyFile(_)), "{err:?}");
    assert!(err.to_string().starts_with("read key file: "));
}

#[test]
fn a_backend_that_is_not_built_in_is_unavailable() {
    let err = keys::open(BackendKind::Cloud).err().unwrap();
    assert!(matches!(err, Error::OpenBackend(_)), "{err:?}");
    assert!(err.to_string().starts_with("keystore backend: "));
    // The library and the keystore crate agree on what is built in.
    assert!(open_backend(BackendKind::Cloud).is_err());
}

#[test]
fn the_capabilities_come_from_the_store() {
    let (_dir, store) = store();
    let capabilities = Keystore::capabilities(&store);
    assert!(capabilities.can_generate);
    assert!(capabilities.supports_listing);
}
