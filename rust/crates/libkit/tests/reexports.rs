//! Each test names one item through a `libkit` module. The test compiles only
//! when the feature that owns the module is on. A run with a feature set
//! checks every module that the set turns on.

use std::any::type_name;

/// The type that a re-export names comes from the source crate.
fn names<T>(krate: &str, name: &str) -> bool {
    let full = type_name::<T>();
    full.starts_with(&format!("{krate}::")) && full.ends_with(&format!("::{name}"))
}

#[test]
fn always_on_modules_resolve() {
    assert!(names::<libkit::core::hash::Hasher>("kit_core", "Hasher"));
    assert!(names::<libkit::attest::Algorithm>(
        "kit_attest",
        "Algorithm"
    ));
    assert!(names::<libkit::keystore::SoftwareKeystore>(
        "kit_keystore",
        "SoftwareKeystore"
    ));
}

#[cfg(feature = "sync")]
#[test]
fn sync_module_resolves() {
    assert!(names::<libkit::sync::SyncOptions>(
        "kit_sync",
        "SyncOptions"
    ));
}

#[cfg(feature = "git-bridge")]
#[test]
fn git_bridge_module_resolves() {
    assert!(names::<libkit::git_bridge::GitObject>(
        "kit_git_bridge",
        "GitObject"
    ));
}

#[cfg(feature = "transport-file")]
#[test]
fn transport_file_module_resolves() {
    assert!(names::<libkit::transport::file::FileTransport>(
        "kit_transport_file",
        "FileTransport"
    ));
}

#[cfg(feature = "transport-ssh")]
#[test]
fn transport_ssh_module_resolves() {
    assert!(names::<libkit::transport::ssh::SshTransport>(
        "kit_transport_ssh",
        "SshTransport"
    ));
}

#[cfg(feature = "transport-s3")]
#[test]
fn transport_s3_module_resolves() {
    assert!(names::<libkit::transport::s3::S3Transport>(
        "kit_transport_s3",
        "S3Transport"
    ));
}

#[cfg(feature = "transport-connect")]
#[test]
fn transport_connect_module_resolves() {
    // The module path must resolve. `admission` is a public module.
    #[allow(unused_imports)]
    use libkit::transport::connect::admission;
}

#[cfg(feature = "history-mmr")]
#[test]
fn history_mmr_item_resolves() {
    assert!(names::<libkit::core::history::CommitHistory>(
        "kit_core",
        "CommitHistory"
    ));
}

#[cfg(feature = "sparse-checkout")]
#[test]
fn sparse_checkout_item_resolves() {
    assert!(names::<libkit::core::sparse::SparseManifest>(
        "kit_core",
        "SparseManifest"
    ));
}

#[test]
fn observer_types_come_from_the_core_crate() {
    assert!(names::<libkit::NoopObserver>("kit_core", "NoopObserver"));
}
