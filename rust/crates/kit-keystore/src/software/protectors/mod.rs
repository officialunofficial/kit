//! OS-backed key-protector integrations for the software keystore.
//!
//! Each supported platform credential store gets its own submodule
//! implementing [`crate::encrypted_record::KeyProtector`] for wrapping the
//! per-record data-encryption key (DEK). The protectors are feature- and
//! target-gated; only the ones compiled in for the current platform are
//! reachable from [`super::default_protector_for_write`] /
//! [`super::default_protector_by_id`].

#[cfg(any(
    all(target_os = "macos", feature = "macos-keychain"),
    all(target_os = "linux", feature = "linux-secret-service")
))]
use crate::Error;
#[cfg(any(
    all(target_os = "macos", feature = "macos-keychain"),
    all(target_os = "linux", feature = "linux-secret-service")
))]
use crate::Result;
#[cfg(any(
    all(target_os = "macos", feature = "macos-keychain"),
    all(target_os = "linux", feature = "linux-secret-service")
))]
use crate::types::hex_lower;

#[cfg(all(target_os = "macos", feature = "macos-keychain"))]
pub(super) mod macos;
#[cfg(all(target_os = "macos", feature = "macos-keychain"))]
pub(super) use macos::MacosKeychainProtector;

#[cfg(all(target_os = "linux", feature = "linux-secret-service"))]
pub(super) mod linux_secret_service;
#[cfg(all(target_os = "linux", feature = "linux-secret-service"))]
pub(super) use linux_secret_service::{
    LinuxSecretServiceProtector, linux_desktop_session_available,
};

/// Random opaque handle used by the credential-store protectors as the
/// account/credential name under which the wrapped DEK is stored.
#[cfg(any(
    all(target_os = "macos", feature = "macos-keychain"),
    all(target_os = "linux", feature = "linux-secret-service")
))]
pub(super) fn random_handle() -> Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| Error::Internal("rng failed".into()))?;
    Ok(hex_lower(&bytes))
}
