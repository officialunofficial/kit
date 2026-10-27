//! Client side of SPEC-WRITE-GRANTS: owner signing and the command line
//! behind `kit grant`, `kit epoch` and `kit visibility`.
//!
//! The header checks, the canonical spelling of statement fields and the user
//! grant store live in [`libkit::grants`]. This module re-exports them for
//! the commands.

pub mod cli;
pub mod owner;
pub mod remote;

use std::time::{SystemTime, UNIX_EPOCH};

pub use libkit::grants::{
    HeaderError, VerifiedGrantHeader, parse_relying_parties, read_bounded, scope_text, spec, store,
    verify_epoch_header, verify_grant_header, verify_visibility_header,
};

/// Milliseconds since the Unix epoch.
#[must_use]
pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_millis()).ok())
        .unwrap_or(0)
}

/// Test helpers shared by the store and command tests.
#[cfg(test)]
pub(crate) mod testutil {
    use std::sync::Arc;

    use kit_attest::grant::{Capabilities, Grant, RepoScope};
    use kit_core::hash::to_hex_bytes;
    use kit_transport_connect::EnvelopeSigner;

    use super::owner::{Kind, NativeOwner, Plan, Produced, produce};

    pub(crate) struct DalekSigner(pub ed25519_dalek::SigningKey);
    impl EnvelopeSigner for DalekSigner {
        fn public_key_hex(&self) -> String {
            to_hex_bytes(&self.0.verifying_key().to_bytes())
        }
        fn sign_hex(&self, message: &[u8; 32]) -> Result<String, String> {
            use ed25519_dalek::Signer as _;
            Ok(to_hex_bytes(&self.0.sign(message).to_bytes()))
        }
    }

    pub(crate) fn owner(seed: u8) -> NativeOwner {
        NativeOwner::ed25519(Arc::new(DalekSigner(
            ed25519_dalek::SigningKey::from_bytes(&[seed; 32]),
        )))
        .unwrap()
    }

    /// A real owner-signed read grant for `audience`, distinct per `nonce`.
    pub(crate) fn signed_grant(seed: u8, nonce: u8, epoch: u64, audience: &str) -> String {
        let now = super::now_ms();
        let Produced::Signed(signed) = produce(
            Plan::Native(owner(seed)),
            |ns| {
                Grant {
                    namespace: *ns,
                    scope: RepoScope::Namespace,
                    grantee: [7; 32],
                    capabilities: Capabilities::Read,
                    audiences: vec![audience.to_owned()],
                    ref_scopes: None,
                    epoch,
                    created_ms: now,
                    expiry_ms: now + 3_600_000,
                    nonce: [nonce; 32],
                }
                .encode()
                .map_err(|e| e.to_string())
            },
            Kind::Grant,
            &[],
            now,
        )
        .unwrap() else {
            panic!("expected a signed grant")
        };
        signed.header
    }
}
