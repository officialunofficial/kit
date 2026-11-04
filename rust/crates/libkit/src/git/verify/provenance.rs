//! Required import claims: signature validity and every contextual binding.

use kit_core::{Hash, layout::RepoLayout, store::ObjectStore};
use kit_git_bridge::gitobj::{Sha1Id, sha1_hex};
use kit_git_bridge::remoteid::attestation_remote;
use serde::Deserialize;

use crate::git::import::PREDICATE_TYPE;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Claim {
    #[serde(rename = "_type")]
    statement_type: String,
    predicate_type: String,
    subject: Vec<Subject>,
    predicate: Predicate,
}

#[derive(Deserialize)]
struct Subject {
    name: String,
    digest: Digests,
}

#[derive(Deserialize)]
struct Digests {
    blake3: String,
    sha256: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Predicate {
    git_commit: String,
    ref_name: String,
    remote_url: String,
    schema_version: u32,
    spec_version: u32,
}

/// What a claim about an imported head must state.
#[derive(Debug, Clone, Copy)]
pub struct ClaimBinding<'a> {
    /// The kit ref of the head.
    pub kit_ref: &'a str,
    /// The kit hash of the head.
    pub twin: &'a Hash,
    /// The SHA-256 digest of the head, in hex.
    pub sha256: &'a str,
    /// The git id of the head.
    pub git_id: &'a Sha1Id,
    /// The remote identity of the import source.
    pub source: &'a str,
}

/// Whether `payload` is a `git-import/v1` statement with exactly the
/// subject and the predicate of `binding`.
///
/// A payload that is not a statement, or that has more than one subject, is
/// not accepted.
#[must_use]
pub fn claim_accepts(payload: &[u8], binding: &ClaimBinding<'_>) -> bool {
    let Ok(claim) = serde_json::from_slice::<Claim>(payload) else {
        return false;
    };
    let [subject] = claim.subject.as_slice() else {
        return false;
    };
    claim.statement_type == kit_attest::statement::IN_TOTO_TYPE
        && claim.predicate_type == PREDICATE_TYPE
        && subject.name == binding.kit_ref
        && subject.digest.blake3 == kit_core::to_hex(binding.twin)
        && subject
            .digest
            .sha256
            .as_ref()
            .is_none_or(|h| h == binding.sha256)
        && claim.predicate.ref_name == binding.kit_ref
        && claim.predicate.git_commit == sha1_hex(binding.git_id)
        // An attestation of an earlier import names the local path itself.
        && (claim.predicate.remote_url == binding.source
            || claim.predicate.remote_url == attestation_remote(binding.source))
        && claim.predicate.schema_version == 1
        && claim.predicate.spec_version == kit_git_bridge::import::IMPORT_SPEC_VERSION
}

pub(super) struct Context<'a> {
    pub layout: &'a RepoLayout,
    pub store: &'a ObjectStore,
    pub source: &'a str,
    pub remote: &'a str,
    pub signer: [u8; 32],
}

impl Context<'_> {
    pub(super) fn matches(&self, ref_name: &str, git_id: &Sha1Id, twin: &Hash) -> bool {
        let mut registry = kit_attest::verify::Registry::new();
        let keyid = format!(
            "blake3:{}",
            kit_core::to_hex(&kit_core::hash::hash(&self.signer))
        );
        registry.add(
            keyid,
            kit_attest::verify::TrustRoot::Ed25519PubKey(self.signer),
        );
        let kit_ref = ref_name.strip_prefix("refs/heads/").map_or_else(
            || ref_name.to_owned(),
            |branch| format!("refs/remotes/{}/{branch}", self.remote),
        );
        let Ok(paths) = kit_attest::store::list(self.layout, twin) else {
            return false;
        };
        let Ok(object) = self.store.read_object(twin) else {
            return false;
        };
        let Ok(bytes) = kit_core::serialize(&object) else {
            return false;
        };
        let sha256 = kit_attest::statement::sha256_hex(&bytes);
        let binding = ClaimBinding {
            kit_ref: &kit_ref,
            twin,
            sha256: &sha256,
            git_id,
            source: self.source,
        };
        paths.into_iter().any(|path| {
            let Ok(envelope) = kit_attest::store::load(&path) else {
                return false;
            };
            kit_attest::verify::verify(&envelope, &registry).is_ok_and(|r| r.any_verified)
                && claim_accepts(&envelope.payload, &binding)
        })
    }
}
