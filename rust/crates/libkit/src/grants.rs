//! The client side of SPEC-WRITE-GRANTS: the header checks, the canonical
//! spelling of statement fields and the grant store of the user.
//!
//! Nothing here is repository-scoped. The store lives beside the user config,
//! the relying-party pins come from the user config, and every header is
//! verified with the `kit-attest` verifier before it is stored or sent
//! (SPEC-CONFIG-SECURITY).
//!
//! * [`spec`] turns the spellings of a person into the canonical statements
//!   of SPEC-WRITE-GRANTS §3, §5.1 and §9.1.
//! * [`store`] keeps one file for each grant and re-verifies each on load.
//! * This module checks a header against the rules of the specification.

pub mod spec;
pub mod store;

use kit_attest::grant::{
    AcceptedSchemes, EpochStatement, Grant, GrantError, OwnerScheme, RelyingParty,
    RepositoryIdentity, SignedHeader, VerifiedEpoch, VerifiedVisibility, VerifierConfig,
    verify_epoch_statement, verify_grant_owner, verify_visibility_statement,
};

/// Audience used when only the owner signature matters. The grant checks
/// that involve an audience run on the server; the client never compares it.
const OFFLINE_AUDIENCE: &str = "https://kit-client.invalid";

/// Why a header could not be verified locally.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum HeaderError {
    /// The attest verifier rejected it; the text is its rule name.
    #[error("{0}")]
    Rejected(GrantError),
    /// A `webauthn-p256` signature, and no relying party is pinned.
    #[error(
        "webauthn-p256 signatures need a pinned relying party: set `grant.webauthn_rp = <rp_id> <origin>` in the user config"
    )]
    WebAuthnNotPinned,
}

impl From<GrantError> for HeaderError {
    fn from(error: GrantError) -> Self {
        Self::Rejected(error)
    }
}

/// Why the `grant.webauthn_rp` entries do not parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RelyingPartyError<'a> {
    /// An entry breaks a rule of the relying-party id or an origin.
    #[error(
        "relying party `{id}`: {source} (expected `<rp_id> <origin>...`, e.g. `example.com https://example.com`)"
    )]
    Invalid {
        /// The id of the entry.
        id: &'a str,
        /// The rule that failed.
        source: GrantError,
    },
    /// Two entries have the same id.
    #[error("relying party `{0}` is pinned twice")]
    Duplicate(&'a str),
}

/// Parse `grant.webauthn_rp` entries (`<rp_id> <origin>...`, several entries
/// separated by `|`).
///
/// # Errors
/// A malformed entry, or two entries with the same relying-party id.
pub fn parse_relying_parties(
    entries: &[String],
) -> Result<Vec<RelyingParty>, RelyingPartyError<'_>> {
    let mut out: Vec<RelyingParty> = Vec::new();
    for value in entries {
        for entry in value.split('|') {
            let mut parts = entry.split_whitespace();
            let Some(id) = parts.next() else {
                continue;
            };
            let rp = RelyingParty::new(id, parts)
                .map_err(|source| RelyingPartyError::Invalid { id, source })?;
            if out.iter().any(|other| other.id() == rp.id()) {
                return Err(RelyingPartyError::Duplicate(id));
            }
            out.push(rp);
        }
    }
    Ok(out)
}

/// A verifier that accepts `ed25519` and `secp256k1-eip191`, plus
/// `webauthn-p256` when relying parties are pinned. Loopback audiences and
/// relying parties are allowed: the client has no deployment to protect, and
/// the server applies its own production rules.
fn verifier_config(audience: &str, rps: &[RelyingParty]) -> Result<VerifierConfig, GrantError> {
    let mut schemes = vec![OwnerScheme::Ed25519, OwnerScheme::Secp256k1Eip191];
    if !rps.is_empty() {
        schemes.push(OwnerScheme::WebAuthnP256);
    }
    VerifierConfig::new_allowing_loopback(audience, AcceptedSchemes::of(&schemes), rps.to_vec())
}

fn check_pinned(header: &str, rps: &[RelyingParty]) -> Result<(), HeaderError> {
    if rps.is_empty()
        && let Ok(signed) = SignedHeader::parse(header)
        && signed.scheme == OwnerScheme::WebAuthnP256
    {
        return Err(HeaderError::WebAuthnNotPinned);
    }
    Ok(())
}

/// A grant header whose owner signature verified.
#[derive(Debug, Clone)]
pub struct VerifiedGrantHeader {
    /// The grant that the header carries.
    pub grant: Grant,
    /// The grant id (SPEC-WRITE-GRANTS §3.4).
    pub id: [u8; 32],
    /// The scheme of the owner signature.
    pub scheme: OwnerScheme,
}

/// SPEC-WRITE-GRANTS §7 steps 1, 3 and 4 for a grant header.
///
/// # Errors
/// The rule that failed.
pub fn verify_grant_header(
    header: &str,
    rps: &[RelyingParty],
) -> Result<VerifiedGrantHeader, HeaderError> {
    check_pinned(header, rps)?;
    let cfg = verifier_config(OFFLINE_AUDIENCE, rps)?;
    let verified = verify_grant_owner(&cfg, header)?;
    Ok(VerifiedGrantHeader {
        grant: verified.statement().clone(),
        id: *verified.id(),
        scheme: verified.scheme(),
    })
}

/// The verifier config for a statement header, bound to the first audience
/// that `audiences` reads out of the statement bytes.
fn first_audience_config(
    header: &str,
    rps: &[RelyingParty],
    audiences: impl FnOnce(&[u8]) -> Result<Vec<String>, GrantError>,
) -> Result<VerifierConfig, HeaderError> {
    check_pinned(header, rps)?;
    let signed = SignedHeader::parse(header)?;
    let first = audiences(&signed.statement)?
        .into_iter()
        .next()
        .ok_or(GrantError::AudienceCount)?;
    Ok(verifier_config(&first, rps)?)
}

/// Read at most `max` bytes from `reader`.
///
/// # Errors
/// A read error, or more than `max` bytes (`InvalidData`).
pub fn read_bounded(reader: impl std::io::Read, max: u64) -> std::io::Result<Vec<u8>> {
    use std::io::Read as _;
    let mut bytes = Vec::new();
    reader.take(max.saturating_add(1)).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("larger than {max} bytes"),
        ));
    }
    Ok(bytes)
}

/// SPEC-WRITE-GRANTS §5.2 checks 1–5 against the statement's first audience.
///
/// # Errors
/// The rule that failed.
pub fn verify_epoch_header(
    header: &str,
    rps: &[RelyingParty],
    now_ms: i64,
) -> Result<VerifiedEpoch, HeaderError> {
    let cfg = first_audience_config(header, rps, |statement| {
        EpochStatement::parse(statement).map(|s| s.audiences)
    })?;
    Ok(verify_epoch_statement(&cfg, header, now_ms)?)
}

/// SPEC-WRITE-GRANTS §9.1 checks for a visibility statement sent for
/// `repository`, against the statement's first audience.
///
/// # Errors
/// The rule that failed.
pub fn verify_visibility_header(
    header: &str,
    repository: &RepositoryIdentity,
    rps: &[RelyingParty],
    now_ms: i64,
) -> Result<VerifiedVisibility, HeaderError> {
    let cfg = first_audience_config(header, rps, |statement| {
        kit_attest::grant::VisibilityStatement::parse(statement).map(|s| s.audiences)
    })?;
    Ok(verify_visibility_statement(
        &cfg, header, repository, now_ms,
    )?)
}

/// `<namespace>/*` or `<namespace>/<name>`: the repositories a grant covers.
#[must_use]
pub fn scope_text(grant: &Grant) -> String {
    match &grant.scope {
        kit_attest::grant::RepoScope::Namespace => format!("{}/*", grant.namespace),
        kit_attest::grant::RepoScope::Repository(id) => id.to_string(),
    }
}

#[cfg(test)]
pub(crate) mod testutil {
    //! A signer for the tests of the store.

    use ed25519_dalek::Signer as _;
    use kit_attest::grant::{Capabilities, Grant, Namespace, OwnerScheme, RepoScope, SignedHeader};
    use kit_core::hash::hash;

    /// A read grant for `audience`, signed by the owner with the key from
    /// `seed`. The `nonce` makes the grant id differ.
    pub(crate) fn signed_grant(seed: u8, nonce: u8, epoch: u64, audience: &str) -> String {
        let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let statement = Grant {
            namespace: Namespace::Ed25519(key.verifying_key().to_bytes()),
            scope: RepoScope::Namespace,
            grantee: [7; 32],
            capabilities: Capabilities::Read,
            audiences: vec![audience.to_owned()],
            ref_scopes: None,
            epoch,
            created_ms: 1_700_000_000_000,
            expiry_ms: 1_700_000_000_000 + 3_600_000,
            nonce: [nonce; 32],
        }
        .encode()
        .unwrap();
        let blob = key.sign(&hash(&statement)).to_bytes().to_vec();
        SignedHeader {
            statement,
            scheme: OwnerScheme::Ed25519,
            blob,
        }
        .encode()
        .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relying_party_entries_parse_and_reject_duplicates() {
        let entries = [
            "example.com https://example.com https://app.example.com | other.test https://other.test"
                .to_owned(),
        ];
        let rps = parse_relying_parties(&entries).unwrap();
        assert_eq!(rps.len(), 2);
        assert_eq!(rps[0].id(), "example.com");
        assert_eq!(rps[0].origins().len(), 2);
        assert!(parse_relying_parties(&["example.com".to_owned()]).is_err());
        let twice = [
            "example.com https://a.test".to_owned(),
            "example.com https://b.test".to_owned(),
        ];
        let error = parse_relying_parties(&twice).unwrap_err();
        assert_eq!(
            error.to_string(),
            "relying party `example.com` is pinned twice"
        );
        assert!(parse_relying_parties(&[String::new()]).unwrap().is_empty());
    }

    #[test]
    fn a_signed_grant_verifies_and_a_changed_signature_does_not() {
        let header = testutil::signed_grant(1, 1, 0, "https://git.example.com");
        let verified = verify_grant_header(&header, &[]).unwrap();
        assert_eq!(verified.scheme, OwnerScheme::Ed25519);
        assert_eq!(
            scope_text(&verified.grant),
            format!("{}/*", verified.grant.namespace)
        );
        let mut signed = SignedHeader::parse(&header).unwrap();
        signed.blob[0] ^= 1;
        let error = verify_grant_header(&signed.encode().unwrap(), &[]).unwrap_err();
        assert_eq!(error.to_string(), "bad signature");
    }

    #[test]
    fn a_header_that_is_not_a_header_is_rejected() {
        assert!(matches!(
            verify_grant_header("not a header", &[]),
            Err(HeaderError::Rejected(_))
        ));
        let rps = [];
        assert!(verify_epoch_header("not a header", &rps, 0).is_err());
    }

    #[test]
    fn read_bounded_stops_at_the_limit() {
        assert_eq!(read_bounded(&b"abc"[..], 3).unwrap(), b"abc");
        let error = read_bounded(&b"abcd"[..], 3).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(error.to_string(), "larger than 3 bytes");
        assert_eq!(read_bounded(&b"abc"[..], u64::MAX).unwrap(), b"abc");
    }
}
