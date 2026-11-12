//! The signed messages of the Ed25519 roles cannot collide (SPEC-SIGNING §8).
//!
//! Every role starts its message with a fixed prefix: an object role hashes
//! `u16_le(len) || domain || body`, a statement role hashes
//! `domain "\n" fields`, and a DSSE role signs the PAE, which starts with
//! `"DSSEv1 "`. The test builds each prefix from the production constants
//! and encoders and fails when one prefix equals or extends another. A new
//! role adds a row here and a row to the §8 table.
#![cfg(feature = "grants")]
#![allow(clippy::unwrap_used)] // unwrap is the assertion in tests

use kit_attest::envelope::pae_of;
use kit_attest::grant::{DOMAIN_EPOCH, DOMAIN_GRANT, DOMAIN_URL_TOKEN, DOMAIN_VISIBILITY};
use kit_core::sign::{COMMIT_DOMAIN, REMIX_DOMAIN, TAG_DOMAIN};
use kit_core::write_auth::{self, Context, Operation};

/// The length of the PAE prefix `"DSSEv1 "`.
const PAE_PREFIX_LEN: usize = 7;

/// The first bytes of the hash input of an object role.
fn object_prefix(domain: &[u8]) -> Vec<u8> {
    let mut out = u16::try_from(domain.len()).unwrap().to_le_bytes().to_vec();
    out.extend_from_slice(domain);
    out
}

/// The first bytes of a statement: the domain, then the line feed that ends
/// the first field.
fn statement_prefix(domain: &str) -> Vec<u8> {
    format!("{domain}\n").into_bytes()
}

/// The prefix of an auth v2 request, taken from a real canonical string.
fn auth_v2_prefix() -> Vec<u8> {
    let hex = "0".repeat(64);
    let commitment = format!("body:{hex}");
    let operation = Operation {
        context: Context {
            audience: "https://example.test",
            repository: "ns/repo",
        },
        procedure: "/p",
        commitment: &commitment,
        created_at: 1,
        expires_at: 2,
        nonce: &hex,
    };
    let canonical = operation.canonical().unwrap().into_bytes();
    let line_end = canonical.iter().position(|&b| b == b'\n').unwrap();
    assert_eq!(&canonical[..line_end], write_auth::DOMAIN.as_bytes());
    canonical[..=line_end].to_vec()
}

fn roles() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("commit", object_prefix(COMMIT_DOMAIN)),
        ("remix", object_prefix(REMIX_DOMAIN)),
        ("tag", object_prefix(TAG_DOMAIN)),
        ("auth v2", auth_v2_prefix()),
        ("grant", statement_prefix(DOMAIN_GRANT)),
        ("epoch", statement_prefix(DOMAIN_EPOCH)),
        ("visibility", statement_prefix(DOMAIN_VISIBILITY)),
        ("url token", statement_prefix(DOMAIN_URL_TOKEN)),
        ("dsse", pae_of("t", b"p")[..PAE_PREFIX_LEN].to_vec()),
    ]
}

/// The pairs of roles where one prefix equals or extends the other.
fn collisions<'a>(roles: &[(&'a str, Vec<u8>)]) -> Vec<(&'a str, &'a str)> {
    let mut found = Vec::new();
    for (i, (name_a, a)) in roles.iter().enumerate() {
        for (name_b, b) in &roles[i + 1..] {
            if a.starts_with(b) || b.starts_with(a) {
                found.push((*name_a, *name_b));
            }
        }
    }
    found
}

#[test]
fn no_role_prefix_equals_or_extends_another() {
    let roles = roles();
    assert_eq!(roles.len(), 9);
    assert_eq!(collisions(&roles), Vec::new());
}

#[test]
fn the_dsse_prefix_does_not_depend_on_the_envelope() {
    let expected = b"DSSEv1 ".to_vec();
    assert_eq!(expected.len(), PAE_PREFIX_LEN);
    assert_eq!(pae_of("", b"")[..PAE_PREFIX_LEN], expected);
    assert_eq!(
        pae_of("application/vnd.in-toto+json", b"{}")[..PAE_PREFIX_LEN],
        expected
    );
}

#[test]
fn the_check_reports_equal_and_extending_prefixes() {
    let roles = [
        ("a", b"kit-a\n".to_vec()),
        ("b", b"kit-a\nmore".to_vec()),
        ("c", b"kit-a\n".to_vec()),
        ("d", b"kit-d\n".to_vec()),
    ];
    assert_eq!(collisions(&roles), vec![("a", "b"), ("a", "c"), ("b", "c")]);
}
