//! Ed25519 acceptance goldens (SPEC-SIGNING §1).
//!
//! `rust/tests/golden/ed25519/vectors.json` holds signatures that probe the
//! edges of the predicate: torsion components, small-order points,
//! non-canonical encodings and a non-canonical `s`. For every case:
//!
//! 1. `verify_ed25519` gives the recorded verdict.
//! 2. A batch of every accepted case verifies, and adding any rejected case
//!    to it makes the batch fail.
//!
//! `scripts/golden/ed25519_ref.py` checks the same file independently.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::fs;
use std::path::PathBuf;

use kit_core::hash::{hash, to_hex};
use kit_core::sign::{verify_ed25519, verify_ed25519_batch};

struct Case {
    name: String,
    public: [u8; 32],
    message: Vec<u8>,
    signature: [u8; 64],
    accept: bool,
}

fn golden_dir() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("tests");
    d.push("golden");
    d.push("ed25519");
    d
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn cases() -> Vec<Case> {
    let raw = fs::read(golden_dir().join("vectors.json")).unwrap();
    let manifest = fs::read_to_string(golden_dir().join("MANIFEST.txt")).unwrap();
    let pinned = manifest
        .lines()
        .find_map(|l| l.strip_prefix("vectors.json "))
        .unwrap();
    assert_eq!(
        to_hex(&hash(&raw)),
        pinned,
        "vectors.json does not match MANIFEST.txt"
    );
    let doc: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    doc["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| Case {
            name: c["name"].as_str().unwrap().to_owned(),
            public: hex(c["public"].as_str().unwrap()).try_into().unwrap(),
            message: hex(c["message"].as_str().unwrap()),
            signature: hex(c["signature"].as_str().unwrap()).try_into().unwrap(),
            accept: match c["expect"].as_str().unwrap() {
                "accept" => true,
                "reject" => false,
                other => panic!("unknown expect {other}"),
            },
        })
        .collect()
}

#[test]
fn every_case_gets_its_recorded_verdict() {
    let cases = cases();
    assert_eq!(cases.len(), 11);
    for c in &cases {
        let got = verify_ed25519(&c.public, &c.message, &c.signature).is_ok();
        assert_eq!(got, c.accept, "case {}", c.name);
    }
}

#[test]
fn batch_agrees_with_single_verification() {
    let cases = cases();
    let accepted: Vec<_> = cases
        .iter()
        .filter(|c| c.accept)
        .map(|c| (&c.public, c.message.as_slice(), &c.signature))
        .collect();
    // Fresh random weights on every call: repeat so that a weight that is a
    // multiple of 8 cannot hide a disagreement on the torsion cases.
    for _ in 0..32 {
        verify_ed25519_batch(&accepted).unwrap();
    }
    for bad in cases.iter().filter(|c| !c.accept) {
        let mut batch = accepted.clone();
        batch.push((&bad.public, bad.message.as_slice(), &bad.signature));
        assert!(
            verify_ed25519_batch(&batch).is_err(),
            "batch with {}",
            bad.name
        );
    }
}
