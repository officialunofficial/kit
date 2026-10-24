//! The repository identity grammar vector (SPEC-TRANSPORT-CONNECT §7.4).
//!
//! Each row names an identity and says whether a single-repository deployment
//! and a multi-repository deployment accept it. `scripts/golden/transport_ref.py`
//! checks the same rows against the grammar.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in tests

use kit_core::repo_identity::RepositoryIdentity;
use serde_json::Value;

#[test]
fn repository_grammar_rows_match() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/golden/transport/repository-grammar.json"
    );
    let rows: Vec<Value> = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert!(!rows.is_empty());
    for row in rows {
        let identity = row["identity"].as_str().unwrap();
        assert_eq!(
            RepositoryIdentity::parse_bare_allowed(identity).is_ok(),
            row["single_ok"].as_bool().unwrap(),
            "single-repository: {identity}"
        );
        assert_eq!(
            RepositoryIdentity::parse(identity).is_ok(),
            row["multi_ok"].as_bool().unwrap(),
            "multi-repository: {identity}"
        );
    }
}
