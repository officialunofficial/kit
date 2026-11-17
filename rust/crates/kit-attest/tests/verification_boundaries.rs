#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used)]
use kit_attest::{
    Error,
    envelope::{self, Envelope},
    jcs::{self, Member, Value},
    store,
};

fn envelope() -> Envelope {
    envelope::decode(include_bytes!(
        "../../../tests/golden/attest/envelope_basic.json"
    ))
    .unwrap()
}

#[test]
fn attestation_id_hashes_encoded_content_and_propagates_errors() {
    let mut env = envelope();
    assert_eq!(
        env.attestation_id().unwrap(),
        kit_core::hash::hash(env.encode().unwrap().as_bytes())
    );
    env.signatures.clear();
    assert!(matches!(
        env.attestation_id(),
        Err(Error::EnvelopeNeedsAtLeastOneSignature)
    ));
}

#[test]
fn every_truncated_envelope_is_rejected() {
    let bytes = envelope().encode().unwrap();
    for end in 0..bytes.len() {
        assert!(
            matches!(
                envelope::decode(&bytes.as_bytes()[..end]),
                Err(Error::MalformedEnvelope)
            ),
            "prefix {end}"
        );
    }
}

#[test]
fn envelope_size_cap_is_inclusive() {
    let mut env = envelope();
    let overhead = env.encode().unwrap().len();
    env.signatures[0]
        .keyid
        .push_str(&"a".repeat(store::MAX_ENVELOPE_SIZE - overhead));
    let bytes = env.encode().unwrap();
    assert_eq!(bytes.len(), store::MAX_ENVELOPE_SIZE);
    assert_eq!(envelope::decode(bytes.as_bytes()).unwrap(), env);
}

#[test]
fn jcs_rejects_duplicate_and_descending_keys_in_nested_objects() {
    for keys in [["a", "a"], ["b", "a"]] {
        let object = Value::Object(keys.map(|key| Member::new(key, Value::Null)).into());
        assert!(matches!(
            jcs::encode(&Value::Array(vec![object])),
            Err(Error::JcsObjectKeysUnsorted)
        ));
    }
    assert_eq!(
        jcs::encode(&Value::String("\u{1f} \u{21}".into())).unwrap(),
        "\"\\u001f !\""
    );
}

#[cfg(all(feature = "algo-p256", feature = "algo-secp256k1"))]
#[test]
fn ecdsa_registry_verdicts_distinguish_valid_invalid_and_unknown_keys() {
    use kit_attest::{
        envelope::Sig,
        verify::{self, Reason, Registry, TrustRoot},
    };
    use kit_attest::{signer::Signer, signer_k256::Secp256k1Signer, signer_p256::P256Signer};
    let p = P256Signer::from_seed_zeroizing(&zeroize::Zeroizing::new([2; 32])).unwrap();
    let k = Secp256k1Signer::from_seed_zeroizing(&zeroize::Zeroizing::new([3; 32])).unwrap();
    let mut registry = Registry::new();
    registry.add(p.keyid(), TrustRoot::P256PubKeySec1(p.public_key_sec1()));
    registry.add(
        k.keyid().unwrap(),
        TrustRoot::Secp256k1PubKeySec1(k.public_key_sec1()),
    );
    let mut signers: Vec<Box<dyn Signer>> = vec![Box::new(p), Box::new(k)];
    for signer in &mut signers {
        let mut env = envelope();
        let keyid = signer.keyid().unwrap();
        let sig = signer.sign(&env.pae()).unwrap();
        assert_eq!(sig.len(), 64);
        env.signatures = vec![Sig {
            keyid: keyid.clone(),
            sig,
        }];
        let valid = verify::verify(&env, &registry).unwrap();
        assert!(valid.any_verified);
        assert_eq!(valid.signatures[0].keyid, keyid);
        assert!(valid.signatures[0].verified);
        assert_eq!(valid.signatures[0].reason, Reason::Ok);
        env.payload.push(b' ');
        let invalid = verify::verify(&env, &registry).unwrap();
        assert!(!invalid.any_verified);
        assert!(!invalid.signatures[0].verified);
        assert_eq!(invalid.signatures[0].reason, Reason::SignatureMismatch);
        let unknown = verify::verify(&env, &Registry::new()).unwrap();
        assert!(!unknown.any_verified);
        assert_eq!(unknown.signatures[0].reason, Reason::UnknownKeyid);
    }
}

#[test]
fn storage_preserves_size_boundaries_and_io_error_kinds() {
    use kit_core::layout::RepoLayout;
    let dir = tempfile::tempdir().unwrap();
    let layout = RepoLayout::single(dir.path());
    let bytes = vec![b'x'; store::MAX_ENVELOPE_SIZE];
    let (_, path) = store::save(&layout, &[1; 32], &bytes).unwrap();
    assert_eq!(
        std::fs::metadata(path).unwrap().len(),
        store::MAX_ENVELOPE_SIZE as u64
    );
    assert!(matches!(
        store::save(&layout, &[1; 32], &vec![0; store::MAX_ENVELOPE_SIZE + 1]),
        Err(Error::EnvelopeTooLarge { .. })
    ));
    assert!(matches!(
        store::load(&dir.path().join("missing")),
        Err(Error::Io(_))
    ));
    let commit_dir = layout
        .attestations_dir()
        .join(kit_core::hash::to_hex(&[2; 32]));
    std::fs::write(&commit_dir, b"file in place of directory").unwrap();
    assert!(matches!(store::list(&layout, &[2; 32]), Err(Error::Io(_))));
    let path = store::envelope_path(&layout, &[1; 32], &[3; 32]);
    std::fs::create_dir(&path).unwrap();
    assert!(matches!(
        store::remove(&layout, &[1; 32], &[3; 32]),
        Err(Error::Io(_))
    ));
}

#[cfg(feature = "grants")]
#[test]
fn loopback_rules_preserve_numeric_host_boundaries() {
    use kit_attest::grant::{AcceptedSchemes, OwnerScheme, is_loopback_origin};
    for host in [
        "[::]",
        "[::1]",
        "[::ffff:127.0.0.1]",
        "0x",
        "0x.1",
        "127.255.255.255",
        "1.256.1",
        "1.1.1.1.1",
        "1.1.65536",
        "1.16777216",
    ] {
        assert!(is_loopback_origin(&format!("https://{host}")), "{host}");
    }
    for host in [
        "1.255.1",
        "1.1.65535",
        "1.16777215",
        "255.255.255.255",
        "[2001:db8::1]",
        "1.2.3.4",
        "1.2.3",
    ] {
        assert!(!is_loopback_origin(&format!("https://{host}")), "{host}");
    }
    let schemes = AcceptedSchemes::of(&[OwnerScheme::Ed25519, OwnerScheme::Ed25519]);
    assert!(schemes.contains(OwnerScheme::Ed25519));
    assert!(!schemes.contains(OwnerScheme::Secp256k1Eip191));
    assert!(kit_attest::grant::text::check_lifetime(0, 1, 1).is_ok());
}

#[cfg(feature = "algo-p256")]
#[test]
fn standard_base64_pae_decoder_preserves_bytes_and_rejects_invalid_data() {
    assert_eq!(
        kit_attest::webauthn::decode_pae_b64_standard("RFNTRXYx").unwrap(),
        b"DSSEv1"
    );
    assert!(matches!(
        kit_attest::webauthn::decode_pae_b64_standard("!"),
        Err(Error::WebAuthnBadClientDataJson)
    ));
}

#[test]
fn unknown_algorithm_error_names_the_rejected_prefix() {
    let err = "unknown"
        .parse::<kit_attest::algorithm::Algorithm>()
        .unwrap_err();
    assert_eq!(err.to_string(), "unknown algorithm prefix: unknown");
}

#[cfg(feature = "grants")]
#[test]
fn grant_expiry_error_precedence_preserves_zero_and_negative_boundaries() {
    use kit_attest::grant::{GrantError, text::check_lifetime};
    assert!(matches!(
        check_lifetime(0, 0, 10),
        Err(GrantError::ExpiryNotAfterCreated)
    ));
    assert!(matches!(
        check_lifetime(0, -1, 10),
        Err(GrantError::DecimalOutOfRange)
    ));
}

#[test]
fn removing_one_attestation_keeps_its_sibling() {
    let dir = tempfile::tempdir().unwrap();
    let layout = kit_core::layout::RepoLayout::single(dir.path());
    let (first, _) = store::save(&layout, &[1; 32], b"first").unwrap();
    let (_, second) = store::save(&layout, &[1; 32], b"second").unwrap();
    store::remove(&layout, &[1; 32], &first).unwrap();
    assert_eq!(store::list(&layout, &[1; 32]).unwrap(), vec![second]);
}

#[test]
fn predicate_boundary_errors_distinguish_each_missing_brace() {
    use kit_attest::statement::{self, Statement};
    for predicate in [b"{x]", b"[x}"] {
        let stmt = Statement {
            subjects: vec![],
            predicate_type: "https://example.com/p".into(),
            predicate_jcs: predicate,
        };
        assert!(matches!(
            statement::encode(&stmt),
            Err(Error::PredicateMustBeJsonObject)
        ));
    }
}

#[cfg(unix)]
#[test]
fn attestation_cleanup_propagates_unexpected_permission_errors() {
    use std::os::unix::fs::PermissionsExt;
    if std::process::Command::new("id")
        .arg("-u")
        .output()
        .unwrap()
        .stdout
        == b"0\n"
    {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let layout = kit_core::layout::RepoLayout::single(dir.path());
    let (id, _) = store::save(&layout, &[1; 32], b"first").unwrap();
    let parent = layout.attestations_dir();
    let original = std::fs::metadata(&parent).unwrap().permissions();
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o500)).unwrap();
    let result = store::remove(&layout, &[1; 32], &id);
    std::fs::set_permissions(&parent, original).unwrap();
    assert!(matches!(result, Err(Error::Io(_))));
}
