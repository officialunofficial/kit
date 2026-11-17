#![allow(clippy::unwrap_used)]
use kit_attest::pack;
use kit_core::hash::hash;
const ENVELOPE: &[u8] = include_bytes!("../../../tests/golden/attest/envelope_basic.json");

#[test]
fn streams_envelopes_without_installing_objects() {
    let bytes = pack::build(&[ENVELOPE], 4096).unwrap();
    let mut seen = vec![];
    pack::read(
        &mut bytes.as_slice(),
        bytes.len() as u64,
        4096,
        hash(&bytes),
        &mut pack::DecodeBudget::default(),
        |subject, id, envelope| seen.push((subject, id, envelope.to_vec())),
    )
    .unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].1, hash(ENVELOPE));
    assert_eq!(seen[0].2, ENVELOPE);
}

#[test]
fn rejects_length_and_digest_mismatches() {
    let bytes = pack::build(&[ENVELOPE], 4096).unwrap();
    for (len, cap, key) in [
        (bytes.len() as u64, 1, hash(&bytes)),
        (bytes.len() as u64, 4096, [0; 32]),
        (bytes.len() as u64 + 1, 4096, hash(&bytes)),
    ] {
        assert!(
            pack::read(
                &mut bytes.as_slice(),
                len,
                cap,
                key,
                &mut pack::DecodeBudget::default(),
                |_, _, _| {}
            )
            .is_err()
        );
    }
    let mut corrupt = bytes.clone();
    corrupt[20] ^= 1;
    assert!(
        pack::read(
            &mut corrupt.as_slice(),
            corrupt.len() as u64,
            4096,
            hash(&corrupt),
            &mut pack::DecodeBudget::default(),
            |_, _, _| {}
        )
        .is_err()
    );
}

#[test]
fn rejects_delta_and_oversized_compressed_claim_before_payload_read() {
    for (version, kind, len, claim) in [(1u32, 2u8, 1u32, None), (2, 3, 4, Some(u32::MAX))] {
        let mut bytes = b"KIT\0".to_vec();
        bytes.extend(version.to_le_bytes());
        bytes.extend(1u32.to_le_bytes());
        bytes.push(kind);
        bytes.extend(len.to_le_bytes());
        if let Some(claim) = claim {
            bytes.extend(claim.to_le_bytes());
        }
        // No payload or trailer: rejection must precede any such read.
        let err = pack::read(
            &mut bytes.as_slice(),
            100,
            100,
            [0; 32],
            &mut pack::DecodeBudget::default(),
            |_, _, _| {},
        )
        .unwrap_err();
        assert!(matches!(err, pack::PackError::Invalid(_)));
    }
}

#[test]
fn golden_pack_and_node_match() {
    let bytes = pack::build(&[ENVELOPE], 4096).unwrap();
    assert_eq!(
        bytes,
        include_bytes!("../../../tests/golden/attest/pack_basic.bin")
    );
    let node = kit_core::transfer::PackListNode {
        prev: None,
        packs: vec![hash(&bytes)],
    };
    assert_eq!(
        kit_core::transfer::encode_packlist(node.prev, &node.packs).unwrap(),
        include_bytes!("../../../tests/golden/attest/node_basic.bin")
    );
}

#[test]
fn compressed_and_raw_entries_share_the_same_envelope_contract() {
    let mut env = kit_attest::envelope::decode(ENVELOPE).unwrap();
    let mut payload: serde_json::Value = serde_json::from_slice(&env.payload).unwrap();
    payload["predicate"] = serde_json::json!({"data": "x".repeat(16_384)});
    env.payload = serde_json::to_vec(&payload).unwrap();
    let bytes = kit_attest::envelope::encode(&env).unwrap();
    let raw =
        kit_core::serialize::serialize(&kit_core::object::Object::Blob(kit_core::object::Blob {
            data: bytes.as_bytes().to_vec(),
        }))
        .unwrap();
    let mut writer = kit_core::pack::PackWriter::new();
    writer.push_raw(hash(&raw), &raw).unwrap();
    let pack = writer.finish().unwrap();
    let mut count = 0;
    pack::read(
        &mut pack.as_slice(),
        pack.len() as u64,
        32_768,
        hash(&pack),
        &mut pack::DecodeBudget::default(),
        |_, _, content| {
            assert_eq!(content, bytes.as_bytes());
            count += 1;
        },
    )
    .unwrap();
    assert_eq!(count, 1);
}

#[test]
fn non_blobs_and_invalid_envelopes_are_rejected() {
    let mut bytes = pack::build(&[ENVELOPE], 4096).unwrap();
    bytes[17] = 0x02;
    assert!(
        pack::read(
            &mut bytes.as_slice(),
            bytes.len() as u64,
            4096,
            hash(&bytes),
            &mut pack::DecodeBudget::default(),
            |_, _, _| {}
        )
        .is_err()
    );
    assert!(pack::build(&[b"{}"], 4096).is_err());
}

#[test]
fn a_pack_above_the_starting_fetch_allowance_is_rejected_not_deferred() {
    let bytes = pack::build(&[ENVELOPE], 4096).unwrap();
    for _ in 0..2 {
        let mut budget = pack::DecodeBudget::new(ENVELOPE.len() as u64 + 9);
        let mut seen = 0;
        let result = pack::read(
            &mut bytes.as_slice(),
            bytes.len() as u64,
            4096,
            hash(&bytes),
            &mut budget,
            |_, _, _| seen += 1,
        );
        assert!(matches!(result, Err(pack::PackError::Invalid(_))));
        assert_eq!(seen, 0);
    }
    let size = ENVELOPE.len() as u64 + 10;
    let mut budget = pack::DecodeBudget::new(size * 2 - 1);
    pack::read(
        &mut bytes.as_slice(),
        bytes.len() as u64,
        4096,
        hash(&bytes),
        &mut budget,
        |_, _, _| {},
    )
    .unwrap();
    assert!(matches!(
        pack::read(
            &mut bytes.as_slice(),
            bytes.len() as u64,
            4096,
            hash(&bytes),
            &mut budget,
            |_, _, _| {}
        ),
        Err(pack::PackError::FetchBudget)
    ));
}

#[test]
fn empty_pack_and_exact_wire_caps_are_accepted() {
    for envelopes in [vec![], vec![ENVELOPE], vec![ENVELOPE, ENVELOPE]] {
        let size = 44 + envelopes.iter().map(|e| e.len() as u64 + 15).sum::<u64>();
        let bytes = pack::build(&envelopes, size).unwrap();
        assert_eq!(bytes.len() as u64, size);
        assert!(matches!(
            pack::build(&envelopes, size - 1),
            Err(pack::PackError::Invalid("pack cap"))
        ));
        let mut seen = 0;
        let mut budget = pack::DecodeBudget::default();
        let initial = budget.remaining();
        pack::read(
            &mut bytes.as_slice(),
            size,
            size,
            hash(&bytes),
            &mut budget,
            |_, _, _| seen += 1,
        )
        .unwrap();
        assert_eq!(seen, envelopes.len());
        assert_eq!(
            budget.remaining(),
            initial - envelopes.iter().map(|e| e.len() as u64 + 10).sum::<u64>()
        );
    }
    assert_eq!(pack::MAX_PACK_DECODED_BYTES, 67_108_864);
    assert_eq!(pack::MAX_FETCH_DECODED_BYTES, 536_870_912);
}

#[test]
fn every_required_statement_field_is_checked_independently() {
    for (field, bad) in [
        ("_type", serde_json::json!("wrong")),
        ("predicateType", serde_json::Value::Null),
        ("predicate", serde_json::json!([])),
    ] {
        let mut env = kit_attest::envelope::decode(ENVELOPE).unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(&env.payload).unwrap();
        value[field] = bad;
        env.payload = serde_json::to_vec(&value).unwrap();
        let bytes = env.encode().unwrap();
        assert!(matches!(
            pack::build(&[bytes.as_bytes()], 4096),
            Err(pack::PackError::Invalid("in-toto statement"))
        ));
    }
}

#[test]
fn invalid_headers_are_rejected_before_reading_frames() {
    for (magic, version, count, len) in [
        (b"BAD\0", 1u32, 0u32, 44u64),
        (b"KIT\0", 3, 0, 44),
        (b"KIT\0", 1, 10_000_001, 60_000_049),
        (b"KIT\0", 1, 1, 48),
    ] {
        let mut header = magic.to_vec();
        header.extend(version.to_le_bytes());
        header.extend(count.to_le_bytes());
        assert!(matches!(
            pack::read(
                &mut header.as_slice(),
                len,
                len,
                [0; 32],
                &mut pack::DecodeBudget::default(),
                |_, _, _| {}
            ),
            Err(pack::PackError::Invalid("header"))
        ));
    }
    assert!(matches!(
        pack::read(
            &mut [].as_slice(),
            43,
            43,
            [0; 32],
            &mut pack::DecodeBudget::default(),
            |_, _, _| {}
        ),
        Err(pack::PackError::Invalid("pack length"))
    ));
}

#[test]
fn frame_kinds_and_size_bounds_are_checked_before_payload_reads() {
    let canonical_max = u32::try_from(kit_attest::store::MAX_ENVELOPE_SIZE).unwrap() + 10;
    for (version, kind, len, claim, declared, reason) in [
        (1u32, 1u8, 1u32, None, 100u64, "non-raw entry"),
        (1, 3, 4, None, 100, "non-raw entry"),
        (2, 4, 4, None, 100, "non-raw entry"),
        (1, 0, 52, None, 100, "frame cap"),
        (
            1,
            0,
            canonical_max + 1,
            None,
            u64::from(canonical_max) + 50,
            "frame cap",
        ),
        (
            2,
            3,
            canonical_max + (canonical_max >> 8) + 5,
            None,
            u64::from(canonical_max + (canonical_max >> 8) + 5) + 49,
            "frame cap",
        ),
        (2, 3, 3, None, 100, "compressed header"),
        (2, 3, 4, Some(canonical_max + 1), 100, "decoded cap"),
    ] {
        let mut bytes = b"KIT\0".to_vec();
        bytes.extend(version.to_le_bytes());
        bytes.extend(1u32.to_le_bytes());
        bytes.push(kind);
        bytes.extend(len.to_le_bytes());
        if let Some(claim) = claim {
            bytes.extend(claim.to_le_bytes());
        }
        assert!(
            matches!(pack::read(&mut bytes.as_slice(), declared, declared, [0; 32], &mut pack::DecodeBudget::default(), |_, _, _| {}), Err(pack::PackError::Invalid(r)) if r == reason),
            "{version}/{kind}/{len}/{reason}"
        );
    }
}

#[test]
fn decoded_pack_cap_accepts_the_boundary_and_rejects_the_next_entry() {
    let mut env = kit_attest::envelope::decode(ENVELOPE).unwrap();
    let target = kit_attest::store::MAX_ENVELOPE_SIZE - 10;
    let overhead = env.encode().unwrap().len();
    env.signatures[0]
        .keyid
        .push_str(&"a".repeat(target - overhead));
    let bytes = env.encode().unwrap();
    assert_eq!(bytes.len(), target);
    let envelopes = vec![bytes.as_bytes(); 64];
    let cap = 70 * 1024 * 1024;
    assert!(pack::build(&envelopes, cap).is_ok());
    let mut tail = kit_attest::envelope::decode(ENVELOPE).unwrap();
    tail.signatures[0].keyid = "k".into();
    let tail = tail.encode().unwrap();
    // A short final envelope exposes even a missing ten-byte header charge.
    assert!(tail.len() < 64 * 10);
    let mut envelopes = vec![bytes.as_bytes(); 64];
    envelopes.push(tail.as_bytes());
    assert!(matches!(
        pack::build(&envelopes, cap),
        Err(pack::PackError::Invalid("pack cap"))
    ));
}

#[test]
fn inclusive_header_and_frame_bounds_reach_the_payload_reader() {
    let mut header = b"KIT\0".to_vec();
    header.extend(1u32.to_le_bytes());
    header.extend(10_000_000u32.to_le_bytes());
    assert!(matches!(
        pack::read(
            &mut header.as_slice(),
            50_000_044,
            50_000_044,
            [0; 32],
            &mut pack::DecodeBudget::default(),
            |_, _, _| {}
        ),
        Err(pack::PackError::Io(_))
    ));
    let canonical_max = u32::try_from(kit_attest::store::MAX_ENVELOPE_SIZE).unwrap() + 10;
    for (version, kind, len, claim) in [
        (1u32, 0u8, canonical_max, None),
        (
            2,
            3,
            canonical_max + (canonical_max >> 8) + 4,
            Some(canonical_max),
        ),
    ] {
        let mut bytes = b"KIT\0".to_vec();
        bytes.extend(version.to_le_bytes());
        bytes.extend(1u32.to_le_bytes());
        bytes.push(kind);
        bytes.extend(len.to_le_bytes());
        if let Some(claim) = claim {
            bytes.extend(claim.to_le_bytes());
        }
        let declared = u64::from(len) + 49;
        assert!(matches!(
            pack::read(
                &mut bytes.as_slice(),
                declared,
                declared,
                [0; 32],
                &mut pack::DecodeBudget::default(),
                |_, _, _| {}
            ),
            Err(pack::PackError::Io(_))
        ));
    }
}

#[test]
fn exact_frame_header_space_reaches_the_reader() {
    let mut header = b"KIT\0".to_vec();
    header.extend(1u32.to_le_bytes());
    header.extend(1u32.to_le_bytes());
    assert!(matches!(
        pack::read(
            &mut header.as_slice(),
            49,
            49,
            [0; 32],
            &mut pack::DecodeBudget::default(),
            |_, _, _| {}
        ),
        Err(pack::PackError::Io(_))
    ));
}
