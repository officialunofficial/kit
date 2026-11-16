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
