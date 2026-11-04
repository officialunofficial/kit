//! Pins the order in which `PackDecodeCursor` reports errors.
//!
//! Framing and claim errors surface from `new`, before the sink sees any
//! entry. A wire-cap violation of one frame surfaces from `resume` when the
//! decode reaches that frame, so an earlier frame's refusal comes first.
//! A failed decode is terminal, and a missing base leaves its frame ready to
//! retry.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::collections::HashMap;
use std::path::PathBuf;

use kit_core::delta;
use kit_core::hash::{self, Hash};
use kit_core::object::{Blob, Object};
use kit_core::pack::{DecodeLimits, DeltaBaseSource, NoExternalBases, PackDecodeCursor, PackError};

fn blob(data: &[u8]) -> Vec<u8> {
    kit_core::serialize::serialize(&Object::Blob(Blob {
        data: data.to_vec(),
    }))
    .unwrap()
}

fn id_of(bytes: &[u8]) -> Hash {
    let object = kit_core::serialize::deserialize(bytes).unwrap();
    kit_core::object::id_from_object(&object, bytes)
}

/// A pack of `(entry type, payload)` frames with a valid trailer. Nothing
/// checks the entry rules, so a test can frame a pack a reader must refuse.
fn framed(version: u32, frames: &[(u8, Vec<u8>)]) -> Vec<u8> {
    let mut pack = b"KIT\0".to_vec();
    pack.extend(version.to_le_bytes());
    pack.extend(u32::try_from(frames.len()).unwrap().to_le_bytes());
    for (etype, payload) in frames {
        pack.push(*etype);
        pack.extend(u32::try_from(payload.len()).unwrap().to_le_bytes());
        pack.extend(payload);
    }
    let trailer = hash::hash(&pack);
    pack.extend(trailer);
    pack
}

fn delta_frame(base: &[u8], target: &[u8]) -> (u8, Vec<u8>) {
    let mut payload = id_of(base).to_vec();
    payload.extend(delta::encode(base, target).unwrap());
    (0x02, payload)
}

#[derive(Default)]
struct Supplied(HashMap<Hash, Vec<u8>>);

impl DeltaBaseSource for Supplied {
    fn base(&mut self, id: &Hash) -> Result<Option<Vec<u8>>, PackError> {
        Ok(self.0.get(id).cloned())
    }
}

fn golden(name: &str) -> Vec<u8> {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.extend(["tests", "golden", "pack-v2", name]);
    std::fs::read(path).unwrap()
}

fn resume_all(
    cursor: &mut PackDecodeCursor<'_>,
    bases: &mut impl DeltaBaseSource,
    seen: &mut Vec<Hash>,
) -> Result<kit_core::pack::DecodeReport, PackError> {
    cursor.resume(bases, |entry| {
        seen.push(entry.id);
        Ok(())
    })
}

#[test]
fn framing_vectors_fail_in_new_before_any_entry() {
    for name in [
        "boundary_payload_high_bit.bin",
        "boundary_payload_u32_max.bin",
    ] {
        let pack = golden(name);
        assert!(
            matches!(
                PackDecodeCursor::new(&pack, DecodeLimits::default()),
                Err(PackError::UnexpectedEof)
            ),
            "{name}"
        );
    }
}

#[test]
fn missing_base_vector_stops_at_its_frame_and_retries_there() {
    let pack = golden("boundary_later_delta_base.bin");
    let b = blob(b"middle");
    let mut cursor = PackDecodeCursor::new(&pack, DecodeLimits::default()).unwrap();
    let mut seen = Vec::new();
    let mut hook_calls = 0usize;

    for expected_hook_calls in [2, 3] {
        let err = cursor
            .resume_checked(
                &mut NoExternalBases,
                |_| {
                    hook_calls += 1;
                    Ok(())
                },
                |entry| {
                    seen.push(entry.id);
                    Ok(())
                },
            )
            .unwrap_err();
        assert!(matches!(err, PackError::DeltaBaseMissing(_)), "{err:?}");
        // The raw frame reached the sink once. The delta runs the hook on
        // every attempt.
        assert_eq!(seen.len(), 1);
        assert_eq!(hook_calls, expected_hook_calls);
    }

    let mut supplied = Supplied::default();
    supplied.0.insert(id_of(&b), b);
    let report = resume_all(&mut cursor, &mut supplied, &mut seen).unwrap();
    assert_eq!(seen.len(), 3);
    assert_eq!((report.raw_count, report.delta_count), (1, 2));
    assert_eq!(report.ids, seen);
}

#[test]
fn a_wire_cap_is_reported_when_its_frame_is_reached() {
    let small = blob(b"a");
    let big = blob(&[7u8; 200]);
    let pack = framed(
        1,
        &[(0x00, small.clone()), (0x00, big), (0x00, b"zz".to_vec())],
    );
    let limits = DecodeLimits::default().with_entry_geometry(64, 64);
    let mut cursor = PackDecodeCursor::new(&pack, limits).unwrap();
    let mut seen = Vec::new();
    let mut hook_calls = 0usize;
    let err = cursor
        .resume_checked(
            &mut NoExternalBases,
            |_| {
                hook_calls += 1;
                Ok(())
            },
            |entry| {
                seen.push(entry.id);
                Ok(())
            },
        )
        .unwrap_err();
    assert!(matches!(err, PackError::PackfileTooLarge), "{err:?}");
    assert_eq!(seen, vec![id_of(&small)]);
    // The hook runs after a frame's cap, so the capped frame never reaches it.
    assert_eq!(hook_calls, 1);

    // A failed decode is terminal.
    let again = resume_all(&mut cursor, &mut NoExternalBases, &mut seen).unwrap_err();
    assert!(matches!(again, PackError::PackfileCorrupted), "{again:?}");
    assert_eq!(seen.len(), 1);
}

#[test]
fn an_earlier_invalid_object_comes_before_a_later_cap() {
    let big = blob(&[7u8; 200]);
    let pack = framed(1, &[(0x00, b"zz".to_vec()), (0x00, big)]);
    let limits = DecodeLimits::default().with_entry_geometry(64, 64);
    let mut cursor = PackDecodeCursor::new(&pack, limits).unwrap();
    let mut seen = Vec::new();
    let err = resume_all(&mut cursor, &mut NoExternalBases, &mut seen).unwrap_err();
    assert!(!matches!(err, PackError::PackfileTooLarge), "{err:?}");
    assert!(seen.is_empty());
}

#[test]
fn a_delta_claim_over_the_budget_fails_in_new_before_an_invalid_object() {
    let base = blob(b"base object");
    let target = blob(b"target object");
    let (etype, mut payload) = delta_frame(&base, &target);
    // The declared result length is the u32 at offset 5 of the stream.
    let stream = 32;
    payload[stream + 5..stream + 9].copy_from_slice(&1_000_000u32.to_le_bytes());
    let pack = framed(1, &[(0x00, b"zz".to_vec()), (etype, payload)]);
    let limits = DecodeLimits::default().with_max_decoded_bytes(1000);
    assert!(matches!(
        PackDecodeCursor::new(&pack, limits),
        Err(PackError::PackfileTooLarge)
    ));
}

#[test]
fn a_nonempty_pack_decodes_the_same_through_the_cursor_and_the_helper() {
    let a = blob(b"alpha alpha alpha alpha");
    let b = blob(b"alpha alpha alpha beta!");
    let pack = framed(1, &[(0x00, a.clone()), delta_frame(&a, &b)]);
    let mut cursor = PackDecodeCursor::new(&pack, DecodeLimits::default()).unwrap();
    let mut seen = Vec::new();
    let report = resume_all(&mut cursor, &mut NoExternalBases, &mut seen).unwrap();
    assert_eq!(seen, vec![id_of(&a), id_of(&b)]);
    assert_eq!(report.ids, seen);
    let mut helper_seen = Vec::new();
    let helper = kit_core::pack::decode_entries_with(
        &pack,
        &mut NoExternalBases,
        DecodeLimits::default(),
        |entry| {
            helper_seen.push(entry.id);
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(helper, report);
    assert_eq!(helper_seen, seen);
}

#[cfg(feature = "pack-zstd")]
mod compressed {
    use super::*;

    fn zstd_raw(bytes: &[u8]) -> (u8, Vec<u8>) {
        let mut payload = u32::try_from(bytes.len()).unwrap().to_le_bytes().to_vec();
        payload.extend(zstd::bulk::compress(bytes, 3).unwrap());
        (0x03, payload)
    }

    #[test]
    fn a_truncated_frame_fails_in_new_before_a_later_delta_claim_is_charged() {
        let base = blob(b"base object");
        let target = blob(b"target object");
        let (etype, mut payload) = delta_frame(&base, &target);
        payload[32 + 5..32 + 9].copy_from_slice(&1_000_000u32.to_le_bytes());
        // A claim of 4 bytes with no zstd frame behind it.
        let truncated = (0x03, 4u32.to_le_bytes().to_vec());
        let pack = framed(2, &[(etype, payload), truncated]);
        let limits = DecodeLimits::default().with_max_decoded_bytes(1000);
        let err = PackDecodeCursor::new(&pack, limits).unwrap_err();
        assert!(!matches!(err, PackError::PackfileTooLarge), "{err:?}");
    }

    #[test]
    fn a_claim_over_the_budget_fails_before_a_truncated_frame_is_decoded() {
        let big_claim = (0x03, 1_000_000u32.to_le_bytes().to_vec());
        let truncated = (0x03, 4u32.to_le_bytes().to_vec());
        let pack = framed(2, &[big_claim, truncated]);
        let limits = DecodeLimits::default().with_max_decoded_bytes(1000);
        assert!(matches!(
            PackDecodeCursor::new(&pack, limits),
            Err(PackError::PackfileTooLarge)
        ));
    }

    #[test]
    fn compressed_entries_decode_in_pack_order() {
        let a = blob(&[1u8; 300]);
        let b = blob(&[2u8; 300]);
        let c = blob(b"plain");
        let pack = framed(2, &[zstd_raw(&a), (0x00, c.clone()), zstd_raw(&b)]);
        let mut cursor = PackDecodeCursor::new(&pack, DecodeLimits::default()).unwrap();
        let mut seen = Vec::new();
        let report = resume_all(&mut cursor, &mut NoExternalBases, &mut seen).unwrap();
        assert_eq!(seen, vec![id_of(&a), id_of(&c), id_of(&b)]);
        assert_eq!(report.raw_count, 3);
    }

    #[test]
    fn a_missing_base_of_a_compressed_delta_keeps_its_stream_for_the_retry() {
        let a = blob(&[1u8; 300]);
        let c = blob(&[3u8; 300]);
        let base = blob(b"external base object");
        let target = blob(b"external base object, edited");
        let stream = delta::encode(&base, &target).unwrap();
        let mut payload = id_of(&base).to_vec();
        payload.extend(u32::try_from(stream.len()).unwrap().to_le_bytes());
        payload.extend(zstd::bulk::compress(&stream, 3).unwrap());
        let pack = framed(2, &[zstd_raw(&a), (0x04, payload), zstd_raw(&c)]);

        let mut supplied = Supplied::default();
        supplied.0.insert(id_of(&base), base.clone());
        let mut expected = Vec::new();
        let baseline = kit_core::pack::decode_entries_with(
            &pack,
            &mut supplied,
            DecodeLimits::default(),
            |entry| {
                expected.push((entry.id, entry.bytes.to_vec()));
                Ok(())
            },
        )
        .unwrap();

        let mut cursor = PackDecodeCursor::new(&pack, DecodeLimits::default()).unwrap();
        let mut seen = Vec::new();
        for _ in 0..2 {
            let err = resume_all(&mut cursor, &mut NoExternalBases, &mut seen).unwrap_err();
            assert!(matches!(err, PackError::DeltaBaseMissing(_)), "{err:?}");
            assert_eq!(seen, vec![id_of(&a)]);
        }
        let mut retried = Vec::new();
        let report = cursor
            .resume(&mut supplied, |entry| {
                retried.push((entry.id, entry.bytes.to_vec()));
                Ok(())
            })
            .unwrap();
        assert_eq!(report, baseline);
        assert_eq!(retried, expected[1..]);
        assert_eq!(retried[1].0, id_of(&c));
    }
}
