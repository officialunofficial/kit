//! Cross-check against `scripts/golden/chunk_offsets_expected.json`.
//!
//! The file holds the expected values of the chunk-offset format. A Python
//! reference wrote it from the specs, without reading this crate. The test
//! reads the file only: it never regenerates it. Every manifest, id, proof,
//! disclosure bundle and span container in the file must give here the
//! outcome the file names, and every refusal here must be the one it names.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in a test

use std::fs;
use std::path::PathBuf;

use kit_core::hash::{Hash, from_hex, hash, to_hex};
use kit_core::merkle::{self, Proof};
use kit_core::object::{KitError, Object};
use kit_core::serialize::{deserialize, serialize};
use kit_core::verify::{self, DisclosedPayload, VerifyError};
use serde_json::Value;

fn expected() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../scripts/golden/chunk_offsets_expected.json");
    serde_json::from_slice(&fs::read(path).expect("read chunk_offsets_expected.json")).unwrap()
}

fn bytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

fn id(v: &Value) -> Hash {
    from_hex(v.as_str().unwrap()).unwrap()
}

fn decimal(v: &Value) -> u64 {
    v.as_str().unwrap().parse().unwrap()
}

/// The refusal label the file gives each `KitError` of a chunked manifest.
fn manifest_label(error: &KitError) -> &'static str {
    match error {
        KitError::ChunkLengthAboveLimit { .. } => "chunk length above the object limit",
        KitError::ChunkEndAboveTotalSize { .. } => "end above total_size",
        KitError::ChunkEndNotIncreasing { .. } => "end not increasing",
        KitError::FixedChunkEnd { .. } => "fixed layout end",
        KitError::ChunkedBlobLastEnd => "last end below total_size",
        KitError::ChunkedBlobLength => "manifest length",
        KitError::TooManyChunks => "too many chunks",
        KitError::ChunkedBlobTotalSizeInvalid => "total_size above the file limit",
        KitError::ChunkedBlobNoChunks => "total_size without chunks",
        KitError::UnsupportedObjectVersion => "unsupported object version",
        _ => "other",
    }
}

fn disclosure_label(error: &VerifyError) -> String {
    match error {
        VerifyError::ChunkLengthDiffersFromSpan { .. } => {
            "blob length differs from the span".into()
        }
        VerifyError::FirstChunkStart { .. } => "index 0 and start 0 disagree".into(),
        VerifyError::LastChunkEnd { .. } => "last index and end == total_size disagree".into(),
        VerifyError::FixedChunkLength { .. } => "wrong span".into(),
        VerifyError::ChunkBytesNotBlob => "not a blob".into(),
        VerifyError::RangePastSpan { .. } => "range past the committed span".into(),
        VerifyError::SpanAboveObjectLimit { .. } => "span above the object limit".into(),
        VerifyError::SpanOutsideFile { .. } => "span outside the file".into(),
        VerifyError::UnsupportedBundleVersion(n) => format!("unsupported bundle version {n}"),
        // A span the leaf does not commit, or a proof that does not fold.
        VerifyError::InnerRootMismatch { .. }
        | VerifyError::InnerRootFoldMismatch
        | VerifyError::Merkle(_) => "does not fold".into(),
        other => format!("other: {other:?}"),
    }
}

/// Compare a verified disclosure with the summary the file gives.
fn check_disclosure(label: &str, d: &verify::Disclosed, want: &Value) {
    assert_eq!(to_hex(&d.leaf_id), want["leaf_id_hex"], "{label}: leaf");
    assert_eq!(to_hex(&d.tree_hash), want["tree_hash_hex"], "{label}: tree");
    assert_eq!(
        d.chunk_inner_root.as_ref().map(to_hex).as_deref(),
        want["chunk_inner_root_hex"].as_str(),
        "{label}: chunk inner root"
    );
    let payload = &want["payload"];
    match &d.payload {
        DisclosedPayload::Chunk {
            total_size,
            chunk_size,
            index,
            start,
            end,
            bytes,
        } => {
            assert_eq!(payload["kind"], "chunk", "{label}");
            assert_eq!(
                *total_size,
                payload["total_size"].as_u64().unwrap(),
                "{label}"
            );
            assert_eq!(
                u64::from(*chunk_size),
                payload["chunk_size"].as_u64().unwrap()
            );
            assert_eq!(
                u64::from(*index),
                payload["index"].as_u64().unwrap(),
                "{label}"
            );
            assert_eq!(*start, decimal(&payload["start"]), "{label}: start");
            assert_eq!(*end, decimal(&payload["end"]), "{label}: end");
            assert_eq!(to_hex(&hash(bytes)), payload["bytes_blake3"], "{label}");
        }
        DisclosedPayload::Range {
            blob_id,
            chunk,
            start,
            end,
            offset_in_blob,
            absolute_offset,
            bytes,
        } => {
            assert_eq!(payload["kind"], "range", "{label}");
            assert_eq!(to_hex(blob_id), payload["blob_id_hex"], "{label}");
            assert_eq!(*offset_in_blob, payload["offset_in_blob"].as_u64().unwrap());
            assert_eq!(
                *absolute_offset,
                payload["absolute_offset"].as_u64().unwrap()
            );
            assert_eq!(to_hex(&hash(bytes)), payload["bytes_blake3"], "{label}");
            let want_chunk = &payload["chunk"];
            match chunk {
                Some((index, total_size, chunk_size)) => {
                    assert_eq!(u64::from(*index), want_chunk["index"].as_u64().unwrap());
                    assert_eq!(*total_size, want_chunk["total_size"].as_u64().unwrap());
                    assert_eq!(
                        u64::from(*chunk_size),
                        want_chunk["chunk_size"].as_u64().unwrap()
                    );
                    assert_eq!(start.unwrap(), decimal(&want_chunk["start"]), "{label}");
                    assert_eq!(end.unwrap(), decimal(&want_chunk["end"]), "{label}");
                }
                None => assert!(want_chunk.is_null(), "{label}"),
            }
        }
        DisclosedPayload::Object { .. } => panic!("{label}: an object payload"),
    }
}

fn check_disclosures(name: &str, disclosures: &Value) {
    for (n, entry) in disclosures.as_array().unwrap().iter().enumerate() {
        let label = format!("{name} disclosure {n}");
        let d =
            verify::verify_disclosure(&id(&entry["commit_id_hex"]), &bytes(&entry["bundle_hex"]))
                .unwrap_or_else(|e| panic!("{label}: {e:?}"));
        check_disclosure(&label, &d, &entry["disclosed"]);
    }
}

#[test]
fn manifests_ids_and_proofs_match_the_reference() {
    for case in expected()["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let manifest = bytes(&case["manifest_hex"]);
        assert_eq!(
            manifest.len() as u64,
            case["manifest_len"].as_u64().unwrap(),
            "{name}"
        );
        let Object::ChunkedBlob(cb) =
            deserialize(&manifest).unwrap_or_else(|e| panic!("{name}: {e}"))
        else {
            panic!("{name}: not a chunked blob");
        };
        assert_eq!(
            serialize(&Object::ChunkedBlob(cb.clone())).unwrap(),
            manifest,
            "{name}"
        );
        assert_eq!(
            cb.total_size(),
            case["total_size"].as_u64().unwrap(),
            "{name}"
        );
        assert_eq!(
            u64::from(cb.chunk_size()),
            case["chunk_size"].as_u64().unwrap(),
            "{name}"
        );
        for (i, chunk) in case["chunks"].as_array().unwrap().iter().enumerate() {
            let index = u32::try_from(i).unwrap();
            let (start, end) = cb.span(index).unwrap();
            assert_eq!(
                (start, end),
                (decimal(&chunk["start"]), decimal(&chunk["end"])),
                "{name}"
            );
            assert_eq!(cb.chunks()[i], id(&chunk["chunk_id_hex"]), "{name}");
        }
        assert_eq!(
            to_hex(&merkle::chunked_inner_root(&cb)),
            case["inner_root_hex"],
            "{name}"
        );
        assert_eq!(
            to_hex(&merkle::compute_chunked_id(&cb)),
            case["chunked_id_hex"],
            "{name}"
        );
        for (kind, proof) in case["proofs"].as_object().unwrap() {
            let positions: Vec<u32> = proof["positions"]
                .as_array()
                .unwrap()
                .iter()
                .map(|p| u32::try_from(p.as_u64().unwrap()).unwrap())
                .collect();
            let built = merkle::build_chunks_multi_proof(&cb, positions.iter().copied()).unwrap();
            let want = Proof::decode(&bytes(&proof["proof_hex"]), usize::MAX).unwrap();
            assert_eq!(built.leaf_count, want.leaf_count, "{name} {kind}");
            assert_eq!(built.siblings, want.siblings, "{name} {kind}");
        }
        check_disclosures(name, &case["disclosures"]);
        for (n, span) in case["spans"].as_array().unwrap().iter().enumerate() {
            let got = verify::span::verify_disclosure_span(
                &id(&span["commit_id_hex"]),
                &bytes(&span["span_hex"]),
            )
            .unwrap_or_else(|e| panic!("{name} span {n}: {e}"));
            assert_eq!(
                got.offset,
                span["offset"].as_u64().unwrap(),
                "{name} span {n}"
            );
            assert_eq!(got.bytes.len() as u64, span["len"].as_u64().unwrap());
            assert_eq!(
                to_hex(&hash(&got.bytes)),
                span["content_blake3"],
                "{name} span {n}"
            );
            assert_eq!(u64::from(got.first), span["first_index"].as_u64().unwrap());
            assert_eq!(u64::from(got.last), span["last_index"].as_u64().unwrap());
        }
    }
}

#[test]
fn every_refused_manifest_is_refused_for_the_named_reason() {
    for case in expected()["refusals"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let error = deserialize(&bytes(&case["manifest_hex"]))
            .expect_err(&format!("{name}: must be refused"));
        let label = manifest_label(&error);
        let want = case["refused_by"].as_str().unwrap();
        assert_eq!(
            label, want,
            "{name}: refused as `{label}` ({error:?}), the file says `{want}`"
        );
    }
}

#[test]
fn overlapping_and_long_chunk_disclosures_verify() {
    let file = expected();
    check_disclosures("overlap", &file["overlap"]["disclosures"]);
    check_disclosures("long chunk", &file["long_chunk_range"]["disclosures"]);
}

#[test]
fn every_negative_disclosure_is_refused_for_the_named_reason() {
    for case in expected()["negative_disclosures"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let error =
            verify::verify_disclosure(&id(&case["commit_id_hex"]), &bytes(&case["bundle_hex"]))
                .expect_err(&format!("{name}: must be refused"));
        let want = case["refused_by"].as_str().unwrap();
        let got = disclosure_label(&error);
        assert_eq!(got, want, "{name}");
    }
}

#[test]
fn every_negative_span_is_refused_for_the_named_reason() {
    for case in expected()["negative_spans"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let mut input = bytes(&case["span_hex"]);
        // An oversize input is a short seed the file expands with zeros.
        if let Some(len) = case["expand_to"].as_u64() {
            input.resize(usize::try_from(len).unwrap(), 0);
        }
        let error = verify::span::verify_disclosure_span(&id(&case["commit_id_hex"]), &input)
            .expect_err(&format!("{name}: must be refused"));
        assert_eq!(
            error.reason(),
            case["refused_by"].as_str().unwrap(),
            "{name}"
        );
    }
}
