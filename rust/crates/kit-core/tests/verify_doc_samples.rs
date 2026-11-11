//! The code samples of `docs/VERIFY.md` section 5 compile and run here.
//!
//! Each sample sits between `sample:begin` and `sample:end` markers in this
//! file, exactly as the document prints it. A guard test checks that the
//! document still holds the same lines, so the document and the compiled
//! code cannot drift apart.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use kit_core::hash::{Hash, hash};
use kit_core::merkle::{build_chunk_proof, chunked_inner_root, compute_chunked_id};
use kit_core::object::ChunkedBlob;

type Outcome = Result<(), Box<dyn std::error::Error>>;

// sample:begin prover-supplies-the-root
fn prover_supplies_the_root(
    trusted_chunked_id: Hash,
    prover_inner_root: Hash,
    leaf: Hash,
    position: u32,
    proof_bytes: &[u8],
) -> Outcome {
    use commonware_codec::{Copying, Read as _};
    use commonware_cryptography::blake3::{Blake3, Digest};
    use commonware_storage::bmt::Proof as UpstreamProof;
    use kit_core::hash::domain_digest;

    assert_eq!(
        domain_digest(b"kit.chunked\x00", &prover_inner_root),
        trusted_chunked_id,
    );

    let mut r = Copying(proof_bytes);
    let proof = UpstreamProof::<Digest>::read_cfg(&mut r, &1usize)?;
    proof.verify_element_inclusion::<Blake3>(
        &Digest(leaf),
        position,
        &Digest(prover_inner_root),
    )?;
    Ok(())
}
// sample:end prover-supplies-the-root

struct Fixture {
    chunked_id: Hash,
    inner_root: Hash,
    leaf: Hash,
    position: u32,
    proof_bytes: Vec<u8>,
}

fn fixture() -> Fixture {
    let chunks: Vec<Hash> = [b"a", b"b", b"c", b"d", b"e"]
        .iter()
        .map(|c| hash(*c))
        .collect();
    let cb = ChunkedBlob {
        total_size: 5 * 65_536,
        chunk_size: 0,
        chunks,
    };
    // SPEC-MERKLE-OBJECTS section 3.1: chunk 2 is at position 3.
    let position = 3;
    Fixture {
        chunked_id: compute_chunked_id(&cb),
        inner_root: chunked_inner_root(&cb),
        leaf: cb.chunks[2],
        position,
        proof_bytes: build_chunk_proof(&cb, position).unwrap().encode(),
    }
}

#[test]
fn the_prover_supplied_root_sample_accepts_a_real_proof_and_rejects_a_wrong_leaf() {
    let f = fixture();
    prover_supplies_the_root(
        f.chunked_id,
        f.inner_root,
        f.leaf,
        f.position,
        &f.proof_bytes,
    )
    .unwrap();
    assert!(
        prover_supplies_the_root(
            f.chunked_id,
            f.inner_root,
            hash(b"other"),
            f.position,
            &f.proof_bytes
        )
        .is_err()
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")]
fn the_prover_supplied_root_sample_rejects_a_forged_root_before_the_proof_runs() {
    let f = fixture();
    let forged = hash(b"forged inner root");
    let _ = prover_supplies_the_root(f.chunked_id, forged, f.leaf, f.position, &f.proof_bytes);
}

/// Code lines only: no blank lines, no comment lines, no indentation.
fn code_lines(text: &str) -> String {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The lines of the sample between its markers, minus the function frame.
fn sample(name: &str) -> String {
    let source = include_str!("verify_doc_samples.rs");
    let begin = format!("// sample:begin {name}");
    let end = format!("// sample:end {name}");
    let start = source.find(&begin).unwrap() + begin.len();
    let stop = source.find(&end).unwrap();
    let body = &source[start..stop];
    // Drop the `fn` header and the closing `Ok(())` and brace, which the
    // document leaves out because its samples are statements.
    let open = body.find("{\n").unwrap() + 2;
    let close = body.rfind("Ok(())").unwrap();
    code_lines(&body[open..close])
}

#[test]
fn the_document_prints_the_compiled_samples() {
    let doc = code_lines(include_str!("../../../../docs/VERIFY.md"));
    let text = sample("prover-supplies-the-root");
    assert!(text.lines().count() >= 8, "the sample is empty:\n{text}");
    assert!(
        doc.contains(&text),
        "docs/VERIFY.md no longer prints the compiled sample:\n{text}"
    );
}
