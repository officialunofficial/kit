//! The code samples of `docs/VERIFY.md` section 5 compile and run here.
//!
//! Each sample sits between `sample:begin` and `sample:end` markers in this
//! file, exactly as the document prints it. A guard test checks that the
//! document still holds the same lines, so the document and the compiled
//! code cannot drift apart.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

// The second sample runs after the first, in the same scope of imports.
use commonware_codec::{Copying, Read as _};
use commonware_cryptography::blake3::{Blake3, Digest};
use commonware_storage::bmt::Proof as UpstreamProof;
use kit_core::hash::{Hash, domain_digest, hash};
use kit_core::merkle::{
    build_tree_entry_proof, compute_tree_id, tree_entry_position, tree_inner_root,
};
use kit_core::object::{EntryMode, Tree, TreeEntry};
use kit_core::verify::Step;

type Outcome = Result<(), Box<dyn std::error::Error>>;

// sample:begin prover-supplies-the-root
fn prover_supplies_the_root(
    trusted_tree_id: Hash,
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
        domain_digest(b"kit.tree\x00", &prover_inner_root), // or b"kit.chunked\x00"
        trusted_tree_id,
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

// sample:begin v2-step
fn v2_step(step: &Step, trusted_tree_id: Hash, leaf: Hash) -> Outcome {
    assert_eq!(
        domain_digest(b"kit.tree\x00", &step.inner_root),
        trusted_tree_id,
    );
    let proof_bytes = step.proof.encode();
    let mut r = Copying(&proof_bytes[..]);
    let proof = UpstreamProof::<Digest>::read_cfg(&mut r, &1usize)?;
    proof.verify_element_inclusion::<Blake3>(
        &Digest(leaf),
        step.position,
        &Digest(step.inner_root),
    )?;
    Ok(())
}
// sample:end v2-step

struct Fixture {
    tree_id: Hash,
    inner_root: Hash,
    leaf: Hash,
    position: u32,
    step: Step,
}

fn fixture() -> Fixture {
    let entry = |name: &[u8]| TreeEntry {
        name: name.to_vec(),
        mode: EntryMode::Blob,
        object_hash: hash(name),
    };
    let tree = Tree {
        entries: vec![
            entry(b"a"),
            entry(b"b"),
            entry(b"c"),
            entry(b"d"),
            entry(b"e"),
        ],
    };
    let position = tree_entry_position(&tree, b"c").unwrap();
    let chosen = &tree.entries[position as usize];
    // SPEC-MERKLE-OBJECTS section 3: the leaf of one tree entry.
    let mut body = Vec::new();
    body.extend_from_slice(&u32::try_from(chosen.name.len()).unwrap().to_le_bytes());
    body.extend_from_slice(&chosen.name);
    body.push(chosen.mode as u8);
    body.extend_from_slice(&chosen.object_hash);
    let leaf = domain_digest(b"kit-tree-entry-v1", &body);
    let inner_root = tree_inner_root(&tree);
    let proof = build_tree_entry_proof(&tree, position).unwrap();
    Fixture {
        tree_id: compute_tree_id(&tree),
        inner_root,
        leaf,
        position,
        step: Step {
            name: chosen.name.clone(),
            mode: chosen.mode,
            child_id: chosen.object_hash,
            inner_root,
            position,
            proof,
        },
    }
}

#[test]
fn the_prover_supplied_root_sample_accepts_a_real_proof_and_rejects_a_wrong_leaf() {
    let f = fixture();
    let bytes = f.step.proof.encode();
    prover_supplies_the_root(f.tree_id, f.inner_root, f.leaf, f.position, &bytes).unwrap();
    assert!(
        prover_supplies_the_root(f.tree_id, f.inner_root, hash(b"other"), f.position, &bytes)
            .is_err()
    );
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")]
fn the_prover_supplied_root_sample_rejects_a_forged_root_before_the_proof_runs() {
    let f = fixture();
    let bytes = f.step.proof.encode();
    let forged = hash(b"forged inner root");
    let _ = prover_supplies_the_root(f.tree_id, forged, f.leaf, f.position, &bytes);
}

#[test]
fn the_v2_step_sample_accepts_a_real_proof_and_rejects_a_wrong_leaf() {
    let f = fixture();
    v2_step(&f.step, f.tree_id, f.leaf).unwrap();
    assert!(v2_step(&f.step, f.tree_id, hash(b"other")).is_err());
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
    for name in ["prover-supplies-the-root", "v2-step"] {
        let text = sample(name);
        assert!(text.lines().count() >= 8, "sample {name} is empty:\n{text}");
        assert!(
            doc.contains(&text),
            "docs/VERIFY.md no longer prints the compiled sample {name}:\n{text}"
        );
    }
}
