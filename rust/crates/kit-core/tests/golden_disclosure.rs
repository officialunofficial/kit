//! Golden vectors for the SPEC-DISCLOSURE.md partial-disclosure bundle.
//!
//! Like `golden_proofs.rs`, this file is deliberately two independent
//! halves:
//!
//! * [`write_all`] (run via `KIT_WRITE_GOLDEN=1`) builds a deterministic
//!   fixture repo, assembles every vector, and (re)writes the `.bin`/
//!   `.json`/`MANIFEST.txt` files under `rust/tests/golden/disclosure/`.
//! * `golden_disclosure_vectors_verify` reads ONLY the committed files —
//!   never the generator — and replays the accept/reject check an
//!   independent verifier built from SPEC-DISCLOSURE.md plus these
//!   vectors would perform. This is what runs in CI.
//!
//! Every reject vector's bytes are assembled by [`wire`], a from-scratch
//! encoder over `commonware-codec` public primitives — not by tampering
//! with `kit_core::verify`'s private wire types (there are none reachable
//! from an external test crate; see that module's docs on why `Step` is
//! public but the payload's wire shape is not). This mirrors exactly what
//! an independent, non-Rust verifier's own vector generator would need to
//! do, per acceptance criteria.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;

use commonware_codec::Write as CodecWrite;
use kit_core::hash::{Hash, ZERO, hash, to_hex};
use kit_core::merkle;
use kit_core::object::{Commit, EntryMode, Identity, Object, Tree, TreeEntry};
use kit_core::sign::{KeyPair, sign_commit};
use kit_core::store::ObjectStore;
use kit_core::verify::{self, Disclosed, DisclosedPayload, Selector, Step, VerifyError};
use serde_json::{Value, json};

mod common;

fn golden_root() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop(); // crates/
    d.pop(); // rust/
    d.push("tests");
    d.push("golden");
    d
}

fn disclosure_dir() -> PathBuf {
    golden_root().join("disclosure")
}

fn writing() -> bool {
    std::env::var("KIT_WRITE_GOLDEN").is_ok()
}

// ---------------------------------------------------------------------------
// From-scratch wire encoder (commonware-codec public primitives only).
// ---------------------------------------------------------------------------

mod wire {
    use super::CodecWrite;
    use kit_core::hash::Hash;
    use kit_core::merkle::Proof;
    use kit_core::verify::Step;

    pub(crate) fn bundle(
        commit_id: &Hash,
        commit_bytes: &[u8],
        steps: &[Step],
        payload: &[u8],
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"KDPB");
        out.push(3u8);
        commit_id.write(&mut out);
        commit_bytes.write(&mut out);
        steps.write(&mut out);
        out.extend_from_slice(payload);
        out
    }

    pub(crate) fn object_payload(bytes: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8];
        bytes.write(&mut out);
        out
    }

    /// A chunk with the span its leaf commits (SPEC-DISCLOSURE §3).
    pub(crate) struct Span {
        pub(crate) start: u64,
        pub(crate) end: u64,
    }

    pub(crate) struct ChunkFields<'a> {
        pub(crate) total_size: u64,
        pub(crate) chunk_size: u32,
        pub(crate) index: u32,
        pub(crate) span: Span,
        pub(crate) inner_root: &'a Hash,
        pub(crate) proof: &'a Proof,
    }

    pub(crate) fn chunk_payload(fields: &ChunkFields<'_>, bytes: &[u8]) -> Vec<u8> {
        let mut out = vec![1u8];
        fields.total_size.write(&mut out);
        fields.chunk_size.write(&mut out);
        fields.index.write(&mut out);
        fields.span.start.write(&mut out);
        fields.span.end.write(&mut out);
        fields.inner_root.write(&mut out);
        fields.proof.write(&mut out);
        bytes.write(&mut out);
        out
    }

    /// Range payload's `ChunkHdr` sub-message fields (SPEC-DISCLOSURE §3).
    pub(crate) struct ChunkHdr<'a> {
        pub(crate) fields: ChunkFields<'a>,
        pub(crate) chunk_id: Hash,
    }

    pub(crate) fn range_payload(
        chunk: Option<&ChunkHdr<'_>>,
        offset_in_blob: u64,
        len: u64,
        slice: &[u8],
    ) -> Vec<u8> {
        let mut out = vec![2u8];
        match chunk {
            None => false.write(&mut out),
            Some(c) => {
                true.write(&mut out);
                c.fields.total_size.write(&mut out);
                c.fields.chunk_size.write(&mut out);
                c.fields.index.write(&mut out);
                c.fields.span.start.write(&mut out);
                c.fields.span.end.write(&mut out);
                c.fields.inner_root.write(&mut out);
                c.chunk_id.write(&mut out);
                c.fields.proof.write(&mut out);
            }
        }
        offset_in_blob.write(&mut out);
        len.write(&mut out);
        slice.write(&mut out);
        out
    }
}

/// A chunked-file id built from leaves alone, the way a forged tree names an
/// id no manifest decodes to (SPEC-MERKLE-OBJECTS §1.1 and §3.1). Written
/// from the spec, with no call into `kit_core`'s tree code, so a vector can
/// name a span the manifest rules would refuse and still carry a proof that
/// folds to the id.
mod forge {
    use kit_core::hash::{Hash, domain_digest, hash};
    use kit_core::merkle::{ObjectKind, Proof, wrap_id};

    pub(crate) fn meta_leaf(total_size: u64, chunk_size: u32) -> Hash {
        let mut body = total_size.to_le_bytes().to_vec();
        body.extend_from_slice(&chunk_size.to_le_bytes());
        domain_digest(b"kit-cblob-meta-v2", &body)
    }

    pub(crate) fn chunk_leaf(start: u64, end: u64, id: &Hash) -> Hash {
        let mut body = start.to_le_bytes().to_vec();
        body.extend_from_slice(&end.to_le_bytes());
        body.extend_from_slice(id);
        domain_digest(b"kit-cblob-chunk-v1", &body)
    }

    fn node(position: u32, leaf: &Hash) -> Hash {
        let mut body = position.to_be_bytes().to_vec();
        body.extend_from_slice(leaf);
        hash(&body)
    }

    fn pair(left: &Hash, right: &Hash) -> Hash {
        let mut body = left.to_vec();
        body.extend_from_slice(right);
        hash(&body)
    }

    /// The bare root of the BMT over `leaves`.
    pub(crate) fn inner_root(leaves: &[Hash]) -> Hash {
        let mut level: Vec<Hash> = (0u32..).zip(leaves).map(|(i, l)| node(i, l)).collect();
        while level.len() > 1 {
            if level.len() % 2 == 1 {
                level.push(*level.last().unwrap());
            }
            level = level.chunks(2).map(|p| pair(&p[0], &p[1])).collect();
        }
        let mut body = u32::try_from(leaves.len()).unwrap().to_be_bytes().to_vec();
        body.extend_from_slice(&level[0]);
        hash(&body)
    }

    pub(crate) fn chunked_id(inner_root: &Hash) -> Hash {
        wrap_id(ObjectKind::ChunkedBlob, inner_root)
    }

    /// The multi-proof of `positions` over `leaves`.
    pub(crate) fn proof(leaves: &[Hash], positions: &[u32]) -> Proof {
        let mut level: Vec<Hash> = (0u32..).zip(leaves).map(|(i, l)| node(i, l)).collect();
        let mut known: Vec<usize> = positions.iter().map(|&p| p as usize).collect();
        known.sort_unstable();
        known.dedup();
        let mut siblings = Vec::new();
        while level.len() > 1 {
            let size = level.len();
            let mut parents = Vec::new();
            for &pos in &known {
                let sib = if pos % 2 == 0 {
                    if pos + 1 < size { pos + 1 } else { pos }
                } else {
                    pos - 1
                };
                if sib != pos && !known.contains(&sib) {
                    siblings.push(level[sib]);
                }
                parents.push(pos / 2);
            }
            parents.dedup();
            if size % 2 == 1 {
                level.push(*level.last().unwrap());
            }
            level = level.chunks(2).map(|p| pair(&p[0], &p[1])).collect();
            known = parents;
        }
        Proof {
            leaf_count: u32::try_from(leaves.len()).unwrap(),
            siblings,
        }
    }
}

use common::build_fixture;

/// A signed commit over one file `name` whose id is `file_id`. The commit,
/// signer and timestamp are fixed, so the vectors stay byte-identical.
fn commit_over_file(store: &ObjectStore, name: &[u8], file_id: Hash) -> Hash {
    use kit_core::hash::ZERO;
    use kit_core::serialize::serialize;
    use kit_core::sign::{KeyPair, sign_commit};

    let tree = Tree {
        entries: vec![TreeEntry {
            name: name.to_vec(),
            mode: EntryMode::Blob,
            object_hash: file_id,
        }],
    };
    let tree_hash = store
        .write(&serialize(&Object::Tree(tree)).unwrap())
        .unwrap();
    let kp = KeyPair::from_seed([0x11; 32]);
    let mut commit = Commit {
        tree_hash,
        parents: vec![],
        author: Identity::ed25519(kp.public.0),
        signer: kp.public.0,
        message: b"SPEC-DISCLOSURE chunk span fixture".to_vec(),
        timestamp: 1_726_300_000,
        message_hash: ZERO,
        content_digest: ZERO,
        signature: [0u8; 64],
    };
    commit.signature = sign_commit(&commit, &kp).unwrap().0;
    store
        .write(&serialize(&Object::Commit(commit)).unwrap())
        .unwrap()
}

/// Write one chunk blob of `len` deterministic bytes, returning its id and
/// canonical bytes. `seed` makes two chunks of one length differ.
fn write_chunk(store: &ObjectStore, seed: u64, len: usize) -> (Hash, Vec<u8>) {
    let blob = Object::Blob(kit_core::object::Blob {
        data: common::prng_bytes(0xF1_7ED5 + seed, len),
    });
    let bytes = kit_core::serialize::serialize(&blob).unwrap();
    (store.write(&bytes).unwrap(), bytes)
}

/// A signed commit over one file, `fixed.bin`, whose manifest names the
/// fixed-size layout `chunk_size = 16` and `total_size = 53` (four chunks of
/// 16, 16, 16 and 5 bytes) while its chunk blobs hold `lens` bytes each.
fn fixed_layout_commit(lens: &[usize]) -> (tempfile::TempDir, ObjectStore, Hash) {
    let (dir, store, commit_id, _) = layout_commit(16, &[16, 16, 16, 5], lens);
    (dir, store, commit_id)
}

/// A signed commit over one file, `fixed.bin`, whose valid manifest has
/// the spans `span_lens` under `chunk_size`, while its chunk blobs hold
/// `lens` bytes each. Returns the chunk ids too.
fn layout_commit(
    chunk_size: u32,
    span_lens: &[u64],
    lens: &[usize],
) -> (tempfile::TempDir, ObjectStore, Hash, Vec<Hash>) {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let store = ObjectStore::init(&kit_core::layout::RepoLayout::single(dir.path())).unwrap();
    let chunks: Vec<Hash> = lens
        .iter()
        .enumerate()
        .map(|(i, &n)| write_chunk(&store, i as u64, n).0)
        .collect();
    let mut end = 0;
    let manifest = kit_core::object::ChunkedBlob::new(
        span_lens.iter().sum(),
        chunk_size,
        chunks.iter().zip(span_lens).map(|(&id, &len)| {
            end += len;
            (id, end)
        }),
    )
    .unwrap();
    let file = store
        .write(&kit_core::serialize::serialize(&Object::ChunkedBlob(manifest)).unwrap())
        .unwrap();
    let commit_id = commit_over_file(&store, b"fixed.bin", file);
    (dir, store, commit_id, chunks)
}

/// The `ChunkedBlob` the one file of a `layout_commit` commit names.
fn layout_manifest(store: &ObjectStore, commit_id: &Hash) -> kit_core::object::ChunkedBlob {
    let tree_hash = tree_of_commit(store, commit_id);
    let (_, leaf) = walk_path(store, tree_hash, &[b"fixed.bin".as_slice()]);
    let Object::ChunkedBlob(cb) = store.read_object(&leaf).unwrap() else {
        panic!("fixed.bin is a ChunkedBlob");
    };
    cb
}

/// A bundle over `fixed.bin` of a `layout_commit` commit with `payload`.
fn layout_bundle(store: &ObjectStore, commit_id: &Hash, payload: &[u8]) -> Vec<u8> {
    let tree_hash = tree_of_commit(store, commit_id);
    let (steps, _) = walk_path(store, tree_hash, &[b"fixed.bin".as_slice()]);
    wire::bundle(
        commit_id,
        &canonical_bytes(store, commit_id),
        &steps,
        payload,
    )
}

/// A chunked file whose spans are committed as given, whatever the manifest
/// rules say, and one disclosed chunk of it.
struct Forged<'a> {
    name: &'static str,
    description: &'static str,
    total_size: u64,
    chunk_size: u32,
    spans: &'a [(u64, u64)],
    /// Each chunk blob's length; only the disclosed chunk's bytes are shipped.
    blob_lens: &'a [usize],
    index: u32,
    /// `None` for a vector the verifier must accept.
    reason: Option<&'static str>,
}

/// Build the `Chunk` disclosure of `forged`, with a proof that folds to the
/// id its leaves name. `refused_by` recognises the error a reject vector
/// must fail with; an accept vector never calls it.
fn forged_chunk_vector(
    forged: &Forged<'_>,
    raw_bytes: Option<&[u8]>,
    refused_by: impl Fn(&VerifyError) -> bool,
) -> Vector {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let store = ObjectStore::init(&kit_core::layout::RepoLayout::single(dir.path())).unwrap();
    let mut ids: Vec<Hash> = forged
        .blob_lens
        .iter()
        .enumerate()
        .map(|(i, &n)| write_chunk(&store, i as u64, n).0)
        .collect();
    // A chunk id is the hash of its bytes whatever they are, so a forged tree
    // can name bytes that are not a Blob.
    if let Some(raw) = raw_bytes {
        ids[forged.index as usize] = hash(raw);
    }
    let mut leaves = vec![forge::meta_leaf(forged.total_size, forged.chunk_size)];
    leaves.extend(
        forged
            .spans
            .iter()
            .zip(&ids)
            .map(|(&(start, end), id)| forge::chunk_leaf(start, end, id)),
    );
    let inner_root = forge::inner_root(&leaves);
    let commit_id = commit_over_file(&store, b"fixed.bin", forge::chunked_id(&inner_root));
    let index = forged.index as usize;
    let (start, end) = forged.spans[index];
    let proof = forge::proof(&leaves, &[0, forged.index + 1]);
    let bin = layout_bundle(
        &store,
        &commit_id,
        &wire::chunk_payload(
            &wire::ChunkFields {
                total_size: forged.total_size,
                chunk_size: forged.chunk_size,
                index: forged.index,
                span: wire::Span { start, end },
                inner_root: &inner_root,
                proof: &proof,
            },
            &raw_bytes.map_or_else(|| canonical_bytes(&store, &ids[index]), <[u8]>::to_vec),
        ),
    );
    let path = [b"fixed.bin".as_slice()];
    let selector = format!("chunk({})", forged.index);
    let mut json = base_json(
        &commit_id,
        &path,
        &selector,
        forged.reason.is_none(),
        forged.reason,
    );
    match verify::verify_disclosure(&commit_id, &bin) {
        Ok(d) => {
            assert!(forged.reason.is_none(), "{} must be rejected", forged.name);
            json.as_object_mut()
                .unwrap()
                .insert("disclosed".into(), disclosed_summary(&d));
        }
        Err(e) => assert!(
            forged.reason.is_some() && refused_by(&e),
            "{}: {e:?}",
            forged.name
        ),
    }
    Vector {
        name: forged.name,
        description: forged.description,
        bin,
        json,
    }
}

/// The spec-written `forge` fold agrees with `kit_core`'s on a manifest both
/// can build, so a forged id is the id a real tree would carry.
#[test]
fn forge_matches_the_real_fold() {
    let (_dir, store, commit_id, ids) = layout_commit(16, &[16, 16, 16, 5], &[16, 16, 16, 5]);
    let cb = layout_manifest(&store, &commit_id);
    let mut leaves = vec![forge::meta_leaf(53, 16)];
    let mut start = 0;
    for (i, id) in ids.iter().enumerate() {
        let end = cb.span(u32::try_from(i).unwrap()).unwrap().1;
        leaves.push(forge::chunk_leaf(start, end, id));
        start = end;
    }
    assert_eq!(forge::inner_root(&leaves), merkle::chunked_inner_root(&cb));
    let mine = forge::proof(&leaves, &[0, 3]);
    let real = merkle::build_chunks_multi_proof(&cb, [0, 3]).unwrap();
    assert_eq!(mine.leaf_count, real.leaf_count);
    assert_eq!(mine.siblings, real.siblings);
}

/// Walk `path` from the fixture's root tree, independently of
/// `verify::build_disclosure`, returning the authenticated `Step`s and
/// the leaf id. Used by every vector builder below so reject vectors can
/// mutate one ingredient (a step, a payload field) while every other
/// piece is genuinely valid.
fn walk_path(store: &ObjectStore, tree_hash: Hash, path: &[&[u8]]) -> (Vec<Step>, Hash) {
    let mut steps = Vec::with_capacity(path.len());
    let mut current = tree_hash;
    let mut leaf = tree_hash;
    for &name in path {
        let Object::Tree(tree) = store.read_object(&current).unwrap() else {
            panic!("path component is not under a Tree");
        };
        let position = merkle::tree_entry_position(&tree, name).expect("entry present");
        let entry = tree.entries[position as usize].clone();
        let proof = merkle::build_tree_entry_proof(&tree, position).unwrap();
        steps.push(Step {
            name: name.to_vec(),
            mode: entry.mode,
            child_id: entry.object_hash,
            inner_root: merkle::tree_inner_root(&tree),
            position,
            proof,
        });
        leaf = entry.object_hash;
        if entry.mode == EntryMode::Tree {
            current = entry.object_hash;
        }
    }
    (steps, leaf)
}

fn bao_slice(canonical: &[u8], bao_offset: u64, len: u64) -> Vec<u8> {
    let (outboard, _root) = bao::encode::outboard(canonical);
    let mut extractor = bao::encode::SliceExtractor::new_outboard(
        std::io::Cursor::new(canonical),
        std::io::Cursor::new(outboard),
        bao_offset,
        len,
    );
    let mut out = Vec::new();
    std::io::Read::read_to_end(&mut extractor, &mut out).unwrap();
    out
}

fn canonical_bytes(store: &ObjectStore, id: &Hash) -> Vec<u8> {
    store.read(id).unwrap()
}

// ---------------------------------------------------------------------------
// Vector assembly
// ---------------------------------------------------------------------------

struct Vector {
    name: &'static str,
    description: &'static str,
    bin: Vec<u8>,
    json: Value,
}

fn hex_path(path: &[&[u8]]) -> Vec<String> {
    path.iter().map(hex::encode).collect()
}

fn base_json(
    commit_id: &Hash,
    path: &[&[u8]],
    selector_desc: &str,
    expect_accept: bool,
    reject_reason: Option<&'static str>,
) -> Value {
    let mut v = json!({
        "commit_id_hex": to_hex(commit_id),
        "path_hex": hex_path(path),
        "selector": selector_desc,
        "expect": if expect_accept { "accept" } else { "reject" },
    });
    if let Some(r) = reject_reason {
        v.as_object_mut()
            .unwrap()
            .insert("reject_reason".into(), json!(r));
    }
    v
}

fn disclosed_summary(d: &Disclosed) -> Value {
    let path: Vec<Value> = d
        .path
        .iter()
        .map(|(name, mode)| json!({"name_hex": hex::encode(name), "mode": *mode as u8}))
        .collect();
    let payload = match &d.payload {
        DisclosedPayload::Object { bytes } => json!({
            "kind": "object",
            "bytes_blake3": to_hex(&hash(bytes)),
            "len": bytes.len(),
        }),
        DisclosedPayload::Chunk {
            total_size,
            chunk_size,
            index,
            start,
            end,
            bytes,
        } => json!({
            "kind": "chunk",
            "total_size": total_size,
            "chunk_size": chunk_size,
            "index": index,
            // Span values are decimal strings: a JSON number loses precision
            // near `u64::MAX`.
            "start": start.to_string(),
            "end": end.to_string(),
            "bytes_blake3": to_hex(&hash(bytes)),
            "len": bytes.len(),
        }),
        DisclosedPayload::Range {
            blob_id,
            chunk,
            start,
            end,
            offset_in_blob,
            absolute_offset,
            bytes,
        } => json!({
            "kind": "range",
            "blob_id_hex": to_hex(blob_id),
            "chunk": chunk.map(|(idx, ts, cs)| json!({
                "index": idx,
                "total_size": ts,
                "chunk_size": cs,
                "start": start.unwrap().to_string(),
                "end": end.unwrap().to_string(),
            })),
            "offset_in_blob": offset_in_blob,
            "absolute_offset": absolute_offset,
            "bytes_blake3": to_hex(&hash(bytes)),
            "len": bytes.len(),
        }),
    };
    json!({
        "tree_hash_hex": to_hex(&d.tree_hash),
        "leaf_id_hex": to_hex(&d.leaf_id),
        "path": path,
        "payload": payload,
        "signer_hex": to_hex(&d.signer),
        "signature_valid": d.signature_valid,
        "step_inner_roots_hex": d.step_inner_roots.iter().map(to_hex).collect::<Vec<_>>(),
        "chunk_inner_root_hex": d.chunk_inner_root.as_ref().map(to_hex),
    })
}

/// A signed commit whose tree has one entry `x` of `mode` naming `target`.
fn commit_with_entry(store: &ObjectStore, mode: EntryMode, target: Hash) -> Hash {
    let tree = Tree {
        entries: vec![TreeEntry {
            name: b"x".to_vec(),
            mode,
            object_hash: target,
        }],
    };
    let tree_hash = store
        .write(&kit_core::serialize::serialize(&Object::Tree(tree)).unwrap())
        .unwrap();
    let kp = KeyPair::from_seed([0x23; 32]);
    let mut commit = Commit {
        tree_hash,
        parents: vec![],
        author: Identity::ed25519(kp.public.0),
        signer: kp.public.0,
        message: b"SPEC-DISCLOSURE entry mode vector".to_vec(),
        timestamp: 1_726_400_000,
        message_hash: ZERO,
        content_digest: ZERO,
        signature: [0u8; 64],
    };
    commit.signature = sign_commit(&commit, &kp).unwrap().0;
    store
        .write(&kit_core::serialize::serialize(&Object::Commit(commit)).unwrap())
        .unwrap()
}

fn tree_of_commit(store: &ObjectStore, commit_id: &Hash) -> Hash {
    let Object::Commit(commit) = store.read_object(commit_id).unwrap() else {
        panic!("expected a commit");
    };
    commit.tree_hash
}

#[allow(clippy::too_many_lines)] // one block per golden vector, kept together for auditability
fn build_vectors() -> Vec<Vector> {
    let f = build_fixture();
    let mut v = Vec::new();

    // ---- accept: Object over increasingly deep paths ----

    for (name, description, path) in [
        (
            "root_tree",
            "The commit's root tree, disclosed directly (empty path).",
            Vec::<&[u8]>::new(),
        ),
        (
            "shallow_file",
            "A file directly under the root.",
            vec![b"shallow.txt".as_slice()],
        ),
        (
            "nested_file_3levels",
            "A file 3 directory levels deep.",
            vec![
                b"sub".as_slice(),
                b"deep".as_slice(),
                b"deep.txt".as_slice(),
            ],
        ),
        (
            "executable_file",
            "A file with the Executable entry mode.",
            vec![b"exec.sh".as_slice()],
        ),
    ] {
        let bundle =
            verify::build_disclosure(&f.store, &f.commit_id, &path, Selector::Object).unwrap();
        let d = verify::verify_disclosure(&f.commit_id, &bundle).unwrap();
        let mut j = base_json(&f.commit_id, &path, "object", true, None);
        j.as_object_mut()
            .unwrap()
            .insert("disclosed".into(), disclosed_summary(&d));
        v.push(Vector {
            name,
            description,
            bin: bundle,
            json: j,
        });
    }

    // ---- accept: chunks of the chunked file: first, middle and last ----

    let chunked_path = [b"chunked.bin".as_slice()];
    let chunk_count = {
        let Object::ChunkedBlob(cb) = f
            .store
            .read_object(&walk_path(&f.store, f.tree_hash, &chunked_path).1)
            .unwrap()
        else {
            panic!("chunked.bin is a ChunkedBlob");
        };
        u32::try_from(cb.chunks().len()).unwrap()
    };
    assert!(
        chunk_count >= 3,
        "fixture needs a first, middle and last chunk"
    );
    for (name, description, index) in [
        (
            "chunked_file_chunk0",
            "Chunk index 0 of the chunked file: it starts at offset 0.",
            0,
        ),
        (
            "chunked_file_chunk1",
            "Chunk index 1 of the chunked file, a middle chunk.",
            1,
        ),
        (
            "chunked_file_chunk_last",
            "The last chunk of the chunked file: it ends at total_size.",
            chunk_count - 1,
        ),
    ] {
        let bundle = verify::build_disclosure(
            &f.store,
            &f.commit_id,
            &chunked_path,
            Selector::Chunk(index),
        )
        .unwrap();
        let d = verify::verify_disclosure(&f.commit_id, &bundle).unwrap();
        let mut j = base_json(
            &f.commit_id,
            &chunked_path,
            &format!("chunk({index})"),
            true,
            None,
        );
        j.as_object_mut()
            .unwrap()
            .insert("disclosed".into(), disclosed_summary(&d));
        v.push(Vector {
            name,
            description,
            bin: bundle,
            json: j,
        });
    }

    // ---- accept: a range inside a chunk ----

    // An offset inside a chunk other than chunk 0, so the absolute offset
    // is the committed start plus the offset in the chunk.
    let range_offset: u64 = {
        let Object::ChunkedBlob(cb) = f
            .store
            .read_object(&walk_path(&f.store, f.tree_hash, &chunked_path).1)
            .unwrap()
        else {
            panic!("chunked.bin is a ChunkedBlob");
        };
        cb.span(0).unwrap().1 + 32
    };
    {
        let bundle = verify::build_disclosure(
            &f.store,
            &f.commit_id,
            &chunked_path,
            Selector::Range {
                offset: range_offset,
                len: 64,
            },
        )
        .unwrap();
        let d = verify::verify_disclosure(&f.commit_id, &bundle).unwrap();
        let mut j = base_json(
            &f.commit_id,
            &chunked_path,
            &format!("range(offset={range_offset},len=64)"),
            true,
            None,
        );
        j.as_object_mut()
            .unwrap()
            .insert("disclosed".into(), disclosed_summary(&d));
        v.push(Vector {
            name: "chunked_range",
            description: "A 64-byte range inside a non-first chunk; the absolute offset is the committed start of the chunk plus the offset in it.",
            bin: bundle,
            json: j,
        });
    }

    // ---- accept: ranges over a small (multi-Bao-block) blob ----

    let range_path = [b"range.bin".as_slice()];
    for (name, description, offset, len) in [
        (
            "small_blob_range_first_block",
            "The first 1 KiB Bao block of a 1536-byte blob.",
            0u64,
            1024u64,
        ),
        (
            "small_blob_range_last_partial_block",
            "The final, partial (< 1 KiB) Bao block of the same blob.",
            1024u64,
            (f.range_blob.len() as u64) - 1024,
        ),
        (
            "small_blob_range_whole",
            "The entire small blob, as one range.",
            0u64,
            f.range_blob.len() as u64,
        ),
    ] {
        let bundle = verify::build_disclosure(
            &f.store,
            &f.commit_id,
            &range_path,
            Selector::Range { offset, len },
        )
        .unwrap();
        let d = verify::verify_disclosure(&f.commit_id, &bundle).unwrap();
        let mut j = base_json(
            &f.commit_id,
            &range_path,
            &format!("range(offset={offset},len={len})"),
            true,
            None,
        );
        j.as_object_mut()
            .unwrap()
            .insert("disclosed".into(), disclosed_summary(&d));
        v.push(Vector {
            name,
            description,
            bin: bundle,
            json: j,
        });
    }

    // ---- reject vectors ----

    // 1. Non-tree intermediate mode: the middle step of the 3-level path,
    //    with its mode overwritten to Blob (a structurally valid step,
    //    but not the final one).
    {
        let (mut steps, leaf) = walk_path(&f.store, f.tree_hash, &[b"sub", b"deep", b"deep.txt"]);
        steps[1].mode = EntryMode::Blob;
        let bytes = canonical_bytes(&f.store, &leaf);
        let commit_bytes = canonical_bytes(&f.store, &f.commit_id);
        let bin = wire::bundle(
            &f.commit_id,
            &commit_bytes,
            &steps,
            &wire::object_payload(&bytes),
        );
        v.push(Vector {
            name: "neg_non_tree_intermediate_mode",
            description: "The 2nd of 3 steps has mode Blob though it is not the final step.",
            bin,
            json: base_json(
                &f.commit_id,
                &[b"sub", b"deep", b"deep.txt"],
                "object",
                false,
                Some("non-final step's mode is not Tree"),
            ),
        });
    }

    // 2. Step proof checked against the wrong parent: swap the first two
    //    of the 3-level path's steps.
    {
        let (mut steps, leaf) = walk_path(&f.store, f.tree_hash, &[b"sub", b"deep", b"deep.txt"]);
        steps.swap(0, 1);
        let bytes = canonical_bytes(&f.store, &leaf);
        let commit_bytes = canonical_bytes(&f.store, &f.commit_id);
        let bin = wire::bundle(
            &f.commit_id,
            &commit_bytes,
            &steps,
            &wire::object_payload(&bytes),
        );
        v.push(Vector {
            name: "neg_swapped_steps",
            description: "The first two of three path steps are swapped.",
            bin,
            json: base_json(
                &f.commit_id,
                &[b"sub", b"deep", b"deep.txt"],
                "object",
                false,
                Some("a step's proof does not verify against the (now wrong) parent id"),
            ),
        });
    }

    // 3. Invalid entry name (trailing space).
    {
        let (mut steps, leaf) = walk_path(&f.store, f.tree_hash, &[b"shallow.txt"]);
        steps[0].name = b"shallow.txt ".to_vec();
        let bytes = canonical_bytes(&f.store, &leaf);
        let commit_bytes = canonical_bytes(&f.store, &f.commit_id);
        let bin = wire::bundle(
            &f.commit_id,
            &commit_bytes,
            &steps,
            &wire::object_payload(&bytes),
        );
        v.push(Vector {
            name: "neg_invalid_entry_name",
            description: "The step's entry name has a trailing space (SPEC-OBJECTS §4.1).",
            bin,
            json: base_json(
                &f.commit_id,
                &[b"shallow.txt"],
                "object",
                false,
                Some("entry name fails SPEC-OBJECTS §4.1 validation"),
            ),
        });
    }

    // 4. Payload id != leaf id: flip the last byte of the disclosed
    //    Object payload.
    {
        let (steps, leaf) = walk_path(&f.store, f.tree_hash, &[b"shallow.txt"]);
        let mut bytes = canonical_bytes(&f.store, &leaf);
        *bytes.last_mut().unwrap() ^= 0xFF;
        let commit_bytes = canonical_bytes(&f.store, &f.commit_id);
        let bin = wire::bundle(
            &f.commit_id,
            &commit_bytes,
            &steps,
            &wire::object_payload(&bytes),
        );
        v.push(Vector {
            name: "neg_payload_id_mismatch",
            description: "The Object payload's last byte is flipped; its id no longer matches the leaf id.",
            bin,
            json: base_json(
                &f.commit_id,
                &[b"shallow.txt"],
                "object",
                false,
                Some("payload id does not equal the authenticated leaf id"),
            ),
        });
    }

    // 5. Chunk meta with forged total_size.
    {
        let (steps, leaf) = walk_path(&f.store, f.tree_hash, &["chunked.bin".as_bytes()]);
        let Object::ChunkedBlob(cb) = f.store.read_object(&leaf).unwrap() else {
            panic!("expected ChunkedBlob");
        };
        let position = merkle::chunk_position(&cb, &cb.chunks()[1]).unwrap();
        let proof = merkle::build_chunks_multi_proof(&cb, [0, position]).unwrap();
        let chunk_bytes = canonical_bytes(&f.store, &cb.chunks()[1]);
        let (start, end) = cb.span(1).unwrap();
        let commit_bytes = canonical_bytes(&f.store, &f.commit_id);
        let bin = wire::bundle(
            &f.commit_id,
            &commit_bytes,
            &steps,
            &wire::chunk_payload(
                &wire::ChunkFields {
                    total_size: cb.total_size() + 1,
                    chunk_size: cb.chunk_size(),
                    index: 1,
                    span: wire::Span { start, end },
                    inner_root: &merkle::chunked_inner_root(&cb),
                    proof: &proof,
                },
                &chunk_bytes,
            ),
        );
        v.push(Vector {
            name: "neg_chunk_meta_forged_total_size",
            description: "The Chunk payload's total_size is off by one from the real ChunkedBlob's.",
            bin,
            json: base_json(
                &f.commit_id,
                &chunked_path,
                "chunk(1) [forged total_size]",
                false,
                Some("forged total_size no longer folds to the ChunkedBlob id"),
            ),
        });
    }

    // 6. Slice at the wrong offset: request the range payload's Bao
    //    slice for one offset but claim a different `offset_in_blob` in a
    //    *different* 1 KiB Bao chunk (a claimed offset inside the same
    //    already-authenticated chunk would trivially still verify — Bao's
    //    cryptographic granularity is the whole 1 KiB chunk, not the
    //    sub-range requested within it — so the claim MUST cross a chunk
    //    boundary to actually be a forgery: the slice built for chunk 0
    //    contains none of chunk 1's bytes to satisfy a chunk-1 claim).
    {
        let (steps, leaf) = walk_path(&f.store, f.tree_hash, &["range.bin".as_bytes()]);
        let canonical = canonical_bytes(&f.store, &leaf);
        let slice = bao_slice(&canonical, 10, 32); // real slice: chunk 0, offset 0, len 32
        let commit_bytes = canonical_bytes(&f.store, &f.commit_id);
        let bin = wire::bundle(
            &f.commit_id,
            &commit_bytes,
            &steps,
            &wire::range_payload(None, 1024, 32, &slice), // claims chunk 1, not chunk 0
        );
        v.push(Vector {
            name: "neg_slice_wrong_offset",
            description: "A genuine Bao slice for chunk 0 (offset 0) is claimed to be at offset 1024 (chunk 1).",
            bin,
            json: base_json(
                &f.commit_id,
                &range_path,
                "range(offset=1024,len=32) [slice built for offset=0]",
                false,
                Some("Bao slice does not verify at the claimed offset"),
            ),
        });
    }

    // 7. Zero-length range.
    {
        let (steps, leaf) = walk_path(&f.store, f.tree_hash, &["shallow.txt".as_bytes()]);
        let canonical = canonical_bytes(&f.store, &leaf);
        let slice = bao_slice(&canonical, 10, 1);
        let commit_bytes = canonical_bytes(&f.store, &f.commit_id);
        let bin = wire::bundle(
            &f.commit_id,
            &commit_bytes,
            &steps,
            &wire::range_payload(None, 0, 0, &slice),
        );
        v.push(Vector {
            name: "neg_zero_length_range",
            description: "A Range payload with len = 0.",
            bin,
            json: base_json(
                &f.commit_id,
                &[b"shallow.txt"],
                "range(offset=0,len=0)",
                false,
                Some("byte range length is zero"),
            ),
        });
    }

    // 9. steps.len() = 129 (one over MAX_TREE_DEPTH).
    {
        let (steps, leaf) = walk_path(&f.store, f.tree_hash, &["shallow.txt".as_bytes()]);
        let too_many: Vec<Step> = std::iter::repeat_n(steps[0].clone(), 129).collect();
        let bytes = canonical_bytes(&f.store, &leaf);
        let commit_bytes = canonical_bytes(&f.store, &f.commit_id);
        let bin = wire::bundle(
            &f.commit_id,
            &commit_bytes,
            &too_many,
            &wire::object_payload(&bytes),
        );
        v.push(Vector {
            name: "neg_too_many_steps",
            description: "129 steps, one over MAX_TREE_DEPTH (128).",
            bin,
            json: base_json(
                &f.commit_id,
                &[],
                "object",
                false,
                Some("steps.len() > MAX_TREE_DEPTH"),
            ),
        });
    }

    // 10. version = 4 (unknown; v3 is the only supported value).
    {
        let (steps, leaf) = walk_path(&f.store, f.tree_hash, &["shallow.txt".as_bytes()]);
        let bytes = canonical_bytes(&f.store, &leaf);
        let commit_bytes = canonical_bytes(&f.store, &f.commit_id);
        let mut bin = wire::bundle(
            &f.commit_id,
            &commit_bytes,
            &steps,
            &wire::object_payload(&bytes),
        );
        bin[4] = 4;
        v.push(Vector {
            name: "neg_unsupported_version",
            description: "The version byte is 4 instead of the only supported value, 3.",
            bin,
            json: base_json(
                &f.commit_id,
                &[b"shallow.txt"],
                "object",
                false,
                Some("unsupported version"),
            ),
        });
    }

    // 11. Trailing byte.
    {
        let (steps, leaf) = walk_path(&f.store, f.tree_hash, &["shallow.txt".as_bytes()]);
        let bytes = canonical_bytes(&f.store, &leaf);
        let commit_bytes = canonical_bytes(&f.store, &f.commit_id);
        let mut bin = wire::bundle(
            &f.commit_id,
            &commit_bytes,
            &steps,
            &wire::object_payload(&bytes),
        );
        bin.push(0);
        v.push(Vector {
            name: "neg_trailing_byte",
            description: "One extra trailing byte after the declared body.",
            bin,
            json: base_json(
                &f.commit_id,
                &[b"shallow.txt"],
                "object",
                false,
                Some("trailing bytes"),
            ),
        });
    }

    // 12. commit_bytes that decode to a Tag, not a Commit/Remix.
    {
        let tag = kit_core::object::Tag {
            target: f.commit_id,
            target_type: kit_core::object::ObjectType::Commit,
            name: b"v1".to_vec(),
            tagger: Identity::ed25519([9u8; 32]),
            signer: [9u8; 32],
            message: Vec::new(),
            timestamp: 0,
            signature: [0u8; 64],
        };
        let tag_bytes = kit_core::serialize::serialize(&Object::Tag(tag)).unwrap();
        let tag_id = hash(&tag_bytes);
        let bin = wire::bundle(&tag_id, &tag_bytes, &[], &wire::object_payload(&tag_bytes));
        v.push(Vector {
            name: "neg_commit_bytes_are_a_tag",
            description: "commit_bytes decode to a valid, signed Tag rather than a Commit/Remix.",
            bin,
            json: base_json(
                &tag_id,
                &[],
                "object",
                false,
                Some("commit_bytes decode to a Tag"),
            ),
        });
    }

    // 14. Declared inner_root does not wrap to the parent id.
    {
        let (mut steps, leaf) = walk_path(&f.store, f.tree_hash, &[b"shallow.txt"]);
        steps[0].inner_root[0] ^= 0xFF;
        let bytes = canonical_bytes(&f.store, &leaf);
        let commit_bytes = canonical_bytes(&f.store, &f.commit_id);
        let bin = wire::bundle(
            &f.commit_id,
            &commit_bytes,
            &steps,
            &wire::object_payload(&bytes),
        );
        v.push(Vector {
            name: "neg_inner_root_forged",
            description: "The step's declared inner_root does not wrap to the parent Tree id.",
            bin,
            json: base_json(
                &f.commit_id,
                &[b"shallow.txt"],
                "object",
                false,
                Some("declared inner root does not wrap to the parent id"),
            ),
        });
    }

    // 15. Declared inner_root wraps correctly, but the proof was built
    //     for a different tree, so the fold disagrees.
    {
        let (mut steps, leaf) = walk_path(&f.store, f.tree_hash, &[b"shallow.txt"]);
        let (nested, _) = walk_path(
            &f.store,
            f.tree_hash,
            &[
                b"sub".as_slice(),
                b"deep".as_slice(),
                b"deep.txt".as_slice(),
            ],
        );
        steps[0].proof = nested[1].proof.clone();
        steps[0].position = nested[1].position;
        let bytes = canonical_bytes(&f.store, &leaf);
        let commit_bytes = canonical_bytes(&f.store, &f.commit_id);
        let bin = wire::bundle(
            &f.commit_id,
            &commit_bytes,
            &steps,
            &wire::object_payload(&bytes),
        );
        v.push(Vector {
            name: "neg_inner_root_fold_mismatch",
            description: "The declared inner_root wraps to the parent id, but the proof was built for a different tree so the fold disagrees.",
            bin,
            json: base_json(
                &f.commit_id,
                &[b"shallow.txt"],
                "object",
                false,
                Some("proof fold does not equal the declared inner root"),
            ),
        });
    }

    // 16. version = 1.
    {
        let (steps, leaf) = walk_path(&f.store, f.tree_hash, &["shallow.txt".as_bytes()]);
        let bytes = canonical_bytes(&f.store, &leaf);
        let commit_bytes = canonical_bytes(&f.store, &f.commit_id);
        let mut bin = wire::bundle(
            &f.commit_id,
            &commit_bytes,
            &steps,
            &wire::object_payload(&bytes),
        );
        bin[4] = 1;
        v.push(Vector {
            name: "neg_bundle_version_1",
            description: "The version byte is 1; v3 is the only supported value.",
            bin,
            json: base_json(
                &f.commit_id,
                &[b"shallow.txt"],
                "object",
                false,
                Some("unsupported bundle version 1"),
            ),
        });
    }

    // 16b. version = 2: the bundle of the format before chunk spans.
    {
        let (steps, leaf) = walk_path(&f.store, f.tree_hash, &["shallow.txt".as_bytes()]);
        let bytes = canonical_bytes(&f.store, &leaf);
        let commit_bytes = canonical_bytes(&f.store, &f.commit_id);
        let mut bin = wire::bundle(
            &f.commit_id,
            &commit_bytes,
            &steps,
            &wire::object_payload(&bytes),
        );
        bin[4] = 2;
        v.push(Vector {
            name: "neg_bundle_version_2",
            description: "The version byte is 2, the version before chunks carried their spans.",
            bin,
            json: base_json(
                &f.commit_id,
                &[b"shallow.txt"],
                "object",
                false,
                Some("unsupported bundle version 2"),
            ),
        });
    }

    // 17. Zero-length range on a chunked leaf (chunk = Some(hdr)). §4
    //     requires `len == 0` to be rejected before the chunk header's
    //     wrap/fold checks even here, not just on the plain-Blob path
    //     (vector 7, `neg_zero_length_range`).
    {
        let (steps, leaf) = walk_path(&f.store, f.tree_hash, &chunked_path);
        let Object::ChunkedBlob(cb) = f.store.read_object(&leaf).unwrap() else {
            panic!("expected ChunkedBlob");
        };
        let position = merkle::chunk_position(&cb, &cb.chunks()[1]).unwrap();
        let hdr_proof = merkle::build_chunks_multi_proof(&cb, [0, position]).unwrap();
        let chunk1_canonical = f.store.read(&cb.chunks()[1]).unwrap();
        // A genuine, otherwise-valid slice; the payload's declared `len`
        // (0) is what must be rejected, independent of the slice content.
        let slice = bao_slice(&chunk1_canonical, 10 + 32, 1);
        let commit_bytes = canonical_bytes(&f.store, &f.commit_id);
        let (start, end) = cb.span(1).unwrap();
        let inner_root = merkle::chunked_inner_root(&cb);
        let bin = wire::bundle(
            &f.commit_id,
            &commit_bytes,
            &steps,
            &wire::range_payload(
                Some(&wire::ChunkHdr {
                    fields: wire::ChunkFields {
                        total_size: cb.total_size(),
                        chunk_size: cb.chunk_size(),
                        index: 1,
                        span: wire::Span { start, end },
                        inner_root: &inner_root,
                        proof: &hdr_proof,
                    },
                    chunk_id: cb.chunks()[1],
                }),
                32,
                0,
                &slice,
            ),
        );
        v.push(Vector {
            name: "neg_zero_length_range_chunked",
            description: "A Range payload over a chunked leaf (chunk = Some(hdr)) with len = 0.",
            bin,
            json: base_json(
                &f.commit_id,
                &chunked_path,
                "range(offset=32,len=0,chunk=1)",
                false,
                Some("byte range length is zero"),
            ),
        });
    }

    // 18. Range over a chunked leaf whose chunk header's total_size is
    //     forged, mirroring vector 5 (`neg_chunk_meta_forged_total_size`,
    //     the plain Chunk payload) for the Range/chunk variant.
    {
        let (steps, leaf) = walk_path(&f.store, f.tree_hash, &chunked_path);
        let Object::ChunkedBlob(cb) = f.store.read_object(&leaf).unwrap() else {
            panic!("expected ChunkedBlob");
        };
        let position = merkle::chunk_position(&cb, &cb.chunks()[1]).unwrap();
        let hdr_proof = merkle::build_chunks_multi_proof(&cb, [0, position]).unwrap();
        let chunk1_canonical = f.store.read(&cb.chunks()[1]).unwrap();
        let slice = bao_slice(&chunk1_canonical, 10 + 32, 16);
        let commit_bytes = canonical_bytes(&f.store, &f.commit_id);
        let (start, end) = cb.span(1).unwrap();
        let inner_root = merkle::chunked_inner_root(&cb);
        let bin = wire::bundle(
            &f.commit_id,
            &commit_bytes,
            &steps,
            &wire::range_payload(
                Some(&wire::ChunkHdr {
                    fields: wire::ChunkFields {
                        total_size: cb.total_size() + 1,
                        chunk_size: cb.chunk_size(),
                        index: 1,
                        span: wire::Span { start, end },
                        inner_root: &inner_root,
                        proof: &hdr_proof,
                    },
                    chunk_id: cb.chunks()[1],
                }),
                32,
                16,
                &slice,
            ),
        );
        v.push(Vector {
            name: "neg_range_chunk_meta_forged_total_size",
            description: "A Range payload over a chunked leaf (chunk = Some(hdr)) whose total_size is off by one from the real ChunkedBlob's.",
            bin,
            json: base_json(
                &f.commit_id,
                &chunked_path,
                "range(offset=32,len=16,chunk=1) [forged total_size]",
                false,
                Some("forged total_size no longer folds to the ChunkedBlob id"),
            ),
        });
    }

    // 19, 20. The final step's mode disagrees with the type of the
    //     Object payload. The commit is signed and its tree is valid; the
    //     entry names an object of the wrong type for its mode.
    for (name, description, mode, target, reason) in [
        (
            "neg_blob_mode_names_tree",
            "The final step has mode Blob but its child id is a tree; the Object payload is that tree.",
            EntryMode::Blob,
            f.tree_hash,
            "Object payload is a Tree under a Blob mode",
        ),
        (
            "neg_tree_mode_names_blob",
            "The final step has mode Tree but its child id is a blob; the Object payload is that blob.",
            EntryMode::Tree,
            kit_core::worktree::store_file_object(&f.store, b"shallow file content").unwrap(),
            "Object payload is a Blob under a Tree mode",
        ),
    ] {
        let commit_id = commit_with_entry(&f.store, mode, target);
        let tree_hash = tree_of_commit(&f.store, &commit_id);
        let (steps, leaf) = walk_path(&f.store, tree_hash, &[b"x"]);
        let bytes = canonical_bytes(&f.store, &leaf);
        let commit_bytes = canonical_bytes(&f.store, &commit_id);
        let bin = wire::bundle(
            &commit_id,
            &commit_bytes,
            &steps,
            &wire::object_payload(&bytes),
        );
        v.push(Vector {
            name,
            description,
            bin,
            json: base_json(&commit_id, &[b"x"], "object", false, Some(reason)),
        });
    }

    // 21-23. A Chunk or Range payload is blob data, so a final step of mode
    //     Tree cannot name its leaf.
    {
        let chunked = f
            .store
            .read_object(&{
                let Object::Tree(root) = f.store.read_object(&f.tree_hash).unwrap() else {
                    panic!("root is a Tree");
                };
                root.entries
                    .iter()
                    .find(|e| e.name == b"chunked.bin")
                    .unwrap()
                    .object_hash
            })
            .map(|_| ())
            .ok();
        assert!(chunked.is_some());
    }
    for (name, description, small, selector, selector_desc, reason) in [
        (
            "neg_tree_mode_chunk_payload",
            "The final step has mode Tree but names a chunked blob; the payload is one of its chunks.",
            false,
            Selector::Chunk(1),
            "chunk(1)",
            "Chunk payload under a Tree mode",
        ),
        (
            "neg_tree_mode_range_chunked",
            "The final step has mode Tree but names a chunked blob; the payload is a range inside a chunk.",
            false,
            Selector::Range { offset: 0, len: 8 },
            "range(offset=0,len=8)",
            "Range payload over a chunked blob under a Tree mode",
        ),
        (
            "neg_tree_mode_range_blob",
            "The final step has mode Tree but names a plain blob; the payload is a range of it.",
            true,
            Selector::Range { offset: 0, len: 8 },
            "range(offset=0,len=8)",
            "Range payload over a blob under a Tree mode",
        ),
    ] {
        let target = if small {
            kit_core::worktree::store_file_object(&f.store, &f.range_blob).unwrap()
        } else {
            let Object::Tree(root) = f.store.read_object(&f.tree_hash).unwrap() else {
                panic!("root is a Tree");
            };
            root.entries
                .iter()
                .find(|e| e.name == b"chunked.bin")
                .unwrap()
                .object_hash
        };
        let commit_id = commit_with_entry(&f.store, EntryMode::Tree, target);
        let bin = verify::build_disclosure(&f.store, &commit_id, &[b"x"], selector).unwrap();
        v.push(Vector {
            name,
            description,
            bin,
            json: base_json(&commit_id, &[b"x"], selector_desc, false, Some(reason)),
        });
    }

    // ---- chunk spans: layouts the committed offsets describe ----

    let fixed_path = [b"fixed.bin".as_slice()];
    for (name, description, selector, desc) in [
        (
            "fixed_range",
            "A range in chunk 2 of a fixed-size layout (chunk_size 16); the absolute offset is 2 * 16 + 2.",
            Selector::Range { offset: 34, len: 4 },
            "range(offset=34,len=4)",
        ),
        (
            "fixed_chunk_last",
            "The last chunk of a fixed-size layout, holding the 5 bytes left of total_size 53.",
            Selector::Chunk(3),
            "chunk(3)",
        ),
    ] {
        let (_dir, store, commit_id) = fixed_layout_commit(&[16, 16, 16, 5]);
        let bin = verify::build_disclosure(&store, &commit_id, &fixed_path, selector).unwrap();
        let d = verify::verify_disclosure(&commit_id, &bin).unwrap();
        let mut json = base_json(&commit_id, &fixed_path, desc, true, None);
        json.as_object_mut()
            .unwrap()
            .insert("disclosed".into(), disclosed_summary(&d));
        v.push(Vector {
            name,
            description,
            bin,
            json,
        });
    }

    // A one-chunk file: chunk 0 is both the first and the last.
    {
        let (_dir, store, commit_id, _) = layout_commit(0, &[8], &[8]);
        let bin =
            verify::build_disclosure(&store, &commit_id, &fixed_path, Selector::Chunk(0)).unwrap();
        let d = verify::verify_disclosure(&commit_id, &bin).unwrap();
        let mut json = base_json(&commit_id, &fixed_path, "chunk(0)", true, None);
        json.as_object_mut()
            .unwrap()
            .insert("disclosed".into(), disclosed_summary(&d));
        v.push(Vector {
            name: "chunked_one_chunk",
            description: "The only chunk of a one-chunk file: it starts at 0 and ends at total_size.",
            bin,
            json,
        });
    }

    // One chunk id at two indices: the spans, not the ids, tell them apart.
    for (name, description, index) in [
        (
            "chunk_same_id_first",
            "Index 0 of a file whose chunks 0 and 1 are the same blob.",
            0,
        ),
        (
            "chunk_same_id_second",
            "Index 1 of a file whose chunks 0 and 1 are the same blob: its span is [8, 16).",
            1,
        ),
    ] {
        let dir = tempfile::TempDir::new().unwrap();
        let store = ObjectStore::init(&kit_core::layout::RepoLayout::single(dir.path())).unwrap();
        let (same, _) = write_chunk(&store, 0, 8);
        let (other, _) = write_chunk(&store, 1, 4);
        let manifest =
            kit_core::object::ChunkedBlob::new(20, 0, [(same, 8), (same, 16), (other, 20)])
                .unwrap();
        let file = store
            .write(&kit_core::serialize::serialize(&Object::ChunkedBlob(manifest)).unwrap())
            .unwrap();
        let commit_id = commit_over_file(&store, b"fixed.bin", file);
        let bin = verify::build_disclosure(&store, &commit_id, &fixed_path, Selector::Chunk(index))
            .unwrap();
        let d = verify::verify_disclosure(&commit_id, &bin).unwrap();
        let mut json = base_json(
            &commit_id,
            &fixed_path,
            &format!("chunk({index})"),
            true,
            None,
        );
        json.as_object_mut()
            .unwrap()
            .insert("disclosed".into(), disclosed_summary(&d));
        v.push(Vector {
            name,
            description,
            bin,
            json,
        });
    }

    // Spans that overlap. The manifest rules never produce them, but the leaf
    // commits whatever the tree names, and the verifier checks each span
    // alone, so both disclosures verify.
    for (name, description, index) in [
        (
            "chunk_overlap_first",
            "Chunk 0 of a forged file whose chunks cover [0, 12) and [8, 16).",
            0,
        ),
        (
            "chunk_overlap_second",
            "Chunk 1 of a forged file whose chunks cover [0, 12) and [8, 16).",
            1,
        ),
    ] {
        v.push(forged_chunk_vector(
            &Forged {
                name,
                description,
                total_size: 16,
                chunk_size: 0,
                spans: &[(0, 12), (8, 16)],
                blob_lens: &[12, 8],
                index,
                reason: None,
            },
            None,
            |_| false,
        ));
    }

    // Forged spans a verifier must refuse, one per rule, each with a proof
    // that folds to the tree's chunked-file id.
    let over_limit = kit_core::serialize::MAX_CHUNK_LEN + 1;
    for (forged, expect) in [
        (
            Forged {
                name: "neg_span_first_start_not_zero",
                description: "Chunk 0 whose span starts at 4.",
                total_size: 20,
                chunk_size: 0,
                spans: &[(4, 12), (12, 20)],
                blob_lens: &[8, 8],
                index: 0,
                reason: Some("index 0 and start 0 disagree"),
            },
            (|e: &VerifyError| matches!(e, VerifyError::FirstChunkStart { index: 0, start: 4 }))
                as fn(&VerifyError) -> bool,
        ),
        (
            Forged {
                name: "neg_span_last_end_not_total",
                description: "The last chunk whose span ends at 16, short of total_size 20.",
                total_size: 20,
                chunk_size: 0,
                spans: &[(0, 8), (8, 16)],
                blob_lens: &[8, 8],
                index: 1,
                reason: Some("the last chunk does not end at total_size"),
            },
            |e| matches!(e, VerifyError::LastChunkEnd { index: 1, end: 16 }),
        ),
        (
            Forged {
                name: "neg_span_middle_ends_at_total",
                description: "A middle chunk whose span ends at total_size.",
                total_size: 20,
                chunk_size: 0,
                spans: &[(0, 8), (8, 20), (20, 24)],
                blob_lens: &[8, 12, 4],
                index: 1,
                reason: Some("a chunk that is not the last ends at total_size"),
            },
            |e| matches!(e, VerifyError::LastChunkEnd { index: 1, end: 20 }),
        ),
        (
            Forged {
                name: "neg_span_empty",
                description: "A chunk whose span is empty.",
                total_size: 8,
                chunk_size: 0,
                spans: &[(0, 0), (0, 8)],
                blob_lens: &[0, 8],
                index: 0,
                reason: Some("the span is empty"),
            },
            |e| {
                matches!(
                    e,
                    VerifyError::SpanOutsideFile {
                        start: 0,
                        end: 0,
                        total_size: 8
                    }
                )
            },
        ),
        (
            Forged {
                name: "neg_span_end_above_total",
                description: "A chunk whose span ends at 12, past total_size 8.",
                total_size: 8,
                chunk_size: 0,
                spans: &[(0, 12)],
                blob_lens: &[12],
                index: 0,
                reason: Some("the span reaches past total_size"),
            },
            |e| {
                matches!(
                    e,
                    VerifyError::SpanOutsideFile {
                        start: 0,
                        end: 12,
                        total_size: 8
                    }
                )
            },
        ),
        (
            Forged {
                name: "neg_span_above_object_limit",
                description: "A chunk whose span is one byte longer than a chunk blob can be.",
                total_size: over_limit,
                chunk_size: 0,
                spans: &[(0, over_limit)],
                blob_lens: &[8],
                index: 0,
                reason: Some("the span is longer than a blob can be"),
            },
            |e| matches!(e, VerifyError::SpanAboveObjectLimit { start: 0, .. }),
        ),
        (
            Forged {
                name: "neg_span_fixed_end_off_by_one",
                description: "Chunk 1 of a fixed-size layout (chunk_size 16) whose span ends at 31.",
                total_size: 40,
                chunk_size: 16,
                spans: &[(0, 16), (16, 31), (31, 40)],
                blob_lens: &[16, 15, 9],
                index: 1,
                reason: Some("a fixed-size chunk does not end where its layout says"),
            },
            |e| {
                matches!(
                    e,
                    VerifyError::FixedChunkLength {
                        index: 1,
                        start: 16,
                        end: 31
                    }
                )
            },
        ),
    ] {
        v.push(forged_chunk_vector(&forged, None, expect));
    }

    // A real chunk whose payload claims another span: the leaf the verifier
    // folds is not the leaf the tree commits.
    {
        let (_dir, store, commit_id, chunks) = layout_commit(0, &[8, 12, 5], &[8, 12, 5]);
        let cb = layout_manifest(&store, &commit_id);
        let proof = merkle::build_chunks_multi_proof(&cb, [0, 2]).unwrap();
        let inner_root = merkle::chunked_inner_root(&cb);
        let bin = layout_bundle(
            &store,
            &commit_id,
            &wire::chunk_payload(
                &wire::ChunkFields {
                    total_size: cb.total_size(),
                    chunk_size: cb.chunk_size(),
                    index: 1,
                    // The same length as the real span [8, 20), shifted by one.
                    span: wire::Span { start: 9, end: 21 },
                    inner_root: &inner_root,
                    proof: &proof,
                },
                &canonical_bytes(&store, &chunks[1]),
            ),
        );
        assert!(verify::verify_disclosure(&commit_id, &bin).is_err());
        v.push(Vector {
            name: "neg_span_moved",
            description: "Chunk 1 with the span [9, 21) where the tree commits [8, 20).",
            bin,
            json: base_json(
                &commit_id,
                &fixed_path,
                "chunk(1) [claims span 9..21]",
                false,
                Some("the claimed span is not the committed span"),
            ),
        });
    }

    // Chunk bytes that are not a Blob: the tree names the hash of twelve raw
    // bytes, so the proof folds and only the bytes themselves are wrong.
    v.push(forged_chunk_vector(
        &Forged {
            name: "neg_chunk_bytes_not_blob",
            description: "Chunk 1 whose bytes are twelve raw bytes, not a Blob object.",
            total_size: 20,
            chunk_size: 0,
            spans: &[(0, 8), (8, 20)],
            blob_lens: &[8, 12],
            index: 1,
            reason: Some("a chunk is one blob"),
        },
        Some(b"twelve bytes"),
        |e| matches!(e, VerifyError::ChunkBytesNotBlob),
    ));

    // A chunk blob that does not hold its span.
    {
        let (_dir, store, commit_id, chunks) = layout_commit(16, &[16, 16, 16, 5], &[8, 16, 16, 5]);
        let cb = layout_manifest(&store, &commit_id);
        let proof = merkle::build_chunks_multi_proof(&cb, [0, 1]).unwrap();
        let inner_root = merkle::chunked_inner_root(&cb);
        let bin = layout_bundle(
            &store,
            &commit_id,
            &wire::chunk_payload(
                &wire::ChunkFields {
                    total_size: cb.total_size(),
                    chunk_size: cb.chunk_size(),
                    index: 0,
                    span: wire::Span { start: 0, end: 16 },
                    inner_root: &inner_root,
                    proof: &proof,
                },
                &canonical_bytes(&store, &chunks[0]),
            ),
        );
        assert!(matches!(
            verify::verify_disclosure(&commit_id, &bin),
            Err(VerifyError::ChunkLengthDiffersFromSpan {
                index: 0,
                expected: 16,
                actual: 8
            })
        ));
        v.push(Vector {
            name: "neg_chunk_length_differs_from_span",
            description: "Chunk 0 of a fixed-size layout (chunk_size 16) whose blob holds 8 bytes where its span is 16.",
            bin,
            json: base_json(
                &commit_id,
                &fixed_path,
                "chunk(0) [holds 8 bytes]",
                false,
                Some("the blob's length is not the span's length"),
            ),
        });
    }

    // A range past the span, inside a real chunk that is longer than its
    // span. The Bao slice is genuine; the span is what rules it out.
    {
        let (_dir, store, commit_id, chunks) =
            layout_commit(16, &[16, 16, 16, 5], &[16, 24, 16, 5]);
        let cb = layout_manifest(&store, &commit_id);
        let proof = merkle::build_chunks_multi_proof(&cb, [0, 2]).unwrap();
        let inner_root = merkle::chunked_inner_root(&cb);
        let canonical = canonical_bytes(&store, &chunks[1]);
        // Bytes 20..22 of chunk 1: inside the 24 bytes it holds, past the 16
        // its span covers.
        let slice = bao_slice(&canonical, 10 + 20, 2);
        let bin = layout_bundle(
            &store,
            &commit_id,
            &wire::range_payload(
                Some(&wire::ChunkHdr {
                    fields: wire::ChunkFields {
                        total_size: cb.total_size(),
                        chunk_size: cb.chunk_size(),
                        index: 1,
                        span: wire::Span { start: 16, end: 32 },
                        inner_root: &inner_root,
                        proof: &proof,
                    },
                    chunk_id: chunks[1],
                }),
                20,
                2,
                &slice,
            ),
        );
        assert!(matches!(
            verify::verify_disclosure(&commit_id, &bin),
            Err(VerifyError::RangePastSpan {
                offset_in_blob: 20,
                len: 2,
                span_len: 16
            })
        ));
        v.push(Vector {
            name: "neg_range_past_span",
            description: "A range at offset 20 of chunk 1, whose blob holds 24 bytes but whose span is 16.",
            bin,
            json: base_json(
                &commit_id,
                &fixed_path,
                "range(chunk=1,offset=20,len=2)",
                false,
                Some("the range reaches past the committed span"),
            ),
        });
    }

    v
}

/// Regenerate `rust/tests/golden/disclosure/` from `build_vectors()`.
fn write_all() {
    let dir = disclosure_dir();
    fs::create_dir_all(&dir).expect("create disclosure/ dir");
    let mut manifest = String::from(
        "# SPEC-DISCLOSURE golden vectors (deterministic)\n\
         # Produced by `KIT_WRITE_GOLDEN=1 cargo test -p kit-core --test golden_disclosure`\n\
         # Format: <name> <blake3-hex-of-bin-bytes>\n\
         # See docs/specs/SPEC-DISCLOSURE.md.\n",
    );
    for v in build_vectors() {
        let digest = to_hex(&hash(&v.bin));
        fs::write(dir.join(format!("{}.bin", v.name)), &v.bin).expect("write .bin");
        let mut sidecar = json!({
            "name": v.name,
            "description": v.description,
            "bin": format!("{}.bin", v.name),
            "size": v.bin.len(),
            "blake3": digest,
        });
        let merged = sidecar.as_object_mut().unwrap();
        for (k, val) in v.json.as_object().unwrap() {
            merged.insert(k.clone(), val.clone());
        }
        fs::write(
            dir.join(format!("{}.json", v.name)),
            serde_json::to_string_pretty(&sidecar).unwrap() + "\n",
        )
        .expect("write .json");
        let _ = writeln!(manifest, "{} {}", v.name, digest);
    }
    fs::write(dir.join("MANIFEST.txt"), manifest).expect("write MANIFEST.txt");
}

#[test]
fn write_golden_disclosure_vectors_if_requested() {
    if writing() {
        write_all();
    }
}

// Exercise today's encoder independently of the fixture-only verifier below.
// Never regenerate the committed bytes to accommodate a dependency update.
#[test]
fn disclosure_encoders_match_committed_bytes() {
    if writing() {
        return;
    }
    for vector in build_vectors() {
        let expected = fs::read(disclosure_dir().join(format!("{}.bin", vector.name)))
            .expect("read committed golden bytes");
        assert_eq!(
            vector.bin, expected,
            "{}: encoded bytes changed; investigate before updating the wire format",
            vector.name
        );
    }
}

// ---------------------------------------------------------------------------
// Consumer: reads ONLY the committed files, never the generator above.
// ---------------------------------------------------------------------------

fn manifest_names_and_digests() -> Vec<(String, String)> {
    let raw = fs::read_to_string(disclosure_dir().join("MANIFEST.txt"))
        .expect("read rust/tests/golden/disclosure/MANIFEST.txt");
    raw.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            let mut parts = l.split_whitespace();
            let name = parts.next().expect("name").to_string();
            let digest = parts.next().expect("digest").to_string();
            (name, digest)
        })
        .collect()
}

fn verify_vector(name: &str, want_digest: &str) {
    let dir = disclosure_dir();
    let bin = fs::read(dir.join(format!("{name}.bin")))
        .unwrap_or_else(|e| panic!("cannot read {name}.bin: {e}"));
    let got_digest = to_hex(&hash(&bin));
    assert_eq!(
        got_digest, want_digest,
        "{name}.bin: BLAKE3 digest does not match MANIFEST.txt"
    );

    let sidecar: Value = serde_json::from_str(
        &fs::read_to_string(dir.join(format!("{name}.json")))
            .unwrap_or_else(|e| panic!("cannot read {name}.json: {e}")),
    )
    .unwrap_or_else(|e| panic!("{name}.json is not valid JSON: {e}"));
    assert_eq!(sidecar["blake3"].as_str().unwrap(), want_digest);
    assert_eq!(
        usize::try_from(sidecar["size"].as_u64().unwrap()).unwrap(),
        bin.len()
    );

    let commit_id: Hash =
        kit_core::hash::from_hex(sidecar["commit_id_hex"].as_str().unwrap()).unwrap();
    let expect_accept = match sidecar["expect"].as_str().unwrap() {
        "accept" => true,
        "reject" => false,
        other => panic!("{name}.json: unknown expect value {other:?}"),
    };

    let result: Result<Disclosed, VerifyError> = verify::verify_disclosure(&commit_id, &bin);
    match (expect_accept, result) {
        (true, Ok(d)) => {
            let want = &sidecar["disclosed"];
            assert_eq!(
                to_hex(&d.leaf_id),
                want["leaf_id_hex"].as_str().unwrap(),
                "{name}: leaf_id mismatch"
            );
            assert_eq!(
                to_hex(&d.tree_hash),
                want["tree_hash_hex"].as_str().unwrap(),
                "{name}: tree_hash mismatch"
            );
            let payload_bytes = match &d.payload {
                DisclosedPayload::Object { bytes }
                | DisclosedPayload::Chunk { bytes, .. }
                | DisclosedPayload::Range { bytes, .. } => bytes,
            };
            assert_eq!(
                to_hex(&hash(payload_bytes)),
                want["payload"]["bytes_blake3"].as_str().unwrap(),
                "{name}: disclosed payload bytes hash mismatch"
            );
            if let DisclosedPayload::Range {
                absolute_offset, ..
            } = &d.payload
            {
                let want_abs = want["payload"]["absolute_offset"].as_u64();
                assert_eq!(
                    Some(*absolute_offset),
                    want_abs,
                    "{name}: absolute_offset mismatch"
                );
            }
            let want_roots = want["step_inner_roots_hex"]
                .as_array()
                .unwrap_or_else(|| panic!("{name}: step_inner_roots_hex missing"));
            assert_eq!(
                want_roots.len(),
                d.step_inner_roots.len(),
                "{name}: step_inner_roots length"
            );
            for (got, want_hex) in d.step_inner_roots.iter().zip(want_roots) {
                assert_eq!(
                    to_hex(got),
                    want_hex.as_str().unwrap(),
                    "{name}: step_inner_roots mismatch"
                );
            }
            match (
                d.chunk_inner_root.as_ref(),
                want["chunk_inner_root_hex"].as_str(),
            ) {
                (Some(got), Some(want_hex)) => {
                    assert_eq!(to_hex(got), want_hex, "{name}: chunk_inner_root mismatch");
                }
                (None, None) => {}
                other => panic!("{name}: chunk_inner_root presence mismatch: {other:?}"),
            }
        }
        (true, Err(e)) => panic!("{name}: expected accept, got {e:?}"),
        (false, Ok(_)) => panic!(
            "{name}: expected reject ({}), but verification accepted it",
            sidecar
                .get("reject_reason")
                .and_then(Value::as_str)
                .unwrap_or("<none recorded>")
        ),
        (false, Err(_)) => {} // any typed rejection satisfies a reject vector
    }
}

#[test]
fn golden_disclosure_vectors_verify() {
    if writing() {
        return;
    }
    let vectors = manifest_names_and_digests();
    assert!(
        !vectors.is_empty(),
        "MANIFEST.txt listed no vectors — did you forget to run \
         `KIT_WRITE_GOLDEN=1 cargo test -p kit-core --test golden_disclosure`?"
    );
    for (name, digest) in vectors {
        verify_vector(&name, &digest);
    }
}
