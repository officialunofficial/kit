//! Native-only acceptance test for SPEC-DISCLOSURE v3 bundles.
//! Every accept golden is verified using **only** bundle fields,
//! `commonware_storage::bmt::Proof` for chunk headers, a keyed tree fold
//! written here from SPEC-MERKLE-OBJECTS §5.8 for tree steps,
//! `commonware_cryptography::blake3`, and `kit_core::hash::domain_digest`
//! with the hardcoded domain byte strings from the spec. Never calls
//! `kit_core::merkle` or `kit_core::verify` verifiers. Leaf digests are
//! recomputed from SPEC-MERKLE-OBJECTS §3.
#![allow(clippy::unwrap_used)]

use std::fs;
use std::path::PathBuf;

use commonware_codec::{Copying, Read as _, ReadExt, ReadRangeExt};
use commonware_cryptography::blake3::{Blake3, Digest};
use commonware_storage::bmt::Proof as UpstreamProof;
use kit_core::hash::{Hash, domain_digest, hash};
use kit_core::object::{EntryMode, Object};
use kit_core::serialize;
use kit_core::store::MAX_TREE_DEPTH;
use kit_core::verify::Step;
use serde_json::Value;

const TREE_DOMAIN: &[u8] = b"kit.tree\x00";
const CHUNKED_DOMAIN: &[u8] = b"kit.chunked\x00";
const TREE_ENTRY_DOMAIN: &[u8] = b"kit-tree-entry-v1";
const CBLOB_META_DOMAIN: &[u8] = b"kit-cblob-meta-v1";

fn golden_dir() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("tests");
    d.push("golden");
    d.push("disclosure");
    d
}

fn tree_entry_leaf(name: &[u8], mode: EntryMode, child_id: &Hash) -> Hash {
    let mut body = Vec::with_capacity(4 + name.len() + 1 + 32);
    body.extend_from_slice(&u32::try_from(name.len()).unwrap().to_le_bytes());
    body.extend_from_slice(name);
    body.push(mode as u8);
    body.extend_from_slice(child_id);
    domain_digest(TREE_ENTRY_DOMAIN, &body)
}

fn chunked_meta_leaf(total_size: u64, chunk_size: u32) -> Hash {
    let mut body = [0u8; 12];
    body[..8].copy_from_slice(&total_size.to_le_bytes());
    body[8..].copy_from_slice(&chunk_size.to_le_bytes());
    domain_digest(CBLOB_META_DOMAIN, &body)
}

enum NativeFail {
    Version(u8),
    Wrap,
    Upstream,
    Other(&'static str),
}

impl std::fmt::Display for NativeFail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Version(v) => write!(f, "unsupported version {v}"),
            Self::Wrap => f.write_str("wrapped digest mismatch"),
            Self::Upstream => f.write_str("upstream proof rejected"),
            Self::Other(what) => f.write_str(what),
        }
    }
}

fn wrap_ok(domain: &[u8], inner_root: &Hash, expected_id: &Hash) -> bool {
    domain_digest(domain, inner_root) == *expected_id
}

/// SPEC-MERKLE-OBJECTS §5.8, written from the spec: fold a keyed tree
/// proof and check the name against every separator.
fn keyed_tree_entry(step: &Step, expected_id: &Hash) -> bool {
    let leaf = tree_entry_leaf(&step.name, step.mode, &step.child_id);
    let leaf_count = step.proof.leaf_count;
    let mut position = step.position;
    if position >= leaf_count {
        return false;
    }
    let mut c = blake3::Hasher::new()
        .update(&position.to_be_bytes())
        .update(&leaf)
        .finalize();
    let mut size = leaf_count;
    let mut steps = step.proof.steps.iter();
    while size > 1 {
        if position.is_multiple_of(2) && position + 1 >= size {
            c = blake3::Hasher::new()
                .update(c.as_bytes())
                .update(c.as_bytes())
                .finalize();
        } else {
            let Some(s) = steps.next() else { return false };
            let separator = s.separator.as_slice();
            let left_side = position.is_multiple_of(2);
            if (left_side && step.name.as_slice() >= separator)
                || (!left_side && step.name.as_slice() < separator)
            {
                return false;
            }
            let (l, r) = if left_side {
                (*c.as_bytes(), s.sibling)
            } else {
                (s.sibling, *c.as_bytes())
            };
            c = blake3::Hasher::new()
                .update(&l)
                .update(&r)
                .update(&[u8::try_from(separator.len()).unwrap()])
                .update(separator)
                .finalize();
        }
        position /= 2;
        size = size.div_ceil(2);
    }
    if steps.next().is_some() {
        return false;
    }
    let root = blake3::Hasher::new()
        .update(&leaf_count.to_be_bytes())
        .update(c.as_bytes())
        .finalize();
    wrap_ok(TREE_DOMAIN, root.as_bytes(), expected_id)
}

/// Decode a v3 bundle far enough to check every step with the keyed fold
/// and every chunk header with upstream BMT, without calling kit
/// verifiers.
fn native_check(bundle: &[u8]) -> Result<(), NativeFail> {
    if bundle.len() < 5 || &bundle[..4] != b"KDPB" {
        return Err(NativeFail::Other("bad magic"));
    }
    let version = bundle[4];
    if version != 3 {
        return Err(NativeFail::Version(version));
    }
    let mut r = Copying(&bundle[5..]);
    let commit_id = Hash::read(&mut r).map_err(|_| NativeFail::Other("commit_id"))?;
    let commit_bytes = Vec::<u8>::read_range(&mut r, ..=4 * 1024 * 1024)
        .map_err(|_| NativeFail::Other("commit_bytes"))?;
    if hash(&commit_bytes) != commit_id {
        return Err(NativeFail::Other("commit hash"));
    }
    let obj =
        serialize::deserialize(&commit_bytes).map_err(|_| NativeFail::Other("commit decode"))?;
    let tree_hash = match obj {
        Object::Commit(c) => c.tree_hash,
        Object::Remix(rm) => rm.tree_hash,
        _ => return Err(NativeFail::Other("not commit/remix")),
    };
    let steps: Vec<Step> = Vec::<Step>::read_range(&mut r, ..=MAX_TREE_DEPTH)
        .map_err(|_| NativeFail::Other("steps"))?;

    let mut expected = tree_hash;
    for step in &steps {
        if !keyed_tree_entry(step, &expected) {
            return Err(NativeFail::Wrap);
        }
        expected = step.child_id;
    }
    let leaf_id = if steps.is_empty() {
        tree_hash
    } else {
        steps.last().unwrap().child_id
    };

    check_payload(&mut r, leaf_id)
}

fn check_chunked(
    leaf_id: Hash,
    total_size: u64,
    chunk_size: u32,
    index: u32,
    inner_root: Hash,
    second_leaf: Hash,
    proof: &UpstreamProof<Digest>,
) -> Result<(), NativeFail> {
    if !wrap_ok(CHUNKED_DOMAIN, &inner_root, &leaf_id) {
        return Err(NativeFail::Wrap);
    }
    let position = index.checked_add(1).ok_or(NativeFail::Other("index+1"))?;
    let cw = [
        (Digest(chunked_meta_leaf(total_size, chunk_size)), 0u32),
        (Digest(second_leaf), position),
    ];
    if proof
        .verify_multi_inclusion::<Blake3>(&cw, &Digest(inner_root))
        .is_err()
    {
        return Err(NativeFail::Upstream);
    }
    Ok(())
}

fn check_payload(r: &mut Copying<'_>, leaf_id: Hash) -> Result<(), NativeFail> {
    let payload_kind = u8::read(r).map_err(|_| NativeFail::Other("payload_kind"))?;
    match payload_kind {
        1 => {
            let total_size = u64::read(r).map_err(|_| NativeFail::Other("total_size"))?;
            let chunk_size = u32::read(r).map_err(|_| NativeFail::Other("chunk_size"))?;
            let index = u32::read(r).map_err(|_| NativeFail::Other("index"))?;
            let inner_root = Hash::read(r).map_err(|_| NativeFail::Other("chunk inner_root"))?;
            let proof = UpstreamProof::<Digest>::read_cfg(r, &2usize)
                .map_err(|_| NativeFail::Other("chunk proof"))?;
            let bytes = Vec::<u8>::read_range(r, ..=kit_core::store::MAX_RAW_OBJECT_SIZE)
                .map_err(|_| NativeFail::Other("chunk bytes"))?;
            check_chunked(
                leaf_id,
                total_size,
                chunk_size,
                index,
                inner_root,
                hash(&bytes),
                &proof,
            )
        }
        2 => {
            let present = bool::read(r).map_err(|_| NativeFail::Other("chunk option"))?;
            if !present {
                return Ok(());
            }
            let total_size = u64::read(r).map_err(|_| NativeFail::Other("hdr total_size"))?;
            let chunk_size = u32::read(r).map_err(|_| NativeFail::Other("hdr chunk_size"))?;
            let index = u32::read(r).map_err(|_| NativeFail::Other("hdr index"))?;
            let inner_root = Hash::read(r).map_err(|_| NativeFail::Other("hdr inner_root"))?;
            let chunk_id = Hash::read(r).map_err(|_| NativeFail::Other("hdr chunk_id"))?;
            let proof = UpstreamProof::<Digest>::read_cfg(r, &2usize)
                .map_err(|_| NativeFail::Other("hdr proof"))?;
            check_chunked(
                leaf_id, total_size, chunk_size, index, inner_root, chunk_id, &proof,
            )
        }
        _ => Ok(()),
    }
}

#[test]
fn accept_vectors_verify_natively_with_commonware() {
    let dir = golden_dir();
    let manifest = fs::read_to_string(dir.join("MANIFEST.txt")).unwrap();
    let mut n_accept = 0usize;
    for line in manifest.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let name = line.split_whitespace().next().unwrap();
        let sidecar: Value =
            serde_json::from_str(&fs::read_to_string(dir.join(format!("{name}.json"))).unwrap())
                .unwrap();
        if sidecar["expect"].as_str() != Some("accept") {
            continue;
        }
        let bin = fs::read(dir.join(format!("{name}.bin"))).unwrap();
        native_check(&bin)
            .unwrap_or_else(|e| panic!("{name}: native commonware check failed: {e}"));
        n_accept += 1;
    }
    assert!(
        n_accept >= 8,
        "expected several accept vectors, got {n_accept}"
    );
}

#[test]
fn new_negatives_fail_at_wrap_or_upstream() {
    let dir = golden_dir();
    let cases = [
        ("neg_inner_root_forged", "wrap"),
        ("neg_inner_root_fold_mismatch", "upstream"),
        ("neg_bundle_version_1", "version"),
        ("neg_bundle_version_2", "version"),
        ("neg_separator_violated", "wrap"),
        ("neg_duplicate_name", "wrap"),
    ];
    for (name, want) in cases {
        let bin = fs::read(dir.join(format!("{name}.bin"))).unwrap_or_else(|_| {
            panic!("{name}.bin missing; regenerate goldens with KIT_WRITE_GOLDEN=1")
        });
        let Err(err) = native_check(&bin) else {
            panic!("{name} must fail");
        };
        let ok = matches!(
            (want, &err),
            ("wrap", NativeFail::Wrap)
                | ("upstream", NativeFail::Upstream)
                | ("version", NativeFail::Version(1 | 2))
        );
        assert!(ok, "{name}: expected {want}, got {err}");
    }
}
