//! Every format version that kit 0.8.0 to 0.10.0 wrote stays readable.
//!
//! Each test reads committed bytes under `rust/tests/golden/` with today's
//! reader and checks the id or the content the bytes must give. Nothing here
//! writes a vector. The version byte and the magic of each vector are written
//! out in the test, not taken from a constant of the reader, so a vector that
//! is regenerated at a newer version fails here.
//!
//! A test here that stops passing is a format break. The fix is a reader for
//! the old bytes next to the new one, never a new vector in place of the old
//! (CONTRIBUTING, "Formats stay readable").
//!
//! Where each format's vectors are read (`golden/` is `rust/tests/golden/`):
//!
//! | Format and version | Vectors | Read by |
//! |---|---|---|
//! | Object prologue `KOB1`, schema 1 and 2 (blob, tree, commit, remix, chunked, tag) | `objects/`, `tags/`, ids in `formats/object-ids.txt` | here, `golden.rs`, `golden_tag.rs` |
//! | Object ids (byte hash, tree root, chunked root) | `formats/object-ids.txt`, `proofs/` | here, `golden_proofs.rs` |
//! | Pack `KIT\0` version 1 (raw and delta entries) and 2 (zstd entries) | `pack-v2/`, `local_pack_mixed/mixed.pack` | here, `golden_pack.rs` |
//! | Local pack index `KITX` version 1, store marker `bmt-v2\nP` | `local_pack_mixed/` | here, `store::local_pack::tests` |
//! | Staging index `KIDX` version 3, ref wire form, symbolic HEAD | `refs-index/` | here, `refs_integration.rs` |
//! | Pack list `KPKL` version 1 | `formats/packlist-*.bin` | here |
//! | Sparse wire `KSP1` and cache `KSPC` version 2 | `sparse/response_v2.bin`, `formats/sparse-cache.bin` | here (feature `sparse-checkout`) |
//! | Stash manifest `KSTS` | `formats/stash-list.bin` | here |
//! | Disclosure bundle `KDPB` version 3, span `KDSP` version 2, closure manifest `KCLM` version 1 | `disclosure/`, `http-objects/`, `closure/` | `golden_disclosure.rs`, `golden_http_objects.rs`, `golden_closure.rs` |
//! | Chunk offsets, FastCDC profiles 1 and 2 | `fastcdc/` | `golden_pack.rs`, `golden_chunk_offsets.rs` |
//! | Delta stream version 1 | `pack-v2/`, inline pins | `golden_pack.rs` |
//! | Encrypted key record `KITKSV1` | inline frozen record | `kit-keystore` unit tests, `golden_vectors.rs` |
//! | Attestation envelopes and write grants | `attest/`, `grants/`, `auth-v2/`, `redaction/` | `kit-attest` golden tests, `golden_uploads.rs` |
//!
//! Records that a reader may drop and rebuild are not listed: the ancestry
//! snapshot, the fetch cursor and checkpoint, the verified-tip record, the
//! upload receipts, the sparse and attestation caches on disk.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::fs;
use std::path::PathBuf;

use kit_core::hash::{self, Hash, to_hex};
use kit_core::index::{self, EntryStatus};
use kit_core::layout::RepoLayout;
use kit_core::object::{Object, id_from_object};
use kit_core::ops::stash::{self, StashEntry};
use kit_core::pack::{PackReader, pack_key};
use kit_core::refs::{self, Head};
use kit_core::store::ObjectStore;
use kit_core::transfer::decode_packlist;
use kit_core::{deserialize, serialize};

fn golden(path: &str) -> PathBuf {
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    dir.pop(); // crates/
    dir.pop(); // rust/
    dir.extend(["tests", "golden"]);
    dir.join(path)
}

fn read(path: &str) -> Vec<u8> {
    fs::read(golden(path)).unwrap_or_else(|e| panic!("cannot read vector {path}: {e}"))
}

fn text(path: &str) -> String {
    String::from_utf8(read(path)).unwrap()
}

fn seed(text: &str) -> Hash {
    hash::hash(text.as_bytes())
}

fn lines(path: &str) -> Vec<Vec<String>> {
    text(path)
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .map(|l| l.split_whitespace().map(str::to_owned).collect())
        .collect()
}

/// A vector of `formats/` is the bytes its manifest names.
fn format_vector(name: &str) -> Vec<u8> {
    let bytes = read(&format!("formats/{name}"));
    let row = lines("formats/MANIFEST.txt")
        .into_iter()
        .find(|row| row[0] == name)
        .unwrap_or_else(|| panic!("formats/MANIFEST.txt does not list {name}"));
    assert_eq!(
        to_hex(&hash::hash(&bytes)),
        row[1],
        "{name}: the committed bytes changed"
    );
    bytes
}

fn type_name(object: &Object) -> &'static str {
    match object {
        Object::Blob(_) => "blob",
        Object::Tree(_) => "tree",
        Object::Commit(_) => "commit",
        Object::Remix(_) => "remix",
        Object::ChunkedBlob(_) => "chunked",
        Object::Tag(_) => "tag",
        Object::Delta(_) => "delta",
    }
}

fn fresh_store() -> (tempfile::TempDir, RepoLayout, ObjectStore) {
    let dir = tempfile::tempdir().unwrap();
    let layout = RepoLayout::single(dir.path());
    let store = ObjectStore::init(&layout).unwrap();
    (dir, layout, store)
}

#[test]
fn every_object_vector_keeps_its_type_and_id() {
    let rows = lines("formats/object-ids.txt");
    assert_eq!(rows.len(), 14, "every object vector has a row");
    let mut types = std::collections::BTreeSet::new();
    for row in rows {
        let [file, kind, id] = row.as_slice() else {
            panic!("bad row {row:?}");
        };
        let bytes = read(file);
        let object = deserialize(&bytes).unwrap_or_else(|e| panic!("{file}: {e}"));
        assert_eq!(type_name(&object), kind, "{file}: type");
        assert_eq!(to_hex(&id_from_object(&object, &bytes)), *id, "{file}: id");
        assert_eq!(serialize(&object).unwrap(), bytes, "{file}: bytes");
        types.insert(kind.clone());
    }
    assert_eq!(
        types.into_iter().collect::<Vec<_>>(),
        ["blob", "chunked", "commit", "remix", "tag", "tree"]
    );
}

#[test]
fn pinned_object_ids_do_not_move() {
    // Ids that scripts/golden/objects_ref.py derives without this crate.
    let id_of = |file: &str| {
        let bytes = read(file);
        to_hex(&id_from_object(&deserialize(&bytes).unwrap(), &bytes))
    };
    assert_eq!(
        id_of("objects/empty_tree.bin"),
        "b29117ce9b3d66ba98cd0a57145400f0bf6fff8b5c27c4552d80a38446f27ef7"
    );
    // A blob and a commit are addressed by the BLAKE3 of their bytes.
    for file in ["objects/blob.bin", "objects/commit_0parent.bin"] {
        let bytes = read(file);
        assert_eq!(id_of(file), to_hex(&hash::hash(&bytes)), "{file}");
    }
}

/// Version 1 packs with raw and delta entries, and version 2 packs with
/// compressed entries, read into a store.
#[test]
fn pack_vectors_of_versions_1_and_2_keep_reading() {
    let mut versions = std::collections::BTreeSet::new();
    for name in [
        "boundary_earlier_delta_base",
        #[cfg(feature = "pack-zstd")]
        "delta_repeat",
        #[cfg(feature = "pack-zstd")]
        "large_literals",
        #[cfg(feature = "pack-zstd")]
        "mixed",
        #[cfg(feature = "pack-zstd")]
        "raw_4k_repeat",
        #[cfg(feature = "pack-zstd")]
        "tree_and_commit",
    ] {
        let pack = read(&format!("pack-v2/{name}.bin"));
        let side: serde_json::Value = serde_json::from_slice(&read(&format!("pack-v2/{name}.json")))
            .unwrap();
        assert_eq!(&pack[..4], b"KIT\0", "{name}: magic");
        versions.insert(u32::from_le_bytes(pack[4..8].try_into().unwrap()));
        let (_dir, _layout, store) = fresh_store();
        let report = PackReader::read(&pack, &store).unwrap_or_else(|e| panic!("{name}: {e}"));
        let ids: Vec<Hash> = side["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| hash::from_hex(e["id"].as_str().unwrap()).unwrap())
            .collect();
        assert_eq!(report.stored, ids, "{name}: stored ids");
        for id in &ids {
            let bytes = store.read(id).unwrap();
            let object = deserialize(&bytes).unwrap();
            assert_eq!(&id_from_object(&object, &bytes), id, "{name}: object id");
        }
        if let Some(key) = side["pack_key"].as_str() {
            assert_eq!(to_hex(&pack_key(&pack)), key, "{name}: pack key");
        }
    }
    #[cfg(feature = "pack-zstd")]
    assert_eq!(versions.into_iter().collect::<Vec<_>>(), [1, 2]);
    #[cfg(not(feature = "pack-zstd"))]
    assert_eq!(versions.into_iter().collect::<Vec<_>>(), [1]);
}

/// A local pack (a version 1 pack with a `KITX` version 1 index) in a store
/// marked `bmt-v2\nP`.
#[test]
fn local_pack_vector_keeps_reading() {
    let (_dir, layout, _store) = fresh_store();
    let objects = lines("local_pack_mixed/objects.txt");
    let key = objects.last().unwrap();
    assert_eq!(key[0], "pack");

    let marker = read("local_pack_mixed/marker.bin");
    assert_eq!(marker, b"bmt-v2\nP");
    let pack = read("local_pack_mixed/mixed.pack");
    let index = read("local_pack_mixed/mixed.idx");
    assert_eq!(&pack[..8], b"KIT\0\x01\0\0\0");
    assert_eq!(&index[..8], b"KITX\x01\0\0\0");
    assert_eq!(to_hex(&pack_key(&pack)), key[1]);

    fs::create_dir_all(layout.objects_dir().join("pack")).unwrap();
    fs::write(layout.format_file(), &marker).unwrap();
    fs::write(layout.objects_dir().join("pack").join(format!("{}.pack", key[1])), &pack).unwrap();
    fs::write(layout.objects_dir().join("pack").join(format!("{}.idx", key[1])), &index).unwrap();
    fs::write(layout.objects_dir().join("pack").join("unknown.meta"), read("local_pack_mixed/unknown.meta"))
        .unwrap();

    let store = ObjectStore::open(&layout).unwrap();
    assert_eq!(store.check_local_packs(false).unwrap(), 0, "no damaged pair");
    // The vector's fourth object is the loose one (`loose.bin`); the other
    // three are in the pack.
    let packed = &objects[..3];
    assert_eq!(store.iter_object_hashes().unwrap().len(), 3);
    for row in packed {
        let id = hash::from_hex(&row[0]).unwrap();
        let bytes = store.read(&id).unwrap();
        assert_eq!(bytes.len().to_string(), row[1]);
        let object = deserialize(&bytes).unwrap();
        assert_eq!(id_from_object(&object, &bytes), id, "the id is stable");
    }
}

#[test]
fn staging_index_ref_and_head_vectors_keep_reading() {
    let empty = read("refs-index/index_empty.bin");
    assert_eq!(&empty[..5], b"KIDX\x03");
    assert!(index::deserialize(&empty).unwrap().entries.is_empty());

    let three = read("refs-index/index_3entries.bin");
    assert_eq!(&three[..5], b"KIDX\x03");
    let idx = index::deserialize(&three).unwrap();
    let rows: std::collections::BTreeMap<_, _> = idx
        .entries
        .iter()
        .map(|e| (e.path.as_str(), (e.status, e.object_hash)))
        .collect();
    assert_eq!(
        rows,
        [
            ("README.md", (EntryStatus::Blob, seed("refs-index-blob"))),
            ("scripts/build", (EntryStatus::Executable, seed("refs-index-exe"))),
            ("src", (EntryStatus::Tree, seed("refs-index-tree"))),
        ]
        .into_iter()
        .collect()
    );

    let detached = read("refs-index/ref_detached.bin");
    assert_eq!(
        refs::decode_ref_wire(&detached).unwrap(),
        seed("refs-index-detached-head")
    );

    let dir = tempfile::tempdir().unwrap();
    let layout = RepoLayout::single(dir.path());
    fs::create_dir_all(layout.worktree_state_dir()).unwrap();
    fs::write(layout.head_file(), read("refs-index/head_symbolic.bin")).unwrap();
    assert_eq!(refs::read_head(&layout).unwrap(), Head::Branch("main".to_owned()));
}

#[test]
fn pack_list_vectors_keep_reading() {
    let first = format_vector("packlist-first.bin");
    assert_eq!(&first[..5], b"KPKL\x01");
    let node = decode_packlist(&first).unwrap();
    assert_eq!(node.prev, None);
    assert_eq!(node.packs, [seed("packlist-pack-0")]);

    let chained = format_vector("packlist-chained.bin");
    assert_eq!(&chained[..5], b"KPKL\x01");
    let node = decode_packlist(&chained).unwrap();
    assert_eq!(node.prev, Some(seed("packlist-prev")));
    assert_eq!(node.packs, [seed("packlist-pack-1"), seed("packlist-pack-2")]);
}

#[test]
fn stash_manifest_vector_keeps_reading() {
    let bytes = format_vector("stash-list.bin");
    assert_eq!(&bytes[..4], b"KSTS");
    let list = stash::deserialize_list(&bytes).unwrap();
    assert_eq!(
        list.entries,
        [
            StashEntry {
                commit_hash: seed("stash-commit-1"),
                parent_hash: seed("stash-parent-1"),
                timestamp: 1_700_000_100,
                message: "WIP on main: second".to_owned(),
            },
            StashEntry {
                commit_hash: seed("stash-commit-0"),
                parent_hash: hash::ZERO,
                timestamp: 1_700_000_000,
                message: "WIP on a branch: \u{e9}t\u{e9}".to_owned(),
            },
        ]
    );
    assert_eq!(stash::serialize_list(&list).unwrap(), bytes);
}

#[cfg(feature = "sparse-checkout")]
#[test]
fn sparse_wire_and_cache_vectors_keep_reading() {
    use kit_core::sparse::{decode_sparse_cache, decode_sparse_response};

    let wire = read("sparse/response_v2.bin");
    assert_eq!(&wire[..5], b"KSP1\x02");
    let response = decode_sparse_response(&wire).unwrap();

    let cache = format_vector("sparse-cache.bin");
    assert_eq!(&cache[..5], b"KSPC\x02");
    let (manifest, proof) = decode_sparse_cache(&cache).unwrap();
    assert_eq!(manifest, response.manifest);
    assert_eq!(proof, response.proof);
    // The two envelopes differ in the magic only.
    assert_eq!(cache[4..], wire[4..]);
}
