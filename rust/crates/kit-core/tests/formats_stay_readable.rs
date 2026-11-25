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
//! | Object prologue `KOB1`, schema 1 and 2 (blob, tree, commit, remix, chunked, tag) | `objects/`, `tags/`, ids in `OBJECT_IDS` below | here, `golden.rs`, `golden_tag.rs` |
//! | Object ids (byte hash, tree root, chunked root) | `OBJECT_IDS` below, `formats/object-ids.txt`, `proofs/` | here, `golden_proofs.rs` |
//! | Pack `KIT\0` version 1 (raw and delta entries) and 2 (zstd entries) | `pack-v2/`, `local_pack_mixed/mixed.pack` | here, `golden_pack.rs` |
//! | Local pack index `KITX` version 1, store marker `bmt-v2\nP` | `local_pack_mixed/` | here, `store::local_pack::tests` |
//! | Loose store of 0.8.0 and 0.9.0, marker `bmt-v2\n` | `objects/blob.bin`, `objects/tree.bin` | here |
//! | Staging index `KIDX` version 3, ref wire form, symbolic HEAD | `refs-index/` | here, `refs_integration.rs` |
//! | Pack list `KPKL` version 1 | `formats/packlist-*.bin` | here |
//! | Sparse wire `KSP1` and cache `KSPC` version 2 | `sparse/response_v2.bin`, `formats/sparse-cache.bin` | here (feature `sparse-checkout`) |
//! | Stash manifest `KSTS`, and a 0.8 stash entry with no scope blob | `formats/stash-list.bin`, `formats/stash-08-*` | here |
//! | Disclosure bundle `KDPB` version 3, span `KDSP` version 2, closure manifest `KCLM` version 1 | `disclosure/`, `http-objects/`, `closure/` | `golden_disclosure.rs`, `golden_http_objects.rs`, `golden_closure.rs` |
//! | Chunk offsets, `FastCDC` profiles 1 and 2 | `fastcdc/` | `golden_pack.rs`, `golden_chunk_offsets.rs` |
//! | Delta stream version 1 | `pack-v2/`, inline pins | `golden_pack.rs` |
//! | Encrypted key record `KITKSV1` | inline frozen record | `kit-keystore` unit tests, `golden_vectors.rs` |
//! | Attestation envelopes and write grants | `attest/`, `grants/`, `auth-v2/`, `redaction/` | `kit-attest` golden tests, `golden_uploads.rs` |
//! | Git bridge and git import headers and translations | `git-bridge/`, `git-import/` | the `kit-git-bridge` golden tests |
//! | File remote ref locks and stripe versions | `ref-locks/` | `kit-transport-file` tests |
//! | Connect and ssh transport wire, signatures | `transport/`, `ssh-serve/`, `ed25519/` | `golden_repository_grammar.rs`, `golden_ed25519.rs`, `kit-bin` and `kit-transport-*` tests |
//!
//! Not read here, and why:
//!
//! - The refusal vectors of `pack-v2/` (`boundary_later_delta_base`,
//!   `boundary_payload_high_bit`, `boundary_payload_u32_max`): they must be
//!   refused, and `golden_pack.rs` checks that.
//! - The ancestry snapshot (`KHAN` version 2, `KSCR` version 2): only builds
//!   with the `history-mmr` feature write it, and no release enables that
//!   feature. The decoder is private, so a vector needs an in-crate test.
//!   This is a gap. `KHAN` version 1 was retired before 0.8.0.
//! - Disposable records that a reader may drop and rebuild: the fetch cursor
//!   and checkpoint, the verified-tip record, the upload receipts, the
//!   attestation cache.
//! - Delta objects (type `0x06`): they exist in packs only.
//! - Files with no version marker and no vector: `.kit/config`, the key
//!   files, `shallow`, the sparse-checkout pattern file, the worktree
//!   `commondir`, `kitdir` and `locked` files, and the git-bridge state
//!   files. These are gaps.
//!
//! The store layout of 0.8.0 and 0.9.0 (marker `bmt-v2\n`, loose objects
//! only) is written out in `loose_store_of_0_8_and_0_9_keeps_reading`. The
//! marker of those releases is a literal there.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::fs;
use std::path::PathBuf;

use kit_core::deserialize;
use kit_core::hash::{self, Hash, to_hex};
use kit_core::index::{self, EntryStatus};
use kit_core::layout::RepoLayout;
use kit_core::object::{Object, id_from_object};
use kit_core::ops::stash::{self, StashEntry};
use kit_core::pack::{PackReader, pack_key};
use kit_core::refs::{self, Head};
use kit_core::store::ObjectStore;
use kit_core::transfer::decode_packlist;

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

/// A vector of `formats/`, with the digest written out here: the manifest
/// beside the vector is not enough, because the example rewrites both.
fn format_vector(name: &str, digest: &str) -> Vec<u8> {
    let bytes = read(&format!("formats/{name}"));
    assert_eq!(
        to_hex(&hash::hash(&bytes)),
        digest,
        "{name}: the committed bytes changed"
    );
    bytes
}

const OBJECT_IDS: [(&str, &str, &str); 14] = [
    (
        "objects/blob.bin",
        "blob",
        "591ca28e2d4a899e6856980172975f24c00893119d4d86f8e8c958831545b605",
    ),
    (
        "objects/empty_blob.bin",
        "blob",
        "9c71bce9d9acb21dc70fbeb505bf22cbc0e080ffe38d798d6dd35ba4fd2b9dfe",
    ),
    (
        "objects/empty_tree.bin",
        "tree",
        "b29117ce9b3d66ba98cd0a57145400f0bf6fff8b5c27c4552d80a38446f27ef7",
    ),
    (
        "objects/tree.bin",
        "tree",
        "6c08baba2342c0314204ee4e8b2917fe7b40aa9e23fc6729484f51d7711bf6a9",
    ),
    (
        "objects/tree_single_file.bin",
        "tree",
        "a4619f5be94e5d51d2575e1c176d52bbd17997c31830f1d637e5b08d29415a62",
    ),
    (
        "objects/chunked_blob.bin",
        "chunked",
        "02a34823f71a66cb9ae6e45fb266ccc23a2fe34b8a7ecad7b3c3056d5275a366",
    ),
    (
        "objects/chunked_blob_cs0_3chunks.bin",
        "chunked",
        "ec977e00e22d242df081590048270d0d5f98b6e34dcce104b66f4322e53f04f7",
    ),
    (
        "objects/commit_0parent.bin",
        "commit",
        "ef10b9d6cbc575c7d204b9a674482bb0cdee118b85c5494d47cc47c4e0d60405",
    ),
    (
        "objects/commit_1parent.bin",
        "commit",
        "a268f91be41f13ec03b83fe7f46553015598c9e53a07f821f352c3a4d52f0312",
    ),
    (
        "objects/commit_2parent.bin",
        "commit",
        "a72004436b820eb0877a2102ab57702d6d0c1de02c878ce2eaf8a52a2ca37aca",
    ),
    (
        "objects/remix_2sources.bin",
        "remix",
        "6a8e07b6b7ad9a5df78353cf187ca07615a4e4cbfceda7e1b03bf890685b42d1",
    ),
    (
        "objects/remix_identical_upstream_distinct_commit.bin",
        "remix",
        "04cf36f6a653d58a6c620e55bff6f866464a420f51472f3238b09fd707680104",
    ),
    (
        "tags/tag_annotated.bin",
        "tag",
        "d4dea5aae3d94d698d0de51725b5ddc3631c3c4a771d6233edd47a682059a709",
    ),
    (
        "tags/tag_signed.bin",
        "tag",
        "0a235e943960b14019cbede26325283387f17ec70ce2d30a7926a7421c98abbb",
    ),
];

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
    let mut types = std::collections::BTreeSet::new();
    for (file, kind, id) in OBJECT_IDS {
        let bytes = read(file);
        let object = deserialize(&bytes).unwrap_or_else(|e| panic!("{file}: {e}"));
        assert_eq!(type_name(&object), kind, "{file}: type");
        assert_eq!(to_hex(&id_from_object(&object, &bytes)), id, "{file}: id");
        types.insert(kind);
    }
    assert_eq!(
        types.into_iter().collect::<Vec<_>>(),
        ["blob", "chunked", "commit", "remix", "tag", "tree"]
    );
    // The listing that the reference check reads is the same table.
    let listing = format_vector(
        "object-ids.txt",
        "e87d690af227f8b697103761df745e67cc5a906df19ad193eccb1cbbcb71ce73",
    );
    let rows: Vec<Vec<String>> = String::from_utf8(listing)
        .unwrap()
        .lines()
        .filter(|l| !l.starts_with('#'))
        .map(|l| l.split_whitespace().map(str::to_owned).collect())
        .collect();
    let table: Vec<Vec<String>> = OBJECT_IDS
        .iter()
        .map(|(f, k, i)| vec![(*f).to_owned(), (*k).to_owned(), (*i).to_owned()])
        .collect();
    assert_eq!(rows, table);
}

/// The store that 0.8.0 and 0.9.0 left: the marker `bmt-v2\n` and loose
/// objects only, one file per object at `objects/<2 hex>/<62 hex>`.
#[test]
fn loose_store_of_0_8_and_0_9_keeps_reading() {
    let dir = tempfile::tempdir().unwrap();
    let layout = RepoLayout::single(dir.path());
    fs::create_dir_all(layout.objects_dir()).unwrap();
    fs::write(layout.format_file(), b"bmt-v2\n").unwrap();
    let mut ids = Vec::new();
    for (file, _, id) in OBJECT_IDS {
        if file != "objects/blob.bin" && file != "objects/tree.bin" {
            continue;
        }
        let loose = layout.objects_dir().join(&id[..2]);
        fs::create_dir_all(&loose).unwrap();
        fs::write(loose.join(&id[2..]), read(file)).unwrap();
        ids.push((file, hash::from_hex(id).unwrap()));
    }
    let store = ObjectStore::open(&layout).unwrap();
    assert_eq!(store.iter_object_hashes().unwrap().len(), 2);
    for (file, id) in ids {
        assert_eq!(store.read(&id).unwrap(), read(file), "{file}");
    }
}

/// Version 1 packs with raw and delta entries, and version 2 packs with
/// compressed entries, read into a store.
#[test]
fn pack_vectors_of_versions_1_and_2_keep_reading() {
    let mut versions = std::collections::BTreeSet::new();
    for (name, digest) in [
        (
            "boundary_earlier_delta_base",
            "ebe419ce30637180b67b487e2496d436d1fdd62d05f171a42a4a82af48912666",
        ),
        #[cfg(feature = "pack-zstd")]
        (
            "mixed",
            "be39c79d31eef3b1bbdebfbf99939f1283905d16c7f2d6f387271924b787d44c",
        ),
        #[cfg(feature = "pack-zstd")]
        (
            "raw_4k_repeat",
            "7341c264369dc37847bb0275e3248e9ff6b64c8bb5f5cdd97e249f4e3a32948f",
        ),
    ] {
        let pack = read(&format!("pack-v2/{name}.bin"));
        let side: serde_json::Value =
            serde_json::from_slice(&read(&format!("pack-v2/{name}.json"))).unwrap();
        assert_eq!(
            to_hex(&hash::hash(&pack)),
            digest,
            "{name}: the bytes changed"
        );
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
    assert_eq!(
        key[1], "59bfa107ae4377d4be6d7c6b89a2e99da91203d857cd7a60ba35df3a2c0bf6ea",
        "the committed pack changed"
    );

    fs::create_dir_all(layout.objects_dir().join("pack")).unwrap();
    fs::write(layout.format_file(), &marker).unwrap();
    fs::write(
        layout
            .objects_dir()
            .join("pack")
            .join(format!("{}.pack", key[1])),
        &pack,
    )
    .unwrap();
    fs::write(
        layout
            .objects_dir()
            .join("pack")
            .join(format!("{}.idx", key[1])),
        &index,
    )
    .unwrap();
    fs::write(
        layout.objects_dir().join("pack").join("unknown.meta"),
        read("local_pack_mixed/unknown.meta"),
    )
    .unwrap();

    let store = ObjectStore::open(&layout).unwrap();
    assert_eq!(
        store.check_local_packs(false).unwrap(),
        0,
        "no damaged pair"
    );
    // The pack holds all four objects. `loose.bin` is a second copy of the
    // fourth, which a store reads from either place.
    let packed = &objects[..objects.len() - 1];
    assert_eq!(packed.len(), 4);
    assert_eq!(store.iter_object_hashes().unwrap().len(), 4);
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
            (
                "scripts/build",
                (EntryStatus::Executable, seed("refs-index-exe"))
            ),
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
    assert_eq!(
        refs::read_head(&layout).unwrap(),
        Head::Branch("main".to_owned())
    );
}

#[test]
fn pack_list_vectors_keep_reading() {
    let first = format_vector(
        "packlist-first.bin",
        "aa528fb3046f4847209bff803d4da3b9988b3a6e5857cfbf230c3b532f3b8759",
    );
    assert_eq!(&first[..5], b"KPKL\x01");
    let node = decode_packlist(&first).unwrap();
    assert_eq!(node.prev, None);
    assert_eq!(node.packs, [seed("packlist-pack-0")]);

    let chained = format_vector(
        "packlist-chained.bin",
        "fcc576cf4f6e52c622dbe9ab3fd6293ef2147d83fb762907106bd95357524b67",
    );
    assert_eq!(&chained[..5], b"KPKL\x01");
    let node = decode_packlist(&chained).unwrap();
    assert_eq!(node.prev, Some(seed("packlist-prev")));
    assert_eq!(
        node.packs,
        [seed("packlist-pack-1"), seed("packlist-pack-2")]
    );
}

#[test]
fn stash_manifest_vector_keeps_reading() {
    let bytes = format_vector(
        "stash-list.bin",
        "ed2185e9ded879fba71561ebcb754d1b93850a54cf33b78d6d577beeb520ceca",
    );
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
}

/// A stash that kit 0.8.1 saved with `kit stash push -m wip`: a staged change
/// to `a.txt`, an unstaged change to `b.txt`, an untracked `c.txt`, and no `p` scope blob in the
/// index wrapper, which 0.9 added. The manifest and the 13 loose objects of
/// that repository are committed as `formats/stash-08-*`. Nothing in them
/// was written by this checkout.
#[test]
fn stash_entry_of_0_8_keeps_applying() {
    let manifest = format_vector(
        "stash-08-list.bin",
        "93cf8f1d8f028b34df0a785cc4dc1f6821fad3cf3a9ab50d1331023f2efd11df",
    );
    let list = stash::deserialize_list(&manifest).unwrap();
    let head =
        hash::from_hex("7e50456cdc0cc3505d3f2e0d2565b68cbcd154fbdd88bfd936a0531e1d168ec0").unwrap();
    let saved =
        hash::from_hex("530c4cb8538320d5f693fad8334250ea08a3989070a58f134187a801a7496c39").unwrap();
    assert_eq!(list.entries.len(), 1);
    assert_eq!(list.entries[0].commit_hash, saved);
    assert_eq!(list.entries[0].parent_hash, head);
    assert_eq!(list.entries[0].message, "On main: wip");

    let dir = tempfile::tempdir().unwrap();
    let layout = RepoLayout::single(dir.path());
    fs::create_dir_all(layout.objects_dir()).unwrap();
    fs::write(layout.format_file(), b"bmt-v2\n").unwrap();
    fs::write(layout.stash_file(), &manifest).unwrap();
    let mut objects = 0;
    for file in fs::read_dir(golden("formats")).unwrap() {
        let name = file.unwrap().file_name().into_string().unwrap();
        let Some(id) = name
            .strip_prefix("stash-08-")
            .and_then(|n| n.strip_suffix(".bin"))
            .filter(|n| n.len() == 64)
        else {
            continue;
        };
        let loose = layout.objects_dir().join(&id[..2]);
        fs::create_dir_all(&loose).unwrap();
        fs::write(loose.join(&id[2..]), read(&format!("formats/{name}"))).unwrap();
        objects += 1;
    }
    assert_eq!(objects, 13);
    let store = ObjectStore::open(&layout).unwrap();

    // The index wrapper has `i` and `t` only: kit 0.8 had no selected stashes,
    // so the entry reads as a full stash.
    assert_eq!(
        stash::entry_restore_options(&store, &layout, 0)
            .unwrap()
            .sparse_patterns,
        None
    );
    let staged = stash::entry_index(&store, &layout, 0).unwrap();
    let paths: Vec<_> = staged.entries.iter().map(|e| e.path.as_str()).collect();
    assert_eq!(paths, ["a.txt", "b.txt"]);

    // The worktree as the stash left it: `HEAD`'s files.
    fs::write(dir.path().join("a.txt"), b"one\n").unwrap();
    fs::write(dir.path().join("b.txt"), b"keep\n").unwrap();
    stash::apply(&store, &layout, 0).unwrap();
    assert_eq!(fs::read(dir.path().join("a.txt")).unwrap(), b"two\n");
    assert_eq!(fs::read(dir.path().join("b.txt")).unwrap(), b"changed\n");
    // The stash also holds the untracked `c.txt`. Pop refuses to overwrite it,
    // so put the worktree back as it was and pop.
    assert_eq!(fs::read(dir.path().join("c.txt")).unwrap(), b"new\n");
    fs::remove_file(dir.path().join("c.txt")).unwrap();
    fs::write(dir.path().join("a.txt"), b"one\n").unwrap();
    fs::write(dir.path().join("b.txt"), b"keep\n").unwrap();
    stash::pop(&store, &layout, 0).unwrap();
    assert!(stash::list(&layout).unwrap().entries.is_empty());
}

#[cfg(feature = "sparse-checkout")]
#[test]
fn sparse_wire_and_cache_vectors_keep_reading() {
    use kit_core::sparse::{decode_sparse_cache, decode_sparse_response};

    let wire = read("sparse/response_v2.bin");
    assert_eq!(&wire[..5], b"KSP1\x02");
    let response = decode_sparse_response(&wire).unwrap();

    let cache = format_vector(
        "sparse-cache.bin",
        "da65e1069a7f916b32993b12a05c7eeef3305479ec07da0588128238863ab832",
    );
    assert_eq!(&cache[..5], b"KSPC\x02");
    let (manifest, proof) = decode_sparse_cache(&cache).unwrap();
    assert_eq!(manifest, response.manifest);
    assert_eq!(proof.tree_bytes, response.proof.tree_bytes);
    // The two envelopes differ in the magic only.
    assert_eq!(cache[4..], wire[4..]);
}
