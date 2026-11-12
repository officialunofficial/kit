//! Golden vectors for the SPEC-DISCLOSURE.md closure profile.
//!
//! Two halves, same as `golden_disclosure.rs`:
//!
//! * [`write_all`] (`KIT_WRITE_GOLDEN=1`) builds vectors from a small
//!   fixture repo and writes `.manifest.bin` / `.packN.bin` / `.json` /
//!   `MANIFEST.txt` under `rust/tests/golden/closure/`.
//! * `golden_closure_vectors_verify` reads ONLY the committed files.
#![allow(
    clippy::unwrap_used,
    clippy::too_many_lines,
    clippy::too_many_arguments,
    clippy::needless_pass_by_value
)]

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;

use kit_core::chunker::{ChunkIterator, FastCdc};
use kit_core::hash::{Hash, ZERO, from_hex, hash, to_hex};
use kit_core::layout::RepoLayout;
use kit_core::object::{
    Blob, ChunkedBlob, Commit, EntryMode, Identity, Object, ObjectType, Remix, Tag, Tree, TreeEntry,
};
use kit_core::pack::{PackEntries, PackEntry, PackWriter, pack_key};
use kit_core::sign::{KeyPair, sign_commit, sign_remix, sign_tag};
use kit_core::store::ObjectStore;
use kit_core::verify::{
    ClosureManifest, ObjectSource, export_closure, verify_closure, verify_closure_manifest,
    verify_closure_streaming,
};
use kit_core::worktree::store_file_object;
use kit_core::{ClosureMode, reachable_objects, reachable_snapshot};
use serde_json::{Value, json};

mod common;

fn golden_root() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("tests");
    d.push("golden");
    d
}

fn closure_dir() -> PathBuf {
    golden_root().join("closure")
}

fn writing() -> bool {
    std::env::var("KIT_WRITE_GOLDEN").is_ok()
}

struct Vector {
    name: &'static str,
    description: String,
    manifest: Vec<u8>,
    packs: Vec<Vec<u8>>,
    json: Value,
}

struct BorrowedSource<'a> {
    objects: BTreeMap<Hash, &'a [u8]>,
}

impl ObjectSource for BorrowedSource<'_> {
    fn fetch(&mut self, id: &Hash) -> Result<Option<Cow<'_, [u8]>>, kit_core::verify::VerifyError> {
        Ok(self.objects.get(id).map(|bytes| Cow::Borrowed(*bytes)))
    }
}

fn mode_str(mode: ClosureMode) -> &'static str {
    match mode {
        ClosureMode::Snapshot => "snapshot",
        ClosureMode::History => "history",
    }
}

fn mode_from_str(mode: &str) -> ClosureMode {
    match mode {
        "snapshot" => ClosureMode::Snapshot,
        "history" => ClosureMode::History,
        other => panic!("unknown closure mode {other:?}"),
    }
}

fn accept_json(
    name: &str,
    description: &str,
    root: &Hash,
    mode: ClosureMode,
    packs: &[Vec<u8>],
    verified: usize,
    ids: &[Hash],
    unreferenced: &[Hash],
    expect: &str,
    reason: Option<&str>,
) -> Value {
    let mut v = json!({
        "name": name,
        "description": description,
        "root_hex": to_hex(root),
        "mode": mode_str(mode),
        "pack_hashes": packs.iter().map(|p| to_hex(&pack_key(p))).collect::<Vec<_>>(),
        "verified": verified,
        "ids": ids.iter().map(to_hex).collect::<Vec<_>>(),
        "unreferenced": unreferenced.iter().map(to_hex).collect::<Vec<_>>(),
        "expect": expect,
    });
    if let Some(r) = reason {
        v["reason"] = json!(r);
    }
    v
}

fn pack_objects(objects: &[Vec<u8>]) -> Vec<u8> {
    let mut w = PackWriter::new_raw_only();
    for bytes in objects {
        let obj = kit_core::serialize::deserialize(bytes).unwrap();
        let id = kit_core::object::id_from_object(&obj, bytes);
        w.push_raw(id, bytes).unwrap();
    }
    w.finish().unwrap()
}

fn objects_from_packs(packs: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for pack in packs {
        for entry in PackEntries::new(pack).unwrap() {
            let PackEntry::Raw { bytes } = entry.unwrap() else {
                panic!("expected raw-only pack");
            };
            out.push(bytes.into_owned());
        }
    }
    out
}

fn sorted_ids(store: &ObjectStore, root: &Hash, mode: ClosureMode) -> Vec<Hash> {
    match mode {
        ClosureMode::Snapshot => reachable_snapshot(store, root).unwrap(),
        ClosureMode::History => reachable_objects(store, root).unwrap(),
    }
    .into_iter()
    .collect()
}

fn history_head(store: &ObjectStore, parent: Hash) -> Hash {
    let extra = store_file_object(store, b"history-only child file").unwrap();
    let tree = Tree {
        entries: vec![TreeEntry {
            name: b"child.txt".to_vec(),
            mode: EntryMode::Blob,
            object_hash: extra,
        }],
    };
    let tree_hash = store
        .write(&kit_core::serialize::serialize(&Object::Tree(tree)).unwrap())
        .unwrap();
    let kp = KeyPair::from_seed([0x07; 32]);
    let mut commit = Commit {
        tree_hash,
        parents: vec![parent],
        author: Identity::ed25519(kp.public.0),
        signer: kp.public.0,
        message: b"SPEC-DISCLOSURE closure history head".to_vec(),
        timestamp: 1_726_300_001,
        message_hash: ZERO,
        content_digest: ZERO,
        signature: [0u8; 64],
    };
    commit.signature = sign_commit(&commit, &kp).unwrap().0;
    store
        .write(&kit_core::serialize::serialize(&Object::Commit(commit)).unwrap())
        .unwrap()
}

fn tag_for(store: &ObjectStore, commit_id: Hash) -> Hash {
    let kp = KeyPair::from_seed([0x07; 32]);
    let mut tag = Tag {
        target: commit_id,
        target_type: ObjectType::Commit,
        name: b"v-closure".to_vec(),
        tagger: Identity::ed25519(kp.public.0),
        signer: kp.public.0,
        message: b"closure tag root".to_vec(),
        timestamp: 1_726_300_002,
        signature: [0u8; 64],
    };
    tag.signature = sign_tag(&tag, &kp).unwrap().0;
    store
        .write(&kit_core::serialize::serialize(&Object::Tag(tag)).unwrap())
        .unwrap()
}

/// Size of the chunked file in the closure fixture. The file is above
/// the `FastCDC` minimum chunk size (16 KiB) and splits into several
/// chunks. It is far below the 1 MiB threshold the worktree uses,
/// because the fixture writes the `ChunkedBlob` directly. This keeps the
/// vectors small.
const CHUNKED_FILE_LEN: usize = 36 * 1024;

struct ClosureFixture {
    _dir: tempfile::TempDir,
    store: ObjectStore,
    commit_id: Hash,
    tree_hash: Hash,
}

fn write_object(store: &ObjectStore, object: Object) -> Hash {
    store
        .write(&kit_core::serialize::serialize(&object).unwrap())
        .unwrap()
}

fn build_fixture() -> ClosureFixture {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let store = ObjectStore::init(&RepoLayout::single(dir.path())).expect("store init");

    let shallow = store_file_object(&store, b"shallow file content").unwrap();
    let deep_file = store_file_object(&store, b"three levels deep, deterministic").unwrap();
    let exec = store_file_object(&store, b"#!/bin/sh\necho hi\n").unwrap();

    let chunked_bytes = common::prng_bytes(3, CHUNKED_FILE_LEN);
    let chunks: Vec<Hash> = ChunkIterator::new(FastCdc::v1(), &chunked_bytes)
        .take(chunked_bytes.len() + 1)
        .map(|b| {
            let data = chunked_bytes[b.offset..b.offset + b.length].to_vec();
            write_object(&store, Object::Blob(Blob { data }))
        })
        .collect();
    assert!(chunks.len() > 1, "fixture file must split into chunks");
    let chunked_id = write_object(
        &store,
        Object::ChunkedBlob(ChunkedBlob {
            total_size: CHUNKED_FILE_LEN as u64,
            chunk_size: 0,
            chunks,
        }),
    );

    let entry = |name: &[u8], mode, object_hash| TreeEntry {
        name: name.to_vec(),
        mode,
        object_hash,
    };
    let deep_tree_id = write_object(
        &store,
        Object::Tree(Tree {
            entries: vec![entry(b"deep.txt", EntryMode::Blob, deep_file)],
        }),
    );
    let mid_tree_id = write_object(
        &store,
        Object::Tree(Tree {
            entries: vec![entry(b"deep", EntryMode::Tree, deep_tree_id)],
        }),
    );
    let tree_hash = write_object(
        &store,
        Object::Tree(Tree {
            entries: vec![
                entry(b"chunked.bin", EntryMode::Blob, chunked_id),
                entry(b"exec.sh", EntryMode::Executable, exec),
                entry(b"shallow.txt", EntryMode::Blob, shallow),
                entry(b"sub", EntryMode::Tree, mid_tree_id),
            ],
        }),
    );

    let kp = KeyPair::from_seed([0x07; 32]);
    let mut commit = Commit {
        tree_hash,
        parents: vec![],
        author: Identity::ed25519(kp.public.0),
        signer: kp.public.0,
        message: b"SPEC-DISCLOSURE closure fixture".to_vec(),
        timestamp: 1_726_300_000,
        message_hash: ZERO,
        content_digest: ZERO,
        signature: [0u8; 64],
    };
    commit.signature = sign_commit(&commit, &kp).unwrap().0;
    let commit_id = write_object(&store, Object::Commit(commit));

    ClosureFixture {
        _dir: dir,
        store,
        commit_id,
        tree_hash,
    }
}

const DAMAGED_BLOB: &str = "One blob's magic byte flipped so deserialize fails. The blob it replaces is missing and the damaged bytes are unreferenced.";

const UNDECODABLE_EXTRA: &str =
    "Bytes that decode to no object are supplied; unreferenced, still complete.";

/// Canonical bytes of `object` and its id.
fn object_bytes(object: Object) -> (Hash, Vec<u8>) {
    let bytes = kit_core::serialize::serialize(&object).unwrap();
    (kit_core::object::id_from_object(&object, &bytes), bytes)
}

/// A signed commit over `tree_hash` with no parent.
fn signed_commit(tree_hash: Hash) -> (Hash, Vec<u8>) {
    let kp = KeyPair::from_seed([0x07; 32]);
    let mut commit = Commit {
        tree_hash,
        parents: vec![],
        author: Identity::ed25519(kp.public.0),
        signer: kp.public.0,
        message: b"SPEC-DISCLOSURE closure entry mode vector".to_vec(),
        timestamp: 1_726_300_003,
        message_hash: ZERO,
        content_digest: ZERO,
        signature: [0u8; 64],
    };
    commit.signature = sign_commit(&commit, &kp).unwrap().0;
    object_bytes(Object::Commit(commit))
}

/// An incomplete vector whose root has a reachable object that does not fit.
fn corrupt_vector(
    name: &'static str,
    description: &str,
    root: Hash,
    objects: &[Vec<u8>],
) -> Vector {
    let pack = pack_objects(objects);
    let manifest = ClosureManifest {
        root,
        mode: ClosureMode::Snapshot,
        packs: vec![pack_key(&pack)],
    }
    .encode();
    Vector {
        name,
        description: description.into(),
        json: accept_json(
            name,
            description,
            &root,
            ClosureMode::Snapshot,
            std::slice::from_ref(&pack),
            0,
            &[],
            &[],
            "incomplete",
            Some("corrupt"),
        ),
        manifest,
        packs: vec![pack],
    }
}

fn build_vectors() -> Vec<Vector> {
    let f = build_fixture();
    let mut v = Vec::new();

    // snapshot
    {
        let export = export_closure(&f.store, &f.commit_id, ClosureMode::Snapshot).unwrap();
        let ids = sorted_ids(&f.store, &f.commit_id, ClosureMode::Snapshot);
        v.push(Vector {
            name: "snapshot",
            description: "Snapshot closure of the fixture head commit.".into(),
            json: accept_json(
                "snapshot",
                "Snapshot closure of the fixture head commit.",
                &f.commit_id,
                ClosureMode::Snapshot,
                &export.packs,
                ids.len(),
                &ids,
                &[],
                "accept",
                None,
            ),
            manifest: export.manifest,
            packs: export.packs,
        });
    }

    // history
    let head = history_head(&f.store, f.commit_id);
    {
        let export = export_closure(&f.store, &head, ClosureMode::History).unwrap();
        let ids = sorted_ids(&f.store, &head, ClosureMode::History);
        v.push(Vector {
            name: "history",
            description: "History closure of a second commit; parent tree objects are present."
                .into(),
            json: accept_json(
                "history",
                "History closure of a second commit; parent tree objects are present.",
                &head,
                ClosureMode::History,
                &export.packs,
                ids.len(),
                &ids,
                &[],
                "accept",
                None,
            ),
            manifest: export.manifest,
            packs: export.packs,
        });
    }

    // tag_root
    let tag_id = tag_for(&f.store, f.commit_id);
    {
        let export = export_closure(&f.store, &tag_id, ClosureMode::Snapshot).unwrap();
        let ids = sorted_ids(&f.store, &tag_id, ClosureMode::Snapshot);
        v.push(Vector {
            name: "tag_root",
            description: "Snapshot closure whose root is a tag pointing at the fixture commit."
                .into(),
            json: accept_json(
                "tag_root",
                "Snapshot closure whose root is a tag pointing at the fixture commit.",
                &tag_id,
                ClosureMode::Snapshot,
                &export.packs,
                ids.len(),
                &ids,
                &[],
                "accept",
                None,
            ),
            manifest: export.manifest,
            packs: export.packs,
        });
    }

    let snap = export_closure(&f.store, &f.commit_id, ClosureMode::Snapshot).unwrap();
    let snap_objects = objects_from_packs(&snap.packs);

    // missing chunk: drop one chunk blob of the chunked file
    {
        let mut objects = snap_objects.clone();
        let chunked_id = {
            let Object::Tree(root) = f.store.read_object(&f.tree_hash).unwrap() else {
                panic!("root tree");
            };
            root.entries
                .iter()
                .find(|e| e.name == b"chunked.bin")
                .unwrap()
                .object_hash
        };
        let Object::ChunkedBlob(cb) = f.store.read_object(&chunked_id).unwrap() else {
            panic!("chunked");
        };
        let drop_id = cb.chunks[0];
        objects.retain(|b| {
            kit_core::serialize::deserialize(b)
                .ok()
                .map(|o| kit_core::object::id_from_object(&o, b))
                != Some(drop_id)
        });
        let pack = pack_objects(&objects);
        let manifest = ClosureManifest {
            root: f.commit_id,
            mode: ClosureMode::Snapshot,
            packs: vec![pack_key(&pack)],
        }
        .encode();
        v.push(Vector {
            name: "neg_missing_chunk",
            description: "One chunk blob dropped from the snapshot export.".into(),
            json: accept_json(
                "neg_missing_chunk",
                "One chunk blob dropped from the snapshot export.",
                &f.commit_id,
                ClosureMode::Snapshot,
                std::slice::from_ref(&pack),
                0,
                &[],
                &[],
                "incomplete",
                Some("missing"),
            ),
            manifest,
            packs: vec![pack],
        });
    }

    // corrupt blob: flip a MAGIC byte so deserialize fails
    {
        let mut objects = snap_objects.clone();
        let shallow = objects
            .iter()
            .position(|b| {
                b.windows(b"shallow file content".len())
                    .any(|w| w == b"shallow file content")
            })
            .expect("shallow blob");
        objects[shallow][1] ^= 0xFF;
        let pack = pack_objects_raw(&objects);
        let manifest = ClosureManifest {
            root: f.commit_id,
            mode: ClosureMode::Snapshot,
            packs: vec![pack_key(&pack)],
        }
        .encode();
        v.push(Vector {
            name: "neg_corrupt_blob",
            description: DAMAGED_BLOB.into(),
            json: accept_json(
                "neg_corrupt_blob",
                DAMAGED_BLOB,
                &f.commit_id,
                ClosureMode::Snapshot,
                std::slice::from_ref(&pack),
                0,
                &[],
                &[],
                "incomplete",
                Some("missing"),
            ),
            manifest,
            packs: vec![pack],
        });
    }

    // entry modes and chunk lists that do not fit together
    {
        let (blob_id, blob_bytes) = object_bytes(Object::Blob(Blob {
            data: b"mode vector blob".to_vec(),
        }));
        let (inner_id, inner_bytes) = object_bytes(Object::Tree(Tree {
            entries: vec![TreeEntry {
                name: b"g".to_vec(),
                mode: EntryMode::Blob,
                object_hash: blob_id,
            }],
        }));
        let (five_id, five_bytes) = object_bytes(Object::Blob(Blob {
            data: b"12345".to_vec(),
        }));
        let (seven_id, seven_bytes) = object_bytes(Object::Blob(Blob {
            data: b"1234567".to_vec(),
        }));
        let chunked = |chunks: &[Hash]| {
            object_bytes(Object::ChunkedBlob(ChunkedBlob {
                total_size: 13,
                chunk_size: 0,
                chunks: chunks.to_vec(),
            }))
        };
        let (names_tree_id, names_tree_bytes) = chunked(&[inner_id]);
        let (sum_id, sum_bytes) = chunked(&[five_id, seven_id]);
        let (fixed_id, fixed_bytes) = object_bytes(Object::ChunkedBlob(ChunkedBlob {
            total_size: 12,
            chunk_size: 6,
            chunks: vec![five_id, seven_id],
        }));
        for (name, description, mode, target, objects) in [
            (
                "neg_tree_mode_names_blob",
                "A tree entry of mode Tree names a blob.",
                EntryMode::Tree,
                blob_id,
                vec![blob_bytes.clone()],
            ),
            (
                "neg_blob_mode_names_tree",
                "A tree entry of mode Blob names a tree.",
                EntryMode::Blob,
                inner_id,
                vec![inner_bytes.clone(), blob_bytes.clone()],
            ),
            (
                "neg_chunk_names_non_blob",
                "A chunk id of a ChunkedBlob names a tree.",
                EntryMode::Blob,
                names_tree_id,
                vec![names_tree_bytes, inner_bytes.clone(), blob_bytes.clone()],
            ),
            (
                "neg_fixed_chunk_length",
                "A ChunkedBlob of chunk_size 6 and total_size 12 whose chunks hold 5 and 7 bytes.",
                EntryMode::Blob,
                fixed_id,
                vec![fixed_bytes, five_bytes.clone(), seven_bytes.clone()],
            ),
            (
                "neg_chunk_length_sum",
                "The chunk lengths of a ChunkedBlob add up to 12, but its total_size is 13.",
                EntryMode::Blob,
                sum_id,
                vec![sum_bytes, five_bytes, seven_bytes],
            ),
        ] {
            let (tree_id, tree_bytes) = object_bytes(Object::Tree(Tree {
                entries: vec![TreeEntry {
                    name: b"f".to_vec(),
                    mode,
                    object_hash: target,
                }],
            }));
            let (root, commit_bytes) = signed_commit(tree_id);
            let mut objects = objects;
            objects.extend([commit_bytes, tree_bytes]);
            v.push(corrupt_vector(name, description, root, &objects));
        }

        // Two entries name one absent object, as a tree and as a file. The
        // edges conflict, so the id is corrupt as well as missing.
        let absent = hash(b"an object no pack supplies");
        let (tree_id, tree_bytes) = object_bytes(Object::Tree(Tree {
            entries: vec![
                TreeEntry {
                    name: b"a".to_vec(),
                    mode: EntryMode::Tree,
                    object_hash: absent,
                },
                TreeEntry {
                    name: b"b".to_vec(),
                    mode: EntryMode::Blob,
                    object_hash: absent,
                },
            ],
        }));
        let (root, commit_bytes) = signed_commit(tree_id);
        v.push(corrupt_vector(
            "neg_conflicting_edges_to_missing",
            "Two tree entries name one absent object, one as a tree and one as a file.",
            root,
            &[commit_bytes, tree_bytes],
        ));

        // A commit, a remix and a tag whose tree or target has the wrong type.
        let (remix_id, remix_bytes) = {
            let kp = KeyPair::from_seed([0x07; 32]);
            let mut remix = Remix {
                tree_hash: blob_id,
                parents: vec![],
                sources: vec![],
                author: Identity::ed25519(kp.public.0),
                signer: kp.public.0,
                message: b"SPEC-DISCLOSURE closure remix vector".to_vec(),
                timestamp: 1_726_300_004,
                signature: [0u8; 64],
            };
            remix.signature = sign_remix(&remix, &kp).unwrap().0;
            object_bytes(Object::Remix(remix))
        };
        let (commit_id, commit_bytes) = signed_commit(blob_id);
        let (tag_id, tag_bytes) = {
            let kp = KeyPair::from_seed([0x07; 32]);
            let mut tag = Tag {
                target: inner_id,
                target_type: ObjectType::Commit,
                name: b"v-closure-lie".to_vec(),
                tagger: Identity::ed25519(kp.public.0),
                signer: kp.public.0,
                message: b"records a commit, names a tree".to_vec(),
                timestamp: 1_726_300_005,
                signature: [0u8; 64],
            };
            tag.signature = sign_tag(&tag, &kp).unwrap().0;
            object_bytes(Object::Tag(tag))
        };
        v.push(corrupt_vector(
            "neg_commit_tree_names_blob",
            "A commit's tree_hash names a blob.",
            commit_id,
            &[commit_bytes, blob_bytes.clone()],
        ));
        v.push(corrupt_vector(
            "neg_remix_tree_names_blob",
            "A remix's tree_hash names a blob.",
            remix_id,
            &[remix_bytes, blob_bytes.clone()],
        ));
        v.push(corrupt_vector(
            "neg_tag_target_type",
            "A tag records target_type Commit but its target is a tree.",
            tag_id,
            &[tag_bytes, inner_bytes, blob_bytes],
        ));
    }

    // undecodable extra: bytes that are no object are unreferenced
    {
        let junk = b"bytes that are not an object".to_vec();
        let junk_id = hash(&junk);
        let mut objects = snap_objects.clone();
        objects.push(junk);
        let pack = pack_objects_raw(&objects);
        let ids = sorted_ids(&f.store, &f.commit_id, ClosureMode::Snapshot);
        let manifest = ClosureManifest {
            root: f.commit_id,
            mode: ClosureMode::Snapshot,
            packs: vec![pack_key(&pack)],
        }
        .encode();
        v.push(Vector {
            name: "unreferenced_undecodable_extra",
            description: UNDECODABLE_EXTRA.into(),
            json: accept_json(
                "unreferenced_undecodable_extra",
                UNDECODABLE_EXTRA,
                &f.commit_id,
                ClosureMode::Snapshot,
                std::slice::from_ref(&pack),
                ids.len(),
                &ids,
                &[junk_id],
                "accept",
                Some("unreferenced"),
            ),
            manifest,
            packs: vec![pack],
        });
    }

    // unreferenced extra
    {
        let extra = kit_core::serialize::serialize(&Object::Blob(Blob {
            data: b"unrelated extra blob".to_vec(),
        }))
        .unwrap();
        let extra_id = kit_core::object::id_from_object(
            &kit_core::serialize::deserialize(&extra).unwrap(),
            &extra,
        );
        let mut objects = snap_objects.clone();
        objects.push(extra);
        let pack = pack_objects(&objects);
        let ids = sorted_ids(&f.store, &f.commit_id, ClosureMode::Snapshot);
        let manifest = ClosureManifest {
            root: f.commit_id,
            mode: ClosureMode::Snapshot,
            packs: vec![pack_key(&pack)],
        }
        .encode();
        v.push(Vector {
            name: "neg_unreferenced_extra",
            description: "An unrelated blob is supplied; still complete.".into(),
            json: accept_json(
                "neg_unreferenced_extra",
                "An unrelated blob is supplied; still complete.",
                &f.commit_id,
                ClosureMode::Snapshot,
                std::slice::from_ref(&pack),
                ids.len(),
                &ids,
                &[extra_id],
                "accept",
                Some("unreferenced"),
            ),
            manifest,
            packs: vec![pack],
        });
    }

    // delta entry
    {
        let base = kit_core::serialize::serialize(&Object::Blob(Blob {
            data: b"delta-base-for-closure-neg".to_vec(),
        }))
        .unwrap();
        let target = kit_core::serialize::serialize(&Object::Blob(Blob {
            data: b"delta-target-for-closure-neg".to_vec(),
        }))
        .unwrap();
        let base_hash = hash(&base);
        let stream = kit_core::delta::encode(&base, &target).unwrap();
        let mut w = PackWriter::new();
        w.push_raw(base_hash, &base).unwrap();
        w.push_delta(&base_hash, &stream).unwrap();
        let pack = w.finish().unwrap();
        let manifest = ClosureManifest {
            root: f.commit_id,
            mode: ClosureMode::Snapshot,
            packs: vec![pack_key(&pack)],
        }
        .encode();
        v.push(Vector {
            name: "neg_delta_entry",
            description: "A pack written with the normal writer containing a delta entry.".into(),
            json: accept_json(
                "neg_delta_entry",
                "A pack written with the normal writer containing a delta entry.",
                &f.commit_id,
                ClosureMode::Snapshot,
                std::slice::from_ref(&pack),
                0,
                &[],
                &[],
                "reject",
                Some("profile violation (delta)"),
            ),
            manifest,
            packs: vec![pack],
        });
    }

    // compressed entry — hand-built v2 0x03 so this vector does not
    // depend on the `pack-zstd` feature (is_raw_only scans types without
    // decompressing).
    {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"KIT\0");
        buf.extend_from_slice(&2u32.to_le_bytes());
        buf.extend_from_slice(&1u32.to_le_bytes());
        buf.push(0x03);
        let mut inner = Vec::new();
        inner.extend_from_slice(&64u32.to_le_bytes());
        inner.extend_from_slice(&[0u8; 8]);
        buf.extend_from_slice(&u32::try_from(inner.len()).unwrap().to_le_bytes());
        buf.extend_from_slice(&inner);
        let trailer = hash(&buf);
        buf.extend_from_slice(&trailer);
        let pack = buf;
        let manifest = ClosureManifest {
            root: f.commit_id,
            mode: ClosureMode::Snapshot,
            packs: vec![pack_key(&pack)],
        }
        .encode();
        v.push(Vector {
            name: "neg_compressed_entry",
            description: "A pack written with the normal writer (pack-zstd) so the entry is 0x03."
                .into(),
            json: accept_json(
                "neg_compressed_entry",
                "A pack written with the normal writer (pack-zstd) so the entry is 0x03.",
                &f.commit_id,
                ClosureMode::Snapshot,
                std::slice::from_ref(&pack),
                0,
                &[],
                &[],
                "reject",
                Some("profile violation (compressed)"),
            ),
            manifest,
            packs: vec![pack],
        });
    }

    // manifest pack-hash mismatch
    {
        let mut decoded = ClosureManifest::decode(&snap.manifest).unwrap();
        decoded.packs[0] = [0xFF; 32];
        v.push(Vector {
            name: "neg_manifest_pack_hash",
            description: "Manifest pack hash does not equal pack_key of the supplied pack.".into(),
            json: accept_json(
                "neg_manifest_pack_hash",
                "Manifest pack hash does not equal pack_key of the supplied pack.",
                &f.commit_id,
                ClosureMode::Snapshot,
                &snap.packs,
                0,
                &[],
                &[],
                "reject",
                Some("pack-hash mismatch"),
            ),
            manifest: decoded.encode(),
            packs: snap.packs.clone(),
        });
    }

    // wrong root id
    {
        let other = [0x11u8; 32];
        let mut decoded = ClosureManifest::decode(&snap.manifest).unwrap();
        decoded.root = other;
        v.push(Vector {
            name: "neg_wrong_root",
            description: "Bundle is complete for A, verified against a different root B.".into(),
            json: accept_json(
                "neg_wrong_root",
                "Bundle is complete for A, verified against a different root B.",
                &other,
                ClosureMode::Snapshot,
                &snap.packs,
                0,
                &[],
                &[],
                "incomplete",
                Some("missing root"),
            ),
            manifest: decoded.encode(),
            packs: snap.packs.clone(),
        });
    }

    // manifest root replaced; caller still supplies the trusted root
    {
        let mut bytes = snap.manifest.clone();
        bytes[5..37].copy_from_slice(&[0x22u8; 32]);
        v.push(Vector {
            name: "neg_manifest_wrong_root",
            description:
                "A valid snapshot export whose manifest root was replaced by another 32-byte value."
                    .into(),
            json: accept_json(
                "neg_manifest_wrong_root",
                "A valid snapshot export whose manifest root was replaced by another 32-byte value.",
                &f.commit_id,
                ClosureMode::Snapshot,
                &snap.packs,
                0,
                &[],
                &[],
                "reject",
                Some("manifest root differs from the caller's trusted root"),
            ),
            manifest: bytes,
            packs: snap.packs.clone(),
        });
    }

    // manifest version 2
    {
        let mut bytes = snap.manifest.clone();
        bytes[4] = 2;
        v.push(Vector {
            name: "neg_manifest_version_2",
            description: "Manifest version byte is 2.".into(),
            json: accept_json(
                "neg_manifest_version_2",
                "Manifest version byte is 2.",
                &f.commit_id,
                ClosureMode::Snapshot,
                &snap.packs,
                0,
                &[],
                &[],
                "reject",
                Some("unsupported version"),
            ),
            manifest: bytes,
            packs: snap.packs.clone(),
        });
    }

    // manifest trailing byte
    {
        let mut bytes = snap.manifest.clone();
        bytes.push(0x00);
        v.push(Vector {
            name: "neg_manifest_trailing_byte",
            description: "One extra trailing byte after the declared manifest body.".into(),
            json: accept_json(
                "neg_manifest_trailing_byte",
                "One extra trailing byte after the declared manifest body.",
                &f.commit_id,
                ClosureMode::Snapshot,
                &snap.packs,
                0,
                &[],
                &[],
                "reject",
                Some("trailing bytes"),
            ),
            manifest: bytes,
            packs: snap.packs.clone(),
        });
    }

    v
}

/// Pack objects without requiring them to deserialize (for corrupt vectors).
fn pack_objects_raw(objects: &[Vec<u8>]) -> Vec<u8> {
    let mut w = PackWriter::new_raw_only();
    for bytes in objects {
        let id = hash(bytes);
        w.push_raw(id, bytes).unwrap();
    }
    w.finish().unwrap()
}

fn write_all() {
    let dir = closure_dir();
    fs::create_dir_all(&dir).expect("create closure/ dir");
    let mut manifest = String::from(
        "# SPEC-DISCLOSURE closure-profile golden vectors (deterministic)\n\
         # Produced by `KIT_WRITE_GOLDEN=1 cargo test -p kit-core --test golden_closure`\n\
         # Format: <name> <blake3-hex-of-manifest-bytes>\n\
         # See docs/specs/SPEC-DISCLOSURE.md.\n",
    );
    for v in build_vectors() {
        let digest = to_hex(&hash(&v.manifest));
        fs::write(dir.join(format!("{}.manifest.bin", v.name)), &v.manifest)
            .expect("write manifest");
        for (i, pack) in v.packs.iter().enumerate() {
            fs::write(dir.join(format!("{}.pack{i}.bin", v.name)), pack).expect("write pack");
        }
        let mut sidecar = v.json.clone();
        sidecar["bin"] = json!(format!("{}.manifest.bin", v.name));
        sidecar["size"] = json!(v.manifest.len());
        sidecar["blake3"] = json!(digest);
        sidecar["n_packs"] = json!(v.packs.len());
        sidecar["description"] = json!(v.description);
        fs::write(
            dir.join(format!("{}.json", v.name)),
            serde_json::to_string_pretty(&sidecar).unwrap() + "\n",
        )
        .expect("write json");
        let _ = writeln!(manifest, "{} {}", v.name, digest);
    }
    fs::write(dir.join("MANIFEST.txt"), manifest).expect("write MANIFEST.txt");
}

#[test]
fn write_golden_closure_vectors_if_requested() {
    if writing() {
        write_all();
    }
}

// Exercise today's encoder independently of the fixture-only verifier below.
// Never regenerate the committed bytes to accommodate a dependency update.
#[test]
fn closure_encoders_match_committed_bytes() {
    if writing() {
        return;
    }
    for vector in build_vectors() {
        let expected = fs::read(closure_dir().join(format!("{}.manifest.bin", vector.name)))
            .expect("read committed golden bytes");
        assert_eq!(
            vector.manifest, expected,
            "{}: encoded bytes changed; investigate before updating the wire format",
            vector.name
        );
    }
}

fn manifest_names_and_digests() -> Vec<(String, String)> {
    let raw = fs::read_to_string(closure_dir().join("MANIFEST.txt"))
        .expect("read rust/tests/golden/closure/MANIFEST.txt");
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
    let dir = closure_dir();
    let manifest = fs::read(dir.join(format!("{name}.manifest.bin")))
        .unwrap_or_else(|e| panic!("cannot read {name}.manifest.bin: {e}"));
    let got_digest = to_hex(&hash(&manifest));
    assert_eq!(
        got_digest, want_digest,
        "{name}.manifest.bin: BLAKE3 digest does not match MANIFEST.txt"
    );

    let sidecar: Value = serde_json::from_str(
        &fs::read_to_string(dir.join(format!("{name}.json")))
            .unwrap_or_else(|e| panic!("cannot read {name}.json: {e}")),
    )
    .unwrap_or_else(|e| panic!("{name}.json is not valid JSON: {e}"));
    assert_eq!(sidecar["blake3"].as_str().unwrap(), want_digest);

    let n_packs = usize::try_from(sidecar["n_packs"].as_u64().unwrap()).unwrap();
    let mut packs = Vec::with_capacity(n_packs);
    for i in 0..n_packs {
        packs.push(
            fs::read(dir.join(format!("{name}.pack{i}.bin")))
                .unwrap_or_else(|e| panic!("cannot read {name}.pack{i}.bin: {e}")),
        );
    }
    let pack_refs: Vec<&[u8]> = packs.iter().map(Vec::as_slice).collect();
    let expected_root: Hash =
        from_hex(sidecar["root_hex"].as_str().unwrap()).expect("sidecar root_hex");
    let expect = sidecar["expect"].as_str().unwrap();

    match expect {
        "reject" => {
            let err = verify_closure_manifest(&expected_root, &manifest, &pack_refs);
            assert!(err.is_err(), "{name}: expected reject, got {err:?}");
        }
        "accept" | "incomplete" => {
            let report = verify_closure_manifest(&expected_root, &manifest, &pack_refs)
                .unwrap_or_else(|e| panic!("{name}: expected {expect}, got {e:?}"));
            if expect == "accept" {
                assert!(
                    report.is_complete(),
                    "{name}: expected complete, missing={:?} corrupt={:?}",
                    report.missing,
                    report.corrupt
                );
                let want_verified = usize::try_from(sidecar["verified"].as_u64().unwrap()).unwrap();
                assert_eq!(report.verified, want_verified, "{name}: verified count");
                let want_unref: Vec<String> = sidecar["unreferenced"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|x| x.as_str().unwrap().to_string())
                    .collect();
                let got_unref: Vec<String> = report.unreferenced.iter().map(to_hex).collect();
                assert_eq!(got_unref, want_unref, "{name}: unreferenced");
                assert!(report.unreferenced_checked, "{name}: unreferenced check");

                let objects = objects_from_packs(&packs);
                let map_report = verify_closure(
                    &expected_root,
                    mode_from_str(sidecar["mode"].as_str().unwrap()),
                    objects.iter().map(Vec::as_slice),
                )
                .unwrap_or_else(|e| panic!("{name}: map path failed: {e:?}"));
                let mut source_objects = BTreeMap::new();
                for bytes in &objects {
                    let Ok(object) = kit_core::serialize::deserialize(bytes) else {
                        continue;
                    };
                    let id = kit_core::object::id_from_object(&object, bytes);
                    source_objects.insert(id, bytes.as_slice());
                }
                let mut source = BorrowedSource {
                    objects: source_objects,
                };
                let streaming_report = verify_closure_streaming(
                    &expected_root,
                    mode_from_str(sidecar["mode"].as_str().unwrap()),
                    &mut source,
                )
                .unwrap_or_else(|e| panic!("{name}: streaming path failed: {e:?}"));
                assert_eq!(map_report.verified, streaming_report.verified, "{name}");
                assert_eq!(map_report.missing, streaming_report.missing, "{name}");
                assert_eq!(
                    map_report.is_complete(),
                    streaming_report.is_complete(),
                    "{name}"
                );
            } else {
                assert!(
                    !report.is_complete(),
                    "{name}: expected incomplete, report was complete"
                );
                match sidecar["reason"].as_str().unwrap() {
                    "corrupt" => assert!(!report.corrupt.is_empty(), "{name}: {report:?}"),
                    "missing" | "missing root" => {
                        assert!(!report.missing.is_empty(), "{name}: {report:?}");
                    }
                    other => panic!("{name}.json: unknown reason {other:?}"),
                }
            }
        }
        other => panic!("{name}.json: unknown expect value {other:?}"),
    }
}

#[test]
fn golden_closure_vectors_verify() {
    if writing() {
        return;
    }
    let vectors = manifest_names_and_digests();
    assert!(
        !vectors.is_empty(),
        "MANIFEST.txt listed no vectors — did you forget to run \
         `KIT_WRITE_GOLDEN=1 cargo test -p kit-core --test golden_closure`?"
    );
    for (name, digest) in vectors {
        verify_vector(&name, &digest);
    }
}
