//! Tests of packs on disk: the spool writer, the download spool and the
//! file-backed reader, checked against the slice reader.

use super::file_read::{
    SCAN_BUFFER, WindowShape, bookkeeping, decoded_share, file_budget, read_file,
};
use super::*;
use crate::layout::RepoLayout;
use crate::object::{Blob, Commit, Identity, ObjectType, Remix, RemixSource, Tag, Tree, TreeEntry};
use crate::protocol::{PACK_BODY_LIMIT, PackKey};
use crate::serialize;
use proptest::prelude::*;
use std::collections::BTreeMap;
use std::path::Path;
use tempfile::TempDir;

fn fresh_store() -> (TempDir, ObjectStore) {
    let dir = TempDir::new().unwrap();
    let store = ObjectStore::init(&RepoLayout::single(dir.path())).unwrap();
    (dir, store)
}

/// Every object file under the store, by path, with its bytes.
fn objects(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    let root = dir.join(".kit").join("objects");
    for shard in std::fs::read_dir(&root).unwrap() {
        let shard = shard.unwrap();
        if !shard.file_type().unwrap().is_dir() {
            continue;
        }
        let name = shard.file_name().into_string().unwrap();
        if name.len() != 2 {
            continue;
        }
        for file in std::fs::read_dir(shard.path()).unwrap() {
            let file = file.unwrap();
            let file_name = file.file_name().into_string().unwrap();
            if file_name.len() == 62 {
                out.insert(
                    format!("{name}{file_name}"),
                    std::fs::read(file.path()).unwrap(),
                );
            }
        }
    }
    out
}

/// A pack the spool checked, from its bytes, fed in uneven pieces.
fn verified(bytes: &[u8], dir: &Path) -> VerifiedPack {
    let mut spool = PackSpool::create(dir, PACK_BODY_LIMIT).unwrap();
    spool.begin(Some(bytes.len() as u64)).unwrap();
    for piece in bytes.chunks(7919) {
        spool.write(piece).unwrap();
    }
    spool.finish(&PackKey::new(pack_key(bytes))).unwrap()
}

/// `body` with a correct trailer appended.
fn with_trailer(mut body: Vec<u8>) -> Vec<u8> {
    let trailer = hash::hash(&body);
    body.extend_from_slice(&trailer);
    body
}

fn blob(data: &[u8]) -> (Hash, Vec<u8>) {
    let bytes = serialize::serialize(&Object::Blob(Blob {
        data: data.to_vec(),
    }))
    .unwrap();
    (hash::hash(&bytes), bytes)
}

fn object(object: &Object) -> (Hash, Vec<u8>) {
    let bytes = serialize::serialize(object).unwrap();
    let id = crate::object::id_from_object(object, &bytes);
    (id, bytes)
}

fn commit(tree: Hash, message: &str) -> Object {
    Object::Commit(Commit {
        tree_hash: tree,
        parents: Vec::new(),
        author: Identity::ed25519([1; 32]),
        signer: [1; 32],
        message: message.as_bytes().to_vec(),
        timestamp: 7,
        message_hash: [0; 32],
        content_digest: [0; 32],
        signature: [0; 64],
    })
}

fn tree(blob: Hash) -> Object {
    Object::Tree(Tree {
        entries: vec![TreeEntry {
            name: b"f".to_vec(),
            mode: crate::object::EntryMode::Blob,
            object_hash: blob,
        }],
    })
}

/// Reads `pack` with the slice reader and with the file reader (cut into
/// windows of `shape`) into two stores seeded with `seed`, and checks they
/// agree: both succeed or both fail, with the same objects stored.
fn assert_readers_agree(pack: &[u8], seed: &[Vec<u8>], shape: WindowShape) {
    let (slice_dir, slice_store) = fresh_store();
    let (file_dir, file_store) = fresh_store();
    let slice_seed = slice_store.batch();
    let file_seed = file_store.batch();
    for bytes in seed {
        slice_seed.write(bytes).unwrap();
        file_seed.write(bytes).unwrap();
    }
    slice_seed.commit().unwrap();
    file_seed.commit().unwrap();
    let spool_dir = TempDir::new().unwrap();
    let from_slice = PackReader::read(pack, &slice_store);
    let pack_file = verified(pack, spool_dir.path());
    let from_file = read_file(&pack_file, &file_store, shape, None, None);
    match (&from_slice, &from_file) {
        (Ok(slice), Ok(file)) => {
            assert_eq!(slice.raw_count, file.raw_count);
            assert_eq!(slice.delta_count, file.delta_count);
            assert_eq!(slice.signed, file.signed);
            assert!(file.stored.is_empty());
            assert_eq!(
                slice.stored.len(),
                (slice.raw_count + slice.delta_count) as usize
            );
        }
        (Err(_), Err(_)) => {}
        _ => panic!("the readers disagree: slice {from_slice:?}, file {from_file:?}"),
    }
    if from_slice.is_ok() {
        assert_eq!(objects(slice_dir.path()), objects(file_dir.path()));
    }
}

/// One entry of a generated pack.
#[derive(Debug, Clone)]
enum Gen {
    /// A blob of `len` bytes, repeating (compressible) or not.
    Raw { seed: u8, len: usize, repeat: bool },
    /// A raw entry repeating an earlier object.
    Duplicate(usize),
    /// A delta whose target edits an earlier object of the pack: one byte
    /// added, or a long run inserted, which makes a stream the writer
    /// compresses (`0x04`).
    DeltaInPack { base: usize, edit: u8, long: bool },
    /// A delta on one of the objects already in the store.
    DeltaOnStore { base: usize, edit: u8 },
    /// A commit naming a tree of the pack.
    Commit(u8),
}

fn gen_entry() -> impl Strategy<Value = Gen> {
    prop_oneof![
        4 => (any::<u8>(), 0usize..600, any::<bool>())
            .prop_map(|(seed, len, repeat)| Gen::Raw { seed, len, repeat }),
        1 => (0usize..64).prop_map(Gen::Duplicate),
        3 => (0usize..64, any::<u8>(), any::<bool>())
            .prop_map(|(base, edit, long)| Gen::DeltaInPack { base, edit, long }),
        2 => (0usize..4, any::<u8>()).prop_map(|(base, edit)| Gen::DeltaOnStore { base, edit }),
        1 => any::<u8>().prop_map(Gen::Commit),
    ]
}

fn blob_data(seed: u8, len: usize, repeat: bool) -> Vec<u8> {
    (0..len)
        .map(|i| {
            if repeat {
                seed.wrapping_add((i % 7).to_le_bytes()[0])
            } else {
                seed.wrapping_mul(31)
                    .wrapping_add((i * 131 + i / 3).to_le_bytes()[0])
            }
        })
        .collect()
}

/// The objects already in the store that generated deltas may use as bases.
fn store_bases() -> Vec<Vec<u8>> {
    (0..4u8)
        .map(|i| {
            blob(&blob_data(
                i.wrapping_mul(53),
                300 + usize::from(i) * 40,
                i % 2 == 0,
            ))
            .1
        })
        .collect()
}

/// Build a pack from `entries`: the bytes of each object the pack holds, kept
/// so later entries can repeat them or delta on them.
fn build_pack(entries: &[Gen]) -> Vec<u8> {
    let mut w = PackWriter::new();
    fill(&mut w, entries);
    w.finish().unwrap()
}

/// Push `entries` to `w` through the writer's public push methods.
fn fill<W: std::io::Write>(w: &mut PackWriter<W>, entries: &[Gen]) {
    let bases = store_bases();
    let mut held: Vec<(Hash, Vec<u8>)> = Vec::new();
    for entry in entries {
        match *entry {
            Gen::Raw { seed, len, repeat } => {
                let (id, bytes) = blob(&blob_data(seed, len, repeat));
                w.push_raw(id, &bytes).unwrap();
                held.push((id, bytes));
            }
            Gen::Duplicate(at) if !held.is_empty() => {
                let (id, bytes) = held[at % held.len()].clone();
                w.push_raw(id, &bytes).unwrap();
            }
            Gen::DeltaInPack { base, edit, long } if !held.is_empty() => {
                let (base_id, base_bytes) = held[base % held.len()].clone();
                let Ok(Object::Blob(Blob { mut data })) = serialize::deserialize(&base_bytes)
                else {
                    continue;
                };
                if long {
                    let mid = data.len() / 2;
                    data.splice(mid..mid, std::iter::repeat_n(edit, 200));
                } else {
                    data.push(edit);
                }
                let (id, target) = blob(&data);
                w.push_delta(&base_id, &delta::encode(&base_bytes, &target).unwrap())
                    .unwrap();
                held.push((id, target));
            }
            Gen::DeltaOnStore { base, edit } => {
                let base_bytes = &bases[base];
                let Ok(Object::Blob(Blob { mut data })) = serialize::deserialize(base_bytes) else {
                    unreachable!("store bases are blobs")
                };
                data.insert(0, edit);
                let (id, target) = blob(&data);
                w.push_delta(
                    &hash::hash(base_bytes),
                    &delta::encode(base_bytes, &target).unwrap(),
                )
                .unwrap();
                held.push((id, target));
            }
            Gen::Commit(seed) => {
                let (blob_id, blob_bytes) = blob(&[seed]);
                let (tree_id, tree_bytes) = object(&tree(blob_id));
                let (commit_id, commit_bytes) = object(&commit(tree_id, &format!("c{seed}")));
                w.push_raw(blob_id, &blob_bytes).unwrap();
                w.push_raw(tree_id, &tree_bytes).unwrap();
                w.push_raw(commit_id, &commit_bytes).unwrap();
            }
            Gen::Duplicate(_) | Gen::DeltaInPack { .. } => {}
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 48, ..ProptestConfig::default() })]

    /// Random packs of raw, compressed, duplicate and delta entries, with
    /// bases in the pack, in earlier windows and in the store, unpack to the
    /// same store from a slice and from a verified file, cut into windows of
    /// any shape.
    #[test]
    fn random_packs_unpack_the_same_from_a_slice_and_a_file(
        // A few windows cover the same entry shapes without thousands of
        // durable object writes per generated case.
        entries in prop::collection::vec(gen_entry(), 0..24),
        window_entries in 1usize..9,
        window_bytes in 1u64..4096,
    ) {
        let pack = build_pack(&entries);
        let seed = store_bases();
        assert_readers_agree(&pack, &seed, WindowShape { entries: window_entries, bytes: window_bytes });
        assert_readers_agree(&pack, &seed, WindowShape::DEFAULT);
    }

    /// A pack with one byte changed and its trailer fixed is refused by the
    /// file reader exactly when the slice reader refuses it, and otherwise
    /// stores the same objects.
    #[test]
    fn a_changed_pack_is_refused_by_both_readers_or_by_neither(
        entries in prop::collection::vec(gen_entry(), 1..24),
        at in any::<prop::sample::Index>(),
        value in any::<u8>(),
        window_entries in 1usize..5,
    ) {
        let pack = build_pack(&entries);
        let mut body = pack[..pack.len() - TRAILER_LEN].to_vec();
        let at = at.index(body.len());
        body[at] = value;
        let pack = with_trailer(body);
        assert_readers_agree(&pack, &store_bases(), WindowShape { entries: window_entries, bytes: 512 });
    }

    /// The spool writer and the in-memory writer write the same bytes and
    /// give the same key, and each hashes the pack once.
    #[test]
    fn spooled_and_in_memory_writers_give_the_same_bytes_and_key(
        entries in prop::collection::vec(gen_entry(), 0..60),
    ) {
        let in_memory = build_pack(&entries);
        let dir = TempDir::new().unwrap();
        let mut w = PackWriter::spool(dir.path()).unwrap();
        fill(&mut w, &entries);
        let spooled = w.finish_spool().unwrap();
        prop_assert_eq!(spooled.len(), in_memory.len() as u64);
        prop_assert_eq!(spooled.key(), pack_key(&in_memory));
        let mut bytes = vec![0u8; in_memory.len()];
        spooled.read_at(0, &mut bytes).unwrap();
        prop_assert_eq!(bytes, in_memory);
    }
}

/// A pack longer than the spool writer's buffer, so the writer flushes to
/// its file partway and patches the header after: the spool writer and the
/// in-memory writer give the same bytes and key.
#[test]
fn a_spooled_pack_longer_than_its_buffer_matches_the_in_memory_pack() {
    // Incompressible blobs, so the frames stay as long as the objects.
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    let noise: Vec<(Hash, Vec<u8>)> = (0..400)
        .map(|_| {
            let data: Vec<u8> = (0..4096)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    state.to_le_bytes()[0]
                })
                .collect();
            blob(&data)
        })
        .collect();
    let entries = [
        Gen::Raw {
            seed: 5,
            len: 300,
            repeat: false,
        },
        Gen::DeltaInPack {
            base: 0,
            edit: 1,
            long: true,
        },
    ];
    let mut w = PackWriter::new();
    for (id, bytes) in &noise {
        w.push_raw(*id, bytes).unwrap();
    }
    fill(&mut w, &entries);
    let in_memory = w.finish().unwrap();
    assert!(
        in_memory.len() > 3 * SPOOL_BUFFER / 2,
        "{} bytes",
        in_memory.len()
    );
    let dir = TempDir::new().unwrap();
    let mut w = PackWriter::spool(dir.path()).unwrap();
    for (id, bytes) in &noise {
        w.push_raw(*id, bytes).unwrap();
    }
    fill(&mut w, &entries);
    let spooled = w.finish_spool().unwrap();
    assert_eq!(spooled.key(), pack_key(&in_memory));
    let mut bytes = vec![0u8; in_memory.len()];
    spooled.read_at(0, &mut bytes).unwrap();
    assert_eq!(bytes, in_memory);
}

/// The frame type of each entry of `pack`.
fn frame_types(pack: &[u8]) -> Vec<u8> {
    let mut entries = PackEntries::new(pack).unwrap();
    let mut types = Vec::new();
    while let Some(entry) = entries.next() {
        entry.unwrap();
        types.push(pack[entries.last_payload_range().unwrap().start - ENTRY_FRAME_LEN]);
    }
    types
}

/// The generator makes every frame type, so the property tests compare the
/// readers on each: a long inserted run gives a compressed delta (`0x04`),
/// read the same from a slice and from a file across window boundaries.
#[test]
fn generated_packs_hold_every_frame_type() {
    let entries = [
        Gen::Raw {
            seed: 1,
            len: 300,
            repeat: false,
        },
        Gen::Raw {
            seed: 2,
            len: 300,
            repeat: true,
        },
        Gen::DeltaInPack {
            base: 0,
            edit: 9,
            long: false,
        },
        Gen::DeltaInPack {
            base: 0,
            edit: 9,
            long: true,
        },
    ];
    let pack = build_pack(&entries);
    assert_eq!(frame_types(&pack), [0x00, 0x03, 0x02, 0x04]);
    for entries in 1..4 {
        assert_readers_agree(&pack, &[], WindowShape { entries, bytes: 64 });
    }
}

fn hashed_during(f: impl FnOnce()) -> u64 {
    let before = HASHED_BYTES.with(std::cell::Cell::get);
    f();
    HASHED_BYTES.with(std::cell::Cell::get) - before
}

#[test]
fn a_writer_hashes_each_pack_once() {
    let entries: Vec<Gen> = (0..200u8)
        .map(|seed| Gen::Raw {
            seed,
            len: 4096,
            repeat: false,
        })
        .collect();
    let writer = || {
        let mut w = PackWriter::new();
        for entry in &entries {
            let Gen::Raw { seed, len, repeat } = *entry else {
                unreachable!()
            };
            let (id, bytes) = blob(&blob_data(seed, len, repeat));
            w.push_raw(id, &bytes).unwrap();
        }
        w
    };
    let mut two_pass = (Vec::new(), [0u8; 32]);
    let before = hashed_during(|| {
        let pack = writer().finish().unwrap();
        let key = pack_key(&pack);
        two_pass = (pack, key);
    });
    let mut one_pass = (Vec::new(), [0u8; 32]);
    let after = hashed_during(|| one_pass = writer().finish_with_key().unwrap());
    assert_eq!(one_pass, two_pass, "the same bytes and the same key");
    let len = two_pass.0.len() as u64;
    assert_eq!(before, 2 * len, "finish then pack_key");
    assert_eq!(after, len, "one pass: body, then the trailer");
    // 0.8 sealed with `finish`, which hashed the body, then `pack_key`,
    // which hashed the whole pack: 2 × len − 32 bytes. `finish` now also
    // derives the key, so `before` counts 32 bytes more than 0.8 did.
    eprintln!(
        "hashed per seal of a {len}-byte pack: {before} by finish then pack_key \
         (2 x len - 32 = {} in 0.8), {after} by finish_with_key",
        2 * len - TRAILER_LEN as u64
    );

    let dir = TempDir::new().unwrap();
    let mut spooled = None;
    let spool = hashed_during(|| {
        let mut w = PackWriter::spool(dir.path()).unwrap();
        fill(&mut w, &entries);
        spooled = Some(w.finish_spool().unwrap());
    });
    assert_eq!(spooled.unwrap().key(), two_pass.1);
    assert_eq!(spool, len, "the spool writer hashes the pack once too");

    // The download spool hashes what it receives once, for both checks.
    let mut spool = PackSpool::create(dir.path(), PACK_BODY_LIMIT).unwrap();
    let key = PackKey::new(two_pass.1);
    let received = hashed_during(|| {
        spool.begin(Some(len)).unwrap();
        for piece in two_pass.0.chunks(1000) {
            spool.write(piece).unwrap();
        }
        drop(spool.finish(&key).unwrap());
    });
    assert_eq!(received, len);
}

#[test]
fn a_spool_refuses_every_bad_stream_and_yields_nothing() {
    let pack = build_pack(&[
        Gen::Raw {
            seed: 1,
            len: 100,
            repeat: false,
        },
        Gen::Commit(3),
    ]);
    let key = PackKey::new(pack_key(&pack));
    let len = pack.len() as u64;
    let dir = TempDir::new().unwrap();
    let spool = |limit| PackSpool::create(dir.path(), limit).unwrap();

    // A declared length over the limit is refused before any byte.
    let mut s = spool(len - 1);
    assert!(matches!(
        s.begin(Some(len)),
        Err(PackError::PackfileTooLarge)
    ));
    assert!(matches!(s.write(&pack[..1]), Err(PackError::UnexpectedEof)));
    assert_eq!(s.taken(), (0, 0), "nothing was taken");
    assert!(s.finish(&key).is_err());

    // A write past the declared length ends the body: a later write that
    // would fit is refused too.
    let mut s = spool(PACK_BODY_LIMIT);
    s.begin(Some(len - 1)).unwrap();
    assert!(matches!(s.write(&pack), Err(PackError::PackfileTooLarge)));
    assert!(matches!(s.write(&pack[..1]), Err(PackError::UnexpectedEof)));
    assert!(s.finish(&key).is_err());

    // A write past the limit, with no length declared.
    let mut s = spool(len - 1);
    s.begin(None).unwrap();
    assert!(matches!(s.write(&pack), Err(PackError::PackfileTooLarge)));
    assert!(s.finish(&key).is_err());

    // A short stream.
    let mut s = spool(PACK_BODY_LIMIT);
    s.begin(Some(len)).unwrap();
    s.write(&pack[..pack.len() - 1]).unwrap();
    assert!(matches!(s.finish(&key), Err(PackError::UnexpectedEof)));

    // A stream with no begin.
    let mut s = spool(PACK_BODY_LIMIT);
    assert!(matches!(s.write(&pack), Err(PackError::UnexpectedEof)));
    assert!(matches!(s.finish(&key), Err(PackError::UnexpectedEof)));

    // The wrong key.
    let mut s = spool(PACK_BODY_LIMIT);
    s.begin(None).unwrap();
    s.write(&pack).unwrap();
    let wrong = PackKey::new(hash::hash(b"another pack"));
    assert!(matches!(s.finish(&wrong), Err(PackError::KeyMismatch)));

    // The right key for bytes whose trailer is wrong.
    let mut bad = pack.clone();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    let mut s = spool(PACK_BODY_LIMIT);
    s.begin(Some(len)).unwrap();
    s.write(&bad).unwrap();
    assert!(matches!(
        s.finish(&PackKey::new(pack_key(&bad))),
        Err(PackError::PackfileCorrupted)
    ));

    // Shorter than a header and a trailer, under the right key.
    let tiny = &pack[..HEADER_LEN + TRAILER_LEN - 1];
    let mut s = spool(PACK_BODY_LIMIT);
    s.begin(None).unwrap();
    s.write(tiny).unwrap();
    assert!(matches!(
        s.finish(&PackKey::new(pack_key(tiny))),
        Err(PackError::PackfileTooShort)
    ));

    // A retry starts over: the bytes of the failed attempt are discarded,
    // whether they were buffered or already written to the file.
    let mut s = spool(PACK_BODY_LIMIT);
    s.begin(Some(3 * SPOOL_BUFFER as u64)).unwrap();
    s.write(&vec![7u8; SPOOL_BUFFER + 3]).unwrap();
    assert_eq!(s.taken().1, SPOOL_BUFFER as u64 + 3, "in the file");
    s.begin(Some(len)).unwrap();
    assert_eq!(s.taken(), (0, 0));
    s.write(&[7u8; 10]).unwrap();
    assert_eq!(s.taken(), (10, 0), "buffered");
    s.begin(Some(len)).unwrap();
    for byte in &pack {
        s.write(std::slice::from_ref(byte)).unwrap();
    }
    let good = s.finish(&key).unwrap();
    let mut back = vec![0u8; pack.len()];
    good.read_at(0, &mut back).unwrap();
    assert_eq!(back, pack);
    let (_d, store) = fresh_store();
    let report = PackReader::read_verified(&good, &store).unwrap();
    assert_eq!(report.raw_count, 4);
}

/// Output that takes `left` bytes, then fails.
struct FailingOut {
    left: usize,
}

impl std::io::Write for FailingOut {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.left == 0 {
            return Err(std::io::Error::other("disk full"));
        }
        let n = buf.len().min(self.left);
        self.left -= n;
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A write that fails partway through a frame leaves the writer refusing
/// every later entry and the seal, so it cannot seal misframed bytes.
#[test]
fn a_writer_whose_output_failed_refuses_more_entries_and_the_seal() {
    use std::io::Write as _;
    let (id, bytes) = blob(&blob_data(4, 100, false));
    let mut w = PackWriter::over(FailingOut { left: 20 });
    w.out.write_all(&initial_header()).unwrap();
    assert!(matches!(w.push_raw(id, &bytes), Err(PackError::Io(_))));
    w.out.left = 1 << 20;
    let (other, small) = blob(b"x");
    assert!(matches!(w.push_raw(other, &small), Err(PackError::Io(_))));
    assert!(matches!(w.patched_header(), Err(PackError::Io(_))));
}

#[test]
fn a_spool_takes_writes_larger_than_its_buffer() {
    let mut w = PackWriter::new_raw_only();
    let (id, big) = blob(&blob_data(9, 3 * SPOOL_BUFFER + 17, false));
    w.push_raw(id, &big).unwrap();
    let pack = w.finish().unwrap();
    let dir = TempDir::new().unwrap();
    let mut s = PackSpool::create(dir.path(), PACK_BODY_LIMIT).unwrap();
    s.begin(Some(pack.len() as u64)).unwrap();
    s.write(&pack[..5]).unwrap();
    s.write(&pack[5..2 * SPOOL_BUFFER]).unwrap();
    s.write(&pack[2 * SPOOL_BUFFER..]).unwrap();
    let file = s.finish(&PackKey::new(pack_key(&pack))).unwrap();
    let (_d, store) = fresh_store();
    PackReader::read_verified(&file, &store).unwrap();
    assert_eq!(store.read(&id).unwrap(), big);
}

#[test]
fn file_unpack_uses_two_full_flushes_per_byte_window() {
    use crate::batch::testing::{Ev, RecordingSyncer};
    use std::sync::Arc;

    let mut writer = PackWriter::new_raw_only();
    for i in 0u8..6 {
        let (id, bytes) = blob(&[i; 64]);
        writer.push_raw(id, &bytes).unwrap();
    }
    let pack = writer.finish().unwrap();
    // Six equal frames fit two at a time.
    let window_bytes = ((pack.len() - HEADER_LEN - TRAILER_LEN) / 3) as u64;
    let (dir, mut store) = fresh_store();
    let file = verified(&pack, dir.path());
    let syncer = Arc::new(RecordingSyncer::default());
    store.set_syncer(syncer.clone());

    let report = read_file(
        &file,
        &store,
        WindowShape {
            entries: 6,
            bytes: window_bytes,
        },
        None,
        None,
    )
    .unwrap();

    assert_eq!(report.raw_count, 6);
    let events = syncer.events();
    let full_flushes = events.iter().filter(|event| matches!(event, Ev::Full(_)));
    assert_eq!(full_flushes.count(), 6);
    assert!(!events.iter().any(|event| matches!(event, Ev::DirSync(_))));
}

/// A small file whose header claims ten million entries is refused by the
/// header check, before the reader charges or allocates anything for them.
#[test]
fn a_tiny_file_claiming_ten_million_entries_is_refused_from_its_header() {
    let mut body = initial_header().to_vec();
    body[ENTRY_COUNT_OFFSET..ENTRY_COUNT_OFFSET + 4].copy_from_slice(&MAX_ENTRIES.to_le_bytes());
    body.extend_from_slice(&[0u8; 64]);
    let pack = with_trailer(body);
    let dir = TempDir::new().unwrap();
    let file = verified(&pack, dir.path());
    let (_d, store) = fresh_store();
    assert!(matches!(
        PackReader::read_verified(&file, &store),
        Err(PackError::TooManyObjects(MAX_ENTRIES))
    ));
    assert_eq!(file.window_bytes.load(Ordering::Relaxed), 0);
}

/// A frame whose header claims a payload past the frame limit for its type is
/// refused from the header: no window is read and nothing is stored. The
/// bytes after the frame header are several scan buffers long, and the reader
/// reads at most the header and one scan buffer of the file.
#[test]
fn an_oversized_frame_is_refused_from_its_header() {
    let (id, small) = blob(b"first");
    for (etype, len) in [
        (0x00u8, MAX_RAW_FRAME_PAYLOAD + 1),
        (0x02, MAX_FRAME_PAYLOAD + 1),
        (0x03, MAX_FRAME_PAYLOAD + 1),
        (0x04, MAX_FRAME_PAYLOAD + 1),
    ] {
        let mut body = initial_header().to_vec();
        body[VERSION_OFFSET..VERSION_OFFSET + 4].copy_from_slice(&VERSION_V2.to_le_bytes());
        body[ENTRY_COUNT_OFFSET..ENTRY_COUNT_OFFSET + 4].copy_from_slice(&2u32.to_le_bytes());
        body.push(0x00);
        body.extend_from_slice(&u32::try_from(small.len()).unwrap().to_le_bytes());
        body.extend_from_slice(&small);
        body.push(etype);
        body.extend_from_slice(&u32::try_from(len).unwrap().to_le_bytes());
        body.resize(body.len() + 4 * SCAN_BUFFER, 0);
        let pack = with_trailer(body);
        let dir = TempDir::new().unwrap();
        let file = verified(&pack, dir.path());
        let (_d, store) = fresh_store();
        assert!(
            matches!(
                PackReader::read_verified(&file, &store),
                Err(PackError::PackfileTooLarge)
            ),
            "type {etype:#04x}"
        );
        assert_eq!(
            file.window_bytes.load(Ordering::Relaxed),
            0,
            "no window read"
        );
        let read = file.read_bytes.load(Ordering::Relaxed);
        assert!(
            read <= (HEADER_LEN + SCAN_BUFFER) as u64,
            "read {read} of {} bytes",
            pack.len()
        );
        assert!(!store.contains(&id), "nothing stored");
    }
}

#[test]
fn the_writer_refuses_a_frame_over_the_frame_limit() {
    let w = PackWriter::new();
    let raw = usize::try_from(MAX_RAW_FRAME_PAYLOAD).unwrap();
    let any = usize::try_from(MAX_FRAME_PAYLOAD).unwrap();
    w.check_caps_for(0x00, raw).unwrap();
    assert!(matches!(
        w.check_caps_for(0x00, raw + 1),
        Err(PackError::PackfileTooLarge)
    ));
    for etype in [0x02, 0x03, 0x04] {
        w.check_caps_for(etype, any).unwrap();
        assert!(matches!(
            w.check_caps_for(etype, any + 1),
            Err(PackError::PackfileTooLarge)
        ));
    }
    // The limit holds every frame a writer makes: a raw object of the
    // largest size, and a compressed or delta payload, which is smaller than
    // the object it encodes.
    assert_eq!(MAX_RAW_FRAME_PAYLOAD, MAX_RAW_OBJECT_SIZE as u64);
    assert!(MAX_FRAME_PAYLOAD > MAX_RAW_OBJECT_SIZE as u64 + 36);
    // The entry caps are unchanged.
    assert_eq!(MAX_ENTRIES, 10_000_000);
    assert_eq!(MAX_WRITE_ENTRIES, 1_198_372);
}

/// A small pack's decoded share is `max(2 GiB, 16 × len)` capped at 3 GiB,
/// charged apart from its entries. Whatever room the slice reader left a pack
/// for decoded bytes, the file reader leaves at least as much up to 192 MiB,
/// and never more than the slice reader's whole cap.
#[test]
fn the_decoded_share_follows_the_pack_size_up_to_three_gib() {
    let gib = 1u64 << 30;
    for (len, share) in [
        (1u64 << 10, 2 * gib),
        (64 << 20, 2 * gib),
        (128 << 20, 2 * gib),
        (160 << 20, 160 << 24),
        (192 << 20, 3 * gib),
        (gib, 3 * gib),
        (4 * gib, 3 * gib),
    ] {
        assert_eq!(decoded_share(len), share, "share of a {len}-byte pack");
        let entries = usize::try_from(len / 64).unwrap().min(1000);
        let budget = file_budget(len, entries, 30, None).unwrap();
        let admitted = usize::try_from(share).unwrap();
        drop(budget.charge(admitted).expect("the share is admitted"));
        assert!(budget.charge(admitted + 1).is_err(), "one past it is not");
        let slice_cap = resident_bytes_cap(usize::try_from(len).unwrap());
        assert!(admitted <= slice_cap, "never above the slice reader's cap");
        if len <= 192 << 20 {
            let slice_room = slice_cap - entries * PACK_ENTRY_RESIDENT_COST;
            assert!(admitted >= slice_room, "at least the slice reader's room");
        }
    }
    // The largest admission of all.
    let largest = bookkeeping(MAX_ENTRIES as usize, 0).unwrap() as u64 + RESIDENT_ENTRY_MAX;
    assert_eq!(largest, UNPACK_MEMORY_CAP);
    assert!(
        (6 * gib..6 * gib + gib / 10).contains(&UNPACK_MEMORY_CAP),
        "about 6.04 GiB, got {UNPACK_MEMORY_CAP} bytes"
    );
}

/// A delta in a later window whose base an earlier window stored reads the
/// base back from the store, and no decoded byte outlives its window.
#[test]
fn a_base_used_in_two_windows_is_read_back_and_nothing_outlives_its_window() {
    // A compressible base, so it is decoded (owned) rather than borrowed.
    let (base_id, base) = blob(&blob_data(5, 4000, true));
    let edit = |byte: u8| {
        let Ok(Object::Blob(Blob { mut data })) = serialize::deserialize(&base) else {
            unreachable!()
        };
        data[100] = byte;
        blob(&data)
    };
    let (t1, b1) = edit(1);
    let (t2, b2) = edit(2);
    let (t3, b3) = edit(3);
    let mut w = PackWriter::new();
    w.push_raw(base_id, &base).unwrap(); // window 1
    w.push_delta(&base_id, &delta::encode(&base, &b1).unwrap())
        .unwrap(); // window 1
    w.push_delta(&t1, &delta::encode(&b1, &b2).unwrap())
        .unwrap(); // window 2, base from window 1
    w.push_delta(&base_id, &delta::encode(&base, &b3).unwrap())
        .unwrap(); // window 2, the 0.7.3 interleaving
    let pack = w.finish().unwrap();
    assert_eq!(pack[HEADER_LEN], 0x03, "the base is stored compressed");

    let dir = TempDir::new().unwrap();
    let file = verified(&pack, dir.path());
    let (_d, store) = fresh_store();
    let mut boundaries = Vec::new();
    let mut hook = |held: usize| boundaries.push(held);
    let report = read_file(
        &file,
        &store,
        WindowShape {
            entries: 2,
            bytes: u64::MAX,
        },
        None,
        Some(&mut hook),
    )
    .unwrap();
    assert_eq!((report.raw_count, report.delta_count), (1, 3));
    assert_eq!(
        boundaries,
        vec![0, 0],
        "no decoded byte is held past a window"
    );
    assert_eq!(
        store.read_call_count(),
        2,
        "window 2 reads its two bases back from the store, once each"
    );
    for (id, bytes) in [(t1, b1), (t2, b2), (t3, b3)] {
        assert_eq!(store.read(&id).unwrap(), bytes);
    }
}

/// Every commit, remix and tag a pack stores is listed in `signed` with its
/// length, in pack order, from either reader; nothing else is.
#[test]
fn the_report_lists_exactly_the_signed_objects_stored() {
    let (blob_id, blob_bytes) = blob(b"content");
    let (tree_id, tree_bytes) = object(&tree(blob_id));
    let c1 = commit(tree_id, "first");
    let (c1_id, c1_bytes) = object(&c1);
    let (c2_id, c2_bytes) = object(&commit(tree_id, "second, sent as a delta"));
    let (remix_id, remix_bytes) = object(&Object::Remix(Remix {
        tree_hash: tree_id,
        parents: vec![c1_id],
        sources: vec![RemixSource {
            upstream_id: [4; 32],
            commit_hash: c1_id,
        }],
        author: Identity::ed25519([1; 32]),
        signer: [1; 32],
        message: b"remix".to_vec(),
        timestamp: 9,
        signature: [0; 64],
    }));
    let (tag_id, tag_bytes) = object(&Object::Tag(Tag {
        target: c1_id,
        target_type: ObjectType::Commit,
        name: b"v1".to_vec(),
        tagger: Identity::ed25519([1; 32]),
        signer: [1; 32],
        message: b"tag".to_vec(),
        timestamp: 10,
        signature: [0; 64],
    }));
    let mut w = PackWriter::new();
    w.push_raw(blob_id, &blob_bytes).unwrap();
    w.push_raw(tree_id, &tree_bytes).unwrap();
    w.push_raw(c1_id, &c1_bytes).unwrap();
    w.push_delta(&c1_id, &delta::encode(&c1_bytes, &c2_bytes).unwrap())
        .unwrap();
    w.push_raw(remix_id, &remix_bytes).unwrap();
    w.push_raw(tag_id, &tag_bytes).unwrap();
    let pack = w.finish().unwrap();
    let expected = vec![
        (c1_id, u32::try_from(c1_bytes.len()).unwrap()),
        (c2_id, u32::try_from(c2_bytes.len()).unwrap()),
        (remix_id, u32::try_from(remix_bytes.len()).unwrap()),
        (tag_id, u32::try_from(tag_bytes.len()).unwrap()),
    ];

    let (_d, store) = fresh_store();
    assert_eq!(PackReader::read(&pack, &store).unwrap().signed, expected);
    let dir = TempDir::new().unwrap();
    let (_d, store) = fresh_store();
    let report = PackReader::read_verified(&verified(&pack, dir.path()), &store).unwrap();
    assert_eq!(report.signed, expected);
    assert!(report.stored.is_empty());
}

#[test]
fn a_previously_staged_pack_supplies_a_delta_without_publishing_its_base() {
    let (dir, store) = fresh_store();
    let (base, base_bytes) = blob(b"base contents");
    let (target, target_bytes) = blob(b"changed contents");
    let mut writer = PackWriter::new_raw_only();
    writer.push_raw(base, &base_bytes).unwrap();
    let first = verified(&writer.finish().unwrap(), dir.path());
    let pending = ObjectSpool::new(dir.path()).unwrap();
    let report = PackReader::stage_verified(&first, &store, None, &pending).unwrap();
    assert_eq!(report.raw_count, 1);
    assert!(!store.contains(&base));

    let mut writer = PackWriter::new();
    writer
        .push_delta(&base, &delta::encode(&base_bytes, &target_bytes).unwrap())
        .unwrap();
    // Independent raw frames can stage in parallel. This frame must never
    // supply the earlier delta, although it carries the exact base bytes.
    writer.push_raw(base, &base_bytes).unwrap();
    let second = verified(&writer.finish().unwrap(), dir.path());
    let staged = ObjectSpool::new(dir.path()).unwrap();
    assert!(matches!(
        PackReader::stage_verified(&second, &store, None, &staged),
        Err(PackError::DeltaBaseMissing(_)),
    ));
    let staged = ObjectSpool::new(dir.path()).unwrap();
    let report = PackReader::stage_verified(&second, &store, Some(&pending), &staged).unwrap();
    assert_eq!((report.raw_count, report.delta_count), (1, 1));
    assert_eq!(staged.read(&target).unwrap(), Some(target_bytes));
    assert!(!store.contains(&base));
    assert!(!store.contains(&target));
}

#[test]
fn an_empty_pack_reads_from_a_file() {
    let pack = PackWriter::new().finish().unwrap();
    let dir = TempDir::new().unwrap();
    let (_d, store) = fresh_store();
    let report = PackReader::read_verified(&verified(&pack, dir.path()), &store).unwrap();
    assert_eq!(report, UnpackReport::default());
}

/// The header checks the slice reader applies hold for a file too.
#[test]
fn the_file_reader_refuses_a_bad_header() {
    let good = build_pack(&[Gen::Commit(1)]);
    let cases: [(usize, &[u8]); 3] = [(0, b"KIX\0"), (4, &[3, 0, 0, 0]), (4, &[1, 0, 0, 0])];
    let mut v2 = build_pack(&[Gen::Raw {
        seed: 1,
        len: 300,
        repeat: true,
    }]);
    assert_eq!(v2[4], 2, "a compressed entry makes a v2 pack");
    v2.truncate(v2.len() - TRAILER_LEN);
    for (index, (at, bytes)) in cases.iter().enumerate() {
        let mut body = if index == 2 {
            v2.clone()
        } else {
            good[..good.len() - TRAILER_LEN].to_vec()
        };
        body[*at..*at + bytes.len()].copy_from_slice(bytes);
        let pack = with_trailer(body);
        let dir = TempDir::new().unwrap();
        let (_d, store) = fresh_store();
        let from_file = PackReader::read_verified(&verified(&pack, dir.path()), &store);
        let (_d, store) = fresh_store();
        let from_slice = PackReader::read(&pack, &store);
        assert_eq!(
            format!("{from_file:?}"),
            format!("{from_slice:?}"),
            "case {index}"
        );
        assert!(from_file.is_err());
    }
}

/// A pack of `len` bytes that do not compress.
fn noise_pack(len: usize) -> (Vec<u8>, PackKey) {
    // Hash output does not compress, so the pack is about `len` bytes.
    let mut data = vec![0u8; len];
    blake3::Hasher::new()
        .update(b"noise")
        .finalize_xof()
        .fill(&mut data);
    let (id, bytes) = blob(&data);
    let mut w = PackWriter::new();
    w.push_raw(id, &bytes).unwrap();
    let pack = w.finish().unwrap();
    let key = PackKey::new(pack_key(&pack));
    (pack, key)
}

#[test]
fn a_spool_continues_an_interrupted_body_and_verifies_the_whole_pack() {
    let (pack, key) = noise_pack(3 << 20);
    let len = pack.len() as u64;
    let dir = TempDir::new().unwrap();
    // Cuts in the buffer, on the buffer edge, past it, and at the last byte.
    for cut in [
        1,
        100,
        SPOOL_BUFFER - 1,
        SPOOL_BUFFER,
        SPOOL_BUFFER + 1,
        5 << 19,
        pack.len() - 1,
    ] {
        let mut s = PackSpool::create(dir.path(), PACK_BODY_LIMIT).unwrap();
        assert_eq!(s.retained(), 0, "before a body");
        s.begin(Some(len)).unwrap();
        assert_eq!(s.retained(), 0, "no byte yet");
        s.write(&pack[..cut]).unwrap();
        assert_eq!(s.retained(), cut as u64, "cut at {cut}");
        s.resume(len, cut as u64).unwrap();
        assert_eq!(s.retained(), cut as u64, "resuming keeps the prefix");
        s.write(&pack[cut..]).unwrap();
        let done = s.finish(&key).unwrap();
        assert_eq!(done.len(), len);
        let mut read = vec![0u8; pack.len()];
        done.read_at(0, &mut read).unwrap();
        assert!(read == pack, "cut at {cut}");
    }
}

#[test]
fn a_prefix_of_another_body_fails_the_pack_check_after_a_resume() {
    let (pack, key) = noise_pack(1 << 16);
    let len = pack.len() as u64;
    let mut damaged = pack.clone();
    damaged[1000] ^= 1;
    let dir = TempDir::new().unwrap();
    let mut s = PackSpool::create(dir.path(), PACK_BODY_LIMIT).unwrap();
    s.begin(Some(len)).unwrap();
    s.write(&damaged[..5000]).unwrap();
    s.resume(len, 5000).unwrap();
    s.write(&pack[5000..]).unwrap();
    assert!(matches!(s.finish(&key), Err(PackError::KeyMismatch)));
}

#[test]
fn a_spool_refuses_to_continue_what_it_does_not_hold() {
    let (pack, _) = noise_pack(1 << 16);
    let len = pack.len() as u64;
    let dir = TempDir::new().unwrap();
    let begun = |declared: Option<u64>, taken: usize| {
        let mut s = PackSpool::create(dir.path(), PACK_BODY_LIMIT).unwrap();
        s.begin(declared).unwrap();
        s.write(&pack[..taken]).unwrap();
        s
    };

    // No body begun.
    let mut s = PackSpool::create(dir.path(), PACK_BODY_LIMIT).unwrap();
    assert!(matches!(s.resume(len, 0), Err(PackError::UnexpectedEof)));
    // No byte taken.
    assert!(begun(Some(len), 0).resume(len, 0).is_err());
    // No declared length: the end of the body is not known.
    let mut s = begun(None, 100);
    assert_eq!(s.retained(), 0);
    assert!(s.resume(len, 100).is_err());
    // An offset that is not the prefix held, or a total that is not declared.
    let mut s = begun(Some(len), 100);
    assert!(s.resume(len, 99).is_err());
    assert!(s.resume(len, 101).is_err());
    assert!(s.resume(len + 1, 100).is_err());
    assert!(s.resume(len - 1, 100).is_err());
    s.resume(len, 100).unwrap();
    // A prefix that already is the whole body has nothing to continue.
    let mut s = begun(Some(100), 100);
    assert_eq!(s.retained(), 100);
    assert!(s.resume(100, 100).is_err());
    // A body that ended past its length keeps nothing.
    let mut s = begun(Some(100), 50);
    assert!(s.write(&pack[..100]).is_err());
    assert_eq!(s.retained(), 0);
    assert!(s.resume(100, 50).is_err());
    // A new body starts over.
    let mut s = begun(Some(len), 100);
    s.begin(Some(len)).unwrap();
    assert_eq!(s.retained(), 0);
}

#[test]
fn a_sink_view_of_a_spool_resumes_and_maps_refusals() {
    let (pack, key) = noise_pack(1 << 16);
    let len = pack.len() as u64;
    let dir = TempDir::new().unwrap();
    let mut s = PackSpool::create(dir.path(), PACK_BODY_LIMIT).unwrap();
    let sink: &mut dyn crate::protocol::PackSink = &mut s;
    sink.begin(Some(len)).unwrap();
    sink.write(&pack[..200]).unwrap();
    assert_eq!(sink.retained(), 200);
    assert!(matches!(
        sink.resume(len, 199),
        Err(crate::protocol::TransportError::ProtocolError)
    ));
    sink.resume(len, 200).unwrap();
    sink.write(&pack[200..]).unwrap();
    assert!(s.finish(&key).is_ok());
}

#[cfg(feature = "fault-injection")]
#[test]
fn a_spool_that_failed_to_write_keeps_nothing_to_continue() {
    let (pack, _) = noise_pack(3 << 20);
    let len = pack.len() as u64;
    let dir = TempDir::new().unwrap();
    let mut s = PackSpool::create(dir.path(), PACK_BODY_LIMIT).unwrap();
    s.begin(Some(len)).unwrap();
    s.write(&pack[..100]).unwrap();
    {
        let _full = crate::fault::fail_writes(crate::fault::Site::Spool);
        assert!(s.write(&pack[100..(2 << 20)]).is_err());
    }
    assert!(s.failed().is_some());
    assert_eq!(s.retained(), 0);
    assert!(matches!(s.resume(len, 100), Err(PackError::Io(_))));
}
