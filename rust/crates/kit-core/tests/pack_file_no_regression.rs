//! Every pack the slice reader reads, the file-backed reader reads too, and
//! some it refuses: packs of millions of entries, and an entry near the
//! largest object size. Most read millions of entries or packs of several GiB, so
//! they run in the ignored lane.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use kit_core::layout::RepoLayout;
use kit_core::object::{Blob, Object};
use kit_core::pack::{
    MAX_ENTRIES, MAX_WRITE_ENTRIES, PACK_ENTRY_RESIDENT_COST, PackError, PackSpool, SpooledPack,
    VerifiedPack,
};
use kit_core::protocol::{PACK_BODY_LIMIT, PackKey};
use kit_core::store::MAX_RAW_OBJECT_SIZE;
use kit_core::{ObjectStore, PackReader, PackWriter, delta, hash::hash, pack_key, serialize};
use std::path::Path;
use tempfile::TempDir;

fn store() -> (TempDir, ObjectStore) {
    let dir = TempDir::new().unwrap();
    let store = ObjectStore::init(&RepoLayout::single(dir.path())).unwrap();
    (dir, store)
}

fn blob(data: Vec<u8>) -> (kit_core::hash::Hash, Vec<u8>) {
    let bytes = serialize::serialize(&Object::Blob(Blob { data })).unwrap();
    (hash(&bytes), bytes)
}

/// A tiny blob: 4 bytes of data, a frame of a few dozen bytes.
fn tiny(i: u32) -> (kit_core::hash::Hash, Vec<u8>) {
    blob(i.to_le_bytes().to_vec())
}

/// Objects a pack of millions of entries repeats: one window of the file
/// reader. Its first window stores that many new objects, and each later
/// window reads its entries in full and finds them stored, so the test
/// writes one window of files rather than millions.
const DISTINCT: u32 = 65_536;

fn verified(pack: &[u8], dir: &Path) -> VerifiedPack {
    let mut spool = PackSpool::create(dir, PACK_BODY_LIMIT).unwrap();
    spool.begin(Some(pack.len() as u64)).unwrap();
    for piece in pack.chunks(1 << 20) {
        spool.write(piece).unwrap();
    }
    spool.finish(&PackKey::new(pack_key(pack))).unwrap()
}

/// The pack a spool writer sealed, passed through a download spool.
fn verified_spooled(pack: &SpooledPack, dir: &Path) -> VerifiedPack {
    let mut spool = PackSpool::create(dir, PACK_BODY_LIMIT).unwrap();
    spool.begin(Some(pack.len())).unwrap();
    let mut buf = vec![0u8; 1 << 20];
    let mut at = 0u64;
    while at < pack.len() {
        let n = buf.len().min(usize::try_from(pack.len() - at).unwrap());
        pack.read_at(at, &mut buf[..n]).unwrap();
        spool.write(&buf[..n]).unwrap();
        at += n as u64;
    }
    spool.finish(&PackKey::new(pack.key())).unwrap()
}

/// Would the 0.8 reader admit a pack of `len` bytes and `entries` entries?
/// It charged 896 bytes per entry against `max(2 GiB, 16 × len)`.
fn slice_reader_admits(len: u64, entries: u64) -> bool {
    let cap = (2 * MAX_RAW_OBJECT_SIZE as u64).max(16 * len);
    PACK_ENTRY_RESIDENT_COST as u64 * entries <= cap
}

/// 2.5 million entries under 56 bytes each, in a pack under 140 MB. The
/// slice reader refuses it: 896 bytes per entry pass its 2 GiB cap. The file
/// reader reads it.
#[test]
#[ignore = "reads 2.5 million entries; run in the ignored lane"]
fn a_short_pack_of_two_and_a_half_million_entries_reads() {
    const N: u32 = 2_500_000;
    let mut w = PackWriter::new();
    for i in 0..N {
        let (id, bytes) = tiny(i % DISTINCT);
        assert!(bytes.len() + 5 < 56);
        w.push_raw(id, &bytes).unwrap();
    }
    let pack = w.finish().unwrap();
    assert!(pack.len() < 140_000_000, "{} bytes", pack.len());
    assert!(!slice_reader_admits(pack.len() as u64, u64::from(N)));
    let (_d, slice_store) = store();
    assert!(matches!(
        PackReader::read(&pack, &slice_store),
        Err(PackError::PackfileTooLarge)
    ));

    let spool = TempDir::new().unwrap();
    let file = verified(&pack, spool.path());
    drop(pack);
    let (_d, store) = store();
    let report = PackReader::read_verified(&file, &store).unwrap();
    assert_eq!(report.raw_count, N);
    for i in [0, 1, N / 2 % DISTINCT, DISTINCT - 1] {
        let (id, bytes) = tiny(i);
        assert_eq!(store.read(&id).unwrap(), bytes);
    }
}

/// A pack in the shape the 0.7.3 writer made, with no bound of 1,198,372
/// entries: 16 shared incompressible bases first, then `n - 16` entries,
/// each `every`-th a delta on a shared base far from its other uses, the
/// rest tiny blobs repeating every [`DISTINCT`]. Returns the pack and the
/// delta targets.
fn the_0_7_3_shape(n: u32, every: u32) -> (Vec<u8>, Vec<(kit_core::hash::Hash, Vec<u8>)>) {
    const SHARED: u32 = 16;
    let shared: Vec<_> = (0..SHARED)
        .map(|i| blob(noise(u64::from(i) + 1, 200 + i as usize)))
        .collect();
    let mut w = PackWriter::new();
    for (id, bytes) in &shared {
        w.push_raw(*id, bytes).unwrap();
    }
    let mut targets = Vec::new();
    for i in SHARED..n {
        if i % every == 0 {
            let (base_id, base) = &shared[(i / every % SHARED) as usize];
            let Object::Blob(Blob { mut data }) = serialize::deserialize(base).unwrap() else {
                unreachable!()
            };
            data.extend_from_slice(&i.to_le_bytes());
            let (id, target) = blob(data);
            w.push_delta(base_id, &delta::encode(base, &target).unwrap())
                .unwrap();
            targets.push((id, target));
        } else {
            let (id, bytes) = tiny(i % DISTINCT);
            w.push_raw(id, &bytes).unwrap();
        }
    }
    (w.finish().unwrap(), targets)
}

/// The writer makes this shape byte for byte as kit-core 0.7.3 did. A scratch
/// crate depending on `kit-core = "=0.7.3"` from crates.io ran the body of
/// [`the_0_7_3_shape`] for the same 600 entries, with that version's
/// `PackWriter`, `delta::encode` and `serialize`, and its writer sealed a
/// 15,316-byte version 1 pack under this key. The pack holds raw and delta
/// frames only, the kinds the 3 million entry test writes.
#[test]
fn the_0_7_3_shape_is_the_0_7_3_writers_pack() {
    let (pack, targets) = the_0_7_3_shape(600, 50);
    assert_eq!(targets.len(), 11);
    assert_eq!(pack.len(), 15_316);
    assert_eq!(
        kit_core::hash::to_hex(&pack_key(&pack)),
        "95e53102296ac0468d84896c0b73d3e5734ca153459adb32c57624c4471ea00a"
    );
}

/// A pack of 3 million entries in the 0.7.3 writer's shape reads: each later
/// use of a shared base reads it back from the store.
#[test]
#[ignore = "reads 3 million entries; run in the ignored lane"]
fn a_pack_of_three_million_entries_from_the_0_7_3_writer_reads() {
    const N: u32 = 3_000_000;
    let (pack, targets) = the_0_7_3_shape(N, 50_000);
    assert!(N as usize > MAX_WRITE_ENTRIES);
    let spool = TempDir::new().unwrap();
    let file = verified(&pack, spool.path());
    drop(pack);
    let (_d, store) = store();
    let report = PackReader::read_verified(&file, &store).unwrap();
    assert_eq!(report.raw_count + report.delta_count, N);
    assert_eq!(report.delta_count as usize, targets.len());
    for (id, bytes) in &targets {
        assert_eq!(&store.read(id).unwrap(), bytes);
    }
}

/// A pack of `entries` entries cycling through `distinct` blobs of `data_len`
/// bytes, sealed by the spool writer and passed through a download spool.
fn cycling_pack(entries: u32, distinct: u32, data_len: usize, dir: &Path) -> VerifiedPack {
    let blobs: Vec<_> = (0..distinct)
        .map(|i| {
            let mut data = vec![0u8; data_len];
            data[..4].copy_from_slice(&i.to_le_bytes());
            blob(data)
        })
        .collect();
    let mut w = PackWriter::spool(dir).unwrap();
    for i in 0..entries {
        let (id, bytes) = &blobs[(i % distinct) as usize];
        w.push_raw(*id, bytes).unwrap();
    }
    let sealed = w.finish_spool().unwrap();
    verified_spooled(&sealed, dir)
}

/// Ten million entries, the format's cap, in a pack long enough for the
/// slice reader too.
#[test]
#[ignore = "reads ten million entries; run in the ignored lane"]
fn a_pack_at_the_entry_cap_long_enough_for_0_8_reads() {
    let dir = TempDir::new().unwrap();
    let file = cycling_pack(MAX_ENTRIES, DISTINCT, 52, dir.path());
    assert!(slice_reader_admits(file.len(), u64::from(MAX_ENTRIES)));
    let (_d, store) = store();
    let report = PackReader::read_verified(&file, &store).unwrap();
    assert_eq!(report.raw_count, MAX_ENTRIES);
}

/// A hosted build splits packs at the format's cap of ten million entries,
/// whatever their length: a short pack of ten million tiny entries, which the
/// slice reader refuses, reads.
#[test]
#[ignore = "reads ten million entries; run in the ignored lane"]
fn a_hosted_pack_split_at_the_entry_cap_reads() {
    let dir = TempDir::new().unwrap();
    let file = cycling_pack(MAX_ENTRIES, DISTINCT, 4, dir.path());
    assert!(!slice_reader_admits(file.len(), u64::from(MAX_ENTRIES)));
    let (_d, store) = store();
    let report = PackReader::read_verified(&file, &store).unwrap();
    assert_eq!(report.raw_count, MAX_ENTRIES);
}

/// Incompressible bytes from a seed.
fn noise(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed | 1;
    let mut out = Vec::with_capacity(len + 8);
    while out.len() < len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.extend_from_slice(&state.to_le_bytes());
    }
    out.truncate(len);
    out
}

/// A pack holding an entry near the largest object size, a delta on it from
/// a later window, and small entries around them stores the same objects from
/// a slice and from a file.
#[test]
#[ignore = "writes a pack of about 1 GiB; run in the ignored lane"]
fn a_pack_with_an_entry_near_1_gib_reads_the_same_from_a_slice_and_a_file() {
    let mut data = noise(7, MAX_RAW_OBJECT_SIZE - (64 << 10));
    let last = data.len() - 1;
    data[last] = 0x5A;
    let (big_id, big) = blob(data);
    // A small target that copies the big object's last byte: the delta
    // needs the whole base, which a later window reads back from the store.
    let (target_id, target) = blob(b"tail is \x5A".to_vec());
    let mut stream = vec![1u8];
    stream.extend_from_slice(&u32::try_from(big.len()).unwrap().to_le_bytes());
    stream.extend_from_slice(&u32::try_from(target.len()).unwrap().to_le_bytes());
    let head = &target[..target.len() - 1];
    for piece in head.chunks(127) {
        stream.push(u8::try_from(piece.len()).unwrap());
        stream.extend_from_slice(piece);
    }
    stream.push(0x80);
    stream.extend_from_slice(&u32::try_from(big.len() - 1).unwrap().to_le_bytes());
    stream.extend_from_slice(&1u16.to_le_bytes());
    assert_eq!(delta::decode(&big, &stream).unwrap(), target);

    let small: Vec<_> = (0..100).map(tiny).collect();
    let mut w = PackWriter::new();
    for (id, bytes) in &small[..50] {
        w.push_raw(*id, bytes).unwrap();
    }
    w.push_raw(big_id, &big).unwrap();
    w.push_delta(&big_id, &stream).unwrap();
    for (id, bytes) in &small[50..] {
        w.push_raw(*id, bytes).unwrap();
    }
    drop(big);
    let pack = w.finish().unwrap();

    let (_d, slice_store) = store();
    let from_slice = PackReader::read(&pack, &slice_store).unwrap();
    let spool = TempDir::new().unwrap();
    let file = verified(&pack, spool.path());
    drop(pack);
    let (_d, file_store) = store();
    let from_file = PackReader::read_verified(&file, &file_store).unwrap();
    assert_eq!(
        (from_file.raw_count, from_file.delta_count),
        (from_slice.raw_count, from_slice.delta_count)
    );
    assert!(from_slice.stored.contains(&target_id));
    for id in &from_slice.stored {
        assert_eq!(
            hash(&file_store.read(id).unwrap()),
            hash(&slice_store.read(id).unwrap())
        );
    }
}
