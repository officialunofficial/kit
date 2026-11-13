//! A pack a push seals is one the smallest kit reader takes.
//!
//! A reader applies the budget of `DecodeLimits::default()` (1 GiB) to the
//! bytes a pack decodes to and to the delta bases it holds at once. These
//! tests push to a `kit+file://` remote, read every pack back through
//! `kit_client::unpack` and `rewrite_excluding` with those default limits,
//! and expect both to take it.
//!
//! The tests move gigabytes of content and are `#[ignore]`. Run them in
//! release mode: `cargo test --release -p kit-bin --test reader_budget_fit --
//! --ignored`.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

mod common;

use std::collections::HashSet;
use std::path::Path;

use common::Repo;
use kit_client::{ObjectSink, UnpackOptions, unpack};
use kit_core::hash::Hash;
use kit_core::layout::RepoLayout;
use kit_core::pack::{DecodeLimits, rewrite_excluding};
use kit_core::protocol::{PackKey, Transport};
use kit_core::refs::{self, RefWriteCondition};
use kit_core::store::ObjectStore;
use kit_core::transfer::{self, PackListNode};
use kit_transport_file::FileTransport;
use libkit::transfer::push_branch;

/// Every pack of `branch` on the remote, oldest push first, each push's packs
/// in apply order. Walks the packlist chain through the public verbs.
fn remote_packs(tx: &dyn Transport, branch: &str) -> Vec<Vec<Hash>> {
    let mut nodes: Vec<PackListNode> = Vec::new();
    let mut cursor = tx.read_ref(&format!("refs/kit/packmap/{branch}")).unwrap();
    while let Some(key) = cursor {
        let bytes = tx.download_blob(&PackKey::from_hash(key)).unwrap();
        let node = transfer::decode_packlist(&bytes).unwrap();
        cursor = node.prev;
        nodes.push(node);
    }
    nodes.reverse();
    nodes.into_iter().map(|node| node.packs).collect()
}

fn head(dir: &Path) -> Hash {
    refs::read_ref(&RepoLayout::single(dir), "main")
        .unwrap()
        .unwrap()
}

fn push(repo: &Repo, tx: &dyn Transport, condition: RefWriteCondition) {
    let store = ObjectStore::open(&RepoLayout::single(repo.path())).unwrap();
    push_branch(tx, &store, "main", head(repo.path()), condition).unwrap();
}

/// Delta bases come from the pusher's own store. Nothing is kept.
struct StoreSink<'a> {
    store: &'a ObjectStore,
    stored: usize,
}

impl ObjectSink for StoreSink<'_> {
    fn get(&mut self, id: &Hash) -> Result<Option<Vec<u8>>, String> {
        Ok(self.store.read(id).ok())
    }
    fn put(&mut self, _id: Hash, _bytes: &[u8]) -> Result<(), String> {
        self.stored += 1;
        Ok(())
    }
}

/// Read every pack in `packs` back with the default limits through both
/// readers. Returns how many entries were deltas.
fn read_back(tx: &dyn Transport, store: &ObjectStore, packs: &[Hash]) -> usize {
    let mut deltas = 0;
    for key in packs {
        let pack = tx.download_pack(&PackKey::from_hash(*key)).unwrap();
        let mut sink = StoreSink { store, stored: 0 };
        let unpacked = unpack(
            key,
            &pack,
            &mut sink,
            UnpackOptions::default().with_limits(DecodeLimits::default()),
        )
        .unwrap_or_else(|e| panic!("unpack of a pack of {} bytes: {e}", pack.len()));
        assert_eq!(sink.stored, unpacked.ids.len());
        deltas += unpacked.delta_count;

        let mut bases = store;
        let rewritten =
            rewrite_excluding(&pack, &HashSet::new(), &mut bases, DecodeLimits::default())
                .unwrap_or_else(|e| panic!("rewrite of a pack of {} bytes: {e}", pack.len()));
        assert!(rewritten.unchanged);
    }
    deltas
}

/// Bytes that compress about sixteen to one and repeat nowhere: each block of
/// 64 KiB is 4 KiB of noise sixteen times over, and no two blocks match, so
/// no two chunks are the same object.
fn compressible(seed: u64, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    while out.len() < len {
        let mut noise = [0_u8; 4096];
        for word in noise.chunks_mut(8) {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            word.copy_from_slice(&state.to_le_bytes());
        }
        for _ in 0..16 {
            out.extend_from_slice(&noise);
        }
    }
    out.truncate(len);
    out
}

/// Bytes that do not compress.
fn incompressible(seed: u64, len: usize) -> Vec<u8> {
    let mut buf = vec![0_u8; len];
    let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    for chunk in buf.chunks_mut(8) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        chunk.copy_from_slice(&state.to_le_bytes()[..chunk.len()]);
    }
    buf
}

#[test]
#[ignore = "pushes 1.6 GiB of compressible content; run in release mode"]
fn a_push_of_compressible_content_decodes_under_the_default_budget() {
    let alice = Repo::new();
    // Ten files of 160 MiB, each chunked. A chunk takes little on the wire
    // and decodes to its whole length, so the pack's payload cap never binds
    // and only the decoded budget cuts the push into packs.
    for i in 0..10_u64 {
        alice.write(
            &format!("big{i}.bin"),
            &compressible(0xC0DE_0000 + i, 160 << 20),
        );
    }
    alice.ok(&["add", "."]);
    alice.ok(&["commit", "-m", "compressible content"]);

    let remote = tempfile::tempdir().unwrap();
    let tx = FileTransport::new(remote.path());
    push(&alice, &tx, RefWriteCondition::Missing);

    let pushes = remote_packs(&tx, "main");
    assert_eq!(pushes.len(), 1);
    let store = ObjectStore::open(&RepoLayout::single(alice.path())).unwrap();
    read_back(&tx, &store, &pushes[0]);
    assert!(
        pushes[0].len() >= 2,
        "1.6 GiB of decoded content is more than one pack takes"
    );
}

#[test]
#[ignore = "pushes 1.5 GiB over 1,000 files; run in release mode"]
fn deltas_over_many_bases_read_back_with_one_base_held_at_a_time() {
    const GROUPS: u64 = 500;
    const LEN: usize = 1 << 20;
    let alice = Repo::new();
    // Two files of each group start with the same content, so one blob is the
    // delta base of both after their edits. The files of one member share a
    // directory. The targets of the 1,000 deltas hash in no order of their
    // bases, so a plan ordered by target lists the 500 bases scattered, and a
    // reader holds most of them at once beside the 1,000 results.
    for group in 0..GROUPS {
        let body = incompressible(0xB0DE_0000 + group, LEN);
        for member in 0..2 {
            alice.write(&format!("m{member}/g{group:03}.bin"), &body);
        }
    }
    alice.ok(&["add", "."]);
    alice.ok(&["commit", "-m", "bases"]);
    let remote = tempfile::tempdir().unwrap();
    let tx = FileTransport::new(remote.path());
    let first = head(alice.path());
    push(&alice, &tx, RefWriteCondition::Missing);

    for group in 0..GROUPS {
        let body = incompressible(0xB0DE_0000 + group, LEN);
        for member in 0..2_u64 {
            let mut edited = body.clone();
            let at = LEN / 2 + usize::try_from(member).unwrap();
            edited[at..at + 16].copy_from_slice(&(group * 2 + member).to_le_bytes().repeat(2));
            alice.write(&format!("m{member}/g{group:03}.bin"), &edited);
        }
    }
    alice.ok(&["add", "."]);
    alice.ok(&["commit", "-m", "edits"]);
    push(&alice, &tx, RefWriteCondition::Match(first));

    let pushes = remote_packs(&tx, "main");
    assert_eq!(pushes.len(), 2);
    let store = ObjectStore::open(&RepoLayout::single(alice.path())).unwrap();
    // The deltas of a base sit next to each other, so a reader holds one base
    // at a time and the whole push fits one pack.
    assert_eq!(pushes[1].len(), 1);
    let deltas = read_back(&tx, &store, &pushes[1]);
    assert!(
        deltas >= 2 * usize::try_from(GROUPS).unwrap() - 10,
        "the second push should be almost all deltas, got {deltas}"
    );
}

/// The writer's own verdict on a pack made of one blob of `bytes.len()` bytes
/// and every reader's, with default limits. `compressed` says whether the
/// writer keeps a zstd frame for it: it does not when the bytes it decodes to
/// and the frame together pass the 1 GiB budget.
fn object_reads_back(bytes: Vec<u8>, compressed: bool) {
    use kit_core::pack::window::read_all;
    use kit_core::pack::{PackFill, PackReader, PackWriter};

    // A blob: the six-byte prologue, a four-byte length and the content.
    let mut bytes = bytes;
    bytes[..6].copy_from_slice(&[0x01, b'K', b'O', b'B', b'1', 0x01]);
    let content = u32::try_from(bytes.len() - 10).unwrap();
    bytes[6..10].copy_from_slice(&content.to_le_bytes());
    let id = kit_core::hash::hash(&bytes);
    let entry = PackWriter::prepare_raw(id, bytes);
    assert_eq!(entry.decoded_len() > 0, compressed);
    // The writer takes it into an empty pack. A compressed entry spends most
    // of the decoded budget, so the writer seals before a second one.
    let fill = PackFill::of(&PackWriter::new());
    assert!(!fill.seals_before(entry.incoming(), u64::MAX, None, usize::MAX));
    if compressed {
        let second = PackWriter::prepare_raw(id, compressible(3, 128 << 20)).incoming();
        assert!(
            fill.with(entry.incoming())
                .seals_before(second, u64::MAX, None, usize::MAX),
            "a compressed object of 900 MiB leaves no room for one of 128 MiB"
        );
    }
    let mut writer = PackWriter::new();
    writer.push_prepared_raw(entry).unwrap();
    let pack = writer.finish().unwrap();

    let alice = Repo::new();
    let store = ObjectStore::open(&RepoLayout::single(alice.path())).unwrap();
    let key = kit_core::hash::hash(&pack);
    let mut sink = StoreSink {
        store: &store,
        stored: 0,
    };
    let unpacked = unpack(
        &key,
        &pack,
        &mut sink,
        UnpackOptions::default().with_limits(DecodeLimits::default()),
    )
    .unwrap_or_else(|e| panic!("unpack of a pack of {} bytes: {e}", pack.len()));
    assert_eq!(unpacked.ids, vec![id]);

    let mut bases = &store;
    let rewritten = rewrite_excluding(&pack, &HashSet::new(), &mut bases, DecodeLimits::default())
        .unwrap_or_else(|e| panic!("rewrite of a pack of {} bytes: {e}", pack.len()));
    assert!(rewritten.unchanged);

    for window in [64_u64 << 10, 1 << 20, 64 << 20] {
        let mut entries = 0;
        let mut source: &[u8] = &pack;
        read_all(
            &mut source,
            pack.len() as u64,
            window,
            DecodeLimits::default(),
            None,
            |_| {
                entries += 1;
                Ok(())
            },
        )
        .unwrap_or_else(|e| {
            panic!(
                "window reader with a {window}-byte window of a pack of {} bytes: {e}",
                pack.len()
            )
        });
        assert_eq!(entries, 1);
    }

    let report = PackReader::read(&pack, &store).unwrap();
    assert_eq!(report.raw_count, 1);
}

#[test]
#[ignore = "builds a 1 GiB object; run in release mode"]
fn the_largest_object_of_zeros_reads_back_through_every_reader() {
    // The object takes a few dozen KiB as a frame, but its 1 GiB and the frame
    // pass the budget of the smallest reader, so the writer stores it plain.
    object_reads_back(vec![0_u8; kit_core::store::MAX_RAW_OBJECT_SIZE], false);
}

#[test]
#[ignore = "builds a 1 GiB object; run in release mode"]
fn the_largest_object_of_sixteen_to_one_content_reads_back_through_every_reader() {
    // As a frame it would take about 64 MiB, which the window reader charges
    // beside the 1 GiB when the entry straddles windows. Stored plain, every
    // reader takes it.
    object_reads_back(compressible(7, kit_core::store::MAX_RAW_OBJECT_SIZE), false);
}

#[test]
#[ignore = "builds a 900 MiB object; run in release mode"]
fn a_compressed_object_that_straddles_windows_reads_back_through_every_reader() {
    // About 56 MiB on the wire: the entry is compressed, larger than a 1 MiB
    // window, and the window reader's charge for it, the frame and the 900 MiB
    // together, is under the budget.
    object_reads_back(compressible(7, 900 << 20), true);
}

#[test]
#[ignore = "builds a 1 GiB object; run in release mode"]
fn the_largest_incompressible_object_reads_back_through_every_reader() {
    object_reads_back(
        incompressible(9, kit_core::store::MAX_RAW_OBJECT_SIZE),
        false,
    );
}
