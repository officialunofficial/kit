//! A push sends the packs it always sent: the keys below were made by the
//! in-memory push this one replaced (the previous release), for a fixed
//! history pushed with a small pack cap, raw objects in four packs first and
//! then a delta of every file.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::path::Path;

use kit_core::hash::{Hash, to_hex};
use kit_core::layout::RepoLayout;
use kit_core::object::{Blob, Commit, EntryMode, Identity, Object, Tree, TreeEntry};
use kit_core::protocol::{PackKey, Transport};
use kit_core::refs;
use kit_core::store::ObjectStore;
use kit_core::{serialize, transfer};
use kit_sync::{CloneRemote, TransportSource, init_clone_dir};
use kit_transport_memory::MemoryTransport;

/// Bytes from `seed`, a quarter of them zero so that zstd frames some.
fn content(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let word = if (out.len() / 8) % 4 == 0 { 0 } else { state };
        out.extend_from_slice(&word.to_le_bytes());
    }
    out.truncate(len);
    out
}

/// Commit 24 files of 48 KiB on `parent`; with `edited`, each differs from
/// the unedited one in two bytes. Unsigned, with a fixed signer and time,
/// so every id is fixed.
fn commit(work: &Path, parent: Option<Hash>, edited: bool) -> Hash {
    let layout = RepoLayout::single(work);
    let store = ObjectStore::open(&layout).unwrap();
    let write = |object: &Object| store.write(&serialize::serialize(object).unwrap()).unwrap();
    let entries = (0..24u64)
        .map(|i| {
            let mut data = content(i, 48 << 10);
            if edited {
                data[1000] ^= 1;
                data[30_000] ^= 1;
            }
            TreeEntry {
                name: format!("f{i:02}").into_bytes(),
                mode: EntryMode::Blob,
                object_hash: write(&Object::Blob(Blob { data })),
            }
        })
        .collect();
    let tree = write(&Object::Tree(Tree { entries }));
    let tip = write(&Object::Commit(Commit::new_unannotated(
        tree,
        parent.into_iter().collect(),
        Identity::ed25519([3; 32]),
        [3; 32],
        b"fixed".to_vec(),
        1_700_000_000 + u64::from(edited),
        [0u8; 64],
    )));
    refs::write_ref(&layout, "main", &tip).unwrap();
    refs::write_head_branch(&layout, "main").unwrap();
    tip
}

/// The pack keys of `main`'s chain, oldest node first.
fn chain(tx: &MemoryTransport) -> Vec<String> {
    let mut nodes = Vec::new();
    let mut next = tx.read_ref("refs/kit/packmap/main").unwrap();
    while let Some(key) = next {
        let bytes = tx
            .download_blob(&PackKey::from_hash(key), None, u64::MAX)
            .unwrap();
        let node = transfer::decode_packlist(&bytes).unwrap();
        nodes.push(node.packs.iter().map(to_hex).collect::<Vec<_>>());
        next = node.prev;
    }
    nodes.reverse();
    nodes.concat()
}

#[test]
fn a_push_sends_the_packs_the_in_memory_push_sent() {
    let dir = tempfile::tempdir().unwrap();
    let work = dir.path().join("work");
    init_clone_dir(
        &work,
        &CloneRemote {
            name: "default".to_owned(),
            url: "kit+memory://bytes".to_owned(),
            kind: "memory".to_owned(),
        },
    )
    .unwrap();
    let tx = MemoryTransport::new();
    let source = TransportSource::new(&tx);
    let mut options = kit_sync::PushOptions::default();
    options.pack_payload_cap = 256 << 10;

    let base = commit(&work, None, false);
    kit_sync::push(&work, &source, &options).unwrap();
    let raw = chain(&tx);
    commit(&work, Some(base), true);
    kit_sync::push(&work, &source, &options).unwrap();
    let all = chain(&tx);

    assert_eq!(raw, EXPECTED_RAW);
    assert_eq!(all[..raw.len()], raw[..]);
    assert_eq!(&all[raw.len()..], EXPECTED_DELTA);
}

/// Made by the in-memory push of the previous release.
const EXPECTED_RAW: &[&str] = &[
    "9b8ab8270e62a09d83a526ea989b4302e7c3a14d9a90f42b8c8032523e1e0a48",
    "e9122716f2fc899b2a21b2f631fdad8e7fd91860f17bc9188ab95392ad11c5f8",
    "1aee9f4ab34cc4b5035d6fc1c4d4634ae0c0693326ad0ecfb7f2e1b9ef37445a",
    "b0668f4fba600eba584523931d94e4ce3818458fca0372211838d28419ae28be",
];
const EXPECTED_DELTA: &[&str] =
    &["f6139f2d55c1edae108893a1c4d97a7a542998ecfe1235398e399fbe153c92cc"];
