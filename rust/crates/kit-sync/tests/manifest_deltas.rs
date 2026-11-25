//! A push sends a replacement chunk manifest as a delta against the manifest
//! the remote holds, to a remote that takes one, and in full to every other.
//!
//! A file of many chunks has a manifest of about 40 bytes per chunk. A rewrite
//! that changes one chunk replaces it with a manifest that differs in one
//! entry, so the delta against the old one is a few dozen bytes. These tests
//! push versions of such a file and read the packs the push uploaded: a
//! manifest delta shows as a delta entry whose base is the old manifest.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::cell::RefCell;
use std::path::Path;

use kit_core::hash::Hash;
use kit_core::layout::RepoLayout;
use kit_core::object::{Blob, ChunkedBlob, Commit, EntryMode, Identity, Object, Tree, TreeEntry};
use kit_core::protocol::{PackBody, PackKey, PackSink, Transport};
use kit_core::refs::{self, Ref, RefWriteCondition};
use kit_core::sign::{self, KeyPair};
use kit_core::store::ObjectStore;
use kit_core::{ops, pack, serialize};
use kit_sync::{
    CloneRemote, NoopObserver, PushOptions, RemoteSource, SourceError, SyncOptions,
    TransportSource, clone, init_clone_dir,
};
use kit_transport_memory::MemoryTransport;

const CHUNK_LEN: usize = 4096;
const CHUNKS: usize = 400;

/// `CHUNK_LEN` incompressible bytes from `seed`.
fn chunk(seed: u64) -> Vec<u8> {
    let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    let mut out = vec![0u8; CHUNK_LEN];
    for word in out.chunks_mut(8) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        word.copy_from_slice(&state.to_le_bytes());
    }
    out
}

/// Commit one file of `CHUNKS` chunks on `parent`. Chunk `i` has the content
/// of seed `i`, except that each index in `changed` has the content of seed
/// `1000 + generation`: a rewrite of those chunks. The commit is
/// signed by `key`, and `main` is moved to it.
fn commit(
    work: &Path,
    key: &KeyPair,
    parent: Option<Hash>,
    generation: u64,
    changed: &[usize],
) -> (Hash, Hash) {
    let layout = RepoLayout::single(work);
    let store = ObjectStore::open(&layout).unwrap();
    let write = |object: &Object| store.write(&serialize::serialize(object).unwrap()).unwrap();
    let ids: Vec<(Hash, u64)> = (0..CHUNKS)
        .map(|i| {
            let seed = if changed.contains(&i) {
                1000 + generation * 10 + i as u64
            } else {
                i as u64
            };
            let id = write(&Object::Blob(Blob { data: chunk(seed) }));
            (id, ((i + 1) * CHUNK_LEN) as u64)
        })
        .collect();
    let manifest = ChunkedBlob::new(
        (CHUNKS * CHUNK_LEN) as u64,
        u32::try_from(CHUNK_LEN).unwrap(),
        ids,
    )
    .unwrap();
    let manifest = write(&Object::ChunkedBlob(manifest));
    let tree = write(&Object::Tree(Tree {
        entries: vec![TreeEntry {
            name: b"large.bin".to_vec(),
            mode: EntryMode::Blob,
            object_hash: manifest,
        }],
    }));
    let mut commit = Commit::new_unannotated(
        tree,
        parent.into_iter().collect(),
        Identity::ed25519(key.public.0),
        key.public.0,
        format!("generation {generation}").into_bytes(),
        1_700_000_000 + generation,
        [0u8; 64],
    );
    commit.signature = sign::sign_commit(&commit, key).unwrap().0;
    let tip = write(&Object::Commit(commit));
    refs::write_ref(&layout, "main", &tip).unwrap();
    refs::write_head_branch(&layout, "main").unwrap();
    (tip, manifest)
}

fn remote() -> CloneRemote {
    CloneRemote {
        name: "default".to_owned(),
        url: "kit+memory://manifest".to_owned(),
        kind: "memory".to_owned(),
    }
}

/// A source over a transport that keeps the packs it is sent, and that either
/// reports what the transport does or never takes a manifest delta, as a
/// hosted source does.
struct Recording<'a> {
    inner: TransportSource<'a>,
    hosted: bool,
    packs: RefCell<Vec<Vec<u8>>>,
}

impl<'a> Recording<'a> {
    fn new(tx: &'a MemoryTransport, hosted: bool) -> Self {
        Self {
            inner: TransportSource::new(tx),
            hosted,
            packs: RefCell::default(),
        }
    }

    /// The packs sent since the last call, and the bytes in them.
    fn take(&self) -> (Vec<Vec<u8>>, usize) {
        let packs = std::mem::take(&mut *self.packs.borrow_mut());
        let bytes = packs.iter().map(Vec::len).sum();
        (packs, bytes)
    }
}

impl RemoteSource for Recording<'_> {
    fn list_branches(&self) -> Result<Vec<Ref>, SourceError> {
        self.inner.list_branches()
    }
    fn list_refs(&self, prefix: &str) -> Result<Vec<Ref>, SourceError> {
        self.inner.list_refs(prefix)
    }
    fn read_ref(&self, name: &str) -> Result<Option<Hash>, SourceError> {
        self.inner.read_ref(name)
    }
    fn download_blob(&self, key: &PackKey, hint: &str) -> Result<Vec<u8>, SourceError> {
        self.inner.download_blob(key, hint)
    }
    fn download_pack(
        &self,
        key: &PackKey,
        hint: &str,
        sink: &mut dyn PackSink,
    ) -> Result<(), SourceError> {
        self.inner.download_pack(key, hint, sink)
    }
    fn supports_push(&self) -> bool {
        self.inner.supports_push()
    }
    fn pack_exists(&self, key: &PackKey, hint: &str) -> Result<bool, SourceError> {
        self.inner.pack_exists(key, hint)
    }
    fn upload_pack(
        &self,
        body: &dyn PackBody,
        key: &PackKey,
        head_ref: &str,
    ) -> Result<(), SourceError> {
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut body.read_from(0).unwrap(), &mut bytes).unwrap();
        self.packs.borrow_mut().push(bytes);
        self.inner.upload_pack(body, key, head_ref)
    }
    fn upload_blob(&self, bytes: &[u8], key: &PackKey, head_ref: &str) -> Result<(), SourceError> {
        self.inner.upload_blob(bytes, key, head_ref)
    }
    fn update_ref(
        &self,
        name: &str,
        condition: RefWriteCondition,
        tip: &Hash,
    ) -> Result<(), SourceError> {
        self.inner.update_ref(name, condition, tip)
    }
    #[allow(clippy::too_many_arguments)]
    fn advance_refs_committing(
        &self,
        head: &str,
        head_condition: RefWriteCondition,
        tip: &Hash,
        packmap: &str,
        packmap_condition: RefWriteCondition,
        node: &Hash,
        keys: &[PackKey],
    ) -> Result<kit_core::protocol::CommitOutcome, SourceError> {
        self.inner.advance_refs_committing(
            head,
            head_condition,
            tip,
            packmap,
            packmap_condition,
            node,
            keys,
        )
    }
    fn upload_limits(&self) -> kit_core::protocol::UploadLimits {
        self.inner.upload_limits()
    }
    fn ref_listing(&self) -> kit_core::protocol::RefListing {
        self.inner.ref_listing()
    }
    fn supports_atomic_advance(&self) -> bool {
        self.inner.supports_atomic_advance()
    }
    fn supports_serialized_advance(&self) -> bool {
        self.inner.supports_serialized_advance()
    }
    fn atomic_advance_status(&self) -> Option<bool> {
        self.inner.atomic_advance_status()
    }
    fn accepts_manifest_deltas(&self) -> bool {
        !self.hosted && self.inner.accepts_manifest_deltas()
    }
}

/// A fresh clone-ready working directory.
fn work_dir(dir: &Path) -> std::path::PathBuf {
    let work = dir.join("work");
    init_clone_dir(&work, &remote()).unwrap();
    work
}

/// The bases of every delta entry in `packs`.
fn delta_bases(packs: &[Vec<u8>]) -> Vec<Hash> {
    packs
        .iter()
        .flat_map(|pack| pack::delta_base_hashes(pack).unwrap())
        .collect()
}

/// The newest node of `main`'s pack chain.
fn head_node(tx: &MemoryTransport) -> kit_core::transfer::PackListNode {
    let key = tx.read_ref("refs/kit/packmap/main").unwrap().unwrap();
    let bytes = tx
        .download_blob(&PackKey::from_hash(key), None, u64::MAX)
        .unwrap();
    kit_core::transfer::decode_packlist(&bytes).unwrap()
}

/// Clone the remote into a fresh directory and check that every object the
/// tip reaches reads back and addresses to its id.
fn assert_clones(tx: &MemoryTransport, tip: Hash) {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("clone");
    clone(
        &target,
        &TransportSource::new(tx),
        &remote(),
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();
    let store = ObjectStore::open(&RepoLayout::single(&target)).unwrap();
    let reachable = ops::reachable_objects(&store, &tip).unwrap();
    assert!(reachable.len() > CHUNKS);
    for id in reachable {
        let object = serialize::deserialize(&store.read(&id).unwrap()).unwrap();
        assert_eq!(object.id().unwrap(), id);
    }
}

#[test]
fn a_remote_that_takes_it_gets_the_replacement_manifest_as_a_delta() {
    let dir = tempfile::tempdir().unwrap();
    let work = work_dir(dir.path());
    let key = KeyPair::generate().unwrap();
    let tx = MemoryTransport::new();
    let source = Recording::new(&tx, false);
    let options = PushOptions::default();

    let (first, old_manifest) = commit(&work, &key, None, 0, &[]);
    kit_sync::push(&work, &source, &options).unwrap();
    let (_, first_bytes) = source.take();

    let (second, new_manifest) = commit(&work, &key, Some(first), 1, &[200]);
    assert_ne!(old_manifest, new_manifest);
    kit_sync::push(&work, &source, &options).unwrap();
    let (packs, bytes) = source.take();

    assert!(delta_bases(&packs).contains(&old_manifest));
    // The push sends the new chunk and a few dozen bytes of manifest, not a
    // manifest of 16 KB.
    assert!(
        bytes < CHUNK_LEN + 600,
        "the second push sent {bytes} bytes"
    );
    assert!(bytes * 5 < first_bytes);
    assert_clones(&tx, second);
}

#[test]
fn a_hosted_source_gets_every_manifest_in_full() {
    let dir = tempfile::tempdir().unwrap();
    let work = work_dir(dir.path());
    let key = KeyPair::generate().unwrap();
    let tx = MemoryTransport::new();
    let source = Recording::new(&tx, true);
    let options = PushOptions::default();

    let (first, old_manifest) = commit(&work, &key, None, 0, &[]);
    kit_sync::push(&work, &source, &options).unwrap();
    source.take();
    let (second, _) = commit(&work, &key, Some(first), 1, &[200]);
    kit_sync::push(&work, &source, &options).unwrap();
    let (packs, bytes) = source.take();

    // No delta entry names a manifest, and the new one is sent whole.
    assert!(!delta_bases(&packs).contains(&old_manifest));
    assert!(bytes > CHUNKS * 32, "the manifest went in full: {bytes}");
    assert_clones(&tx, second);
}

#[test]
fn every_version_of_a_pushed_file_clones_across_rebaselines() {
    let dir = tempfile::tempdir().unwrap();
    let work = work_dir(dir.path());
    let key = KeyPair::generate().unwrap();
    let tx = MemoryTransport::new();
    let source = Recording::new(&tx, false);
    // A chain this long is folded into one node every few pushes.
    let mut options = PushOptions::default();
    options.rebaseline_threshold = 2;

    let (mut tip, mut manifest) = commit(&work, &key, None, 0, &[]);
    kit_sync::push(&work, &source, &options).unwrap();
    source.take();
    let (mut deltas, mut rebaselines) = (0, 0);
    for generation in 1..=6u64 {
        let changed = [(usize::try_from(generation).unwrap() * 37) % CHUNKS, 5];
        let (next, next_manifest) = commit(&work, &key, Some(tip), generation, &changed);
        kit_sync::push(&work, &source, &options).unwrap();
        let (packs, _) = source.take();
        deltas += usize::from(delta_bases(&packs).contains(&manifest));
        rebaselines += usize::from(head_node(&tx).prev.is_none());
        (tip, manifest) = (next, next_manifest);
        // A delta's base must still be readable from the chain it was sent on.
        if generation % 2 == 1 || generation == 6 {
            assert_clones(&tx, tip);
        }
    }
    assert!(rebaselines > 0, "the chain was folded at least once");
    assert_eq!(deltas, 6, "every rewrite after the first push was a delta");
}
