//! A push never writes a pack chain that a fetch would refuse to walk:
//! more than 100,000 nodes or 1,000,000 listed packs.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::cell::Cell;
use std::path::PathBuf;

use kit_core::hash::Hash;
use kit_core::layout::RepoLayout;
use kit_core::object::{Blob, Commit, EntryMode, Identity, Object, Tree, TreeEntry};
use kit_core::protocol::{
    PackBody, PackKey, PackSink, RefListing, RepoCursor, Transport, TransportResult,
};
use kit_core::refs::{self, Ref, RefWriteCondition};
use kit_core::sign::{self, KeyPair};
use kit_core::store::ObjectStore;
use kit_core::transfer;
use kit_sync::push::{PushError, PushLease, PushOptions, PushTarget};
use kit_sync::{CloneRemote, NoopObserver, RemoteSource, TransportSource, init_clone_dir};
use kit_transport_memory::MemoryTransport;

const REMOTE: &str = "default";
const MAIN: &str = "refs/heads/main";
const MAIN_MAP: &str = "refs/kit/packmap/main";
/// The deepest chain a fetch walks, in nodes.
const MAX_NODES: usize = 100_000;
/// The most packs a fetch reads from one chain, counted per listing.
const MAX_PACKS: usize = 1_000_000;
/// The most packs one synthetic node lists.
const NODE_PACKS: usize = 4096;

/// A memory remote that offers serialized advance, as the file and Connect
/// transports do, so a force push takes its guarded path.
struct Remote(MemoryTransport);

impl Remote {
    fn new() -> Self {
        Self(MemoryTransport::new())
    }
}

impl Transport for Remote {
    fn repo_cursor(&self) -> TransportResult<Option<RepoCursor>> {
        self.0.repo_cursor()
    }
    fn upload_pack(
        &self,
        pack: &dyn PackBody,
        key: &PackKey,
        head: Option<&str>,
    ) -> TransportResult<()> {
        self.0.upload_pack(pack, key, head)
    }
    fn download_pack(
        &self,
        key: &PackKey,
        hint: Option<&str>,
        sink: &mut dyn PackSink,
    ) -> TransportResult<()> {
        self.0.download_pack(key, hint, sink)
    }
    fn pack_exists(&self, key: &PackKey, hint: Option<&str>) -> TransportResult<bool> {
        self.0.pack_exists(key, hint)
    }
    fn update_ref(
        &self,
        name: &str,
        condition: RefWriteCondition,
        hash: &Hash,
    ) -> TransportResult<()> {
        self.0.update_ref(name, condition, hash)
    }
    fn delete_ref(&self, name: &str, expected: &Hash) -> TransportResult<()> {
        self.0.delete_ref(name, expected)
    }
    fn read_ref(&self, name: &str) -> TransportResult<Option<Hash>> {
        self.0.read_ref(name)
    }
    fn list_refs(&self, prefix: &str) -> TransportResult<Vec<Ref>> {
        self.0.list_refs(prefix)
    }
    fn ref_listing(&self) -> RefListing {
        self.0.ref_listing()
    }
    fn supports_serialized_advance(&self) -> bool {
        true
    }
}

/// A local repository that signs what it makes.
struct Work {
    _dir: tempfile::TempDir,
    path: PathBuf,
    layout: RepoLayout,
    store: ObjectStore,
    key: KeyPair,
    seq: Cell<u64>,
}

impl Work {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("work");
        let remote = CloneRemote {
            name: REMOTE.to_owned(),
            url: "kit+memory://x".to_owned(),
            kind: "memory".to_owned(),
        };
        let layout = init_clone_dir(&path, &remote).unwrap();
        let store = ObjectStore::open(&layout).unwrap();
        Self {
            _dir: dir,
            path,
            layout,
            store,
            key: KeyPair::generate().unwrap(),
            seq: Cell::new(0),
        }
    }

    fn write(&self, object: &Object) -> Hash {
        self.store
            .write(&kit_core::serialize::serialize(object).unwrap())
            .unwrap()
    }

    /// A signed commit on `parent` with one new file.
    fn commit(&self, parent: Option<Hash>) -> Hash {
        self.seq.set(self.seq.get() + 1);
        let n = self.seq.get();
        let blob = self.write(&Object::Blob(Blob {
            data: format!("content {n}\n").into_bytes(),
        }));
        let tree = self.write(&Object::Tree(Tree {
            entries: vec![TreeEntry {
                name: format!("f{n}").into_bytes(),
                mode: EntryMode::Blob,
                object_hash: blob,
            }],
        }));
        let mut commit = Commit::new_unannotated(
            tree,
            parent.into_iter().collect(),
            Identity::ed25519(self.key.public.0),
            self.key.public.0,
            format!("commit {n}").into_bytes(),
            1_700_000_000 + n,
            [0u8; 64],
        );
        commit.signature = sign::sign_commit(&commit, &self.key).unwrap().0;
        self.write(&Object::Commit(commit))
    }

    fn branch(&self, name: &str, tip: Hash) {
        refs::write_ref(&self.layout, name, &tip).unwrap();
    }

    fn push(
        &self,
        source: &dyn RemoteSource,
        lease: PushLease,
    ) -> Result<kit_sync::PushReport, PushError> {
        let mut options = PushOptions::default();
        options.target = PushTarget::Branch {
            local: "main".to_owned(),
            remote: "main".to_owned(),
            lease,
        };
        kit_sync::push(&self.path, source, &options)
    }
}

/// Link `nodes` onto the packmap of `main`, each listing the packs of one
/// entry of `listings`, and move the packmap to the last. Each listing names
/// `pack`, the pack the chain already holds, so the chain stays fetchable.
fn grow_chain(tx: &Remote, pack: Hash, listings: impl Iterator<Item = usize>) {
    let mut head = tx.read_ref(MAIN_MAP).unwrap().unwrap();
    let start = head;
    for count in listings {
        let bytes = transfer::encode_packlist(Some(head), &vec![pack; count]).unwrap();
        let key = kit_core::hash::hash(&bytes);
        tx.upload_blob(&bytes, &PackKey::from_hash(key), Some(MAIN))
            .unwrap();
        head = key;
    }
    tx.update_ref(MAIN_MAP, RefWriteCondition::Match(start), &head)
        .unwrap();
}

/// The chain of `main` as a fetch walks it: its depth and listed packs.
fn fetched_chain(tx: &Remote) -> Result<(usize, usize), kit_sync::SyncError> {
    let head = tx.read_ref(MAIN_MAP).unwrap().unwrap();
    let nodes =
        kit_sync::packmap::walk_pack_chain(&TransportSource::new(tx), &NoopObserver, MAIN, head)?;
    Ok((nodes.len(), nodes.iter().map(|n| n.packs.len()).sum()))
}

/// `main` pushed once, and its chain grown by `listings` to a size a fetch
/// still accepts. Returns the repository, the pushed tip and its child.
fn at_the_bound(tx: &Remote, listings: &[usize]) -> (Work, Hash, Hash) {
    let work = Work::new();
    let c1 = work.commit(None);
    work.branch("main", c1);
    work.push(&TransportSource::new(tx), PushLease::FastForward)
        .unwrap();
    let map = tx.read_ref(MAIN_MAP).unwrap().unwrap();
    let pack = fetched_root_pack(tx, map);
    grow_chain(tx, pack, listings.iter().copied());
    let c2 = work.commit(Some(c1));
    work.branch("main", c2);
    (work, c1, c2)
}

fn fetched_root_pack(tx: &Remote, map: Hash) -> Hash {
    let bytes = tx
        .download_blob(&PackKey::from_hash(map), Some(MAIN), 1 << 20)
        .unwrap();
    transfer::decode_packlist(&bytes).unwrap().packs[0]
}

/// Listings that make the pushed chain `nodes` deep, listing `packs` packs
/// in its first grown node.
fn deep(nodes: usize, packs: usize) -> Vec<usize> {
    let mut listings = vec![packs];
    listings.resize(nodes - 1, 0);
    listings
}

/// 100,000 nodes listing 4,097 packs: too many packs for a re-baseline, so
/// the next push would append a node a fetch refuses to walk.
fn node_bound() -> Vec<usize> {
    deep(MAX_NODES, NODE_PACKS)
}

/// Listings that make the pushed chain list `packs` packs.
fn listing(packs: usize) -> Vec<usize> {
    let mut listings = vec![NODE_PACKS; (packs - 1) / NODE_PACKS];
    listings.push(packs - 1 - listings.len() * NODE_PACKS);
    listings
}

/// 1,000,000 listed packs over 246 nodes.
fn pack_bound() -> Vec<usize> {
    listing(MAX_PACKS)
}

#[test]
fn the_synthetic_chains_are_at_the_fetch_bounds() {
    for (listings, nodes, packs) in [
        (node_bound(), MAX_NODES, NODE_PACKS + 1),
        (pack_bound(), 1 + pack_bound().len(), MAX_PACKS),
    ] {
        let tx = Remote::new();
        at_the_bound(&tx, &listings);
        assert_eq!(fetched_chain(&tx).unwrap(), (nodes, packs));
    }
}

/// A push that would make the chain one node deeper or one pack longer
/// than a fetch walks is refused with a typed error, and the remote keeps
/// the branch and chain it had, which a fetch still walks.
#[test]
fn a_push_refuses_a_chain_a_fetch_would_refuse() {
    for (case, listings) in [("nodes", node_bound()), ("packs", pack_bound())] {
        for lease in [PushLease::FastForward, PushLease::Force] {
            let tx = Remote::new();
            let (work, c1, _c2) = at_the_bound(&tx, &listings);
            let map = tx.read_ref(MAIN_MAP).unwrap();
            let result = work.push(&TransportSource::new(&tx), lease);
            assert!(
                matches!(&result, Err(PushError::PackChainTooLong { branch }) if branch == "main"),
                "{case} {lease:?}: {result:?}"
            );
            assert_eq!(tx.read_ref(MAIN).unwrap(), Some(c1), "{case} {lease:?}");
            assert_eq!(tx.read_ref(MAIN_MAP).unwrap(), map, "{case} {lease:?}");
            fetched_chain(&tx).unwrap();
        }
    }
}

/// A push that lands exactly on a bound is published, and a fetch walks the
/// chain it leaves.
#[test]
fn a_push_that_reaches_a_bound_is_published() {
    for (case, listings, size) in [
        (
            "nodes",
            deep(MAX_NODES - 1, NODE_PACKS),
            (MAX_NODES, NODE_PACKS + 2),
        ),
        (
            "packs",
            listing(MAX_PACKS - 1),
            (2 + listing(MAX_PACKS - 1).len(), MAX_PACKS),
        ),
    ] {
        for lease in [PushLease::FastForward, PushLease::Force] {
            let tx = Remote::new();
            let (work, _c1, c2) = at_the_bound(&tx, &listings);
            work.push(&TransportSource::new(&tx), lease)
                .unwrap_or_else(|error| panic!("{case} {lease:?}: {error}"));
            assert_eq!(tx.read_ref(MAIN).unwrap(), Some(c2), "{case} {lease:?}");
            assert_eq!(fetched_chain(&tx).unwrap(), size, "{case} {lease:?}");
        }
    }
}

/// A chain at the node bound that one node can list re-baselines: the new
/// node has no predecessor, so the bound does not refuse it.
#[test]
fn a_push_at_the_node_bound_re_baselines_a_chain_one_node_can_list() {
    let tx = Remote::new();
    let (work, _c1, c2) = at_the_bound(&tx, &deep(MAX_NODES, 1));
    work.push(&TransportSource::new(&tx), PushLease::FastForward)
        .unwrap();
    assert_eq!(tx.read_ref(MAIN).unwrap(), Some(c2));
    assert_eq!(fetched_chain(&tx).unwrap(), (1, 3));
}

/// A force push of a commit whose closure the remote lacks replaces a chain
/// a fetch refuses (its head names no node) with a new one.
#[test]
fn a_force_push_of_a_fresh_root_resets_a_broken_chain() {
    let tx = Remote::new();
    let work = Work::new();
    let c1 = work.commit(None);
    work.branch("main", c1);
    work.push(&TransportSource::new(&tx), PushLease::FastForward)
        .unwrap();
    tx.update_ref(MAIN_MAP, RefWriteCondition::Any, &[0xEE; 32])
        .unwrap();
    assert!(fetched_chain(&tx).is_err());

    let other = Work::new();
    let root = other.commit(None);
    other.branch("main", root);
    other
        .push(&TransportSource::new(&tx), PushLease::Force)
        .unwrap();
    assert_eq!(tx.read_ref(MAIN).unwrap(), Some(root));
    assert_eq!(fetched_chain(&tx).unwrap().0, 1);
}
