//! A push and its tracking ref: the lease is the tracking ref the push
//! checked, the push refuses a divergent tip, and the tracking ref it writes
//! names objects a concurrent gc kept.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::cell::Cell;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

use kit_core::hash::Hash;
use kit_core::layout::RepoLayout;
use kit_core::object::{Blob, Commit, EntryMode, Identity, Object, Tree, TreeEntry};
use kit_core::protocol::{
    PackBody, PackKey, PackSink, RefListing, RepoCursor, Transport, TransportResult,
};
use kit_core::refs::{self, Ref, RefWriteCondition};
use kit_core::sign::{self, KeyPair};
use kit_core::store::ObjectStore;
use kit_sync::push::{PushError, PushLease, PushOptions, PushTarget};
use kit_sync::{CloneRemote, Observer, RemoteSource, SyncEvent, TransportSource, init_clone_dir};
use kit_transport_memory::MemoryTransport;

const REMOTE: &str = "default";
const MAIN: &str = "refs/heads/main";

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
        branch: &str,
        lease: PushLease,
        observer: Option<&dyn Observer<SyncEvent>>,
    ) -> Result<kit_sync::PushReport, PushError> {
        let mut options = PushOptions::default();
        options.target = PushTarget::Branch {
            local: branch.to_owned(),
            remote: branch.to_owned(),
            lease,
        };
        if let Some(observer) = observer {
            options.control.observer = observer;
        }
        kit_sync::push(&self.path, source, &options)
    }

    fn tracking(&self, branch: &str) -> Option<Hash> {
        refs::read_remote_ref(&self.layout, REMOTE, branch).unwrap()
    }
}

/// `main` pushed as `c1`, then `c2`: the remote and the tracking ref hold
/// `c2`.
fn pushed_main(tx: &MemoryTransport) -> (Work, Hash, Hash) {
    let work = Work::new();
    let c1 = work.commit(None);
    work.branch("main", c1);
    work.push(&TransportSource::new(tx), "main", PushLease::FastForward, None)
        .unwrap();
    let c2 = work.commit(Some(c1));
    work.branch("main", c2);
    work.push(&TransportSource::new(tx), "main", PushLease::FastForward, None)
        .unwrap();
    assert_eq!(tx.read_ref(MAIN).unwrap(), Some(c2));
    assert_eq!(work.tracking("main"), Some(c2));
    (work, c1, c2)
}

/// A plain push of a tip that does not descend from the tracking ref is
/// refused, even though the remote still holds the tracking ref, so the
/// lease alone would let the push replace it.
#[test]
fn a_plain_push_refuses_a_divergent_tip_when_the_lease_holds() {
    let tx = MemoryTransport::new();
    let (work, c1, c2) = pushed_main(&tx);
    let sibling = work.commit(Some(c1));
    work.branch("main", sibling);
    let result = work.push(&TransportSource::new(&tx), "main", PushLease::FastForward, None);
    assert!(
        matches!(result, Err(PushError::NonFastForwardPush { .. })),
        "{result:?}"
    );
    assert_eq!(tx.read_ref(MAIN).unwrap(), Some(c2));
    assert_eq!(work.tracking("main"), Some(c2));
    // A lease push replaces it: the remote still holds the tracking ref.
    work.push(&TransportSource::new(&tx), "main", PushLease::WithLease, None)
        .unwrap();
    assert_eq!(tx.read_ref(MAIN).unwrap(), Some(sibling));
}

type Hook<'a> = dyn Fn(&str) + Send + Sync + 'a;

/// A transport that runs a hook before each ref read.
struct BeforeRead<'a> {
    inner: &'a dyn Transport,
    hook: Box<Hook<'a>>,
}

impl Transport for BeforeRead<'_> {
    fn repo_cursor(&self) -> TransportResult<Option<RepoCursor>> {
        self.inner.repo_cursor()
    }
    fn upload_pack(
        &self,
        pack: &dyn PackBody,
        key: &PackKey,
        head: Option<&str>,
    ) -> TransportResult<()> {
        self.inner.upload_pack(pack, key, head)
    }
    fn download_pack(
        &self,
        key: &PackKey,
        hint: Option<&str>,
        sink: &mut dyn PackSink,
    ) -> TransportResult<()> {
        self.inner.download_pack(key, hint, sink)
    }
    fn pack_exists(&self, key: &PackKey, hint: Option<&str>) -> TransportResult<bool> {
        self.inner.pack_exists(key, hint)
    }
    fn update_ref(
        &self,
        name: &str,
        condition: RefWriteCondition,
        hash: &Hash,
    ) -> TransportResult<()> {
        self.inner.update_ref(name, condition, hash)
    }
    fn delete_ref(&self, name: &str, expected: &Hash) -> TransportResult<()> {
        self.inner.delete_ref(name, expected)
    }
    fn read_ref(&self, name: &str) -> TransportResult<Option<Hash>> {
        (self.hook)(name);
        self.inner.read_ref(name)
    }
    fn list_refs(&self, prefix: &str) -> TransportResult<Vec<Ref>> {
        self.inner.list_refs(prefix)
    }
    fn ref_listing(&self) -> RefListing {
        self.inner.ref_listing()
    }
}

/// A fetch that lands while a plain push runs moves the tracking ref to a
/// remote head the pushed tip does not descend from. The push leases the
/// tracking ref it checked, not the one the fetch wrote, so the remote keeps
/// the other client's commit.
#[test]
fn a_fetch_during_a_plain_push_cannot_make_it_rewind_the_remote() {
    let tx = MemoryTransport::new();
    let (work, _c1, c2) = pushed_main(&tx);
    // Another client advances the remote to `other`, a child of `c2`.
    let other = work.commit(Some(c2));
    // `local` also descends from `c2`, but not from `other`.
    let local = work.commit(Some(c2));
    work.branch("main", local);
    let fetched = AtomicBool::new(false);
    let layout = &work.layout;
    let faulty = BeforeRead {
        inner: &tx,
        hook: Box::new(|name| {
            if name == MAIN && !fetched.swap(true, Ordering::SeqCst) {
                // The other client's push, then this repository's fetch of it.
                tx.update_ref(MAIN, RefWriteCondition::Match(c2), &other)
                    .unwrap();
                refs::write_remote_ref(layout, REMOTE, "main", &other).unwrap();
            }
        }),
    };
    let result = work.push(
        &TransportSource::new(&faulty),
        "main",
        PushLease::FastForward,
        None,
    );
    assert!(fetched.load(Ordering::SeqCst));
    assert!(
        matches!(result, Err(PushError::NonFastForwardPush { .. })),
        "{result:?}"
    );
    assert_eq!(tx.read_ref(MAIN).unwrap(), Some(other));
}

/// On the first pack upload of a push of `topic`, deletes the local branch
/// and runs gc with no grace period, as another process could.
struct GcDuringUpload<'a> {
    layout: &'a RepoLayout,
    ran: Cell<bool>,
}

impl Observer<SyncEvent> for GcDuringUpload<'_> {
    fn event(&self, event: &SyncEvent) {
        let SyncEvent::PackUploaded { .. } = event else {
            return;
        };
        if self.ran.replace(true) {
            return;
        }
        refs::delete_ref(self.layout, "topic").unwrap();
        let store = ObjectStore::open(self.layout).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        kit_core::ops::gc::run_gc(&store, self.layout, now + 3600, 0, false).unwrap();
    }
}

/// A branch deleted and collected while its push uploads leaves a tracking
/// ref whose tip is still in the store: gc keeps every object while the push
/// runs.
#[test]
fn a_gc_during_a_push_keeps_the_tip_its_tracking_ref_names() {
    let tx = MemoryTransport::new();
    let work = Work::new();
    let c1 = work.commit(None);
    let tip = work.commit(Some(c1));
    work.branch("topic", tip);
    let observer = GcDuringUpload {
        layout: &work.layout,
        ran: Cell::new(false),
    };
    work.push(
        &TransportSource::new(&tx),
        "topic",
        PushLease::FastForward,
        Some(&observer),
    )
    .unwrap();
    assert!(observer.ran.get());
    assert_eq!(tx.read_ref("refs/heads/topic").unwrap(), Some(tip));
    assert_eq!(work.tracking("topic"), Some(tip));
    let store = ObjectStore::open(&work.layout).unwrap();
    for id in [tip, c1] {
        assert!(store.contains(&id), "{id:?} pruned under the push");
    }
    // A later gc keeps the tip: the tracking ref is a root.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    kit_core::ops::gc::run_gc(&store, &work.layout, now + 3600, 0, false).unwrap();
    assert!(store.contains(&tip));
}
