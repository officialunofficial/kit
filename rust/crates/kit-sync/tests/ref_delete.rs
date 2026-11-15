//! `kit push --delete` (SPEC-TRANSPORT §7.3): a remote branch or tag goes
//! with its chain ref, each under `Match`.
//!
//! Each test pushes from a local repository to a memory or file remote, then
//! deletes through a [`Faulty`] transport, which can step in before a ref's
//! delete or crash in place of it, as a dying client would.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::cell::Cell;
use std::path::PathBuf;
use std::sync::Mutex;

use kit_core::hash::Hash;
use kit_core::layout::RepoLayout;
use kit_core::object::{Blob, Commit, EntryMode, Identity, Object, Tag, Tree, TreeEntry};
use kit_core::protocol::{
    AdvanceOutcome, PackBody, PackKey, PackSink, RefListing, RepoCursor, Transport, TransportError,
    TransportResult,
};
use kit_core::refs::{self, Ref, RefWriteCondition};
use kit_core::sign::{self, KeyPair};
use kit_core::store::ObjectStore;
use kit_core::transfer;
use kit_sync::push::{
    DeleteError, DeleteTarget, DeletedRef, PushError, PushLease, PushOptions, PushTarget,
    TagPushOutcome, TagSelection,
};
use kit_sync::{
    CloneRemote, NoopObserver, RemoteSource, SourceError, SyncOptions, TransportSource, clone,
    init_clone_dir,
};
use kit_transport_file::FileTransport;
use kit_transport_memory::MemoryTransport;

#[derive(Clone, Copy, Debug)]
enum Kind {
    Memory,
    File,
}

const KINDS: [Kind; 2] = [Kind::Memory, Kind::File];
const REMOTE: &str = "default";

fn transport(kind: Kind) -> (Box<dyn Transport>, Option<tempfile::TempDir>) {
    match kind {
        Kind::Memory => (Box::new(MemoryTransport::new()), None),
        Kind::File => {
            let root = tempfile::tempdir().unwrap();
            (
                Box::new(FileTransport::new(root.path().join("r"))),
                Some(root),
            )
        }
    }
}

fn remote_config() -> CloneRemote {
    CloneRemote {
        name: REMOTE.to_owned(),
        url: "kit+memory://x".to_owned(),
        kind: "memory".to_owned(),
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
        let layout = init_clone_dir(&path, &remote_config()).unwrap();
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

    /// A signed annotated tag `name` on `target`, as a local tag.
    fn tag(&self, name: &str, target: Hash) -> Hash {
        self.seq.set(self.seq.get() + 1);
        let mut tag = Tag {
            target,
            target_type: self.store.object_type(&target).unwrap(),
            name: name.as_bytes().to_vec(),
            tagger: Identity::ed25519(self.key.public.0),
            signer: self.key.public.0,
            message: format!("release {name}").into_bytes(),
            timestamp: 1_700_000_000 + self.seq.get(),
            signature: [0u8; 64],
        };
        tag.signature = sign::sign_tag(&tag, &self.key).unwrap().0;
        let id = self.write(&Object::Tag(tag));
        refs::write_tag(&self.layout, name, &id).unwrap();
        id
    }

    fn branch(&self, name: &str, tip: Hash) {
        refs::write_ref(&self.layout, name, &tip).unwrap();
    }

    fn run(
        &self,
        source: &dyn RemoteSource,
        target: PushTarget,
    ) -> Result<kit_sync::PushReport, PushError> {
        let mut options = PushOptions::default();
        options.target = target;
        kit_sync::push(&self.path, source, &options)
    }

    /// Push `branch` with the tracking ref as its lease.
    fn push_branch(&self, source: &dyn RemoteSource, branch: &str) {
        self.run(
            source,
            PushTarget::Branch {
                local: branch.to_owned(),
                remote: branch.to_owned(),
                lease: PushLease::WithLease,
            },
        )
        .unwrap();
    }

    fn push_tag(&self, source: &dyn RemoteSource, tag: &str) -> TagPushOutcome {
        let tags = self
            .run(
                source,
                PushTarget::Tags {
                    selection: TagSelection::Named(vec![tag.to_owned()]),
                    force: false,
                },
            )
            .unwrap()
            .tags;
        tags.into_iter().next().unwrap().outcome
    }

    fn delete(
        &self,
        source: &dyn RemoteSource,
        target: DeleteTarget,
    ) -> Result<DeletedRef, PushError> {
        Ok(self
            .run(source, PushTarget::Delete(target))?
            .deleted
            .unwrap())
    }

    fn tracking(&self, branch: &str) -> Option<Hash> {
        refs::read_remote_ref(&self.layout, REMOTE, branch).unwrap()
    }
}

type Hook<'a> = dyn Fn(&str, &dyn Transport) + Send + Sync + 'a;

/// A transport over another that can step in before a ref's delete, or
/// crash in place of it.
struct Faulty<'a> {
    inner: &'a dyn Transport,
    /// Runs before each delete reaches the transport.
    before_delete: Mutex<Option<Box<Hook<'a>>>>,
    /// A ref whose delete never reaches the transport and fails, as a
    /// client that dies there.
    crash_on: Mutex<Option<String>>,
    /// Every delete that reached the transport.
    deleted: Mutex<Vec<String>>,
}

impl<'a> Faulty<'a> {
    fn new(inner: &'a dyn Transport) -> Self {
        Self {
            inner,
            before_delete: Mutex::default(),
            crash_on: Mutex::default(),
            deleted: Mutex::default(),
        }
    }

    fn before_delete(&self, hook: impl Fn(&str, &dyn Transport) + Send + Sync + 'a) {
        *self.before_delete.lock().unwrap() = Some(Box::new(hook));
    }

    fn crash_on(&self, name: &str) {
        *self.crash_on.lock().unwrap() = Some(name.to_owned());
    }
}

impl Transport for Faulty<'_> {
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
        if let Some(hook) = self.before_delete.lock().unwrap().as_ref() {
            hook(name, self.inner);
        }
        if self.crash_on.lock().unwrap().as_deref() == Some(name) {
            return Err(TransportError::ConnectionFailed);
        }
        self.deleted.lock().unwrap().push(name.to_owned());
        self.inner.delete_ref(name, expected)
    }
    fn read_ref(&self, name: &str) -> TransportResult<Option<Hash>> {
        self.inner.read_ref(name)
    }
    fn list_refs(&self, prefix: &str) -> TransportResult<Vec<Ref>> {
        self.inner.list_refs(prefix)
    }
    fn ref_listing(&self) -> RefListing {
        self.inner.ref_listing()
    }
}

/// A source whose delete is one transaction, as a Connect server's is: a
/// moved chain ref is a conflict that deletes nothing. It moves the chain ref
/// before each of its first `moves` deletes.
struct Atomic<'a> {
    inner: TransportSource<'a>,
    tx: &'a dyn Transport,
    moves: Cell<usize>,
    calls: Cell<usize>,
}

impl RemoteSource for Atomic<'_> {
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
        true
    }
    fn delete_refs(
        &self,
        head: &str,
        head_expected: &Hash,
        map: &str,
        map_expected: Option<&Hash>,
    ) -> Result<AdvanceOutcome, SourceError> {
        self.calls.set(self.calls.get() + 1);
        if self.moves.get() > 0 {
            self.moves.set(self.moves.get() - 1);
            let current = self.tx.read_ref(map).unwrap().unwrap();
            let moved = kit_core::hash::hash(&self.calls.get().to_le_bytes());
            self.tx
                .update_ref(map, RefWriteCondition::Match(current), &moved)
                .unwrap();
        }
        let head_now = self.tx.read_ref(head).unwrap();
        let map_now = self.tx.read_ref(map).unwrap();
        if map_now.as_ref() != map_expected {
            return Ok(AdvanceOutcome::PackmapConflict);
        }
        if head_now.as_ref() != Some(head_expected) {
            return Ok(AdvanceOutcome::HeadConflict);
        }
        self.inner
            .delete_refs(head, head_expected, map, map_expected)
    }
}

const MAIN: &str = "refs/heads/main";
const MAIN_MAP: &str = "refs/kit/packmap/main";
const V1: &str = "refs/tags/v1";
const V1_MAP: &str = "refs/kit/tagmap/v1";

/// A local repository with `main` pushed, and a remote that holds it.
fn pushed_main(tx: &dyn Transport) -> (Work, Hash) {
    let work = Work::new();
    let tip = work.commit(None);
    work.branch("main", tip);
    work.push_branch(&TransportSource::new(tx), "main");
    (work, tip)
}

fn node(tx: &dyn Transport, key: Hash) -> transfer::PackListNode {
    let bytes = tx
        .download_blob(&PackKey::from_hash(key), None, u64::MAX)
        .unwrap();
    transfer::decode_packlist(&bytes).unwrap()
}

/// A branch goes with its packmap and its tracking ref.
#[test]
fn a_branch_goes_with_its_packmap_and_tracking_ref() {
    for kind in KINDS {
        let (tx, _dir) = transport(kind);
        let (work, tip) = pushed_main(tx.as_ref());
        assert!(tx.read_ref(MAIN_MAP).unwrap().is_some());
        let deleted = work
            .delete(
                &TransportSource::new(tx.as_ref()),
                DeleteTarget::Branch("main".into()),
            )
            .unwrap();
        assert_eq!(deleted.name, MAIN, "{kind:?}");
        assert_eq!(deleted.value, Some(tip));
        assert_eq!(tx.read_ref(MAIN).unwrap(), None, "{kind:?}");
        assert_eq!(tx.read_ref(MAIN_MAP).unwrap(), None, "{kind:?}");
        assert_eq!(work.tracking("main"), None, "{kind:?}");
        // The local branch stays.
        assert_eq!(refs::read_ref(&work.layout, "main").unwrap(), Some(tip));
    }
}

/// A delete under a stale lease is a conflict and deletes nothing: the
/// remote branch moved since the tracking ref was written.
#[test]
fn a_stale_lease_deletes_nothing() {
    for kind in KINDS {
        let (tx, _dir) = transport(kind);
        let (work, tip) = pushed_main(tx.as_ref());
        // Another clone moves `main` on.
        let other = Work::new();
        let ahead = other.commit(None);
        other.branch("main", ahead);
        other
            .run(
                &TransportSource::new(tx.as_ref()),
                PushTarget::Branch {
                    local: "main".into(),
                    remote: "main".into(),
                    lease: PushLease::Force,
                },
            )
            .unwrap();
        let (head, map) = (tx.read_ref(MAIN).unwrap(), tx.read_ref(MAIN_MAP).unwrap());
        assert_eq!(head, Some(ahead));
        let error = work
            .delete(
                &TransportSource::new(tx.as_ref()),
                DeleteTarget::Branch("main".into()),
            )
            .unwrap_err();
        assert!(
            matches!(&error, PushError::Delete(DeleteError::Stale(name)) if name == MAIN),
            "{kind:?}: {error}"
        );
        assert_eq!(tx.read_ref(MAIN).unwrap(), head, "{kind:?}");
        assert_eq!(tx.read_ref(MAIN_MAP).unwrap(), map, "{kind:?}");
        assert_eq!(work.tracking("main"), Some(tip), "the tracking ref stays");
    }
}

/// A branch with no tracking ref has no lease, and nothing is deleted.
#[test]
fn a_branch_without_a_tracking_ref_is_refused() {
    let (tx, _dir) = transport(Kind::Memory);
    let (_work, tip) = pushed_main(tx.as_ref());
    let stranger = Work::new();
    let error = stranger
        .delete(
            &TransportSource::new(tx.as_ref()),
            DeleteTarget::Branch("main".into()),
        )
        .unwrap_err();
    assert!(
        matches!(&error, PushError::Delete(DeleteError::NoLease { branch, .. }) if branch == "main"),
        "{error}"
    );
    assert_eq!(tx.read_ref(MAIN).unwrap(), Some(tip));
}

/// A tag goes with its tag map. The local tag stays.
#[test]
fn a_tag_goes_with_its_tag_map() {
    for kind in KINDS {
        let (tx, _dir) = transport(kind);
        let (work, tip) = pushed_main(tx.as_ref());
        let tag = work.tag("v1", tip);
        let source = TransportSource::new(tx.as_ref());
        assert!(matches!(
            work.push_tag(&source, "v1"),
            TagPushOutcome::Created { .. }
        ));
        assert!(tx.read_ref(V1_MAP).unwrap().is_some());
        let deleted = work
            .delete(&source, DeleteTarget::Tag("v1".into()))
            .unwrap();
        assert_eq!((deleted.name.as_str(), deleted.value), (V1, Some(tag)));
        assert_eq!(tx.read_ref(V1).unwrap(), None, "{kind:?}");
        assert_eq!(tx.read_ref(V1_MAP).unwrap(), None, "{kind:?}");
        assert_eq!(refs::read_tag(&work.layout, "v1").unwrap(), Some(tag));
        // The branch and its packmap are untouched.
        assert_eq!(tx.read_ref(MAIN).unwrap(), Some(tip));
        assert!(tx.read_ref(MAIN_MAP).unwrap().is_some());
    }
}

/// A tag moved between the read and the delete is not deleted: the `Match`
/// holds the value just read.
#[test]
fn a_tag_moved_in_between_is_not_deleted() {
    for kind in KINDS {
        let (tx, _dir) = transport(kind);
        let (work, tip) = pushed_main(tx.as_ref());
        let tag = work.tag("v1", tip);
        work.push_tag(&TransportSource::new(tx.as_ref()), "v1");
        let faulty = Faulty::new(tx.as_ref());
        let moved = [7u8; 32];
        faulty.before_delete(move |name, inner| {
            if name == V1 {
                inner
                    .update_ref(V1, RefWriteCondition::Match(tag), &moved)
                    .unwrap();
            }
        });
        let map = tx.read_ref(V1_MAP).unwrap();
        let error = work
            .delete(
                &TransportSource::new(&faulty),
                DeleteTarget::Tag("v1".into()),
            )
            .unwrap_err();
        assert!(
            matches!(&error, PushError::Delete(DeleteError::Stale(name)) if name == V1),
            "{kind:?}: {error}"
        );
        assert_eq!(tx.read_ref(V1).unwrap(), Some(moved), "{kind:?}");
        assert_eq!(tx.read_ref(V1_MAP).unwrap(), map, "the tag map stays");
    }
}

/// A crash between the head delete and the chain ref delete leaves the chain
/// ref. The delete reports success, since the head is gone, and the next push
/// of that branch appends to the chain ref it left.
#[test]
fn a_crash_between_the_deletes_leaves_a_packmap_the_next_push_appends_to() {
    for kind in KINDS {
        let (tx, _dir) = transport(kind);
        let (work, tip) = pushed_main(tx.as_ref());
        let leftover = tx.read_ref(MAIN_MAP).unwrap().unwrap();
        let faulty = Faulty::new(tx.as_ref());
        faulty.crash_on(MAIN_MAP);
        let deleted = work
            .delete(
                &TransportSource::new(&faulty),
                DeleteTarget::Branch("main".into()),
            )
            .unwrap();
        assert_eq!(deleted.value, Some(tip));
        assert_eq!(tx.read_ref(MAIN).unwrap(), None, "{kind:?}");
        assert_eq!(tx.read_ref(MAIN_MAP).unwrap(), Some(leftover), "{kind:?}");
        assert_eq!(work.tracking("main"), None);
        // A clone reads the leftover as a stale listing.
        let (_clone, report) = clone_of(&TransportSource::new(tx.as_ref()));
        assert_eq!(report.branches_fetched, 0, "{kind:?}");
        // The next push creates the head and appends to the leftover.
        let next = work.commit(Some(tip));
        work.branch("main", next);
        work.push_branch(&TransportSource::new(tx.as_ref()), "main");
        assert_eq!(tx.read_ref(MAIN).unwrap(), Some(next), "{kind:?}");
        let map = tx.read_ref(MAIN_MAP).unwrap().unwrap();
        assert_eq!(node(tx.as_ref(), map).prev, Some(leftover), "{kind:?}");
        let (_clone, report) = clone_of(&TransportSource::new(tx.as_ref()));
        assert_eq!(report.branches_fetched, 1, "{kind:?}");
    }
}

/// A push that moves the tag map between the two deletes makes the
/// chain-ref delete lose its CAS. The delete still reports success, and the
/// next push of that tag appends to the tag map it left.
#[test]
fn a_lost_cas_on_the_tag_map_still_deletes_the_tag() {
    for kind in KINDS {
        let (tx, _dir) = transport(kind);
        let (work, tip) = pushed_main(tx.as_ref());
        let tag = work.tag("v1", tip);
        work.push_tag(&TransportSource::new(tx.as_ref()), "v1");
        // Another writer points the tag map at a real node: the branch's.
        let moved = tx.read_ref(MAIN_MAP).unwrap().unwrap();
        let faulty = Faulty::new(tx.as_ref());
        faulty.before_delete(move |name, inner| {
            if name == V1_MAP {
                let current = inner.read_ref(V1_MAP).unwrap().unwrap();
                inner
                    .update_ref(V1_MAP, RefWriteCondition::Match(current), &moved)
                    .unwrap();
            }
        });
        let deleted = work
            .delete(
                &TransportSource::new(&faulty),
                DeleteTarget::Tag("v1".into()),
            )
            .unwrap();
        assert_eq!(deleted.value, Some(tag));
        assert_eq!(tx.read_ref(V1).unwrap(), None, "{kind:?}");
        assert_eq!(tx.read_ref(V1_MAP).unwrap(), Some(moved), "{kind:?}");
        let source = TransportSource::new(tx.as_ref());
        assert!(matches!(
            work.push_tag(&source, "v1"),
            TagPushOutcome::Created { .. }
        ));
        let map = tx.read_ref(V1_MAP).unwrap().unwrap();
        assert_eq!(node(tx.as_ref(), map).prev, Some(moved), "{kind:?}");
        let (_clone, report) = clone_of(&source);
        assert_eq!(report.tags_fetched, ["v1"], "{kind:?}");
    }
}

/// A crash after the tag delete leaves the tag map. The next push of the tag
/// takes the leftover row: it appends to that tag map, and a clone gets the
/// tag.
#[test]
fn a_leftover_tag_map_is_appended_to_by_the_next_tag_push() {
    for kind in KINDS {
        let (tx, _dir) = transport(kind);
        let (work, tip) = pushed_main(tx.as_ref());
        let tag = work.tag("v1", tip);
        work.push_tag(&TransportSource::new(tx.as_ref()), "v1");
        let leftover = tx.read_ref(V1_MAP).unwrap().unwrap();
        let faulty = Faulty::new(tx.as_ref());
        faulty.crash_on(V1_MAP);
        work.delete(
            &TransportSource::new(&faulty),
            DeleteTarget::Tag("v1".into()),
        )
        .unwrap();
        assert_eq!(tx.read_ref(V1).unwrap(), None, "{kind:?}");
        assert_eq!(tx.read_ref(V1_MAP).unwrap(), Some(leftover), "{kind:?}");
        let source = TransportSource::new(tx.as_ref());
        assert!(matches!(
            work.push_tag(&source, "v1"),
            TagPushOutcome::Created { .. }
        ));
        assert_eq!(tx.read_ref(V1).unwrap(), Some(tag), "{kind:?}");
        let map = tx.read_ref(V1_MAP).unwrap().unwrap();
        assert_eq!(node(tx.as_ref(), map).prev, Some(leftover), "{kind:?}");
        let (_clone, report) = clone_of(&source);
        assert_eq!(report.tags_fetched, ["v1"], "{kind:?}");
    }
}

/// A transaction that loses on a moved chain ref deletes nothing; the chain
/// ref is read again and the delete retried, within a bound.
#[test]
fn an_atomic_delete_retries_a_moved_chain_ref_within_a_bound() {
    let (tx, _dir) = transport(Kind::Memory);
    let (work, tip) = pushed_main(tx.as_ref());
    let atomic = Atomic {
        inner: TransportSource::new(tx.as_ref()),
        tx: tx.as_ref(),
        moves: Cell::new(2),
        calls: Cell::new(0),
    };
    let deleted = work
        .delete(&atomic, DeleteTarget::Branch("main".into()))
        .unwrap();
    assert_eq!(deleted.value, Some(tip));
    assert_eq!(atomic.calls.get(), 3);
    assert_eq!(tx.read_ref(MAIN).unwrap(), None);
    assert_eq!(tx.read_ref(MAIN_MAP).unwrap(), None);

    let (tx, _dir) = transport(Kind::Memory);
    let (work, tip) = pushed_main(tx.as_ref());
    let atomic = Atomic {
        inner: TransportSource::new(tx.as_ref()),
        tx: tx.as_ref(),
        moves: Cell::new(usize::MAX),
        calls: Cell::new(0),
    };
    let error = work
        .delete(&atomic, DeleteTarget::Branch("main".into()))
        .unwrap_err();
    assert!(
        matches!(&error, PushError::Delete(DeleteError::Contended(name)) if name == MAIN),
        "{error}"
    );
    assert_eq!(atomic.calls.get(), 8);
    assert_eq!(tx.read_ref(MAIN).unwrap(), Some(tip), "nothing was deleted");
    assert_eq!(work.tracking("main"), Some(tip));
}

/// A transport that refuses every delete, as s3 does, leaves both refs and
/// the tracking ref, and its refusal is what the caller sees.
#[test]
fn a_refused_delete_leaves_both_refs_and_says_why() {
    struct Refusing<'a>(Faulty<'a>);
    impl Transport for Refusing<'_> {
        fn upload_pack(
            &self,
            p: &dyn PackBody,
            k: &PackKey,
            h: Option<&str>,
        ) -> TransportResult<()> {
            self.0.upload_pack(p, k, h)
        }
        fn download_pack(
            &self,
            k: &PackKey,
            h: Option<&str>,
            s: &mut dyn PackSink,
        ) -> TransportResult<()> {
            self.0.download_pack(k, h, s)
        }
        fn pack_exists(&self, k: &PackKey, h: Option<&str>) -> TransportResult<bool> {
            self.0.pack_exists(k, h)
        }
        fn update_ref(&self, n: &str, c: RefWriteCondition, v: &Hash) -> TransportResult<()> {
            self.0.update_ref(n, c, v)
        }
        fn delete_ref(&self, _: &str, _: &Hash) -> TransportResult<()> {
            Err(TransportError::Unsupported(
                "the s3 transport cannot delete a ref conditionally",
            ))
        }
        fn read_ref(&self, n: &str) -> TransportResult<Option<Hash>> {
            self.0.read_ref(n)
        }
        fn list_refs(&self, p: &str) -> TransportResult<Vec<Ref>> {
            self.0.list_refs(p)
        }
    }
    let (tx, _dir) = transport(Kind::Memory);
    let (work, tip) = pushed_main(tx.as_ref());
    let map = tx.read_ref(MAIN_MAP).unwrap();
    let refusing = Refusing(Faulty::new(tx.as_ref()));
    let error = work
        .delete(
            &TransportSource::new(&refusing),
            DeleteTarget::Branch("main".into()),
        )
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "deleting `refs/heads/main` failed: the s3 transport cannot delete a ref conditionally"
    );
    assert_eq!(tx.read_ref(MAIN).unwrap(), Some(tip));
    assert_eq!(tx.read_ref(MAIN_MAP).unwrap(), map);
    assert_eq!(work.tracking("main"), Some(tip));
}

/// A short name is the remote's branch or tag of that name. A name it holds
/// as both is refused; a name it holds as neither is refused unless a
/// tracking ref names it, which then goes.
#[test]
fn a_short_name_resolves_on_the_remote() {
    let (tx, _dir) = transport(Kind::Memory);
    let source = TransportSource::new(tx.as_ref());
    let (work, tip) = pushed_main(tx.as_ref());
    work.tag("main", tip);
    work.tag("v1", tip);
    work.push_tag(&source, "main");
    work.push_tag(&source, "v1");

    let error = work
        .delete(&source, DeleteTarget::Name("main".into()))
        .unwrap_err();
    assert!(
        matches!(&error, PushError::Delete(DeleteError::Ambiguous(name)) if name == "main"),
        "{error}"
    );
    assert_eq!(tx.read_ref(MAIN).unwrap(), Some(tip));

    let deleted = work
        .delete(&source, DeleteTarget::Name("v1".into()))
        .unwrap();
    assert_eq!(deleted.name, V1);
    let deleted = work
        .delete(&source, DeleteTarget::Tag("main".into()))
        .unwrap();
    assert_eq!(deleted.name, "refs/tags/main");
    let deleted = work
        .delete(&source, DeleteTarget::Name("main".into()))
        .unwrap();
    assert_eq!((deleted.name.as_str(), deleted.value), (MAIN, Some(tip)));
    assert_eq!(work.tracking("main"), None);

    let error = work
        .delete(&source, DeleteTarget::Name("gone".into()))
        .unwrap_err();
    assert!(
        matches!(&error, PushError::Delete(DeleteError::NotOnRemote(_))),
        "{error}"
    );
    let error = work
        .delete(&source, DeleteTarget::Tag("v1".into()))
        .unwrap_err();
    assert!(
        matches!(&error, PushError::Delete(DeleteError::NotOnRemote(name)) if name == V1),
        "{error}"
    );
}

/// A branch someone else already deleted is gone, as asked: the delete
/// reports it with no value and drops the stale tracking ref.
#[test]
fn a_branch_already_gone_clears_its_tracking_ref() {
    for kind in KINDS {
        let (tx, _dir) = transport(kind);
        let (work, tip) = pushed_main(tx.as_ref());
        let map = tx.read_ref(MAIN_MAP).unwrap().unwrap();
        tx.delete_refs(MAIN, &tip, MAIN_MAP, Some(&map)).unwrap();
        for target in [
            DeleteTarget::Branch("main".into()),
            DeleteTarget::Name("main".into()),
        ] {
            work.branch("main", tip);
            refs::write_remote_ref(&work.layout, REMOTE, "main", &tip).unwrap();
            let deleted = work
                .delete(&TransportSource::new(tx.as_ref()), target)
                .unwrap();
            assert_eq!(
                (deleted.name.as_str(), deleted.value),
                (MAIN, None),
                "{kind:?}"
            );
            assert_eq!(work.tracking("main"), None, "{kind:?}");
        }
    }
}

/// A tag whose tag map name is no valid ref has no tag map, and is deleted
/// alone.
#[test]
fn a_tag_too_long_for_a_tag_map_is_deleted_alone() {
    let (tx, _dir) = transport(Kind::Memory);
    let (work, tip) = pushed_main(tx.as_ref());
    let long = "t".repeat(kit_core::refs::MAX_TAG_NAME_BYTES + 1);
    let name = format!("refs/tags/{long}");
    tx.update_ref(&name, RefWriteCondition::Missing, &tip)
        .unwrap();
    let faulty = Faulty::new(tx.as_ref());
    let deleted = work
        .delete(&TransportSource::new(&faulty), DeleteTarget::Tag(long))
        .unwrap();
    assert_eq!(deleted.value, Some(tip));
    assert_eq!(*faulty.deleted.lock().unwrap(), [name.as_str()]);
    assert_eq!(tx.read_ref(&name).unwrap(), None);
}

/// Clone the remote into a new directory.
fn clone_of(source: &dyn RemoteSource) -> (tempfile::TempDir, kit_sync::FetchReport) {
    let dir = tempfile::tempdir().unwrap();
    let report = clone(
        &dir.path().join("clone"),
        source,
        &remote_config(),
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap()
    .pull
    .fetch;
    (dir, report)
}
