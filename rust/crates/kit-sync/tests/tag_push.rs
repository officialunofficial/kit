//! `kit push --tags` and `kit push <remote> <tag>` (SPEC-TRANSPORT §7.2).
//!
//! Each test pushes from a local repository to a memory or file remote
//! through a [`Wire`], which records every upload and can step into an
//! advance between its tag map write and its tag write, then clones the
//! remote elsewhere to check what a reader gets.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::cell::{Cell, RefCell};
use std::collections::{BTreeSet, HashSet};
use std::io::Read as _;
use std::path::PathBuf;

use kit_core::hash::Hash;
use kit_core::layout::RepoLayout;
use kit_core::object::{
    Blob, Commit, EntryMode, Identity, Object, ObjectType, Tag, Tree, TreeEntry,
};
use kit_core::ops::graph::reachable_objects;
use kit_core::pack::PackReader;
use kit_core::protocol::{
    CommitOutcome, PackBody, PackKey, PackSink, RefListing, Transport, UploadLimits,
};
use kit_core::refs::{self, Ref, RefWriteCondition};
use kit_core::sign::{self, KeyPair};
use kit_core::store::ObjectStore;
use kit_core::transfer;
use kit_sync::push::{
    MAX_TAG_LISTING_BYTES, PushLease, PushOptions, PushTarget, TagPushOutcome, TagPushRejection,
    TagPushResult, TagSelection,
};
use kit_sync::{
    CloneRemote, FetchReport, NoopObserver, RemoteSource, SourceError, SyncOptions,
    TransportSource, clone, init_clone_dir,
};
use kit_transport_file::FileTransport;
use kit_transport_memory::MemoryTransport;

#[derive(Clone, Copy, Debug)]
enum Kind {
    Memory,
    File,
}

const KINDS: [Kind; 2] = [Kind::Memory, Kind::File];

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
        name: "default".to_owned(),
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

    fn next(&self) -> u64 {
        self.seq.set(self.seq.get() + 1);
        self.seq.get()
    }

    fn write(&self, object: &Object) -> Hash {
        self.store
            .write(&kit_core::serialize::serialize(object).unwrap())
            .unwrap()
    }

    /// A signed commit on `parent` whose tree holds `parent`'s files and one
    /// new file.
    fn commit(&self, parent: Option<Hash>) -> Hash {
        let n = self.next();
        let mut entries = match parent {
            Some(parent) => {
                let Object::Commit(parent) = self.store.read_object(&parent).unwrap() else {
                    panic!("a commit")
                };
                let Object::Tree(tree) = self.store.read_object(&parent.tree_hash).unwrap() else {
                    panic!("a tree")
                };
                tree.entries
            }
            None => Vec::new(),
        };
        entries.push(TreeEntry {
            name: format!("f{n:04}").into_bytes(),
            mode: EntryMode::Blob,
            object_hash: self.write(&Object::Blob(Blob {
                data: format!("content of file {n}\n").into_bytes(),
            })),
        });
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        let tree = self.write(&Object::Tree(Tree { entries }));
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

    /// `count` commits on `parent`, oldest first.
    fn commits(&self, parent: Option<Hash>, count: usize) -> Vec<Hash> {
        let mut out = Vec::new();
        let mut parent = parent;
        for _ in 0..count {
            let c = self.commit(parent);
            out.push(c);
            parent = Some(c);
        }
        out
    }

    /// An annotated tag object named `name` on `target`.
    fn tag_object(&self, name: &str, target: Hash, signed: bool) -> Hash {
        let mut tag = Tag {
            target,
            target_type: self.store.object_type(&target).unwrap(),
            name: name.as_bytes().to_vec(),
            tagger: Identity::ed25519(self.key.public.0),
            signer: self.key.public.0,
            message: format!("release {name}").into_bytes(),
            timestamp: 1_700_000_000 + self.next(),
            signature: [0u8; 64],
        };
        if signed {
            tag.signature = sign::sign_tag(&tag, &self.key).unwrap().0;
        }
        self.write(&Object::Tag(tag))
    }

    /// A signed annotated tag `name` on `target`, as a local tag.
    fn tag(&self, name: &str, target: Hash) -> Hash {
        let id = self.tag_object(name, target, true);
        refs::write_tag(&self.layout, name, &id).unwrap();
        id
    }

    fn light(&self, name: &str, target: Hash) {
        refs::write_tag(&self.layout, name, &target).unwrap();
    }

    fn branch(&self, name: &str, tip: Hash) {
        refs::write_ref(&self.layout, name, &tip).unwrap();
    }

    fn push(&self, source: &dyn RemoteSource, target: PushTarget) -> Vec<TagPushResult> {
        let mut options = PushOptions::default();
        options.target = target;
        kit_sync::push(&self.path, source, &options).unwrap().tags
    }

    fn push_branch(&self, source: &dyn RemoteSource, branch: &str) {
        self.push(
            source,
            PushTarget::Branch {
                local: branch.to_owned(),
                remote: branch.to_owned(),
                lease: PushLease::Force,
            },
        );
    }

    fn push_tags(&self, source: &dyn RemoteSource, force: bool) -> Vec<TagPushResult> {
        self.push(
            source,
            PushTarget::Tags {
                selection: TagSelection::All,
                force,
            },
        )
    }

    fn push_tag(&self, source: &dyn RemoteSource, name: &str, force: bool) -> Vec<TagPushResult> {
        self.push(
            source,
            PushTarget::Tags {
                selection: TagSelection::Named(vec![name.to_owned()]),
                force,
            },
        )
    }

    /// The closure of `roots` in this store.
    fn closure(&self, roots: &[Hash]) -> HashSet<Hash> {
        let mut out = HashSet::new();
        for root in roots {
            out.extend(reachable_objects(&self.store, root).unwrap());
        }
        out
    }
}

type AdvanceHook<'a> = dyn FnMut(&str) -> Option<Result<CommitOutcome, SourceError>> + 'a;
type BetweenHook<'a> = dyn FnMut(&str) -> Result<(), SourceError> + 'a;
type ReadHook<'a> = dyn FnMut(&str) + 'a;

/// The refusal of a grant whose scopes do not match the ref.
fn denied() -> SourceError {
    SourceError::Remote(Box::new(kit_sync::RemoteFailure {
        code: "permission_denied".to_owned(),
        message: "the grant does not cover this ref".to_owned(),
        details: Vec::new(),
        status: 403,
        headers: Vec::new(),
    }))
}

/// A source over a transport that records what a push sends. Its advance
/// writes the chain ref, then the head, as an ordered transport does, and
/// can step in between.
struct Wire<'a> {
    inner: TransportSource<'a>,
    tx: &'a dyn Transport,
    /// Each uploaded pack: the head ref it was sent for and its bytes.
    packs: RefCell<Vec<(String, Vec<u8>)>>,
    /// Each uploaded node: the head ref and the node's key.
    nodes: RefCell<Vec<(String, Hash)>>,
    listing: Cell<RefListing>,
    limits: Cell<UploadLimits>,
    inspect: Cell<Option<u64>>,
    /// Extra names a listing of `refs/tags/` shows.
    padding: RefCell<Vec<Ref>>,
    /// Runs before an advance reaches the transport; an answer replaces it.
    before: RefCell<Option<Box<AdvanceHook<'a>>>>,
    /// Runs between the chain ref write and the head write of an advance;
    /// an error ends the advance there, as a crash would.
    between: RefCell<Option<Box<BetweenHook<'a>>>>,
    /// Runs before each ref read.
    on_read: RefCell<Option<Box<ReadHook<'a>>>>,
    /// Head refs whose uploads are refused, as a grant that does not cover
    /// them refuses them.
    refused: RefCell<HashSet<String>>,
}

impl<'a> Wire<'a> {
    fn new(tx: &'a dyn Transport) -> Self {
        Self {
            inner: TransportSource::new(tx),
            tx,
            packs: RefCell::default(),
            nodes: RefCell::default(),
            listing: Cell::new(tx.ref_listing()),
            limits: Cell::new(tx.upload_limits()),
            inspect: Cell::new(None),
            padding: RefCell::default(),
            before: RefCell::default(),
            between: RefCell::default(),
            on_read: RefCell::default(),
            refused: RefCell::default(),
        }
    }

    /// The objects of every pack uploaded since the last call, one per entry.
    fn take_objects(&self) -> Vec<Hash> {
        let mut out = Vec::new();
        for (_, bytes) in self.packs.borrow_mut().drain(..) {
            let dir = tempfile::tempdir().unwrap();
            let layout = RepoLayout::single(dir.path());
            let store = ObjectStore::init(&layout).unwrap();
            out.extend(PackReader::read(&bytes, &store).unwrap().stored);
        }
        self.nodes.borrow_mut().clear();
        out
    }

    fn uploaded_for(&self) -> Vec<String> {
        self.packs.borrow().iter().map(|(r, _)| r.clone()).collect()
    }

    fn read(&self, name: &str) -> Option<Hash> {
        self.tx.read_ref(name).unwrap()
    }

    /// The node `key` on the remote.
    fn node(&self, key: Hash) -> transfer::PackListNode {
        let bytes = self
            .tx
            .download_blob(&PackKey::from_hash(key), None, u64::MAX)
            .unwrap();
        transfer::decode_packlist(&bytes).unwrap()
    }
}

impl RemoteSource for Wire<'_> {
    fn list_branches(&self) -> Result<Vec<Ref>, SourceError> {
        self.inner.list_branches()
    }
    fn list_refs(&self, prefix: &str) -> Result<Vec<Ref>, SourceError> {
        let mut listed = self.inner.list_refs(prefix)?;
        if prefix == "refs/tags/" {
            listed.extend(self.padding.borrow().iter().cloned());
        }
        Ok(listed)
    }
    fn read_ref(&self, name: &str) -> Result<Option<Hash>, SourceError> {
        if let Some(hook) = self.on_read.borrow_mut().as_mut() {
            hook(name);
        }
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
    fn upload_pack(
        &self,
        pack: &dyn PackBody,
        key: &PackKey,
        head_ref: &str,
    ) -> Result<(), SourceError> {
        if self.refused.borrow().contains(head_ref) {
            return Err(denied());
        }
        let mut bytes = Vec::new();
        pack.read_from(0).unwrap().read_to_end(&mut bytes).unwrap();
        self.packs.borrow_mut().push((head_ref.to_owned(), bytes));
        self.inner.upload_pack(pack, key, head_ref)
    }
    fn upload_blob(&self, bytes: &[u8], key: &PackKey, head_ref: &str) -> Result<(), SourceError> {
        self.nodes
            .borrow_mut()
            .push((head_ref.to_owned(), key.into_hash()));
        self.inner.upload_blob(bytes, key, head_ref)
    }
    fn update_ref(
        &self,
        name: &str,
        condition: RefWriteCondition,
        tip: &Hash,
    ) -> Result<(), SourceError> {
        if self.refused.borrow().contains(name) {
            return Err(denied());
        }
        self.inner.update_ref(name, condition, tip)
    }
    fn advance_refs_committing(
        &self,
        head: &str,
        head_condition: RefWriteCondition,
        tip: &Hash,
        map: &str,
        map_condition: RefWriteCondition,
        node: &Hash,
        keys: &[PackKey],
    ) -> Result<CommitOutcome, SourceError> {
        if let Some(hook) = self.before.borrow_mut().as_mut()
            && let Some(answer) = hook(head)
        {
            return answer;
        }
        if head.starts_with("refs/heads/") {
            return self.inner.advance_refs_committing(
                head,
                head_condition,
                tip,
                map,
                map_condition,
                node,
                keys,
            );
        }
        match self.inner.update_ref(map, map_condition, node) {
            Ok(()) => {}
            Err(SourceError::RefConflict) => {
                return Ok(CommitOutcome::Advanced(
                    kit_core::protocol::AdvanceOutcome::PackmapConflict,
                ));
            }
            Err(e) => return Err(e),
        }
        if let Some(hook) = self.between.borrow_mut().as_mut() {
            hook(head)?;
        }
        match self.inner.update_ref(head, head_condition, tip) {
            Ok(()) => Ok(CommitOutcome::Advanced(
                kit_core::protocol::AdvanceOutcome::Committed,
            )),
            Err(SourceError::RefConflict) => Ok(CommitOutcome::Advanced(
                kit_core::protocol::AdvanceOutcome::HeadConflict,
            )),
            Err(e) => Err(e),
        }
    }
    fn upload_limits(&self) -> UploadLimits {
        self.limits.get()
    }
    fn inspection_max_objects(&self) -> Option<u64> {
        self.inspect.get()
    }
    fn ref_listing(&self) -> RefListing {
        self.listing.get()
    }
}

/// Clone the remote into a new directory and return the fetch report and
/// the clone's store.
fn clone_of(source: &dyn RemoteSource) -> (tempfile::TempDir, FetchReport, ObjectStore) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("clone");
    let report = clone(
        &path,
        source,
        &remote_config(),
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap()
    .pull
    .fetch;
    let store = ObjectStore::open(&RepoLayout::single(&path)).unwrap();
    (dir, report, store)
}

fn outcome<'r>(results: &'r [TagPushResult], name: &str) -> &'r TagPushOutcome {
    &results
        .iter()
        .find(|r| r.name == name)
        .unwrap_or_else(|| panic!("no result for {name}: {results:?}"))
        .outcome
}

fn rejection<'r>(results: &'r [TagPushResult], name: &str) -> &'r TagPushRejection {
    match outcome(results, name) {
        TagPushOutcome::Rejected(rejection) => rejection,
        other => panic!("{name} was not refused: {other:?}"),
    }
}

fn assert_created(results: &[TagPushResult], name: &str) {
    assert!(
        matches!(outcome(results, name), TagPushOutcome::Created { .. }),
        "{name}: {results:?}"
    );
}

#[test]
fn a_signed_tag_pushed_and_cloned_elsewhere_verifies_byte_for_byte() {
    for kind in KINDS {
        let (tx, _root) = transport(kind);
        let wire = Wire::new(&*tx);
        let work = Work::new();
        let c1 = work.commit(None);
        work.branch("main", c1);
        work.push_branch(&wire, "main");
        let v1 = work.tag("v1", c1);
        work.light("light", c1);

        let results = work.push_tags(&wire, false);
        assert_created(&results, "v1");
        assert_created(&results, "light");

        let (_dir, report, store) = clone_of(&wire);
        assert_eq!(report.tags_fetched, ["light", "v1"], "{kind:?}");
        assert!(
            report.tags_rejected.is_empty(),
            "{:?}",
            report.tags_rejected
        );
        assert_eq!(store.read(&v1).unwrap(), work.store.read(&v1).unwrap());
        sign::verify_object_signature(&store.read_object(&v1).unwrap()).unwrap();
    }
}

/// A tag on a pushed commit sends one pack of one object, its node grafts
/// on the branch's node, and a lightweight tag sends nothing: its tag map is
/// the branch's packmap.
#[test]
fn a_tag_on_a_pushed_commit_sends_only_its_tag_object() {
    for kind in KINDS {
        let (tx, _root) = transport(kind);
        let wire = Wire::new(&*tx);
        let work = Work::new();
        let c2 = *work.commits(None, 2).last().unwrap();
        work.branch("main", c2);
        work.push_branch(&wire, "main");
        wire.take_objects();
        let packmap = wire.read("refs/kit/packmap/main").unwrap();
        let v1 = work.tag("v1", c2);

        work.push_tags(&wire, false);
        assert_eq!(wire.take_objects(), [v1], "{kind:?}");
        let map = wire.read("refs/kit/tagmap/v1").unwrap();
        assert_eq!(wire.node(map).prev, Some(packmap));

        work.light("light", c2);
        let results = work.push_tag(&wire, "light", false);
        assert_created(&results, "light");
        assert!(wire.take_objects().is_empty());
        assert_eq!(wire.read("refs/kit/tagmap/light"), Some(packmap));
        assert_eq!(wire.read("refs/tags/light"), Some(c2));

        let (_dir, report, _) = clone_of(&wire);
        assert_eq!(report.tags_fetched, ["light", "v1"], "{kind:?}");
    }
}

/// A tag on the history of a pushed branch, below its tip, grafts on that
/// branch: an annotated one sends its tag object, a lightweight one nothing.
#[test]
fn a_tag_below_a_pushed_tip_sends_only_its_tag_object() {
    for kind in KINDS {
        let (tx, _root) = transport(kind);
        let wire = Wire::new(&*tx);
        let work = Work::new();
        let c = work.commits(None, 4);
        let fork = work.commits(Some(c[1]), 1);
        work.branch("main", c[3]);
        work.push_branch(&wire, "main");
        wire.take_objects();
        let packmap = wire.read("refs/kit/packmap/main").unwrap();
        let v1 = work.tag("v1", c[1]);
        work.light("old", c[0]);

        let results = work.push_tags(&wire, false);
        assert_created(&results, "v1");
        assert_created(&results, "old");
        assert_eq!(wire.take_objects(), [v1], "{kind:?}");
        assert_eq!(
            wire.node(wire.read("refs/kit/tagmap/v1").unwrap()).prev,
            Some(packmap)
        );
        // One group, one node.
        assert_eq!(
            wire.read("refs/kit/tagmap/old"),
            wire.read("refs/kit/tagmap/v1")
        );

        // A tag on a fork of that history sends the fork and grafts too.
        work.light("fork", fork[0]);
        assert_created(&work.push_tag(&wire, "fork", false), "fork");
        let sent: HashSet<Hash> = wire.take_objects().into_iter().collect();
        assert!(sent.contains(&fork[0]) && !sent.contains(&c[1]), "{kind:?}");
        assert_eq!(
            wire.node(wire.read("refs/kit/tagmap/fork").unwrap()).prev,
            Some(packmap)
        );
        let (_dir, report, _) = clone_of(&wire);
        assert_eq!(report.tags_fetched, ["fork", "old", "v1"], "{kind:?}");
    }
}

/// Ticketed Connect: a tag whose upload or advance the caller's grant does
/// not cover is refused alone; the group goes under the next tag.
#[test]
fn a_tag_outside_the_grant_is_refused_alone() {
    let (tx, _root) = transport(Kind::Memory);
    let wire = Wire::new(&*tx);
    let work = Work::new();
    let c = work.commits(None, 2);
    work.branch("main", c[0]);
    work.push_branch(&wire, "main");
    wire.take_objects();
    for t in ["a", "b", "v1"] {
        work.tag(t, c[1]);
    }
    wire.limits.set(UploadLimits {
        max_pack_bytes: None,
        data_packs_per_advance: Some(6),
        ticket_threshold_bytes: Some(0),
    });
    wire.refused.borrow_mut().insert("refs/tags/a".to_owned());
    *wire.before.borrow_mut() = Some(Box::new(|head: &str| {
        (head == "refs/tags/b").then(|| Err(denied()))
    }));

    let results = work.push_tags(&wire, false);

    for t in ["a", "b"] {
        assert!(
            matches!(rejection(&results, t), TagPushRejection::Refused(_)),
            "{t}: {results:?}"
        );
    }
    assert_created(&results, "v1");
    assert_eq!(wire.uploaded_for(), ["refs/tags/b", "refs/tags/v1"]);
    assert_eq!(wire.read("refs/tags/a"), None);
    assert_eq!(wire.read("refs/tags/b"), None);
}

/// Ticketed Connect: when another push already placed the ticket-carrying
/// tag at the same value, this group's packs are not members, so the next
/// tag uploads them again under its own ticket.
#[test]
fn a_ticketed_tag_another_push_placed_does_not_land_the_group() {
    let (tx, _root) = transport(Kind::Memory);
    let wire = Wire::new(&*tx);
    let work = Work::new();
    let c = work.commits(None, 2);
    work.branch("main", c[0]);
    work.push_branch(&wire, "main");
    wire.take_objects();
    let a = work.tag("a", c[1]);
    work.tag("b", c[1]);
    wire.limits.set(UploadLimits {
        max_pack_bytes: None,
        data_packs_per_advance: Some(6),
        ticket_threshold_bytes: Some(0),
    });
    let remote = &*tx;
    *wire.before.borrow_mut() = Some(Box::new(move |head: &str| {
        (head == "refs/tags/a").then(|| {
            remote
                .update_ref("refs/tags/a", RefWriteCondition::Missing, &a)
                .unwrap();
            Ok(CommitOutcome::Advanced(
                kit_core::protocol::AdvanceOutcome::HeadConflict,
            ))
        })
    }));

    let results = work.push_tags(&wire, false);

    assert_created(&results, "a");
    assert_created(&results, "b");
    assert_eq!(wire.uploaded_for(), ["refs/tags/a", "refs/tags/b"]);
}

/// A tag above the pushed branch sends what the branch lacks; with no
/// branch pushed, it sends its whole closure.
#[test]
fn a_tag_on_an_unpushed_commit_sends_what_its_base_lacks() {
    for kind in KINDS {
        let (tx, _root) = transport(kind);
        let wire = Wire::new(&*tx);
        let work = Work::new();
        let pushed = work.commits(None, 3);
        work.branch("main", pushed[2]);
        work.push_branch(&wire, "main");
        wire.take_objects();
        let above = work.commits(Some(pushed[2]), 2);
        let v2 = work.tag("v2", above[1]);

        work.push_tags(&wire, false);
        let sent: HashSet<Hash> = wire.take_objects().into_iter().collect();
        let expected: HashSet<Hash> = work
            .closure(&[v2])
            .difference(&work.closure(&pushed[2..]))
            .copied()
            .collect();
        assert_eq!(sent, expected, "{kind:?}");

        // No branch on the remote: the whole closure.
        let (fresh, _root) = transport(kind);
        let fresh = Wire::new(&*fresh);
        let work = Work::new();
        let history = work.commits(None, 3);
        let v3 = work.tag("v3", history[2]);
        work.push_tags(&fresh, false);
        let sent: HashSet<Hash> = fresh.take_objects().into_iter().collect();
        assert_eq!(sent, work.closure(&[v3]));
        assert_eq!(
            fresh.node(fresh.read("refs/kit/tagmap/v3").unwrap()).prev,
            None
        );
        let (_dir, report, _) = clone_of(&fresh);
        assert_eq!(report.tags_fetched, ["v3"]);
    }
}

#[test]
fn a_remote_tag_with_another_value_is_refused_and_an_equal_one_is_up_to_date() {
    for kind in KINDS {
        let (tx, _root) = transport(kind);
        let wire = Wire::new(&*tx);
        let work = Work::new();
        let c = work.commits(None, 2);
        work.branch("main", c[1]);
        work.push_branch(&wire, "main");
        work.light("v1", c[0]);
        work.tag("v2", c[1]);
        work.push_tags(&wire, false);
        wire.take_objects();

        let results = work.push_tags(&wire, false);
        assert!(matches!(
            outcome(&results, "v1"),
            TagPushOutcome::UpToDate { .. }
        ));
        assert!(matches!(
            outcome(&results, "v2"),
            TagPushOutcome::UpToDate { .. }
        ));
        assert!(wire.take_objects().is_empty());

        work.light("v1", c[1]);
        let results = work.push_tags(&wire, false);
        assert_eq!(
            rejection(&results, "v1"),
            &TagPushRejection::Exists { remote: c[0] },
            "{kind:?}"
        );
        assert_eq!(wire.read("refs/tags/v1"), Some(c[0]));
    }
}

/// A forced update to a value inside the old value's history sends nothing:
/// the tag map already rebuilds it, so only the tag moves, under `Match` on
/// the old value. A remote that refuses the move refuses that tag.
#[test]
fn a_forced_update_inside_the_old_history_moves_only_the_tag() {
    for kind in KINDS {
        let (tx, _root) = transport(kind);
        let wire = Wire::new(&*tx);
        let work = Work::new();
        let c = work.commits(None, 2);
        work.branch("main", c[1]);
        work.push_branch(&wire, "main");
        work.light("v1", c[1]);
        work.light("v2", c[1]);
        work.push_tags(&wire, false);
        wire.take_objects();
        let map = wire.read("refs/kit/tagmap/v1");

        work.light("v1", c[0]);
        let results = work.push_tag(&wire, "v1", true);
        assert!(
            matches!(outcome(&results, "v1"), TagPushOutcome::Forced { old, value } if *old == c[1] && *value == c[0]),
            "{results:?}"
        );
        assert!(wire.take_objects().is_empty() && wire.nodes.borrow().is_empty());
        assert_eq!(wire.read("refs/kit/tagmap/v1"), map, "{kind:?}");
        assert_eq!(wire.read("refs/tags/v1"), Some(c[0]));
        let (_dir, report, _) = clone_of(&wire);
        assert_eq!(report.tags_fetched, ["v1", "v2"], "{kind:?}");

        work.light("v2", c[0]);
        wire.refused.borrow_mut().insert("refs/tags/v2".to_owned());
        let results = work.push_tag(&wire, "v2", true);
        assert!(
            matches!(rejection(&results, "v2"), TagPushRejection::Refused(_)),
            "{results:?}"
        );
        assert_eq!(wire.read("refs/tags/v2"), Some(c[1]));
    }
}

/// A tag between two pushed branches, below the newer one's tip and above
/// the older one's, grafts on the branch that already holds its commit.
#[test]
fn a_tag_between_two_pushed_branches_grafts_on_the_one_that_holds_it() {
    let (tx, _root) = transport(Kind::Memory);
    let wire = Wire::new(&*tx);
    let work = Work::new();
    let c = work.commits(None, 5);
    work.branch("topic", c[1]);
    work.push_branch(&wire, "topic");
    work.branch("main", c[4]);
    work.push_branch(&wire, "main");
    wire.take_objects();
    let v1 = work.tag("v1", c[3]);

    let results = work.push_tags(&wire, false);

    assert_created(&results, "v1");
    assert_eq!(wire.take_objects(), [v1]);
    assert_eq!(
        wire.node(wire.read("refs/kit/tagmap/v1").unwrap()).prev,
        wire.read("refs/kit/packmap/main")
    );
}

/// `--force` moves a tag with a tag map. A reader who reads the old value
/// after the new tag map lands still fetches and verifies it.
#[test]
fn a_forced_tag_update_keeps_the_old_value_fetchable() {
    for kind in KINDS {
        let fetched = Cell::new(false);
        let (tx, _root) = transport(kind);
        let remote: &dyn Transport = &*tx;
        let wire = Wire::new(remote);
        let work = Work::new();
        let c = work.commits(None, 2);
        work.branch("main", c[0]);
        work.push_branch(&wire, "main");
        let old = work.tag("v1", c[1]);
        work.push_tags(&wire, false);
        let new = work.tag_object("v1", c[0], true);
        refs::write_tag(&work.layout, "v1", &new).unwrap();

        let seen = &fetched;
        *wire.between.borrow_mut() = Some(Box::new(move |head: &str| {
            assert_eq!(head, "refs/tags/v1");
            let inner = TransportSource::new(remote);
            let (dir, report, store) = clone_of(&inner);
            assert_eq!(report.tags_fetched, ["v1"], "{kind:?}");
            assert!(
                report.tags_rejected.is_empty(),
                "{:?}",
                report.tags_rejected
            );
            assert_eq!(
                refs::read_tag(&RepoLayout::single(dir.path().join("clone")), "v1").unwrap(),
                Some(old)
            );
            sign::verify_object_signature(&store.read_object(&old).unwrap()).unwrap();
            seen.set(true);
            Ok(())
        }));
        let results = work.push_tags(&wire, true);
        *wire.between.borrow_mut() = None;
        assert!(fetched.get());
        assert_eq!(
            outcome(&results, "v1"),
            &TagPushOutcome::Forced { old, value: new }
        );
        let (_dir, report, store) = clone_of(&wire);
        assert_eq!(report.tags_fetched, ["v1"]);
        sign::verify_object_signature(&store.read_object(&new).unwrap()).unwrap();
    }
}

/// A forced update over a remote tag with no tag map sends the old value
/// too, so a reader who read it first still verifies it; with the old value
/// not local, the tag is refused.
#[test]
fn a_forced_update_without_a_tag_map_carries_the_old_value() {
    for kind in KINDS {
        let (tx, _root) = transport(kind);
        let remote: &dyn Transport = &*tx;
        let wire = Wire::new(remote);
        let work = Work::new();
        let c = work.commits(None, 3);
        work.branch("main", c[0]);
        work.push_branch(&wire, "main");
        // The remote holds `v1` at a tag object whose history it never got.
        let old = work.tag_object("v1", c[2], true);
        tx.update_ref("refs/tags/v1", RefWriteCondition::Missing, &old)
            .unwrap();
        let new = work.tag("v1", c[1]);

        *wire.between.borrow_mut() = Some(Box::new(move |_: &str| {
            let inner = TransportSource::new(remote);
            let (_dir, report, store) = clone_of(&inner);
            assert_eq!(report.tags_fetched, ["v1"], "{kind:?}");
            assert!(store.contains(&old));
            Ok(())
        }));
        let results = work.push_tags(&wire, true);
        *wire.between.borrow_mut() = None;
        assert_eq!(
            outcome(&results, "v1"),
            &TagPushOutcome::Forced { old, value: new }
        );

        // A remote value this repository lacks is refused.
        let (tx, _root) = transport(kind);
        let wire = Wire::new(&*tx);
        let stranger = kit_core::hash::hash(b"a tag this repository never saw");
        tx.update_ref("refs/tags/v1", RefWriteCondition::Missing, &stranger)
            .unwrap();
        let results = work.push_tags(&wire, true);
        assert_eq!(
            rejection(&results, "v1"),
            &TagPushRejection::OldValueNotLocal { remote: stranger }
        );
        assert!(wire.take_objects().is_empty());
    }
}

/// A forced update over a tag map whose old value is only partly here sends
/// the new value's whole closure.
#[test]
fn a_forced_update_over_an_old_value_partly_here_sends_the_whole_closure() {
    let (tx, _root) = transport(Kind::Memory);
    let wire = Wire::new(&*tx);
    let other = Work::new();
    let theirs = other.commits(None, 2);
    let old = other.tag("v1", theirs[1]);
    other.push_tags(&wire, false);

    let work = Work::new();
    let mine = work.commits(None, 2);
    work.tag("v1", mine[1]);
    // Only the old tag object is here, not its history.
    work.store.write(&other.store.read(&old).unwrap()).unwrap();
    wire.take_objects();
    let results = work.push_tags(&wire, true);
    assert!(matches!(
        outcome(&results, "v1"),
        TagPushOutcome::Forced { .. }
    ));
    let sent: HashSet<Hash> = wire.take_objects().into_iter().collect();
    let new = refs::read_tag(&work.layout, "v1").unwrap().unwrap();
    assert_eq!(sent, work.closure(&[new]));
    let (_dir, report, _) = clone_of(&wire);
    assert_eq!(report.tags_fetched, ["v1"]);
}

/// A crash after the tag map write leaves a tag map without its tag. The
/// next push appends to it and publishes the tag.
#[test]
fn a_leftover_tag_map_is_appended_to() {
    for kind in KINDS {
        let (tx, _root) = transport(kind);
        let wire = Wire::new(&*tx);
        let work = Work::new();
        let c = work.commits(None, 2);
        work.branch("main", c[0]);
        work.push_branch(&wire, "main");
        let v1 = work.tag("v1", c[1]);

        *wire.between.borrow_mut() = Some(Box::new(|_: &str| Err(SourceError::ConnectionFailed)));
        let mut options = PushOptions::default();
        options.target = PushTarget::Tags {
            selection: TagSelection::All,
            force: false,
        };
        assert!(kit_sync::push(&work.path, &wire, &options).is_err());
        *wire.between.borrow_mut() = None;
        let leftover = wire.read("refs/kit/tagmap/v1").unwrap();
        assert_eq!(wire.read("refs/tags/v1"), None);

        let results = work.push_tags(&wire, false);
        assert_created(&results, "v1");
        let map = wire.read("refs/kit/tagmap/v1").unwrap();
        assert_eq!(wire.node(map).prev, Some(leftover), "{kind:?}");
        let (_dir, report, store) = clone_of(&wire);
        assert_eq!(report.tags_fetched, ["v1"]);
        assert!(store.contains(&v1));
    }
}

#[test]
fn a_tag_without_its_tag_map_is_repaired() {
    for kind in KINDS {
        let (tx, _root) = transport(kind);
        let wire = Wire::new(&*tx);
        let work = Work::new();
        let c = work.commits(None, 2);
        work.branch("main", c[0]);
        work.push_branch(&wire, "main");
        let v1 = work.tag("v1", c[1]);
        tx.update_ref("refs/tags/v1", RefWriteCondition::Missing, &v1)
            .unwrap();

        let results = work.push_tags(&wire, false);
        assert_eq!(
            outcome(&results, "v1"),
            &TagPushOutcome::Repaired { value: v1 }
        );
        assert!(wire.read("refs/kit/tagmap/v1").is_some(), "{kind:?}");
        let (_dir, report, _) = clone_of(&wire);
        assert_eq!(report.tags_fetched, ["v1"]);
    }
}

/// The base's head moves between the two head reads: the push reads again
/// and grafts on the head it then reads twice.
#[test]
fn a_base_branch_moved_between_reads_is_read_again() {
    let (tx, _root) = transport(Kind::Memory);
    let work = Work::new();
    let c = work.commits(None, 3);
    // Another push moves `main` on: its head is local here, and its packmap
    // node is new.
    let other = Wire::new(&*tx);
    let done = Cell::new(false);
    let wire = Wire::new(&*tx);
    work.branch("main", c[0]);
    work.push_branch(&wire, "main");
    let (work_ref, other_ref, done_ref, next) = (&work, &other, &done, c[1]);
    *wire.on_read.borrow_mut() = Some(Box::new(move |name: &str| {
        if name == "refs/kit/packmap/main" && !done_ref.replace(true) {
            work_ref.branch("main", next);
            work_ref.push_branch(other_ref, "main");
        }
    }));
    work.tag("v1", c[2]);
    let results = work.push_tags(&wire, false);
    *wire.on_read.borrow_mut() = None;
    assert_created(&results, "v1");
    let map = wire.read("refs/kit/tagmap/v1").unwrap();
    assert_eq!(wire.node(map).prev, wire.read("refs/kit/packmap/main"));
    let (_dir, report, _) = clone_of(&wire);
    assert_eq!(report.tags_fetched, ["v1"]);
}

/// A base whose head moved to a commit this repository lacks gives way to
/// the next branch the tag's history reaches.
#[test]
fn a_base_moved_to_a_foreign_head_falls_to_the_next_branch() {
    let (tx, _root) = transport(Kind::Memory);
    let wire = Wire::new(&*tx);
    let work = Work::new();
    let c = work.commits(None, 3);
    work.branch("release", c[0]);
    work.push_branch(&wire, "release");
    work.branch("main", c[1]);
    work.push_branch(&wire, "main");
    // Someone else force-pushed `main` to history this repository lacks.
    let other = Work::new();
    let foreign = other.commits(None, 1);
    other.branch("main", foreign[0]);
    let other_wire = Wire::new(&*tx);
    other.push_branch(&other_wire, "main");
    work.tag("v1", c[2]);

    let results = work.push_tags(&wire, false);
    assert_created(&results, "v1");
    let map = wire.read("refs/kit/tagmap/v1").unwrap();
    assert_eq!(wire.node(map).prev, wire.read("refs/kit/packmap/release"));
    let (_dir, report, _) = clone_of(&wire);
    assert_eq!(report.tags_fetched, ["v1"]);
}

/// A tag push grafts on the tracking branch whatever HEAD is, a detached
/// HEAD included.
#[test]
fn tags_from_a_detached_head_graft_on_a_tracking_branch() {
    let (tx, _root) = transport(Kind::File);
    let wire = Wire::new(&*tx);
    let work = Work::new();
    let c = work.commits(None, 4);
    work.branch("main", c[2]);
    work.push_branch(&wire, "main");
    refs::write_head_detached(&work.layout, &c[3]).unwrap();
    wire.take_objects();
    let v1 = work.tag("v1", c[3]);

    work.push_tags(&wire, false);
    let sent: HashSet<Hash> = wire.take_objects().into_iter().collect();
    let expected: HashSet<Hash> = work
        .closure(&[v1])
        .difference(&work.closure(&[c[2]]))
        .copied()
        .collect();
    assert_eq!(sent, expected);
    let map = wire.read("refs/kit/tagmap/v1").unwrap();
    assert_eq!(wire.node(map).prev, wire.read("refs/kit/packmap/main"));
}

/// The upload bound: 100 tags along one history, pushed to an empty remote,
/// send that history once, in one node they all share.
#[test]
fn a_hundred_tags_along_one_history_send_it_once() {
    for kind in KINDS {
        let (tx, _root) = transport(kind);
        let wire = Wire::new(&*tx);
        let work = Work::new();
        let history = work.commits(None, 100);
        let mut tags = Vec::new();
        for (i, c) in history.iter().enumerate() {
            if i % 2 == 0 {
                tags.push(work.tag(&format!("v{i:03}"), *c));
            } else {
                work.light(&format!("v{i:03}"), *c);
                tags.push(*c);
            }
        }

        let results = work.push_tags(&wire, false);
        assert_eq!(results.len(), 100);
        assert!(
            results
                .iter()
                .all(|r| matches!(r.outcome, TagPushOutcome::Created { .. }))
        );
        let sent = wire.take_objects();
        let unique: BTreeSet<Hash> = sent.iter().copied().collect();
        assert_eq!(sent.len(), unique.len(), "{kind:?}: an object went twice");
        assert_eq!(unique, work.closure(&tags).into_iter().collect());
        let maps: BTreeSet<Hash> = (0..100)
            .map(|i| wire.read(&format!("refs/kit/tagmap/v{i:03}")).unwrap())
            .collect();
        assert_eq!(maps.len(), 1, "the tags share one node");
    }
}

/// Tags on a pushed release branch that is not the current one: each push
/// grafts on that branch's chain, so each commit goes once, with its branch.
#[test]
fn tags_on_a_pushed_release_branch_send_only_tag_objects() {
    let (tx, _root) = transport(Kind::File);
    let wire = Wire::new(&*tx);
    let work = Work::new();
    let main = work.commits(None, 2);
    work.branch("main", main[1]);
    work.push_branch(&wire, "main");
    let mut tip = main[0];
    for round in 0..3 {
        tip = work.commit(Some(tip));
        work.branch("release", tip);
        work.push_branch(&wire, "release");
        wire.take_objects();
        let tag = work.tag(&format!("r{round}"), tip);
        let results = work.push_tags(&wire, false);
        assert_created(&results, &format!("r{round}"));
        assert_eq!(wire.take_objects(), [tag], "round {round}");
    }
}

/// Tags on a branch never pushed: one push sends each commit once. A later
/// push sends that history again, until the branch itself is pushed.
#[test]
fn tags_on_a_branch_never_pushed_send_each_commit_once_per_push() {
    let (tx, _root) = transport(Kind::Memory);
    let wire = Wire::new(&*tx);
    let work = Work::new();
    let main = work.commits(None, 1);
    work.branch("main", main[0]);
    work.push_branch(&wire, "main");
    wire.take_objects();
    let topic = work.commits(Some(main[0]), 2);
    let a = work.tag("a", topic[0]);
    let b = work.tag("b", topic[1]);
    work.push_tags(&wire, false);
    let sent = wire.take_objects();
    let unique: HashSet<Hash> = sent.iter().copied().collect();
    assert_eq!(sent.len(), unique.len());
    let held = work.closure(&main);
    let expected: HashSet<Hash> = work.closure(&[a, b]).difference(&held).copied().collect();
    assert_eq!(unique, expected);

    // A later tag on the same branch sends its history again.
    let more = work.commit(Some(topic[1]));
    work.tag("c", more);
    work.push_tags(&wire, false);
    let resent: HashSet<Hash> = wire.take_objects().into_iter().collect();
    assert!(resent.contains(&topic[0]), "the documented re-send");

    // Once the branch is pushed, a tag on it sends only its tag object.
    work.branch("topic", more);
    work.push_branch(&wire, "topic");
    wire.take_objects();
    let d = work.tag("d", more);
    work.push_tags(&wire, false);
    assert_eq!(wire.take_objects(), [d]);
}

/// Ticketed Connect: a group whose plan needs more packs, or more objects,
/// than one advance carries is refused before upload.
#[test]
fn a_group_over_one_ticketed_advance_is_refused_before_upload() {
    let (tx, _root) = transport(Kind::Memory);
    let wire = Wire::new(&*tx);
    let work = Work::new();
    let history = work.commits(None, 6);
    work.tag("v1", history[5]);
    wire.limits.set(UploadLimits {
        max_pack_bytes: None,
        data_packs_per_advance: Some(1),
        ticket_threshold_bytes: Some(0),
    });
    let mut options = PushOptions::default();
    options.pack_payload_cap = 200;
    options.target = PushTarget::Tags {
        selection: TagSelection::All,
        force: false,
    };
    let results = kit_sync::push(&work.path, &wire, &options).unwrap().tags;
    assert_eq!(rejection(&results, "v1"), &TagPushRejection::TooLarge);
    assert!(wire.packs.borrow().is_empty());
    assert!(
        rejection(&results, "v1")
            .to_string()
            .contains("push the branch first")
    );

    wire.limits.set(UploadLimits {
        max_pack_bytes: None,
        data_packs_per_advance: Some(6),
        ticket_threshold_bytes: Some(0),
    });
    wire.inspect.set(Some(3));
    let results = work.push_tags(&wire, false);
    assert_eq!(rejection(&results, "v1"), &TagPushRejection::TooLarge);
    assert!(wire.packs.borrow().is_empty());
}

/// Ticketed Connect: when the ticket-carrying tag loses its race, the group
/// is uploaded again under the next tag, the others publish, and the loser
/// is placed again.
#[test]
fn a_lost_ticketed_advance_uploads_again_under_the_next_tag() {
    let lost = Cell::new(false);
    let (tx, _root) = transport(Kind::Memory);
    let wire = Wire::new(&*tx);
    let work = Work::new();
    let c = work.commits(None, 2);
    work.branch("main", c[0]);
    work.push_branch(&wire, "main");
    wire.take_objects();
    work.tag("a", c[1]);
    work.tag("b", c[1]);
    work.tag("c", c[1]);
    wire.limits.set(UploadLimits {
        max_pack_bytes: None,
        data_packs_per_advance: Some(6),
        ticket_threshold_bytes: Some(0),
    });
    let lost = &lost;
    *wire.before.borrow_mut() = Some(Box::new(move |head: &str| {
        (head == "refs/tags/a" && !lost.replace(true)).then_some(Ok(CommitOutcome::Advanced(
            kit_core::protocol::AdvanceOutcome::PackmapConflict,
        )))
    }));
    let results = work.push_tags(&wire, false);
    for t in ["a", "b", "c"] {
        assert_created(&results, t);
    }
    assert_eq!(
        wire.uploaded_for(),
        ["refs/tags/a", "refs/tags/b", "refs/tags/a"],
        "uploaded under a, again under b, then a alone"
    );
    let (_dir, report, _) = clone_of(&wire);
    assert_eq!(report.tags_fetched, ["a", "b", "c"]);
}

/// A ticketed group whose two tags `a` and `b` share one commit.
fn ticketed_pair<'a>(tx: &'a dyn Transport, work: &Work) -> Wire<'a> {
    let wire = Wire::new(tx);
    let c = work.commits(None, 2);
    work.branch("main", c[0]);
    work.push_branch(&wire, "main");
    wire.take_objects();
    work.tag("a", c[1]);
    work.tag("b", c[1]);
    wire.limits.set(UploadLimits {
        max_pack_bytes: None,
        data_packs_per_advance: Some(6),
        ticket_threshold_bytes: Some(0),
    });
    wire
}

/// Ticketed Connect: expired tickets send the group again once under the
/// same tag; expired again, the group is refused.
#[test]
fn expired_tickets_upload_the_group_again_once() {
    let (tx, _root) = transport(Kind::Memory);
    let work = Work::new();
    let expired = Cell::new(0);
    let wire = ticketed_pair(&*tx, &work);
    let expired = &expired;
    *wire.before.borrow_mut() = Some(Box::new(move |head: &str| {
        (head == "refs/tags/a" && expired.replace(expired.get() + 1) == 0)
            .then_some(Ok(CommitOutcome::TicketRejected))
    }));
    let results = work.push_tags(&wire, false);
    assert_created(&results, "a");
    assert_created(&results, "b");
    assert_eq!(wire.uploaded_for(), ["refs/tags/a", "refs/tags/a"]);

    let (tx, _root) = transport(Kind::Memory);
    let work = Work::new();
    let wire = ticketed_pair(&*tx, &work);
    *wire.before.borrow_mut() = Some(Box::new(|head: &str| {
        (head == "refs/tags/a").then_some(Ok(CommitOutcome::TicketRejected))
    }));
    let results = work.push_tags(&wire, false);
    for t in ["a", "b"] {
        assert!(
            matches!(rejection(&results, t), TagPushRejection::Refused(_)),
            "{results:?}"
        );
    }
    assert_eq!(wire.uploaded_for(), ["refs/tags/a", "refs/tags/a"]);
    assert_eq!(wire.read("refs/tags/a"), None);
}

/// Ticketed Connect: a lost delta base plans the group again once, with no
/// base, and the same tag sends it (SPEC-TRANSPORT-CONNECT §7.6).
#[test]
fn a_lost_delta_base_plans_the_group_again_self_contained() {
    let (tx, _root) = transport(Kind::Memory);
    let work = Work::new();
    let lost = Cell::new(false);
    let wire = ticketed_pair(&*tx, &work);
    let lost = &lost;
    *wire.before.borrow_mut() = Some(Box::new(move |head: &str| {
        (head == "refs/tags/a" && !lost.replace(true))
            .then_some(Ok(CommitOutcome::DeltaBaseUnavailable))
    }));
    let results = work.push_tags(&wire, false);
    assert_created(&results, "a");
    assert_created(&results, "b");
    assert_eq!(wire.uploaded_for(), ["refs/tags/a", "refs/tags/a"]);
    let packs = wire.packs.borrow();
    let count = |bytes: &[u8]| {
        let dir = tempfile::tempdir().unwrap();
        let store = ObjectStore::init(&RepoLayout::single(dir.path())).unwrap();
        PackReader::read(bytes, &store).unwrap().stored.len()
    };
    assert!(
        count(&packs[1].1) > count(&packs[0].1),
        "the second plan is the whole closure"
    );
    drop(packs);
    let (_dir, report, _) = clone_of(&wire);
    assert_eq!(report.tags_fetched, ["a", "b"]);
}

/// Ticketed Connect: a ticket-carrying tag that keeps losing its race sends
/// the group again at most `PACKMAP_CAS_ATTEMPTS` times in one round, and
/// every tag that never lands is refused as contended.
#[test]
fn ticketed_tags_that_always_lose_are_contended_after_a_bounded_upload_count() {
    let (tx, _root) = transport(Kind::Memory);
    let wire = Wire::new(&*tx);
    let work = Work::new();
    let c = work.commits(None, 2);
    work.branch("main", c[0]);
    work.push_branch(&wire, "main");
    wire.take_objects();
    let names: Vec<String> = (0..12).map(|n| format!("t{n:02}")).collect();
    for name in &names {
        work.tag(name, c[1]);
    }
    wire.limits.set(UploadLimits {
        max_pack_bytes: None,
        data_packs_per_advance: Some(6),
        ticket_threshold_bytes: Some(0),
    });
    *wire.before.borrow_mut() = Some(Box::new(|head: &str| {
        head.starts_with("refs/tags/")
            .then_some(Ok(CommitOutcome::Advanced(
                kit_core::protocol::AdvanceOutcome::PackmapConflict,
            )))
    }));
    let results = work.push_tags(&wire, false);
    for name in &names {
        assert_eq!(
            rejection(&results, name),
            &TagPushRejection::Contended,
            "{name}"
        );
    }
    let uploads = wire.uploaded_for().len();
    // One first upload per round, and at most eight more across the push.
    assert!(uploads <= 2 * 8, "{uploads} uploads");
    assert_eq!(wire.read("refs/tags/t00"), None);
}

/// Ticketed Connect: a server that refuses the ticket-carrying advance (a
/// pairing rule that knows only heads) refuses the whole group.
#[test]
fn a_refused_ticketed_advance_refuses_its_group() {
    let (tx, _root) = transport(Kind::Memory);
    let wire = Wire::new(&*tx);
    let work = Work::new();
    let c = work.commits(None, 2);
    work.branch("main", c[0]);
    work.push_branch(&wire, "main");
    wire.take_objects();
    work.tag("a", c[1]);
    work.tag("b", c[1]);
    wire.limits.set(UploadLimits {
        max_pack_bytes: None,
        data_packs_per_advance: Some(6),
        ticket_threshold_bytes: Some(0),
    });
    *wire.before.borrow_mut() = Some(Box::new(|_: &str| {
        Some(Err(SourceError::Remote(Box::new(
            kit_sync::RemoteFailure {
                code: "invalid_argument".to_owned(),
                message: "head and packmap refs must pair".to_owned(),
                details: Vec::new(),
                status: 400,
                headers: Vec::new(),
            },
        ))))
    }));
    let results = work.push_tags(&wire, false);
    for t in ["a", "b"] {
        assert!(
            matches!(rejection(&results, t), TagPushRejection::Refused(m) if m.contains("must pair")),
            "{results:?}"
        );
    }
    assert_eq!(wire.uploaded_for(), ["refs/tags/a"], "uploaded once");
    assert_eq!(wire.read("refs/tags/a"), None);
}

/// On a remote whose listing is one frame, a tag create that would take the
/// listing past the bound is refused before any upload; a remote that pages
/// takes it.
#[test]
fn a_tag_past_the_listing_bound_is_refused_where_the_listing_is_one_frame() {
    let entry = |n: usize| Ref {
        name: format!("pad{n:08}"),
        hash: Some(kit_core::hash::hash(&n.to_le_bytes())),
    };
    let per_entry = entry(0).name.len() + 48;
    let room = MAX_TAG_LISTING_BYTES / per_entry;
    let (tx, _root) = transport(Kind::File);
    assert_eq!(tx.ref_listing(), RefListing::OneFrame);
    let wire = Wire::new(&*tx);
    *wire.padding.borrow_mut() = (0..room).map(entry).collect();
    let work = Work::new();
    let c = work.commits(None, 1);
    work.light("v1", c[0]);

    let results = work.push_tags(&wire, false);
    assert_eq!(rejection(&results, "v1"), &TagPushRejection::TooManyTags);
    assert!(wire.packs.borrow().is_empty() && wire.nodes.borrow().is_empty());
    let results = work.push_tag(&wire, "v1", false);
    assert_eq!(rejection(&results, "v1"), &TagPushRejection::TooManyTags);

    // Two entries less leave room.
    wire.padding.borrow_mut().pop();
    wire.padding.borrow_mut().pop();
    assert_created(&work.push_tag(&wire, "v1", false), "v1");

    // A listing that pages has no such bound.
    let (tx, _root) = transport(Kind::Memory);
    assert_eq!(tx.ref_listing(), RefListing::Ordered);
    let wire = Wire::new(&*tx);
    *wire.padding.borrow_mut() = (0..room + 10).map(entry).collect();
    assert_created(&work.push_tags(&wire, false), "v1");
}

/// A name `refs/kit/tagmap/<t>` cannot hold, an annotated tag named for
/// another tag, and an unsigned annotated tag are
/// refused before the remote is read.
#[test]
fn tags_that_cannot_go_are_refused_locally() {
    let (tx, _root) = transport(Kind::Memory);
    let wire = Wire::new(&*tx);
    let work = Work::new();
    let c = work.commits(None, 1);
    // 497 bytes in ten segments, made before the bound.
    let long = format!("{}/{}", vec!["s".repeat(49); 9].join("/"), "s".repeat(47));
    assert_eq!(long.len(), refs::MAX_TAG_NAME_BYTES + 1);
    let path = work.path.join(".kit/refs/tags").join(&long);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, refs::encode_ref_wire(&c[0])).unwrap();
    let v1 = work.tag_object("v1", c[0], true);
    refs::write_tag(&work.layout, "latest", &v1).unwrap();
    let unsigned = work.tag_object("rc", c[0], false);
    refs::write_tag(&work.layout, "rc", &unsigned).unwrap();
    work.light("ok", c[0]);

    let named = work.push_tag(&wire, &long, false);
    assert!(
        matches!(rejection(&named, &long), TagPushRejection::NotPushable(m) if m.contains("too long")),
        "{named:?}"
    );
    let results = work.push_tags(&wire, false);
    assert_eq!(
        rejection(&results, "latest"),
        &TagPushRejection::NameMismatch {
            object_name: "v1".to_owned()
        }
    );
    let refused = rejection(&results, "rc");
    assert_eq!(
        refused,
        &TagPushRejection::Unsigned {
            tag: "rc".to_owned()
        }
    );
    assert!(refused.to_string().contains("kit tag -s rc"));
    assert_created(&results, "ok");
    assert_eq!(wire.read("refs/tags/rc"), None);
    assert_eq!(wire.read("refs/tags/latest"), None);
}

/// A tag object whose type is not a commit, and a lightweight tag on a
/// tree, still go to a remote that checks no objects.
#[test]
fn a_lightweight_tag_on_a_tree_goes_to_a_file_remote() {
    let (tx, _root) = transport(Kind::File);
    let wire = Wire::new(&*tx);
    let work = Work::new();
    let c = work.commits(None, 1);
    let Object::Commit(commit) = work.store.read_object(&c[0]).unwrap() else {
        panic!()
    };
    assert_eq!(
        work.store.object_type(&commit.tree_hash).unwrap(),
        ObjectType::Tree
    );
    work.light("tree", commit.tree_hash);
    assert_created(&work.push_tags(&wire, false), "tree");
    assert_eq!(wire.read("refs/tags/tree"), Some(commit.tree_hash));
}

/// A named tag that is not a local tag is an error, not a result.
#[test]
fn a_named_tag_that_is_not_local_is_an_error() {
    let (tx, _root) = transport(Kind::Memory);
    let wire = Wire::new(&*tx);
    let work = Work::new();
    let mut options = PushOptions::default();
    options.target = PushTarget::Tags {
        selection: TagSelection::Named(vec!["nope".to_owned()]),
        force: false,
    };
    let error = kit_sync::push(&work.path, &wire, &options).unwrap_err();
    assert!(
        error.to_string().contains("'nope' does not exist"),
        "{error}"
    );
}
