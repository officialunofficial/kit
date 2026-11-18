//! The re-baseline of a chain through whole pushes, and a push racing a
//! chain that another client reset.
//!
//! Every test checks the invariant a reader relies on: whenever the head
//! resolves to `T`, the packmap chain rebuilds the closure of `T`. A
//! serialized advance writes the packmap before the head, so a reader
//! between the writes, and a crash between them, pairs the new packmap with
//! the old head; the tests check that pair too.

use super::{PushControl, PushError, RetryReason, push_branch_steps};
use crate::TransportSource;
use crate::packmap::packmap_ref;
use kit_core::hash::Hash;
use kit_core::layout::RepoLayout;
use kit_core::object::{Blob, Commit, EntryMode, Identity, Object, Tree, TreeEntry};
use kit_core::ops::graph::reachable_objects;
use kit_core::pack::{self, PackReader};
use kit_core::protocol::{
    AdvanceOutcome, CommitOutcome, PackKey, Transport, TransportError, TransportResult,
    UploadLimits,
};
use kit_core::refs::{Ref, RefWriteCondition};
use kit_core::store::ObjectStore;
use kit_core::{serialize, transfer};
use kit_transport_memory::MemoryTransport;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tempfile::TempDir;

const HEAD: &str = "refs/heads/main";
const DEPTH: usize = 3;

type Hook<'a> = Box<dyn FnOnce(&Remote<'a>) + Send + 'a>;

/// A remote whose two-ref advance checks both conditions under one lock,
/// then writes the packmap, then the head: serialized for writers, ordered
/// for readers. `atomic` makes it claim an atomic advance instead, and
/// `serialized = false` makes it claim neither. `tickets` makes it limit the
/// tickets of an advance, which sends a push through the split planner.
struct Remote<'a> {
    inner: MemoryTransport,
    lock: Mutex<()>,
    atomic: bool,
    serialized: bool,
    tickets: bool,
    /// Answer the next advance as a server that lost a delta base does.
    lose_delta_base: AtomicBool,
    /// The packs uploaded so far.
    uploads: AtomicUsize,
    /// The packs uploaded when each advance began, in order.
    uploads_at_advance: Mutex<Vec<usize>>,
    /// Stop the next advance after its packmap write, as a crash would.
    crash: AtomicBool,
    /// Run once at the start of the next advance, before its checks.
    before_advance: Mutex<Option<Hook<'a>>>,
    /// The head condition of every advance, in order.
    head_conditions: Mutex<Vec<RefWriteCondition>>,
}

impl<'a> Remote<'a> {
    fn new() -> Self {
        Self {
            inner: MemoryTransport::new(),
            lock: Mutex::new(()),
            atomic: false,
            serialized: true,
            tickets: false,
            lose_delta_base: AtomicBool::new(false),
            uploads: AtomicUsize::new(0),
            uploads_at_advance: Mutex::new(Vec::new()),
            crash: AtomicBool::new(false),
            before_advance: Mutex::new(None),
            head_conditions: Mutex::new(Vec::new()),
        }
    }

    fn before_advance(&self, hook: impl FnOnce(&Remote<'a>) + Send + 'a) {
        *self.before_advance.lock().unwrap() = Some(Box::new(hook));
    }
}

fn holds(condition: RefWriteCondition, current: Option<Hash>) -> bool {
    match condition {
        RefWriteCondition::Any => true,
        RefWriteCondition::Missing => current.is_none(),
        RefWriteCondition::Match(h) => current == Some(h),
    }
}

impl Transport for Remote<'_> {
    fn upload_pack(
        &self,
        bytes: &dyn kit_core::protocol::PackBody,
        key: &kit_core::protocol::PackKey,
        head_ref: Option<&str>,
    ) -> kit_core::protocol::TransportResult<()> {
        self.uploads.fetch_add(1, Ordering::SeqCst);
        self.inner.upload_pack(bytes, key, head_ref)
    }
    fn download_pack(
        &self,
        key: &kit_core::protocol::PackKey,
        ref_hint: Option<&str>,
        sink: &mut dyn kit_core::protocol::PackSink,
    ) -> kit_core::protocol::TransportResult<()> {
        self.inner.download_pack(key, ref_hint, sink)
    }
    fn pack_exists(
        &self,
        key: &kit_core::protocol::PackKey,
        ref_hint: Option<&str>,
    ) -> kit_core::protocol::TransportResult<bool> {
        self.inner.pack_exists(key, ref_hint)
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
        self.inner.read_ref(name)
    }
    fn list_refs(&self, prefix: &str) -> TransportResult<Vec<Ref>> {
        self.inner.list_refs(prefix)
    }
    fn advance_refs(
        &self,
        head_ref: &str,
        head_condition: RefWriteCondition,
        head_value: &Hash,
        packmap_ref: &str,
        packmap_condition: RefWriteCondition,
        packmap_value: &Hash,
    ) -> TransportResult<AdvanceOutcome> {
        let hook = self.before_advance.lock().unwrap().take();
        if let Some(hook) = hook {
            hook(self);
        }
        self.head_conditions.lock().unwrap().push(head_condition);
        self.uploads_at_advance
            .lock()
            .unwrap()
            .push(self.uploads.load(Ordering::SeqCst));
        let _guard = self.lock.lock().unwrap();
        if !holds(packmap_condition, self.inner.read_ref(packmap_ref)?) {
            return Ok(AdvanceOutcome::PackmapConflict);
        }
        if !holds(head_condition, self.inner.read_ref(head_ref)?) {
            return Ok(AdvanceOutcome::HeadConflict);
        }
        self.inner
            .update_ref(packmap_ref, packmap_condition, packmap_value)?;
        if self.crash.swap(false, Ordering::SeqCst) {
            return Err(TransportError::RemoteError("crashed".into()));
        }
        self.inner
            .update_ref(head_ref, head_condition, head_value)?;
        Ok(AdvanceOutcome::Committed)
    }
    #[allow(clippy::too_many_arguments)]
    fn advance_refs_committing(
        &self,
        head_ref: &str,
        head_condition: RefWriteCondition,
        head_value: &Hash,
        packmap_ref: &str,
        packmap_condition: RefWriteCondition,
        packmap_value: &Hash,
        _commit: &[PackKey],
    ) -> TransportResult<CommitOutcome> {
        if self.lose_delta_base.swap(false, Ordering::SeqCst) {
            self.uploads_at_advance
                .lock()
                .unwrap()
                .push(self.uploads.load(Ordering::SeqCst));
            return Ok(CommitOutcome::DeltaBaseUnavailable);
        }
        self.advance_refs(
            head_ref,
            head_condition,
            head_value,
            packmap_ref,
            packmap_condition,
            packmap_value,
        )
        .map(CommitOutcome::Advanced)
    }
    fn supports_atomic_advance(&self) -> bool {
        self.atomic
    }
    fn upload_limits(&self) -> UploadLimits {
        UploadLimits {
            data_packs_per_advance: self.tickets.then_some(6),
            ..UploadLimits::default()
        }
    }
    fn supports_serialized_advance(&self) -> bool {
        self.atomic || self.serialized
    }
}

fn store() -> (TempDir, ObjectStore) {
    let dir = TempDir::new().unwrap();
    let store = ObjectStore::init(&RepoLayout::single(dir.path())).unwrap();
    (dir, store)
}

fn put(store: &ObjectStore, object: &Object) -> Hash {
    store.write(&serialize::serialize(object).unwrap()).unwrap()
}

/// A commit whose tree holds `files`.
fn commit(store: &ObjectStore, files: &[(&str, &str)], parents: &[Hash], seed: u8) -> Hash {
    let mut entries: Vec<TreeEntry> = files
        .iter()
        .map(|(name, data)| TreeEntry {
            name: name.as_bytes().to_vec(),
            mode: EntryMode::Blob,
            object_hash: put(
                store,
                &Object::Blob(Blob {
                    data: data.as_bytes().to_vec(),
                }),
            ),
        })
        .collect();
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    let tree = put(store, &Object::Tree(Tree { entries }));
    put(
        store,
        &Object::Commit(Commit::new_unannotated(
            tree,
            parents.to_vec(),
            Identity::ed25519([7; 32]),
            [0; 32],
            vec![seed],
            u64::from(seed),
            [0; 64],
        )),
    )
}

fn push(
    remote: &Remote<'_>,
    store: &ObjectStore,
    tip: Hash,
    condition: RefWriteCondition,
) -> Result<usize, PushError> {
    push_at(remote, store, tip, condition, DEPTH)
}

/// A push with its own re-baseline threshold; zero never re-baselines.
fn push_at(
    remote: &Remote<'_>,
    store: &ObjectStore,
    tip: Hash,
    condition: RefWriteCondition,
    threshold: usize,
) -> Result<usize, PushError> {
    push_branch_steps(
        &TransportSource::new(remote),
        store,
        "main",
        tip,
        condition,
        threshold,
        pack::MAX_TOTAL_PAYLOAD,
        &PushControl::default(),
        &mut |_| Ok(()),
    )
}

/// The packmap chain of `main`, newest node first.
fn chain(remote: &Remote<'_>) -> Vec<transfer::PackListNode> {
    let mut nodes = Vec::new();
    let mut cursor = remote.read_ref(&packmap_ref("main")).unwrap();
    while let Some(key) = cursor {
        let node = transfer::decode_packlist(
            &remote
                .download_blob(&PackKey::from_hash(key), None, u64::MAX)
                .unwrap(),
        )
        .unwrap();
        cursor = node.prev;
        nodes.push(node);
    }
    nodes
}

/// Whether the packmap chain alone rebuilds the closure of `head`: every
/// pack it names, unpacked oldest first into an empty store, yields every
/// object `head` reaches.
fn rebuilds(remote: &Remote<'_>, head: Hash) -> bool {
    let (_dir, fresh) = store();
    let mut nodes = chain(remote);
    nodes.reverse();
    for key in nodes.iter().flat_map(|node| &node.packs) {
        let bytes = remote
            .download_blob(&PackKey::from_hash(*key), None, u64::MAX)
            .unwrap();
        if PackReader::read(&bytes, &fresh).is_err() {
            return false;
        }
    }
    reachable_objects(&fresh, &head).is_ok()
}

/// The commits of a history and a remote whose chain is `DEPTH` nodes
/// long, so the next push crosses the re-baseline threshold.
struct Setup {
    /// `c[0]` holds `a`; `c[1]` and `c[2]` add `keep`.
    c: [Hash; 3],
    /// A child of `c[2]`: a fast-forward of the remote's head.
    ahead: Hash,
    /// A child of `c[0]` without `keep`: not a fast-forward of `c[2]`.
    aside: Hash,
}

fn setup(store: &ObjectStore, remote: &Remote<'_>) -> Setup {
    let c0 = commit(store, &[("a", "zero")], &[], 0);
    let c1 = commit(store, &[("a", "one"), ("keep", "kept")], &[c0], 1);
    let c2 = commit(store, &[("a", "two"), ("keep", "kept")], &[c1], 2);
    let ahead = commit(store, &[("a", "three"), ("keep", "kept")], &[c2], 3);
    let aside = commit(store, &[("a", "aside")], &[c0], 4);
    push(remote, store, c0, RefWriteCondition::Missing).unwrap();
    push(remote, store, c1, RefWriteCondition::Match(c0)).unwrap();
    push(remote, store, c2, RefWriteCondition::Match(c1)).unwrap();
    assert_eq!(chain(remote).len(), DEPTH);
    assert!(rebuilds(remote, c2));
    Setup {
        c: [c0, c1, c2],
        ahead,
        aside,
    }
}

/// Replace the chain with one node that holds only the closure of `tip`,
/// and move the head to `tip`, as a client that resets the chain does.
fn reset_to(remote: &Remote<'_>, store: &ObjectStore, tip: Hash) {
    let scratch = Remote::new();
    push_at(&scratch, store, tip, RefWriteCondition::Missing, 0).unwrap();
    let node_key = scratch.read_ref(&packmap_ref("main")).unwrap().unwrap();
    let node = scratch
        .download_blob(&PackKey::from_hash(node_key), None, u64::MAX)
        .unwrap();
    for key in transfer::decode_packlist(&node).unwrap().packs {
        let key = PackKey::from_hash(key);
        remote
            .inner
            .upload_pack(
                &kit_core::protocol::SliceBody(
                    &scratch.download_blob(&key, None, u64::MAX).unwrap(),
                ),
                &key,
                None,
            )
            .unwrap();
    }
    remote
        .inner
        .upload_blob(&node, &PackKey::from_hash(node_key), None)
        .unwrap();
    for (name, value) in [(packmap_ref("main"), node_key), (HEAD.to_owned(), tip)] {
        remote
            .inner
            .update_ref(&name, RefWriteCondition::Any, &value)
            .unwrap();
    }
}

/// A remote that offers the advance `kind` names.
fn remote_of<'a>(kind: &str) -> Remote<'a> {
    Remote {
        atomic: kind == "atomic",
        serialized: kind != "ordered",
        ..Remote::new()
    }
}

/// A push that crosses the threshold replaces the chain with one node that
/// lists every pack of the chain and then its own. It uploads what an
/// append uploads. Every advance does this, for a fast-forward and for a push that
/// is not one, because the node drops nothing.
#[test]
fn a_push_at_the_threshold_re_baselines_and_uploads_what_an_append_does() {
    for kind in ["serialized", "ordered", "atomic"] {
        for fast_forward in [true, false] {
            let case = format!("{kind}, fast-forward: {fast_forward}");
            let (_dir, store) = store();
            let (remote, twin) = (remote_of(kind), remote_of(kind));
            let s = setup(&store, &remote);
            setup(&store, &twin);
            let tip = if fast_forward { s.ahead } else { s.aside };
            let held: Vec<Hash> = chain(&remote)
                .into_iter()
                .rev()
                .flat_map(|node| node.packs)
                .collect();
            let uploads = remote.uploads.load(Ordering::SeqCst);
            push(&remote, &store, tip, RefWriteCondition::Match(s.c[2])).unwrap();
            let uploaded = remote.uploads.load(Ordering::SeqCst) - uploads;
            // The same push with no threshold appends.
            let uploads = twin.uploads.load(Ordering::SeqCst);
            push_at(&twin, &store, tip, RefWriteCondition::Match(s.c[2]), 0).unwrap();
            let appended = chain(&twin).remove(0).packs;

            assert_eq!(remote.read_ref(HEAD).unwrap(), Some(tip), "{case}");
            let nodes = chain(&remote);
            assert_eq!(nodes.len(), 1, "{case}");
            assert_eq!(nodes[0].prev, None, "{case}");
            assert_eq!(nodes[0].packs, [held, appended.clone()].concat(), "{case}");
            assert_eq!(
                uploaded,
                twin.uploads.load(Ordering::SeqCst) - uploads,
                "{case}: the uploads of an append, its packs and one node"
            );
            assert!(rebuilds(&remote, tip), "{case}");
        }
    }
}

/// A crash between the packmap write and the head write leaves the old
/// head with the new packmap. That packmap lists every pack of the chain it
/// replaced, so it rebuilds the old head.
#[test]
fn a_crash_between_the_writes_leaves_the_old_head_rebuildable() {
    for fast_forward in [true, false] {
        let (_dir, store) = store();
        let remote = Remote::new();
        let s = setup(&store, &remote);
        let tip = if fast_forward { s.ahead } else { s.aside };
        remote.crash.store(true, Ordering::SeqCst);
        assert!(push(&remote, &store, tip, RefWriteCondition::Match(s.c[2])).is_err());
        assert_eq!(remote.read_ref(HEAD).unwrap(), Some(s.c[2]));
        assert_eq!(chain(&remote).len(), 1, "{fast_forward}");
        assert!(rebuilds(&remote, s.c[2]), "{fast_forward}");
        // The next push from that state lands.
        push(&remote, &store, tip, RefWriteCondition::Match(s.c[2])).unwrap();
        assert!(rebuilds(&remote, tip), "{fast_forward}");
    }
}

/// A force push plans its packs against the head it reads, then appends
/// them. Here, between its plan and its advance, another client resets the
/// chain to the closure of a head that lacks `keep`, which the force push
/// left out as already held. An ordered force append would then publish a
/// head the chain cannot rebuild. On a serialized advance the force push
/// takes the guarded driver, sees the reset drop the chain its plan relied
/// on, and plans again.
#[test]
fn a_force_push_racing_a_reset_plans_again() {
    let (_dir, store) = store();
    let remote = Remote::new();
    let s = setup(&store, &remote);
    let forced = s.ahead;
    let beyond = commit(&store, &[("a", "beyond")], &[s.aside], 5);
    let store_ref = &store;
    remote.before_advance(move |remote| reset_to(remote, store_ref, beyond));
    push(&remote, &store, forced, RefWriteCondition::Any).unwrap();
    assert_eq!(remote.read_ref(HEAD).unwrap(), Some(forced));
    assert!(rebuilds(&remote, forced));
}

/// A force push whose chain another push re-baselines before its advance
/// still lands, and the chain rebuilds its head.
#[test]
fn a_force_push_racing_a_re_baseline_lands() {
    let (_dir, store) = store();
    let remote = Remote::new();
    let s = setup(&store, &remote);
    let (aside, c2) = (s.aside, s.c[2]);
    let store_ref = &store;
    remote.before_advance(move |remote| {
        push(remote, store_ref, aside, RefWriteCondition::Match(c2)).unwrap();
        assert_eq!(chain(remote).len(), 1, "the push re-baselined");
    });
    push(&remote, &store, s.ahead, RefWriteCondition::Any).unwrap();
    assert_eq!(remote.read_ref(HEAD).unwrap(), Some(s.ahead));
    assert!(rebuilds(&remote, s.ahead));
}

/// Force pushes keep the ordered path on a remote that offers neither
/// advance: their head write stays unconditional.
#[test]
fn a_force_push_on_an_ordered_advance_writes_the_head_unconditionally() {
    let (_dir, store) = store();
    let remote = Remote {
        serialized: false,
        ..Remote::new()
    };
    let s = setup(&store, &remote);
    remote.head_conditions.lock().unwrap().clear();
    push(&remote, &store, s.ahead, RefWriteCondition::Any).unwrap();
    assert_eq!(
        *remote.head_conditions.lock().unwrap(),
        [RefWriteCondition::Any]
    );
    assert!(rebuilds(&remote, s.ahead));
}

/// A lease push whose lease differs from the head it reads. The head is
/// `c2`, the lease; another push moves it to `aside`, and the push plans
/// `beyond`, a child of `aside`, against `aside`, leaving `aside` out as
/// already held. Before its advance, another client resets the chain to the
/// closure of `c2`, dropping `aside`. The lease now holds again, so a push that conditions on
/// it would publish `beyond` with a chain that lacks its parent. The driver
/// refuses the push before it plans, on an atomic and on a serialized
/// advance, and through the split planner.
#[test]
fn a_lease_push_refuses_a_head_that_differs_from_its_lease() {
    for (atomic, tickets) in [(true, false), (false, false), (true, true), (false, true)] {
        let case = format!("atomic: {atomic}, tickets: {tickets}");
        let (_dir, store) = store();
        let remote = Remote {
            atomic,
            tickets,
            ..Remote::new()
        };
        let s = setup(&store, &remote);
        let (c2, aside) = (s.c[2], s.aside);
        let beyond = commit(&store, &[("a", "aside"), ("b", "beyond")], &[aside], 5);
        push_at(&remote, &store, aside, RefWriteCondition::Match(c2), 0).unwrap();
        let store_ref = &store;
        remote.before_advance(move |remote| reset_to(remote, store_ref, c2));
        let uploads = remote.uploads.load(Ordering::SeqCst);
        let result = push_at(&remote, &store, beyond, RefWriteCondition::Match(c2), 0);
        let head = remote.read_ref(HEAD).unwrap().unwrap();
        assert!(rebuilds(&remote, head), "{case}: {result:?}");
        assert!(
            matches!(result, Err(PushError::NonFastForwardPush { .. })),
            "{case}: {result:?}"
        );
        assert_eq!(head, aside, "{case}");
        assert_eq!(remote.uploads.load(Ordering::SeqCst), uploads, "{case}");
    }
}

/// A push that leases a missing head is refused before it plans when the
/// head exists: a plan against that head could rely on objects a reset
/// drops before the head goes away again.
#[test]
fn a_push_leasing_a_missing_head_refuses_an_existing_head() {
    for tickets in [false, true] {
        let (_dir, store) = store();
        let remote = Remote {
            atomic: true,
            tickets,
            ..Remote::new()
        };
        let s = setup(&store, &remote);
        let uploads = remote.uploads.load(Ordering::SeqCst);
        let result = push(&remote, &store, s.ahead, RefWriteCondition::Missing);
        assert!(
            matches!(result, Err(PushError::NonFastForwardPush { .. })),
            "tickets: {tickets}: {result:?}"
        );
        assert_eq!(remote.read_ref(HEAD).unwrap(), Some(s.c[2]));
        assert_eq!(remote.uploads.load(Ordering::SeqCst), uploads);
    }
}

/// A push whose earlier attempt landed finds the head at its tip and its
/// lease stale. It succeeds and writes nothing, so a later return of the
/// head to the lease cannot pair the tip with a chain that dropped it.
#[test]
fn a_push_that_already_landed_writes_nothing() {
    for tickets in [false, true] {
        let (_dir, store) = store();
        let remote = Remote {
            atomic: true,
            tickets,
            ..Remote::new()
        };
        let s = setup(&store, &remote);
        push(&remote, &store, s.ahead, RefWriteCondition::Match(s.c[2])).unwrap();
        let packmap = remote.read_ref(&packmap_ref("main")).unwrap();
        let uploads = remote.uploads.load(Ordering::SeqCst);
        remote.head_conditions.lock().unwrap().clear();
        remote.before_advance(|_| panic!("a landed push advances nothing"));
        let steps = push(&remote, &store, s.ahead, RefWriteCondition::Match(s.c[2])).unwrap();
        assert_eq!(steps, 1, "tickets: {tickets}");
        assert_eq!(remote.read_ref(HEAD).unwrap(), Some(s.ahead));
        assert_eq!(remote.read_ref(&packmap_ref("main")).unwrap(), packmap);
        assert_eq!(remote.uploads.load(Ordering::SeqCst), uploads);
        assert!(remote.head_conditions.lock().unwrap().is_empty());
    }
}

/// A commit whose tree holds the given objects.
fn commit_objects(store: &ObjectStore, files: &[(&str, Hash)], parents: &[Hash], seed: u8) -> Hash {
    let mut entries: Vec<TreeEntry> = files
        .iter()
        .map(|(name, hash)| TreeEntry {
            name: name.as_bytes().to_vec(),
            mode: EntryMode::Blob,
            object_hash: *hash,
        })
        .collect();
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    let tree = put(store, &Object::Tree(Tree { entries }));
    put(
        store,
        &Object::Commit(Commit::new_unannotated(
            tree,
            parents.to_vec(),
            Identity::ed25519([7; 32]),
            [0; 32],
            vec![seed],
            u64::from(seed),
            [0; 64],
        )),
    )
}

/// A chunked file of the given chunk contents.
fn chunked_file(store: &ObjectStore, chunks: &[&str]) -> Hash {
    let mut end = 0u64;
    let entries: Vec<(Hash, u64)> = chunks
        .iter()
        .map(|data| {
            let data = data.repeat(200).into_bytes();
            end += data.len() as u64;
            (put(store, &Object::Blob(Blob { data })), end)
        })
        .collect();
    put(
        store,
        &Object::ChunkedBlob(kit_core::object::ChunkedBlob::new(end, 0, entries).unwrap()),
    )
}

/// The same check as [`rebuilds`], for any branch.
fn branch_rebuilds(remote: &Remote<'_>, branch: &str, head: Hash) -> bool {
    let (_dir, fresh) = store();
    let mut nodes = Vec::new();
    let mut cursor = remote.read_ref(&packmap_ref(branch)).unwrap();
    while let Some(key) = cursor {
        let node = transfer::decode_packlist(
            &remote
                .download_blob(&PackKey::from_hash(key), None, u64::MAX)
                .unwrap(),
        )
        .unwrap();
        cursor = node.prev;
        nodes.push(node);
    }
    nodes.reverse();
    for key in nodes.iter().flat_map(|node| &node.packs) {
        let bytes = remote
            .download_blob(&PackKey::from_hash(*key), None, u64::MAX)
            .unwrap();
        if PackReader::read(&bytes, &fresh).is_err() {
            return false;
        }
    }
    reachable_objects(&fresh, &head).is_ok()
}

fn push_branch(
    remote: &Remote<'_>,
    store: &ObjectStore,
    branch: &str,
    tip: Hash,
    condition: RefWriteCondition,
) {
    push_branch_steps(
        &TransportSource::new(remote),
        store,
        branch,
        tip,
        condition,
        DEPTH,
        pack::MAX_TOTAL_PAYLOAD,
        &PushControl::default(),
        &mut |_| Ok(()),
    )
    .unwrap();
    assert_eq!(
        remote.read_ref(&format!("refs/heads/{branch}")).unwrap(),
        Some(tip)
    );
    assert!(
        branch_rebuilds(remote, branch, tip),
        "{branch} must clone after the push"
    );
}

/// Every branch a push publishes can be cloned: its packmap chain rebuilds
/// the closure of its head. The pushes edit, rename and merge a chunked
/// file, branch from an earlier commit, and force a branch onto an unrelated
/// history that holds one of the files, on every kind of advance.
#[test]
fn every_pushed_branch_can_be_cloned() {
    for kind in ["serialized", "ordered", "atomic"] {
        for tickets in [false, true] {
            let case = format!("{kind}, tickets: {tickets}");
            let (_dir, store) = store();
            let remote = Remote {
                atomic: kind == "atomic",
                serialized: kind != "ordered",
                tickets,
                ..Remote::new()
            };
            let note = put(
                &store,
                &Object::Blob(Blob {
                    data: b"note".to_vec(),
                }),
            );
            let big = chunked_file(&store, &["a", "b", "c", "d"]);
            let edited = chunked_file(&store, &["a", "b", "e", "d"]);
            let base = commit_objects(&store, &[("big", big), ("note", note)], &[], 0);
            push_branch(&remote, &store, "main", base, RefWriteCondition::Missing);

            let edit = commit_objects(&store, &[("big", edited), ("note", note)], &[base], 1);
            push_branch(
                &remote,
                &store,
                "main",
                edit,
                RefWriteCondition::Match(base),
            );

            let renamed = commit_objects(&store, &[("moved", edited), ("note", note)], &[edit], 2);
            push_branch(
                &remote,
                &store,
                "main",
                renamed,
                RefWriteCondition::Match(edit),
            );

            // A branch from the first commit that adds a file of its own.
            let extra = chunked_file(&store, &["x", "y"]);
            let feature = commit_objects(
                &store,
                &[("big", big), ("extra", extra), ("note", note)],
                &[base],
                3,
            );
            push_branch(
                &remote,
                &store,
                "feature",
                feature,
                RefWriteCondition::Missing,
            );

            // A merge of the two lines.
            let merged = commit_objects(
                &store,
                &[("extra", extra), ("moved", edited), ("note", note)],
                &[renamed, feature],
                4,
            );
            push_branch(
                &remote,
                &store,
                "main",
                merged,
                RefWriteCondition::Match(renamed),
            );

            // A forced branch onto unrelated history that holds a file the
            // remote has at another path.
            let unrelated = commit_objects(&store, &[("again", edited)], &[], 5);
            push_branch(&remote, &store, "main", unrelated, RefWriteCondition::Any);

            // Every earlier branch still clones.
            assert!(branch_rebuilds(&remote, "feature", feature), "{case}");
        }
    }
}

/// Text that does not compress, so each one fills a pack of its own.
fn bulky(salt: usize) -> String {
    let mut state = salt as u64 + 1;
    (0..6000)
        .map(|_| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            char::from(33 + ((state >> 33) % 94) as u8)
        })
        .collect()
}

/// A line of `count` commits, each with a file of its own that fills a pack.
fn bulky_line(store: &ObjectStore, count: usize) -> Vec<Hash> {
    let mut line: Vec<Hash> = Vec::new();
    for i in 0..count {
        let name = format!("file-{i}");
        let tip = commit(
            store,
            &[(name.as_str(), bulky(i).as_str())],
            line.last().map_or(&[][..], std::slice::from_ref),
            u8::try_from(i).unwrap(),
        );
        line.push(tip);
    }
    line
}

/// The pack payload cap that puts each bulky file in a pack of its own.
const BULKY_CAP: u64 = 4096;
/// The data packs per advance of a remote that sets `tickets`.
const TICKET_BUDGET: usize = 6;

fn push_bulky(
    remote: &Remote<'_>,
    store: &ObjectStore,
    tip: Hash,
    condition: RefWriteCondition,
    control: &PushControl<'_>,
) -> Result<usize, PushError> {
    push_branch_steps(
        &TransportSource::new(remote),
        store,
        "main",
        tip,
        condition,
        DEPTH,
        BULKY_CAP,
        control,
        &mut |_| Ok(()),
    )
}

/// The data packs each advance carried, from the uploads seen at its start.
fn packs_per_advance(remote: &Remote<'_>, before: usize) -> Vec<usize> {
    let seen = remote.uploads_at_advance.lock().unwrap().clone();
    let mut sent = Vec::new();
    let mut last = before;
    for at in seen {
        sent.push(at - last);
        last = at;
    }
    // Nothing is uploaded once the last advance has begun.
    assert_eq!(
        remote.uploads.load(Ordering::SeqCst),
        last,
        "an upload came after the last advance began"
    );
    sent
}

/// A push that needs more data packs than one advance permits lands in
/// several advances, each within the permit, whether the branch is new or
/// the remote already holds an earlier tip.
#[test]
fn a_push_over_the_ticket_budget_splits_into_advances_within_it() {
    for first in [false, true] {
        let (_dir, store) = store();
        let remote = Remote {
            atomic: true,
            tickets: true,
            ..Remote::new()
        };
        let line = bulky_line(&store, 14);
        let (condition, before) = if first {
            push_bulky(
                &remote,
                &store,
                line[1],
                RefWriteCondition::Missing,
                &PushControl::default(),
            )
            .unwrap();
            (
                RefWriteCondition::Match(line[1]),
                remote.uploads.load(Ordering::SeqCst),
            )
        } else {
            (RefWriteCondition::Missing, 0)
        };
        remote.uploads_at_advance.lock().unwrap().clear();
        let tip = *line.last().unwrap();
        let steps = push_bulky(&remote, &store, tip, condition, &PushControl::default()).unwrap();

        assert!(steps > 1, "remote holds a tip: {first}, steps: {steps}");
        assert_eq!(remote.read_ref(HEAD).unwrap(), Some(tip));
        assert!(rebuilds(&remote, tip), "remote holds a tip: {first}");
        let sent = packs_per_advance(&remote, before);
        assert_eq!(sent.len(), steps, "remote holds a tip: {first}");
        // Each advance also carries the packmap node, which this remote
        // counts as an upload like any other.
        assert!(
            sent.iter()
                .all(|packs| (2..=TICKET_BUDGET + 1).contains(packs)),
            "remote holds a tip: {first}, uploads per advance: {sent:?}"
        );
    }
}

#[test]
fn a_linear_push_rebuilds_from_an_earlier_tip_across_several_packs() {
    let (_dir, store) = store();
    let remote = Remote {
        atomic: true,
        ..Remote::new()
    };
    let line = bulky_line(&store, 14);
    let base = line[7];
    push_bulky(
        &remote,
        &store,
        base,
        RefWriteCondition::Missing,
        &PushControl::default(),
    )
    .unwrap();
    let before = remote.uploads.load(Ordering::SeqCst);
    remote.uploads_at_advance.lock().unwrap().clear();
    let tip = line[13];

    let steps = push_bulky(
        &remote,
        &store,
        tip,
        RefWriteCondition::Match(base),
        &PushControl::default(),
    )
    .unwrap();

    assert_eq!(steps, 1);
    assert!(packs_per_advance(&remote, before)[0] > 2);
    assert_eq!(remote.read_ref(HEAD).unwrap(), Some(tip));
    assert!(rebuilds(&remote, tip));
}

/// A push within the ticket budget stays one advance.
#[test]
fn a_push_within_the_ticket_budget_is_one_advance() {
    let (_dir, store) = store();
    let remote = Remote {
        atomic: true,
        tickets: true,
        ..Remote::new()
    };
    let line = bulky_line(&store, 4);
    let tip = *line.last().unwrap();
    let steps = push_bulky(
        &remote,
        &store,
        tip,
        RefWriteCondition::Missing,
        &PushControl::default(),
    )
    .unwrap();
    assert_eq!(steps, 1);
    assert_eq!(remote.read_ref(HEAD).unwrap(), Some(tip));
    assert!(rebuilds(&remote, tip));
}

/// Whether a push ended because it was asked to stop, before or after some
/// of its advances were published.
fn interrupted(error: &PushError) -> bool {
    match error {
        PushError::Sync(crate::SyncError::Interrupted) => true,
        PushError::SplitInterrupted { cause, .. } => interrupted(cause),
        _ => false,
    }
}

/// An observer that asks to stop at one poll only.
struct StopAtPoll {
    stop_at: usize,
    polls: AtomicUsize,
}

impl kit_core::observer::Observer<crate::SyncEvent> for StopAtPoll {
    fn cancelled(&self) -> bool {
        self.polls.fetch_add(1, Ordering::SeqCst) + 1 == self.stop_at
    }
}

/// A stop request that arrives at any checkpoint of a split push, the
/// pre-flight dry run of the seal included, ends the push as interrupted.
#[test]
fn a_stop_request_at_any_checkpoint_of_a_split_push_interrupts_it() {
    let (_dir, store) = store();
    let line = bulky_line(&store, 9);
    let tip = *line.last().unwrap();
    let mut stopped = 0;
    for stop_at in 1.. {
        let remote = Remote {
            atomic: true,
            tickets: true,
            ..Remote::new()
        };
        let observer = StopAtPoll {
            stop_at,
            polls: AtomicUsize::new(0),
        };
        let control = PushControl {
            observer: &observer,
            ..PushControl::default()
        };
        let result = push_bulky(&remote, &store, tip, RefWriteCondition::Missing, &control);
        if observer.polls.load(Ordering::SeqCst) < stop_at {
            // The push finished before this many checkpoints.
            assert!(result.is_ok(), "{result:?}");
            break;
        }
        assert!(
            result.as_ref().is_err_and(interrupted),
            "stop at checkpoint {stop_at}: {result:?}"
        );
        stopped += 1;
    }
    assert!(stopped > 3, "{stopped}");
}

/// A push that is re-sent in full after the server lost a delta base, and
/// would then need more data packs than one advance permits, fails before it
/// uploads any of the re-sent packs. It does so for a lease push and for a
/// force push.
#[test]
fn a_retry_that_would_exceed_the_ticket_budget_uploads_nothing() {
    for force in [false, true] {
        let (_dir, store) = store();
        let remote = Remote {
            atomic: true,
            tickets: true,
            ..Remote::new()
        };
        let line = bulky_line(&store, 10);
        // The remote holds the first eight commits, so the first plan of a
        // push of the tenth is two commits; the full closure is all ten.
        let held = line[7];
        let tip = line[9];
        push_bulky(
            &remote,
            &store,
            held,
            RefWriteCondition::Missing,
            &PushControl::default(),
        )
        .unwrap();
        let condition = if force {
            RefWriteCondition::Any
        } else {
            RefWriteCondition::Match(held)
        };
        let before = remote.uploads.load(Ordering::SeqCst);
        remote.uploads_at_advance.lock().unwrap().clear();
        remote.lose_delta_base.store(true, Ordering::SeqCst);

        let result = push_bulky(&remote, &store, tip, condition, &PushControl::default());

        let Err(PushError::RetryTooLarge {
            reason,
            packs,
            limit,
        }) = result
        else {
            panic!("force: {force}: {result:?}");
        };
        assert_eq!(reason, RetryReason::LostDeltaBase, "force: {force}");
        assert_eq!(limit, TICKET_BUDGET, "force: {force}");
        assert!(packs > TICKET_BUDGET, "force: {force}: {packs}");
        // The first attempt uploaded its packs; the retry uploaded none.
        let lost_at = *remote.uploads_at_advance.lock().unwrap().last().unwrap();
        assert!(lost_at > before, "force: {force}");
        assert_eq!(
            remote.uploads.load(Ordering::SeqCst),
            lost_at,
            "force: {force}"
        );
        assert_eq!(remote.read_ref(HEAD).unwrap(), Some(held), "force: {force}");
    }
}
