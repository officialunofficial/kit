//! The re-baseline gate on a serialized advance, and a force push racing a
//! reset.
//!
//! Every test checks the invariant a reader relies on: whenever the head
//! resolves to `T`, the packmap chain rebuilds the closure of `T`. A
//! serialized advance writes the packmap before the head, so a reader
//! between the writes, and a crash between them, pairs the new packmap with
//! the old head; the tests check that pair too.

use super::{PushControl, PushError, push_branch_steps};
use crate::TransportSource;
use crate::packmap::packmap_ref;
use kit_core::hash::Hash;
use kit_core::layout::RepoLayout;
use kit_core::object::{Blob, Commit, EntryMode, Identity, Object, Tree, TreeEntry};
use kit_core::ops::graph::reachable_objects;
use kit_core::pack::{self, PackReader};
use kit_core::protocol::{AdvanceOutcome, PackKey, Transport, TransportError, TransportResult};
use kit_core::refs::{Ref, RefWriteCondition};
use kit_core::store::ObjectStore;
use kit_core::{serialize, transfer};
use kit_transport_memory::MemoryTransport;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use tempfile::TempDir;

const HEAD: &str = "refs/heads/main";
const DEPTH: usize = 3;

type Hook<'a> = Box<dyn FnOnce(&Remote<'a>) + Send + 'a>;

/// A remote whose two-ref advance checks both conditions under one lock,
/// then writes the packmap, then the head: serialized for writers, ordered
/// for readers. `atomic` makes it claim an atomic advance instead, and
/// `serialized = false` makes it claim neither.
struct Remote<'a> {
    inner: MemoryTransport,
    lock: Mutex<()>,
    atomic: bool,
    serialized: bool,
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
    fn upload_pack(&self, bytes: &[u8], key: &PackKey) -> TransportResult<()> {
        self.inner.upload_pack(bytes, key)
    }
    fn download_pack(&self, key: &PackKey) -> TransportResult<Vec<u8>> {
        self.inner.download_pack(key)
    }
    fn pack_exists(&self, key: &PackKey) -> TransportResult<bool> {
        self.inner.pack_exists(key)
    }
    fn update_ref(
        &self,
        name: &str,
        condition: RefWriteCondition,
        hash: &Hash,
    ) -> TransportResult<()> {
        self.inner.update_ref(name, condition, hash)
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
    fn supports_atomic_advance(&self) -> bool {
        self.atomic
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
    push_branch_steps(
        &TransportSource::new(remote),
        store,
        "main",
        tip,
        condition,
        DEPTH,
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
        let node =
            transfer::decode_packlist(&remote.download_blob(&PackKey::from_hash(key)).unwrap())
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
        let bytes = remote.download_pack(&PackKey::from_hash(*key)).unwrap();
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

#[test]
fn a_fast_forward_resets_the_chain_on_a_serialized_advance() {
    let (_dir, store) = store();
    let remote = Remote::new();
    let s = setup(&store, &remote);
    push(&remote, &store, s.ahead, RefWriteCondition::Match(s.c[2])).unwrap();
    assert_eq!(remote.read_ref(HEAD).unwrap(), Some(s.ahead));
    let nodes = chain(&remote);
    assert_eq!(nodes.len(), 1, "the fast-forward re-baselines");
    assert_eq!(nodes[0].prev, None);
    assert!(rebuilds(&remote, s.ahead));
}

/// A lease push that is not a fast-forward of the head it conditions on
/// appends: a reset would leave that head unrebuildable between the writes.
#[test]
fn a_push_that_is_not_a_fast_forward_appends_on_a_serialized_advance() {
    let (_dir, store) = store();
    let remote = Remote::new();
    let s = setup(&store, &remote);
    push(&remote, &store, s.aside, RefWriteCondition::Match(s.c[2])).unwrap();
    assert_eq!(remote.read_ref(HEAD).unwrap(), Some(s.aside));
    assert_eq!(chain(&remote).len(), DEPTH + 1, "no reset");
    assert!(rebuilds(&remote, s.aside));
}

/// A remote that offers neither advance never resets, even for a
/// fast-forward.
#[test]
fn a_fast_forward_appends_on_an_ordered_advance() {
    let (_dir, store) = store();
    let remote = Remote {
        serialized: false,
        ..Remote::new()
    };
    let s = setup(&store, &remote);
    push(&remote, &store, s.ahead, RefWriteCondition::Match(s.c[2])).unwrap();
    assert_eq!(chain(&remote).len(), DEPTH + 1);
    assert!(rebuilds(&remote, s.ahead));
}

/// An atomic advance commits both refs as one step, so it resets any
/// conditioned push, a fast-forward or not.
#[test]
fn an_atomic_advance_resets_a_push_that_is_not_a_fast_forward() {
    let (_dir, store) = store();
    let remote = Remote {
        atomic: true,
        ..Remote::new()
    };
    let s = setup(&store, &remote);
    push(&remote, &store, s.aside, RefWriteCondition::Match(s.c[2])).unwrap();
    assert_eq!(chain(&remote).len(), 1);
    assert!(rebuilds(&remote, s.aside));
}

/// A crash between the packmap write and the head write leaves the old
/// head with the new packmap, and that packmap rebuilds the old head: the
/// fast-forward's reset holds its closure, and the other push appended.
#[test]
fn a_crash_between_the_writes_leaves_the_old_head_rebuildable() {
    for (fast_forward, nodes_after) in [(true, 1), (false, DEPTH + 1)] {
        let (_dir, store) = store();
        let remote = Remote::new();
        let s = setup(&store, &remote);
        let tip = if fast_forward { s.ahead } else { s.aside };
        remote.crash.store(true, Ordering::SeqCst);
        assert!(push(&remote, &store, tip, RefWriteCondition::Match(s.c[2])).is_err());
        assert_eq!(remote.read_ref(HEAD).unwrap(), Some(s.c[2]));
        assert_eq!(chain(&remote).len(), nodes_after, "{fast_forward}");
        assert!(rebuilds(&remote, s.c[2]), "{fast_forward}");
        // The next push from that state lands.
        push(&remote, &store, tip, RefWriteCondition::Match(s.c[2])).unwrap();
        assert!(rebuilds(&remote, tip), "{fast_forward}");
    }
}

/// A force push plans its packs against the head it reads, then appends
/// them. Here, between its plan and its advance, a lease push moves the
/// head aside and a fast-forward of that resets the chain, dropping the
/// objects the force push left out as already held (`keep`). An ordered
/// force append would then publish a head the chain cannot rebuild. On a
/// serialized advance the force push takes the guarded driver, sees the
/// reset drop the chain its plan relied on, and plans again.
#[test]
fn a_force_push_racing_a_reset_plans_again() {
    let (_dir, store) = store();
    let remote = Remote::new();
    let s = setup(&store, &remote);
    let forced = s.ahead;
    let beyond = commit(&store, &[("a", "beyond")], &[s.aside], 5);
    let (aside, c2) = (s.aside, s.c[2]);
    let store_ref = &store;
    remote.before_advance(move |remote| {
        push(remote, store_ref, aside, RefWriteCondition::Match(c2)).unwrap();
        push(remote, store_ref, beyond, RefWriteCondition::Match(aside)).unwrap();
        assert_eq!(chain(remote).len(), 1, "the fast-forward re-baselined");
    });
    push(&remote, &store, forced, RefWriteCondition::Any).unwrap();
    assert_eq!(remote.read_ref(HEAD).unwrap(), Some(forced));
    assert!(rebuilds(&remote, forced));
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
