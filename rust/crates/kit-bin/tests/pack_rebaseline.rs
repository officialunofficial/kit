//! Periodic re-baseline integration tests.
//!
//! `push_branch` bounds a branch's packlist chain depth: once a push would
//! grow the chain past the re-baseline threshold (default 64, see
//! `remote_dispatch::packmap::configured_depth`), it replaces the chain with
//! one node that lists every pack of the chain and then its own. It uploads
//! no pack again. This changes the transfer index only: every commit keeps
//! its hash and stays checkout-able (re-baselining does NOT squash history).
//!
//! ## Injecting a small threshold
//!
//! Two seams, one per kind of test:
//!
//! * The depth-threshold tests exercise the CLI's env-var knob
//!   (`KIT_PACK_REBASELINE_DEPTH`) end-to-end. `std::env::set_var` is
//!   banned by `clippy::disallowed_methods` in this repo (races other
//!   threads on POSIX), so they spawn the real `kit` binary through the
//!   shared harness's env-capable runner (`common::kit_env`) and set the
//!   var on the child `Command` — never on this test process.
//! * The concurrency tests drive `push_branch_with_depth` in-process (they
//!   need to control the exact CAS race, like the divergent-push tests in
//!   `push_delta.rs`) with an explicit small threshold — instead of
//!   reaching the default threshold (64) with ~64 real pushes.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

mod common;

use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::sync::Mutex;

use common::Repo;
use kit_core::hash::Hash;
use kit_core::layout::RepoLayout;
use kit_core::object::Object;
use kit_core::protocol::{PackKey, RefWriteCondition, Transport, TransportResult};
use kit_core::refs::{self, Ref};
use kit_core::store::ObjectStore;
use kit_core::transfer::{self, PackListNode};
use kit_transport_file::FileTransport;
use kit_transport_memory::MemoryTransport;
use libkit::transfer::{
    Error as TransferError, fetch_all, pull_all, push_all, push_branch_with_depth,
};

/// The small threshold the in-process concurrency tests inject via
/// `push_branch_with_depth` — reachable with a handful of pushes,
/// unlike the default 64.
const TEST_DEPTH: usize = 3;

fn head_hash(dir: &Path) -> Hash {
    refs::read_ref(&RepoLayout::single(dir), "main")
        .unwrap()
        .unwrap()
}

fn file_url(dir: &Path) -> String {
    format!("kit+file://{}", dir.display())
}

/// Walk `<remote>`'s packlist chain for `branch` newest-first via the
/// public [`Transport`] verbs (`read_ref` + `download_blob`), exactly the
/// way the push/fetch paths do — so the test never has to assume anything
/// about a transport's on-disk layout.
fn packmap_chain(tx: &dyn Transport, branch: &str) -> Vec<PackListNode> {
    let mut nodes = Vec::new();
    let mut cursor = tx.read_ref(&format!("refs/kit/packmap/{branch}")).unwrap();
    while let Some(key) = cursor {
        let bytes = tx.download_blob(&PackKey::from_hash(key)).unwrap();
        let node = transfer::decode_packlist(&bytes).unwrap();
        cursor = node.prev;
        nodes.push(node);
    }
    nodes
}

/// The pack keys of `chain`, oldest first.
fn chain_packs(chain: &[PackListNode]) -> Vec<Hash> {
    chain
        .iter()
        .rev()
        .flat_map(|node| node.packs.iter().copied())
        .collect()
}

fn all_ancestor_commit_hashes(store: &ObjectStore, tip: Hash) -> HashSet<Hash> {
    let mut out = HashSet::new();
    let mut stack = vec![tip];
    while let Some(h) = stack.pop() {
        if !out.insert(h) {
            continue;
        }
        if let Object::Commit(c) = store.read_object(&h).unwrap() {
            stack.extend(c.parents);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Depth-threshold behaviour, driven through the real binary against a
// `kit+file://` remote (env-var injection via subprocess, see module docs).
// ---------------------------------------------------------------------------

/// The fourth push would grow the chain past depth 3, so it replaces the
/// chain with one node. The node lists the three packs the chain held, in
/// their order, and then the pack of the fourth push: nothing is uploaded
/// again, and a clone that holds the first three packs fetches only the
/// fourth. The remote stays fully clonable throughout.
#[test]
fn a_push_past_depth_3_over_the_file_transport_re_baselines_the_chain() {
    let alice = Repo::new();
    let remote = tempfile::tempdir().unwrap();
    let url = file_url(remote.path());
    alice.ok(&["remote", "add", &url]);

    let mut held = Vec::new();
    let mut tips = Vec::new();
    for i in 0..4u32 {
        alice.commit_file("f.txt", i.to_string().as_bytes(), &format!("c{i}"));
        tips.push(head_hash(alice.path()));
        alice.ok_env(&["push"], &[("KIT_PACK_REBASELINE_DEPTH", "3")]);
        let chain = packmap_chain(&FileTransport::new(remote.path()), "main");
        let want = if i < 3 {
            usize::try_from(i).unwrap() + 1
        } else {
            1
        };
        assert_eq!(chain.len(), want, "after push {i}");
        if i < 3 {
            held = chain_packs(&chain);
        }
    }
    let final_tip = *tips.last().unwrap();

    let tx = FileTransport::new(remote.path());
    let chain = packmap_chain(&tx, "main");
    assert_eq!(
        chain[0].prev, None,
        "the fourth push re-baselined the chain"
    );
    assert_eq!(held.len(), 3);
    assert_eq!(chain[0].packs.len(), 4);
    assert_eq!(
        chain[0].packs[..3],
        held,
        "the packs of the chain it replaced"
    );
    assert_eq!(
        tx.read_ref("refs/heads/main").unwrap(),
        Some(final_tip),
        "head must resolve to the latest tip"
    );

    // The remote stays clonable, and a fresh clone reconstructs every
    // commit with unchanged hashes.
    let dest = tempfile::tempdir().unwrap();
    let xdg = tempfile::tempdir().unwrap();
    let out = common::kit(dest.path(), xdg.path(), &["clone", &url, "bob"]);
    assert!(out.status.success(), "clone failed: {out:?}");
    let bob = dest.path().join("bob");
    assert_eq!(head_hash(&bob), final_tip);
    let bob_store = ObjectStore::open(&RepoLayout::single(&bob)).unwrap();
    let ancestry = all_ancestor_commit_hashes(&bob_store, final_tip);
    for tip in &tips {
        assert!(
            ancestry.contains(tip),
            "commit {tip:?} missing from the reconstructed history"
        );
    }
    assert_eq!(ancestry.len(), 4, "all 4 commits, and only those, present");
    assert_eq!(fs::read(bob.join("f.txt")).unwrap(), b"3");
}

#[test]
fn two_pushes_below_depth_3_threshold_keep_two_nodes() {
    let alice = Repo::new();
    let remote = tempfile::tempdir().unwrap();
    let url = file_url(remote.path());
    alice.ok(&["remote", "add", &url]);

    for i in 0..2u32 {
        alice.commit_file("f.txt", i.to_string().as_bytes(), &format!("c{i}"));
        alice.ok_env(&["push"], &[("KIT_PACK_REBASELINE_DEPTH", "3")]);
    }

    let tx = FileTransport::new(remote.path());
    let chain = packmap_chain(&tx, "main");
    assert_eq!(
        chain.len(),
        2,
        "no re-baseline while the chain is still below the threshold"
    );
}

#[test]
fn depth_zero_disables_rebaseline() {
    let alice = Repo::new();
    let remote = tempfile::tempdir().unwrap();
    let url = file_url(remote.path());
    alice.ok(&["remote", "add", &url]);

    for i in 0..4u32 {
        alice.commit_file("f.txt", i.to_string().as_bytes(), &format!("c{i}"));
        alice.ok_env(&["push"], &[("KIT_PACK_REBASELINE_DEPTH", "0")]);
    }

    let tx = FileTransport::new(remote.path());
    let chain = packmap_chain(&tx, "main");
    assert_eq!(
        chain.len(),
        4,
        "KIT_PACK_REBASELINE_DEPTH=0 must disable re-baselining"
    );
}

// ---------------------------------------------------------------------------
// Concurrency: a divergent push whose depth check WOULD re-baseline.
// ---------------------------------------------------------------------------

/// A [`MemoryTransport`] wrapper with a genuinely atomic `advance_refs`:
/// both preconditions are checked under one lock before either ref is
/// written, so a losing push never commits half of a two-ref advance.
/// This models the transactional advance of a production remote, such
/// as the native HTTP transport.
///
/// The plain default `advance_refs` (used by [`MemoryTransport`] and
/// exercised by `push_delta.rs`) commits packmap-then-head sequentially,
/// and so, for readers, does [`FileTransport`]'s locked advance. The tests
/// below check that a losing push leaves the remote untouched, which only
/// an atomic advance promises.
struct AtomicTransport {
    inner: MemoryTransport,
    lock: Mutex<()>,
}

impl AtomicTransport {
    fn new() -> Self {
        Self {
            inner: MemoryTransport::new(),
            lock: Mutex::new(()),
        }
    }
}

fn condition_holds(condition: RefWriteCondition, current: Option<Hash>) -> bool {
    match condition {
        RefWriteCondition::Any => true,
        RefWriteCondition::Missing => current.is_none(),
        RefWriteCondition::Match(h) => current == Some(h),
    }
}

impl Transport for AtomicTransport {
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
    ) -> TransportResult<kit_core::protocol::AdvanceOutcome> {
        use kit_core::protocol::AdvanceOutcome;
        let _guard = self.lock.lock().unwrap();
        if !condition_holds(packmap_condition, self.inner.read_ref(packmap_ref)?) {
            return Ok(AdvanceOutcome::PackmapConflict);
        }
        if !condition_holds(head_condition, self.inner.read_ref(head_ref)?) {
            return Ok(AdvanceOutcome::HeadConflict);
        }
        self.inner
            .update_ref(packmap_ref, packmap_condition, packmap_value)?;
        self.inner
            .update_ref(head_ref, head_condition, head_value)?;
        Ok(AdvanceOutcome::Committed)
    }

    // This transport's `advance_refs` above commits the head and packmap
    // write as one indivisible transaction: both preconditions are checked
    // under one lock before either write lands.
    fn supports_atomic_advance(&self) -> bool {
        true
    }
}

/// `TEST_DEPTH - 1` plain appending pushes of successive `f.txt` contents
/// (`"1"`, `"2"`, …) on top of an already-pushed base commit, growing the
/// remote's chain for `main` to exactly [`TEST_DEPTH`] nodes — the depth at
/// which the NEXT push would itself re-baseline
/// (`TEST_DEPTH + 1 > TEST_DEPTH`). Returns the final tip.
///
/// These build-up pushes go through the ordinary [`push_all`] (default
/// threshold): they sit far below it, so they append — only the decisive
/// push under test injects [`TEST_DEPTH`] via `push_branch_with_depth`.
fn grow_chain_to_test_depth(alice: &Repo, tx: &dyn Transport) -> Hash {
    for i in 1..TEST_DEPTH {
        alice.commit_file("f.txt", i.to_string().as_bytes(), &format!("alice-{i}"));
        push_all(alice.path(), tx).unwrap_or_else(|e| panic!("push alice-{i}: {e}"));
    }
    assert_eq!(packmap_chain(tx, "main").len(), TEST_DEPTH);
    head_hash(alice.path())
}

#[test]
#[allow(clippy::too_many_lines)] // one scenario: race, blocked re-baseline, retry, re-clone
fn divergent_push_that_would_rebaseline_blocks_then_retry_stays_clonable() {
    // Drives `push_branch_with_depth` in-process (like the existing
    // divergent-push tests in push_delta.rs) to control the exact CAS
    // race, at an injected small threshold instead of reaching the
    // default one with ~64 real pushes.
    let alice = Repo::new();
    let bob = Repo::new();

    let tx = AtomicTransport::new();
    alice.commit_file("f.txt", b"0", "base");
    push_all(alice.path(), &tx).expect("alice base push");
    pull_all(bob.path(), &tx, "default", None).expect("bob clones base");
    let shared_tip = head_hash(alice.path());

    // The base push above already contributed the chain's first node;
    // grow to TEST_DEPTH exactly (the next push is the one that would
    // itself re-baseline).
    let alice_tip = grow_chain_to_test_depth(&alice, &tx);

    // bob, still at the shared base, races with a stale expectation. The
    // remote's current depth (TEST_DEPTH) means this push, if it reached
    // the packmap CAS, WOULD re-baseline (TEST_DEPTH + 1 > TEST_DEPTH).
    bob.commit_file("f.txt", b"bob-divergent", "bob-divergent");
    let bob_tip = head_hash(bob.path());
    let bob_store = ObjectStore::open(&RepoLayout::single(bob.path())).unwrap();

    let err = push_branch_with_depth(
        &tx,
        &bob_store,
        "main",
        bob_tip,
        RefWriteCondition::Match(shared_tip),
        TEST_DEPTH,
    )
    .unwrap_err();
    assert!(
        matches!(err, TransferError::NonFastForwardPush { .. }),
        "expected NonFastForwardPush, got {err:?}"
    );

    // The remote must be untouched: bob's push is refused before it writes
    // a re-baseline node.
    assert_eq!(tx.read_ref("refs/heads/main").unwrap(), Some(alice_tip));
    assert_eq!(packmap_chain(&tx, "main").len(), TEST_DEPTH);
    let carol = Repo::new();
    pull_all(carol.path(), &tx, "default", None)
        .expect("remote must stay clonable after the loser's blocked re-baseline");
    assert_eq!(
        fs::read(carol.path().join("f.txt")).unwrap(),
        (TEST_DEPTH - 1).to_string().as_bytes()
    );

    // The loser retries: fast-forward onto alice's tip, recommit, push
    // again. The chain is still at TEST_DEPTH, so this retry ALSO decides
    // to re-baseline — and this time it wins the head CAS outright (nothing
    // else moved the head), collapsing the chain to one node that lists
    // every pack of the merged history.
    fetch_all(bob.path(), &tx, "default").expect("bob's retry fetch");
    let alice_hex = kit_core::to_hex(&alice_tip);
    bob.ok(&["reset", "--hard", "-f", &alice_hex]);
    bob.commit_file("f.txt", b"bob-retry", "bob-retry");
    let bob_retry_tip = head_hash(bob.path());
    let bob_store2 = ObjectStore::open(&RepoLayout::single(bob.path())).unwrap();
    push_branch_with_depth(
        &tx,
        &bob_store2,
        "main",
        bob_retry_tip,
        RefWriteCondition::Match(alice_tip),
        TEST_DEPTH,
    )
    .expect("bob's retry push should succeed");

    assert_eq!(tx.read_ref("refs/heads/main").unwrap(), Some(bob_retry_tip));
    let chain = packmap_chain(&tx, "main");
    assert_eq!(chain.len(), 1, "retry re-baseline collapses the chain");
    assert_eq!(chain[0].packs.len(), TEST_DEPTH + 1);

    // Still clonable, with the full merged history (alice's base +
    // TEST_DEPTH - 1 appending commits, plus bob's retried commit) present
    // and hash-verified.
    let dave = Repo::new();
    pull_all(dave.path(), &tx, "default", None).expect("clone after the retry re-baseline");
    assert_eq!(fs::read(dave.path().join("f.txt")).unwrap(), b"bob-retry");
    let dave_tip = head_hash(dave.path());
    assert_eq!(dave_tip, bob_retry_tip);
    let dave_store = ObjectStore::open(&RepoLayout::single(dave.path())).unwrap();
    let ancestry = all_ancestor_commit_hashes(&dave_store, dave_tip);
    assert_eq!(
        ancestry.len(),
        TEST_DEPTH + 1,
        "base + {} alice commits + bob's retry commit",
        TEST_DEPTH - 1
    );
    for h in &ancestry {
        let bytes = dave_store
            .read(h)
            .expect("object present and hash-verified");
        assert_eq!(
            kit_core::serialize::deserialize(&bytes)
                .unwrap()
                .id()
                .unwrap(),
            *h
        );
    }
}

/// A force push (`RefWriteCondition::Any`) that reaches the re-baseline
/// threshold on an atomic transport takes the guarded force driver, which
/// appends. The next conditioned push re-baselines the chain.
#[test]
fn force_push_at_threshold_appends_and_never_resets() {
    let alice = Repo::new();
    let tx = AtomicTransport::new();
    alice.commit_file("f.txt", b"0", "base");
    push_all(alice.path(), &tx).expect("alice base push");
    grow_chain_to_test_depth(&alice, &tx);

    // A FORCE push (unconditional `Any` head condition) of a new
    // fast-forward commit. The chain sits at TEST_DEPTH, so a
    // CAS-conditioned push would re-baseline here.
    alice.commit_file("f.txt", b"forced", "forced");
    let forced_tip = head_hash(alice.path());
    let store = ObjectStore::open(&RepoLayout::single(alice.path())).unwrap();
    push_branch_with_depth(
        &tx,
        &store,
        "main",
        forced_tip,
        RefWriteCondition::Any,
        TEST_DEPTH,
    )
    .expect("force push at threshold should append, not reset");

    // Appended, not reset: the chain grew to TEST_DEPTH + 1 and its NEWEST
    // node still chains to a `Some` prev (a re-baseline would leave one
    // lone `prev = None` node, i.e. `chain.len() == 1`). `packmap_chain`
    // walks newest-first, so `chain[0]` is that newest node.
    let chain = packmap_chain(&tx, "main");
    assert_eq!(
        chain.len(),
        TEST_DEPTH + 1,
        "a force push at the threshold must append, not reset to a single node"
    );
    assert!(
        chain[0].prev.is_some(),
        "newest node reset to prev = None — a re-baseline leaked through on an `Any` force push"
    );
    assert_eq!(tx.read_ref("refs/heads/main").unwrap(), Some(forced_tip));

    // The remote stays clonable with the full history intact.
    let bob = Repo::new();
    pull_all(bob.path(), &tx, "default", None).expect("clone after the force-push append");
    assert_eq!(fs::read(bob.path().join("f.txt")).unwrap(), b"forced");
    assert_eq!(head_hash(bob.path()), forced_tip);
    let bob_store = ObjectStore::open(&RepoLayout::single(bob.path())).unwrap();
    let ancestry = all_ancestor_commit_hashes(&bob_store, forced_tip);
    assert_eq!(
        ancestry.len(),
        TEST_DEPTH + 1,
        "base + {} appending commits + the forced commit",
        TEST_DEPTH - 1
    );
}
