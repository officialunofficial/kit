//! A fetch holds no repository lock while it downloads and applies packs, and
//! gc deletes none of its objects.
//!
//! The remote is a chain of commits with one pack each. Two seams pause a
//! fetch: a source that blocks, or panics, in the k-th pack download, and an
//! observer that blocks on the k-th `ObjectsUnpacked` event.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::collections::BTreeSet;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Barrier, Mutex};
use std::time::{Duration, Instant};

use kit_core::hash::{self, Hash};
use kit_core::layout::RepoLayout;
use kit_core::object::{Blob, Commit, EntryMode, Identity, Object, Tree, TreeEntry};
use kit_core::ops::run_gc;
use kit_core::pack::{self, PackWriter};
use kit_core::protocol::{PackKey, Transport};
use kit_core::refs::{self, RefWriteCondition};
use kit_core::repo_lock::{self, WORKTREE_LOCK};
use kit_core::sign::{self, KeyPair};
use kit_core::store::ObjectStore;
use kit_core::{delta, serialize, transfer};
use kit_sync::{
    AppliedPacks, CloneRemote, FetchReport, NoopObserver, Observer, PullOutcome, RemoteSource,
    SourceError, SyncError, SyncEvent, SyncOptions, TransportSource, clone, fetch, init_clone_dir,
    pull,
};
use kit_transport_memory::MemoryTransport;

const WAIT: Duration = Duration::from_secs(60);

/// A remote whose `main` is a chain of commits, each added in a pack of its
/// own that a new packmap node lists.
struct Remote {
    tx: MemoryTransport,
    key: KeyPair,
    packmap_head: Option<Hash>,
    tip: Option<Hash>,
    files: Vec<(String, Vec<u8>)>,
    /// Pack keys, oldest first.
    packs: Vec<Hash>,
    /// The ids of each pack's objects.
    objects: Vec<Vec<Hash>>,
}

fn blob(data: &[u8]) -> Object {
    Object::Blob(Blob {
        data: data.to_vec(),
    })
}

/// Bytes that do not compress or repeat, so a delta against them is small.
fn noise(len: usize, seed: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut block = 0u32;
    while out.len() < len {
        out.extend_from_slice(&hash::hash(&[&block.to_le_bytes()[..], &[seed]].concat()));
        block += 1;
    }
    out.truncate(len);
    out
}

impl Remote {
    fn new() -> Self {
        Self {
            tx: MemoryTransport::new(),
            key: KeyPair::generate().unwrap(),
            packmap_head: None,
            tip: None,
            files: Vec::new(),
            packs: Vec::new(),
            objects: Vec::new(),
        }
    }

    /// Commit a new file in a pack of its own: the blob, the tree and the
    /// commit.
    fn push_file(&mut self, name: &str, data: &[u8]) -> Hash {
        let blob = blob(data);
        let mut writer = PackWriter::new();
        writer
            .push_raw(blob.id().unwrap(), &serialize::serialize(&blob).unwrap())
            .unwrap();
        self.finish_commit(name, data, writer, vec![blob.id().unwrap()])
    }

    /// Commit a new file whose blob is a delta against the blob of the file
    /// `base`, which an earlier pack holds.
    fn push_delta_file(&mut self, name: &str, base: &str, data: &[u8]) -> Hash {
        let base_data = &self.files.iter().find(|(n, _)| n == base).unwrap().1;
        let base_blob = blob(base_data);
        let target = blob(data);
        let stream = delta::encode(
            &serialize::serialize(&base_blob).unwrap(),
            &serialize::serialize(&target).unwrap(),
        )
        .unwrap();
        let mut writer = PackWriter::new();
        writer
            .push_delta(&base_blob.id().unwrap(), &stream)
            .unwrap();
        self.finish_commit(name, data, writer, vec![target.id().unwrap()])
    }

    fn finish_commit(
        &mut self,
        name: &str,
        data: &[u8],
        mut writer: PackWriter,
        mut ids: Vec<Hash>,
    ) -> Hash {
        self.files.push((name.to_owned(), data.to_vec()));
        let mut entries: Vec<TreeEntry> = self
            .files
            .iter()
            .map(|(name, data)| TreeEntry {
                name: name.as_bytes().to_vec(),
                mode: EntryMode::Blob,
                object_hash: blob(data).id().unwrap(),
            })
            .collect();
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        let tree = Object::Tree(Tree { entries });
        let mut commit = Commit::new_unannotated(
            tree.id().unwrap(),
            self.tip.into_iter().collect(),
            Identity::ed25519(self.key.public.0),
            self.key.public.0,
            format!("add {name}").into_bytes(),
            1_700_000_000 + self.packs.len() as u64,
            [0u8; 64],
        );
        commit.signature = sign::sign_commit(&commit, &self.key).unwrap().0;
        let commit = Object::Commit(commit);
        for object in [&tree, &commit] {
            writer
                .push_raw(object.id().unwrap(), &serialize::serialize(object).unwrap())
                .unwrap();
            ids.push(object.id().unwrap());
        }
        let tip = commit.id().unwrap();
        let bytes = writer.finish().unwrap();
        let pack_key = pack::pack_key(&bytes);
        self.tx
            .upload_pack(&bytes, &PackKey::from_hash(pack_key))
            .unwrap();
        let node = transfer::encode_packlist(self.packmap_head, &[pack_key]).unwrap();
        let node_key = hash::hash(&node);
        self.tx
            .upload_blob(&node, &PackKey::from_hash(node_key))
            .unwrap();
        let (packmap_condition, head_condition) = match (self.packmap_head, self.tip) {
            (Some(node), Some(tip)) => (
                RefWriteCondition::Match(node),
                RefWriteCondition::Match(tip),
            ),
            _ => (RefWriteCondition::Missing, RefWriteCondition::Missing),
        };
        self.tx
            .update_ref("refs/kit/packmap/main", packmap_condition, &node_key)
            .unwrap();
        self.tx
            .update_ref("refs/heads/main", head_condition, &tip)
            .unwrap();
        self.packmap_head = Some(node_key);
        self.tip = Some(tip);
        self.packs.push(pack_key);
        self.objects.push(ids);
        tip
    }

    /// A chain of `count` commits, one file each.
    fn with_commits(count: usize) -> Self {
        let mut remote = Self::new();
        for i in 0..count {
            remote.push_file(&format!("f{i}.txt"), format!("content {i}\n").as_bytes());
        }
        remote
    }

    fn tip(&self) -> Hash {
        self.tip.unwrap()
    }

    fn source(&self) -> TransportSource<'_> {
        TransportSource::new(&self.tx)
    }
}

fn clone_remote() -> CloneRemote {
    CloneRemote {
        name: "origin".to_owned(),
        url: "kit+memory://unlocked".to_owned(),
        kind: "memory".to_owned(),
    }
}

/// A fresh clone directory with no objects fetched.
fn fresh_target() -> (tempfile::TempDir, std::path::PathBuf, RepoLayout) {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("work");
    let layout = init_clone_dir(&target, &clone_remote()).unwrap();
    (dir, target, layout)
}

fn run_fetch(
    target: &Path,
    source: &dyn RemoteSource,
    observer: &dyn Observer<SyncEvent>,
) -> Result<FetchReport, SyncError> {
    fetch(target, source, "origin", &SyncOptions::default(), observer)
}

fn tracking_tip(layout: &RepoLayout) -> Option<Hash> {
    refs::read_remote_ref(layout, "origin", "main").unwrap()
}

/// Run gc at grace zero over the clone, with no process-level locks. A gc
/// that had to wait for the worktree lock is the caller's concern.
fn gc_now(layout: &RepoLayout) -> kit_core::ops::GcReport {
    let store = ObjectStore::open(layout).unwrap();
    run_gc(&store, layout, u64::MAX, 0, false).unwrap()
}

fn assert_closure_complete(layout: &RepoLayout, tip: Hash) {
    let store = ObjectStore::open(layout).unwrap();
    kit_core::ops::reachable_objects(&store, &tip)
        .expect("every object reachable from the published tip is present");
}

fn worktree_lock_is_free(layout: &RepoLayout) -> bool {
    repo_lock::acquire(
        layout.worktree_state_dir(),
        WORKTREE_LOCK,
        Duration::from_millis(100),
    )
    .is_ok()
}

// ---------------------------------------------------------------------------
// Pausing seams
// ---------------------------------------------------------------------------

/// Blocks the thread that calls [`Gate::hit`] until the test resumes it.
struct Gate {
    reached: Sender<()>,
    go: Mutex<Receiver<()>>,
}

/// The test's end of a [`Gate`].
struct Pause {
    reached: Receiver<()>,
    go: Sender<()>,
}

fn gate() -> (Gate, Pause) {
    let (reached_tx, reached_rx) = channel();
    let (go_tx, go_rx) = channel();
    (
        Gate {
            reached: reached_tx,
            go: Mutex::new(go_rx),
        },
        Pause {
            reached: reached_rx,
            go: go_tx,
        },
    )
}

impl Gate {
    fn hit(&self) {
        let _ = self.reached.send(());
        let _ = self.go.lock().unwrap().recv();
    }
}

impl Pause {
    fn wait_reached(&self) {
        self.reached
            .recv_timeout(WAIT)
            .expect("the fetch reached its pause point");
    }
}

/// Resumes a paused fetch when dropped, so a failed assertion cannot leave
/// the scope waiting forever on a blocked thread.
struct ResumeOnDrop<'a>(&'a Pause);

impl Drop for ResumeOnDrop<'_> {
    fn drop(&mut self) {
        let _ = self.0.go.send(());
    }
}

enum Action<'a> {
    Count,
    Panic,
    Pause(&'a Gate),
    /// Wait for the other fetch, then continue.
    Meet(&'a Barrier),
}

/// Delegates to a transport and does `action` in the `at`-th pack download,
/// counting from one.
struct HookSource<'a> {
    inner: TransportSource<'a>,
    downloads: AtomicUsize,
    at: usize,
    action: Action<'a>,
}

impl<'a> HookSource<'a> {
    fn new(remote: &'a Remote, at: usize, action: Action<'a>) -> Self {
        Self {
            inner: remote.source(),
            downloads: AtomicUsize::new(0),
            at,
            action,
        }
    }

    fn counting(remote: &'a Remote) -> Self {
        Self::new(remote, 0, Action::Count)
    }

    fn downloads(&self) -> usize {
        self.downloads.load(Ordering::SeqCst)
    }
}

impl RemoteSource for HookSource<'_> {
    fn list_branches(&self) -> Result<Vec<refs::Ref>, SourceError> {
        self.inner.list_branches()
    }
    fn read_ref(&self, name: &str) -> Result<Option<Hash>, SourceError> {
        self.inner.read_ref(name)
    }
    fn download_blob_via_ref(&self, key: &PackKey, ref_name: &str) -> Result<Vec<u8>, SourceError> {
        self.inner.download_blob_via_ref(key, ref_name)
    }
    fn download_pack_via_ref(&self, key: &PackKey, ref_name: &str) -> Result<Vec<u8>, SourceError> {
        let n = self.downloads.fetch_add(1, Ordering::SeqCst) + 1;
        if n == self.at {
            match &self.action {
                Action::Count => {}
                Action::Panic => panic!("the fetch dies in download {n}"),
                Action::Pause(gate) => gate.hit(),
                Action::Meet(barrier) => {
                    barrier.wait();
                }
            }
        }
        self.inner.download_pack_via_ref(key, ref_name)
    }
}

/// Records events, and pauses or cancels the fetch at chosen points.
#[derive(Default)]
struct Probe<'a> {
    /// Pause on the `.0`-th `ObjectsUnpacked` event.
    pause_unpack: Option<(usize, &'a Gate)>,
    unpacked: AtomicUsize,
    waiting: AtomicUsize,
    stale: AtomicUsize,
    cancel: AtomicBool,
}

impl Observer<SyncEvent> for Probe<'_> {
    fn event(&self, event: &SyncEvent) {
        match event {
            SyncEvent::ObjectsUnpacked { .. } => {
                let n = self.unpacked.fetch_add(1, Ordering::SeqCst) + 1;
                if let Some((at, gate)) = self.pause_unpack
                    && n == at
                {
                    gate.hit();
                }
            }
            SyncEvent::WaitingForRepoLock => {
                self.waiting.fetch_add(1, Ordering::SeqCst);
            }
            SyncEvent::AppliedPacksStale { .. } => {
                self.stale.fetch_add(1, Ordering::SeqCst);
            }
            _ => {}
        }
    }

    fn cancelled(&self) -> bool {
        self.cancel.load(Ordering::SeqCst)
    }
}

fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + WAIT;
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

// ---------------------------------------------------------------------------
// 1. The lock is free
// ---------------------------------------------------------------------------

#[test]
fn the_lock_is_free_while_a_fetch_downloads() {
    let remote = Remote::with_commits(4);
    let (_dir, target, layout) = fresh_target();
    let (gate, pause) = gate();
    let source = HookSource::new(&remote, 3, Action::Pause(&gate));

    std::thread::scope(|scope| {
        let fetching = scope.spawn(|| run_fetch(&target, &source, &NoopObserver));
        let resume = ResumeOnDrop(&pause);
        pause.wait_reached();
        // Two packs are applied, and the third is in flight.
        assert!(worktree_lock_is_free(&layout));
        assert_eq!(tracking_tip(&layout), None);
        drop(resume);
        fetching.join().unwrap().unwrap();
    });

    assert_eq!(tracking_tip(&layout), Some(remote.tip()));
}

#[test]
fn the_lock_is_free_while_a_fetch_applies() {
    let remote = Remote::with_commits(4);
    let (_dir, target, layout) = fresh_target();
    let (gate, pause) = gate();
    let probe = Probe {
        pause_unpack: Some((2, &gate)),
        ..Probe::default()
    };

    std::thread::scope(|scope| {
        let fetching = scope.spawn(|| run_fetch(&target, &remote.source(), &probe));
        let resume = ResumeOnDrop(&pause);
        pause.wait_reached();
        // The second pack's objects are in the store and no ref names them.
        assert!(worktree_lock_is_free(&layout));
        drop(resume);
        fetching.join().unwrap().unwrap();
    });

    assert_eq!(tracking_tip(&layout), Some(remote.tip()));
}

// ---------------------------------------------------------------------------
// 2. The publish waits
// ---------------------------------------------------------------------------

#[test]
fn the_publish_waits_for_the_lock_and_everything_before_it_is_done() {
    let remote = Remote::with_commits(4);
    let (_dir, target, layout) = fresh_target();
    let source = HookSource::counting(&remote);
    let probe = Probe::default();
    let held = repo_lock::acquire_default(layout.worktree_state_dir(), WORKTREE_LOCK).unwrap();

    std::thread::scope(|scope| {
        let fetching = scope.spawn(|| run_fetch(&target, &source, &probe));
        wait_until("the publish wait", || {
            probe.waiting.load(Ordering::SeqCst) > 0
        });
        // Every pack is downloaded and applied; only the publish waits.
        assert_eq!(source.downloads(), 4);
        assert_eq!(tracking_tip(&layout), None);
        std::thread::sleep(Duration::from_millis(300));
        assert!(!fetching.is_finished());
        drop(held);
        let report = fetching.join().unwrap().unwrap();
        assert_eq!(report.packs_downloaded, 4);
    });

    assert_eq!(
        probe.waiting.load(Ordering::SeqCst),
        1,
        "one event per wait"
    );
    assert_eq!(tracking_tip(&layout), Some(remote.tip()));
    assert_closure_complete(&layout, remote.tip());
}

#[test]
fn the_publish_wait_honours_an_interrupt_and_keeps_the_work() {
    let remote = Remote::with_commits(3);
    let (_dir, target, layout) = fresh_target();
    let probe = Probe::default();
    let held = repo_lock::acquire_default(layout.worktree_state_dir(), WORKTREE_LOCK).unwrap();

    std::thread::scope(|scope| {
        let fetching = scope.spawn(|| run_fetch(&target, &remote.source(), &probe));
        wait_until("the publish wait", || {
            probe.waiting.load(Ordering::SeqCst) > 0
        });
        probe.cancel.store(true, Ordering::SeqCst);
        let error = fetching.join().unwrap().unwrap_err();
        assert!(matches!(error, SyncError::Interrupted), "{error:?}");
    });
    drop(held);

    assert_eq!(tracking_tip(&layout), None);
    let applied = AppliedPacks::load(&layout, "origin").unwrap();
    for key in &remote.packs {
        assert!(applied.contains(&PackKey::from_hash(*key)));
    }
    // The next fetch downloads nothing and publishes.
    let source = HookSource::counting(&remote);
    let report = run_fetch(&target, &source, &NoopObserver).unwrap();
    assert_eq!(source.downloads(), 0);
    assert_eq!(report.packs_already_applied, 3);
    assert_eq!(tracking_tip(&layout), Some(remote.tip()));
}

// ---------------------------------------------------------------------------
// 3. gc during a fetch
// ---------------------------------------------------------------------------

#[test]
fn gc_at_grace_zero_prunes_none_of_a_running_fetchs_objects() {
    let remote = Remote::with_commits(4);
    let (_dir, target, layout) = fresh_target();
    let (gate, pause) = gate();
    let probe = Probe {
        pause_unpack: Some((2, &gate)),
        ..Probe::default()
    };

    std::thread::scope(|scope| {
        let fetching = scope.spawn(|| run_fetch(&target, &remote.source(), &probe));
        let resume = ResumeOnDrop(&pause);
        pause.wait_reached();
        let report = gc_now(&layout);
        assert_eq!(report.pruned, 0, "{report:?}");
        let store = ObjectStore::open(&layout).unwrap();
        for id in remote.objects[..2].iter().flatten() {
            assert!(
                store.contains(id),
                "gc deleted an object of a running fetch"
            );
        }
        drop(resume);
        fetching.join().unwrap().unwrap();
    });

    assert_eq!(tracking_tip(&layout), Some(remote.tip()));
    assert_closure_complete(&layout, remote.tip());
}

#[test]
fn gc_does_not_delete_an_old_orphan_a_fetch_reuses() {
    let remote = Remote::with_commits(4);
    let (_dir, target, layout) = fresh_target();
    // An old object equal to the blob of the second pack. The fetch's write
    // of that blob is a dedup hit that leaves the old modification time.
    let reused = remote.objects[1][0];
    let store = ObjectStore::open(&layout).unwrap();
    store
        .write(&serialize::serialize(&blob(b"content 1\n")).unwrap())
        .unwrap();
    assert!(store.contains(&reused));
    let (gate, pause) = gate();
    let probe = Probe {
        pause_unpack: Some((2, &gate)),
        ..Probe::default()
    };

    std::thread::scope(|scope| {
        let fetching = scope.spawn(|| run_fetch(&target, &remote.source(), &probe));
        let resume = ResumeOnDrop(&pause);
        pause.wait_reached();
        let report = gc_now(&layout);
        assert_eq!(report.pruned, 0, "{report:?}");
        assert!(
            store.contains(&reused),
            "gc deleted an object the fetch reuses"
        );
        drop(resume);
        fetching.join().unwrap().unwrap();
    });

    assert_eq!(tracking_tip(&layout), Some(remote.tip()));
    assert_closure_complete(&layout, remote.tip());
}

// ---------------------------------------------------------------------------
// 5. Kill and resume
// ---------------------------------------------------------------------------

#[test]
fn a_fetch_killed_in_any_download_resumes_with_only_the_remaining_packs() {
    const PACKS: usize = 5;
    let remote = Remote::with_commits(PACKS);
    for k in 1..=PACKS {
        let (_dir, target, layout) = fresh_target();
        let dying = HookSource::new(&remote, k, Action::Panic);
        let died = catch_unwind(AssertUnwindSafe(|| {
            run_fetch(&target, &dying, &NoopObserver)
        }));
        assert!(died.is_err(), "the fetch must die in download {k}");
        assert_eq!(tracking_tip(&layout), None, "no ref after a death in {k}");

        let resumed = HookSource::counting(&remote);
        let report = run_fetch(&target, &resumed, &NoopObserver).unwrap();
        assert_eq!(
            resumed.downloads(),
            PACKS - (k - 1),
            "death in download {k}"
        );
        assert_eq!(report.packs_downloaded, PACKS - (k - 1));
        assert_eq!(report.packs_already_applied, k - 1);
        assert_eq!(tracking_tip(&layout), Some(remote.tip()));
        assert_closure_complete(&layout, remote.tip());
    }
}

// ---------------------------------------------------------------------------
// 6. gc after a killed fetch, then a fetch
// ---------------------------------------------------------------------------

/// Three packs; the third holds a delta against the blob of the first.
fn remote_with_a_delta_across_packs() -> Remote {
    let mut remote = Remote::new();
    remote.push_file("base.bin", &noise(16 * 1024, 1));
    remote.push_file("other.txt", b"other\n");
    let mut changed = noise(16 * 1024, 1);
    changed[100] ^= 0xff;
    remote.push_delta_file("changed.bin", "base.bin", &changed);
    remote
}

/// Kill a fetch in its `die_at`-th download, then gc away what it wrote, then
/// fetch again. Returns the second fetch's report and how often it healed.
fn heal_after_gc(remote: &Remote, die_at: usize) -> (FetchReport, usize, RepoLayout) {
    let (dir, target, layout) = fresh_target();
    // Keep the directory for the rest of the process; the caller's layout
    // points into it.
    std::mem::forget(dir);
    let dying = HookSource::new(remote, die_at, Action::Panic);
    let died = catch_unwind(AssertUnwindSafe(|| {
        run_fetch(&target, &dying, &NoopObserver)
    }));
    assert!(died.is_err());
    let pruned = gc_now(&layout).pruned;
    assert!(pruned > 0, "gc must prune the dead fetch's objects");

    let probe = Probe::default();
    let report = run_fetch(&target, &remote.source(), &probe).unwrap();
    let stale = probe.stale.load(Ordering::SeqCst);
    (report, stale, layout)
}

#[test]
fn a_fetch_after_gc_pruned_a_killed_fetchs_objects_heals() {
    let remote = remote_with_a_delta_across_packs();
    // The first two packs are recorded and nothing references their objects.
    let (report, stale, layout) = heal_after_gc(&remote, 3);

    assert_eq!(stale, 1, "the fetch heals once");
    assert_eq!(report.packs_downloaded, 3);
    assert_eq!(report.packs_already_applied, 0);
    assert_eq!(tracking_tip(&layout), Some(remote.tip()));
    assert_closure_complete(&layout, remote.tip());
}

#[test]
fn a_heal_reports_only_the_attempt_that_published() {
    let remote = remote_with_a_delta_across_packs();
    // Only the first pack is recorded. The retry's first attempt skips it,
    // applies the second pack, and fails on the third pack's delta.
    let (report, stale, layout) = heal_after_gc(&remote, 2);

    assert_eq!(stale, 1);
    assert_eq!(report.packs_downloaded, 3);
    assert_eq!(report.packs_already_applied, 0);
    let objects: usize = remote.objects.iter().map(Vec::len).sum();
    assert_eq!(report.objects_unpacked, objects);
    assert_eq!(tracking_tip(&layout), Some(remote.tip()));
}

// ---------------------------------------------------------------------------
// 7. Two fetches at once
// ---------------------------------------------------------------------------

#[test]
fn two_fetches_at_once_publish_the_same_tip() {
    let remote = Remote::with_commits(4);
    let (_dir, target, layout) = fresh_target();
    let meet = Barrier::new(2);
    let first = HookSource::new(&remote, 2, Action::Meet(&meet));
    let second = HookSource::new(&remote, 2, Action::Meet(&meet));

    std::thread::scope(|scope| {
        let a = scope.spawn(|| run_fetch(&target, &first, &NoopObserver));
        let b = scope.spawn(|| run_fetch(&target, &second, &NoopObserver));
        a.join().unwrap().unwrap();
        b.join().unwrap().unwrap();
    });

    assert_eq!(tracking_tip(&layout), Some(remote.tip()));
    assert_closure_complete(&layout, remote.tip());
}

// ---------------------------------------------------------------------------
// 8. Parity
// ---------------------------------------------------------------------------

/// What a clone leaves behind that must not depend on how it got there.
#[derive(Debug, PartialEq, Eq)]
struct Footprint {
    objects: BTreeSet<Hash>,
    refs: BTreeSet<(String, Option<Hash>)>,
    record: String,
    worktree: Vec<(String, Vec<u8>)>,
}

fn footprint(target: &Path, layout: &RepoLayout) -> Footprint {
    let store = ObjectStore::open(layout).unwrap();
    let mut refs_seen = BTreeSet::new();
    for r in refs::list_refs(layout).unwrap() {
        refs_seen.insert((format!("heads/{}", r.name), r.hash));
    }
    for r in refs::list_remote_refs(layout, "origin").unwrap() {
        refs_seen.insert((format!("remotes/origin/{}", r.name), r.hash));
    }
    let record = std::fs::read_to_string(layout.applied_packs_dir().join("origin")).unwrap();
    let mut worktree = Vec::new();
    for entry in std::fs::read_dir(target).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_file() {
            worktree.push((
                entry.file_name().to_string_lossy().into_owned(),
                std::fs::read(entry.path()).unwrap(),
            ));
        }
    }
    worktree.sort();
    Footprint {
        objects: store.iter_object_hashes().unwrap().into_iter().collect(),
        refs: refs_seen,
        record,
        worktree,
    }
}

#[test]
fn a_resumed_clone_equals_an_uninterrupted_one() {
    const PACKS: usize = 4;
    let remote = Remote::with_commits(PACKS);

    let dir = tempfile::tempdir().unwrap();
    let whole = dir.path().join("whole");
    clone(
        &whole,
        &remote.source(),
        &clone_remote(),
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();
    let expected = footprint(&whole, &RepoLayout::single(&whole));
    assert_eq!(expected.worktree.len(), PACKS);

    for k in 1..=PACKS {
        let resumed = dir.path().join(format!("resumed-{k}"));
        let layout = init_clone_dir(&resumed, &clone_remote()).unwrap();
        let dying = HookSource::new(&remote, k, Action::Panic);
        let died = catch_unwind(AssertUnwindSafe(|| {
            run_fetch(&resumed, &dying, &NoopObserver)
        }));
        assert!(died.is_err());
        let report = pull(
            &resumed,
            &remote.source(),
            "origin",
            &SyncOptions::default(),
            &NoopObserver,
        )
        .unwrap();
        assert!(matches!(report.outcome, PullOutcome::FastForwarded { .. }));
        assert_eq!(
            footprint(&resumed, &layout),
            expected,
            "a clone killed in download {k} and resumed"
        );
    }
}

// ---------------------------------------------------------------------------
// Two fetches and the cursor record
// ---------------------------------------------------------------------------

/// What a fetch read from the remote before a push moved it: the cursor, the
/// listing and the packmap head. Packs and packmap nodes never change, so
/// they come from the live remote.
struct ViewBeforePush<'a> {
    inner: TransportSource<'a>,
    cursor: Option<kit_core::protocol::RepoCursor>,
    tip: Hash,
    packmap: Option<Hash>,
}

impl RemoteSource for ViewBeforePush<'_> {
    fn list_branches(&self) -> Result<Vec<refs::Ref>, SourceError> {
        Ok(vec![refs::Ref {
            name: "main".to_owned(),
            hash: Some(self.tip),
        }])
    }
    fn read_ref(&self, name: &str) -> Result<Option<Hash>, SourceError> {
        if name == "refs/kit/packmap/main" {
            Ok(self.packmap)
        } else {
            self.inner.read_ref(name)
        }
    }
    fn download_blob_via_ref(&self, key: &PackKey, ref_name: &str) -> Result<Vec<u8>, SourceError> {
        self.inner.download_blob_via_ref(key, ref_name)
    }
    fn download_pack_via_ref(&self, key: &PackKey, ref_name: &str) -> Result<Vec<u8>, SourceError> {
        self.inner.download_pack_via_ref(key, ref_name)
    }
    fn repo_cursor(&self) -> Result<Option<kit_core::protocol::RepoCursor>, SourceError> {
        Ok(self.cursor.clone())
    }
}

/// The live remote, pausing in the strong read of one ref.
struct PauseOnRead<'a> {
    inner: TransportSource<'a>,
    name: &'static str,
    gate: &'a Gate,
}

impl RemoteSource for PauseOnRead<'_> {
    fn list_branches(&self) -> Result<Vec<refs::Ref>, SourceError> {
        self.inner.list_branches()
    }
    fn read_ref(&self, name: &str) -> Result<Option<Hash>, SourceError> {
        if name == self.name {
            self.gate.hit();
        }
        self.inner.read_ref(name)
    }
    fn download_blob_via_ref(&self, key: &PackKey, ref_name: &str) -> Result<Vec<u8>, SourceError> {
        self.inner.download_blob_via_ref(key, ref_name)
    }
    fn download_pack_via_ref(&self, key: &PackKey, ref_name: &str) -> Result<Vec<u8>, SourceError> {
        self.inner.download_pack_via_ref(key, ref_name)
    }
    fn repo_cursor(&self) -> Result<Option<kit_core::protocol::RepoCursor>, SourceError> {
        self.inner.repo_cursor()
    }
}

/// A fetch that listed the remote before a push finishes after a fetch that
/// listed it after the push has published the new tip, and before that fetch
/// writes its cursor record. The remote does not change again. The next fetch
/// must still bring the tracking ref to the remote's tip.
#[test]
fn a_fetch_overtaken_by_a_slower_one_does_not_hide_the_new_tip_from_later_fetches() {
    let mut remote = Remote::with_commits(1);
    let old_tip = remote.tip();
    let (cursor_before, packmap_before) = {
        let source = remote.source();
        (
            source.repo_cursor().unwrap(),
            source.read_ref("refs/kit/packmap/main").unwrap(),
        )
    };
    remote.push_file("later.txt", b"later\n");
    let new_tip = remote.tip();
    assert_ne!(old_tip, new_tip);

    let (_dir, target, layout) = fresh_target();
    // A tracking ref of a branch the remote does not have, so a pruning fetch
    // asks the remote about it after it has published `main`.
    refs::write_remote_ref(&layout, "origin", "gone", &old_tip).unwrap();

    let (gate, pause) = gate();
    let newer = PauseOnRead {
        inner: remote.source(),
        name: "refs/heads/gone",
        gate: &gate,
    };
    let slower = ViewBeforePush {
        inner: remote.source(),
        cursor: cursor_before,
        tip: old_tip,
        packmap: packmap_before,
    };
    std::thread::scope(|scope| {
        let pruning = scope.spawn(|| {
            fetch(
                &target,
                &newer,
                "origin",
                &SyncOptions::default().with_prune(true),
                &NoopObserver,
            )
        });
        {
            let _resume = ResumeOnDrop(&pause);
            pause.wait_reached();
            assert_eq!(tracking_tip(&layout), Some(new_tip));
            run_fetch(&target, &slower, &NoopObserver).unwrap();
        }
        pruning.join().unwrap().unwrap();
    });

    let report = run_fetch(&target, &remote.source(), &NoopObserver).unwrap();
    assert_eq!(
        tracking_tip(&layout).map(|tip| hash::to_hex(&tip)),
        Some(hash::to_hex(&new_tip)),
        "the remote's main is at the new tip and nothing changed it since; a fetch that reports remote_unchanged={} left the tracking ref at the older tip {}",
        report.remote_unchanged,
        hash::to_hex(&old_tip)
    );
}
