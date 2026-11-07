//! Concurrent-writer workloads: many writers against one remote root.
//!
//! Each row drives real code paths. `ref-write` calls
//! [`Transport::update_ref`] directly. The push rows run
//! [`kit_sync::push`] from one local repository per pusher, and the fetch
//! rows run [`kit_sync::fetch`] through a counting [`RemoteSource`]. Every
//! row checks its result before it reports a number: a write that a writer
//! believes landed but the remote does not hold fails the run.
//!
//! The workload is deterministic. Ref values, file contents, commit
//! timestamps and the signing key derive from the writer and step numbers
//! only, so the same arguments produce the same pack bytes on every run.
//!
//! A caller passes a [`Connect`] closure, so a row runs against any
//! transport. Every `ref-write` writer opens its own transport, the way
//! separate processes would, and every push and fetch opens a fresh one, as
//! one `kit push` or `kit fetch` does. The timed part of a push or fetch
//! includes opening its connection.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Barrier, Mutex, PoisonError};
use std::time::{Duration, Instant};

use kit_core::hash::Hash;
use kit_core::layout::RepoLayout;
use kit_core::object::{Blob, Commit, EntryMode, Identity, Object, Tree, TreeEntry};
use kit_core::protocol::{PackKey, RefWriteCondition, Transport};
use kit_core::refs::{self, Ref};
use kit_core::sign::{self, KeyPair};
use kit_core::store::ObjectStore;
use kit_sync::{
    CloneRemote, DEFAULT_REMOTE_NAME, FetchReport, NoopObserver, PushError, PushLease, PushOptions,
    PushTarget, RemoteSource, SourceError, SyncOptions, TransportSource,
};

use crate::Xorshift;

/// Opens one transport to the remote under test. Called once per writer.
pub type Connect<'a> = dyn Fn() -> Result<Box<dyn Transport>, String> + Sync + 'a;

/// The largest writer count a row accepts. Every writer is a thread, and a
/// `kit serve` target is also a process per writer.
pub const MAX_WRITERS: usize = 1024;

/// The largest number of operations one writer performs in a row.
pub const MAX_STEPS: usize = 100_000;

/// The largest ref count `fetch-noop` sets up.
pub const MAX_REFS: usize = 100_000;

/// Bytes of file content in each benchmark commit.
const FILE_BYTES: usize = 1024;

/// The remote branch name the remote-tracking refs live under.
const REMOTE: &str = DEFAULT_REMOTE_NAME;

fn check_bounds(writers: usize, steps: usize) -> Result<(), String> {
    if writers == 0 || writers > MAX_WRITERS {
        return Err(format!(
            "writer count {writers} is outside 1..={MAX_WRITERS}"
        ));
    }
    if steps == 0 || steps > MAX_STEPS {
        return Err(format!("step count {steps} is outside 1..={MAX_STEPS}"));
    }
    Ok(())
}

/// The value that writer `writer` stores at step `step` of `ref-write`.
/// Distinct for every pair and never all zero.
#[must_use]
pub fn ref_value(writer: usize, step: usize) -> Hash {
    let mut value = [0u8; 32];
    value[..8].copy_from_slice(&(writer as u64).to_le_bytes());
    value[8..16].copy_from_slice(&(step as u64).to_le_bytes());
    value[16] = 1;
    value
}

/// Result of one `ref-write` run.
#[derive(Debug, Clone, Copy)]
pub struct RefWriteRun {
    /// Writes that landed and were read back.
    pub writes: usize,
    /// Wall-clock time from the first write to the last.
    pub elapsed: Duration,
}

impl RefWriteRun {
    /// Writes per second.
    #[must_use]
    pub fn rate(&self) -> f64 {
        self.writes as f64 / self.elapsed.as_secs_f64()
    }
}

/// `ref-write`: `writers` threads, each doing `steps` compare-and-swap
/// writes to its own ref. The first write is `Missing`, every later one
/// `Match` of the previous value. After the run each ref must hold the
/// writer's last value.
pub fn ref_write(connect: &Connect, writers: usize, steps: usize) -> Result<RefWriteRun, String> {
    check_bounds(writers, steps)?;
    let barrier = Barrier::new(writers + 1);
    let elapsed = std::thread::scope(|s| -> Result<Duration, String> {
        let handles: Vec<_> = (0..writers)
            .map(|w| {
                let barrier = &barrier;
                s.spawn(move || -> Result<(), String> {
                    let tx = connect();
                    barrier.wait();
                    let tx = tx?;
                    let name = format!("refs/heads/w{w}");
                    let mut prev = None;
                    for step in 0..steps {
                        let value = ref_value(w, step);
                        let condition =
                            prev.map_or(RefWriteCondition::Missing, RefWriteCondition::Match);
                        tx.update_ref(&name, condition, &value)
                            .map_err(|e| format!("{name} step {step}: {e}"))?;
                        prev = Some(value);
                    }
                    Ok(())
                })
            })
            .collect();
        barrier.wait();
        let start = Instant::now();
        join_all(handles)?;
        Ok(start.elapsed())
    })?;
    let tx = connect()?;
    for w in 0..writers {
        let name = format!("refs/heads/w{w}");
        let got = tx
            .read_ref(&name)
            .map_err(|e| format!("read {name}: {e}"))?;
        if got != Some(ref_value(w, steps - 1)) {
            return Err(format!("lost write: {name} does not hold its last value"));
        }
    }
    Ok(RefWriteRun {
        writes: writers * steps,
        elapsed,
    })
}

fn join_all<T>(
    handles: Vec<std::thread::ScopedJoinHandle<'_, Result<T, String>>>,
) -> Result<Vec<T>, String> {
    let mut out = Vec::with_capacity(handles.len());
    let mut first_error = None;
    for handle in handles {
        match handle.join() {
            Ok(Ok(v)) => out.push(v),
            Ok(Err(e)) => {
                first_error.get_or_insert(e);
            }
            Err(_) => {
                first_error.get_or_insert_with(|| "a writer thread panicked".to_owned());
            }
        }
    }
    match first_error {
        Some(e) => Err(e),
        None => Ok(out),
    }
}

/// The signing key of every benchmark commit. A fixed seed keeps the
/// commit bytes, and so the pack bytes, the same on every run.
#[must_use]
pub fn bench_key() -> KeyPair {
    KeyPair::from_seed([7u8; 32])
}

/// A local repository that pushes to the remote under test.
struct Pusher<'k> {
    dir: PathBuf,
    layout: RepoLayout,
    store: ObjectStore,
    key: &'k KeyPair,
}

impl<'k> Pusher<'k> {
    fn create(dir: &Path, key: &'k KeyPair) -> Result<Self, String> {
        let remote = CloneRemote {
            name: REMOTE.to_owned(),
            url: String::new(),
            kind: String::new(),
        };
        let layout = kit_sync::init_clone_dir(dir, &remote).map_err(|e| e.to_string())?;
        let store = ObjectStore::open(&layout).map_err(|e| e.to_string())?;
        Ok(Self {
            dir: dir.to_path_buf(),
            layout,
            store,
            key,
        })
    }

    fn write(&self, object: &Object) -> Result<Hash, String> {
        let bytes = kit_core::serialize::serialize(object).map_err(|e| e.to_string())?;
        self.store.write(&bytes).map_err(|e| e.to_string())
    }

    /// Commit one file whose contents derive from `seed` on top of
    /// `parent`, and point the local `branch` at it.
    fn commit(&self, branch: &str, parent: Option<Hash>, seed: u64) -> Result<Hash, String> {
        let blob = Object::Blob(Blob {
            data: Xorshift::new(seed).bytes(FILE_BYTES),
        });
        let blob_hash = self.write(&blob)?;
        let tree = Object::Tree(Tree {
            entries: vec![TreeEntry {
                name: b"f".to_vec(),
                mode: EntryMode::Blob,
                object_hash: blob_hash,
            }],
        });
        let tree_hash = self.write(&tree)?;
        let mut commit = Commit::new_unannotated(
            tree_hash,
            parent.into_iter().collect(),
            Identity::ed25519(self.key.public.0),
            self.key.public.0,
            format!("bench {seed}").into_bytes(),
            1_700_000_000,
            [0u8; 64],
        );
        commit.signature = sign::sign_commit(&commit, self.key)
            .map_err(|e| e.to_string())?
            .0;
        let tip = self.write(&Object::Commit(commit))?;
        refs::update_ref(&self.layout, branch, RefWriteCondition::Any, &tip)
            .map_err(|e| e.to_string())?;
        Ok(tip)
    }

    fn push(&self, source: &dyn RemoteSource, branch: &str) -> Result<(), PushError> {
        let options = PushOptions::default().with_target(PushTarget::Branch {
            local: branch.to_owned(),
            remote: branch.to_owned(),
            lease: PushLease::FastForward,
        });
        kit_sync::push(&self.dir, source, &options).map(|_| ())
    }

    fn fetch(&self, source: &dyn RemoteSource) -> Result<FetchReport, String> {
        kit_sync::fetch(
            &self.dir,
            source,
            REMOTE,
            &SyncOptions::default(),
            &NoopObserver,
        )
        .map_err(|e| e.to_string())
    }

    fn tracked(&self, branch: &str) -> Result<Option<Hash>, String> {
        refs::read_remote_ref(&self.layout, REMOTE, branch).map_err(|e| e.to_string())
    }
}

fn seed(writer: usize, step: usize) -> u64 {
    ((writer as u64) << 32) | step as u64
}

/// Result of one push run.
#[derive(Debug, Clone)]
pub struct PushRun {
    /// Pushes that landed.
    pub pushes: usize,
    /// Rejected attempts, each followed by a fetch and a retry.
    pub conflicts: usize,
    /// Wall-clock time from the first push to the last.
    pub elapsed: Duration,
    /// Time of each landed push, its retries included, sorted.
    pub latencies: Vec<Duration>,
}

impl PushRun {
    /// Landed pushes per second.
    #[must_use]
    pub fn rate(&self) -> f64 {
        self.pushes as f64 / self.elapsed.as_secs_f64()
    }

    /// The latency at quantile `q` in `0.0..=1.0`, nearest rank.
    #[must_use]
    pub fn quantile(&self, q: f64) -> Duration {
        quantile(&self.latencies, q)
    }

    /// Rejected attempts per landed push.
    #[must_use]
    pub fn retries_per_success(&self) -> f64 {
        self.conflicts as f64 / self.pushes as f64
    }
}

/// The value at quantile `q` of `sorted`, nearest rank. Zero when empty.
#[must_use]
pub fn quantile(sorted: &[Duration], q: f64) -> Duration {
    if sorted.is_empty() {
        return Duration::ZERO;
    }
    let rank = (q.clamp(0.0, 1.0) * sorted.len() as f64).ceil() as usize;
    sorted[rank.clamp(1, sorted.len()) - 1]
}

fn is_conflict(e: &PushError) -> bool {
    matches!(
        e,
        PushError::NonFastForwardPush { .. } | PushError::PackmapContended { .. }
    )
}

/// `push-distinct`: `pushers` local repositories, each pushing `steps`
/// commits to its own branch. Each push must land on the first attempt,
/// and the remote must hold every branch's last commit afterwards.
pub fn push_distinct(
    connect: &Connect,
    scratch: &Path,
    pushers: usize,
    steps: usize,
) -> Result<PushRun, String> {
    check_bounds(pushers, steps)?;
    let key = bench_key();
    let barrier = Barrier::new(pushers + 1);
    let (elapsed, per) = std::thread::scope(|s| -> Result<_, String> {
        let handles: Vec<_> = (0..pushers)
            .map(|p| {
                let (barrier, key) = (&barrier, &key);
                s.spawn(move || -> Result<(Hash, Vec<Duration>), String> {
                    let pusher = Pusher::create(&scratch.join(format!("p{p}")), key);
                    barrier.wait();
                    let pusher = pusher?;
                    let branch = format!("p{p}");
                    let mut tip = None;
                    let mut latencies = Vec::with_capacity(steps);
                    for step in 0..steps {
                        let next = pusher.commit(&branch, tip, seed(p, step))?;
                        let t0 = Instant::now();
                        let tx = connect()?;
                        pusher
                            .push(&TransportSource::new(&*tx), &branch)
                            .map_err(|e| format!("push {branch} step {step}: {e}"))?;
                        latencies.push(t0.elapsed());
                        tip = Some(next);
                    }
                    let tip = tip.ok_or("no step ran")?;
                    Ok((tip, latencies))
                })
            })
            .collect();
        barrier.wait();
        let start = Instant::now();
        let per = join_all(handles)?;
        Ok((start.elapsed(), per))
    })?;
    let tx = connect()?;
    let mut latencies = Vec::with_capacity(pushers * steps);
    for (p, (tip, lat)) in per.into_iter().enumerate() {
        let name = format!("refs/heads/p{p}");
        let got = tx
            .read_ref(&name)
            .map_err(|e| format!("read {name}: {e}"))?;
        if got != Some(tip) {
            return Err(format!("lost push: {name} does not hold its last commit"));
        }
        latencies.extend(lat);
    }
    latencies.sort_unstable();
    Ok(PushRun {
        pushes: pushers * steps,
        conflicts: 0,
        elapsed,
        latencies,
    })
}

/// The branch every `push-shared` pusher targets.
pub const SHARED_BRANCH: &str = "shared";

/// `push-shared`: `pushers` local repositories, each landing `steps`
/// commits on one branch. A rejected push fetches, commits again on the
/// new remote tip and retries. Afterwards the branch's first-parent history
/// must hold every landed commit exactly once.
pub fn push_shared(
    connect: &Connect,
    scratch: &Path,
    pushers: usize,
    steps: usize,
) -> Result<PushRun, String> {
    check_bounds(pushers, steps)?;
    let key = bench_key();
    let barrier = Barrier::new(pushers + 1);
    let conflicts = AtomicUsize::new(0);
    let (elapsed, per) = std::thread::scope(|s| -> Result<_, String> {
        let handles: Vec<_> = (0..pushers)
            .map(|p| {
                let (barrier, key, conflicts) = (&barrier, &key, &conflicts);
                s.spawn(move || -> Result<(Vec<Hash>, Vec<Duration>), String> {
                    let pusher = Pusher::create(&scratch.join(format!("p{p}")), key);
                    barrier.wait();
                    let pusher = pusher?;
                    let mut landed = Vec::with_capacity(steps);
                    let mut latencies = Vec::with_capacity(steps);
                    for step in 0..steps {
                        let t0 = Instant::now();
                        let mut attempt = 0usize;
                        let tip = loop {
                            let parent = pusher.tracked(SHARED_BRANCH)?;
                            let tip = pusher.commit(SHARED_BRANCH, parent, seed(p, step))?;
                            let tx = connect()?;
                            match pusher.push(&TransportSource::new(&*tx), SHARED_BRANCH) {
                                Ok(()) => break tip,
                                Err(e) if is_conflict(&e) && attempt < MAX_STEPS => {
                                    attempt += 1;
                                    conflicts.fetch_add(1, Ordering::Relaxed);
                                    drop(tx);
                                    let tx = connect()?;
                                    pusher.fetch(&TransportSource::new(&*tx))?;
                                }
                                Err(e) => return Err(format!("push p{p} step {step}: {e}")),
                            }
                        };
                        latencies.push(t0.elapsed());
                        landed.push(tip);
                    }
                    Ok((landed, latencies))
                })
            })
            .collect();
        barrier.wait();
        let start = Instant::now();
        let per = join_all(handles)?;
        Ok((start.elapsed(), per))
    })?;
    let mut expected = HashSet::with_capacity(pushers * steps);
    let mut latencies = Vec::with_capacity(pushers * steps);
    for (landed, lat) in per {
        expected.extend(landed);
        latencies.extend(lat);
    }
    let history = shared_history(connect, &scratch.join("check"), &key, pushers * steps)?;
    if history != expected {
        return Err(format!(
            "lost push: the branch history holds {} commits, the pushers landed {}",
            history.len(),
            expected.len()
        ));
    }
    latencies.sort_unstable();
    Ok(PushRun {
        pushes: pushers * steps,
        conflicts: conflicts.load(Ordering::Relaxed),
        elapsed,
        latencies,
    })
}

/// Fetch the shared branch into a fresh repository and collect its
/// first-parent history, at most `bound + 1` commits.
fn shared_history(
    connect: &Connect,
    dir: &Path,
    key: &KeyPair,
    bound: usize,
) -> Result<HashSet<Hash>, String> {
    let checker = Pusher::create(dir, key)?;
    let tx = connect()?;
    checker.fetch(&TransportSource::new(&*tx))?;
    let mut seen = HashSet::with_capacity(bound);
    let mut next = checker.tracked(SHARED_BRANCH)?;
    while let Some(h) = next {
        if seen.len() > bound || !seen.insert(h) {
            return Err("the branch history is longer than the pushes or has a cycle".to_owned());
        }
        next = match checker.store.read_object(&h).map_err(|e| e.to_string())? {
            Object::Commit(c) => c.parents.first().copied(),
            _ => return Err("the branch history holds a non-commit".to_owned()),
        };
    }
    Ok(seen)
}

/// Remote requests one fetch made, by kind.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Requests {
    /// Repository cursor reads.
    pub cursor: usize,
    /// Ref listings.
    pub list: usize,
    /// Single ref reads.
    pub read_ref: usize,
    /// Pack list node downloads.
    pub node: usize,
    /// Pack downloads.
    pub pack: usize,
}

impl Requests {
    /// Every request.
    #[must_use]
    pub fn total(&self) -> usize {
        self.cursor + self.list + self.read_ref + self.node + self.pack
    }
}

/// A read-only [`RemoteSource`] that counts the requests it forwards.
struct Counting<'a> {
    inner: TransportSource<'a>,
    counts: Mutex<Requests>,
}

impl<'a> Counting<'a> {
    fn new(tx: &'a dyn Transport) -> Self {
        Self {
            inner: TransportSource::new(tx),
            counts: Mutex::new(Requests::default()),
        }
    }

    fn bump(&self, f: impl FnOnce(&mut Requests)) {
        f(&mut self.counts.lock().unwrap_or_else(PoisonError::into_inner));
    }

    fn take(&self) -> Requests {
        std::mem::take(&mut *self.counts.lock().unwrap_or_else(PoisonError::into_inner))
    }
}

impl RemoteSource for Counting<'_> {
    fn list_branches(&self) -> Result<Vec<Ref>, SourceError> {
        self.bump(|c| c.list += 1);
        self.inner.list_branches()
    }

    fn read_ref(&self, name: &str) -> Result<Option<Hash>, SourceError> {
        self.bump(|c| c.read_ref += 1);
        self.inner.read_ref(name)
    }

    fn download_blob_via_ref(&self, key: &PackKey, ref_name: &str) -> Result<Vec<u8>, SourceError> {
        self.bump(|c| c.node += 1);
        self.inner.download_blob_via_ref(key, ref_name)
    }

    fn download_pack_via_ref(&self, key: &PackKey, ref_name: &str) -> Result<Vec<u8>, SourceError> {
        self.bump(|c| c.pack += 1);
        self.inner.download_pack_via_ref(key, ref_name)
    }

    fn repo_cursor(&self) -> Result<Option<kit_core::protocol::RepoCursor>, SourceError> {
        self.bump(|c| c.cursor += 1);
        self.inner.repo_cursor()
    }

    fn supports_push(&self) -> bool {
        false
    }
}

/// Result of one fetch measurement.
#[derive(Debug, Clone, Copy)]
pub struct FetchRun {
    /// Time of the fetch.
    pub elapsed: Duration,
    /// Requests the fetch made.
    pub requests: Requests,
    /// Packs the fetch downloaded and applied.
    pub packs_downloaded: usize,
}

/// Set up `fetch-noop`: one pushed commit, then `refs` branches that all
/// point at it, and a clone that already holds every branch. Returns the
/// clone's directory.
pub fn fetch_noop_setup(connect: &Connect, scratch: &Path, refs: usize) -> Result<PathBuf, String> {
    if refs == 0 || refs > MAX_REFS {
        return Err(format!("ref count {refs} is outside 1..={MAX_REFS}"));
    }
    let key = bench_key();
    let pusher = Pusher::create(&scratch.join("pusher"), &key)?;
    let tx = connect()?;
    pusher.commit("b0", None, 0)?;
    pusher
        .push(&TransportSource::new(&*tx), "b0")
        .map_err(|e| format!("push b0: {e}"))?;
    let head = tx
        .read_ref("refs/heads/b0")
        .and_then(|h| Ok((h, tx.read_ref("refs/kit/packmap/b0")?)))
        .map_err(|e| e.to_string())?;
    let (Some(head), Some(packmap)) = head else {
        return Err("the first push left no head or packmap".to_owned());
    };
    let mut tx = tx;
    for i in 1..refs {
        // One connection per batch of writes, under a server's
        // per-connection request budget.
        if i % SETUP_BATCH == 0 {
            tx = connect()?;
        }
        for (name, value) in [
            (format!("refs/kit/packmap/b{i}"), packmap),
            (format!("refs/heads/b{i}"), head),
        ] {
            tx.update_ref(&name, RefWriteCondition::Missing, &value)
                .map_err(|e| format!("{name}: {e}"))?;
        }
    }
    let reader = Pusher::create(&scratch.join("reader"), &key)?;
    let tx = connect()?;
    let report = reader.fetch(&TransportSource::new(&*tx))?;
    if report.branches_fetched != refs {
        return Err(format!(
            "the first fetch published {} of {refs} branches",
            report.branches_fetched
        ));
    }
    Ok(reader.dir)
}

/// One `fetch-noop` measurement on a clone from [`fetch_noop_setup`]. The
/// fetch must find nothing to download.
pub fn fetch_noop(connect: &Connect, reader: &Path) -> Result<FetchRun, String> {
    let tx = connect()?;
    let source = Counting::new(&*tx);
    let t0 = Instant::now();
    let report = kit_sync::fetch(
        reader,
        &source,
        REMOTE,
        &SyncOptions::default(),
        &NoopObserver,
    )
    .map_err(|e| e.to_string())?;
    let elapsed = t0.elapsed();
    if report.packs_downloaded != 0 || report.objects_unpacked != 0 {
        return Err("a fetch of an unchanged remote downloaded data".to_owned());
    }
    Ok(FetchRun {
        elapsed,
        requests: source.take(),
        packs_downloaded: 0,
    })
}

/// Result of one `fetch-grow` run.
#[derive(Debug, Clone, Copy)]
pub struct GrowRun {
    /// A fetch into a clone taken before the pushes.
    pub incremental: FetchRun,
    /// A fetch into an empty repository after the pushes.
    pub cold: FetchRun,
    /// Pack list nodes on the branch's chain after the pushes.
    pub chain_nodes: usize,
}

/// Ref writes `fetch-noop` setup makes over one connection, two per branch.
const SETUP_BATCH: usize = 1_000;

/// The branch `fetch-grow` pushes to.
pub const GROW_BRANCH: &str = "grow";

/// `fetch-grow`: one push, a clone, `pushes` more pushes to the branch,
/// then a fetch into that clone and a fetch into an empty repository.
/// Both must end at the last pushed commit.
pub fn fetch_grow(connect: &Connect, scratch: &Path, pushes: usize) -> Result<GrowRun, String> {
    check_bounds(1, pushes)?;
    let key = bench_key();
    let pusher = Pusher::create(&scratch.join("pusher"), &key)?;
    let mut tip = pusher.commit(GROW_BRANCH, None, 0)?;
    let push = |step: usize| -> Result<(), String> {
        let tx = connect()?;
        pusher
            .push(&TransportSource::new(&*tx), GROW_BRANCH)
            .map_err(|e| format!("push {step}: {e}"))
    };
    push(0)?;
    let reader = Pusher::create(&scratch.join("reader"), &key)?;
    reader.fetch(&TransportSource::new(&*connect()?))?;
    for step in 1..=pushes {
        tip = pusher.commit(GROW_BRANCH, Some(tip), seed(0, step))?;
        push(step)?;
    }
    let measure = |repo: &Pusher<'_>| -> Result<FetchRun, String> {
        let tx = connect()?;
        let source = Counting::new(&*tx);
        let t0 = Instant::now();
        let report = repo.fetch(&source)?;
        let elapsed = t0.elapsed();
        if repo.tracked(GROW_BRANCH)? != Some(tip) {
            return Err("the fetch did not end at the last pushed commit".to_owned());
        }
        Ok(FetchRun {
            elapsed,
            requests: source.take(),
            packs_downloaded: report.packs_downloaded,
        })
    };
    let incremental = measure(&reader)?;
    let cold = measure(&Pusher::create(&scratch.join("cold"), &key)?)?;
    let chain_nodes = chain_nodes(&*connect()?, GROW_BRANCH, pushes + 1)?;
    Ok(GrowRun {
        incremental,
        cold,
        chain_nodes,
    })
}

/// Walk the pack list chain of `branch` and count its nodes, at most
/// `bound`.
fn chain_nodes(tx: &dyn Transport, branch: &str, bound: usize) -> Result<usize, String> {
    let mut next = tx
        .read_ref(&kit_sync::packmap::packmap_ref(branch))
        .map_err(|e| e.to_string())?;
    let mut nodes = 0usize;
    while let Some(h) = next {
        if nodes >= bound {
            return Err("the pack list chain is longer than the pushes".to_owned());
        }
        let bytes = tx
            .download_blob(&PackKey::from_hash(h))
            .map_err(|e| e.to_string())?;
        next = kit_core::transfer::decode_packlist(&bytes)
            .map_err(|e| e.to_string())?
            .prev;
        nodes += 1;
    }
    Ok(nodes)
}

/// Mean and sample standard deviation of `xs`. The deviation is zero for
/// fewer than two values.
#[must_use]
pub fn mean_sd(xs: &[f64]) -> (f64, f64) {
    if xs.is_empty() {
        return (0.0, 0.0);
    }
    let n = xs.len() as f64;
    let mean = xs.iter().sum::<f64>() / n;
    if xs.len() < 2 {
        return (mean, 0.0);
    }
    let var = xs.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n - 1.0);
    (mean, var.sqrt())
}
