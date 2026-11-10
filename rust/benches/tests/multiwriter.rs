//! Smoke runs of every concurrent-writer row at tiny sizes, and proof that
//! each row's result check catches a lost write.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in tests

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use kit_benches::multiwriter::{self, Connect};
use kit_core::hash::Hash;
use kit_core::protocol::{PackKey, RefWriteCondition, Transport, TransportResult};
use kit_core::refs::Ref;
use kit_transport_file::FileTransport;

fn file(root: PathBuf) -> impl Fn() -> Result<Box<dyn Transport>, String> + Sync {
    move || Ok(Box::new(FileTransport::new(&root)) as Box<dyn Transport>)
}

#[test]
fn every_row_runs_at_tiny_sizes() {
    let dir = tempfile::tempdir().unwrap();
    let case = |name: &str| {
        let base = dir.path().join(name);
        std::fs::create_dir_all(base.join("remote")).unwrap();
        base
    };

    let base = case("ref-write");
    let run = multiwriter::ref_write(&file(base.join("remote")), 3, 4).unwrap();
    assert_eq!(run.writes, 12);

    let base = case("push-distinct");
    let run =
        multiwriter::push_distinct(&file(base.join("remote")), &base.join("local"), 3, 2).unwrap();
    assert_eq!((run.pushes, run.conflicts, run.latencies.len()), (6, 0, 6));

    let base = case("push-shared");
    let run =
        multiwriter::push_shared(&file(base.join("remote")), &base.join("local"), 3, 2).unwrap();
    assert_eq!((run.pushes, run.latencies.len()), (6, 6));
    // Every landed push is split, and its parts fit inside its time.
    assert_eq!(run.parts.len(), 6);
    for (latency, parts) in run.latencies.iter().zip(&run.parts) {
        assert!(parts.attempts >= 1);
        assert!(parts.commit + parts.rejected + parts.fetch + parts.landed <= *latency);
    }
    let (slow, count) = run.parts_above(0.99);
    assert!(count >= 1 && slow.attempts >= 1);
    // Each landed push chains one node; a rejected attempt can add one.
    assert!((6..=6 + run.conflicts).contains(&run.chain_nodes));

    let base = case("fetch-noop");
    let connect = file(base.join("remote"));
    let reader = multiwriter::fetch_noop_setup(&connect, &base.join("local"), 3).unwrap();
    let run = multiwriter::fetch_noop(&connect, &reader).unwrap();
    assert_eq!(run.packs_downloaded, 0);
    assert!(run.requests.list >= 1);

    let base = case("fetch-grow");
    let run = multiwriter::fetch_grow(&file(base.join("remote")), &base.join("local"), 3).unwrap();
    assert_eq!(run.chain_nodes, 4);
    assert_eq!(run.incremental.packs_downloaded, 3);
    assert_eq!(run.cold.packs_downloaded, 4);
    // A chain this short is never reset. Every push uploads one commit.
    assert_eq!(run.pushes.len(), 3);
    assert_eq!(run.cost(true), multiwriter::PushCost::default());
    let append = run.cost(false);
    assert_eq!(append.pushes, 3);
    assert!(append.mean_bytes > 0.0 && append.max_bytes < 2 * FILE_BYTES);
    assert!(append.median <= append.max);
}

/// Bytes of the one file in each benchmark commit. A pack compresses it,
/// so a push of one commit uploads less than twice this.
const FILE_BYTES: u64 = 1024;

#[test]
fn fetch_grow_reports_the_upload_of_a_chain_reset() {
    // A push resets a chain that it would grow past 64 nodes. The first
    // push makes node 1, so push 64 after the clone is the reset.
    const PUSHES: usize = 66;
    const RESET: usize = 64;
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("remote")).unwrap();
    let run = multiwriter::fetch_grow(
        &file(dir.path().join("remote")),
        &dir.path().join("local"),
        PUSHES,
    )
    .unwrap();
    let resets: Vec<usize> = (1..=PUSHES).filter(|i| run.pushes[i - 1].reset).collect();
    assert_eq!(resets, [RESET]);
    // The reset left one node, and two pushes appended to it.
    assert_eq!(run.chain_nodes, 3);
    assert_eq!(run.cold.packs_downloaded, 3);

    // A push that appends uploads one commit, before and after the reset.
    let append = run.cost(false);
    assert_eq!(append.pushes, PUSHES - 1);
    assert!(append.mean_bytes > 0.0 && append.max_bytes < 2 * FILE_BYTES);

    // The reset uploads the closure of its tip: the first commit and the
    // 64 after it. That is far more than one commit, and at least half of
    // what the 64 pushes before it uploaded, pack list nodes included.
    let reset = run.cost(true);
    assert_eq!(reset.pushes, 1);
    assert_eq!(reset.max_bytes, run.pushes[RESET - 1].uploaded);
    assert!(reset.max_bytes > 32 * append.max_bytes);
    let before: u64 = run.pushes[..RESET - 1].iter().map(|p| p.uploaded).sum();
    assert!(reset.max_bytes > before / 2);
}

#[test]
fn the_workload_is_deterministic() {
    let dir = tempfile::tempdir().unwrap();
    let mut heads = Vec::new();
    for r in 0..2 {
        let base = dir.path().join(format!("r{r}"));
        std::fs::create_dir_all(base.join("remote")).unwrap();
        let connect = file(base.join("remote"));
        multiwriter::push_distinct(&connect, &base.join("local"), 2, 2).unwrap();
        let tx = connect().unwrap();
        heads.push(tx.list_refs("refs/").unwrap());
    }
    assert_eq!(heads[0], heads[1]);
    assert_eq!(heads[0].len(), 4, "two heads and two packmaps");
}

/// A transport that reports success for one chosen ref write without
/// making it.
struct DropsWrite {
    inner: FileTransport,
    /// Writes to refs with this prefix that pass before one is dropped.
    prefix: &'static str,
    pass: usize,
    /// Writes under `prefix` seen so far, across every connection.
    seen: Arc<AtomicUsize>,
}

impl Transport for DropsWrite {
    fn upload_pack(&self, bytes: &[u8], key: &PackKey) -> TransportResult<()> {
        self.inner.upload_pack(bytes, key)
    }
    fn download_pack(&self, key: &PackKey) -> TransportResult<Vec<u8>> {
        self.inner.download_pack(key)
    }
    fn pack_exists(&self, key: &PackKey) -> TransportResult<bool> {
        self.inner.pack_exists(key)
    }
    fn upload_blob(&self, bytes: &[u8], key: &PackKey) -> TransportResult<()> {
        self.inner.upload_blob(bytes, key)
    }
    fn download_blob(&self, key: &PackKey) -> TransportResult<Vec<u8>> {
        self.inner.download_blob(key)
    }
    fn update_ref(
        &self,
        name: &str,
        condition: RefWriteCondition,
        hash: &Hash,
    ) -> TransportResult<()> {
        if name.starts_with(self.prefix) && self.seen.fetch_add(1, Ordering::SeqCst) == self.pass {
            return Ok(());
        }
        self.inner.update_ref(name, condition, hash)
    }
    fn read_ref(&self, name: &str) -> TransportResult<Option<Hash>> {
        self.inner.read_ref(name)
    }
    fn list_refs(&self, prefix: &str) -> TransportResult<Vec<Ref>> {
        self.inner.list_refs(prefix)
    }
}

/// Connect every writer through a [`DropsWrite`]. Counted across all
/// connections, write `pass` under `prefix` is lost.
fn dropping(
    root: PathBuf,
    prefix: &'static str,
    pass: usize,
) -> impl Fn() -> Result<Box<dyn Transport>, String> + Sync {
    let seen = Arc::new(AtomicUsize::new(0));
    move || {
        Ok(Box::new(DropsWrite {
            inner: FileTransport::new(&root),
            prefix,
            pass,
            seen: Arc::clone(&seen),
        }) as Box<dyn Transport>)
    }
}

#[test]
fn ref_write_fails_when_a_last_write_is_dropped() {
    let dir = tempfile::tempdir().unwrap();
    let connect = dropping(dir.path().to_path_buf(), "refs/heads/", 3);
    let connect: &Connect = &connect;
    let err = multiwriter::ref_write(connect, 1, 4).unwrap_err();
    assert!(err.contains("lost write"), "{err}");
}

#[test]
fn ref_write_fails_when_a_middle_write_is_dropped() {
    let dir = tempfile::tempdir().unwrap();
    let connect = dropping(dir.path().to_path_buf(), "refs/heads/", 1);
    let err = multiwriter::ref_write(&connect, 1, 4).unwrap_err();
    assert!(err.contains("step 2"), "{err}");
}

#[test]
fn push_distinct_fails_when_a_head_write_is_dropped() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("remote")).unwrap();
    let connect = dropping(dir.path().join("remote"), "refs/heads/", 1);
    let err = multiwriter::push_distinct(&connect, &dir.path().join("local"), 1, 2).unwrap_err();
    assert!(err.contains("lost push"), "{err}");
}

#[test]
fn push_shared_fails_when_a_head_write_is_dropped() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("remote")).unwrap();
    let connect = dropping(dir.path().join("remote"), "refs/heads/", 1);
    let err = multiwriter::push_shared(&connect, &dir.path().join("local"), 1, 3).unwrap_err();
    assert!(err.contains("lost push"), "{err}");
}

#[test]
fn quantile_uses_the_nearest_rank() {
    use std::time::Duration;
    let xs: Vec<_> = (1..=100).map(Duration::from_millis).collect();
    assert_eq!(multiwriter::quantile(&xs, 0.99), Duration::from_millis(99));
    assert_eq!(multiwriter::quantile(&xs, 0.5), Duration::from_millis(50));
    assert_eq!(
        multiwriter::quantile(&xs[..1], 0.99),
        Duration::from_millis(1)
    );
    assert_eq!(multiwriter::quantile(&[], 0.5), Duration::ZERO);
    let (mean, sd) = multiwriter::mean_sd(&[1.0, 3.0]);
    assert!((mean - 2.0).abs() < 1e-9 && (sd - 2f64.sqrt()).abs() < 1e-9);
}
