//! The ssh and S3 transports stream a pack both ways (SPEC-TRANSPORT §4.2,
//! §6.7): an upload reads the pack from its body, again from offset 0 on
//! every attempt, and a download writes each piece to the sink as it
//! arrives. A push and a fetch of a 1 GiB pack hold a heap that does not
//! grow with the pack.
//!
//! The ssh tests run `kit serve` through a `/bin/sh` stand-in for `ssh`,
//! which the transport finds through `KIT_SSH_PROGRAM`. This process may not
//! set its own environment, so each ssh test runs again in a child of this
//! test binary with that environment set.
//!
//! The S3 tests need an S3-compatible store, such as one run locally.
//! They run in the ignored lane when `KIT_TEST_S3_ENDPOINT`
//! (`http://host:port`), `KIT_TEST_S3_BUCKET`, `KIT_TEST_S3_ACCESS_KEY` and
//! `KIT_TEST_S3_SECRET_KEY` name one, and skip otherwise. Each test works
//! under a prefix of its own.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers
#![allow(unsafe_code)] // the counting allocator below wraps `System`
#![cfg(unix)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::fs;
use std::io::Read as _;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use kit_core::hash::{self, Hash};
use kit_core::layout::RepoLayout;
use kit_core::object::{Blob, Commit, EntryMode, Identity, Object, Tree, TreeEntry};
use kit_core::pack::{self, PackSpool, SpoolWriter, SpooledPack};
use kit_core::protocol::{
    BackoffIterator, PACK_BODY_LIMIT, PackBody, PackKey, PackSink, Transport, TransportError,
};
use kit_core::refs;
use kit_core::sign::{self, KeyPair};
use kit_sync::{
    CloneRemote, NoopObserver, RemoteSource, SyncOptions, TransportSource, fetch, init_clone_dir,
};
use kit_transport_ssh::{SshOptions, SshTransport, parse_kit_ssh_url};

const KIB: usize = 1 << 10;
const MIB: usize = 1 << 20;

// ---------------------------------------------------------------------------
// Counting allocator
// ---------------------------------------------------------------------------

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
/// The tests share the counters, so each one holds this while it runs.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Records the bytes held at once and their high-water mark.
struct CountingAlloc;

fn grow(bytes: usize) {
    let live = LIVE.fetch_add(bytes, Ordering::Relaxed) + bytes;
    PEAK.fetch_max(live, Ordering::Relaxed);
}

// SAFETY: every method forwards to `System` with the unchanged layout and
// pointer, so `System`'s contract holds. The counters have no effect on the
// allocation.
unsafe impl GlobalAlloc for CountingAlloc {
    // SAFETY: the caller upholds the `GlobalAlloc::alloc` contract. The call
    // forwards the same layout to `System`.
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        grow(layout.size());
        // SAFETY: the caller upholds the `GlobalAlloc::alloc` contract for `layout`.
        unsafe { System.alloc(layout) }
    }

    // SAFETY: the caller passes a pointer and layout from a matching `alloc`.
    // The call forwards both to `System` unchanged.
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        // SAFETY: the caller passes a pointer and layout from a matching `alloc`.
        unsafe { System.dealloc(ptr, layout) }
    }

    // SAFETY: the caller passes a pointer and layout from a matching `alloc`.
    // The call forwards them with the new size to `System` unchanged.
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        grow(new_size);
        // SAFETY: the caller passes a pointer and layout from a matching `alloc`.
        let moved = unsafe { System.realloc(ptr, layout, new_size) };
        // The default `realloc` holds both blocks only while it copies, so
        // this keeps that overlap in the high-water mark.
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        moved
    }
}

#[global_allocator]
static ALLOC: CountingAlloc = CountingAlloc;

/// The most that `call` holds at once on top of what is already live.
fn peak_of<T>(call: impl FnOnce() -> T) -> (T, usize) {
    let before = LIVE.load(Ordering::Relaxed);
    PEAK.store(before, Ordering::Relaxed);
    let out = call();
    (out, PEAK.load(Ordering::Relaxed).saturating_sub(before))
}

// ---------------------------------------------------------------------------
// Packs, bodies and sinks
// ---------------------------------------------------------------------------

/// Fill `out` with incompressible bytes from `seed`.
fn noise_into(seed: u64, out: &mut [u8]) {
    let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    for chunk in out.chunks_mut(8) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        chunk.copy_from_slice(&state.to_le_bytes()[..chunk.len()]);
    }
}

/// A pack of `blobs` incompressible blobs of `len` bytes, spooled in `dir`.
fn spooled_pack(dir: &Path, seed: u64, blobs: usize, len: usize) -> SpooledPack {
    let mut writer = SpoolWriter::spool(dir).unwrap();
    let mut data = vec![0u8; len];
    for i in 0..blobs {
        noise_into(seed + i as u64, &mut data);
        let bytes =
            kit_core::serialize::serialize(&Object::Blob(Blob { data: data.clone() })).unwrap();
        writer.push_raw(hash::hash(&bytes), &bytes).unwrap();
    }
    writer.finish_spool().unwrap()
}

/// Download `key` from `tx` into a spool and verify it.
fn download_verified(tx: &dyn Transport, key: &PackKey, dir: &Path) {
    let mut spool = PackSpool::create(dir, PACK_BODY_LIMIT).unwrap();
    tx.download_pack(key, None, &mut spool).unwrap();
    spool.finish(key).unwrap();
}

/// A pack body that records the offset of every read it starts. It can
/// claim a length other than its pack's, change its bytes after its first
/// read, or end early after its first read.
struct Recorded<'a> {
    pack: &'a SpooledPack,
    len: u64,
    after_first: AfterFirst,
    reads: Mutex<Vec<u64>>,
}

#[derive(Clone, Copy)]
#[cfg_attr(
    not(feature = "s3"),
    expect(dead_code, reason = "only the s3 tests change a later read")
)]
enum AfterFirst {
    Same,
    /// Later reads flip one byte at this offset.
    Flip(u64),
    /// Later reads end at this offset.
    Cut(u64),
}

impl<'a> Recorded<'a> {
    fn new(pack: &'a SpooledPack) -> Self {
        Self {
            pack,
            len: pack.len(),
            after_first: AfterFirst::Same,
            reads: Mutex::new(Vec::new()),
        }
    }

    fn claiming(mut self, len: u64) -> Self {
        self.len = len;
        self
    }

    #[cfg_attr(
        not(feature = "s3"),
        expect(dead_code, reason = "only the s3 tests change a later read")
    )]
    fn after_first(mut self, change: AfterFirst) -> Self {
        self.after_first = change;
        self
    }

    fn reads(&self) -> Vec<u64> {
        self.reads.lock().unwrap().clone()
    }
}

impl PackBody for Recorded<'_> {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_from(&self, offset: u64) -> std::io::Result<Box<dyn std::io::Read + Send + '_>> {
        let mut reads = self.reads.lock().unwrap();
        reads.push(offset);
        let later = reads.len() > 1;
        let reader = self.pack.read_from(offset)?;
        Ok(match self.after_first {
            AfterFirst::Cut(at) if later => Box::new(reader.take(at - offset)),
            AfterFirst::Flip(at) if later => Box::new(Flipped {
                inner: reader,
                at: at - offset,
                pos: 0,
            }),
            _ => reader,
        })
    }
}

/// A reader that flips the byte at `at`.
struct Flipped<R> {
    inner: R,
    at: u64,
    pos: u64,
}

impl<R: std::io::Read> std::io::Read for Flipped<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        if (self.pos..self.pos + n as u64).contains(&self.at) {
            buf[usize::try_from(self.at - self.pos).unwrap()] ^= 1;
        }
        self.pos += n as u64;
        Ok(n)
    }
}

/// A sink that keeps nothing, and records each call.
#[derive(Default)]
struct Recording {
    limit: u64,
    begins: Vec<Option<u64>>,
    written: u64,
}

impl PackSink for Recording {
    fn begin(&mut self, declared: Option<u64>) -> Result<(), TransportError> {
        self.begins.push(declared);
        match declared {
            Some(len) if len > self.limit => Err(TransportError::PayloadTooLarge(
                usize::try_from(len).unwrap(),
            )),
            _ => Ok(()),
        }
    }

    fn write(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
        self.written += bytes.len() as u64;
        Ok(())
    }

    fn failed(&self) -> Option<std::io::ErrorKind> {
        None
    }
}

// ---------------------------------------------------------------------------
// A repository to push, and the push and fetch measured
// ---------------------------------------------------------------------------

/// A repository of `files` files of `len` incompressible bytes, every
/// fourth one ending in `zeros` zero bytes, in 256 directories. The objects
/// go straight to the store; HEAD names `main`, which holds the commit.
fn commit_files(work: &Path, key: &KeyPair, files: usize, len: usize, zeros: usize) -> Hash {
    let layout = RepoLayout::single(work);
    let store = kit_core::store::ObjectStore::open(&layout).unwrap();
    let batch = store.batch();
    let mut data = vec![0u8; len];
    let mut dirs = Vec::new();
    for dir in 0..256usize {
        let mut entries = Vec::new();
        for file in (dir..files).step_by(256) {
            let tail = if file % 4 == 0 { zeros } else { 0 };
            noise_into(file as u64, &mut data[..len - tail]);
            data[len - tail..].fill(0);
            let blob = Object::Blob(Blob {
                data: std::mem::take(&mut data),
            });
            let bytes = kit_core::serialize::serialize(&blob).unwrap();
            entries.push(TreeEntry {
                name: format!("f{file:06}").into_bytes(),
                mode: EntryMode::Blob,
                object_hash: batch.write(&bytes).unwrap(),
            });
            let Object::Blob(Blob { data: back }) = blob else {
                unreachable!()
            };
            data = back;
        }
        if entries.is_empty() {
            continue;
        }
        let tree = Object::Tree(Tree { entries });
        dirs.push(TreeEntry {
            name: format!("d{dir:03}").into_bytes(),
            mode: EntryMode::Tree,
            object_hash: batch
                .write(&kit_core::serialize::serialize(&tree).unwrap())
                .unwrap(),
        });
    }
    let root = Object::Tree(Tree { entries: dirs });
    let root = batch
        .write(&kit_core::serialize::serialize(&root).unwrap())
        .unwrap();
    let mut commit = Commit::new_unannotated(
        root,
        Vec::new(),
        Identity::ed25519(key.public.0),
        key.public.0,
        b"many files".to_vec(),
        1_700_000_000,
        [0u8; 64],
    );
    commit.signature = sign::sign_commit(&commit, key).unwrap().0;
    let tip = batch
        .write(&kit_core::serialize::serialize(&Object::Commit(commit)).unwrap())
        .unwrap();
    batch.commit().unwrap();
    refs::write_ref(&layout, "main", &tip).unwrap();
    refs::write_head_branch(&layout, "main").unwrap();
    tip
}

/// The sizes of the packs a push uploaded.
#[derive(Default)]
struct Uploads(Mutex<Vec<u64>>);

impl kit_sync::Observer<kit_sync::SyncEvent> for Uploads {
    fn event(&self, event: &kit_sync::SyncEvent) {
        if let kit_sync::SyncEvent::PackUploaded { bytes } = event {
            self.0.lock().unwrap().push(*bytes);
        }
    }
}

fn clone_remote(url: &str, kind: &str) -> CloneRemote {
    CloneRemote {
        name: "default".to_owned(),
        url: url.to_owned(),
        kind: kind.to_owned(),
    }
}

/// Push a repository of `files` files of 64 KiB, one pack of about 1 GiB
/// for 17,000 files, to `tx`. Then fetch it into a new clone, and check
/// that each held under 96 MiB plus the entry charge. Every fourth file
/// ends in zeros, so a quarter of the entries are zstd frames. zstd's own
/// contexts are allocated in C and not counted. Returns the pack's length.
fn push_and_fetch_one_pack(
    tx: &dyn Transport,
    remote: &CloneRemote,
    files: usize,
    what: &str,
) -> u64 {
    const LEN: usize = 64 * KIB;
    const ZEROS: usize = 8 * KIB;
    let entries = files + files.min(256) + 2;
    let bound = 96 * MIB + 320 * entries;
    let dir = tempfile::tempdir().unwrap();
    let origin = dir.path().join("origin");
    init_clone_dir(&origin, remote).unwrap();
    let key = KeyPair::generate().unwrap();
    let tip = commit_files(&origin, &key, files, LEN, ZEROS);
    let source = TransportSource::new(tx);

    let uploads = Uploads::default();
    let mut options = kit_sync::PushOptions::default();
    options.pack_payload_cap = pack::MAX_TOTAL_PAYLOAD;
    options.control.observer = &uploads;
    let (report, push_peak) = peak_of(|| kit_sync::push(&origin, &source, &options));
    report.unwrap();
    let packs = uploads.0.into_inner().unwrap();
    eprintln!(
        "{what}: push of {packs:?} bytes: peak heap {} MiB, bound {} MiB",
        push_peak / MIB,
        bound / MIB
    );
    assert_eq!(packs.len(), 1, "{packs:?}");
    assert!(push_peak < bound, "{what}: a push held {push_peak} bytes");
    assert_eq!(source.read_ref("refs/heads/main").unwrap(), Some(tip));

    let target = dir.path().join("work");
    init_clone_dir(&target, remote).unwrap();
    let (report, fetch_peak) = peak_of(|| {
        fetch(
            &target,
            &source,
            "default",
            &SyncOptions::default(),
            &NoopObserver,
        )
    });
    report.unwrap();
    eprintln!(
        "{what}: fetch of one {}-byte pack: peak heap {} MiB, bound {} MiB",
        packs[0],
        fetch_peak / MIB,
        bound / MIB
    );
    assert_eq!(
        refs::read_remote_ref(&RepoLayout::single(&target), "default", "main").unwrap(),
        Some(tip)
    );
    assert!(
        fetch_peak < bound,
        "{what}: a fetch held {fetch_peak} bytes"
    );
    packs[0]
}

// ---------------------------------------------------------------------------
// ssh: a stand-in for `ssh`, and each test again in a child process
// ---------------------------------------------------------------------------

/// Names the stand-in's attempt counter file. Only the child sees it.
const SSH_COUNTER_ENV: &str = "KIT_TEST_SSH_COUNTER";
/// Bytes the stand-in lets through on its first connection before it ends
/// that connection. Unset: every connection is whole.
const SSH_CUT_ENV: &str = "KIT_TEST_SSH_CUT";

/// An `ssh` stand-in that runs `kit serve <path>`. On its first connection,
/// with `KIT_TEST_SSH_CUT` set, the server reads only that many bytes of
/// the client's stream and then sees its end, as if the connection dropped.
fn write_ssh_wrapper(dir: &Path) -> PathBuf {
    let wrapper = dir.join("fake_ssh.sh");
    let script = r#"#!/bin/sh
set -eu
found=0
path=""
for a in "$@"; do
  if [ "$found" = 2 ]; then
    path="$a"
    break
  fi
  if [ "$found" = 1 ] && [ "$a" = serve ]; then
    found=2
    continue
  fi
  if [ "$a" = kit ]; then
    found=1
  fi
done
if [ -z "$path" ]; then
  echo "fake_ssh: could not locate 'kit serve <path>' in argv" >&2
  exit 64
fi
count=0
if [ -f "$KIT_TEST_SSH_COUNTER" ]; then
  count=$(cat "$KIT_TEST_SSH_COUNTER")
fi
count=$((count + 1))
echo "$count" > "$KIT_TEST_SSH_COUNTER"
if [ "$count" -eq 1 ] && [ -n "${KIT_TEST_SSH_CUT:-}" ]; then
  dd bs=1 count="$KIT_TEST_SSH_CUT" 2>/dev/null | "$KIT_SSH_TARGET_BIN" serve "$path"
  exit 0
fi
exec "$KIT_SSH_TARGET_BIN" serve "$path"
"#;
    fs::write(&wrapper, script).unwrap();
    let mut perms = fs::metadata(&wrapper).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&wrapper, perms).unwrap();
    wrapper
}

/// Whether this process is the child that runs the ssh test `name`. In the
/// parent, it runs `name` again in a child of this binary, with
/// `KIT_SSH_PROGRAM` naming the stand-in and `extra` set, and checks that
/// the child passed. The child is told apart by the attempt counter, which
/// only this test sets.
fn in_ssh_child(name: &str, extra: &[(&str, &str)]) -> bool {
    if std::env::var_os(SSH_COUNTER_ENV).is_some() {
        return true;
    }
    let dir = tempfile::tempdir().unwrap();
    let wrapper = write_ssh_wrapper(dir.path());
    let mut cmd = Command::new(std::env::current_exe().unwrap());
    cmd.args([name, "--exact", "--nocapture", "--include-ignored"])
        .env("KIT_SSH_PROGRAM", &wrapper)
        .env("KIT_SSH_TARGET_BIN", env!("CARGO_BIN_EXE_kit"))
        .env(SSH_COUNTER_ENV, dir.path().join("attempts"))
        .stdin(Stdio::null());
    for (key, value) in extra {
        cmd.env(key, value);
    }
    let out = cmd.output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("1 passed"),
        "{name} in a child process:\n{stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    eprint!("{}", String::from_utf8_lossy(&out.stderr));
    false
}

/// The stand-in's connections so far.
fn ssh_attempts() -> u32 {
    let counter = std::env::var(SSH_COUNTER_ENV).unwrap();
    fs::read_to_string(counter).map_or(0, |n| n.trim().parse().unwrap())
}

fn fast_backoff() -> BackoffIterator {
    BackoffIterator::with(Duration::from_millis(1), Duration::from_millis(1), 3)
}

fn no_sleep(_: Duration) {}

/// A served repository in `dir`, and an ssh transport to it.
fn ssh_remote(dir: &Path) -> (SshTransport, String) {
    let remote = dir.join("remote");
    fs::create_dir_all(&remote).unwrap();
    let init = Command::new(env!("CARGO_BIN_EXE_kit"))
        .arg("init")
        .current_dir(&remote)
        .env("XDG_CONFIG_HOME", dir)
        .env("HOME", dir)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(init.status.success(), "{init:?}");
    let url = format!("kit+ssh://test@localhost{}", remote.display());
    let target = parse_kit_ssh_url(&url).unwrap();
    let tx = SshTransport::connect_with_options_and_retry(
        &target,
        &SshOptions::default(),
        fast_backoff,
        no_sleep,
    )
    .unwrap();
    (tx, url)
}

/// An upload whose connection drops part way reconnects and sends the pack
/// again from offset 0, and the server takes it only once its bytes match
/// the key.
#[test]
fn ssh_upload_cut_mid_pack_is_sent_again_from_offset_zero() {
    let name = "ssh_upload_cut_mid_pack_is_sent_again_from_offset_zero";
    if !in_ssh_child(name, &[(SSH_CUT_ENV, "1000000")]) {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let (tx, _) = ssh_remote(dir.path());
    let spooled = spooled_pack(dir.path(), 1, 6, 600 * KIB);
    assert!(spooled.len() > 3 * MIB as u64);
    let key = PackKey::from_hash(spooled.key());
    let body = Recorded::new(&spooled);

    tx.upload_pack(&body, &key, None).unwrap();

    assert_eq!(ssh_attempts(), 2, "the first connection drops");
    assert_eq!(body.reads(), [0, 0], "each attempt reads from offset 0");
    assert!(tx.pack_exists(&key, None).unwrap());
    download_verified(&tx, &key, dir.path());
}

/// A body whose length is over the limit is refused before it is read and
/// before any frame: the connection carries the next verb.
#[test]
fn ssh_upload_over_the_limit_is_refused_before_any_read() {
    let name = "ssh_upload_over_the_limit_is_refused_before_any_read";
    if !in_ssh_child(name, &[]) {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let (tx, _) = ssh_remote(dir.path());
    let spooled = spooled_pack(dir.path(), 2, 1, KIB);
    let key = PackKey::from_hash(spooled.key());
    let body = Recorded::new(&spooled).claiming(PACK_BODY_LIMIT + 1);

    assert!(matches!(
        tx.upload_pack(&body, &key, None),
        Err(TransportError::PayloadTooLarge(_))
    ));
    assert!(body.reads().is_empty());
    assert!(!tx.pack_exists(&key, None).unwrap());
    assert_eq!(ssh_attempts(), 1);
}

/// A body that ends before its length is a local error: the upload is not
/// retried, and the connection, whose server still waits for chunks, is
/// closed, so the next verb runs on a new one.
#[test]
fn ssh_upload_of_a_short_body_is_not_retried_and_the_next_verb_reconnects() {
    let name = "ssh_upload_of_a_short_body_is_not_retried_and_the_next_verb_reconnects";
    if !in_ssh_child(name, &[]) {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let (tx, _) = ssh_remote(dir.path());
    let spooled = spooled_pack(dir.path(), 6, 3, 600 * KIB);
    let key = PackKey::from_hash(spooled.key());
    let body = Recorded::new(&spooled).claiming(spooled.len() + 1);

    assert!(matches!(
        tx.upload_pack(&body, &key, None),
        Err(TransportError::ProtocolError)
    ));
    assert_eq!(body.reads(), [0], "not retried");
    assert_eq!(ssh_attempts(), 1);
    assert!(!tx.pack_exists(&key, None).unwrap());
    assert_eq!(ssh_attempts(), 2, "the next verb reconnects");
    tx.upload_pack(&spooled, &key, None).unwrap();
    download_verified(&tx, &key, dir.path());
}

/// A download whose declared length is over the sink's limit is refused
/// before any byte reaches the sink.
#[test]
fn ssh_download_over_the_sink_limit_is_refused_before_any_write() {
    let name = "ssh_download_over_the_sink_limit_is_refused_before_any_write";
    if !in_ssh_child(name, &[]) {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let (tx, _) = ssh_remote(dir.path());
    let spooled = spooled_pack(dir.path(), 3, 3, 600 * KIB);
    let key = PackKey::from_hash(spooled.key());
    tx.upload_pack(&spooled, &key, None).unwrap();

    let mut sink = Recording {
        limit: spooled.len() - 1,
        ..Recording::default()
    };
    assert!(matches!(
        tx.download_pack(&key, None, &mut sink),
        Err(TransportError::PayloadTooLarge(_))
    ));
    assert_eq!(sink.begins, [Some(spooled.len())]);
    assert_eq!(sink.written, 0);
    download_verified(&tx, &key, dir.path());
}

/// A push and a fetch of one pack just under 1 GiB over ssh each hold
/// under 96 MiB plus the entry charge. `kit serve` takes at most 1 GiB of
/// upload in one session (SPEC-TRANSPORT §4.4), so this is about the
/// largest pack it takes.
#[test]
#[ignore = "pushes and fetches a 1 GiB pack over ssh; run in the ignored lane"]
fn ssh_push_and_fetch_of_one_1_gib_pack_hold_under_96_mib_and_the_entry_charge() {
    let name = "ssh_push_and_fetch_of_one_1_gib_pack_hold_under_96_mib_and_the_entry_charge";
    if !in_ssh_child(name, &[]) {
        return;
    }
    let _guard = serial();
    let dir = tempfile::tempdir().unwrap();
    let (tx, url) = ssh_remote(dir.path());
    let len = push_and_fetch_one_pack(&tx, &clone_remote(&url, "ssh"), 16_700, "ssh");
    assert!(len > 1_000_000_000 && len < 1 << 30, "{len}");
}

// ---------------------------------------------------------------------------
// S3, against the store the environment names
// ---------------------------------------------------------------------------

#[cfg(feature = "s3")]
mod s3 {
    use super::*;
    use kit_transport_s3::S3Transport;
    use kit_transport_s3::sigv4::Credentials;

    /// A transport to the test store under a prefix of its own, or `None`
    /// when the environment names no store.
    fn s3_remote() -> Option<S3Transport> {
        let var = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
        let (Some(endpoint), Some(bucket), Some(access), Some(secret)) = (
            var("KIT_TEST_S3_ENDPOINT"),
            var("KIT_TEST_S3_BUCKET"),
            var("KIT_TEST_S3_ACCESS_KEY"),
            var("KIT_TEST_S3_SECRET_KEY"),
        ) else {
            eprintln!("SKIP: KIT_TEST_S3_ENDPOINT and its bucket and keys are not set");
            return None;
        };
        let prefix = format!(
            "t{}",
            hash::to_hex(&hash::hash(&rand_bytes()))[..16].to_owned()
        );
        let mut tx = S3Transport::with_parts(
            endpoint,
            bucket,
            Some(prefix),
            Credentials {
                access_key_id: access,
                secret_access_key: secret,
                region: var("KIT_TEST_S3_REGION").unwrap_or_else(|| "us-east-1".to_owned()),
            },
        )
        .unwrap();
        tx.set_backoff(fast_backoff);
        tx.set_sleeper(no_sleep);
        Some(tx)
    }

    fn rand_bytes() -> [u8; 32] {
        let mut out = [0u8; 32];
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        out[..16].copy_from_slice(&nanos.to_le_bytes());
        out[16..20].copy_from_slice(&std::process::id().to_le_bytes());
        out
    }

    /// The store takes a `PUT` signed over the SHA-256 of the bytes it
    /// streams, and the pack reads back whole.
    #[test]
    #[ignore = "needs an S3 store: set KIT_TEST_S3_ENDPOINT and its bucket and keys"]
    fn s3_signed_streaming_put_is_accepted() {
        let Some(tx) = s3_remote() else { return };
        let dir = tempfile::tempdir().unwrap();
        let spooled = spooled_pack(dir.path(), 4, 6, 600 * KIB);
        let key = PackKey::from_hash(spooled.key());
        let body = Recorded::new(&spooled);

        tx.upload_pack(&body, &key, None).unwrap();

        assert_eq!(body.reads(), [0, 0], "one hash pass, then one send");
        assert!(tx.pack_exists(&key, None).unwrap());
        download_verified(&tx, &key, dir.path());
    }

    /// A body whose bytes or length differ from what was hashed is refused,
    /// and nothing is stored.
    #[test]
    #[ignore = "needs an S3 store: set KIT_TEST_S3_ENDPOINT and its bucket and keys"]
    fn s3_wrong_length_or_bytes_are_refused() {
        let Some(tx) = s3_remote() else { return };
        let dir = tempfile::tempdir().unwrap();
        let spooled = spooled_pack(dir.path(), 5, 4, 600 * KIB);
        let key = PackKey::from_hash(spooled.key());

        // Bytes that change after the hash pass: the store checks the
        // payload hash it was signed with.
        let changed = Recorded::new(&spooled).after_first(AfterFirst::Flip(MIB as u64));
        let err = tx.upload_pack(&changed, &key, None).unwrap_err();
        assert!(
            matches!(err, TransportError::ServerError { status: 400 }),
            "{err:?}"
        );
        assert_eq!(changed.reads(), [0, 0], "a 400 is not retried");
        assert!(!tx.pack_exists(&key, None).unwrap());

        // A body that ends before its length while it is sent: the request
        // ends unfinished, and the local error is not retried.
        let cut = Recorded::new(&spooled).after_first(AfterFirst::Cut(MIB as u64));
        assert!(matches!(
            tx.upload_pack(&cut, &key, None),
            Err(TransportError::ProtocolError)
        ));
        assert_eq!(cut.reads(), [0, 0]);
        assert!(!tx.pack_exists(&key, None).unwrap());

        // A length longer than the body: refused by the hash pass, before
        // any request.
        let long = Recorded::new(&spooled).claiming(spooled.len() + 1);
        assert!(matches!(
            tx.upload_pack(&long, &key, None),
            Err(TransportError::ProtocolError)
        ));
        assert_eq!(long.reads(), [0]);
        assert!(!tx.pack_exists(&key, None).unwrap());
    }

    /// An error answer's body never reaches the sink.
    #[test]
    #[ignore = "needs an S3 store: set KIT_TEST_S3_ENDPOINT and its bucket and keys"]
    fn s3_error_body_never_reaches_the_sink() {
        let Some(tx) = s3_remote() else { return };
        let missing = PackKey::from_hash([9; 32]);
        let mut sink = Recording {
            limit: u64::MAX,
            ..Recording::default()
        };
        assert!(matches!(
            tx.download_pack(&missing, None, &mut sink),
            Err(TransportError::PackNotFound)
        ));
        assert!(sink.begins.is_empty());
        assert_eq!(sink.written, 0);
    }

    /// A push and a fetch of one 1 GiB pack over S3 each hold under 96 MiB
    /// plus the entry charge.
    #[test]
    #[ignore = "needs an S3 store: set KIT_TEST_S3_ENDPOINT and its bucket and keys"]
    fn s3_push_and_fetch_of_one_1_gib_pack_hold_under_96_mib_and_the_entry_charge() {
        let _guard = serial();
        let Some(tx) = s3_remote() else { return };
        let remote = clone_remote("kit+s3://test/bucket", "s3");
        let len = push_and_fetch_one_pack(&tx, &remote, 17_000, "S3");
        assert!(len > 1 << 30, "{len}");
    }
}
