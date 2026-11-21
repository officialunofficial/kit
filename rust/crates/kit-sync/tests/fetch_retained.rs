//! A verified pack whose apply fails stays on disk for the retry, which reads
//! it again, checks it against its key, and does not download it. Nothing is
//! published to a tracking ref until a pack applies and the closure checks.
//!
//! A full disk is injected with `kit_core::fault`, which fails every write
//! of a kind in the process, so the tests here run one at a time.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::cell::Cell;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use kit_core::fault::{self, Site};
use kit_core::hash::{self, Hash};
use kit_core::layout::RepoLayout;
use kit_core::object::{Blob, Commit, EntryMode, Identity, Object, Tree, TreeEntry};
use kit_core::pack::{self, PackWriter};
use kit_core::protocol::{PackKey, PackSink, SliceBody, Transport};
use kit_core::refs::{self, RefWriteCondition};
use kit_core::sign::{self, KeyPair};
use kit_core::{serialize, transfer};
use kit_sync::{
    AppliedPacks, CloneRemote, DownloadSavings, Observer, RemoteSource, SourceError, SyncError,
    SyncEvent, SyncOptions, TransportSource, fetch, init_clone_dir,
};
use kit_transport_memory::MemoryTransport;

static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Bytes that do not compress.
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

/// A remote whose `main` is one signed commit of one 3 MiB file, in one pack:
/// longer than the spool's buffer, so the spool writes to its file while
/// the pack arrives.
struct Remote {
    tx: MemoryTransport,
    tip: Hash,
    pack: Hash,
}

fn remote() -> Remote {
    let tx = MemoryTransport::new();
    let blob = Object::Blob(Blob {
        data: noise(3 << 20, 7),
    });
    let tree = Object::Tree(Tree {
        entries: vec![TreeEntry {
            name: b"big.bin".to_vec(),
            mode: EntryMode::Blob,
            object_hash: blob.id().unwrap(),
        }],
    });
    let key = KeyPair::generate().unwrap();
    let mut commit = Commit::new_unannotated(
        tree.id().unwrap(),
        Vec::new(),
        Identity::ed25519(key.public.0),
        key.public.0,
        b"big file".to_vec(),
        1_700_000_000,
        [0u8; 64],
    );
    commit.signature = sign::sign_commit(&commit, &key).unwrap().0;
    let commit = Object::Commit(commit);
    let mut writer = PackWriter::new();
    for object in [&blob, &tree, &commit] {
        writer
            .push_raw(object.id().unwrap(), &serialize::serialize(object).unwrap())
            .unwrap();
    }
    let bytes = writer.finish().unwrap();
    let pack = pack::pack_key(&bytes);
    tx.upload_pack(&SliceBody(&bytes), &PackKey::from_hash(pack), None)
        .unwrap();
    let node = transfer::encode_packlist(None, &[pack]).unwrap();
    let node_key = hash::hash(&node);
    tx.upload_blob(&node, &PackKey::from_hash(node_key), None)
        .unwrap();
    tx.update_ref(
        "refs/kit/packmap/main",
        RefWriteCondition::Missing,
        &node_key,
    )
    .unwrap();
    let tip = commit.id().unwrap();
    tx.update_ref("refs/heads/main", RefWriteCondition::Missing, &tip)
        .unwrap();
    Remote { tx, tip, pack }
}

/// A clone directory with nothing fetched yet.
fn target() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let work = dir.path().join("work");
    init_clone_dir(
        &work,
        &CloneRemote {
            name: "origin".to_owned(),
            url: "kit+memory://spool".to_owned(),
            kind: "memory".to_owned(),
        },
    )
    .unwrap();
    (dir, work)
}

/// Records what a fetch reports.
#[derive(Default)]
struct Events(Mutex<Vec<SyncEvent>>);

impl Observer<SyncEvent> for Events {
    fn event(&self, event: &SyncEvent) {
        self.0.lock().unwrap().push(event.clone());
    }
}

fn run_fetch(
    work: &Path,
    source: &dyn RemoteSource,
    events: &Events,
) -> Result<DownloadSavings, SyncError> {
    fetch(work, source, "origin", &SyncOptions::default(), events).map(|report| report.savings)
}

fn retained_dir(work: &Path) -> PathBuf {
    work.join(".kit").join("tmp").join("retained")
}

fn retained_files(work: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(retained_dir(work))
        .map(|list| {
            list.map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}

fn retained_path(work: &Path, pack: Hash) -> PathBuf {
    retained_dir(work).join(format!("{}.pack", PackKey::from_hash(pack).to_hex()))
}

fn recorded(work: &Path, pack: Hash) -> bool {
    AppliedPacks::load(&RepoLayout::single(work), "origin")
        .unwrap()
        .contains(&PackKey::from_hash(pack))
}

fn remote_tip(work: &Path) -> Option<Hash> {
    refs::read_remote_ref(&RepoLayout::single(work), "origin", "main").unwrap()
}

/// Counts pack downloads.
struct Downloads<'a> {
    inner: TransportSource<'a>,
    packs: Cell<usize>,
}

impl<'a> Downloads<'a> {
    fn new(remote: &'a Remote) -> Self {
        Self {
            inner: TransportSource::new(&remote.tx),
            packs: Cell::new(0),
        }
    }
}

impl RemoteSource for Downloads<'_> {
    fn list_branches(&self) -> Result<Vec<refs::Ref>, SourceError> {
        self.inner.list_branches()
    }
    fn list_refs(&self, prefix: &str) -> Result<Vec<refs::Ref>, SourceError> {
        self.inner.list_refs(prefix)
    }
    fn read_ref(&self, name: &str) -> Result<Option<Hash>, SourceError> {
        self.inner.read_ref(name)
    }
    fn download_blob(&self, key: &PackKey, ref_hint: &str) -> Result<Vec<u8>, SourceError> {
        self.inner.download_blob(key, ref_hint)
    }
    fn download_pack(
        &self,
        key: &PackKey,
        ref_hint: &str,
        sink: &mut dyn PackSink,
    ) -> Result<(), SourceError> {
        self.packs.set(self.packs.get() + 1);
        self.inner.download_pack(key, ref_hint, sink)
    }
}

/// A fetch that fails to store the pack on a full disk.
fn failed_apply(work: &Path, source: &Downloads<'_>) {
    let _full = fault::fail_writes(Site::Store);
    assert!(matches!(
        run_fetch(work, source, &Events::default()),
        Err(SyncError::Io(_))
    ));
}

#[test]
fn a_pack_whose_apply_fails_is_kept_and_the_retry_does_not_download_it() {
    let _guard = serial();
    let remote = remote();
    let (_dir, work) = target();
    let source = Downloads::new(&remote);

    failed_apply(&work, &source);

    assert_eq!(source.packs.get(), 1);
    assert_eq!(retained_files(&work).len(), 1);
    assert!(retained_path(&work, remote.pack).is_file());
    // Nothing is published before the pack applies and the closure checks.
    assert!(!recorded(&work, remote.pack));
    assert_eq!(remote_tip(&work), None);

    let events = Events::default();
    let savings = run_fetch(&work, &source, &events).unwrap();

    assert_eq!(source.packs.get(), 1, "the retry downloads nothing");
    assert_eq!(remote_tip(&work), Some(remote.tip));
    assert!(recorded(&work, remote.pack));
    assert!(savings.bytes_reused > 3 << 20);
    assert!(events.0.lock().unwrap().iter().any(
        |event| matches!(event, SyncEvent::PackReused { bytes } if *bytes == savings.bytes_reused)
    ));
    assert_eq!(
        retained_files(&work),
        Vec::<String>::new(),
        "removed after success"
    );
}

#[test]
fn a_kept_pack_whose_retry_fails_again_stays_for_the_next() {
    let _guard = serial();
    let remote = remote();
    let (_dir, work) = target();
    let source = Downloads::new(&remote);

    failed_apply(&work, &source);
    failed_apply(&work, &source);

    assert_eq!(source.packs.get(), 1, "the second try read the disk");
    assert_eq!(retained_files(&work).len(), 1);

    run_fetch(&work, &source, &Events::default()).unwrap();
    assert_eq!(source.packs.get(), 1);
    assert_eq!(retained_files(&work), Vec::<String>::new());
}

/// How a test spoils a kept pack.
type Damage = Box<dyn Fn(Vec<u8>) -> Vec<u8>>;

#[test]
fn a_damaged_stale_or_short_kept_pack_is_refused_and_downloaded_again() {
    let _guard = serial();
    let remote = remote();
    let other = {
        let mut writer = PackWriter::new();
        let blob = Object::Blob(Blob { data: vec![1; 64] });
        writer
            .push_raw(blob.id().unwrap(), &serialize::serialize(&blob).unwrap())
            .unwrap();
        writer.finish().unwrap()
    };
    let cases: Vec<(&str, Damage)> = vec![
        (
            "flipped byte",
            Box::new(|mut bytes| {
                let middle = bytes.len() / 2;
                bytes[middle] ^= 1;
                bytes
            }),
        ),
        ("short", Box::new(|bytes| bytes[..bytes.len() - 1].to_vec())),
        ("another pack", Box::new(move |_| other.clone())),
        ("empty", Box::new(|_| Vec::new())),
    ];
    for (name, damage) in cases {
        let (_dir, work) = target();
        let source = Downloads::new(&remote);
        failed_apply(&work, &source);
        let path = retained_path(&work, remote.pack);
        std::fs::write(&path, damage(std::fs::read(&path).unwrap())).unwrap();

        let savings = run_fetch(&work, &source, &Events::default()).unwrap();

        assert_eq!(source.packs.get(), 2, "{name}: downloaded again");
        assert_eq!(savings.bytes_reused, 0, "{name}");
        assert_eq!(remote_tip(&work), Some(remote.tip), "{name}");
        assert_eq!(retained_files(&work), Vec::<String>::new(), "{name}");
    }
}

#[test]
fn a_kept_pack_that_has_aged_out_is_dropped_when_a_fetch_starts() {
    let _guard = serial();
    let remote = remote();
    let (_dir, work) = target();
    let source = Downloads::new(&remote);
    failed_apply(&work, &source);
    let path = retained_path(&work, remote.pack);
    let eight_days = Duration::from_hours(8 * 24);
    std::fs::File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_modified(std::time::SystemTime::now() - eight_days)
        .unwrap();

    let savings = run_fetch(&work, &source, &Events::default()).unwrap();

    assert_eq!(source.packs.get(), 2);
    assert_eq!(savings.bytes_reused, 0);
    assert_eq!(retained_files(&work), Vec::<String>::new());
}

#[test]
fn a_fetch_that_downloads_and_applies_keeps_nothing() {
    let _guard = serial();
    let remote = remote();
    let (_dir, work) = target();
    let source = Downloads::new(&remote);

    let savings = run_fetch(&work, &source, &Events::default()).unwrap();

    assert_eq!(savings, DownloadSavings::default());
    assert_eq!(retained_files(&work), Vec::<String>::new());
    assert!(!retained_dir(&work).exists() || retained_files(&work).is_empty());
}
