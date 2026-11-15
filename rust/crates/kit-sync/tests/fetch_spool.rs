//! A fetch spools each pack in `.kit/tmp/` and leaves nothing there: not
//! when it is killed mid-pack, not when the disk fills, and not after a
//! stale file from an earlier run.
//!
//! A full disk is injected with `kit_core::fault`, which fails every write
//! of a kind in the process, so the tests here run one at a time.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::cell::Cell;
use std::io::ErrorKind;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use kit_core::fault::{self, Site};
use kit_core::hash::{self, Hash};
use kit_core::layout::RepoLayout;
use kit_core::object::{Blob, Commit, EntryMode, Identity, Object, Tree, TreeEntry};
use kit_core::pack::{self, PackSpool, PackWriter};
use kit_core::protocol::{
    BackoffIterator, PACK_BODY_LIMIT, PackKey, PackSink, SliceBody, Transport, TransportError,
    retrying,
};
use kit_core::refs::{self, RefWriteCondition};
use kit_core::sign::{self, KeyPair};
use kit_core::{serialize, transfer};
use kit_sync::{
    AppliedPacks, CloneRemote, NoopObserver, RemoteSource, SourceError, SyncError, SyncOptions,
    TransportSource, fetch, init_clone_dir,
};
use kit_transport_memory::MemoryTransport;

/// The tests share the injected failures, so each one holds this while it
/// runs.
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

fn run_fetch(work: &Path, source: &dyn RemoteSource) -> Result<(), SyncError> {
    fetch(
        work,
        source,
        "origin",
        &SyncOptions::default(),
        &NoopObserver,
    )
    .map(drop)
}

fn spool_dir(work: &Path) -> std::path::PathBuf {
    work.join(".kit").join("tmp")
}

/// The entries in `dir`, or none when it is missing.
fn entries(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir).map_or_else(
        |_| Vec::new(),
        |list| {
            list.map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect()
        },
    )
}

/// Files under the objects directory whose names are not object ids: the
/// temporary files of an unfinished store write.
fn stray_object_files(work: &Path) -> Vec<String> {
    fn walk(dir: &Path, out: &mut Vec<String>) {
        for entry in std::fs::read_dir(dir).into_iter().flatten() {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else {
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.len() != 62 || !name.bytes().all(|b| b.is_ascii_hexdigit()) {
                    out.push(path.display().to_string());
                }
            }
        }
    }
    let mut out = Vec::new();
    walk(&work.join(".kit").join("objects"), &mut out);
    out
}

/// Whether the applied-pack record of `origin` names `pack`.
fn recorded(work: &Path, pack: Hash) -> bool {
    AppliedPacks::load(&RepoLayout::single(work), "origin")
        .unwrap()
        .contains(&PackKey::from_hash(pack))
}

fn remote_tip(work: &Path) -> Option<Hash> {
    refs::read_remote_ref(&RepoLayout::single(work), "origin", "main").unwrap()
}

/// Counts pack downloads and, when `cut` is set, writes the first half of
/// the pack into the spool and panics, as a fetch killed mid-pack would
/// stop.
struct Downloads<'a> {
    inner: TransportSource<'a>,
    remote: &'a Remote,
    packs: Cell<usize>,
    cut: bool,
}

impl<'a> Downloads<'a> {
    fn new(remote: &'a Remote, cut: bool) -> Self {
        Self {
            inner: TransportSource::new(&remote.tx),
            remote,
            packs: Cell::new(0),
            cut,
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
        if self.cut {
            let bytes = self.remote.tx.download_blob(key, None, u64::MAX).unwrap();
            sink.begin(Some(bytes.len() as u64)).unwrap();
            sink.write(&bytes[..bytes.len() / 2]).unwrap();
            panic!("the fetch is killed mid-pack");
        }
        self.inner.download_pack(key, ref_hint, sink)
    }
}

#[test]
fn a_fetch_killed_mid_pack_leaves_no_record_and_no_spool_and_the_next_one_applies() {
    let _guard = serial();
    let remote = remote();
    let (_dir, work) = target();

    let killed = catch_unwind(AssertUnwindSafe(|| {
        run_fetch(&work, &Downloads::new(&remote, true))
    }));

    assert!(killed.is_err());
    assert!(!recorded(&work, remote.pack));
    assert_eq!(entries(&spool_dir(&work)), Vec::<String>::new());
    assert_eq!(remote_tip(&work), None);

    let source = Downloads::new(&remote, false);
    run_fetch(&work, &source).unwrap();
    assert_eq!(source.packs.get(), 1);
    assert_eq!(remote_tip(&work), Some(remote.tip));
    assert!(recorded(&work, remote.pack));
    assert_eq!(entries(&spool_dir(&work)), Vec::<String>::new());
}

/// A full disk under the spool, or under the store, ends the fetch as
/// `SyncError::Io` after one download, with no file left behind. The next
/// fetch, on a disk with room, applies the pack.
#[test]
fn a_full_disk_ends_the_fetch_as_an_io_error_without_a_retry_or_a_file() {
    let _guard = serial();
    let remote = remote();
    for site in [Site::Spool, Site::Store] {
        let (_dir, work) = target();
        let source = Downloads::new(&remote, false);

        let failed = {
            let _full = fault::fail_writes(site);
            run_fetch(&work, &source)
        };

        match failed {
            Err(SyncError::Io(error)) => {
                assert_eq!(error.kind(), ErrorKind::StorageFull, "{site:?}: {error}");
                if site == Site::Spool {
                    let message = error.to_string();
                    assert!(message.contains(".kit/tmp"), "{message}");
                }
            }
            other => panic!("{site:?}: expected SyncError::Io, got {other:?}"),
        }
        assert_eq!(
            source.packs.get(),
            1,
            "{site:?}: the download is not retried"
        );
        assert_eq!(entries(&spool_dir(&work)), Vec::<String>::new(), "{site:?}");
        assert_eq!(stray_object_files(&work), Vec::<String>::new(), "{site:?}");
        assert!(!recorded(&work, remote.pack), "{site:?}");
        assert_eq!(remote_tip(&work), None, "{site:?}");

        run_fetch(&work, &source).unwrap();
        assert_eq!(remote_tip(&work), Some(remote.tip), "{site:?}");
    }
}

/// Once a spool's write fails, a `begin` from a retry, a fallback to
/// another location or a reconnect is refused and `failed()` stays set, so
/// the transfer ends at the first local error.
#[test]
fn a_failed_spool_refuses_every_later_begin() {
    let _guard = serial();
    let dir = tempfile::tempdir().unwrap();
    let mut spool = PackSpool::create(dir.path(), PACK_BODY_LIMIT).unwrap();
    let body = noise(2 << 20, 3);
    let attempts = Cell::new(0);

    let result = retrying(
        || {
            attempts.set(attempts.get() + 1);
            PackSink::begin(&mut spool, Some(body.len() as u64))?;
            if attempts.get() == 1 {
                let _full = fault::fail_writes(Site::Spool);
                let written = PackSink::write(&mut spool, &body);
                assert!(matches!(written, Err(TransportError::ProtocolError)));
                // The connection drops as well: the ladder would retry.
                return Err(TransportError::ConnectionFailed);
            }
            PackSink::write(&mut spool, &body)
        },
        || BackoffIterator::with(Duration::ZERO, Duration::ZERO, 5),
        |_| {},
    );

    assert_eq!(attempts.get(), 2, "the retry's begin ends the transfer");
    assert!(
        matches!(result, Err(TransportError::ProtocolError)),
        "{result:?}"
    );
    assert_eq!(PackSink::failed(&spool), Some(ErrorKind::StorageFull));
    // A fallback or reconnect begins again later: still refused.
    assert!(PackSink::begin(&mut spool, None).is_err());
    assert_eq!(PackSink::failed(&spool), Some(ErrorKind::StorageFull));
}

/// The sweep at fetch start removes a file an earlier run left in
/// `.kit/tmp/`, and a spool another transfer holds open there keeps working.
#[test]
fn the_sweep_at_fetch_start_removes_a_stale_file_and_leaves_an_open_spool() {
    let _guard = serial();
    let remote = remote();
    let (_dir, work) = target();
    let tmp = spool_dir(&work);
    std::fs::create_dir_all(&tmp).unwrap();
    std::fs::write(tmp.join("stale"), b"left by a power loss").unwrap();
    let body = remote
        .tx
        .download_blob(&PackKey::from_hash(remote.pack), None, u64::MAX)
        .unwrap();
    let mut open = PackSpool::create(&tmp, PACK_BODY_LIMIT).unwrap();
    open.begin(Some(body.len() as u64)).unwrap();
    open.write(&body[..body.len() / 2]).unwrap();

    run_fetch(&work, &Downloads::new(&remote, false)).unwrap();

    assert_eq!(entries(&tmp), Vec::<String>::new());
    open.write(&body[body.len() / 2..]).unwrap();
    open.finish(&PackKey::from_hash(remote.pack)).unwrap();
}
