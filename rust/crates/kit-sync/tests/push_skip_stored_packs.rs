//! A push that is run again after it failed sends only the packs the remote
//! does not hold yet, and never moves a ref before every pack and the
//! packmap are in place.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::path::PathBuf;
use std::sync::Mutex;

use kit_core::hash::Hash;
use kit_core::layout::RepoLayout;
use kit_core::object::{Blob, Commit, EntryMode, Identity, Object, Tree, TreeEntry};
use kit_core::protocol::{
    AdvanceOutcome, PackBody, PackKey, PackSink, RefListing, RepoCursor, Transport, TransportError,
    TransportResult,
};
use kit_core::refs::{self, Ref, RefWriteCondition};
use kit_core::sign::{self, KeyPair};
use kit_core::store::ObjectStore;
use kit_sync::push::{PushError, PushLease, PushOptions, PushTarget};
use kit_sync::{CloneRemote, TransportSource, init_clone_dir};
use kit_transport_file::FileTransport;
use kit_transport_memory::MemoryTransport;

const MAIN: &str = "refs/heads/main";
/// Each blob is this big, so each sealed pack is over the size the push
/// checks the remote for, and the payload cap below holds one blob per pack.
const BLOB: usize = 9 << 20;
const CAP: u64 = 10 << 20;

/// A local repository that signs what it makes.
struct Work {
    _dir: tempfile::TempDir,
    path: PathBuf,
    layout: RepoLayout,
    store: ObjectStore,
    key: KeyPair,
}

impl Work {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("work");
        let remote = CloneRemote {
            name: "default".to_owned(),
            url: "kit+memory://x".to_owned(),
            kind: "memory".to_owned(),
        };
        let layout = init_clone_dir(&path, &remote).unwrap();
        let store = ObjectStore::open(&layout).unwrap();
        Self {
            _dir: dir,
            path,
            layout,
            store,
            key: KeyPair::generate().unwrap(),
        }
    }

    fn write(&self, object: &Object) -> Hash {
        self.store
            .write(&kit_core::serialize::serialize(object).unwrap())
            .unwrap()
    }

    /// A signed commit of `files`, each a blob of `size` bytes no pack can
    /// shrink.
    fn commit(&self, files: usize, size: usize) -> Hash {
        let entries = (0..files)
            .map(|n| {
                let blob = self.write(&Object::Blob(Blob {
                    data: noise(n as u64 + 1, size),
                }));
                TreeEntry {
                    name: format!("f{n}").into_bytes(),
                    mode: EntryMode::Blob,
                    object_hash: blob,
                }
            })
            .collect();
        let tree = self.write(&Object::Tree(Tree { entries }));
        let mut commit = Commit::new_unannotated(
            tree,
            Vec::new(),
            Identity::ed25519(self.key.public.0),
            self.key.public.0,
            b"commit".to_vec(),
            1_700_000_000,
            [0u8; 64],
        );
        commit.signature = sign::sign_commit(&commit, &self.key).unwrap().0;
        self.write(&Object::Commit(commit))
    }

    fn push(&self, remote: &dyn Transport) -> Result<kit_sync::PushReport, PushError> {
        let mut options = PushOptions::default();
        options.pack_payload_cap = CAP;
        options.target = PushTarget::Branch {
            local: "main".to_owned(),
            remote: "main".to_owned(),
            lease: PushLease::WithLease,
        };
        kit_sync::push(&self.path, &TransportSource::new(remote), &options)
    }
}

/// Bytes xorshift made from `seed`: they do not compress.
fn noise(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    let mut bytes = Vec::with_capacity(len + 8);
    while bytes.len() < len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        bytes.extend_from_slice(&state.to_le_bytes());
    }
    bytes.truncate(len);
    bytes
}

/// What a push asked of the remote.
#[derive(Default)]
struct Calls {
    /// The keys of the packs uploaded, in order.
    uploads: Vec<PackKey>,
    /// How many stored-length checks were made.
    checks: usize,
    /// The packs uploaded when each ref write began.
    uploaded_at_ref_write: Vec<usize>,
}

/// A transport that counts what the push sends, fails the upload number
/// `fail_upload` (counting from one) and answers stored-length checks with
/// `check_error`.
struct Recording<'a> {
    inner: &'a dyn Transport,
    calls: Mutex<Calls>,
    fail_upload: Option<usize>,
    check_error: bool,
}

impl<'a> Recording<'a> {
    fn new(inner: &'a dyn Transport) -> Self {
        Self {
            inner,
            calls: Mutex::new(Calls::default()),
            fail_upload: None,
            check_error: false,
        }
    }

    fn ref_write_began(&self) {
        let mut calls = self.calls.lock().unwrap();
        let uploaded = calls.uploads.len();
        calls.uploaded_at_ref_write.push(uploaded);
    }
}

impl Transport for Recording<'_> {
    fn repo_cursor(&self) -> TransportResult<Option<RepoCursor>> {
        self.inner.repo_cursor()
    }
    fn upload_pack(
        &self,
        pack: &dyn PackBody,
        key: &PackKey,
        head: Option<&str>,
    ) -> TransportResult<()> {
        let mut calls = self.calls.lock().unwrap();
        if self.fail_upload == Some(calls.uploads.len() + 1) {
            return Err(TransportError::AccessDenied);
        }
        self.inner.upload_pack(pack, key, head)?;
        calls.uploads.push(*key);
        Ok(())
    }
    // Packmap nodes are not data packs: pass them through uncounted.
    fn upload_blob(&self, bytes: &[u8], key: &PackKey, head: Option<&str>) -> TransportResult<()> {
        self.inner.upload_blob(bytes, key, head)
    }
    fn download_pack(
        &self,
        key: &PackKey,
        hint: Option<&str>,
        sink: &mut dyn PackSink,
    ) -> TransportResult<()> {
        self.inner.download_pack(key, hint, sink)
    }
    fn pack_exists(&self, key: &PackKey, hint: Option<&str>) -> TransportResult<bool> {
        self.inner.pack_exists(key, hint)
    }
    fn pack_len(&self, key: &PackKey, hint: Option<&str>) -> TransportResult<Option<u64>> {
        self.calls.lock().unwrap().checks += 1;
        if self.check_error {
            return Err(TransportError::AccessDenied);
        }
        self.inner.pack_len(key, hint)
    }
    fn update_ref(
        &self,
        name: &str,
        condition: RefWriteCondition,
        hash: &Hash,
    ) -> TransportResult<()> {
        self.ref_write_began();
        self.inner.update_ref(name, condition, hash)
    }
    #[allow(clippy::too_many_arguments)]
    fn advance_refs(
        &self,
        head_ref: &str,
        head_condition: RefWriteCondition,
        head_value: &Hash,
        packmap_ref: &str,
        packmap_condition: RefWriteCondition,
        packmap_value: &Hash,
    ) -> TransportResult<AdvanceOutcome> {
        self.ref_write_began();
        self.inner.advance_refs(
            head_ref,
            head_condition,
            head_value,
            packmap_ref,
            packmap_condition,
            packmap_value,
        )
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
    fn ref_listing(&self) -> RefListing {
        self.inner.ref_listing()
    }
    fn supports_atomic_advance(&self) -> bool {
        self.inner.supports_atomic_advance()
    }
    fn supports_serialized_advance(&self) -> bool {
        self.inner.supports_serialized_advance()
    }
}

/// A push of three packs over `remote` that fails on its third upload, then
/// runs again: the second run sends the one pack the first did not store, and
/// no ref moved before it.
fn rerun_sends_only_the_missing_pack(remote: &dyn Transport) {
    let work = Work::new();
    let tip = work.commit(3, BLOB);
    refs::write_ref(&work.layout, "main", &tip).unwrap();

    let mut first = Recording::new(remote);
    first.fail_upload = Some(3);
    assert!(work.push(&first).is_err());
    let stored = first.calls.into_inner().unwrap().uploads;
    assert_eq!(stored.len(), 2);
    assert_eq!(remote.read_ref(MAIN).unwrap(), None);

    let second = Recording::new(remote);
    work.push(&second).unwrap();
    let calls = second.calls.into_inner().unwrap();
    assert_eq!(calls.uploads.len(), 1, "only the missing pack is sent");
    assert!(
        stored.iter().all(|key| !calls.uploads.contains(key)),
        "a stored pack was sent again"
    );
    assert_eq!(remote.read_ref(MAIN).unwrap(), Some(tip));
    // The ref moved after the last upload.
    assert!(calls.uploaded_at_ref_write.iter().all(|&n| n == 1));
    assert!(!calls.uploaded_at_ref_write.is_empty());
    for key in stored.iter().chain(&calls.uploads) {
        assert!(remote.pack_exists(key, None).unwrap());
    }
}

#[test]
fn a_rerun_over_memory_sends_only_the_missing_pack() {
    rerun_sends_only_the_missing_pack(&MemoryTransport::new());
}

#[test]
fn a_rerun_over_a_file_remote_sends_only_the_missing_pack() {
    let dir = tempfile::tempdir().unwrap();
    rerun_sends_only_the_missing_pack(&FileTransport::new(dir.path()));
}

#[test]
fn an_existence_check_that_fails_falls_back_to_the_upload() {
    let remote = MemoryTransport::new();
    let work = Work::new();
    let tip = work.commit(2, BLOB);
    refs::write_ref(&work.layout, "main", &tip).unwrap();

    let mut recording = Recording::new(&remote);
    recording.check_error = true;
    work.push(&recording).unwrap();
    let calls = recording.calls.into_inner().unwrap();
    assert!(calls.checks > 0, "the push asked");
    assert_eq!(calls.uploads.len(), 2);
    assert_eq!(remote.read_ref(MAIN).unwrap(), Some(tip));
}

#[test]
fn a_small_push_asks_the_remote_nothing_extra() {
    let remote = MemoryTransport::new();
    let work = Work::new();
    let tip = work.commit(3, 4096);
    refs::write_ref(&work.layout, "main", &tip).unwrap();

    let recording = Recording::new(&remote);
    work.push(&recording).unwrap();
    let calls = recording.calls.into_inner().unwrap();
    assert_eq!(calls.checks, 0);
    assert_eq!(calls.uploads.len(), 1);
}

/// A clone of `remote` into a new directory, with the tip it checked out.
fn clone_tip(remote: &dyn Transport) -> Result<Hash, kit_sync::SyncError> {
    let temp = tempfile::tempdir().unwrap();
    let desc = CloneRemote {
        name: "origin".into(),
        url: "kit+file://x".into(),
        kind: "file".into(),
    };
    kit_sync::clone(
        temp.path(),
        &TransportSource::new(remote),
        &desc,
        &kit_sync::SyncOptions::default(),
        &kit_sync::NoopObserver,
    )?;
    Ok(refs::read_ref(&RepoLayout::single(temp.path()), "main")
        .unwrap()
        .unwrap())
}

#[test]
fn a_short_pack_under_a_key_is_sent_again_and_the_clone_works() {
    let dir = tempfile::tempdir().unwrap();
    let remote = FileTransport::new(dir.path());
    let work = Work::new();
    let tip = work.commit(3, BLOB);
    refs::write_ref(&work.layout, "main", &tip).unwrap();

    // The first run stores two packs and fails on the third; one of the two
    // is cut to half its bytes.
    let mut first = Recording::new(&remote);
    first.fail_upload = Some(3);
    assert!(work.push(&first).is_err());
    let stored = first.calls.into_inner().unwrap().uploads;
    assert_eq!(stored.len(), 2);
    let short = dir.path().join("packs").join(stored[0].to_hex());
    let whole = std::fs::read(&short).unwrap();
    std::fs::write(&short, &whole[..whole.len() / 2]).unwrap();

    let second = Recording::new(&remote);
    work.push(&second).unwrap();
    let calls = second.calls.into_inner().unwrap();
    assert_eq!(calls.uploads.len(), 2, "the short pack and the missing one");
    assert!(calls.uploads.contains(&stored[0]));
    assert!(!calls.uploads.contains(&stored[1]), "a whole pack is kept");
    assert_eq!(std::fs::read(&short).unwrap(), whole);
    assert_eq!(remote.read_ref(MAIN).unwrap(), Some(tip));
    assert_eq!(clone_tip(&remote).unwrap(), tip);
}
