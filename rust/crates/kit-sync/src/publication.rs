//! Private fetch windows. Only complete, checked wire packs enter a window.

use std::collections::HashSet;

use kit_core::chunker;
use kit_core::hash::{Hash, to_hex};
use kit_core::object::{Object, ObjectType};
use kit_core::pack::{LooseStaging, ObjectSpool, PackError};
use kit_core::protocol::PackKey;
use kit_core::serialize;
use kit_core::store::{
    ClosureSource, GuardedStore, LocalPackWriter, ObjectSource, ObjectStore, PACK_SEAL_BYTES,
    PACK_SEAL_ENTRIES, PruneGuard, SealJob, StoreError, StoreResult,
};
use std::thread::JoinHandle;

use crate::applied_packs::AppliedPacks;
use crate::observer::{Observer, SyncEvent};

// The largest object a kit writer cuts as a chunk, with its blob prologue.
// Every object of at most this size is packed, whatever its kind.
const PACK_OBJECT_BYTES: usize = chunker::MAX_SIZE + serialize::BLOB_PROLOGUE_LEN;

/// The bytes a wire pack must contribute to a window before the window reads
/// them from the wire pack's file. Absorbing keeps that file open until the
/// window seals, so a window of at most `PACK_SEAL_BYTES` holds at most
/// `PACK_SEAL_BYTES / ABSORB_MIN_BYTES` files, whatever the pack chain is.
/// Smaller contributions are copied, which costs less than the open file.
const ABSORB_MIN_BYTES: u64 = 1 << 20;

/// An object as the decoder staged it: position, id, length and type.
type Entry = (usize, Hash, u32, ObjectType);

pub(crate) struct Publication<'a> {
    store: &'a ObjectStore,
    guard: &'a PruneGuard,
    pack: bool,
    window: Option<Window>,
    /// The window whose pack is being sealed on a worker thread while the
    /// next window is received. At most one.
    sealing: Option<Sealing>,
}

/// A window whose local pack is sealing, and what finishing it needs. Its
/// spool stays readable until then: the objects of the window are neither in
/// the store nor in `Publication::window`, and a later wire pack may name
/// one as a delta base.
struct Sealing {
    window: Window,
    loose: Vec<(Hash, u32)>,
    seal: Seal,
}

struct Window {
    /// The objects to pack and the objects to write loose, which stay in the
    /// files of the spools they were decoded into.
    spool: ObjectSpool,
    bytes: usize,
    entries: usize,
    completed: Vec<PackKey>,
    completed_set: HashSet<PackKey>,
}

impl<'a> Publication<'a> {
    pub(crate) fn new(store: &'a ObjectStore, guard: &'a PruneGuard) -> StoreResult<Self> {
        Ok(Self {
            store,
            guard,
            pack: store.local_packs_active(guard)?,
            window: None,
            sealing: None,
        })
    }

    /// A spool for decoding one wire pack. It writes each object that ends as
    /// a loose file once, to its own temporary file, so `accept` and `seal`
    /// hand that file on instead of copying or reading it.
    pub(crate) fn decode_spool(&self) -> std::io::Result<ObjectSpool> {
        let over = if self.pack { PACK_OBJECT_BYTES } else { 0 };
        ObjectSpool::with_loose_staging(
            &self.store.spool_dir(),
            LooseStaging::new(self.store.objects_root(), over),
        )
    }

    /// The spools of the windows that are not in the store yet, newest first.
    pub(crate) fn pending(&self) -> Vec<&ObjectSpool> {
        self.window
            .iter()
            .chain(self.sealing.iter().map(|sealing| &sealing.window))
            .map(|window| &window.spool)
            .collect()
    }

    /// The pending objects over the store, for a walk that runs under this
    /// publication's guard. No seal may be in flight: [`Self::finish`] first.
    pub(crate) fn view(&self) -> StoreResult<PendingView<'_>> {
        if self.sealing.is_some() {
            return Err(std::io::Error::other("a seal is still in flight").into());
        }
        PendingView::guarded(
            self.store,
            self.window.as_ref().map(|window| &window.spool),
            self.guard,
        )
    }

    pub(crate) fn completed(&self, key: &PackKey) -> bool {
        self.window
            .iter()
            .chain(self.sealing.iter().map(|sealing| &sealing.window))
            .any(|window| window.completed_set.contains(key))
    }

    pub(crate) fn accept(
        &mut self,
        spool: &ObjectSpool,
        key: PackKey,
        observer: &dyn Observer<SyncEvent>,
        remote: &str,
        applied: &mut AppliedPacks,
    ) -> Result<(), PackError> {
        let order = spool.take_order();
        if order.is_empty() {
            record(key, observer, remote, applied);
            return Ok(());
        }
        // An object that ends as a loose file is in a
        // temporary file of its own, which `spool` wrote when the decoder
        // derived its id: the window takes that file over, and `seal` renames it
        // into place. An object that ends in a pack stays in `spool`'s file when
        // the wire pack holds enough of them, and the window reads it from there
        // until `seal` writes it to the pack; a few are copied (`adopt`). The
        // files stay on disk until the window seals.
        let mut loose = Vec::new();
        let mut packed = Vec::new();
        let mut sealed_here = false;
        for (_, id, len, ty) in order {
            let size = len as usize;
            if self.window.as_ref().is_some_and(|window| {
                window.bytes + size > PACK_SEAL_BYTES || window.entries == PACK_SEAL_ENTRIES
            }) {
                // A seal before this wire pack put anything into the window is
                // no reason to copy: its file holds no more than the window.
                sealed_here |= !loose.is_empty() || !packed.is_empty();
                self.adopt(spool, &mut loose, &mut packed, false)?;
                self.seal_window(observer, remote, applied)?;
            }
            let packs = self.packs(size);
            let window = self.window()?;
            if packs {
                packed.push((window.entries, id, len, ty));
            } else {
                loose.push((window.entries, id, len, ty));
            }
            window.bytes += size;
            window.entries += 1;
        }
        // A wire pack that filled a window holds more than a window in its file,
        // and the window it leaves open would hold the file until the next wire
        // pack was decoded. What is left of it is copied.
        self.adopt(spool, &mut loose, &mut packed, sealed_here)?;
        let pack = self.pack;
        let window = self.window()?;
        window.completed.push(key);
        window.completed_set.insert(key);
        if !pack || window.bytes >= PACK_SEAL_BYTES || window.entries == PACK_SEAL_ENTRIES {
            self.seal_window(observer, remote, applied)?;
        }
        Ok(())
    }

    /// Whether an object of `len` bytes goes into a local pack. Any other
    /// object is written as a loose file.
    fn packs(&self, len: usize) -> bool {
        self.pack && len <= PACK_OBJECT_BYTES
    }

    /// Hand the window the temporary files of the `loose` entries of `from`,
    /// and its `packed` entries: their frames if there are enough of them and
    /// `copy` is not set, their bytes otherwise.
    fn adopt(
        &mut self,
        from: &ObjectSpool,
        loose: &mut Vec<Entry>,
        packed: &mut Vec<Entry>,
        copy: bool,
    ) -> Result<(), PackError> {
        if !loose.is_empty() {
            self.window()?.spool.adopt(from, &loose[..])?;
            loose.clear();
        }
        if !packed.is_empty() {
            let bytes: u64 = packed.iter().map(|entry| u64::from(entry.2)).sum();
            let window = self.window()?;
            if bytes >= ABSORB_MIN_BYTES && !copy {
                window.spool.absorb(from, &packed[..])?;
            } else {
                let mut scratch = Vec::new();
                for &(position, id, _, ty) in packed.iter() {
                    window
                        .spool
                        .append_from(from, position, id, ty, &mut scratch)?;
                }
            }
            packed.clear();
        }
        Ok(())
    }

    fn window(&mut self) -> Result<&mut Window, PackError> {
        if self.window.is_none() {
            self.window = Some(Window {
                spool: ObjectSpool::new(&self.store.spool_dir())?,
                bytes: 0,
                entries: 0,
                completed: Vec::new(),
                completed_set: HashSet::new(),
            });
        }
        Ok(self.window.as_mut().expect("created publication window"))
    }

    /// Seal the open window and wait for every seal: when this returns, all
    /// accepted packs are in the store and recorded.
    pub(crate) fn seal(
        &mut self,
        observer: &dyn Observer<SyncEvent>,
        remote: &str,
        applied: &mut AppliedPacks,
    ) -> Result<(), PackError> {
        // The window in flight finishes even when the open one cannot be built.
        let sealed = self.seal_window(observer, remote, applied);
        let finished = self.finish(observer, remote, applied);
        sealed.and(finished)
    }

    /// Wait for the seal in flight and finish its window.
    pub(crate) fn finish(
        &mut self,
        observer: &dyn Observer<SyncEvent>,
        remote: &str,
        applied: &mut AppliedPacks,
    ) -> Result<(), PackError> {
        let Some(sealing) = self.sealing.take() else {
            return Ok(());
        };
        sealing.seal.wait()?;
        self.publish_loose(sealing.window, &sealing.loose, observer, remote, applied)
    }

    /// Finish the seal in flight when its worker has already ended, so the
    /// window is recorded without waiting for the next one to fill.
    pub(crate) fn finish_if_done(
        &mut self,
        observer: &dyn Observer<SyncEvent>,
        remote: &str,
        applied: &mut AppliedPacks,
    ) -> Result<(), PackError> {
        if self
            .sealing
            .as_ref()
            .is_some_and(|sealing| sealing.seal.is_done())
        {
            self.finish(observer, remote, applied)?;
        }
        Ok(())
    }

    /// Write the open window's objects to a local pack and hand the pack to a
    /// worker, which seals it while the caller receives the next window. A
    /// window whose seal is in flight finishes first, so a window is never
    /// recorded before the one before it, and at most one seal runs.
    fn seal_window(
        &mut self,
        observer: &dyn Observer<SyncEvent>,
        remote: &str,
        applied: &mut AppliedPacks,
    ) -> Result<(), PackError> {
        let Some(window) = self.window.take() else {
            return Ok(());
        };
        let mut loose_ids = Vec::new();
        let mut seen = HashSet::new();
        let mut pack = None;
        let mut scratch = Vec::new();
        for (_, id, len, _) in window.spool.take_order() {
            if self.packs(len as usize) {
                if pack.is_none() {
                    pack = Some(LocalPackWriter::new(self.store, self.guard)?);
                }
                let pack = pack.as_mut().expect("created local pack");
                window.spool.write_to_pack(&id, pack, &mut scratch)?;
            } else if seen.insert(id) {
                loose_ids.push((id, len));
            }
        }
        // The pack is complete in its file. The previous window finishes
        // before this one starts sealing.
        let job = pack.map(LocalPackWriter::detach);
        self.finish(observer, remote, applied)?;
        match job {
            Some(job) => {
                self.sealing = Some(Sealing {
                    window,
                    loose: loose_ids,
                    seal: Seal::start(job),
                });
                Ok(())
            }
            // Only loose objects: nothing to seal.
            None => self.publish_loose(window, &loose_ids, observer, remote, applied),
        }
    }

    /// The decoder hashed each loose object once and wrote it under its id.
    /// They are renamed into place at commit, not read again, and only after
    /// the window's pack is in the store. Then the window is recorded.
    fn publish_loose(
        &self,
        window: Window,
        loose_ids: &[(Hash, u32)],
        observer: &dyn Observer<SyncEvent>,
        remote: &str,
        applied: &mut AppliedPacks,
    ) -> Result<(), PackError> {
        let loose = self.store.batch();
        for &(id, len) in loose_ids {
            let file = window
                .spool
                .take_loose(&id)
                .ok_or_else(|| StoreError::ObjectNotFound(to_hex(&id)))?;
            loose.stage_temp(id, file, u64::from(len))?;
        }
        loose.commit()?;
        for key in window.completed {
            record(key, observer, remote, applied);
        }
        crate::fetch::persist_record(applied, observer, remote);
        Ok(())
    }
}

impl Drop for Publication<'_> {
    fn drop(&mut self) {
        // An abandoned fetch: the seal in flight must not outlive the guard
        // that keeps the pack directory in place. Its window is not recorded.
        if let Some(sealing) = self.sealing.take() {
            sealing.seal.discard();
        }
    }
}

/// The seal of one pack, on its own thread.
enum Seal {
    Running(JoinHandle<StoreResult<()>>),
    /// No thread could be started: the pack was sealed on the caller's.
    Done(StoreResult<()>),
}

impl Seal {
    fn start(job: SealJob) -> Self {
        let job = std::sync::Arc::new(std::sync::Mutex::new(Some(job)));
        let handed = std::sync::Arc::clone(&job);
        let take = move || {
            handed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
                .expect("a seal job runs once")
        };
        let again = take.clone();
        match std::thread::Builder::new()
            .name("kit-seal".into())
            .spawn(move || take().publish())
        {
            Ok(handle) => Self::Running(handle),
            // The job stays reachable when the thread never starts.
            Err(_) => Self::Done(again().publish()),
        }
    }

    fn is_done(&self) -> bool {
        match self {
            Self::Running(handle) => handle.is_finished(),
            Self::Done(_) => true,
        }
    }

    /// Wait for the seal and drop its outcome, a panic included.
    fn discard(self) {
        if let Self::Running(handle) = self {
            let _ = handle.join();
        }
    }

    /// Wait for the seal. A panic of the worker resumes here.
    fn wait(self) -> StoreResult<()> {
        match self {
            Self::Running(handle) => match handle.join() {
                Ok(sealed) => sealed,
                Err(panic) => std::panic::resume_unwind(panic),
            },
            Self::Done(sealed) => sealed,
        }
    }
}

fn record(
    key: PackKey,
    observer: &dyn Observer<SyncEvent>,
    remote: &str,
    applied: &mut AppliedPacks,
) {
    if let Err(e) = applied.record_applied(&key) {
        observer.event(&SyncEvent::AppliedPacksPersistFailed {
            remote: remote.to_owned(),
            error: e.to_string(),
        });
    }
}

/// Hash-check private reads and fall through to the durable store on a miss.
/// The type and head of a private object are read from its first bytes alone.
/// The decoder derived the id of each private object from the bytes it wrote,
/// and a full read checks them against that id again; a loose object's file is
/// renamed into place at `seal` without a read.
pub(crate) struct PendingView<'a> {
    store: &'a ObjectStore,
    spool: Option<&'a ObjectSpool>,
    /// The durable reads of a walk that holds the guard.
    guarded: Option<GuardedStore<'a>>,
}

impl<'a> PendingView<'a> {
    pub(crate) fn new(store: &'a ObjectStore, spool: Option<&'a ObjectSpool>) -> Self {
        Self {
            store,
            spool,
            guarded: None,
        }
    }

    /// A view whose durable reads check each local pack once. `guard` must
    /// outlive the view, and the view must be built before its first read.
    pub(crate) fn guarded(
        store: &'a ObjectStore,
        spool: Option<&'a ObjectSpool>,
        guard: &'a PruneGuard,
    ) -> StoreResult<Self> {
        Ok(Self {
            store,
            spool,
            guarded: Some(store.guarded(guard)?),
        })
    }

    /// The durable store the view falls through to.
    fn durable(&self) -> &dyn ClosureSource {
        match &self.guarded {
            Some(guarded) => guarded,
            None => self.store,
        }
    }

    fn pending(&self, id: &Hash) -> StoreResult<Option<Vec<u8>>> {
        self.spool.map_or(Ok(None), |spool| spool.read(id))
    }

    /// The head of a staged object. Its id came from its bytes at decode, so a
    /// head read does not read or hash the rest.
    fn pending_head(&self, id: &Hash) -> StoreResult<Option<(ObjectType, Option<u64>)>> {
        self.spool.map_or(Ok(None), |spool| spool.head(id))
    }

    pub(crate) fn contains(&self, id: &Hash) -> bool {
        self.spool.is_some_and(|spool| spool.contains(id)) || self.store.contains(id)
    }
}

impl ObjectSource for PendingView<'_> {
    fn read(&self, id: &Hash) -> StoreResult<Vec<u8>> {
        self.pending(id)?
            .map_or_else(|| self.durable().read(id), Ok)
    }

    fn read_object(&self, id: &Hash) -> StoreResult<Object> {
        if let Some(bytes) = self.pending(id)? {
            Ok(serialize::deserialize_owned(bytes)?)
        } else {
            self.durable().read_object(id)
        }
    }
}
impl ClosureSource for PendingView<'_> {
    fn object_type(&self, id: &Hash) -> StoreResult<ObjectType> {
        if let Some((ty, _)) = self.pending_head(id)? {
            Ok(ty)
        } else {
            self.durable().object_type(id)
        }
    }

    fn object_head(&self, id: &Hash) -> StoreResult<(ObjectType, Option<u64>)> {
        if let Some(head) = self.pending_head(id)? {
            Ok(head)
        } else {
            self.durable().object_head(id)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NoopObserver;
    use kit_core::layout::RepoLayout;
    use kit_core::object::Tree;

    #[test]
    fn an_exactly_full_byte_window_seals_as_one_pack() {
        let dir = tempfile::tempdir().unwrap();
        let layout = RepoLayout::single(dir.path());
        let store = ObjectStore::init(&layout).unwrap();
        store.try_activate_local_packs().unwrap();
        let guard = store.prune_guard().unwrap();
        std::fs::create_dir_all(store.spool_dir()).unwrap();
        let spool = ObjectSpool::new(&store.spool_dir()).unwrap();
        let mut publication = Publication::new(&store, &guard).unwrap();
        let mut applied = AppliedPacks::load(&layout, "origin").unwrap();
        let blob = |byte| {
            let object = Object::Blob(kit_core::object::Blob {
                data: vec![byte; 8192 - serialize::BLOB_PROLOGUE_LEN],
            });
            (object.id().unwrap(), serialize::serialize(&object).unwrap())
        };
        let (first_id, first) = blob(1);
        let (last_id, last) = blob(2);

        for position in 0..8191 {
            spool
                .append(position, first_id, ObjectType::Blob, &first)
                .unwrap();
        }
        spool
            .append(8191, last_id, ObjectType::Blob, &last)
            .unwrap();
        let key = PackKey::from_hash(kit_core::hash::hash(b"exact byte window"));
        publication
            .accept(&spool, key, &NoopObserver, "origin", &mut applied)
            .unwrap();
        publication
            .finish(&NoopObserver, "origin", &mut applied)
            .unwrap();

        assert!(publication.pending().is_empty());
        assert!(applied.contains(&key));
        assert_eq!(store.read(&first_id).unwrap(), first);
        assert_eq!(store.read(&last_id).unwrap(), last);
        assert_eq!(
            std::fs::read_dir(layout.objects_dir().join("pack"))
                .unwrap()
                .count(),
            2
        );
    }

    fn big_blob(len: usize, seed: u8) -> (Hash, Vec<u8>) {
        let object = Object::Blob(kit_core::object::Blob {
            data: (0..len)
                .map(|i| seed.wrapping_add(u8::try_from(i % 251).unwrap()))
                .collect(),
        });
        (object.id().unwrap(), serialize::serialize(&object).unwrap())
    }

    fn loose_path(layout: &RepoLayout, id: &Hash) -> std::path::PathBuf {
        let hex = to_hex(id);
        layout.objects_dir().join(&hex[..2]).join(&hex[2..])
    }

    /// The temporary files an unsealed window leaves in the shard
    /// directories: the files of the objects that will be loose.
    fn staged_files(layout: &RepoLayout) -> Vec<std::path::PathBuf> {
        let mut files = Vec::new();
        for shard in std::fs::read_dir(layout.objects_dir()).unwrap() {
            let shard = shard.unwrap().path();
            if shard.file_name().is_some_and(|name| name.len() == 2) {
                for file in std::fs::read_dir(shard).unwrap() {
                    files.push(file.unwrap().path());
                }
            }
        }
        files.sort();
        files
    }

    struct Fixture {
        layout: RepoLayout,
        store: ObjectStore,
        _dir: tempfile::TempDir,
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let layout = RepoLayout::single(dir.path());
        let store = ObjectStore::init(&layout).unwrap();
        store.try_activate_local_packs().unwrap();
        std::fs::create_dir_all(store.spool_dir()).unwrap();
        Fixture {
            layout,
            store,
            _dir: dir,
        }
    }

    fn stage(spool: &ObjectSpool, objects: &[&(Hash, Vec<u8>)]) {
        for (position, (id, bytes)) in objects.iter().enumerate() {
            spool
                .append(position, *id, ObjectType::Blob, bytes)
                .unwrap();
        }
    }

    #[test]
    fn objects_over_the_pack_limit_are_written_once_and_renamed_into_place() {
        let Fixture {
            layout,
            store,
            _dir,
        } = fixture();
        let guard = store.prune_guard().unwrap();
        let mut publication = Publication::new(&store, &guard).unwrap();
        let mut applied = AppliedPacks::load(&layout, "origin").unwrap();
        let small = big_blob(1000, 1);
        let mid = big_blob(300 << 10, 2);
        let large = big_blob(1 << 20, 3);
        assert!(mid.1.len() > PACK_OBJECT_BYTES);

        let spool = publication.decode_spool().unwrap();
        stage(&spool, &[&small, &mid, &large]);
        // Only the packed object is in the decoder's file. The others are
        // named temporary files in their shards, written by the decoder.
        assert_eq!(spool.written_bytes(), small.1.len() as u64);
        let staged = staged_files(&layout);
        assert_eq!(staged.len(), 2);
        let inodes = |files: &[std::path::PathBuf]| {
            files
                .iter()
                .map(|file| {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::MetadataExt;
                        std::fs::metadata(file).unwrap().ino()
                    }
                    #[cfg(not(unix))]
                    {
                        std::fs::metadata(file).unwrap().len()
                    }
                })
                .collect::<std::collections::BTreeSet<_>>()
        };
        let before = inodes(&staged);
        for id in [&mid.0, &large.0] {
            assert!(!loose_path(&layout, id).exists(), "not visible yet");
        }

        let key = PackKey::from_hash(kit_core::hash::hash(b"over the pack limit"));
        publication
            .accept(&spool, key, &NoopObserver, "origin", &mut applied)
            .unwrap();
        drop(spool);

        // The window took the files over: only the packed object was copied,
        // for a wire pack with that little to pack is not kept open.
        let pending = publication.pending()[0];
        assert_eq!(pending.written_bytes(), small.1.len() as u64);
        assert_eq!(pending.donor_files(), 0);
        assert_eq!(staged_files(&layout), staged);
        let view = publication.view().unwrap();
        assert!(view.contains(&mid.0) && view.contains(&large.0));
        assert_eq!(view.read(&small.0).unwrap(), small.1);
        assert_eq!(view.read(&mid.0).unwrap(), mid.1);
        assert_eq!(view.read(&large.0).unwrap(), large.1);
        // The closure check asks for a head, which reads ten bytes.
        assert_eq!(
            view.object_head(&mid.0).unwrap(),
            (ObjectType::Blob, Some(300 << 10))
        );
        assert_eq!(view.object_type(&large.0).unwrap(), ObjectType::Blob);
        assert!(!loose_path(&layout, &mid.0).exists(), "not visible yet");

        publication
            .seal(&NoopObserver, "origin", &mut applied)
            .unwrap();
        assert!(applied.contains(&key));
        // The decoder's own files are now the objects: same inodes, none left.
        let placed = [&mid.0, &large.0].map(|id| loose_path(&layout, id));
        assert_eq!(inodes(&placed), before);
        assert_eq!(std::fs::read(&placed[0]).unwrap(), mid.1);
        assert_eq!(std::fs::read(&placed[1]).unwrap(), large.1);
        assert!(!loose_path(&layout, &small.0).exists());
        for (id, bytes) in [small, mid, large] {
            assert_eq!(store.read(&id).unwrap(), bytes);
        }
        let leftovers: Vec<_> = staged_files(&layout)
            .into_iter()
            .filter(|file| file.file_name().is_some_and(|name| name.len() != 62))
            .collect();
        assert_eq!(leftovers, Vec::<std::path::PathBuf>::new());
    }

    #[test]
    fn a_store_without_local_packs_writes_every_object_loose_from_the_decoder() {
        let dir = tempfile::tempdir().unwrap();
        let layout = RepoLayout::single(dir.path());
        let store = ObjectStore::init(&layout).unwrap();
        std::fs::create_dir_all(store.spool_dir()).unwrap();
        let guard = store.prune_guard().unwrap();
        let mut publication = Publication::new(&store, &guard).unwrap();
        // A store that does not pack: every object is a loose file.
        publication.pack = false;
        let mut applied = AppliedPacks::load(&layout, "origin").unwrap();
        let tiny = big_blob(50, 4);

        let spool = publication.decode_spool().unwrap();
        stage(&spool, &[&tiny]);
        assert_eq!(spool.written_bytes(), 0);
        assert_eq!(staged_files(&layout).len(), 1);
        let key = PackKey::from_hash(kit_core::hash::hash(b"loose store"));
        publication
            .accept(&spool, key, &NoopObserver, "origin", &mut applied)
            .unwrap();

        assert_eq!(std::fs::read(loose_path(&layout, &tiny.0)).unwrap(), tiny.1);
    }

    #[test]
    fn a_window_that_is_dropped_before_it_seals_leaves_no_object_and_no_file() {
        let Fixture {
            layout,
            store,
            _dir,
        } = fixture();
        let guard = store.prune_guard().unwrap();
        let mid = big_blob(300 << 10, 5);
        let large = big_blob(1 << 20, 6);
        let mut applied = AppliedPacks::load(&layout, "origin").unwrap();
        let key = PackKey::from_hash(kit_core::hash::hash(b"never sealed"));

        // Decoded and accepted, but the process stops before the seal.
        {
            let mut publication = Publication::new(&store, &guard).unwrap();
            let spool = publication.decode_spool().unwrap();
            stage(&spool, &[&mid]);
            publication
                .accept(&spool, key, &NoopObserver, "origin", &mut applied)
                .unwrap();
            assert_eq!(staged_files(&layout).len(), 1);
        }
        // Decoded but not accepted: a pack that fails after some of it staged.
        {
            let publication = Publication::new(&store, &guard).unwrap();
            let spool = publication.decode_spool().unwrap();
            stage(&spool, &[&large]);
            assert_eq!(staged_files(&layout).len(), 1);
        }

        assert_eq!(staged_files(&layout), Vec::<std::path::PathBuf>::new());
        assert!(!store.contains(&mid.0) && !store.contains(&large.0));
        assert!(!applied.contains(&key));
    }

    #[test]
    fn an_object_sealed_in_an_earlier_window_is_not_written_again() {
        let Fixture {
            layout,
            store,
            _dir,
        } = fixture();
        let guard = store.prune_guard().unwrap();
        let mut publication = Publication::new(&store, &guard).unwrap();
        let mut applied = AppliedPacks::load(&layout, "origin").unwrap();

        // One wire pack holds an object twice: once first, and once after
        // enough bytes to close the window the first copy went into.
        let first = big_blob(300 << 10, 7);
        let fillers: Vec<_> = (0..PACK_SEAL_BYTES / (1 << 20))
            .map(|n| big_blob(1 << 20, 10 + u8::try_from(n).unwrap()))
            .collect();
        let mut objects = vec![&first];
        objects.extend(&fillers);
        objects.push(&first);
        let spool = publication.decode_spool().unwrap();
        stage(&spool, &objects);
        assert_eq!(staged_files(&layout).len(), 1 + fillers.len());

        let key = PackKey::from_hash(kit_core::hash::hash(b"repeated object"));
        publication
            .accept(&spool, key, &NoopObserver, "origin", &mut applied)
            .unwrap();
        // The first window sealed on the way and holds the first copy.
        assert_eq!(store.read(&first.0).unwrap(), first.1);
        assert!(!publication.pending().is_empty());
        publication
            .seal(&NoopObserver, "origin", &mut applied)
            .unwrap();

        for (id, bytes) in std::iter::once(&first).chain(&fillers) {
            assert_eq!(&store.read(id).unwrap(), bytes);
        }
        assert!(applied.contains(&key));
        let leftovers: Vec<_> = staged_files(&layout)
            .into_iter()
            .filter(|file| file.file_name().is_some_and(|name| name.len() != 62))
            .collect();
        assert_eq!(leftovers, Vec::<std::path::PathBuf>::new());
    }

    /// A blob of `len` bytes that no other `n` shares.
    fn numbered_blob(n: u32, len: usize) -> (Hash, Vec<u8>) {
        let mut data: Vec<u8> = (0..len)
            .map(|i| {
                u8::try_from(i % 251)
                    .unwrap()
                    .wrapping_add(n.to_le_bytes()[0])
            })
            .collect();
        data[..4].copy_from_slice(&n.to_le_bytes());
        let object = Object::Blob(kit_core::object::Blob { data });
        (object.id().unwrap(), serialize::serialize(&object).unwrap())
    }

    fn packs_on_disk(layout: &RepoLayout) -> usize {
        std::fs::read_dir(layout.objects_dir().join("pack"))
            .unwrap()
            .filter(|entry| {
                entry
                    .as_ref()
                    .unwrap()
                    .path()
                    .extension()
                    .is_some_and(|ext| ext == "pack")
            })
            .count()
    }

    #[test]
    fn small_wire_packs_are_copied_so_a_long_chain_keeps_no_file_open() {
        let Fixture {
            layout,
            store,
            _dir,
        } = fixture();
        let guard = store.prune_guard().unwrap();
        let mut publication = Publication::new(&store, &guard).unwrap();
        let mut applied = AppliedPacks::load(&layout, "origin").unwrap();

        let objects: Vec<_> = (0..300).map(|n| numbered_blob(n, 2000)).collect();
        for (n, object) in objects.iter().enumerate() {
            let spool = publication.decode_spool().unwrap();
            stage(&spool, &[object]);
            let key = PackKey::from_hash(kit_core::hash::hash(&n.to_le_bytes()));
            publication
                .accept(&spool, key, &NoopObserver, "origin", &mut applied)
                .unwrap();
        }
        let pending = publication.pending()[0];
        assert_eq!(pending.donor_files(), 0);
        assert!(pending.written_bytes() > 0);
        publication
            .seal(&NoopObserver, "origin", &mut applied)
            .unwrap();
        for (id, bytes) in &objects {
            assert_eq!(&store.read(id).unwrap(), bytes);
        }
        assert_eq!(packs_on_disk(&layout), 1);
    }

    #[test]
    fn a_wire_pack_with_enough_to_pack_is_read_from_its_own_file() {
        let Fixture {
            layout,
            store,
            _dir,
        } = fixture();
        let guard = store.prune_guard().unwrap();
        let mut publication = Publication::new(&store, &guard).unwrap();
        let mut applied = AppliedPacks::load(&layout, "origin").unwrap();

        let objects: Vec<_> = (0..10).map(|n| numbered_blob(n, 200_000)).collect();
        let packed_bytes: usize = objects.iter().map(|object| object.1.len()).sum();
        assert!(packed_bytes as u64 >= ABSORB_MIN_BYTES);
        assert!(objects[0].1.len() <= PACK_OBJECT_BYTES);
        let spool = publication.decode_spool().unwrap();
        stage(&spool, &objects.iter().collect::<Vec<_>>());
        let key = PackKey::from_hash(kit_core::hash::hash(b"enough"));
        publication
            .accept(&spool, key, &NoopObserver, "origin", &mut applied)
            .unwrap();
        drop(spool);

        let pending = publication.pending()[0];
        assert_eq!(pending.donor_files(), 1);
        assert_eq!(pending.written_bytes(), 0);
        assert_eq!(
            publication.view().unwrap().read(&objects[9].0).unwrap(),
            objects[9].1
        );
        publication
            .seal(&NoopObserver, "origin", &mut applied)
            .unwrap();
        assert!(applied.contains(&key));
        assert_eq!(packs_on_disk(&layout), 1);
        for (id, bytes) in &objects {
            assert_eq!(&store.read(id).unwrap(), bytes);
        }
    }

    #[test]
    fn each_wire_pack_with_enough_to_pack_keeps_its_file_until_the_window_seals() {
        let Fixture {
            layout,
            store,
            _dir,
        } = fixture();
        let guard = store.prune_guard().unwrap();
        let mut publication = Publication::new(&store, &guard).unwrap();
        let mut applied = AppliedPacks::load(&layout, "origin").unwrap();

        let objects: Vec<_> = (0..20).map(|n| numbered_blob(n, 200_000)).collect();
        for (n, chunk) in objects.chunks(10).enumerate() {
            let spool = publication.decode_spool().unwrap();
            stage(&spool, &chunk.iter().collect::<Vec<_>>());
            let key = PackKey::from_hash(kit_core::hash::hash(&[u8::try_from(n).unwrap()]));
            publication
                .accept(&spool, key, &NoopObserver, "origin", &mut applied)
                .unwrap();
        }
        let pending = publication.pending()[0];
        assert_eq!(pending.donor_files(), 2);
        assert_eq!(pending.written_bytes(), 0);
        publication
            .seal(&NoopObserver, "origin", &mut applied)
            .unwrap();
        assert_eq!(packs_on_disk(&layout), 1);
        for (id, bytes) in &objects {
            assert_eq!(&store.read(id).unwrap(), bytes);
        }
    }

    #[test]
    fn a_seal_before_a_wire_pack_adds_anything_does_not_make_it_copy() {
        let Fixture {
            layout,
            store,
            _dir,
        } = fixture();
        let guard = store.prune_guard().unwrap();
        let mut publication = Publication::new(&store, &guard).unwrap();
        let mut applied = AppliedPacks::load(&layout, "origin").unwrap();

        // A first wire pack leaves its window one object short of full, and
        // the second wire pack's first object does not fit.
        let first: Vec<_> = (0..335).map(|n| numbered_blob(n, 200_000)).collect();
        let second: Vec<_> = (400..410).map(|n| numbered_blob(n, 200_000)).collect();
        for (n, objects) in [&first, &second].into_iter().enumerate() {
            let spool = publication.decode_spool().unwrap();
            stage(&spool, &objects.iter().collect::<Vec<_>>());
            let key = PackKey::from_hash(kit_core::hash::hash(&[u8::try_from(n).unwrap()]));
            publication
                .accept(&spool, key, &NoopObserver, "origin", &mut applied)
                .unwrap();
        }
        let window_bytes: usize = first.iter().map(|object| object.1.len()).sum();
        assert!(window_bytes + second[0].1.len() > PACK_SEAL_BYTES);
        assert_eq!(packs_on_disk(&layout), 1);
        let pending = publication.pending()[0];
        assert_eq!(pending.donor_files(), 1);
        assert_eq!(pending.written_bytes(), 0);
        publication
            .seal(&NoopObserver, "origin", &mut applied)
            .unwrap();
        assert_eq!(packs_on_disk(&layout), 2);
        for (id, bytes) in first.iter().chain(&second) {
            assert_eq!(&store.read(id).unwrap(), bytes);
        }
    }

    #[test]
    fn the_tail_of_a_wire_pack_that_filled_a_window_is_copied_so_its_file_is_not_held() {
        let Fixture {
            layout,
            store,
            _dir,
        } = fixture();
        let guard = store.prune_guard().unwrap();
        let mut publication = Publication::new(&store, &guard).unwrap();
        let mut applied = AppliedPacks::load(&layout, "origin").unwrap();

        // 360 objects of 200,000 bytes are packed, and more than one window.
        let objects: Vec<_> = (0..360).map(|n| numbered_blob(n, 200_000)).collect();
        assert!(objects[0].1.len() <= PACK_OBJECT_BYTES);
        assert!(objects.len() * objects[0].1.len() > PACK_SEAL_BYTES);
        let spool = publication.decode_spool().unwrap();
        stage(&spool, &objects.iter().collect::<Vec<_>>());
        let key = PackKey::from_hash(kit_core::hash::hash(b"two windows"));
        publication
            .accept(&spool, key, &NoopObserver, "origin", &mut applied)
            .unwrap();
        drop(spool);
        publication
            .finish(&NoopObserver, "origin", &mut applied)
            .unwrap();

        // The first window sealed on the way. The open one holds the tail's
        // bytes, not the wire pack's file, which is gone with the spool.
        assert_eq!(packs_on_disk(&layout), 1);
        assert!(store.contains(&objects[0].0));
        assert!(!store.contains(&objects[359].0));
        let pending = publication.pending()[0];
        assert_eq!(pending.donor_files(), 0);
        assert!(pending.written_bytes() > 0);
        assert_eq!(
            publication.view().unwrap().read(&objects[359].0).unwrap(),
            objects[359].1
        );
        publication
            .seal(&NoopObserver, "origin", &mut applied)
            .unwrap();
        assert!(applied.contains(&key));
        assert_eq!(packs_on_disk(&layout), 2);
        for (id, bytes) in &objects {
            assert_eq!(&store.read(id).unwrap(), bytes);
        }
    }

    #[test]
    fn pending_view_checks_both_sources_and_refuses_a_corrupt_spool_copy() {
        let dir = tempfile::tempdir().unwrap();
        let layout = RepoLayout::single(dir.path());
        let store = ObjectStore::init(&layout).unwrap();
        std::fs::create_dir_all(store.spool_dir()).unwrap();
        let spool = ObjectSpool::new(&store.spool_dir()).unwrap();
        let durable = serialize::serialize(&Object::Blob(kit_core::object::Blob {
            data: b"durable".to_vec(),
        }))
        .unwrap();
        let pending = serialize::serialize(&Object::Blob(kit_core::object::Blob {
            data: b"pending".to_vec(),
        }))
        .unwrap();
        let durable_id = store.write(&durable).unwrap();
        let pending_id = kit_core::hash::hash(&pending);
        spool
            .append(0, pending_id, ObjectType::Blob, &pending)
            .unwrap();
        let view = PendingView::new(&store, Some(&spool));

        assert!(view.contains(&durable_id));
        assert!(view.contains(&pending_id));
        assert!(!view.contains(&[0; 32]));
        assert_eq!(view.read(&durable_id).unwrap(), durable);
        assert_eq!(view.read(&pending_id).unwrap(), pending);

        spool
            .append(1, durable_id, ObjectType::Blob, &pending)
            .unwrap();
        assert!(matches!(
            view.read(&durable_id),
            Err(StoreError::HashMismatch { .. })
        ));
    }

    #[test]
    fn a_guarded_view_reads_the_spool_before_the_store_and_refuses_a_foreign_guard() {
        let dir = tempfile::tempdir().unwrap();
        let layout = RepoLayout::single(dir.path());
        let store = ObjectStore::init(&layout).unwrap();
        store.try_activate_local_packs().unwrap();
        std::fs::create_dir_all(store.spool_dir()).unwrap();
        let spool = ObjectSpool::new(&store.spool_dir()).unwrap();
        let blob = |data: &[u8]| {
            serialize::serialize(&Object::Blob(kit_core::object::Blob {
                data: data.to_vec(),
            }))
            .unwrap()
        };
        let (durable, pending) = (blob(b"durable"), blob(b"pending"));
        let durable_id = store.write(&durable).unwrap();
        let pending_id = kit_core::hash::hash(&pending);
        spool
            .append(0, pending_id, ObjectType::Blob, &pending)
            .unwrap();
        let guard = store.prune_guard().unwrap();
        let view = PendingView::guarded(&store, Some(&spool), &guard).unwrap();

        assert_eq!(view.read(&durable_id).unwrap(), durable);
        assert_eq!(view.read(&pending_id).unwrap(), pending);
        assert_eq!(
            view.object_head(&pending_id).unwrap(),
            (ObjectType::Blob, Some(7))
        );
        assert_eq!(view.object_type(&durable_id).unwrap(), ObjectType::Blob);
        // A staged copy comes first, so a corrupt one is not hidden by a
        // good copy in the store.
        spool
            .append(1, durable_id, ObjectType::Blob, &pending)
            .unwrap();
        assert!(matches!(
            view.read(&durable_id),
            Err(StoreError::HashMismatch { .. })
        ));

        let other = tempfile::tempdir().unwrap();
        let other_store = ObjectStore::init(&RepoLayout::single(other.path())).unwrap();
        assert!(PendingView::guarded(&other_store, None, &guard).is_err());
    }

    #[test]
    fn tiny_entries_seal_at_the_entry_limit_even_below_the_byte_limit() {
        let dir = tempfile::tempdir().unwrap();
        let layout = RepoLayout::single(dir.path());
        let store = ObjectStore::init(&layout).unwrap();
        store.try_activate_local_packs().unwrap();
        std::fs::create_dir_all(store.spool_dir()).unwrap();
        let guard = store.prune_guard().unwrap();
        let mut publication = Publication::new(&store, &guard).unwrap();
        let mut applied = AppliedPacks::load(&layout, "origin").unwrap();
        let spool = ObjectSpool::new(&store.spool_dir()).unwrap();
        let tree = Object::Tree(Tree {
            entries: Vec::new(),
        });
        let bytes = serialize::serialize(&tree).unwrap();
        let id = tree.id().unwrap();
        for position in 0..65_536 {
            spool
                .append(position, id, ObjectType::Tree, &bytes)
                .unwrap();
        }
        let key = PackKey::from_hash(kit_core::hash::hash(b"wire pack"));
        publication
            .accept(&spool, key, &NoopObserver, "origin", &mut applied)
            .unwrap();
        publication
            .finish(&NoopObserver, "origin", &mut applied)
            .unwrap();

        assert!(publication.pending().is_empty());
        assert_eq!(store.read(&id).unwrap(), bytes);
        assert!(
            AppliedPacks::load(&layout, "origin")
                .unwrap()
                .contains(&key)
        );
    }

    #[test]
    fn a_full_window_seals_in_the_background_and_is_recorded_when_it_finishes() {
        let Fixture {
            layout,
            store,
            _dir,
        } = fixture();
        let guard = store.prune_guard().unwrap();
        let mut publication = Publication::new(&store, &guard).unwrap();
        let mut applied = AppliedPacks::load(&layout, "origin").unwrap();

        // Two wire packs of 40 MB: the second one fills the window with its
        // first 24 MB and leaves the rest in the next window.
        let objects: Vec<_> = (0..400).map(|n| numbered_blob(n, 200_000)).collect();
        let keys: Vec<_> = (0..2_u8)
            .map(|n| PackKey::from_hash(kit_core::hash::hash(&[n])))
            .collect();
        for (n, key) in keys.iter().enumerate() {
            let spool = publication.decode_spool().unwrap();
            stage(
                &spool,
                &objects[n * 200..(n + 1) * 200].iter().collect::<Vec<_>>(),
            );
            publication
                .accept(&spool, *key, &NoopObserver, "origin", &mut applied)
                .unwrap();
        }
        // The first window is sealing, and its objects stay readable as bases
        // through the pending spools. Nothing names it before it finishes.
        assert!(publication.sealing.is_some());
        assert_eq!(publication.pending().len(), 2);
        assert!(publication.completed(&keys[0]));
        assert!(!applied.contains(&keys[0]));
        assert!(
            publication
                .pending()
                .iter()
                .any(|spool| spool.contains(&objects[0].0))
        );

        publication
            .finish(&NoopObserver, "origin", &mut applied)
            .unwrap();
        assert!(publication.sealing.is_none());
        assert_eq!(publication.pending().len(), 1);
        assert!(applied.contains(&keys[0]));
        assert!(!applied.contains(&keys[1]));
        assert!(store.contains(&objects[0].0));
        assert!(!store.contains(&objects[399].0));

        publication
            .seal(&NoopObserver, "origin", &mut applied)
            .unwrap();
        assert!(applied.contains(&keys[1]));
        for (id, bytes) in &objects {
            assert_eq!(&store.read(id).unwrap(), bytes);
        }
        assert_eq!(packs_on_disk(&layout), 2);
    }

    /// A window whose pack cannot be sealed: its writer already failed.
    fn failing_sealing(store: &ObjectStore, guard: &PruneGuard, key: PackKey) -> Sealing {
        let mut writer = LocalPackWriter::new(store, guard).unwrap();
        writer.write(&numbered_blob(1, 1000).1).unwrap();
        assert!(writer.write(b"not an object").is_err());
        let window = Window {
            spool: ObjectSpool::new(&store.spool_dir()).unwrap(),
            bytes: 0,
            entries: 1,
            completed: vec![key],
            completed_set: HashSet::from([key]),
        };
        Sealing {
            window,
            loose: Vec::new(),
            seal: Seal::start(writer.detach()),
        }
    }

    #[test]
    fn a_failed_background_seal_fails_the_next_step_and_records_nothing_of_its_window() {
        let Fixture {
            layout,
            store,
            _dir,
        } = fixture();
        let guard = store.prune_guard().unwrap();
        let mut publication = Publication::new(&store, &guard).unwrap();
        let mut applied = AppliedPacks::load(&layout, "origin").unwrap();
        let sealed = numbered_blob(7, 5000);
        let sealed_key = PackKey::from_hash(kit_core::hash::hash(b"sealed"));
        let spool = publication.decode_spool().unwrap();
        stage(&spool, &[&sealed]);
        publication
            .accept(&spool, sealed_key, &NoopObserver, "origin", &mut applied)
            .unwrap();
        publication
            .seal(&NoopObserver, "origin", &mut applied)
            .unwrap();

        let failed_key = PackKey::from_hash(kit_core::hash::hash(b"failed"));
        publication.sealing = Some(failing_sealing(&store, &guard, failed_key));
        // The next window's seal finishes the one in flight first, and fails.
        let next = numbered_blob(8, 5000);
        let spool = publication.decode_spool().unwrap();
        stage(&spool, &[&next]);
        let next_key = PackKey::from_hash(kit_core::hash::hash(b"next"));
        publication
            .accept(&spool, next_key, &NoopObserver, "origin", &mut applied)
            .unwrap();
        assert!(
            publication
                .seal(&NoopObserver, "origin", &mut applied)
                .is_err()
        );

        // What was sealed before stays; nothing else is named or published.
        assert!(applied.contains(&sealed_key));
        assert!(!applied.contains(&failed_key));
        assert!(!applied.contains(&next_key));
        assert!(store.contains(&sealed.0));
        assert!(!store.contains(&next.0));
        assert_eq!(packs_on_disk(&layout), 1);
        assert!(
            AppliedPacks::load(&layout, "origin")
                .unwrap()
                .contains(&sealed_key)
        );
    }

    #[test]
    fn a_dropped_publication_waits_for_its_worker() {
        let Fixture { store, _dir, .. } = fixture();
        let guard = store.prune_guard().unwrap();
        let mut publication = Publication::new(&store, &guard).unwrap();
        let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = std::sync::Arc::clone(&done);
        let mut sealing = failing_sealing(
            &store,
            &guard,
            PackKey::from_hash(kit_core::hash::hash(b"slow")),
        );
        sealing.seal = Seal::Running(std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(300));
            flag.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }));
        publication.sealing = Some(sealing);
        drop(publication);
        assert!(done.load(std::sync::atomic::Ordering::SeqCst));
    }

    /// A window sealed by `seal`, which is the outcome of its worker.
    fn sealing_with(store: &ObjectStore, key: PackKey, seal: Seal) -> Sealing {
        Sealing {
            window: Window {
                spool: ObjectSpool::new(&store.spool_dir()).unwrap(),
                bytes: 0,
                entries: 1,
                completed: vec![key],
                completed_set: HashSet::from([key]),
            },
            loose: Vec::new(),
            seal,
        }
    }

    #[test]
    fn a_seal_that_has_ended_is_finished_without_waiting_for_the_next_window() {
        let Fixture {
            layout,
            store,
            _dir,
        } = fixture();
        let guard = store.prune_guard().unwrap();
        let mut publication = Publication::new(&store, &guard).unwrap();
        let mut applied = AppliedPacks::load(&layout, "origin").unwrap();
        let key = PackKey::from_hash(kit_core::hash::hash(b"running"));
        let (release, wait) = std::sync::mpsc::channel::<()>();
        publication.sealing = Some(sealing_with(
            &store,
            key,
            Seal::Running(std::thread::spawn(move || {
                wait.recv().unwrap();
                Ok(())
            })),
        ));
        // The worker is still running: nothing is waited for or recorded.
        publication
            .finish_if_done(&NoopObserver, "origin", &mut applied)
            .unwrap();
        assert!(publication.sealing.is_some());
        assert!(!applied.contains(&key));

        release.send(()).unwrap();
        while !publication.sealing.as_ref().unwrap().seal.is_done() {
            std::thread::yield_now();
        }
        publication
            .finish_if_done(&NoopObserver, "origin", &mut applied)
            .unwrap();
        assert!(publication.sealing.is_none());
        assert!(applied.contains(&key));

        // A seal that ran on the caller's thread is always done.
        let key = PackKey::from_hash(kit_core::hash::hash(b"inline"));
        publication.sealing = Some(sealing_with(&store, key, Seal::Done(Ok(()))));
        publication
            .finish_if_done(&NoopObserver, "origin", &mut applied)
            .unwrap();
        assert!(applied.contains(&key));
    }

    #[test]
    fn a_walk_is_refused_while_a_seal_is_in_flight() {
        let Fixture { store, _dir, .. } = fixture();
        let guard = store.prune_guard().unwrap();
        let mut publication = Publication::new(&store, &guard).unwrap();
        assert!(publication.view().is_ok());
        publication.sealing = Some(sealing_with(
            &store,
            PackKey::from_hash(kit_core::hash::hash(b"busy")),
            Seal::Done(Ok(())),
        ));
        assert!(publication.view().is_err());
    }

    #[test]
    fn a_worker_that_panics_fails_the_finish_and_does_not_panic_the_drop() {
        let Fixture {
            layout,
            store,
            _dir,
        } = fixture();
        let guard = store.prune_guard().unwrap();
        let key = PackKey::from_hash(kit_core::hash::hash(b"panic"));
        let panicking = || {
            Seal::Running(std::thread::spawn(|| -> StoreResult<()> {
                std::panic::resume_unwind(Box::new("worker"))
            }))
        };
        let mut publication = Publication::new(&store, &guard).unwrap();
        let mut applied = AppliedPacks::load(&layout, "origin").unwrap();
        publication.sealing = Some(sealing_with(&store, key, panicking()));
        let finished = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = publication.finish(&NoopObserver, "origin", &mut applied);
        }));
        assert!(finished.is_err());
        assert!(!applied.contains(&key));

        // An abandoned fetch swallows it: the drop is not the place to fail.
        let mut publication = Publication::new(&store, &guard).unwrap();
        publication.sealing = Some(sealing_with(&store, key, panicking()));
        drop(publication);
    }

    #[test]
    fn a_window_that_fails_to_build_still_lets_the_one_before_finish() {
        let Fixture {
            layout,
            store,
            _dir,
        } = fixture();
        let guard = store.prune_guard().unwrap();
        let mut publication = Publication::new(&store, &guard).unwrap();
        let mut applied = AppliedPacks::load(&layout, "origin").unwrap();
        let key = PackKey::from_hash(kit_core::hash::hash(b"before"));
        publication.sealing = Some(sealing_with(&store, key, Seal::Done(Ok(()))));
        // The next window cannot start a pack: its directory is a file.
        let packs = layout.objects_dir().join("pack");
        let next = numbered_blob(9, 200_000);
        let spool = publication.decode_spool().unwrap();
        stage(&spool, &[&next]);
        let next_key = PackKey::from_hash(kit_core::hash::hash(b"after"));
        publication
            .accept(&spool, next_key, &NoopObserver, "origin", &mut applied)
            .unwrap();
        let _ = std::fs::remove_dir_all(&packs);
        std::fs::write(&packs, b"not a directory").unwrap();
        assert!(
            publication
                .seal(&NoopObserver, "origin", &mut applied)
                .is_err()
        );
        // The window in flight was finished by the failed seal itself.
        assert!(publication.sealing.is_none());
        assert!(applied.contains(&key));
        assert!(!applied.contains(&next_key));
    }
}
