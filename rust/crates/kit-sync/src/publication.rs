//! Private fetch windows. Only complete, checked wire packs enter a window.

use std::collections::HashSet;

use kit_core::chunker;
use kit_core::hash::{Hash, to_hex};
use kit_core::object::{Object, ObjectType};
use kit_core::pack::{ObjectSpool, PackError};
use kit_core::protocol::PackKey;
use kit_core::serialize;
use kit_core::store::{
    ClosureSource, LocalPackWriter, ObjectSource, ObjectStore, PruneGuard, StoreError, StoreResult,
};

use crate::applied_packs::AppliedPacks;
use crate::observer::{Observer, SyncEvent};

const WINDOW_BYTES: usize = 64 << 20;
// A minimum-size blob is ten bytes. The byte limit alone would allow more
// than six million tiny objects. Stop at 65,536 entries, which bounds the
// locators, batch paths and pack index workspace to the same entry count as
// the decoder's normal window.
const WINDOW_ENTRIES: usize = 1 << 16;
// The largest object a kit writer cuts as a chunk, with its blob prologue.
// Every object of at most this size is packed, whatever its kind.
const PACK_OBJECT_BYTES: usize = chunker::MAX_SIZE + serialize::BLOB_PROLOGUE_LEN;
// A window holds one open handle for each wire pack whose loose objects it
// adopted. Seal at this many, so a window never holds enough to reach a low
// descriptor limit.
const WINDOW_ADOPTED_PACKS: usize = 32;

pub(crate) struct Publication<'a> {
    store: &'a ObjectStore,
    guard: &'a PruneGuard,
    pack: bool,
    window: Option<Window>,
}

struct Window {
    /// The objects to pack, copied here, and the objects to write loose,
    /// adopted from the spools they were decoded into.
    spool: ObjectSpool,
    bytes: usize,
    entries: usize,
    adopted_packs: usize,
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
        })
    }

    pub(crate) fn pending(&self) -> Option<&ObjectSpool> {
        self.window.as_ref().map(|window| &window.spool)
    }

    pub(crate) fn view(&self) -> PendingView<'_> {
        PendingView::new(self.store, self.pending())
    }

    pub(crate) fn completed(&self, key: &PackKey) -> bool {
        self.window
            .as_ref()
            .is_some_and(|window| window.completed_set.contains(key))
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
        // An object that ends as a loose file is not copied: the window adopts
        // it from `spool`, whose decoder already derived its id, and `seal`
        // reads it once to write it.
        // The decoder's file stays on disk until the window seals, so a pack of
        // mostly packed objects holds its bytes twice for that time.
        let mut loose = Vec::new();
        for (_, id, len, ty) in order {
            let size = len as usize;
            if self.window.as_ref().is_some_and(|window| {
                window.bytes + size > WINDOW_BYTES || window.entries == WINDOW_ENTRIES
            }) {
                self.adopt(spool, &mut loose)?;
                self.seal(observer, remote, applied)?;
            }
            let copied = if self.packs(size) {
                Some(staged(spool, &id)?)
            } else {
                None
            };
            let window = self.window()?;
            if let Some(bytes) = copied {
                window.spool.append(window.entries, id, ty, &bytes)?;
            } else {
                loose.push((window.entries, id, len, ty));
            }
            window.bytes += size;
            window.entries += 1;
        }
        self.adopt(spool, &mut loose)?;
        let packed = self.pack;
        let window = self.window()?;
        window.completed.push(key);
        window.completed_set.insert(key);
        if !packed
            || window.bytes >= WINDOW_BYTES
            || window.entries == WINDOW_ENTRIES
            || window.adopted_packs >= WINDOW_ADOPTED_PACKS
        {
            self.seal(observer, remote, applied)?;
        }
        Ok(())
    }

    /// Whether an object of `len` bytes goes into a local pack. Any other
    /// object is written as a loose file.
    fn packs(&self, len: usize) -> bool {
        self.pack && len <= PACK_OBJECT_BYTES
    }

    /// Hand the window the `loose` entries of `from`.
    fn adopt(
        &mut self,
        from: &ObjectSpool,
        loose: &mut Vec<(usize, Hash, u32, ObjectType)>,
    ) -> Result<(), PackError> {
        if loose.is_empty() {
            return Ok(());
        }
        let window = self.window()?;
        window.spool.adopt(from, &loose[..])?;
        window.adopted_packs += 1;
        loose.clear();
        Ok(())
    }

    fn window(&mut self) -> Result<&mut Window, PackError> {
        if self.window.is_none() {
            self.window = Some(Window {
                spool: ObjectSpool::new(&self.store.spool_dir())?,
                bytes: 0,
                entries: 0,
                adopted_packs: 0,
                completed: Vec::new(),
                completed_set: HashSet::new(),
            });
        }
        Ok(self.window.as_mut().expect("created publication window"))
    }

    pub(crate) fn seal(
        &mut self,
        observer: &dyn Observer<SyncEvent>,
        remote: &str,
        applied: &mut AppliedPacks,
    ) -> Result<(), PackError> {
        let Some(window) = self.window.take() else {
            return Ok(());
        };
        let loose = self.store.batch();
        let mut loose_ids = Vec::new();
        let mut seen = HashSet::new();
        let mut pack = None;
        for (_, id, len, _) in window.spool.take_order() {
            if self.packs(len as usize) {
                if pack.is_none() {
                    pack = Some(LocalPackWriter::new(self.store, self.guard)?);
                }
                let bytes = staged(&window.spool, &id)?;
                pack.as_mut().expect("created local pack").write(&bytes)?;
            } else if seen.insert(id) {
                loose_ids.push(id);
            }
        }
        // One checked read of each, from the decoder's file for an adopted
        // object, then a write under the checked id.
        loose.stage_spooled(&window.spool, &loose_ids)?;
        if let Some(pack) = pack {
            pack.publish()?;
        }
        loose.commit()?;
        for key in window.completed {
            record(key, observer, remote, applied);
        }
        crate::fetch::persist_record(applied, observer, remote);
        Ok(())
    }
}

fn staged(spool: &ObjectSpool, id: &Hash) -> StoreResult<Vec<u8>> {
    spool
        .read(id)?
        .ok_or_else(|| StoreError::ObjectNotFound(to_hex(id)))
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
pub(crate) struct PendingView<'a> {
    store: &'a ObjectStore,
    spool: Option<&'a ObjectSpool>,
}

impl<'a> PendingView<'a> {
    pub(crate) fn new(store: &'a ObjectStore, spool: Option<&'a ObjectSpool>) -> Self {
        Self { store, spool }
    }

    fn pending(&self, id: &Hash) -> StoreResult<Option<Vec<u8>>> {
        self.spool.map_or(Ok(None), |spool| spool.read(id))
    }

    /// The head of a staged object. A staged object's bytes are checked when
    /// they are written out, so a head read does not read the rest.
    fn pending_head(&self, id: &Hash) -> StoreResult<Option<(ObjectType, Option<u64>)>> {
        self.spool.map_or(Ok(None), |spool| spool.head(id))
    }

    pub(crate) fn contains(&self, id: &Hash) -> bool {
        self.spool.is_some_and(|spool| spool.contains(id)) || self.store.contains(id)
    }
}

impl ObjectSource for PendingView<'_> {
    fn read(&self, id: &Hash) -> StoreResult<Vec<u8>> {
        self.pending(id)?.map_or_else(|| self.store.read(id), Ok)
    }

    fn read_object(&self, id: &Hash) -> StoreResult<Object> {
        if let Some(bytes) = self.pending(id)? {
            Ok(serialize::deserialize_owned(bytes)?)
        } else {
            self.store.read_object(id)
        }
    }
}
impl ClosureSource for PendingView<'_> {
    fn object_type(&self, id: &Hash) -> StoreResult<ObjectType> {
        if let Some((ty, _)) = self.pending_head(id)? {
            Ok(ty)
        } else {
            self.store.object_type(id)
        }
    }

    fn object_head(&self, id: &Hash) -> StoreResult<(ObjectType, Option<u64>)> {
        if let Some(head) = self.pending_head(id)? {
            Ok(head)
        } else {
            self.store.object_head(id)
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

        assert!(publication.pending().is_none());
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

    #[test]
    fn objects_over_the_pack_limit_are_written_loose_straight_from_the_decoder_spool() {
        let dir = tempfile::tempdir().unwrap();
        let layout = RepoLayout::single(dir.path());
        let store = ObjectStore::init(&layout).unwrap();
        store.try_activate_local_packs().unwrap();
        let guard = store.prune_guard().unwrap();
        std::fs::create_dir_all(store.spool_dir()).unwrap();
        let mut publication = Publication::new(&store, &guard).unwrap();
        let mut applied = AppliedPacks::load(&layout, "origin").unwrap();
        let (small_id, small) = big_blob(1000, 1);
        let (mid_id, mid) = big_blob(300 << 10, 2);
        let (large_id, large) = big_blob(1 << 20, 3);
        assert!(mid.len() > PACK_OBJECT_BYTES);

        let spool = ObjectSpool::new(&store.spool_dir()).unwrap();
        for (position, (id, bytes)) in [(small_id, &small), (mid_id, &mid), (large_id, &large)]
            .into_iter()
            .enumerate()
        {
            spool.append(position, id, ObjectType::Blob, bytes).unwrap();
        }
        let key = PackKey::from_hash(kit_core::hash::hash(b"over the pack limit"));
        publication
            .accept(&spool, key, &NoopObserver, "origin", &mut applied)
            .unwrap();
        drop(spool);

        // Only the packed object was copied into the window's own file. The
        // loose ones are readable, checked, from the decoder's file.
        let pending = publication.pending().unwrap();
        assert_eq!(pending.written_bytes(), small.len() as u64);
        let view = publication.view();
        assert!(view.contains(&mid_id) && view.contains(&large_id));
        assert_eq!(view.read(&mid_id).unwrap(), mid);
        assert_eq!(view.read(&large_id).unwrap(), large);
        // The closure check asks for a head, which reads ten bytes.
        assert_eq!(
            view.object_head(&mid_id).unwrap(),
            (ObjectType::Blob, Some(300 << 10))
        );
        assert_eq!(view.object_type(&large_id).unwrap(), ObjectType::Blob);

        publication
            .seal(&NoopObserver, "origin", &mut applied)
            .unwrap();
        assert!(applied.contains(&key));
        assert_eq!(std::fs::read(loose_path(&layout, &mid_id)).unwrap(), mid);
        assert_eq!(
            std::fs::read(loose_path(&layout, &large_id)).unwrap(),
            large
        );
        assert!(!loose_path(&layout, &small_id).exists());
        for (id, bytes) in [(small_id, small), (mid_id, mid), (large_id, large)] {
            assert_eq!(store.read(&id).unwrap(), bytes);
        }
    }

    #[test]
    fn a_window_seals_before_it_holds_too_many_decoder_files() {
        let dir = tempfile::tempdir().unwrap();
        let layout = RepoLayout::single(dir.path());
        let store = ObjectStore::init(&layout).unwrap();
        store.try_activate_local_packs().unwrap();
        let guard = store.prune_guard().unwrap();
        std::fs::create_dir_all(store.spool_dir()).unwrap();
        let mut publication = Publication::new(&store, &guard).unwrap();
        let mut applied = AppliedPacks::load(&layout, "origin").unwrap();

        for n in 0..WINDOW_ADOPTED_PACKS {
            let byte = u8::try_from(n).unwrap();
            let (id, bytes) = big_blob(PACK_OBJECT_BYTES + 1, byte);
            let spool = ObjectSpool::new(&store.spool_dir()).unwrap();
            spool.append(0, id, ObjectType::Blob, &bytes).unwrap();
            let key = PackKey::from_hash(kit_core::hash::hash(&[byte]));
            publication
                .accept(&spool, key, &NoopObserver, "origin", &mut applied)
                .unwrap();
            // Each pack stays in the window until the last one fills it.
            let last = n + 1 == WINDOW_ADOPTED_PACKS;
            assert_eq!(publication.pending().is_none(), last, "pack {n}");
            assert_eq!(applied.contains(&key), last, "pack {n}");
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

        assert!(publication.pending().is_none());
        assert_eq!(store.read(&id).unwrap(), bytes);
        assert!(
            AppliedPacks::load(&layout, "origin")
                .unwrap()
                .contains(&key)
        );
    }
}
