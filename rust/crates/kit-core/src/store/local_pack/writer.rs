use std::collections::HashSet;
use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};

use crate::pack::{HEADER_LEN, MAGIC, MAX_ENTRIES, MAX_TOTAL_PAYLOAD};

use super::{
    Arc, Hash, Index, ObjectStore, Pair, StoreResult, format, index, open_regular, regular,
    scan_pair, stage_file, stage_index,
};
use crate::store::{MAX_RAW_OBJECT_SIZE, PruneGuard, StoreError};

/// The store's wide test writer. Fetch has its own selection and window rules.
pub(super) struct Writer<'a> {
    store: &'a ObjectStore,
    guard: PruneGuard,
    pack: tempfile::NamedTempFile,
    ids: HashSet<Hash>,
    payload: u64,
    max_entries: u32,
    max_payload: u64,
}

impl<'a> Writer<'a> {
    pub(super) fn new(
        store: &'a ObjectStore,
        max_entries: u32,
        max_payload: u64,
    ) -> StoreResult<Self> {
        assert!((1..=MAX_ENTRIES).contains(&max_entries));
        assert!((1..=MAX_TOTAL_PAYLOAD).contains(&max_payload));
        if !format::check(&store.format_path())? {
            // A publisher racing the first activation can try again once the
            // other publisher releases the exclusive lock.
            format::activate(&store.format_path())?;
        }
        let guard = store.prune_guard()?;
        format::sync_packed(&store.format_path(), &guard)?;
        let dir = store.pack_dir();
        if !dir.exists() {
            fs::create_dir_all(&dir)?;
        }
        if !fs::symlink_metadata(&dir)?.is_dir() {
            return Err(index::invalid("local pack directory is not a directory").into());
        }
        crate::atomic::sync_dir(store.objects_root())?;
        let pack = new_pack(store)?;
        Ok(Self {
            store,
            guard,
            pack,
            ids: HashSet::new(),
            payload: 0,
            max_entries,
            max_payload,
        })
    }

    pub(super) fn write(&mut self, bytes: &[u8]) -> StoreResult<Hash> {
        if bytes.len() > MAX_RAW_OBJECT_SIZE || bytes.len() as u64 > self.max_payload {
            return Err(StoreError::ObjectTooLarge);
        }
        let id = index::canonical_id(bytes)?;
        if self.ids.contains(&id) {
            return Ok(id);
        }
        if self.ids.len() == self.max_entries as usize
            || self.payload + bytes.len() as u64 > self.max_payload
        {
            let next = new_pack(self.store)?;
            let pack = std::mem::replace(&mut self.pack, next);
            Staged::seal(self.store, pack, self.ids.len())?.publish(self.store)?;
            self.payload = 0;
            self.ids.clear();
        }
        self.pack.write_all(&[0])?;
        self.pack.write_all(
            &u32::try_from(bytes.len())
                .expect("bounded object length")
                .to_le_bytes(),
        )?;
        self.pack.write_all(bytes)?;
        self.payload += bytes.len() as u64;
        self.ids.insert(id);
        Ok(id)
    }

    pub(super) fn stage(self) -> StoreResult<(Staged, PruneGuard)> {
        Ok((
            Staged::seal(self.store, self.pack, self.ids.len())?,
            self.guard,
        ))
    }

    pub(super) fn finish(self) -> StoreResult<()> {
        let store = self.store;
        if !self.ids.is_empty() {
            let (staged, _guard) = self.stage()?;
            staged.publish(store)?;
        }
        Ok(())
    }
}

fn new_pack(store: &ObjectStore) -> StoreResult<tempfile::NamedTempFile> {
    let mut pack = stage_file(&store.pack_dir(), ".tmp.pack")?;
    pack.write_all(MAGIC)?;
    pack.write_all(&1_u32.to_le_bytes())?;
    pack.write_all(&0_u32.to_le_bytes())?;
    Ok(pack)
}

pub(super) struct Staged {
    pub(super) pair: Pair,
    pub(super) pack: tempfile::NamedTempFile,
    pub(super) idx: tempfile::NamedTempFile,
}

impl Staged {
    fn seal(
        store: &ObjectStore,
        mut pack: tempfile::NamedTempFile,
        count: usize,
    ) -> StoreResult<Self> {
        pack.seek(SeekFrom::Start(HEADER_LEN as u64 - 4))?;
        pack.write_all(
            &u32::try_from(count)
                .expect("bounded frame count")
                .to_le_bytes(),
        )?;
        pack.rewind()?;
        let mut digest = blake3::Hasher::new();
        let mut buffer = [0; 16 * 1024];
        loop {
            let read = pack.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            digest.update(&buffer[..read]);
        }
        pack.write_all(digest.finalize().as_bytes())?;
        let (key, rows) = index::scan(pack.as_file_mut())?;
        let dir = store.pack_dir();
        let pair = Pair::new(&dir, key);
        pack.as_file().sync_all()?;
        let idx = stage_index(&dir, &pair, pack.path(), &rows)?;
        Ok(Self { pair, pack, idx })
    }

    pub(super) fn publish(self, store: &ObjectStore) -> StoreResult<()> {
        self.publish_with(store, || Ok(()))
    }

    pub(super) fn publish_with(
        self,
        store: &ObjectStore,
        after_pack_sync: impl FnOnce() -> StoreResult<()>,
    ) -> StoreResult<()> {
        let Self { pair, pack, idx } = self;
        let dir = store.pack_dir();
        // A publisher may leave a valid pack without its index. A later
        // writer of the same key can complete the pair under the guard.
        let existing_pack = persist_unique(pack, &pair.pack)?;
        if existing_pack {
            scan_pair(&pair)?;
            open_regular(&pair.pack)?.sync_all()?;
        }
        crate::atomic::sync_dir(&dir)?;
        after_pack_sync()?;
        let existing_index = persist_unique(idx, &pair.index)?;
        let checked = Index::open(&pair)?;
        if existing_pack || existing_index {
            let rows = scan_pair(&pair)?;
            if !checked.matches(&rows) || !regular(&pair.pack)? || !regular(&pair.index)? {
                return Err(pair.error("existing pack and index disagree"));
            }
            open_regular(&pair.index)?.sync_all()?;
        }
        crate::atomic::sync_dir(&dir)?;
        store
            .packs
            .enabled
            .store(true, std::sync::atomic::Ordering::Relaxed);
        store.packs.remember(Arc::new(checked));
        Ok(())
    }
}

fn persist_unique(tmp: tempfile::NamedTempFile, path: &std::path::Path) -> StoreResult<bool> {
    match tmp.persist_noclobber(path) {
        Ok(_) => Ok(false),
        Err(e) if e.error.kind() == io::ErrorKind::AlreadyExists => Ok(true),
        Err(e) => Err(e.error.into()),
    }
}
