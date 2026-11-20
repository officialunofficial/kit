use std::collections::HashSet;
use std::fs;
use std::io::{self, BufWriter, Read, Seek, SeekFrom, Write};

use crate::pack::{HEADER_LEN, MAGIC, MAX_ENTRIES, MAX_TOTAL_PAYLOAD};

use super::{
    Arc, Hash, Index, ObjectStore, Pair, StoreResult, format, index, matching_index, open_regular,
    scan_pair, stage_file, stage_index,
};
use crate::store::{MAX_RAW_OBJECT_SIZE, PruneGuard, StoreError};

/// Write a private local pack, then make it durable and discoverable.
#[doc(hidden)]
#[derive(Debug)]
pub struct LocalPackWriter<'a> {
    store: &'a ObjectStore,
    _guard: &'a PruneGuard,
    pack: BufWriter<tempfile::NamedTempFile>,
    ids: HashSet<Hash>,
    payload: u64,
}

impl<'a> LocalPackWriter<'a> {
    /// Open one pack under the store's existing shared guard.
    ///
    /// # Errors
    /// The packed marker could not be validated or synced, or staging failed.
    pub fn new(store: &'a ObjectStore, guard: &'a PruneGuard) -> StoreResult<Self> {
        store.check_prune_guard(guard)?;
        prepare_dir(store, guard)?;
        Ok(Self {
            store,
            _guard: guard,
            pack: BufWriter::with_capacity(256 << 10, new_pack(store)?),
            ids: HashSet::new(),
            payload: 0,
        })
    }

    /// Stage one canonical object, deduplicating only within this pack.
    ///
    /// # Errors
    /// Invalid bytes, a full pack, or a staging write error.
    pub fn write(&mut self, bytes: &[u8]) -> StoreResult<Hash> {
        let id = checked_id(bytes)?;
        if !self.ids.contains(&id) {
            if self.ids.len() == MAX_ENTRIES as usize
                || self.payload + bytes.len() as u64 > MAX_TOTAL_PAYLOAD
            {
                return Err(StoreError::ObjectTooLarge);
            }
            #[cfg(feature = "fault-injection")]
            crate::fault::check(crate::fault::Site::Store)?;
            write_frame(&mut self.pack, bytes)?;
            self.payload += bytes.len() as u64;
            self.ids.insert(id);
        }
        Ok(id)
    }

    /// Sync and publish the pack and index. An empty pack needs no pair.
    ///
    /// # Errors
    /// A staging or publication failure.
    pub fn publish(self) -> StoreResult<()> {
        if !self.ids.is_empty() {
            let pack = self
                .pack
                .into_inner()
                .map_err(std::io::IntoInnerError::into_error)?;
            Staged::seal(self.store, pack, self.ids.len())?.publish(self.store)?;
        }
        Ok(())
    }
}

fn prepare_dir(store: &ObjectStore, guard: &PruneGuard) -> StoreResult<()> {
    format::sync_packed(&store.format_path(), guard)?;
    let dir = store.pack_dir();
    fs::create_dir_all(&dir)?;
    if !fs::symlink_metadata(&dir)?.is_dir() {
        return Err(index::invalid("local pack directory is not a directory").into());
    }
    crate::atomic::sync_dir(store.objects_root())?;
    Ok(())
}

fn checked_id(bytes: &[u8]) -> StoreResult<Hash> {
    if bytes.len() > MAX_RAW_OBJECT_SIZE {
        return Err(StoreError::ObjectTooLarge);
    }
    index::canonical_id(bytes)
}

fn write_frame(mut writer: impl Write, bytes: &[u8]) -> StoreResult<()> {
    let mut frame = [0; 5];
    frame[1..].copy_from_slice(
        &u32::try_from(bytes.len())
            .expect("bounded object length")
            .to_le_bytes(),
    );
    writer.write_all(&frame)?;
    writer.write_all(bytes)?;
    Ok(())
}

#[cfg(test)]
pub(super) struct Writer<'a> {
    store: &'a ObjectStore,
    guard: PruneGuard,
    pack: tempfile::NamedTempFile,
    ids: HashSet<Hash>,
    payload: u64,
    max_entries: u32,
    max_payload: u64,
}

#[cfg(test)]
impl<'a> Writer<'a> {
    pub(super) fn new(
        store: &'a ObjectStore,
        max_entries: u32,
        max_payload: u64,
    ) -> StoreResult<Self> {
        assert!((1..=MAX_ENTRIES).contains(&max_entries));
        assert!((1..=MAX_TOTAL_PAYLOAD).contains(&max_payload));
        store.try_activate_local_packs()?;
        let guard = store.prune_guard()?;
        prepare_dir(store, &guard)?;
        Ok(Self {
            store,
            guard,
            pack: new_pack(store)?,
            ids: HashSet::new(),
            payload: 0,
            max_entries,
            max_payload,
        })
    }

    pub(super) fn write(&mut self, bytes: &[u8]) -> StoreResult<Hash> {
        if bytes.len() as u64 > self.max_payload {
            return Err(StoreError::ObjectTooLarge);
        }
        let id = checked_id(bytes)?;
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
        write_frame(&mut self.pack, bytes)?;
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
        if let Some(staged) = persist_unique(pack, &pair.pack)? {
            let existing = open_regular(&pair.pack)?;
            pair.check_versions()?;
            match scan_pair(&pair) {
                Ok(_) => {
                    crate::store::refresh_mtime(&pair.pack)?;
                    existing.sync_all()?;
                }
                // The staged copy was fully verified and has this exact key.
                // Replace a damaged member without making the pair disappear.
                Err(StoreError::Io(e)) if e.kind() == io::ErrorKind::InvalidData => {
                    staged.persist(&pair.pack).map_err(|e| e.error)?;
                }
                Err(e) => return Err(e),
            }
        }
        crate::atomic::sync_dir(&dir)?;
        after_pack_sync()?;
        if let Some(staged) = persist_unique(idx, &pair.index)? {
            let existing = open_regular(&pair.index)?;
            let rows = scan_pair(&pair)?;
            if matching_index(&pair, &rows)? {
                existing.sync_all()?;
            } else {
                staged.persist(&pair.index).map_err(|e| e.error)?;
            }
        }
        let checked = Index::open(&pair)?;
        crate::atomic::sync_dir(&dir)?;
        store
            .packs
            .enabled
            .store(true, std::sync::atomic::Ordering::Relaxed);
        store.packs.remember(Arc::new(checked));
        Ok(())
    }
}

// Return the staged copy on collision so the caller can compare it with the
// existing member or replace a damaged copy of the same content.
fn persist_unique(
    tmp: tempfile::NamedTempFile,
    path: &std::path::Path,
) -> StoreResult<Option<tempfile::NamedTempFile>> {
    match tmp.persist_noclobber(path) {
        Ok(_) => Ok(None),
        Err(e) if e.error.kind() == io::ErrorKind::AlreadyExists => Ok(Some(e.file)),
        Err(e) => Err(e.error.into()),
    }
}
