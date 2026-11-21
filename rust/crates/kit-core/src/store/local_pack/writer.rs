use std::collections::HashSet;
use std::fs;
use std::io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write};

use crate::pack::{ENTRY_FRAME_LEN, HEADER_LEN, MAGIC, MAX_ENTRIES, MAX_TOTAL_PAYLOAD};

use super::{
    Frame, Hash, Index, ObjectStore, Pair, StoreResult, format, index, matching_index,
    open_regular, scan_pair, stage_file, stage_index,
};
use crate::store::{MAX_RAW_OBJECT_SIZE, PruneGuard, StoreError};

/// Where each frame of a pack under construction sits, in write order.
#[derive(Debug)]
struct Frames {
    rows: Vec<(Hash, Frame)>,
    /// The offset one past the last frame, where the trailer will start.
    end: u64,
}

impl Frames {
    fn new() -> Self {
        Self {
            rows: Vec::new(),
            end: HEADER_LEN as u64,
        }
    }

    fn record(&mut self, id: Hash, len: u32) {
        self.rows.push((
            id,
            Frame {
                offset: self.end + ENTRY_FRAME_LEN as u64,
                len,
            },
        ));
        self.end += ENTRY_FRAME_LEN as u64 + u64::from(len);
    }
}

/// The most a pack and each object in it may hold.
#[derive(Debug, Clone, Copy)]
struct Limits {
    object: usize,
    entries: usize,
    payload: u64,
}

impl Limits {
    const PACK: Self = Self {
        object: MAX_RAW_OBJECT_SIZE,
        entries: MAX_ENTRIES as usize,
        payload: MAX_TOTAL_PAYLOAD,
    };
}

/// Write a private local pack, then make it durable and discoverable.
///
/// Any error inside a write leaves the writer unusable: the staging file may
/// hold half a frame, so [`Self::publish`] of a failed writer publishes
/// nothing and returns an error.
#[doc(hidden)]
#[derive(Debug)]
pub struct LocalPackWriter<'a> {
    store: &'a ObjectStore,
    _guard: &'a PruneGuard,
    pack: BufWriter<tempfile::NamedTempFile>,
    ids: HashSet<Hash>,
    frames: Frames,
    payload: u64,
    limits: Limits,
    failed: bool,
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
            frames: Frames::new(),
            payload: 0,
            limits: Limits::PACK,
            failed: false,
        })
    }

    /// Stage one canonical object, deduplicating only within this pack.
    ///
    /// # Errors
    /// Invalid bytes, a full pack, or a staging write error.
    pub fn write(&mut self, bytes: &[u8]) -> StoreResult<Hash> {
        self.guarded(|writer| {
            let id = checked_id(bytes)?;
            writer.append(id, &[bytes])
        })
    }

    /// Stage one object under an id the caller already proved, with its bytes
    /// in order as `parts`. It does not hash them again, so a caller outside
    /// kit-core must not reach it: in debug builds a wrong id panics.
    ///
    /// # Errors
    /// An oversized object, a full pack, or a staging write error.
    #[cfg_attr(not(test), allow(dead_code))] // The batch's pack sink is its caller.
    pub(crate) fn write_hashed(&mut self, id: Hash, parts: &[&[u8]]) -> StoreResult<Hash> {
        debug_assert_eq!(
            index::canonical_id(&parts.concat()).ok(),
            Some(id),
            "a prehashed object must carry its own id"
        );
        self.guarded(|writer| writer.append(id, parts))
    }

    /// Run one step. Any error leaves the staging file in an unknown state.
    fn guarded<T>(&mut self, step: impl FnOnce(&mut Self) -> StoreResult<T>) -> StoreResult<T> {
        if self.failed {
            return Err(failed_writer());
        }
        let result = step(self);
        self.failed |= result.is_err();
        result
    }

    fn append(&mut self, id: Hash, parts: &[&[u8]]) -> StoreResult<Hash> {
        let len = parts.iter().map(|part| part.len()).sum::<usize>();
        if len > self.limits.object {
            return Err(StoreError::ObjectTooLarge);
        }
        if !self.ids.contains(&id) {
            if self.ids.len() == self.limits.entries
                || self.payload + len as u64 > self.limits.payload
            {
                return Err(StoreError::ObjectTooLarge);
            }
            #[cfg(feature = "fault-injection")]
            crate::fault::check(crate::fault::Site::Store)?;
            write_frame(&mut self.pack, len, parts)?;
            self.payload += len as u64;
            self.ids.insert(id);
            self.frames
                .record(id, u32::try_from(len).expect("bounded object length"));
        }
        Ok(id)
    }

    /// Sync and publish the pack and index. An empty pack needs no pair.
    ///
    /// # Errors
    /// An earlier write failed, or a staging or publication failure.
    pub fn publish(self) -> StoreResult<()> {
        if self.failed {
            return Err(failed_writer());
        }
        if !self.ids.is_empty() {
            let pack = self
                .pack
                .into_inner()
                .map_err(std::io::IntoInnerError::into_error)?;
            Staged::seal(self.store, pack, self.frames)?.publish(self.store)?;
        }
        Ok(())
    }
}

fn failed_writer() -> StoreError {
    io::Error::other("an earlier write to this local pack failed").into()
}

/// Make the marker and the parents of `pack/` durable once per store, then
/// only check capability `P` under this writer's own guard.
fn prepare_dir(store: &ObjectStore, guard: &PruneGuard) -> StoreResult<()> {
    use std::sync::atomic::Ordering;

    let prepared = &store.pack_writes.pack_dir_prepared;
    if prepared.load(Ordering::Acquire) {
        return format::require_packed(guard);
    }
    format::sync_packed(&store.format_path(), guard)?;
    let dir = store.pack_dir();
    fs::create_dir_all(&dir)?;
    if !fs::symlink_metadata(&dir)?.is_dir() {
        return Err(index::invalid_at(&dir, "not a directory"));
    }
    crate::atomic::sync_dir(store.objects_root())?;
    prepared.store(true, Ordering::Release);
    Ok(())
}

fn checked_id(bytes: &[u8]) -> StoreResult<Hash> {
    if bytes.len() > MAX_RAW_OBJECT_SIZE {
        return Err(StoreError::ObjectTooLarge);
    }
    // Bytes handed to a writer are input. Rejecting them is not damage.
    index::canonical_id(bytes).map_err(|error| match error {
        StoreError::LocalPackDamaged { reason, .. } => {
            io::Error::new(io::ErrorKind::InvalidData, reason.into_string()).into()
        }
        other => other,
    })
}

fn write_frame(mut writer: impl Write, len: usize, parts: &[&[u8]]) -> StoreResult<()> {
    let mut frame = [0; ENTRY_FRAME_LEN];
    frame[1..].copy_from_slice(
        &u32::try_from(len)
            .expect("bounded object length")
            .to_le_bytes(),
    );
    writer.write_all(&frame)?;
    #[cfg(test)]
    tests::after_frame_header()?;
    for part in parts {
        writer.write_all(part)?;
    }
    Ok(())
}

#[cfg(test)]
pub(super) struct Writer<'a> {
    store: &'a ObjectStore,
    guard: PruneGuard,
    pack: tempfile::NamedTempFile,
    ids: HashSet<Hash>,
    frames: Frames,
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
            frames: Frames::new(),
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
            let frames = std::mem::replace(&mut self.frames, Frames::new());
            Staged::seal(self.store, pack, frames)?.publish(self.store)?;
            self.payload = 0;
            self.ids.clear();
        }
        write_frame(&mut self.pack, bytes.len(), &[bytes])?;
        self.payload += bytes.len() as u64;
        self.ids.insert(id);
        self.frames.record(
            id,
            u32::try_from(bytes.len()).expect("bounded object length"),
        );
        Ok(id)
    }

    pub(super) fn stage(self) -> StoreResult<(Staged, PruneGuard)> {
        Ok((
            Staged::seal(self.store, self.pack, self.frames)?,
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
    /// Seal a finished pack file whose frames are `frames`: write the count,
    /// check the file against the rows in one read pass that also digests it,
    /// append the trailer, and stage the index from the rows. The file is
    /// never scanned again, so nothing is hashed twice.
    fn seal(
        store: &ObjectStore,
        mut pack: tempfile::NamedTempFile,
        frames: Frames,
    ) -> StoreResult<Self> {
        let Frames { mut rows, end } = frames;
        pack.seek(SeekFrom::Start(HEADER_LEN as u64 - 4))?;
        pack.write_all(
            &u32::try_from(rows.len())
                .expect("bounded frame count")
                .to_le_bytes(),
        )?;
        pack.rewind()?;
        let mut digest = check_frames(pack.as_file_mut(), &rows, end)
            .map_err(|error| index::named(pack.path(), error))?;
        let trailer = *digest.finalize().as_bytes();
        pack.seek(SeekFrom::End(0))?;
        pack.write_all(&trailer)?;
        // The key continues the same hasher over the trailer, as `scan` does.
        digest.update(&trailer);
        let key = *digest.finalize().as_bytes();
        rows.sort_unstable_by_key(|(id, _)| *id);
        if rows.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(index::invalid_at(pack.path(), "duplicate id in local pack"));
        }
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
                // The staged copy's layout was checked against the writer's
                // rows and it has this exact key. Replace a damaged member
                // without making the pair disappear.
                Err(StoreError::LocalPackDamaged { .. }) => {
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
        Index::open(&pair)?;
        crate::atomic::sync_dir(&dir)?;
        store
            .packs
            .enabled
            .store(true, std::sync::atomic::Ordering::Relaxed);
        store.packs.remember_publication(&pair);
        Ok(())
    }
}

/// Read the pack once, from its header to the end of its last frame, and
/// check it against the rows the writer recorded: the magic, version and
/// count, each frame's reserved byte, offset and length, that the frames end
/// where the trailer will start, and that nothing follows. Returns the digest
/// of those bytes. The ids come from the writer, so this is the one check of
/// everything `scan` verifies except the id hash of each object.
fn check_frames(
    file: &mut fs::File,
    rows: &[(Hash, Frame)],
    end: u64,
) -> StoreResult<blake3::Hasher> {
    let mut reader = BufReader::with_capacity(256 << 10, file);
    let header = index::read_version::<HEADER_LEN>(&mut reader, *MAGIC, "local pack")?;
    if index::le_u32(&header[8..12]) as usize != rows.len() {
        return Err(index::invalid("local pack frame count disagrees with rows"));
    }
    let mut digest = blake3::Hasher::new();
    digest.update(&header);
    let mut next = HEADER_LEN as u64;
    let mut bytes = Vec::new();
    for (_, row) in rows {
        let len = index::read_frame_header(&mut reader)?;
        let frame = Frame {
            offset: next + ENTRY_FRAME_LEN as u64,
            len,
        };
        let (_, frame_end) = frame
            .extent(end)
            .ok_or_else(|| index::invalid("invalid raw frame extent"))?;
        if frame != *row {
            return Err(index::invalid("local pack frame disagrees with its row"));
        }
        bytes.resize(len as usize, 0);
        reader.read_exact(&mut bytes)?;
        digest.update(&[0]);
        digest.update(&len.to_le_bytes());
        digest.update(&bytes);
        next = frame_end;
    }
    if next != end || reader.read(&mut [0])? != 0 {
        return Err(index::invalid("local pack does not end at its last frame"));
    }
    Ok(digest)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::RepoLayout;
    use crate::object::{Blob, ChunkedBlob, EntryMode, Object, Tree, TreeEntry};
    use crate::serialize::serialize;
    use proptest::prelude::*;
    use std::cell::Cell;
    use std::path::PathBuf;

    thread_local! {
        static FAIL_AFTER_HEADER: Cell<bool> = const { Cell::new(false) };
    }

    /// Fails the frame being written after its header and before its body,
    /// as a full disk can, when this thread asked for it.
    pub(super) fn after_frame_header() -> StoreResult<()> {
        if FAIL_AFTER_HEADER.with(Cell::get) {
            return Err(io::Error::from(io::ErrorKind::StorageFull).into());
        }
        Ok(())
    }

    fn packed_store() -> (tempfile::TempDir, RepoLayout, ObjectStore) {
        let dir = tempfile::tempdir().unwrap();
        let layout = RepoLayout::single(dir.path());
        let store = ObjectStore::init(&layout).unwrap();
        store.try_activate_local_packs().unwrap();
        (dir, layout, store)
    }

    fn blob(data: &[u8]) -> Vec<u8> {
        serialize(&Object::Blob(Blob {
            data: data.to_vec(),
        }))
        .unwrap()
    }

    fn tree(entries: usize, seed: u8) -> Vec<u8> {
        let target = index::canonical_id(&blob(&[seed])).unwrap();
        serialize(&Object::Tree(Tree {
            entries: (0..entries)
                .map(|i| TreeEntry {
                    name: format!("file-{i:05}").into_bytes(),
                    mode: EntryMode::Blob,
                    object_hash: target,
                })
                .collect(),
        }))
        .unwrap()
    }

    fn manifest(chunks: usize, seed: u8) -> Vec<u8> {
        let chunk = index::canonical_id(&blob(&[seed; 64])).unwrap();
        serialize(&Object::ChunkedBlob(
            ChunkedBlob::new(
                (chunks * 16_384) as u64,
                16_384,
                (1..=chunks).map(|i| (chunk, (i * 16_384) as u64)),
            )
            .unwrap(),
        ))
        .unwrap()
    }

    /// The pack and index files of every published pair.
    fn pairs(store: &ObjectStore) -> Vec<(PathBuf, PathBuf)> {
        let mut packs: Vec<_> = fs::read_dir(store.pack_dir())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "pack"))
            .collect();
        packs.sort();
        packs
            .into_iter()
            .map(|pack| {
                let idx = pack.with_extension("idx");
                (pack, idx)
            })
            .collect()
    }

    /// What the scan of the finished pack file derives, which is what the
    /// writer derived before it recorded rows: the key and the index bytes.
    fn scanned(pack: &std::path::Path) -> (Hash, Vec<u8>) {
        let (key, rows) = index::scan(&mut fs::File::open(pack).unwrap()).unwrap();
        (key, index::encode(key, &rows))
    }

    fn object(kind: u8, size: usize, seed: u8) -> Vec<u8> {
        match kind % 4 {
            0 => blob(&vec![seed; size]),
            1 => blob(
                &(0..size)
                    .map(|i| u8::try_from(i % 251).unwrap().wrapping_mul(seed | 1))
                    .collect::<Vec<_>>(),
            ),
            2 => tree(size % 300 + 1, seed),
            _ => manifest(size % 300 + 2, seed),
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(24))]

        #[test]
        fn recorded_rows_give_the_pack_key_and_index_that_a_scan_does(
            specs in proptest::collection::vec((any::<u8>(), 0_usize..70_000, any::<u8>()), 1..14),
        ) {
            let (_dir, _layout, store) = packed_store();
            let guard = store.prune_guard().unwrap();
            let mut writer = LocalPackWriter::new(&store, &guard).unwrap();
            for (n, (kind, size, seed)) in specs.iter().enumerate() {
                let bytes = object(*kind, *size, *seed);
                let id = if n % 2 == 0 {
                    writer.write(&bytes).unwrap()
                } else {
                    let id = index::canonical_id(&bytes).unwrap();
                    let (head, tail) = bytes.split_at(bytes.len() / 2);
                    writer.write_hashed(id, &[head, tail]).unwrap()
                };
                prop_assert_eq!(id, index::canonical_id(&bytes).unwrap());
            }
            writer.publish().unwrap();
            let published = pairs(&store);
            prop_assert_eq!(published.len(), 1);
            let (pack, idx) = &published[0];
            let (key, bytes) = scanned(pack);
            prop_assert_eq!(pack.file_stem().unwrap().to_str().unwrap(), crate::hash::to_hex(&key));
            prop_assert_eq!(fs::read(idx).unwrap(), bytes);
        }
    }

    #[test]
    fn a_pack_of_chunks_small_blobs_trees_and_manifests_keeps_the_scan_bytes() {
        let (_dir, _layout, store) = packed_store();
        let guard = store.prune_guard().unwrap();
        let mut writer = LocalPackWriter::new(&store, &guard).unwrap();
        for bytes in [
            blob(&[7; 16_384]),
            blob(b"small"),
            blob(b""),
            tree(40, 1),
            manifest(40, 2),
            blob(&[7; 16_384]),
        ] {
            writer.write(&bytes).unwrap();
        }
        writer.publish().unwrap();
        let published = pairs(&store);
        assert_eq!(published.len(), 1);
        let (key, bytes) = scanned(&published[0].0);
        assert_eq!(fs::read(&published[0].1).unwrap(), bytes);
        assert_eq!(
            published[0].0.file_stem().unwrap().to_str().unwrap(),
            crate::hash::to_hex(&key)
        );
    }

    #[test]
    fn later_packs_of_a_store_skip_the_marker_and_parent_syncs() {
        let (_dir, layout, store) = packed_store();
        let guard = store.prune_guard().unwrap();
        crate::atomic::testing::reset_dir_sync_calls();
        let mut first = LocalPackWriter::new(&store, &guard).unwrap();
        first.write(&blob(b"first")).unwrap();
        first.publish().unwrap();
        // The marker's directory, the objects root, then the pack directory
        // after the pack and again after the index.
        assert_eq!(crate::atomic::testing::dir_sync_calls(), 4);

        crate::atomic::testing::reset_dir_sync_calls();
        let mut second = LocalPackWriter::new(&store, &guard).unwrap();
        second.write(&blob(b"second")).unwrap();
        second.publish().unwrap();
        assert_eq!(crate::atomic::testing::dir_sync_calls(), 2);
        assert_eq!(pairs(&store).len(), 2);
        drop(guard);

        // Every writer still reads the marker under its own guard.
        fs::write(layout.format_file(), b"bmt-v2\n").unwrap();
        let guard = store.prune_guard().unwrap();
        assert!(matches!(
            LocalPackWriter::new(&store, &guard),
            Err(StoreError::IncompatibleRepoFormat { .. })
        ));
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "a prehashed object must carry its own id")]
    fn a_wrong_prehashed_id_panics_in_debug_builds() {
        let (_dir, _layout, store) = packed_store();
        let guard = store.prune_guard().unwrap();
        let mut writer = LocalPackWriter::new(&store, &guard).unwrap();
        let wrong = index::canonical_id(&blob(b"other")).unwrap();
        let _ = writer.write_hashed(wrong, &[&blob(b"this")]);
    }

    #[test]
    fn a_failed_frame_poisons_the_writer_and_publishes_nothing() {
        let (_dir, _layout, store) = packed_store();
        let guard = store.prune_guard().unwrap();
        let mut writer = LocalPackWriter::new(&store, &guard).unwrap();
        writer.write(&blob(b"kept")).unwrap();
        FAIL_AFTER_HEADER.with(|fail| fail.set(true));
        let failed = writer.write(&blob(b"torn"));
        FAIL_AFTER_HEADER.with(|fail| fail.set(false));
        assert!(matches!(failed, Err(StoreError::Io(_))));

        // Nothing more is accepted, not even an object that fits.
        assert!(writer.write(&blob(b"after")).is_err());
        assert!(writer.publish().is_err());
        assert!(pairs(&store).is_empty());
        let leftovers = fs::read_dir(store.pack_dir()).unwrap().count();
        assert_eq!(leftovers, 0, "the staging file is gone");
    }

    #[test]
    fn any_rejected_write_poisons_the_writer() {
        let (_dir, _layout, store) = packed_store();
        let guard = store.prune_guard().unwrap();
        let mut writer = LocalPackWriter::new(&store, &guard).unwrap();
        assert!(writer.write(b"not an object").is_err());
        assert!(writer.write(&blob(b"fine")).is_err());
        assert!(writer.publish().is_err());
        assert!(pairs(&store).is_empty());
    }

    fn small_writer<'a>(
        store: &'a ObjectStore,
        guard: &'a PruneGuard,
        limits: Limits,
    ) -> LocalPackWriter<'a> {
        let mut writer = LocalPackWriter::new(store, guard).unwrap();
        writer.limits = limits;
        writer
    }

    #[test]
    fn a_pack_takes_objects_up_to_its_limits_and_no_more() {
        let (_dir, _layout, store) = packed_store();
        let guard = store.prune_guard().unwrap();
        let (a, b, c) = (blob(&[1; 40]), blob(&[2; 40]), blob(&[3; 40]));
        let object = a.len();
        let limits = Limits {
            object,
            entries: 2,
            payload: 2 * object as u64,
        };

        // Exactly at every limit is accepted, and a duplicate costs nothing.
        let mut writer = small_writer(&store, &guard, limits);
        writer.write(&a).unwrap();
        writer.write(&b).unwrap();
        writer.write(&a).unwrap();
        writer.publish().unwrap();
        assert_eq!(pairs(&store).len(), 1);

        // A third distinct object passes neither the entry nor payload limit.
        for limits in [
            Limits {
                payload: u64::MAX / 2,
                ..limits
            },
            Limits {
                entries: 9,
                ..limits
            },
        ] {
            let mut writer = small_writer(&store, &guard, limits);
            writer.write(&a).unwrap();
            writer.write(&b).unwrap();
            assert!(matches!(writer.write(&c), Err(StoreError::ObjectTooLarge)));
            assert!(writer.publish().is_err());
        }

        // One byte over the payload limit with entries to spare.
        let mut writer = small_writer(
            &store,
            &guard,
            Limits {
                payload: 2 * object as u64 - 1,
                ..limits
            },
        );
        writer.write(&a).unwrap();
        assert!(matches!(writer.write(&b), Err(StoreError::ObjectTooLarge)));

        // One byte over the object limit, through the prehashed entry.
        let mut writer = small_writer(&store, &guard, Limits { object: object - 1, ..limits });
        let id = index::canonical_id(&a).unwrap();
        assert!(matches!(
            writer.write_hashed(id, &[&a]),
            Err(StoreError::ObjectTooLarge)
        ));
        let mut writer = small_writer(&store, &guard, limits);
        let id = index::canonical_id(&a).unwrap();
        writer.write_hashed(id, &[&a]).unwrap();
    }

    #[test]
    fn a_pack_damaged_between_its_last_write_and_the_seal_fails_the_seal() {
        for corrupt in [Corruption::FrameLength, Corruption::Trailing] {
            let (_dir, _layout, store) = packed_store();
            let guard = store.prune_guard().unwrap();
            let mut writer = LocalPackWriter::new(&store, &guard).unwrap();
            writer.write(&blob(&[1; 500])).unwrap();
            writer.write(&blob(&[2; 600])).unwrap();
            writer.pack.flush().unwrap();
            let path = writer.pack.get_ref().path().to_path_buf();
            let mut file = fs::OpenOptions::new().write(true).open(&path).unwrap();
            match corrupt {
                // The first frame's length, after its reserved byte.
                Corruption::FrameLength => {
                    file.seek(SeekFrom::Start(HEADER_LEN as u64 + 1)).unwrap();
                    file.write_all(&501_u32.to_le_bytes()).unwrap();
                }
                Corruption::Trailing => {
                    file.seek(SeekFrom::End(0)).unwrap();
                    file.write_all(b"x").unwrap();
                }
            }
            assert!(matches!(
                writer.publish(),
                Err(StoreError::LocalPackDamaged { .. })
            ));
            assert!(pairs(&store).is_empty());
            assert_eq!(fs::read_dir(store.pack_dir()).unwrap().count(), 0);
        }
    }

    enum Corruption {
        FrameLength,
        Trailing,
    }

    #[test]
    fn publishing_to_a_missing_directory_is_not_a_collision() {
        let dir = tempfile::tempdir().unwrap();
        let staged = tempfile::NamedTempFile::new_in(dir.path()).unwrap();
        let target = dir.path().join("missing").join("pack");
        assert!(matches!(
            persist_unique(staged, &target),
            Err(StoreError::Io(error)) if error.kind() == io::ErrorKind::NotFound
        ));
    }
}
