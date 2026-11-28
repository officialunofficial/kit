//! Private canonical object bytes retained while a fetch accepts a wire pack.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use tempfile::TempPath;

use crate::hash::{Hash, to_hex};
use crate::object::{ObjectType, verified_id_and_object};
use crate::store::{MAX_RAW_OBJECT_SIZE, StoreError, StoreResult};

use super::{PackError, UnpackSink, read_spooled};

/// Where a spool writes the objects that end as loose files: straight into a
/// temporary file in the object's shard directory, once, instead of into the
/// spool's own file. The caller names the size above which an object is loose.
/// The batch that commits the file renames it into place, so the bytes are
/// neither copied nor read again.
#[derive(Debug, Clone)]
pub struct LooseStaging {
    objects_root: PathBuf,
    over: usize,
}

impl LooseStaging {
    /// Stage every object of more than `over` bytes under `objects_root`.
    #[must_use]
    pub fn new(objects_root: &Path, over: usize) -> Self {
        Self {
            objects_root: objects_root.to_owned(),
            over,
        }
    }

    fn write(&self, id: &Hash, bytes: &[u8]) -> StoreResult<TempPath> {
        let shard = self.objects_root.join(&to_hex(id)[..2]);
        fs::create_dir_all(&shard)?;
        let mut file = crate::durable::temp_file_in(&shard)?;
        #[cfg(feature = "fault-injection")]
        crate::fault::check(crate::fault::Site::Store)?;
        file.as_file_mut().write_all(bytes)?;
        Ok(file.into_temp_path())
    }
}

/// An unnamed append-only file and its in-memory locator. Every read verifies
/// the object id; offsets and lengths come from the decoder, never the file.
///
/// An object above the spool's [`LooseStaging`] limit is not in the file. It
/// is a named temporary file of its own, which a window takes over from the
/// spool that decoded it ([`ObjectSpool::adopt`]) and a batch finally renames
/// into place ([`ObjectSpool::take_loose`]).
#[derive(Debug)]
pub struct ObjectSpool {
    inner: Mutex<Spool>,
    staging: Option<LooseStaging>,
}

#[derive(Debug, Clone, Copy)]
struct Frame {
    position: usize,
    /// In `Spool::loose` rather than in a file of the spool's.
    loose: bool,
    /// The file `offset` is in: 0 is the spool's own, `n` is `Spool::donors[n - 1]`.
    file: u32,
    offset: u64,
    len: u32,
    /// The object's first bytes, kept when it was staged, so
    /// [`ObjectSpool::head`] answers without a read.
    head: Head,
}

/// Up to the first ten bytes of a staged object: its type tag, prologue and,
/// for a blob, its payload length. Empty when the frame was taken from a
/// spool that did not keep them.
#[derive(Debug, Clone, Copy, Default)]
struct Head {
    bytes: [u8; 10],
    len: u8,
}

impl Head {
    fn of(bytes: &[u8]) -> Self {
        let mut head = Self::default();
        let len = bytes.len().min(head.bytes.len());
        head.bytes[..len].copy_from_slice(&bytes[..len]);
        head.len = u8::try_from(len).expect("ten bytes at most");
        head
    }

    fn get(&self) -> Option<&[u8]> {
        (self.len != 0).then(|| &self.bytes[..usize::from(self.len)])
    }
}

/// The spool's own file, which donated frames keep reading after the spool is gone.
#[derive(Debug)]
struct Shared(Arc<File>);

impl Write for Shared {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        (&*self.0).write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Debug)]
struct Spool {
    writer: BufWriter<Shared>,
    /// The files of the spools whose frames this one absorbed.
    donors: Vec<Arc<File>>,
    end: u64,
    by_id: HashMap<Hash, Frame>,
    order: Vec<(usize, Hash, u32, ObjectType)>,
    /// The temporary file of each loose object this spool holds.
    loose: HashMap<Hash, TempPath>,
}

impl ObjectSpool {
    /// Create an unnamed object spool in the repository's spool directory.
    ///
    /// # Errors
    /// The directory or file cannot be created.
    pub fn new(dir: &Path) -> io::Result<Self> {
        Self::create(dir, None)
    }

    /// [`Self::new`] for a spool that writes the objects `staging` names as
    /// loose temporary files.
    ///
    /// # Errors
    /// The directory or file cannot be created.
    pub fn with_loose_staging(dir: &Path, staging: LooseStaging) -> io::Result<Self> {
        Self::create(dir, Some(staging))
    }

    fn create(dir: &Path, staging: Option<LooseStaging>) -> io::Result<Self> {
        Ok(Self {
            inner: Mutex::new(Spool {
                writer: BufWriter::with_capacity(
                    256 << 10,
                    Shared(Arc::new(tempfile::tempfile_in(dir)?)),
                ),
                donors: Vec::new(),
                end: 0,
                by_id: HashMap::new(),
                order: Vec::new(),
                loose: HashMap::new(),
            }),
            staging,
        })
    }

    /// Append bytes with their already derived id and decode position.
    ///
    /// # Errors
    /// An oversized object or a local write error.
    ///
    /// # Panics
    /// If a previous spool operation panicked while holding its lock.
    pub fn append(
        &self,
        position: usize,
        id: Hash,
        ty: ObjectType,
        bytes: &[u8],
    ) -> StoreResult<()> {
        if bytes.len() > MAX_RAW_OBJECT_SIZE {
            return Err(StoreError::ObjectTooLarge);
        }
        let len = u32::try_from(bytes.len()).expect("bounded object length");
        if let Some(staging) = self.staging.as_ref().filter(|s| bytes.len() > s.over) {
            return self.append_loose(staging, position, id, ty, bytes);
        }
        let mut spool = self.inner.lock().expect("object spool mutex");
        if spool
            .by_id
            .get(&id)
            .is_none_or(|frame| frame.position > position)
        {
            let frame = Frame {
                position,
                loose: false,
                file: 0,
                offset: spool.end,
                len,
                head: Head::of(bytes),
            };
            spool.writer.write_all(bytes)?;
            spool.end += u64::from(len);
            spool.by_id.insert(id, frame);
        }
        spool.order.push((position, id, len, ty));
        Ok(())
    }

    /// [`Self::append`] for a loose object. One id is one file, so a repeat
    /// only lowers the position the id is known at. The file is written
    /// outside the lock.
    fn append_loose(
        &self,
        staging: &LooseStaging,
        position: usize,
        id: Hash,
        ty: ObjectType,
        bytes: &[u8],
    ) -> StoreResult<()> {
        let len = u32::try_from(bytes.len()).expect("bounded object length");
        let known = |spool: &mut Spool| {
            spool.by_id.get_mut(&id).is_some_and(|frame| {
                frame.position = frame.position.min(position);
                true
            })
        };
        let seen = known(&mut self.inner.lock().expect("object spool mutex"));
        let written = if seen {
            None
        } else {
            Some(staging.write(&id, bytes)?)
        };
        let mut spool = self.inner.lock().expect("object spool mutex");
        // A concurrent worker may have staged the same id meanwhile; its
        // file stays and this one is unlinked when `written` drops.
        if let Some(file) = written.filter(|_| !known(&mut spool)) {
            spool.by_id.insert(
                id,
                Frame {
                    position,
                    loose: true,
                    file: 0,
                    offset: 0,
                    len,
                    head: Head::of(bytes),
                },
            );
            spool.loose.insert(id, file);
        }
        spool.order.push((position, id, len, ty));
        Ok(())
    }

    /// Take over the loose objects `entries` names, each
    /// `(position, id, length, type)` as [`Self::take_order`] of `from`
    /// returned it. Their files move to this spool, which reads and finally
    /// renames them, so `from` no longer holds them. An object `from` already
    /// handed over, here or to an earlier window, is skipped. The entries join
    /// this spool's own, under the same rules as [`Self::append`].
    ///
    /// # Errors
    /// An entry that is not a loose object of `from`.
    ///
    /// # Panics
    /// If `from` is this spool, or a previous spool operation panicked while
    /// holding its lock.
    pub fn adopt(
        &self,
        from: &Self,
        entries: &[(usize, Hash, u32, ObjectType)],
    ) -> StoreResult<()> {
        assert!(!std::ptr::eq(self, from), "a spool cannot adopt itself");
        let moved = {
            let mut other = from.inner.lock().expect("object spool mutex");
            let mut moved = Vec::new();
            for &(position, id, len, ty) in entries {
                let Some(head) = other
                    .by_id
                    .get(&id)
                    .filter(|frame| frame.loose && frame.len == len)
                    .map(|frame| frame.head)
                else {
                    return Err(StoreError::ObjectNotFound(to_hex(&id)));
                };
                if let Some(file) = other.loose.remove(&id) {
                    moved.push(((position, id, len, ty), file, head));
                }
            }
            moved
        };
        let mut spool = self.inner.lock().expect("object spool mutex");
        for ((position, id, len, ty), file, head) in moved {
            if spool
                .by_id
                .get(&id)
                .is_none_or(|frame| frame.position > position)
            {
                spool.by_id.insert(
                    id,
                    Frame {
                        position,
                        loose: true,
                        file: 0,
                        offset: 0,
                        len,
                        head,
                    },
                );
                spool.loose.insert(id, file);
            }
            spool.order.push((position, id, len, ty));
        }
        Ok(())
    }

    /// Take over the staged objects `entries` names, each
    /// `(position, id, length, type)` as [`Self::take_order`] of `from`
    /// returned it, without copying them: this spool reads them from the file
    /// of `from`, which stays on disk for as long as this spool holds a frame
    /// of it. Only an object `from` holds in a file, not one it holds as a
    /// loose file ([`Self::adopt`]), can be absorbed. The entries join this
    /// spool's own, under the same rules as [`Self::append`]. A read of an
    /// absorbed object checks its bytes against the id, but
    /// [`Self::write_to_pack`] does not: `from` derived each id from the bytes.
    ///
    /// Each absorbed spool keeps one file open for as long as this one lives,
    /// so a caller that absorbs many spools should copy the small ones with
    /// [`Self::append_from`].
    ///
    /// # Errors
    /// An entry that is not a staged object of `from`, or a local write error.
    ///
    /// # Panics
    /// If `from` is this spool, or a previous spool operation panicked while
    /// holding its lock.
    pub fn absorb(
        &self,
        from: &Self,
        entries: &[(usize, Hash, u32, ObjectType)],
    ) -> StoreResult<()> {
        assert!(!std::ptr::eq(self, from), "a spool cannot absorb itself");
        let (files, moved) = {
            let mut other = from.inner.lock().expect("object spool mutex");
            other.writer.flush()?;
            let mut files = vec![Arc::clone(&other.writer.get_ref().0)];
            files.extend(other.donors.iter().cloned());
            let mut moved = Vec::with_capacity(entries.len());
            for &(position, id, len, ty) in entries {
                let frame = other
                    .by_id
                    .get(&id)
                    .copied()
                    .filter(|frame| !frame.loose && frame.len == len)
                    .ok_or_else(|| StoreError::ObjectNotFound(to_hex(&id)))?;
                moved.push((
                    (position, id, len, ty),
                    frame.file as usize,
                    frame.offset,
                    frame.head,
                ));
            }
            (files, moved)
        };
        let mut spool = self.inner.lock().expect("object spool mutex");
        // Where each of the donor's files that an entry reads sits among this
        // spool's donors.
        let mut used = vec![false; files.len()];
        for &(_, donor_file, _, _) in &moved {
            used[donor_file] = true;
        }
        let slots: Vec<u32> = files
            .iter()
            .zip(used)
            .map(|(file, used)| {
                if !used {
                    return 0;
                }
                let at = spool
                    .donors
                    .iter()
                    .position(|have| Arc::ptr_eq(have, file))
                    .unwrap_or_else(|| {
                        spool.donors.push(Arc::clone(file));
                        spool.donors.len() - 1
                    });
                u32::try_from(at + 1).expect("bounded donor files")
            })
            .collect();
        for ((position, id, len, ty), donor_file, offset, head) in moved {
            let file = slots[donor_file];
            if spool
                .by_id
                .get(&id)
                .is_none_or(|frame| frame.position > position)
            {
                spool.by_id.insert(
                    id,
                    Frame {
                        position,
                        loose: false,
                        file,
                        offset,
                        len,
                        head,
                    },
                );
            }
            spool.order.push((position, id, len, ty));
        }
        Ok(())
    }

    /// Take the temporary file of a loose object, for the batch that renames
    /// it into place. The object is no longer readable here.
    ///
    /// # Panics
    /// If a previous spool operation panicked while holding its lock.
    pub fn take_loose(&self, id: &Hash) -> Option<TempPath> {
        self.inner
            .lock()
            .expect("object spool mutex")
            .loose
            .remove(id)
    }

    /// Bytes this spool wrote to its own file. Loose objects are not counted.
    ///
    /// # Panics
    /// If a previous spool operation panicked while holding its lock.
    #[must_use]
    pub fn written_bytes(&self) -> u64 {
        self.inner.lock().expect("object spool mutex").end
    }

    /// Take the list of staged ids and lengths in wire order.
    ///
    /// # Panics
    /// If a previous spool operation panicked while holding its lock.
    pub fn take_order(&self) -> Vec<(usize, Hash, u32, ObjectType)> {
        let mut spool = self.inner.lock().expect("object spool mutex");
        let mut order = std::mem::take(&mut spool.order);
        order.sort_unstable_by_key(|entry| entry.0);
        order
    }

    /// Whether the decoder staged this id.
    ///
    /// # Panics
    /// If a previous spool operation panicked while holding its lock.
    #[must_use]
    pub fn contains(&self, id: &Hash) -> bool {
        self.inner
            .lock()
            .expect("object spool mutex")
            .by_id
            .contains_key(id)
    }

    /// Read and verify a staged copy, if present.
    ///
    /// # Errors
    /// A local read or integrity error.
    pub fn read(&self, id: &Hash) -> StoreResult<Option<Vec<u8>>> {
        self.read_before(id, usize::MAX, |_| Ok(()))
    }

    /// The type and, for a blob, the payload length of a staged object, from
    /// its ten-byte head alone, as [`crate::store::ObjectStore::object_head`]
    /// reads a stored one. The head was kept when the object was staged, so
    /// nothing is read. The rest of the object is neither read nor hashed.
    ///
    /// # Errors
    /// A local read error, or a head that is not an object's.
    ///
    /// # Panics
    /// If a previous spool operation panicked while holding its lock.
    pub fn head(&self, id: &Hash) -> StoreResult<Option<(ObjectType, Option<u64>)>> {
        let spool = self.inner.lock().expect("object spool mutex");
        let Some(frame) = spool.by_id.get(id).copied() else {
            return Ok(None);
        };
        if let Some(kept) = frame.head.get() {
            return Ok(Some(crate::store::head_at(&mut &kept[..])?));
        }
        let mut head = [0; 10];
        let len = head.len().min(frame.len as usize);
        Self::read_frame(spool, id, frame, &mut head[..len])?;
        Ok(Some(crate::store::head_at(&mut &head[..len])?))
    }

    /// Copy a staged object of `from` into this spool, as [`Self::append`]
    /// would, without reading it through a hash check. `from` derived the id
    /// from these bytes when it staged them. `scratch` holds the bytes between
    /// the read and the write, and is reused across calls.
    ///
    /// # Errors
    /// `from` does not hold `id`, or a local read or write error.
    pub fn append_from(
        &self,
        from: &Self,
        position: usize,
        id: Hash,
        ty: ObjectType,
        scratch: &mut Vec<u8>,
    ) -> StoreResult<()> {
        from.read_staged(&id, scratch)?;
        self.append(position, id, ty, scratch)
    }

    /// The number of files of other spools this one reads from.
    ///
    /// # Panics
    /// If a previous spool operation panicked while holding its lock.
    #[must_use]
    pub fn donor_files(&self) -> usize {
        self.inner.lock().expect("object spool mutex").donors.len()
    }

    /// Stage a staged object of this spool in `pack`, under the id the
    /// decoder derived from its bytes, without hashing it again. The id is the
    /// one the caller of [`Self::append`] gave, so that caller must have
    /// derived it from the bytes. A frame
    /// already written for the id is not written twice. `scratch` holds the
    /// bytes between the read and the write, and is reused across calls.
    ///
    /// # Errors
    /// The spool does not hold `id`, a local read error, or the pack's write
    /// error.
    pub fn write_to_pack(
        &self,
        id: &Hash,
        pack: &mut crate::store::LocalPackWriter<'_>,
        scratch: &mut Vec<u8>,
    ) -> StoreResult<()> {
        self.read_staged(id, scratch)?;
        pack.write_hashed(*id, &[scratch])?;
        Ok(())
    }

    /// Read the bytes staged under `id` into `buf`, without checking them
    /// against it: the decoder derived `id` from them.
    fn read_staged(&self, id: &Hash, buf: &mut Vec<u8>) -> StoreResult<()> {
        let spool = self.inner.lock().expect("object spool mutex");
        let frame = spool
            .by_id
            .get(id)
            .copied()
            .ok_or_else(|| StoreError::ObjectNotFound(to_hex(id)))?;
        let len = frame.len as usize;
        buf.clear();
        buf.try_reserve_exact(len)
            .map_err(|_| StoreError::ObjectTooLarge)?;
        buf.resize(len, 0);
        Self::read_frame(spool, id, frame, buf)?;
        Ok(())
    }

    pub(super) fn read_before<E: From<StoreError>>(
        &self,
        id: &Hash,
        before: usize,
        admit: impl FnOnce(usize) -> Result<(), E>,
    ) -> Result<Option<Vec<u8>>, E> {
        let spool = self.inner.lock().expect("object spool mutex");
        let Some(frame) = spool
            .by_id
            .get(id)
            .copied()
            .filter(|frame| frame.position < before)
        else {
            return Ok(None);
        };
        let len = frame.len as usize;
        admit(len)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(len)
            .map_err(|_| StoreError::ObjectTooLarge)?;
        bytes.resize(len, 0);
        Self::read_frame(spool, id, frame, &mut bytes).map_err(StoreError::from)?;
        let actual = verified_id_and_object(&bytes).0;
        if actual != *id {
            return Err(StoreError::HashMismatch {
                expected: to_hex(id),
                actual: to_hex(&actual),
                pack: None,
            }
            .into());
        }
        Ok(Some(bytes))
    }

    /// Fill `buf` from the start of `frame`'s bytes. Takes the lock guard, so
    /// a loose file is opened and read without the lock.
    fn read_frame(
        mut spool: std::sync::MutexGuard<'_, Spool>,
        id: &Hash,
        frame: Frame,
        buf: &mut [u8],
    ) -> io::Result<()> {
        if frame.loose {
            let path = spool
                .loose
                .get(id)
                .map(|file| file.to_path_buf())
                .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
            drop(spool);
            return read_spooled(&File::open(path)?, 0, buf);
        }
        let file = match frame.file {
            0 => {
                spool.writer.flush()?;
                return read_spooled(&spool.writer.get_ref().0, frame.offset, buf);
            }
            n => Arc::clone(&spool.donors[n as usize - 1]),
        };
        drop(spool);
        read_spooled(&file, frame.offset, buf)
    }
}

impl UnpackSink for ObjectSpool {
    fn stage(
        &self,
        position: usize,
        id: Hash,
        ty: ObjectType,
        bytes: &[u8],
    ) -> Result<(), PackError> {
        Ok(self.append(position, id, ty, bytes)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::{Blob, Object};
    use crate::serialize::serialize;

    fn blob(data: &[u8]) -> (Hash, Vec<u8>) {
        let object = Object::Blob(Blob {
            data: data.to_vec(),
        });
        (object.id().unwrap(), serialize(&object).unwrap())
    }

    #[test]
    fn the_spool_accepts_the_size_limit_and_rejects_one_byte_more() {
        let dir = tempfile::tempdir().unwrap();
        let spool = ObjectSpool::new(dir.path()).unwrap();
        let (id, bytes) = blob(b"existing frame");
        spool.append(0, id, ObjectType::Blob, &bytes).unwrap();

        // Keep the first frame for this id so neither body needs a disk write.
        let padded = vec![0u8; MAX_RAW_OBJECT_SIZE + 1];
        spool
            .append(1, id, ObjectType::Blob, &padded[..MAX_RAW_OBJECT_SIZE])
            .unwrap();
        assert!(matches!(
            spool.append(2, id, ObjectType::Blob, &padded),
            Err(StoreError::ObjectTooLarge)
        ));
        assert_eq!(spool.read(&id).unwrap(), Some(bytes));
    }

    #[test]
    fn duplicate_ids_keep_the_earliest_decode_position() {
        let dir = tempfile::tempdir().unwrap();
        let spool = ObjectSpool::new(dir.path()).unwrap();
        let (id, bytes) = blob(b"repeated base");

        spool.append(4, id, ObjectType::Blob, &bytes).unwrap();
        spool.append(2, id, ObjectType::Blob, &bytes).unwrap();
        spool.append(3, id, ObjectType::Blob, &bytes).unwrap();
        assert_eq!(
            spool.read_before::<StoreError>(&id, 3, |_| Ok(())).unwrap(),
            Some(bytes.clone())
        );

        spool.append(2, id, ObjectType::Blob, &bytes).unwrap();
        let state = spool.inner.lock().unwrap();
        assert_eq!(state.by_id[&id].position, 2);
        assert_eq!(state.by_id[&id].offset, bytes.len() as u64);
        assert_eq!(state.end, 2 * bytes.len() as u64);
    }

    #[test]
    fn earlier_windows_cannot_resolve_later_bases_and_reads_check_the_id() {
        let dir = tempfile::tempdir().unwrap();
        let spool = ObjectSpool::new(dir.path()).unwrap();
        let (a, bytes_a) = blob(b"alpha");
        let (b, bytes_b) = blob(b"beta");
        let (c, _) = blob(b"corrupted read");
        assert!(!spool.contains(&a));
        assert_eq!(spool.read(&a).unwrap(), None);
        spool.append(2, b, ObjectType::Blob, &bytes_b).unwrap();
        spool.append(0, a, ObjectType::Blob, &bytes_a).unwrap();
        spool.append(1, c, ObjectType::Blob, &bytes_b).unwrap();
        assert!(spool.contains(&a));
        assert_eq!(
            spool
                .read_before::<StoreError>(&b, 2, |_| panic!("future base"))
                .unwrap(),
            None
        );
        assert_eq!(
            spool
                .read_before::<StoreError>(&b, 3, |size| {
                    assert_eq!(size, bytes_b.len());
                    Ok(())
                })
                .unwrap(),
            Some(bytes_b),
        );
        assert_eq!(spool.read(&a).unwrap(), Some(bytes_a));
        assert!(matches!(
            spool.read(&c),
            Err(StoreError::HashMismatch { .. })
        ));
        let ids: Vec<_> = spool
            .take_order()
            .into_iter()
            .map(|(_, id, _, _)| id)
            .collect();
        assert_eq!(ids, [a, c, b]);
        assert!(spool.take_order().is_empty());
    }

    /// A spool that stages every object of more than 100 bytes as a loose
    /// file under `dir/objects`.
    fn loose_spool(dir: &Path) -> ObjectSpool {
        ObjectSpool::with_loose_staging(dir, LooseStaging::new(&dir.join("objects"), 100)).unwrap()
    }

    /// The temporary files under `dir/objects`: every file there while no
    /// object has been renamed into place.
    fn staged_files(dir: &Path) -> Vec<PathBuf> {
        let mut files = Vec::new();
        for shard in fs::read_dir(dir.join("objects")).into_iter().flatten() {
            for file in fs::read_dir(shard.unwrap().path()).unwrap() {
                files.push(file.unwrap().path());
            }
        }
        files.sort();
        files
    }

    #[test]
    fn a_loose_object_is_written_once_to_its_own_file_and_not_to_the_spool() {
        let dir = tempfile::tempdir().unwrap();
        let spool = loose_spool(dir.path());
        let (small, small_bytes) = blob(b"packed");
        let (big, big_bytes) = blob(&[7; 300]);
        spool
            .append(0, small, ObjectType::Blob, &small_bytes)
            .unwrap();
        spool.append(1, big, ObjectType::Blob, &big_bytes).unwrap();

        assert_eq!(spool.written_bytes(), small_bytes.len() as u64);
        let files = staged_files(dir.path());
        assert_eq!(files.len(), 1);
        assert_eq!(fs::read(&files[0]).unwrap(), big_bytes);
        assert_eq!(
            files[0].parent().unwrap().file_name().unwrap().to_str(),
            Some(&to_hex(&big)[..2]),
            "in the shard directory of its id"
        );
        assert_eq!(spool.read(&big).unwrap(), Some(big_bytes.clone()));
        assert_eq!(
            spool.head(&big).unwrap(),
            Some((ObjectType::Blob, Some(300)))
        );
        assert_eq!(spool.read(&small).unwrap(), Some(small_bytes));

        // The limit itself is not over it: such an object stays in the file.
        let at_limit = blob(&[5; 100 - crate::serialize::BLOB_PROLOGUE_LEN]);
        let past_limit = blob(&[6; 101 - crate::serialize::BLOB_PROLOGUE_LEN]);
        assert_eq!((at_limit.1.len(), past_limit.1.len()), (100, 101));
        let before = spool.written_bytes();
        spool
            .append(2, at_limit.0, ObjectType::Blob, &at_limit.1)
            .unwrap();
        spool
            .append(3, past_limit.0, ObjectType::Blob, &past_limit.1)
            .unwrap();
        assert_eq!(spool.written_bytes(), before + 100);
        assert_eq!(staged_files(dir.path()).len(), 2);

        // A repeat is one file, and only an earlier position moves its frame.
        spool.append(5, big, ObjectType::Blob, &big_bytes).unwrap();
        spool.append(0, big, ObjectType::Blob, &big_bytes).unwrap();
        assert_eq!(staged_files(dir.path()).len(), 2);
        assert_eq!(
            spool
                .read_before::<StoreError>(&big, 1, |_| Ok(()))
                .unwrap(),
            Some(big_bytes)
        );

        // The file belongs to the spool: dropping it unlinks the file.
        drop(spool);
        assert_eq!(staged_files(dir.path()), Vec::<PathBuf>::new());
    }

    #[test]
    fn a_corrupt_loose_file_is_refused_on_read_and_not_on_head() {
        let dir = tempfile::tempdir().unwrap();
        let spool = loose_spool(dir.path());
        let (id, bytes) = blob(&[3; 300]);
        spool.append(0, id, ObjectType::Blob, &bytes).unwrap();
        let file = staged_files(dir.path()).remove(0);
        let mut damaged = bytes.clone();
        damaged[200] ^= 1;
        fs::write(file, damaged).unwrap();

        assert!(matches!(
            spool.read(&id),
            Err(StoreError::HashMismatch { .. })
        ));
        // A head read does not read the rest, as for a packed object.
        assert_eq!(
            spool.head(&id).unwrap(),
            Some((ObjectType::Blob, Some(300)))
        );
    }

    #[test]
    fn an_adopted_loose_file_moves_to_the_window_and_is_read_after_the_donor_is_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let window = ObjectSpool::new(dir.path()).unwrap();
        let (own, own_bytes) = blob(b"copied");
        window.append(5, own, ObjectType::Blob, &own_bytes).unwrap();
        let (big, big_bytes) = blob(&[7; 300]);
        let (twice, twice_bytes) = blob(&[9; 301]);

        let donor = loose_spool(dir.path());
        donor.append(0, big, ObjectType::Blob, &big_bytes).unwrap();
        donor
            .append(1, twice, ObjectType::Blob, &twice_bytes)
            .unwrap();
        donor
            .append(2, twice, ObjectType::Blob, &twice_bytes)
            .unwrap();
        let order = donor.take_order();
        assert_eq!(order.len(), 3);
        window.adopt(&donor, &order[..]).unwrap();
        drop(donor);

        // The files outlive the donor, and the window did not copy them.
        assert_eq!(staged_files(dir.path()).len(), 2);
        assert_eq!(window.written_bytes(), own_bytes.len() as u64);
        assert!(window.contains(&big));
        assert_eq!(window.read(&big).unwrap(), Some(big_bytes.clone()));
        assert_eq!(window.read(&twice).unwrap(), Some(twice_bytes));
        assert_eq!(window.read(&own).unwrap(), Some(own_bytes));
        let ids: Vec<_> = window
            .take_order()
            .into_iter()
            .map(|(position, id, _, _)| (position, id))
            .collect();
        // The repeat of `twice` is one object and one entry.
        assert_eq!(ids, [(0, big), (1, twice), (5, own)]);

        // Whoever takes a file out of the window owns it.
        let taken = window.take_loose(&big).unwrap();
        assert_eq!(fs::read(&taken).unwrap(), big_bytes);
        assert!(window.take_loose(&big).is_none());
        drop(taken);
        assert_eq!(staged_files(dir.path()).len(), 1);
        drop(window);
        assert_eq!(staged_files(dir.path()), Vec::<PathBuf>::new());
    }

    #[test]
    fn an_object_adopted_before_is_skipped_by_the_next_adoption() {
        let dir = tempfile::tempdir().unwrap();
        let (big, bytes) = blob(&[1; 300]);
        let donor = loose_spool(dir.path());
        donor.append(0, big, ObjectType::Blob, &bytes).unwrap();
        let order = donor.take_order();
        let first = ObjectSpool::new(dir.path()).unwrap();
        first.adopt(&donor, &order).unwrap();
        drop(first);

        // A later window sees the id again, from the same wire pack, after
        // the first window sealed: the object is already published.
        let second = ObjectSpool::new(dir.path()).unwrap();
        second.adopt(&donor, &order).unwrap();
        assert!(!second.contains(&big));
        assert!(second.take_order().is_empty());
    }

    #[test]
    fn adopting_what_is_not_a_loose_object_of_the_donor_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let window = ObjectSpool::new(dir.path()).unwrap();
        let donor = loose_spool(dir.path());
        let (id, bytes) = blob(&[2; 300]);
        let len = u32::try_from(bytes.len()).unwrap();
        let entry = (0, id, len, ObjectType::Blob);
        assert!(matches!(
            window.adopt(&donor, &[entry]),
            Err(StoreError::ObjectNotFound(_))
        ));
        donor.append(0, id, ObjectType::Blob, &bytes).unwrap();
        let wrong_len = (0, id, len + 1, ObjectType::Blob);
        assert!(matches!(
            window.adopt(&donor, &[wrong_len]),
            Err(StoreError::ObjectNotFound(_))
        ));
        // An object in the donor's own file is not adoptable.
        let (small, small_bytes) = blob(b"small");
        donor
            .append(1, small, ObjectType::Blob, &small_bytes)
            .unwrap();
        let own = (
            1,
            small,
            u32::try_from(small_bytes.len()).unwrap(),
            ObjectType::Blob,
        );
        assert!(matches!(
            window.adopt(&donor, &[own]),
            Err(StoreError::ObjectNotFound(_))
        ));
        assert!(!window.contains(&id) && !window.contains(&small));
    }

    #[test]
    fn the_head_of_a_staged_object_comes_from_its_first_ten_bytes() {
        use crate::object::Tree;
        let dir = tempfile::tempdir().unwrap();
        let window = ObjectSpool::new(dir.path()).unwrap();
        let (blob_id, blob_bytes) = blob(&vec![3; 70_000]);
        let tree = Object::Tree(Tree {
            entries: Vec::new(),
        });
        let (tree_id, tree_bytes) = (tree.id().unwrap(), serialize(&tree).unwrap());

        let donor = loose_spool(dir.path());
        donor
            .append(0, blob_id, ObjectType::Blob, &blob_bytes)
            .unwrap();
        window
            .append(1, tree_id, ObjectType::Tree, &tree_bytes)
            .unwrap();
        window.adopt(&donor, &donor.take_order()).unwrap();
        drop(donor);

        assert_eq!(
            window.head(&blob_id).unwrap(),
            Some((ObjectType::Blob, Some(70_000)))
        );
        assert_eq!(
            window.head(&tree_id).unwrap(),
            Some((ObjectType::Tree, None))
        );
        assert_eq!(window.head(&[0; 32]).unwrap(), None);

        // A frame too short for a head is refused, not read past.
        let (short, _) = blob(b"short");
        window
            .append(2, short, ObjectType::Blob, &[1, 2, 3])
            .unwrap();
        assert!(window.head(&short).is_err());
    }

    #[test]
    fn an_absorbed_frame_is_read_from_the_donor_file_after_the_donor_is_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let window = ObjectSpool::new(dir.path()).unwrap();
        let (own, own_bytes) = blob(b"copied");
        window.append(5, own, ObjectType::Blob, &own_bytes).unwrap();
        let (a, a_bytes) = blob(b"alpha");
        let (b, b_bytes) = blob(b"beta");
        let (big, big_bytes) = blob(&[7; 300]);

        let donor = loose_spool(dir.path());
        donor.append(0, a, ObjectType::Blob, &a_bytes).unwrap();
        donor.append(1, b, ObjectType::Blob, &b_bytes).unwrap();
        donor.append(2, a, ObjectType::Blob, &a_bytes).unwrap();
        donor.append(3, big, ObjectType::Blob, &big_bytes).unwrap();
        let (packed, loose): (Vec<_>, Vec<_>) = donor
            .take_order()
            .into_iter()
            .partition(|entry| entry.1 != big);
        window.absorb(&donor, &packed).unwrap();
        window.adopt(&donor, &loose).unwrap();
        // Another window of the same donor shares its file.
        let second = ObjectSpool::new(dir.path()).unwrap();
        second.absorb(&donor, &packed[1..2]).unwrap();
        drop(donor);

        // Nothing was copied, and the bytes are still read and checked.
        assert_eq!(window.written_bytes(), own_bytes.len() as u64);
        assert_eq!(second.written_bytes(), 0);
        assert_eq!(window.read(&a).unwrap(), Some(a_bytes));
        assert_eq!(window.read(&b).unwrap(), Some(b_bytes.clone()));
        assert_eq!(window.read(&big).unwrap(), Some(big_bytes));
        assert_eq!(window.read(&own).unwrap(), Some(own_bytes));
        assert_eq!(second.read(&b).unwrap(), Some(b_bytes));
        assert_eq!(window.head(&a).unwrap(), Some((ObjectType::Blob, Some(5))));
        let ids: Vec<_> = window
            .take_order()
            .into_iter()
            .map(|(position, id, _, _)| (position, id))
            .collect();
        assert_eq!(ids, [(0, a), (1, b), (2, a), (3, big), (5, own)]);
    }

    #[test]
    fn a_head_comes_from_what_staging_kept_and_an_absorbed_frame_carries_it() {
        let dir = tempfile::tempdir().unwrap();
        let data = b"spooled head";
        let (id, bytes) = blob(data);
        let len = u32::try_from(bytes.len()).unwrap();
        let expected = Some((ObjectType::Blob, Some(data.len() as u64)));
        let donor = ObjectSpool::new(dir.path()).unwrap();
        donor.append(0, id, ObjectType::Blob, &bytes).unwrap();
        // Damage the staged head on disk: a head that read it would fail.
        {
            let mut file = donor.inner.lock().unwrap();
            file.writer.flush().unwrap();
            crate::pack::write_spooled(&file.writer.get_ref().0, 0, &[0xff; 10]).unwrap();
        }
        assert_eq!(donor.head(&id).unwrap(), expected);

        let window = ObjectSpool::new(dir.path()).unwrap();
        window
            .absorb(&donor, &[(0, id, len, ObjectType::Blob)])
            .unwrap();
        assert_eq!(window.head(&id).unwrap(), expected);
        assert!(window.read(&id).is_err());
        assert_eq!(window.head(&blob(b"absent").0).unwrap(), None);
    }

    #[test]
    fn an_absorbed_frame_keeps_its_earliest_position_and_a_damaged_byte_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (id, bytes) = blob(b"base");
        let len = u32::try_from(bytes.len()).unwrap();
        let entry = |position| (position, id, len, ObjectType::Blob);
        let donor = ObjectSpool::new(dir.path()).unwrap();
        donor.append(0, id, ObjectType::Blob, &bytes).unwrap();
        let window = ObjectSpool::new(dir.path()).unwrap();
        window.append(4, id, ObjectType::Blob, &bytes).unwrap();
        window.absorb(&donor, &[entry(2)]).unwrap();
        assert_eq!(
            window
                .read_before::<StoreError>(&id, 3, |_| Ok(()))
                .unwrap(),
            Some(bytes.clone())
        );
        window.absorb(&donor, &[entry(9)]).unwrap();
        assert_eq!(
            window
                .read_before::<StoreError>(&id, 3, |_| Ok(()))
                .unwrap(),
            Some(bytes.clone())
        );

        // The frame already at a position stays when another donor offers one
        // for the same position: a damaged copy there is never read.
        let damaged = ObjectSpool::new(dir.path()).unwrap();
        damaged.append(0, id, ObjectType::Blob, &bytes).unwrap();
        {
            let mut file = damaged.inner.lock().unwrap();
            file.writer.flush().unwrap();
            crate::pack::write_spooled(&file.writer.get_ref().0, 12, &[0xff]).unwrap();
        }
        let tied = ObjectSpool::new(dir.path()).unwrap();
        tied.absorb(&donor, &[entry(5)]).unwrap();
        tied.absorb(&damaged, &[entry(5)]).unwrap();
        assert_eq!(tied.read(&id).unwrap(), Some(bytes.clone()));
        let later = ObjectSpool::new(dir.path()).unwrap();
        later.absorb(&damaged, &[entry(5)]).unwrap();
        later.absorb(&donor, &[entry(4)]).unwrap();
        assert_eq!(later.read(&id).unwrap(), Some(bytes.clone()));

        // A byte of the donor's file that changed is caught on a read.
        let (other, other_bytes) = blob(b"other bytes");
        donor
            .append(1, other, ObjectType::Blob, &other_bytes)
            .unwrap();
        let mut file = donor.inner.lock().unwrap();
        file.writer.flush().unwrap();
        crate::pack::write_spooled(&file.writer.get_ref().0, bytes.len() as u64 + 10, &[0xff])
            .unwrap();
        drop(file);
        window
            .absorb(
                &donor,
                &[(
                    1,
                    other,
                    u32::try_from(other_bytes.len()).unwrap(),
                    ObjectType::Blob,
                )],
            )
            .unwrap();
        assert!(matches!(
            window.read(&other),
            Err(StoreError::HashMismatch { .. })
        ));
    }

    #[test]
    fn a_window_can_absorb_from_a_window_that_absorbed() {
        let dir = tempfile::tempdir().unwrap();
        let (a, a_bytes) = blob(b"alpha");
        let (b, b_bytes) = blob(b"beta");
        let (c, c_bytes) = blob(b"gamma");
        let entry = |position, id: Hash, bytes: &Vec<u8>| {
            (
                position,
                id,
                u32::try_from(bytes.len()).unwrap(),
                ObjectType::Blob,
            )
        };

        let first = ObjectSpool::new(dir.path()).unwrap();
        first.append(0, a, ObjectType::Blob, &a_bytes).unwrap();
        let second = ObjectSpool::new(dir.path()).unwrap();
        second.append(0, b, ObjectType::Blob, &b_bytes).unwrap();
        let first_window = ObjectSpool::new(dir.path()).unwrap();
        first_window
            .absorb(&first, &[entry(0, a, &a_bytes)])
            .unwrap();
        first_window
            .absorb(&second, &[entry(1, b, &b_bytes)])
            .unwrap();
        first_window
            .append(2, c, ObjectType::Blob, &c_bytes)
            .unwrap();
        assert_eq!(first_window.donor_files(), 2);

        // The next window reads three files: one own, two the first absorbed.
        let next = ObjectSpool::new(dir.path()).unwrap();
        let order = first_window.take_order();
        assert_eq!(order.len(), 3);
        next.absorb(&first_window, &order).unwrap();
        drop((first, second, first_window));
        assert_eq!(next.donor_files(), 3);
        let a_bytes_again = a_bytes.clone();
        assert_eq!(next.read(&a).unwrap(), Some(a_bytes));
        assert_eq!(next.read(&b).unwrap(), Some(b_bytes));
        assert_eq!(next.read(&c).unwrap(), Some(c_bytes));

        // A third window of the same spools shares their files.
        let third = ObjectSpool::new(dir.path()).unwrap();
        third.absorb(&next, &next.take_order()).unwrap();
        assert_eq!(third.donor_files(), 3);

        // A file that no absorbed entry reads is not kept open.
        let fourth = ObjectSpool::new(dir.path()).unwrap();
        let only_a = entry(0, a, &a_bytes_again);
        fourth.absorb(&third, &[only_a]).unwrap();
        assert_eq!(fourth.donor_files(), 1);
        assert_eq!(fourth.read(&a).unwrap(), Some(a_bytes_again));
    }

    #[test]
    fn absorbing_what_is_not_a_staged_object_of_the_donor_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let window = ObjectSpool::new(dir.path()).unwrap();
        let donor = loose_spool(dir.path());
        let (id, bytes) = blob(&[2; 300]);
        let len = u32::try_from(bytes.len()).unwrap();
        assert!(matches!(
            window.absorb(&donor, &[(0, id, len, ObjectType::Blob)]),
            Err(StoreError::ObjectNotFound(_))
        ));
        // A loose object is adopted, not absorbed.
        donor.append(0, id, ObjectType::Blob, &bytes).unwrap();
        assert!(matches!(
            window.absorb(&donor, &[(0, id, len, ObjectType::Blob)]),
            Err(StoreError::ObjectNotFound(_))
        ));
        let (small, small_bytes) = blob(b"small");
        let small_len = u32::try_from(small_bytes.len()).unwrap();
        donor
            .append(1, small, ObjectType::Blob, &small_bytes)
            .unwrap();
        assert!(matches!(
            window.absorb(&donor, &[(1, small, small_len + 1, ObjectType::Blob)]),
            Err(StoreError::ObjectNotFound(_))
        ));
        assert!(!window.contains(&id) && !window.contains(&small));
        window
            .absorb(&donor, &[(1, small, small_len, ObjectType::Blob)])
            .unwrap();
        assert!(window.contains(&small));
    }

    #[test]
    fn staged_objects_go_to_a_pack_once_under_their_decoded_ids() {
        use crate::layout::RepoLayout;
        use crate::store::{LocalPackWriter, ObjectStore};
        let dir = tempfile::tempdir().unwrap();
        let layout = RepoLayout::single(dir.path());
        let store = ObjectStore::init(&layout).unwrap();
        store.try_activate_local_packs().unwrap();
        let guard = store.prune_guard().unwrap();
        fs::create_dir_all(store.spool_dir()).unwrap();
        let spool = ObjectSpool::new(&store.spool_dir()).unwrap();
        let (a, a_bytes) = blob(b"alpha");
        let (b, b_bytes) = blob(&vec![9; 70_000]);
        spool.append(0, a, ObjectType::Blob, &a_bytes).unwrap();
        spool.append(1, b, ObjectType::Blob, &b_bytes).unwrap();
        spool.append(2, a, ObjectType::Blob, &a_bytes).unwrap();

        let mut pack = LocalPackWriter::new(&store, &guard).unwrap();
        let mut scratch = Vec::new();
        for id in [&a, &b, &a] {
            spool.write_to_pack(id, &mut pack, &mut scratch).unwrap();
        }
        assert!(matches!(
            spool.write_to_pack(&[1; 32], &mut pack, &mut scratch),
            Err(StoreError::ObjectNotFound(_))
        ));
        // A refused id is not a failed write: the writer is still good.
        pack.publish().unwrap();
        assert_eq!(store.read(&a).unwrap(), a_bytes);
        assert_eq!(store.read(&b).unwrap(), b_bytes);
        assert_eq!(fs::read_dir(store.pack_dir()).unwrap().count(), 2);
    }

    #[test]
    fn an_adopted_frame_replaces_a_staged_one_only_at_an_earlier_position() {
        let dir = tempfile::tempdir().unwrap();
        let (id, good) = blob(&[4; 300]);
        let entry = |position| {
            (
                position,
                id,
                u32::try_from(good.len()).unwrap(),
                ObjectType::Blob,
            )
        };
        // The donor's file is damaged, so a read tells which frame won.
        let adopt_at = |staged_at: usize, adopted_at: usize| {
            let window = loose_spool(dir.path());
            window
                .append(staged_at, id, ObjectType::Blob, &good)
                .unwrap();
            fs::create_dir_all(dir.path().join("donor")).unwrap();
            let donor = loose_spool(&dir.path().join("donor"));
            donor.append(0, id, ObjectType::Blob, &good).unwrap();
            let mut damaged = good.clone();
            damaged[100] ^= 1;
            fs::write(&staged_files(&dir.path().join("donor"))[0], damaged).unwrap();
            window.adopt(&donor, &[entry(adopted_at)]).unwrap();
            window.read(&id)
        };

        assert!(matches!(
            adopt_at(5, 2),
            Err(StoreError::HashMismatch { .. })
        ));
        assert_eq!(adopt_at(2, 2).unwrap(), Some(good.clone()));
        assert_eq!(adopt_at(2, 9).unwrap(), Some(good));
    }
}
