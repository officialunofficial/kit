//! Private canonical object bytes retained while a fetch accepts a wire pack.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

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
        let mut file = crate::atomic::temp_file_in(&shard)?;
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
    /// In `Spool::loose` rather than in the spool's file.
    loose: bool,
    offset: u64,
    len: u32,
}

#[derive(Debug)]
struct Spool {
    writer: BufWriter<File>,
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
                writer: BufWriter::with_capacity(256 << 10, tempfile::tempfile_in(dir)?),
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
                offset: spool.end,
                len,
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
                    offset: 0,
                    len,
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
                if !other
                    .by_id
                    .get(&id)
                    .is_some_and(|frame| frame.loose && frame.len == len)
                {
                    return Err(StoreError::ObjectNotFound(to_hex(&id)));
                }
                if let Some(file) = other.loose.remove(&id) {
                    moved.push(((position, id, len, ty), file));
                }
            }
            moved
        };
        let mut spool = self.inner.lock().expect("object spool mutex");
        for ((position, id, len, ty), file) in moved {
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
                        offset: 0,
                        len,
                    },
                );
                spool.loose.insert(id, file);
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

    /// The type and, for a blob, the payload length of a staged object, read
    /// from its ten-byte head alone, as [`crate::store::ObjectStore::object_head`]
    /// reads a stored one. The rest of the object is neither read nor hashed.
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
        let mut head = [0; 10];
        let len = head.len().min(frame.len as usize);
        Self::read_frame(spool, id, frame, &mut head[..len])?;
        Ok(Some(crate::store::head_at(&mut &head[..len])?))
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
        spool.writer.flush()?;
        read_spooled(spool.writer.get_ref(), frame.offset, buf)
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
