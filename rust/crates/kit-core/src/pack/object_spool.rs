//! Private canonical object bytes retained while a fetch accepts a wire pack.

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::Path;
use std::sync::Mutex;

use crate::hash::{Hash, to_hex};
use crate::object::{ObjectType, verified_id_and_object};
use crate::store::{MAX_RAW_OBJECT_SIZE, StoreError, StoreResult};

use super::{PackError, UnpackSink, read_spooled};

/// An unnamed append-only file and its in-memory locator. Every read but
/// [`ObjectSpool::read_decoded`] verifies the object id; offsets and lengths
/// come from the decoder, never the file.
///
/// A spool can also adopt objects another spool holds, by keeping a handle to
/// that spool's file rather than copying the bytes ([`ObjectSpool::adopt`]).
#[derive(Debug)]
pub struct ObjectSpool {
    inner: Mutex<Spool>,
}

#[derive(Debug, Clone, Copy)]
struct Frame {
    position: usize,
    /// Zero for the spool's own file, else one past the index in
    /// `Spool::adopted`.
    segment: u32,
    offset: u64,
    len: u32,
}

#[derive(Debug)]
struct Spool {
    writer: BufWriter<File>,
    end: u64,
    /// Files of other spools whose frames this spool adopted.
    adopted: Vec<File>,
    by_id: HashMap<Hash, Frame>,
    order: Vec<(usize, Hash, u32, ObjectType)>,
}

impl ObjectSpool {
    /// Create an unnamed object spool in the repository's spool directory.
    ///
    /// # Errors
    /// The directory or file cannot be created.
    pub fn new(dir: &Path) -> io::Result<Self> {
        Ok(Self {
            inner: Mutex::new(Spool {
                writer: BufWriter::with_capacity(256 << 10, tempfile::tempfile_in(dir)?),
                end: 0,
                adopted: Vec::new(),
                by_id: HashMap::new(),
                order: Vec::new(),
            }),
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
        let mut spool = self.inner.lock().expect("object spool mutex");
        let len = u32::try_from(bytes.len()).expect("bounded object length");
        if spool
            .by_id
            .get(&id)
            .is_none_or(|frame| frame.position > position)
        {
            let frame = Frame {
                position,
                segment: 0,
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

    /// Adopt the objects `entries` names, each `(position, id, length, type)`
    /// as [`Self::take_order`] of `from` returned it, without copying their
    /// bytes: this spool keeps a handle to `from`'s file, so the bytes stay
    /// readable here after `from` is dropped. The entries join this spool's
    /// own, under the same rules as [`Self::append`].
    ///
    /// # Errors
    /// An entry `from` does not hold, or a local I/O error.
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
        if entries.is_empty() {
            return Ok(());
        }
        let (file, offsets) = {
            let mut other = from.inner.lock().expect("object spool mutex");
            other.writer.flush()?;
            let offsets = entries
                .iter()
                .map(|(_, id, len, _)| match other.by_id.get(id) {
                    Some(frame) if frame.segment == 0 && frame.len == *len => Ok(frame.offset),
                    _ => Err(StoreError::ObjectNotFound(to_hex(id))),
                })
                .collect::<StoreResult<Vec<_>>>()?;
            (other.writer.get_ref().try_clone()?, offsets)
        };
        let mut spool = self.inner.lock().expect("object spool mutex");
        spool.adopted.push(file);
        let segment = u32::try_from(spool.adopted.len()).expect("bounded segment count");
        for (&(position, id, len, ty), offset) in entries.iter().zip(offsets) {
            if spool
                .by_id
                .get(&id)
                .is_none_or(|frame| frame.position > position)
            {
                spool.by_id.insert(
                    id,
                    Frame {
                        position,
                        segment,
                        offset,
                        len,
                    },
                );
            }
            spool.order.push((position, id, len, ty));
        }
        Ok(())
    }

    /// Bytes this spool wrote to its own file. Objects it adopted are not
    /// counted.
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

    /// Read a staged copy without hashing it again, if present. For an object
    /// the decoder derived the id of when it staged it, whose bytes go
    /// straight to a write that names them by that id: the loose write of a
    /// fetched object, which is read here once and hashed once, at decode.
    ///
    /// # Errors
    /// A local read error.
    pub fn read_decoded(&self, id: &Hash) -> StoreResult<Option<Vec<u8>>> {
        self.read_frame(id, usize::MAX, |_| Ok(()), false)
    }

    pub(super) fn read_before<E: From<StoreError>>(
        &self,
        id: &Hash,
        before: usize,
        admit: impl FnOnce(usize) -> Result<(), E>,
    ) -> Result<Option<Vec<u8>>, E> {
        self.read_frame(id, before, admit, true)
    }

    fn read_frame<E: From<StoreError>>(
        &self,
        id: &Hash,
        before: usize,
        admit: impl FnOnce(usize) -> Result<(), E>,
        verify: bool,
    ) -> Result<Option<Vec<u8>>, E> {
        let mut spool = self.inner.lock().expect("object spool mutex");
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
        spool.writer.flush().map_err(StoreError::from)?;
        let file = match frame.segment {
            0 => spool.writer.get_ref(),
            segment => &spool.adopted[segment as usize - 1],
        };
        read_spooled(file, frame.offset, &mut bytes).map_err(StoreError::from)?;
        drop(spool);
        if !verify {
            return Ok(Some(bytes));
        }
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

    #[test]
    fn an_adopted_object_is_read_from_the_donor_file_after_the_donor_is_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let window = ObjectSpool::new(dir.path()).unwrap();
        let (own, own_bytes) = blob(b"copied");
        window.append(5, own, ObjectType::Blob, &own_bytes).unwrap();
        let (big, big_bytes) = blob(&vec![7; 300_000]);
        let (twice, twice_bytes) = blob(&vec![9; 300_001]);

        let donor = ObjectSpool::new(dir.path()).unwrap();
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

        assert_eq!(window.written_bytes(), own_bytes.len() as u64);
        assert!(window.contains(&big));
        assert_eq!(window.read(&big).unwrap(), Some(big_bytes.clone()));
        assert_eq!(window.read_decoded(&twice).unwrap(), Some(twice_bytes));
        assert_eq!(window.read(&own).unwrap(), Some(own_bytes));
        let ids: Vec<_> = window
            .take_order()
            .into_iter()
            .map(|(position, id, _, _)| (position, id))
            .collect();
        assert_eq!(ids, [(0, big), (1, twice), (2, twice), (5, own)]);
    }

    #[test]
    fn adopting_an_object_the_donor_never_held_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let window = ObjectSpool::new(dir.path()).unwrap();
        let donor = ObjectSpool::new(dir.path()).unwrap();
        let (id, bytes) = blob(b"absent");
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
        assert!(!window.contains(&id));
    }

    #[test]
    fn a_decoded_read_skips_the_hash_that_a_checked_read_refuses() {
        let dir = tempfile::tempdir().unwrap();
        let spool = ObjectSpool::new(dir.path()).unwrap();
        let (claimed, _) = blob(b"claimed");
        let (_, other) = blob(b"other bytes");
        spool.append(0, claimed, ObjectType::Blob, &other).unwrap();
        assert!(matches!(
            spool.read(&claimed),
            Err(StoreError::HashMismatch { .. })
        ));
        assert_eq!(spool.read_decoded(&claimed).unwrap(), Some(other));
        assert_eq!(spool.read_decoded(&[0; 32]).unwrap(), None);
    }
}
