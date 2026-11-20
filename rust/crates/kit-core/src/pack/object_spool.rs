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

/// An unnamed append-only file and its in-memory locator. Every read verifies
/// the object id; offsets and lengths come from the decoder, never the file.
#[derive(Debug)]
pub struct ObjectSpool {
    inner: Mutex<Spool>,
}

#[derive(Debug, Clone, Copy)]
struct Frame {
    position: usize,
    offset: u64,
    len: u32,
}

#[derive(Debug)]
struct Spool {
    writer: BufWriter<File>,
    end: u64,
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

    pub(super) fn read_before<E: From<StoreError>>(
        &self,
        id: &Hash,
        before: usize,
        admit: impl FnOnce(usize) -> Result<(), E>,
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
        read_spooled(spool.writer.get_ref(), frame.offset, &mut bytes).map_err(StoreError::from)?;
        drop(spool);
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
}
