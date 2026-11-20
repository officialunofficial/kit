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
        if !spool
            .by_id
            .get(&id)
            .is_some_and(|frame| frame.position <= position)
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
    pub fn take_order(&self) -> Vec<(usize, Hash, u32, ObjectType)> {
        let mut spool = self.inner.lock().expect("object spool mutex");
        let mut order = std::mem::take(&mut spool.order);
        order.sort_unstable_by_key(|entry| entry.0);
        order
    }

    /// Whether the decoder staged this id.
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
