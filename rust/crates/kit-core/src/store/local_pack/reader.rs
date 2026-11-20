use std::collections::VecDeque;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::Path;
use std::sync::Arc;

use crate::hash::Hash;
use crate::pack::{HEADER_LEN, MAGIC, read_spooled};

use super::index::{
    FANOUT_END, Frame, INDEX_BASE_LEN, INDEX_ROW_LEN, MAGIC_INDEX, Pair, Stamp, invalid, le_u32,
    open_regular, read_frame_header, read_header, read_version,
};
use super::{StoreError, StoreResult, is_disappeared};

// Keep room for loose objects, transports and other repository files.
const HANDLE_LIMIT: usize = 96;
pub(super) const ROW_CACHE_BYTES: usize = 64 << 20;
pub(super) const ROUTE_CACHE_BYTES: usize = 288 << 20;

#[derive(Debug, Default)]
pub(super) struct Handles(MutexHandles);

type MutexHandles = std::sync::Mutex<VecDeque<(Arc<Locator>, Member, Arc<File>)>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Member {
    Index,
    Pack,
}

impl Handles {
    #[cfg(test)]
    pub(super) fn cached(&self) -> usize {
        self.0.lock().unwrap().len()
    }

    pub(super) fn get(&self, locator: &Arc<Locator>, member: Member) -> StoreResult<Arc<File>> {
        let mut handles = self.0.lock().expect("local pack handles mutex");
        let handle = if let Some(position) = handles
            .iter()
            .position(|(old, kind, _)| Arc::ptr_eq(old, locator) && *kind == member)
        {
            handles
                .remove(position)
                .expect("position in handle cache")
                .2
        } else {
            let (path, stamp) = match member {
                Member::Index => (&locator.pair.index, &locator.index_stamp),
                Member::Pack => (&locator.pair.pack, &locator.pack_stamp),
            };
            let file = open_regular(path)?;
            let opened = Stamp::get(&file.metadata()?)?;
            let current = match member {
                Member::Index => opened == *stamp,
                Member::Pack => opened.same_file(stamp),
            };
            if !current {
                return locator.changed();
            }
            Arc::new(file)
        };
        if handles.len() == HANDLE_LIMIT {
            handles.pop_back();
        }
        handles.push_front((Arc::clone(locator), member, Arc::clone(&handle)));
        Ok(handle)
    }

    pub(super) fn retain(&self, mut live: impl FnMut(&Arc<Locator>) -> bool) {
        self.0
            .lock()
            .expect("local pack handles mutex")
            .retain(|(locator, _, _)| live(locator));
    }
}

#[derive(Debug)]
pub(in crate::store) struct Locator {
    pub(super) pair: Pair,
    pack_stamp: Stamp,
    index_stamp: Stamp,
    count: usize,
    trailer: u64,
    fanout: Box<[u8; FANOUT_END]>,
    rows: Box<[u8]>,
    prefixes: Box<[u32]>,
}

impl Locator {
    pub(super) fn open(pair: &Pair, rows: usize, routes: usize) -> StoreResult<Self> {
        let result = Self::load(pair, rows, routes);
        if let Err(error) = &result
            && !is_disappeared(error)
        {
            if !matches!(error, StoreError::IncompatibleRepoFormat { .. }) {
                // A damaged member can hide the other member's version.
                pair.check_versions()?;
            }
            return result.map_err(|e| pair.context(e));
        }
        result
    }

    fn load(pair: &Pair, row_budget: usize, route_budget: usize) -> StoreResult<Self> {
        let mut pack = open_regular(&pair.pack)?;
        let pack_stamp = Stamp::get(&pack.metadata()?)?;
        let (count, trailer, _) = read_header(&mut pack)?;
        let mut index = open_regular(&pair.index)?;
        let metadata = index.metadata()?;
        let index_stamp = Stamp::get(&metadata)?;
        let row_bytes = INDEX_ROW_LEN * count;
        let size = INDEX_BASE_LEN + row_bytes;
        if metadata.len() != size as u64 {
            return Err(invalid("index length does not match frame count").into());
        }
        let fanout = Box::new(read_version::<FANOUT_END>(
            &mut index,
            *MAGIC_INDEX,
            "local index",
        )?);
        if le_u32(&fanout[8..12]) as usize != count {
            return Err(invalid("index count differs from pack count").into());
        }
        super::index::validate_fanout_bounds(&fanout[12..], count)?;
        let mut key = [0; 32];
        read_spooled(&index, (size - 64) as u64, &mut key)?;
        if key != pair.key {
            return Err(invalid("index key differs from filename").into());
        }
        let mut rows = Vec::new();
        let mut prefixes = Vec::new();
        let route_bytes = count * (size_of::<Route>() + size_of::<u32>());
        if route_bytes <= route_budget {
            if row_bytes <= row_budget {
                rows.resize(row_bytes, 0);
                index.read_exact(&mut rows)?;
            } else {
                prefixes.reserve_exact(count);
                let mut buffer = [0; 32 * 256];
                let mut remaining = count;
                while remaining != 0 {
                    let entries = remaining.min(256);
                    let bytes = &mut buffer[..entries * 32];
                    index.read_exact(bytes)?;
                    prefixes.extend(bytes.chunks_exact(32).map(prefix));
                    remaining -= entries;
                }
            }
        }
        Ok(Self {
            pair: pair.clone(),
            pack_stamp,
            index_stamp,
            count,
            trailer,
            fanout,
            rows: rows.into_boxed_slice(),
            prefixes: prefixes.into_boxed_slice(),
        })
    }

    pub(super) fn row_charge(&self) -> usize {
        self.rows.len()
    }

    pub(super) fn route_charge(&self) -> usize {
        self.route_count() * (size_of::<Route>() + size_of::<u32>())
    }

    pub(super) fn route_count(&self) -> usize {
        if self.rows.is_empty() {
            self.prefixes.len()
        } else {
            self.count
        }
    }

    fn named_stamp(path: &Path) -> io::Result<Option<Stamp>> {
        let metadata = fs::symlink_metadata(path)?;
        metadata
            .is_file()
            .then(|| Stamp::get(&metadata))
            .transpose()
    }

    pub(super) fn check_current(&self) -> StoreResult<bool> {
        // Retirement unlinks the pack first. Check its name last so a
        // live index alone cannot authorize a read through a cached handle.
        if Self::named_stamp(&self.pair.index)?.as_ref() != Some(&self.index_stamp) {
            return self.changed();
        }
        let Some(pack) = Self::named_stamp(&self.pair.pack)? else {
            return self.changed();
        };
        if !pack.same_file(&self.pack_stamp) {
            return self.changed();
        }
        Ok(pack == self.pack_stamp)
    }

    fn changed<T>(&self) -> StoreResult<T> {
        self.pair.check_versions()?;
        Err(io::Error::from(io::ErrorKind::NotFound).into())
    }

    fn read_column<const N: usize>(&self, file: Option<&File>, at: usize) -> io::Result<[u8; N]> {
        if let Some(file) = file {
            let mut bytes = [0; N];
            read_spooled(file, (FANOUT_END + at) as u64, &mut bytes)?;
            Ok(bytes)
        } else {
            Ok(self.rows[at..at + N]
                .try_into()
                .expect("bounded index column"))
        }
    }

    fn bucket(&self, shard: u8) -> std::ops::Range<usize> {
        let at = 12 + usize::from(shard) * 4;
        let start = if shard == 0 {
            0
        } else {
            le_u32(&self.fanout[at - 4..at])
        };
        start as usize..le_u32(&self.fanout[at..at + 4]) as usize
    }

    fn find_row(&self, file: &File, id: &Hash) -> io::Result<Option<usize>> {
        let mut range = self.bucket(id[0]);
        while range.start < range.end {
            let mid = range.start + (range.end - range.start) / 2;
            let candidate: Hash = self.read_column(Some(file), mid * 32)?;
            match candidate.cmp(id) {
                std::cmp::Ordering::Less => range.start = mid + 1,
                std::cmp::Ordering::Equal => return Ok(Some(mid)),
                std::cmp::Ordering::Greater => range.end = mid,
            }
        }
        Ok(None)
    }

    pub(super) fn find(
        self: &Arc<Self>,
        handles: &Handles,
        id: &Hash,
        row: Option<usize>,
    ) -> StoreResult<Option<Frame>> {
        let file = if self.rows.is_empty() {
            if row.is_none() && self.bucket(id[0]).is_empty() {
                return Ok(None);
            }
            self.check_current()?;
            Some(handles.get(self, Member::Index)?)
        } else {
            None
        };
        let row = if let Some(row) = row {
            let candidate: Hash = self
                .read_column(file.as_deref(), row * 32)
                .map_err(|e| self.pair.error(e))?;
            if candidate != *id {
                return Ok(None);
            }
            row
        } else {
            let file = file.as_deref().expect("unrouted rows are on disk");
            let Some(row) = self.find_row(file, id).map_err(|e| self.pair.error(e))? else {
                return Ok(None);
            };
            row
        };
        let frame = self
            .frame_from_row(file.as_deref(), row)
            .map_err(|e| self.pair.error(e))?;
        if frame.extent(self.trailer).is_none() {
            self.check_current()?;
            return Err(self.pair.error("invalid index extent"));
        }
        Ok(Some(frame))
    }

    fn frame_from_row(&self, file: Option<&File>, row: usize) -> io::Result<Frame> {
        Ok(Frame {
            offset: u64::from_le_bytes(self.read_column(file, self.count * 32 + row * 8)?),
            len: u32::from_le_bytes(self.read_column(file, self.count * 40 + row * 4)?),
        })
    }

    pub(super) fn routes(&self, pack: usize) -> impl Iterator<Item = Route> + '_ {
        self.rows
            .chunks_exact(32)
            .take(self.count)
            .map(prefix)
            .chain(self.prefixes.iter().copied())
            .enumerate()
            .map(move |(row, prefix)| Route {
                prefix,
                pack: u32::try_from(pack).expect("bounded pack number"),
                row: u32::try_from(row).expect("bounded index row"),
            })
    }

    pub(super) fn open_frame(&self, file: &File, frame: Frame) -> StoreResult<()> {
        if !self.check_current()? {
            // Reuse can touch a pack's timestamps without replacing it.
            let mut header = [0; HEADER_LEN];
            read_spooled(file, 0, &mut header).map_err(|e| self.pair.error(e))?;
            let header = read_version::<HEADER_LEN>(&mut header.as_slice(), *MAGIC, "local pack")
                .map_err(|e| self.pair.context(e))?;
            if le_u32(&header[8..]) as usize != self.count {
                return Err(self.pair.error("pack size or count changed"));
            }
        }
        let (start, _) = frame
            .extent(self.trailer)
            .ok_or_else(|| self.pair.error("invalid frame extent"))?;
        let mut header = [0; crate::pack::ENTRY_FRAME_LEN];
        read_spooled(file, start, &mut header).map_err(|e| self.pair.error(e))?;
        let len = read_frame_header(&mut header.as_slice()).map_err(|e| self.pair.error(e))?;
        if len != frame.len {
            return Err(self.pair.error("index and pack disagree on frame length"));
        }
        Ok(())
    }
}

#[derive(Debug)]
pub(super) struct Route {
    pub(super) prefix: u32,
    pub(super) pack: u32,
    pub(super) row: u32,
}

pub(super) fn prefix(id: &[u8]) -> u32 {
    u32::from_le_bytes(id[..4].try_into().expect("id prefix"))
}
