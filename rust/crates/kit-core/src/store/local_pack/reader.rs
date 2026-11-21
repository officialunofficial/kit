use std::fs::{self, File};
use std::io::{self, IoSliceMut, Read};
use std::path::Path;
use std::sync::Arc;

use rustc_hash::FxHashMap;

use crate::hash::Hash;
use crate::pack::{ENTRY_FRAME_LEN, HEADER_LEN, MAGIC, read_spooled};

use super::index::{
    FANOUT_END, Frame, INDEX_BASE_LEN, INDEX_ROW_LEN, MAGIC_INDEX, Pair, Stamp, invalid, le_u32,
    open_regular, read_frame_header, read_header_sized, read_version,
};
use super::{StoreError, StoreResult, is_disappeared};

/// Handles the cache keeps at least, whatever the open-file limit. This leaves
/// room for loose objects, transports and other repository files.
pub(super) const HANDLE_FLOOR: usize = 96;
/// Handles the cache keeps at most.
pub(super) const HANDLE_CEILING: usize = 1024;

/// A quarter of the soft open-file limit `soft`, held between
/// [`HANDLE_FLOOR`] and [`HANDLE_CEILING`]: a store with that many packs or
/// fewer keeps a handle for each, so a scan that visits the packs in any order
/// opens each once. The rest of the limit stays for loose objects, transports
/// and other files.
pub(super) fn handle_limit_for(soft: u64) -> usize {
    usize::try_from(soft / 4)
        .unwrap_or(usize::MAX)
        .clamp(HANDLE_FLOOR, HANDLE_CEILING)
}

/// How many handles a cache keeps in this process. The soft limit is read
/// once. Where it cannot be read, the cache keeps [`HANDLE_FLOOR`].
fn handle_limit() -> usize {
    static LIMIT: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *LIMIT.get_or_init(|| {
        #[cfg(unix)]
        {
            crate::batch::soft_open_file_limit().map_or(HANDLE_FLOOR, handle_limit_for)
        }
        #[cfg(not(unix))]
        {
            HANDLE_FLOOR
        }
    })
}

/// Most pairs a catalog keeps without rows or routes. Each pair may hold an
/// index handle and a pack handle in the cache, and these must both fit.
pub(super) const LAZY_PAIR_LIMIT: usize = 40;
const _: () = assert!(2 * LAZY_PAIR_LIMIT <= HANDLE_FLOOR);
pub(super) const ROW_CACHE_BYTES: usize = 64 << 20;
pub(super) const ROUTE_CACHE_BYTES: usize = 288 << 20;

/// An LRU of open pack and index files.
///
/// The lock covers only the table. A miss opens and checks the file with the
/// lock released, so one slow `open` never holds up probes of cached packs,
/// and the file an insert evicts closes after the lock is released. A hit
/// looks the file up in a hash table and stamps it, so the lock is held for
/// a few instructions however many files are cached.
#[derive(Debug)]
pub(super) struct Handles {
    cache: std::sync::Mutex<Cache>,
    /// Files the cache keeps open at most.
    limit: usize,
    #[cfg(test)]
    opens: std::sync::atomic::AtomicUsize,
    /// Runs once between a miss's open and its insert, with no lock held.
    #[cfg(test)]
    after_open: std::sync::Mutex<AfterOpen>,
}

impl Default for Handles {
    fn default() -> Self {
        Self::with_limit(handle_limit())
    }
}

#[cfg(test)]
#[derive(Default)]
pub(super) struct AfterOpen(Option<Hook>);

#[cfg(test)]
type Hook = Box<dyn FnOnce(&Handles) + Send>;

#[cfg(test)]
impl std::fmt::Debug for AfterOpen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AfterOpen")
    }
}

/// One cached file. The locator is held so that its address, which keys the
/// entry, is never reused by another locator.
#[derive(Debug)]
struct Entry {
    locator: Arc<Locator>,
    handle: Arc<File>,
    /// The cache's clock at the last use: the lowest is the least recently used.
    used: u64,
}

#[derive(Debug, Default)]
struct Cache {
    entries: FxHashMap<(usize, Member), Entry>,
    /// Ticks at every use.
    clock: u64,
    /// Bumped by `retain`, so a file opened before a retire is not cached after it.
    retains: u64,
}

impl Cache {
    fn key(locator: &Arc<Locator>, member: Member) -> (usize, Member) {
        (Arc::as_ptr(locator) as usize, member)
    }

    /// Marks a cached entry as just used and returns its handle.
    fn promote(&mut self, locator: &Arc<Locator>, member: Member) -> Option<Arc<File>> {
        self.clock += 1;
        let entry = self.entries.get_mut(&Self::key(locator, member))?;
        entry.used = self.clock;
        Some(Arc::clone(&entry.handle))
    }

    /// Caches `handle`, and returns the least recently used entry when that
    /// was needed to stay within `limit`. The caller drops it with no lock
    /// held, because dropping the last handle to a file closes it.
    fn insert(
        &mut self,
        locator: &Arc<Locator>,
        member: Member,
        handle: Arc<File>,
        limit: usize,
    ) -> Option<Entry> {
        let evicted = if self.entries.len() >= limit {
            let oldest = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.used)
                .map(|(key, _)| *key)?;
            self.entries.remove(&oldest)
        } else {
            None
        };
        self.clock += 1;
        self.entries.insert(
            Self::key(locator, member),
            Entry {
                locator: Arc::clone(locator),
                handle,
                used: self.clock,
            },
        );
        evicted
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) enum Member {
    Index,
    Pack,
}

impl Handles {
    fn with_limit(limit: usize) -> Self {
        Self {
            cache: std::sync::Mutex::default(),
            limit,
            #[cfg(test)]
            opens: std::sync::atomic::AtomicUsize::default(),
            #[cfg(test)]
            after_open: std::sync::Mutex::default(),
        }
    }

    #[cfg(test)]
    pub(super) fn limited(limit: usize) -> Self {
        Self::with_limit(limit)
    }

    #[cfg(test)]
    pub(super) fn limit(&self) -> usize {
        self.limit
    }

    #[cfg(test)]
    pub(super) fn cached(&self) -> usize {
        self.lock().entries.len()
    }

    #[cfg(test)]
    pub(super) fn opens(&self) -> usize {
        self.opens.load(std::sync::atomic::Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(super) fn once_after_open(&self, hook: impl FnOnce(&Handles) + Send + 'static) {
        self.after_open.lock().unwrap().0 = Some(Box::new(hook));
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Cache> {
        self.cache.lock().expect("local pack handles mutex")
    }

    pub(super) fn get(&self, locator: &Arc<Locator>, member: Member) -> StoreResult<Arc<File>> {
        let retains = {
            let mut cache = self.lock();
            if let Some(handle) = cache.promote(locator, member) {
                return Ok(handle);
            }
            cache.retains
        };
        #[cfg(test)]
        self.opens
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let handle = Arc::new(open_current(locator, member)?);
        #[cfg(test)]
        {
            let hook = self.after_open.lock().unwrap().0.take();
            if let Some(hook) = hook {
                hook(self);
            }
        }
        let mut cache = self.lock();
        if let Some(cached) = cache.promote(locator, member) {
            // Another thread cached this file while this one opened it: keep one.
            return Ok(cached);
        }
        if cache.retains != retains {
            // Some pack was retired during the open. This file may be a retired
            // pack's, and caching it would hold a deleted file open.
            return Ok(handle);
        }
        let evicted = cache.insert(locator, member, Arc::clone(&handle), self.limit);
        drop(cache);
        drop(evicted);
        Ok(handle)
    }

    pub(super) fn retain(&self, mut live: impl FnMut(&Arc<Locator>) -> bool) {
        let removed: Vec<_> = {
            let mut cache = self.lock();
            cache.retains += 1;
            cache
                .entries
                .extract_if(|_, entry| !live(&entry.locator))
                .collect()
        };
        drop(removed);
    }
}

/// Opens a locator's pack or index file and checks it is still the one indexed.
fn open_current(locator: &Arc<Locator>, member: Member) -> StoreResult<File> {
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
    if current { Ok(file) } else { locator.changed() }
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
    /// How many times this locator checked that its pair is current.
    #[cfg(test)]
    pub(super) checks: std::sync::atomic::AtomicUsize,
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
            return result.map_err(|e| pair.index_context(e));
        }
        result
    }

    fn load(pair: &Pair, row_budget: usize, route_budget: usize) -> StoreResult<Self> {
        let (mut pack, pack_metadata) = open_member(&pair.pack)?;
        let (mut index, metadata) = open_member(&pair.index)?;
        let pack_stamp = Stamp::get(&pack_metadata)?;
        let (count, trailer, _) = read_header_sized(&mut pack, pack_metadata.len())?;
        let index_stamp = Stamp::get(&metadata)?;
        let row_bytes = INDEX_ROW_LEN * count;
        let size = INDEX_BASE_LEN + row_bytes;
        if metadata.len() != size as u64 {
            return Err(invalid("index length does not match frame count"));
        }
        let route_bytes = count * (size_of::<Route>() + size_of::<u32>());
        // Rows that fit are read with the header, the fanout and the key in
        // one call. Otherwise read the header and the fanout, then the key.
        let rows_fit = route_bytes <= route_budget && row_bytes <= row_budget;
        let mut rows = Vec::new();
        let mut tail = [0; 64];
        let fanout = if rows_fit {
            let mut head = [0; FANOUT_END];
            // The row budget and the file length checked above bound this.
            rows.resize(row_bytes, 0);
            read_exact_vectored(
                &mut index,
                &mut [
                    IoSliceMut::new(&mut head),
                    IoSliceMut::new(&mut rows),
                    IoSliceMut::new(&mut tail),
                ],
            )?;
            read_version::<FANOUT_END>(&mut head.as_slice(), *MAGIC_INDEX, "local index")?
        } else {
            read_version::<FANOUT_END>(&mut index, *MAGIC_INDEX, "local index")?
        };
        let fanout = Box::new(fanout);
        if le_u32(&fanout[8..12]) as usize != count {
            return Err(invalid("index count differs from pack count"));
        }
        super::index::validate_fanout_bounds(&fanout[12..], count)?;
        let mut key = [0; 32];
        if rows_fit {
            key.copy_from_slice(&tail[..32]);
        } else {
            read_spooled(&index, (size - 64) as u64, &mut key)?;
        }
        if key != pair.key {
            return Err(invalid("index key differs from filename"));
        }
        let mut prefixes = Vec::new();
        if !rows_fit && route_bytes <= route_budget {
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
        Ok(Self {
            pair: pair.clone(),
            pack_stamp,
            index_stamp,
            count,
            trailer,
            fanout,
            rows: rows.into_boxed_slice(),
            prefixes: prefixes.into_boxed_slice(),
            #[cfg(test)]
            checks: std::sync::atomic::AtomicUsize::new(0),
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
        #[cfg(test)]
        self.checks
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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

    /// [`Self::check_current`], skipped when `currency` already found this
    /// locator exact.
    pub(super) fn check_current_once(
        self: &Arc<Self>,
        currency: Option<&Currency>,
    ) -> StoreResult<bool> {
        match currency {
            Some(currency) => currency.check(self),
            None => self.check_current(),
        }
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
        currency: Option<&Currency>,
    ) -> StoreResult<Option<Frame>> {
        let file = if self.rows.is_empty() {
            if row.is_none() && self.bucket(id[0]).is_empty() {
                return Ok(None);
            }
            self.check_current_once(currency)?;
            Some(handles.get(self, Member::Index)?)
        } else {
            None
        };
        let row = if let Some(row) = row {
            let candidate: Hash = self
                .read_column(file.as_deref(), row * 32)
                .map_err(|e| self.pair.context(e))?;
            if candidate != *id {
                return Ok(None);
            }
            row
        } else {
            let file = file.as_deref().expect("unrouted rows are on disk");
            let Some(row) = self.find_row(file, id).map_err(|e| self.pair.context(e))? else {
                return Ok(None);
            };
            row
        };
        let frame = self
            .frame_from_row(file.as_deref(), row)
            .map_err(|e| self.pair.context(e))?;
        if frame.extent(self.trailer).is_none() {
            self.check_current()?;
            return Err(self.pair.index_error("invalid index extent"));
        }
        Ok(Some(frame))
    }

    fn frame_from_row(&self, file: Option<&File>, row: usize) -> io::Result<Frame> {
        Ok(Frame {
            offset: u64::from_le_bytes(self.read_column(file, self.count * 32 + row * 8)?),
            len: u32::from_le_bytes(self.read_column(file, self.count * 40 + row * 4)?),
        })
    }

    /// The routing prefix of each row, in row order.
    pub(super) fn prefixes(&self) -> impl Iterator<Item = u32> + '_ {
        self.rows
            .chunks_exact(32)
            .take(self.count)
            .map(prefix)
            .chain(self.prefixes.iter().copied())
    }

    /// Add the ids of one shard to `out`. A pair with no rows in memory reads
    /// that shard's ids from its index.
    pub(super) fn shard_ids(
        self: &Arc<Self>,
        handles: &Handles,
        shard: u8,
        out: &mut Vec<Hash>,
    ) -> StoreResult<()> {
        let range = self.bucket(shard);
        if range.is_empty() {
            return Ok(());
        }
        let mut ids = vec![0; range.len() * 32];
        if self.rows.is_empty() {
            self.check_current()?;
            let file = handles.get(self, Member::Index)?;
            read_spooled(&file, (FANOUT_END + range.start * 32) as u64, &mut ids)
                .map_err(|e| self.pair.context(e))?;
        } else {
            ids.copy_from_slice(&self.rows[range.start * 32..range.end * 32]);
        }
        out.extend(
            ids.chunks_exact(32)
                .map(|id| Hash::try_from(id).expect("id width")),
        );
        Ok(())
    }

    /// Check that the pair is still the one this locator read. `checked` says
    /// a guarded walk found it exact already.
    fn confirm_pack(&self, file: &File, checked: bool) -> StoreResult<()> {
        if !checked && !self.check_current()? {
            // Reuse can touch a pack's timestamps without replacing it.
            let mut header = [0; HEADER_LEN];
            read_spooled(file, 0, &mut header).map_err(|e| self.pair.context(e))?;
            let header = read_version::<HEADER_LEN>(&mut header.as_slice(), *MAGIC, "local pack")
                .map_err(|e| self.pair.context(e))?;
            if le_u32(&header[8..]) as usize != self.count {
                return Err(self.pair.error("pack size or count changed"));
            }
        }
        Ok(())
    }

    fn frame_start(&self, frame: Frame) -> StoreResult<u64> {
        let (start, _) = frame
            .extent(self.trailer)
            .ok_or_else(|| self.pair.error("invalid frame extent"))?;
        Ok(start)
    }

    fn check_frame_len(&self, header: &[u8], frame: Frame) -> StoreResult<()> {
        let len = read_frame_header(&mut &*header).map_err(|e| self.pair.context(e))?;
        if len != frame.len {
            return Err(self.pair.error("index and pack disagree on frame length"));
        }
        Ok(())
    }

    pub(super) fn open_frame(&self, file: &File, frame: Frame, checked: bool) -> StoreResult<()> {
        self.confirm_pack(file, checked)?;
        let start = self.frame_start(frame)?;
        let mut header = [0; ENTRY_FRAME_LEN];
        read_spooled(file, start, &mut header).map_err(|e| self.pair.context(e))?;
        self.check_frame_len(&header, frame)
    }

    /// [`Self::open_frame`], then the first bytes of the payload up to
    /// `head.len()`, fewer when the frame is shorter: how many came. The frame
    /// header and those bytes come in one read. `None` when that read fails, so
    /// the caller reads the frame as it does without this path and a damaged
    /// pack gives the same error.
    pub(super) fn read_head(
        &self,
        file: &File,
        frame: Frame,
        checked: bool,
        head: &mut [u8],
    ) -> StoreResult<Option<usize>> {
        /// A head this short reads through the stack. A longer one, a whole
        /// small frame, reads through a buffer of its own size.
        const STACK_HEAD: usize = 16;
        self.confirm_pack(file, checked)?;
        let start = self.frame_start(frame)?;
        let len = head.len().min(frame.len as usize);
        let mut stack = [0; ENTRY_FRAME_LEN + STACK_HEAD];
        let mut large;
        let bytes = if len <= STACK_HEAD {
            &mut stack[..ENTRY_FRAME_LEN + len]
        } else {
            large = vec![0; ENTRY_FRAME_LEN + len];
            &mut large[..]
        };
        if read_spooled(file, start, bytes).is_err() {
            return Ok(None);
        }
        self.check_frame_len(&bytes[..ENTRY_FRAME_LEN], frame)?;
        head[..len].copy_from_slice(&bytes[ENTRY_FRAME_LEN..]);
        Ok(Some(len))
    }
}

/// The locators a guarded walk found current. A guard keeps a pair from being
/// retired while the walk runs, so one check per locator stands for every
/// read through it. The set holds each `Arc` it names, so an address is never
/// reused by another locator.
#[derive(Debug, Default)]
pub(crate) struct Currency {
    current: std::sync::RwLock<std::collections::HashMap<usize, Arc<Locator>>>,
}

impl Currency {
    fn key(locator: &Arc<Locator>) -> usize {
        Arc::as_ptr(locator) as usize
    }

    /// Whether the locator is current: from the set when it was found exact,
    /// otherwise by checking it. Only an exact match is remembered, so a pair
    /// whose timestamps moved is checked at every read. Threads that meet a
    /// locator for the first time wait for one check.
    fn check(&self, locator: &Arc<Locator>) -> StoreResult<bool> {
        let key = Self::key(locator);
        if self
            .current
            .read()
            .expect("currency set")
            .contains_key(&key)
        {
            return Ok(true);
        }
        let mut current = self.current.write().expect("currency set");
        if current.contains_key(&key) {
            return Ok(true);
        }
        let exact = locator.check_current()?;
        if exact {
            current.insert(key, Arc::clone(locator));
        }
        Ok(exact)
    }

    /// Check this locator again at its next read.
    pub(super) fn forget(&self, locator: &Arc<Locator>) {
        self.current
            .write()
            .expect("currency set")
            .remove(&Self::key(locator));
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Route {
    pub(super) prefix: u32,
    pub(super) pack: u32,
    pub(super) row: u32,
}

pub(super) fn prefix(id: &[u8]) -> u32 {
    u32::from_le_bytes(id[..4].try_into().expect("id prefix"))
}

/// Fill every buffer from the reader with as few calls as it takes.
pub(super) fn read_exact_vectored(
    file: &mut impl Read,
    mut buffers: &mut [IoSliceMut<'_>],
) -> io::Result<()> {
    IoSliceMut::advance_slices(&mut buffers, 0);
    while !buffers.is_empty() {
        match file.read_vectored(buffers) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => IoSliceMut::advance_slices(&mut buffers, n),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Never follow a link, and never wait on a pipe.
#[cfg(unix)]
const OPEN_FLAGS: i32 = libc::O_NOFOLLOW | libc::O_NONBLOCK;

/// Open a pack or index file. A symlink or any other kind of file is not a
/// member: report it as absent, without waiting on a pipe. Linux and macOS
/// report a refused symlink as `ELOOP`.
fn open_member(path: &Path) -> io::Result<(File, fs::Metadata)> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(OPEN_FLAGS);
    }
    #[cfg(not(unix))]
    if !fs::symlink_metadata(path)?.is_file() {
        return Err(io::Error::from(io::ErrorKind::NotFound));
    }
    let file = match options.open(path) {
        #[cfg(unix)]
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => {
            return Err(io::Error::from(io::ErrorKind::NotFound));
        }
        result => result?,
    };
    let metadata = file.metadata()?;
    if metadata.is_file() {
        Ok((file, metadata))
    } else {
        Err(io::Error::from(io::ErrorKind::NotFound))
    }
}
