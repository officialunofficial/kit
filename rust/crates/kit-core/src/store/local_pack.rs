use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::hash::{Hash, to_hex};

use super::{ObjectStore, StoreError, StoreResult, format};

mod gc;
mod index;
#[cfg(feature = "fuzzing")]
pub(super) use index::fuzz_index;
use index::{Frame, Index, Pair, open_regular};
pub(super) use index::{canonical_id, invalid};

#[cfg(test)]
mod tests;
mod writer;
pub use writer::LocalPackWriter;

const CACHE_BYTES: usize = 64 * 1024 * 1024;
const CACHE_ENTRIES: usize = 64;

#[derive(Debug)]
pub(super) struct LocalPacks {
    enabled: AtomicBool,
    known: Mutex<Vec<Arc<Index>>>,
}

impl LocalPacks {
    pub(super) fn new(enabled: bool) -> Self {
        Self {
            enabled: AtomicBool::new(enabled),
            known: Mutex::new(Vec::new()),
        }
    }

    fn refresh_enabled(&self, store: &ObjectStore) -> StoreResult<bool> {
        if !self.enabled.load(Ordering::Relaxed) {
            let enabled = format::check(&store.format_path())?;
            if enabled {
                self.enabled.store(true, Ordering::Relaxed);
            }
            return Ok(enabled || self.enabled.load(Ordering::Relaxed));
        }
        Ok(true)
    }

    fn remember(&self, index: Arc<Index>) {
        if index.byte_len() > CACHE_BYTES {
            return;
        }
        let mut known = self.known.lock().expect("local pack cache mutex");
        known.retain(|old| old.pair.key != index.pair.key);
        let mut bytes = index.byte_len() + known.iter().map(|i| i.byte_len()).sum::<usize>();
        while bytes > CACHE_BYTES || known.len() >= CACHE_ENTRIES {
            bytes -= known.pop().expect("cache exceeds capacity").byte_len();
        }
        known.insert(0, index);
    }

    fn forget(&self, key: &Hash) {
        self.known
            .lock()
            .expect("local pack cache mutex")
            .retain(|i| i.pair.key != *key);
    }

    pub(super) fn collect(
        &self,
        store: &ObjectStore,
        shard: Option<u8>,
        out: &mut Vec<Hash>,
    ) -> StoreResult<()> {
        if self.refresh_enabled(store)? {
            visit_pairs(&store.pack_dir(), |pair| {
                let index = Arc::new(Index::open(&pair)?);
                out.extend(index.ids(shard));
                self.remember(index);
                Ok(())
            })?;
        }
        Ok(())
    }

    /// Resolve known indexed locations, then the loose path, then any pair
    /// discovered by a fresh scan. Stop at the first copy the caller accepts.
    pub(super) fn lookup<T>(
        &self,
        store: &ObjectStore,
        id: &Hash,
        refresh: bool,
        mut use_location: impl FnMut(Location) -> StoreResult<T>,
    ) -> StoreResult<T> {
        let mut error = None;
        let mut mismatch = None;
        let mut attempt = |location| match use_location(location) {
            Ok(value) => Ok(Some(value)),
            Err(e @ StoreError::IncompatibleRepoFormat { .. }) => Err(e),
            Err(e) if is_disappeared(&e) => Ok(None),
            Err(e @ StoreError::HashMismatch { .. }) => {
                mismatch.get_or_insert(e);
                Ok(None)
            }
            Err(e) => {
                error.get_or_insert(e);
                Ok(None)
            }
        };
        let known = self.known.lock().expect("local pack cache mutex").clone();
        for index in &known {
            let Some(frame) = index.find(id) else {
                continue;
            };
            if let Some(value) = attempt(Location::Packed(Arc::clone(index), frame))? {
                return Ok(value);
            }
        }
        let loose = store.path_for(id);
        if let Some(value) = attempt(Location::Loose(loose))? {
            return Ok(value);
        }
        let mut found = None;
        let mut pair_error = None;
        if refresh && self.refresh_enabled(store)? {
            let dir = store.pack_dir();
            visit_pairs_until(&dir, |pair| {
                if known
                    .iter()
                    .any(|index| index.pair.key == pair.key && index.unchanged())
                {
                    return Ok(false);
                }
                let index = match Index::open(&pair) {
                    Ok(index) => Arc::new(index),
                    Err(e @ StoreError::IncompatibleRepoFormat { .. }) => return Err(e),
                    Err(e) => {
                        pair_error.get_or_insert(e);
                        return Ok(false);
                    }
                };
                let frame = index.find(id);
                self.remember(Arc::clone(&index));
                if let Some(frame) = frame {
                    found = attempt(Location::Packed(index, frame))?;
                }
                Ok(found.is_some())
            })?;
        }
        found.ok_or_else(|| {
            mismatch
                .or(error)
                .or(pair_error)
                .unwrap_or_else(|| StoreError::ObjectNotFound(to_hex(id)))
        })
    }
}

fn is_disappeared(err: &StoreError) -> bool {
    matches!(err, StoreError::Io(e) if e.kind() == io::ErrorKind::NotFound)
}

#[derive(Debug)]
pub(super) enum Location {
    Loose(PathBuf),
    Packed(Arc<Index>, Frame),
}

impl Location {
    pub(super) fn path(&self) -> &Path {
        match self {
            Self::Loose(path) => path,
            Self::Packed(index, _) => &index.pair.pack,
        }
    }

    pub(super) fn is_packed(&self) -> bool {
        matches!(self, Self::Packed(..))
    }

    pub(super) fn open(&self) -> StoreResult<Contents> {
        match self {
            Self::Loose(path) => {
                let file = File::open(path)?;
                let len = file.metadata()?.len();
                Ok(Contents {
                    file,
                    packed_len: None,
                    len,
                })
            }
            Self::Packed(index, frame) => {
                // A disappeared member invalidates the cached location.
                index.check_index_version()?;
                let file = index.open_frame(*frame)?;
                let len = u64::from(frame.len);
                Ok(Contents {
                    file,
                    packed_len: Some(len),
                    len,
                })
            }
        }
    }

    pub(super) fn size(&self) -> StoreResult<u64> {
        match self {
            Self::Loose(path) => Ok(fs::metadata(path)?.len()),
            Self::Packed(..) => Ok(self.open()?.len),
        }
    }

    pub(super) fn present(&self) -> StoreResult<()> {
        if let Self::Loose(path) = self {
            return if fs::metadata(path)?.is_file() {
                Ok(())
            } else {
                Err(io::Error::from(io::ErrorKind::NotFound).into())
            };
        }
        self.open().map(|_| ())
    }
}

pub(super) struct Contents {
    file: File,
    packed_len: Option<u64>,
    pub(super) len: u64,
}

impl Read for Contents {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let Some(remaining) = &mut self.packed_len else {
            return self.file.read(bytes);
        };
        let limit = (*remaining).min(bytes.len() as u64);
        let read = self
            .file
            .read(&mut bytes[..usize::try_from(limit).expect("limited to slice length")])?;
        *remaining -= read as u64;
        Ok(read)
    }
}

fn visit_pairs(dir: &Path, mut visit: impl FnMut(Pair) -> StoreResult<()>) -> StoreResult<()> {
    visit_pairs_until(dir, |pair| {
        visit(pair)?;
        Ok(false)
    })
}

fn regular(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(meta) => Ok(meta.is_file()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

fn pair_is_live(pair: &Pair) -> io::Result<bool> {
    Ok(regular(&pair.pack)? && regular(&pair.index)?)
}

fn read_pack_dir(dir: &Path) -> io::Result<Option<fs::ReadDir>> {
    match fs::symlink_metadata(dir) {
        Ok(meta) if meta.is_dir() => fs::read_dir(dir).map(Some),
        Ok(_) => Err(index::invalid("local pack directory is not a directory")),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

fn visit_pairs_until(
    dir: &Path,
    mut visit: impl FnMut(Pair) -> StoreResult<bool>,
) -> StoreResult<()> {
    let Some(entries) = read_pack_dir(dir)? else {
        return Ok(());
    };
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let Some(pair) = name
            .to_str()
            .and_then(|name| Pair::from_pack_name(dir, name))
        else {
            continue;
        };
        if pair_is_live(&pair)? && visit(pair)? {
            break;
        }
    }
    Ok(())
}

pub(super) fn check_live_pack_versions(objects: &Path) -> StoreResult<()> {
    visit_pairs(&objects.join("pack"), |pair| pair.check_versions())
}

fn matching_index(pair: &Pair, rows: &[(Hash, Frame)]) -> StoreResult<bool> {
    match Index::open(pair) {
        Ok(index) => Ok(index.matches(rows)),
        Err(e @ StoreError::IncompatibleRepoFormat { .. }) => Err(e),
        Err(_) => Ok(false),
    }
}

fn scan_pair(pair: &Pair) -> StoreResult<Vec<(Hash, Frame)>> {
    let (key, rows) = index::scan(&mut open_regular(&pair.pack)?).map_err(|e| pair.context(e))?;
    if key != pair.key {
        return Err(pair.error("pack key does not match filename"));
    }
    Ok(rows)
}

fn stage_index(
    dir: &Path,
    pair: &Pair,
    pack: &Path,
    rows: &[(Hash, Frame)],
) -> StoreResult<tempfile::NamedTempFile> {
    let mut tmp = stage_file(dir, ".tmp.idx")?;
    tmp.write_all(&index::encode(pair.key, rows))?;
    tmp.as_file().sync_all()?;
    let staged = Pair {
        key: pair.key,
        pack: pack.to_path_buf(),
        index: tmp.path().to_path_buf(),
    };
    if !Index::open(&staged)?.matches(rows) {
        return Err(pair.error("staged index does not match pack"));
    }
    Ok(tmp)
}

fn stage_file(dir: &Path, suffix: &str) -> io::Result<tempfile::NamedTempFile> {
    stage_file_with_nonce(dir, suffix, || {
        let mut nonce = [0; 16];
        getrandom::fill(&mut nonce).map_err(|e| io::Error::other(e.to_string()))?;
        Ok(u128::from_le_bytes(nonce))
    })
}

fn stage_file_with_nonce(
    dir: &Path,
    suffix: &str,
    mut next_nonce: impl FnMut() -> io::Result<u128>,
) -> io::Result<tempfile::NamedTempFile> {
    // The random part is formatted as hex for the orphan sweep's name rule.
    loop {
        let nonce = next_nonce()?;
        let name = format!(".{nonce:032x}{suffix}");
        let path = dir.join(name);
        match fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)
        {
            Ok(file) => {
                return Ok(tempfile::NamedTempFile::from_parts(
                    file,
                    tempfile::TempPath::try_from_path(path)?,
                ));
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
    }
}

impl ObjectStore {
    pub(super) fn format_path(&self) -> PathBuf {
        self.objects_root.with_file_name(super::FORMAT_FILE)
    }

    /// Try the one-way local-pack activation before taking a prune guard.
    /// Contention and readable noncanonical legacy markers leave it loose.
    ///
    /// # Errors
    /// An unreadable, incompatible or unwritable format marker.
    #[doc(hidden)]
    pub fn try_activate_local_packs(&self) -> StoreResult<()> {
        format::try_activate(&self.format_path())
    }

    /// Check whether the current marker selects packed storage.
    ///
    /// # Errors
    /// An unreadable or incompatible marker.
    #[doc(hidden)]
    pub fn local_packs_enabled(&self) -> StoreResult<bool> {
        self.packs.refresh_enabled(self)
    }

    /// Check the marker on the handle that holds the shared prune guard.
    ///
    /// # Errors
    /// An unreadable or incompatible format marker.
    #[doc(hidden)]
    pub fn local_packs_active(&self, guard: &super::PruneGuard) -> StoreResult<bool> {
        self.check_prune_guard(guard)?;
        format::packed_under_guard(guard)
    }

    fn check_prune_guard(&self, guard: &super::PruneGuard) -> StoreResult<()> {
        if guard.objects_root != self.objects_root {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "prune guard belongs to a different object store",
            )
            .into());
        }
        Ok(())
    }

    fn pack_dir(&self) -> PathBuf {
        self.objects_root.join("pack")
    }

    /// Check each published local pack and its index. In repair mode,
    /// replace a damaged locator only after checking its entire pack.
    /// Returns the number of rebuilt indexes.
    ///
    /// # Errors
    /// A corrupt pack, an invalid index in check-only mode, a busy repair
    /// lock, or a filesystem failure prevents a complete scan.
    pub fn check_local_packs(&self, repair: bool) -> StoreResult<usize> {
        if !self.packs.refresh_enabled(self)? {
            return Ok(0);
        }
        let dir = self.pack_dir();
        let mut rebuilt = 0;
        visit_pairs(&dir, |pair| {
            pair.check_versions()?;
            let rows = scan_pair(&pair)?;
            if matching_index(&pair, &rows)? {
                return Ok(());
            }
            if !repair {
                return Err(pair.error("index does not match verified pack"));
            }

            drop(rows);
            let lock = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(self.format_path())?;
            lock.try_lock().map_err(io::Error::from)?;
            // Reopen under the lock so a retired pack cannot be resurrected.
            if !pair_is_live(&pair)? {
                return Ok(());
            }
            pair.check_versions()?;
            let rows = scan_pair(&pair)?;
            if matching_index(&pair, &rows)? {
                return Ok(());
            }
            let tmp = stage_index(&dir, &pair, &pair.pack, &rows)?;
            super::sync_reused_file(&pair.pack)?;
            crate::atomic::sync_dir(&dir)?;
            tmp.persist(&pair.index).map_err(|e| e.error)?;
            crate::atomic::sync_dir(&dir)?;
            self.packs.forget(&pair.key);
            rebuilt += 1;
            Ok(())
        })?;
        Ok(rebuilt)
    }
}
