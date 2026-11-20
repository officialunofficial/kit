use std::collections::BTreeMap;
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

mod reader;
#[cfg(test)]
mod tests;
mod writer;
use reader::{Handles, Locator, Member, ROUTE_CACHE_BYTES, ROW_CACHE_BYTES, Route, prefix};
pub use writer::LocalPackWriter;

#[derive(Debug, Default)]
struct Catalog {
    error: Option<Arc<StoreError>>,
    packs: Vec<Arc<Locator>>,
    routes: Vec<Route>,
    on_disk: Vec<usize>,
}

impl Catalog {
    fn from_packs(packs: Vec<Arc<Locator>>, error: Option<StoreError>) -> Self {
        let mut routes = Vec::with_capacity(packs.iter().map(|p| p.route_count()).sum());
        let mut on_disk = Vec::new();
        for (number, pack) in packs.iter().enumerate() {
            if pack.route_count() == 0 {
                on_disk.push(number);
            } else {
                routes.extend(pack.routes(number));
            }
        }
        routes.sort_unstable_by_key(|route| (route.prefix, route.pack));
        Self {
            error: error.map(Arc::new),
            packs,
            routes,
            on_disk,
        }
    }

    fn candidates(&self, id: &Hash) -> impl Iterator<Item = (&Arc<Locator>, Option<usize>)> {
        let prefix = prefix(id);
        let start = self.routes.partition_point(|route| route.prefix < prefix);
        self.routes[start..]
            .iter()
            .take_while(move |route| route.prefix == prefix)
            .map(|route| (&self.packs[route.pack as usize], Some(route.row as usize)))
            .chain(self.on_disk.iter().map(|&pack| (&self.packs[pack], None)))
    }
}

#[derive(Debug, Default)]
struct Discovery {
    catalog: Arc<Catalog>,
    latest: Option<Arc<Locator>>,
    dir: Option<index::Stamp>,
    scanned: bool,
}

#[derive(Debug)]
pub(super) struct LocalPacks {
    enabled: AtomicBool,
    discovery: Mutex<Discovery>,
    handles: Handles,
    #[cfg(test)]
    index_loads: std::sync::atomic::AtomicUsize,
}

impl LocalPacks {
    pub(super) fn new(enabled: bool) -> Self {
        Self {
            enabled: AtomicBool::new(enabled),
            discovery: Mutex::default(),
            handles: Handles::default(),
            #[cfg(test)]
            index_loads: std::sync::atomic::AtomicUsize::new(0),
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

    fn forget(&self, key: &Hash) {
        let mut discovery = self.discovery.lock().expect("local pack catalog mutex");
        discovery.scanned = false;
        if discovery
            .latest
            .as_ref()
            .is_some_and(|pack| pack.pair.key == *key)
        {
            discovery.latest = None;
        }
        self.handles.retain(|locator| locator.pair.key != *key);
    }

    fn remember_publication(&self, pair: &Pair) {
        // A writer frequently reads back the pair it just sealed. Keep
        // its locator until discovery sees it without rebuilding on hits.
        if let Ok(locator) = Locator::open(pair, 0, 0) {
            let mut discovery = self.discovery.lock().expect("local pack catalog mutex");
            discovery.latest = Some(Arc::new(locator));
            discovery.scanned = false;
        }
    }

    fn discover(&self, dir: &Path, force: bool) -> StoreResult<Arc<Catalog>> {
        let mut discovery = self.discovery.lock().expect("local pack catalog mutex");
        let stamp = match fs::symlink_metadata(dir) {
            Ok(meta) if meta.is_dir() => Some(index::Stamp::get(&meta)?),
            Ok(_) => return Err(index::invalid("local pack directory is not a directory").into()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        // A publication changes ctime even when mtime is restored. A
        // recent ctime may share its filesystem tick with a later publish.
        if !force && discovery.scanned && discovery.dir == stamp {
            return Ok(Arc::clone(&discovery.catalog));
        }
        let settled = stamp.as_ref().is_none_or(index::Stamp::settled);
        let old: BTreeMap<_, _> = discovery
            .catalog
            .packs
            .iter()
            .map(|p| (p.pair.key, p))
            .collect();
        let mut pairs = Vec::new();
        visit_pairs(dir, |pair| {
            pairs.push(pair);
            Ok(())
        })?;
        pairs.sort_unstable_by_key(|pair| pair.key);

        let mut row_budget = ROW_CACHE_BYTES;
        let mut route_budget = ROUTE_CACHE_BYTES;
        for locator in pairs.iter().filter_map(|pair| old.get(&pair.key)) {
            row_budget -= locator.row_charge();
            route_budget -= locator.route_charge();
        }
        let mut packs = Vec::with_capacity(pairs.len());
        let mut error = None;
        for pair in pairs {
            let retained = old.get(&pair.key);
            let locator = if let Some(locator) = retained.filter(|p| p.check_current().is_ok()) {
                Arc::clone(locator)
            } else {
                if let Some(locator) = retained {
                    row_budget += locator.row_charge();
                    route_budget += locator.route_charge();
                }
                #[cfg(test)]
                self.index_loads.fetch_add(1, Ordering::Relaxed);
                match Locator::open(&pair, row_budget, route_budget) {
                    Ok(locator) => {
                        row_budget -= locator.row_charge();
                        route_budget -= locator.route_charge();
                        Arc::new(locator)
                    }
                    Err(e @ StoreError::IncompatibleRepoFormat { .. }) => return Err(e),
                    Err(e) if is_disappeared(&e) => continue,
                    Err(e) => {
                        error.get_or_insert(e);
                        continue;
                    }
                }
            };
            packs.push(locator);
        }
        discovery.scanned = settled;
        discovery.dir = stamp;
        if packs.len() == discovery.catalog.packs.len()
            && packs
                .iter()
                .zip(&discovery.catalog.packs)
                .all(|(new, old)| Arc::ptr_eq(new, old))
            && error.is_none()
            && discovery.catalog.error.is_none()
        {
            return Ok(Arc::clone(&discovery.catalog));
        }
        self.handles.retain(|locator| {
            packs
                .binary_search_by_key(&locator.pair.key, |p| p.pair.key)
                .is_ok_and(|i| Arc::ptr_eq(&packs[i], locator))
        });
        discovery.latest = None;
        discovery.catalog = Arc::new(Catalog::from_packs(packs, error));
        Ok(Arc::clone(&discovery.catalog))
    }

    pub(super) fn collect(
        &self,
        store: &ObjectStore,
        shard: Option<u8>,
        out: &mut Vec<Hash>,
    ) -> StoreResult<()> {
        if self.refresh_enabled(store)? {
            visit_pairs(&store.pack_dir(), |pair| {
                let index = Index::open(&pair)?;
                out.extend(index.ids(shard));
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
        let (known, latest) = {
            let discovery = self.discovery.lock().expect("local pack catalog mutex");
            (Arc::clone(&discovery.catalog), discovery.latest.clone())
        };
        let mut errors = LookupErrors::default();
        if let Some(pack) = latest
            && let Some(value) = self.try_pack(&pack, id, None, &mut errors, &mut use_location)?
        {
            return Ok(value);
        }
        if let Some(value) = self.try_catalog(&known, id, None, &mut errors, &mut use_location)? {
            return Ok(value);
        }
        if let Some(value) = errors.attempt(use_location(Location::Loose(store.path_for(id))))? {
            return Ok(value);
        }
        let mut pair_error = None;
        if refresh && self.refresh_enabled(store)? {
            let fresh = self.discover(&store.pack_dir(), errors.stale)?;
            pair_error = fresh.error.as_ref().map(|error| {
                StoreError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    Arc::clone(error),
                ))
            });
            if !Arc::ptr_eq(&known, &fresh)
                && let Some(value) =
                    self.try_catalog(&fresh, id, Some(&known), &mut errors, &mut use_location)?
            {
                return Ok(value);
            }
        }
        Err(errors
            .mismatch
            .or(errors.error)
            .or(pair_error)
            .unwrap_or_else(|| StoreError::ObjectNotFound(to_hex(id))))
    }

    fn try_catalog<T>(
        &self,
        catalog: &Catalog,
        id: &Hash,
        checked: Option<&Catalog>,
        errors: &mut LookupErrors,
        use_location: &mut impl FnMut(Location) -> StoreResult<T>,
    ) -> StoreResult<Option<T>> {
        for (locator, row) in catalog.candidates(id) {
            if checked.is_some_and(|old| old.candidates(id).any(|(p, _)| Arc::ptr_eq(p, locator))) {
                continue;
            }
            if let Some(value) = self.try_pack(locator, id, row, errors, use_location)? {
                return Ok(Some(value));
            }
        }
        Ok(None)
    }

    fn try_pack<T>(
        &self,
        locator: &Arc<Locator>,
        id: &Hash,
        row: Option<usize>,
        errors: &mut LookupErrors,
        use_location: &mut impl FnMut(Location) -> StoreResult<T>,
    ) -> StoreResult<Option<T>> {
        let value = (|| {
            let Some(frame) = locator.find(&self.handles, id, row)? else {
                return Ok(None);
            };
            let file = self.handles.get(locator, Member::Pack)?;
            use_location(Location::Packed(Arc::clone(locator), frame, file)).map(Some)
        })();
        if value.as_ref().is_err_and(is_disappeared) {
            errors.stale = true;
        }
        Ok(errors.attempt(value)?.flatten())
    }
}

#[derive(Default)]
struct LookupErrors {
    mismatch: Option<StoreError>,
    error: Option<StoreError>,
    stale: bool,
}

impl LookupErrors {
    fn attempt<T>(&mut self, value: StoreResult<T>) -> StoreResult<Option<T>> {
        match value {
            Ok(value) => Ok(Some(value)),
            Err(e @ StoreError::IncompatibleRepoFormat { .. }) => Err(e),
            Err(e) if is_disappeared(&e) => Ok(None),
            Err(e @ StoreError::HashMismatch { .. }) => {
                self.mismatch.get_or_insert(e);
                Ok(None)
            }
            Err(e) => {
                self.error.get_or_insert(e);
                Ok(None)
            }
        }
    }
}

fn is_disappeared(err: &StoreError) -> bool {
    matches!(err, StoreError::Io(e) if e.kind() == io::ErrorKind::NotFound)
}

#[derive(Debug)]
pub(super) enum Location {
    Loose(PathBuf),
    Packed(Arc<Locator>, Frame, Arc<File>),
}

impl Location {
    pub(super) fn path(&self) -> &Path {
        match self {
            Self::Loose(path) => path,
            Self::Packed(index, ..) => &index.pair.pack,
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
                    source: Source::Loose(file),
                    len,
                })
            }
            Self::Packed(index, frame, file) => {
                index.open_frame(file, *frame)?;
                Ok(Contents {
                    source: Source::Packed {
                        file: Arc::clone(file),
                        offset: frame.offset,
                        remaining: usize::try_from(frame.len).expect("bounded frame length"),
                    },
                    len: u64::from(frame.len),
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
    source: Source,
    pub(super) len: u64,
}

enum Source {
    Loose(File),
    Packed {
        file: Arc<File>,
        offset: u64,
        remaining: usize,
    },
}

impl Read for Contents {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        match &mut self.source {
            Source::Loose(file) => file.read(bytes),
            Source::Packed {
                file,
                offset,
                remaining,
            } => {
                let len = (*remaining).min(bytes.len());
                crate::pack::read_spooled(file, *offset, &mut bytes[..len])?;
                *offset += len as u64;
                *remaining -= len;
                Ok(len)
            }
        }
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

fn matching_index(pair: &Pair, rows: &[(Hash, Frame)]) -> StoreResult<bool> {
    match Index::open(pair) {
        Ok(index) => Ok(index.matches(rows)),
        Err(e @ StoreError::IncompatibleRepoFormat { .. }) => Err(e),
        Err(_) => Ok(false),
    }
}

fn scan_pair(pair: &Pair) -> StoreResult<Vec<(Hash, Frame)>> {
    #[cfg(test)]
    tests::pack_scan_error(pair.key)?;
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
