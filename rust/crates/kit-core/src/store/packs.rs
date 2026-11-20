//! Local pack segments: many objects in one file, found through a sorted
//! index.
//!
//! A segment is two files under `objects/packs/`: `<id>.pack` holds object
//! bytes back to back, and `<id>.idx` lists where each object sits. The index
//! is renamed into place last, so an object in a segment is visible exactly
//! when its index is. A writer makes both files durable before that rename,
//! so a visible packed object is a durable one (SPEC-OBJECTS §10.1).
//!
//! Index layout, all integers little-endian:
//!
//! ```text
//! magic     8   "KITLPX01"
//! count     4   number of entries
//! pack_len  8   length of the .pack file
//! entries   count × (id 32, offset 8, len 4), ids strictly ascending
//! trailer   32  BLAKE3 of every byte before it
//! ```
//!
//! Every read still recomputes the object id, so a damaged segment fails the
//! read-time hash check like a damaged loose object.

use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::RwLock;

#[cfg(unix)]
use std::os::unix::fs::FileExt;

use crate::hash::{Hash, to_hex};

use super::{MAX_RAW_OBJECT_SIZE, StoreError, StoreResult};

/// The directory under `objects/` that holds segments.
pub(crate) const PACKS_DIR: &str = "packs";

const MAGIC: &[u8; 8] = b"KITLPX01";
const HEADER_LEN: usize = 8 + 4 + 8;
const ENTRY_LEN: usize = 32 + 8 + 4;
const TRAILER_LEN: usize = 32;

/// The largest index a reader accepts, checked before it allocates.
const MAX_INDEX_BYTES: u64 = 256 * 1024 * 1024;

/// One object's place in a segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Entry {
    pub(crate) id: Hash,
    pub(crate) offset: u64,
    pub(crate) len: u32,
}

/// Why an index was refused.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum IndexError {
    TooLarge,
    BadLength,
    BadMagic,
    NotSorted,
    OutOfRange,
    BadTrailer,
}

/// Encode an index for `entries` over a pack of `pack_len` bytes. Sorts the
/// entries by id; the caller passes distinct ids.
pub(crate) fn encode_index(entries: &mut [Entry], pack_len: u64) -> Vec<u8> {
    entries.sort_unstable_by_key(|e| e.id);
    let count = u32::try_from(entries.len()).expect("segment holds fewer than 2^32 objects");
    let mut out = Vec::with_capacity(HEADER_LEN + entries.len() * ENTRY_LEN + TRAILER_LEN);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&pack_len.to_le_bytes());
    for e in entries.iter() {
        out.extend_from_slice(&e.id);
        out.extend_from_slice(&e.offset.to_le_bytes());
        out.extend_from_slice(&e.len.to_le_bytes());
    }
    let trailer = blake3::hash(&out);
    out.extend_from_slice(trailer.as_bytes());
    out
}

/// Parse an index strictly: exact length, known magic, ids strictly
/// ascending, every range inside the pack and no larger than an object may
/// be, and a matching trailer.
pub(crate) fn decode_index(bytes: &[u8]) -> Result<(Vec<Entry>, u64), IndexError> {
    if bytes.len() as u64 > MAX_INDEX_BYTES {
        return Err(IndexError::TooLarge);
    }
    if bytes.len() < HEADER_LEN + TRAILER_LEN {
        return Err(IndexError::BadLength);
    }
    let (body, trailer) = bytes.split_at(bytes.len() - TRAILER_LEN);
    if &body[..8] != MAGIC {
        return Err(IndexError::BadMagic);
    }
    let count = u32::from_le_bytes(body[8..12].try_into().expect("4 bytes")) as usize;
    let pack_len = u64::from_le_bytes(body[12..20].try_into().expect("8 bytes"));
    let want = count
        .checked_mul(ENTRY_LEN)
        .and_then(|n| n.checked_add(HEADER_LEN))
        .ok_or(IndexError::BadLength)?;
    if body.len() != want {
        return Err(IndexError::BadLength);
    }
    if blake3::hash(body).as_bytes() != trailer {
        return Err(IndexError::BadTrailer);
    }
    let mut entries = Vec::with_capacity(count);
    for raw in body[HEADER_LEN..].chunks_exact(ENTRY_LEN) {
        let id: Hash = raw[..32].try_into().expect("32 bytes");
        let offset = u64::from_le_bytes(raw[32..40].try_into().expect("8 bytes"));
        let len = u32::from_le_bytes(raw[40..44].try_into().expect("4 bytes"));
        if len as usize > MAX_RAW_OBJECT_SIZE
            || offset
                .checked_add(u64::from(len))
                .is_none_or(|end| end > pack_len)
        {
            return Err(IndexError::OutOfRange);
        }
        if entries.last().is_some_and(|prev: &Entry| prev.id >= id) {
            return Err(IndexError::NotSorted);
        }
        entries.push(Entry { id, offset, len });
    }
    Ok((entries, pack_len))
}

#[derive(Debug)]
pub(crate) struct Segment {
    pub(crate) name: String,
    pub(crate) pack: File,
    pub(crate) entries: Vec<Entry>,
}

impl Segment {
    fn find(&self, h: &Hash) -> Option<&Entry> {
        self.entries
            .binary_search_by(|e| e.id.cmp(h))
            .ok()
            .map(|i| &self.entries[i])
    }
}

#[derive(Debug, Default)]
struct Loaded {
    segments: Vec<Segment>,
    /// The `packs/` directory's mtime and entry count at the last load. A
    /// lookup that misses reloads only when this changed.
    stamp: Option<(std::time::SystemTime, usize)>,
}

/// The segments of one store, loaded lazily and reloaded when a lookup
/// misses and the `packs/` directory changed.
#[derive(Debug)]
pub(crate) struct PackSet {
    dir: PathBuf,
    loaded: RwLock<Loaded>,
}

impl PackSet {
    pub(crate) fn new(objects_root: &Path) -> Self {
        Self {
            dir: objects_root.join(PACKS_DIR),
            loaded: RwLock::new(Loaded::default()),
        }
    }

    pub(crate) fn dir(&self) -> &Path {
        &self.dir
    }

    /// True when a visible segment holds `h`.
    pub(crate) fn contains(&self, h: &Hash) -> bool {
        self.locate(h).is_some()
    }

    /// Read `h`'s bytes from its segment, unverified; the caller checks the
    /// id. `None` when no segment holds it.
    pub(crate) fn read(&self, h: &Hash) -> Option<StoreResult<Vec<u8>>> {
        let loaded = self.loaded.read().expect("pack set poisoned");
        let found = loaded
            .segments
            .iter()
            .find_map(|s| s.find(h).map(|e| (s, *e)));
        if let Some((seg, e)) = found {
            return Some(read_at(&seg.pack, e));
        }
        drop(loaded);
        // Look again even when this thread loaded nothing: another thread
        // may have loaded the segment between the miss and the reload.
        self.reload_if_changed();
        let loaded = self.loaded.read().expect("pack set poisoned");
        loaded
            .segments
            .iter()
            .find_map(|s| s.find(h).map(|e| read_at(&s.pack, *e)))
    }

    /// The stored length of `h`, when a segment holds it.
    pub(crate) fn len(&self, h: &Hash) -> Option<u64> {
        self.locate(h).map(|e| u64::from(e.len))
    }

    fn locate(&self, h: &Hash) -> Option<Entry> {
        {
            let loaded = self.loaded.read().expect("pack set poisoned");
            if let Some(e) = loaded.segments.iter().find_map(|s| s.find(h)) {
                return Some(*e);
            }
        }
        self.reload_if_changed();
        let loaded = self.loaded.read().expect("pack set poisoned");
        loaded.segments.iter().find_map(|s| s.find(h)).copied()
    }

    /// Drop segment `name` from the loaded set, after gc removed it.
    pub(crate) fn forget(&self, name: &str) {
        let mut loaded = self.loaded.write().expect("pack set poisoned");
        loaded.segments.retain(|s| s.name != name);
        loaded.stamp = None;
    }

    /// Load any index that appeared since the last load.
    fn reload_if_changed(&self) {
        let Ok(meta) = fs::metadata(&self.dir) else {
            return;
        };
        let Ok(mtime) = meta.modified() else {
            return;
        };
        let Ok(names) = index_names(&self.dir) else {
            return;
        };
        let stamp = Some((mtime, names.len()));
        let mut loaded = self.loaded.write().expect("pack set poisoned");
        if loaded.stamp == stamp {
            return;
        }
        for name in names {
            if loaded.segments.iter().any(|s| s.name == name) {
                continue;
            }
            // An index that fails to load is skipped, not trusted: its
            // objects stay unresolved and a read reports them missing.
            if let Ok(seg) = load_segment(&self.dir, &name) {
                loaded.segments.push(seg);
            }
        }
        loaded.stamp = stamp;
    }
}

pub(crate) fn index_names(dir: &Path) -> io::Result<Vec<String>> {
    let mut out = Vec::new();
    let rd = match fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(e),
    };
    for ent in rd {
        let ent = ent?;
        let name = ent.file_name();
        let Some(name) = name.to_str() else { continue };
        if let Some(stem) = name.strip_suffix(".idx")
            && stem.len() == 64
            && stem.bytes().all(|b| b.is_ascii_hexdigit())
        {
            out.push(stem.to_owned());
        }
    }
    out.sort();
    Ok(out)
}

pub(crate) fn load_segment(dir: &Path, name: &str) -> StoreResult<Segment> {
    let idx = File::open(dir.join(format!("{name}.idx")))?;
    let size = idx.metadata()?.len();
    if size > MAX_INDEX_BYTES {
        return Err(StoreError::Io(io::Error::other("pack index too large")));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(size).unwrap_or(0));
    idx.take(MAX_INDEX_BYTES + 1).read_to_end(&mut bytes)?;
    let (entries, pack_len) = decode_index(&bytes)
        .map_err(|e| StoreError::Io(io::Error::other(format!("pack index {name}: {e:?}"))))?;
    let pack = File::open(dir.join(format!("{name}.pack")))?;
    if pack.metadata()?.len() != pack_len {
        return Err(StoreError::Io(io::Error::other(format!(
            "pack {name}: length differs from its index"
        ))));
    }
    Ok(Segment {
        name: name.to_owned(),
        pack,
        entries,
    })
}

#[cfg(unix)]
pub(crate) fn read_at(pack: &File, e: Entry) -> StoreResult<Vec<u8>> {
    let mut buf = vec![0u8; e.len as usize];
    pack.read_exact_at(&mut buf, e.offset)
        .map_err(|err| match err.kind() {
            io::ErrorKind::UnexpectedEof => StoreError::ObjectNotFound(to_hex(&e.id)),
            _ => StoreError::Io(err),
        })?;
    Ok(buf)
}

#[cfg(not(unix))]
pub(crate) fn read_at(_pack: &File, e: Entry) -> StoreResult<Vec<u8>> {
    Err(StoreError::ObjectNotFound(to_hex(&e.id)))
}

/// One index entry as the fuzz harness sees it: id, offset, length.
#[doc(hidden)]
pub type FuzzEntry = (Hash, u64, u32);

/// Decode a pack index for the fuzz harness: `(id, offset, len)` per
/// entry and the pack length, or `None` when the index is refused. Not a
/// stable API.
#[doc(hidden)]
#[must_use]
pub fn fuzz_decode_index(bytes: &[u8]) -> Option<(Vec<FuzzEntry>, u64)> {
    decode_index(bytes).ok().map(|(es, len)| {
        (
            es.into_iter().map(|e| (e.id, e.offset, e.len)).collect(),
            len,
        )
    })
}

/// Encode a pack index for the fuzz harness. Not a stable API.
#[doc(hidden)]
#[must_use]
pub fn fuzz_encode_index(entries: &[FuzzEntry], pack_len: u64) -> Vec<u8> {
    let mut es: Vec<Entry> = entries
        .iter()
        .map(|&(id, offset, len)| Entry { id, offset, len })
        .collect();
    encode_index(&mut es, pack_len)
}

/// A step of a segment's publish or removal, reported to a test hook so a
/// test can stop the sequence at any point, as a crash would.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Step {
    PackSynced,
    IndexSynced,
    PackRenamed,
    IndexRenamed,
    DirSynced,
    OldIndexRemoved,
    OldPackRemoved,
}

/// A hook that sees each [`Step`]. An error stops the sequence there and
/// leaves the files on disk as they are, as a crash would.
pub(crate) type StepHook<'a> = &'a mut dyn FnMut(Step) -> io::Result<()>;

/// Writes one segment front to back, then publishes it on the same durable
/// schedule as a write batch: both files flushed, the pack renamed, the
/// index renamed, the directory flushed. Used by gc's repack.
pub(crate) struct SegmentWriter {
    dir: PathBuf,
    pack: tempfile::NamedTempFile,
    len: u64,
    entries: Vec<Entry>,
}

impl SegmentWriter {
    pub(crate) fn new(dir: &Path) -> io::Result<Self> {
        fs::create_dir_all(dir)?;
        Ok(Self {
            dir: dir.to_path_buf(),
            pack: super::temp_file_in(dir, "segment")?,
            len: 0,
            entries: Vec::new(),
        })
    }

    pub(crate) fn append(&mut self, id: Hash, bytes: &[u8]) -> io::Result<()> {
        use std::io::Write;
        let len = u32::try_from(bytes.len()).map_err(|_| io::Error::other("object too large"))?;
        self.pack.as_file_mut().write_all(bytes)?;
        self.entries.push(Entry {
            id,
            offset: self.len,
            len,
        });
        self.len += u64::from(len);
        Ok(())
    }

    /// Make the segment durable, then visible. Returns its name.
    pub(crate) fn finish(mut self, hook: StepHook<'_>) -> io::Result<String> {
        use std::io::Write;
        self.pack.as_file().sync_data()?;
        let pack = self.pack.into_temp_path();
        if let Err(e) = hook(Step::PackSynced) {
            pack.keep().ok();
            return Err(e);
        }
        let idx = encode_index(&mut self.entries, self.len);
        let name = to_hex(blake3::hash(&idx).as_bytes());
        let mut idx_tmp = super::temp_file_in(&self.dir, "segment-index")?;
        idx_tmp.as_file_mut().write_all(&idx)?;
        // On macOS this is F_FULLFSYNC, which also flushes the pack's
        // pages pushed out above.
        idx_tmp.as_file().sync_all()?;
        let idx_tmp = idx_tmp.into_temp_path();
        let crash = |e, pack: tempfile::TempPath, idx: tempfile::TempPath| {
            pack.keep().ok();
            idx.keep().ok();
            Err(e)
        };
        if let Err(e) = hook(Step::IndexSynced) {
            return crash(e, pack, idx_tmp);
        }
        pack.persist(self.dir.join(format!("{name}.pack")))
            .map_err(|e| e.error)?;
        if let Err(e) = hook(Step::PackRenamed) {
            idx_tmp.keep().ok();
            return Err(e);
        }
        idx_tmp
            .persist(self.dir.join(format!("{name}.idx")))
            .map_err(|e| e.error)?;
        hook(Step::IndexRenamed)?;
        crate::atomic::sync_parent_dir(&self.dir)?;
        hook(Step::DirSynced)?;
        Ok(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(b: u8, offset: u64, len: u32) -> Entry {
        Entry {
            id: [b; 32],
            offset,
            len,
        }
    }

    #[test]
    fn index_round_trips_sorted() {
        let mut es = vec![entry(9, 10, 5), entry(1, 0, 10)];
        let bytes = encode_index(&mut es, 15);
        let (got, len) = decode_index(&bytes).unwrap();
        assert_eq!(len, 15);
        assert_eq!(got, vec![entry(1, 0, 10), entry(9, 10, 5)]);
    }

    #[test]
    fn index_rejects_damage() {
        let mut es = vec![entry(1, 0, 10), entry(2, 10, 5)];
        let good = encode_index(&mut es, 15);
        let mut flipped = good.clone();
        flipped[25] ^= 1;
        assert_eq!(decode_index(&flipped), Err(IndexError::BadTrailer));
        assert_eq!(
            decode_index(&good[..good.len() - 1]),
            Err(IndexError::BadLength)
        );
        let mut trailing = good.clone();
        trailing.push(0);
        assert!(decode_index(&trailing).is_err());
    }

    #[test]
    fn index_rejects_ranges_past_the_pack() {
        let mut es = vec![entry(1, 10, 6)];
        assert_eq!(
            decode_index(&encode_index(&mut es, 15)),
            Err(IndexError::OutOfRange)
        );
    }

    #[test]
    fn index_rejects_duplicate_ids() {
        let mut es = vec![entry(1, 0, 1), entry(1, 1, 1)];
        assert_eq!(
            decode_index(&encode_index(&mut es, 2)),
            Err(IndexError::NotSorted)
        );
    }
}
