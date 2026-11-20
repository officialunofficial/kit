use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use crate::hash::{Hash, from_hex, to_hex};
use crate::object::{Object, ObjectType, id_from_object};
use crate::pack::{
    ENTRY_FRAME_LEN, HEADER_LEN, MAGIC, MAX_ENTRIES, MAX_TOTAL_PAYLOAD, TRAILER_LEN,
};
use crate::serialize;

use super::super::{MAX_RAW_OBJECT_SIZE, StoreError, StoreResult, read_header_prefix};

const MAGIC_INDEX: &[u8; 4] = b"KITX";
const FANOUT_END: usize = 12 + 256 * 4;
const INDEX_BASE_LEN: usize = FANOUT_END + 64;
const INDEX_ROW_LEN: usize = 44;
const FRAME_LEN: u64 = ENTRY_FRAME_LEN as u64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::store) struct Frame {
    pub(super) offset: u64,
    pub(super) len: u32,
}

impl Frame {
    fn extent(self, trailer: u64) -> Option<(u64, u64)> {
        let start = self.offset.checked_sub(FRAME_LEN)?;
        let end = self.offset.checked_add(u64::from(self.len))?;
        (start >= HEADER_LEN as u64
            && end <= trailer
            && (6..=MAX_RAW_OBJECT_SIZE).contains(&(self.len as usize)))
        .then_some((start, end))
    }
}

#[derive(Clone, Debug)]
pub(super) struct Pair {
    pub(super) key: Hash,
    pub(super) pack: PathBuf,
    pub(super) index: PathBuf,
}

impl Pair {
    pub(super) fn new(dir: &Path, key: Hash) -> Self {
        let name = to_hex(&key);
        Self {
            key,
            pack: dir.join(format!("{name}.pack")),
            index: dir.join(format!("{name}.idx")),
        }
    }

    pub(super) fn from_pack_name(dir: &Path, name: &str) -> Option<Self> {
        let key = name.strip_suffix(".pack")?;
        if key.bytes().any(|b| b.is_ascii_uppercase()) {
            return None;
        }
        Some(Self::new(dir, from_hex(key).ok()?))
    }

    pub(super) fn error(&self, error: impl std::fmt::Display) -> StoreError {
        invalid(format!("local pack {}: {error}", self.pack.display())).into()
    }

    pub(super) fn context(&self, error: StoreError) -> StoreError {
        match error {
            StoreError::IncompatibleRepoFormat { found } => StoreError::IncompatibleRepoFormat {
                found: found.map(|format| format!("{format} in {}", self.pack.display())),
            },
            other => self.error(other),
        }
    }

    pub(super) fn check_versions(&self) -> StoreResult<()> {
        for (path, magic, kind) in [
            (&self.pack, *MAGIC, "local pack"),
            (&self.index, *MAGIC_INDEX, "local index"),
        ] {
            if let Err(error @ StoreError::IncompatibleRepoFormat { .. }) = open_regular(path)
                .map_err(StoreError::from)
                .and_then(|mut file| read_version::<8>(&mut file, magic, kind))
            {
                return Err(self.context(error));
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
pub(in crate::store) struct Index {
    pub(super) pair: Pair,
    bytes: Vec<u8>,
    count: usize,
    trailer: u64,
    stamp: Option<IndexStamp>,
}

#[derive(Debug, PartialEq, Eq)]
struct IndexStamp {
    modified: std::time::SystemTime,
    len: u64,
    #[cfg(unix)]
    identity: (u64, u64),
}

impl IndexStamp {
    fn get(metadata: &fs::Metadata) -> io::Result<Self> {
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt;

        Ok(Self {
            modified: metadata.modified()?,
            len: metadata.len(),
            #[cfg(unix)]
            identity: (metadata.dev(), metadata.ino()),
        })
    }
}

impl Index {
    pub(super) fn open(pair: &Pair) -> StoreResult<Self> {
        Self::load(pair).or_else(|error| {
            // A damaged member can hide the other member's version.
            if !matches!(error, StoreError::IncompatibleRepoFormat { .. }) {
                pair.check_versions()?;
            }
            Err(pair.context(error))
        })
    }

    fn load(pair: &Pair) -> StoreResult<Self> {
        let mut pack = open_regular(&pair.pack)?;
        let (count, trailer, _) = read_header(&mut pack)?;
        let mut file = open_regular(&pair.index)?;
        let prefix = read_version::<8>(&mut file, *MAGIC_INDEX, "local index")?;
        let size = INDEX_BASE_LEN + INDEX_ROW_LEN * count;
        let metadata = file.metadata()?;
        if metadata.len() != size as u64 {
            return Err(invalid("index length does not match frame count").into());
        }
        let mut bytes = vec![0; size];
        bytes[..prefix.len()].copy_from_slice(&prefix);
        file.read_exact(&mut bytes[prefix.len()..])?;
        if file.read(&mut [0])? != 0 {
            return Err(invalid("trailing index bytes").into());
        }
        let mut index = Self::decode(pair.clone(), bytes, count, trailer)?;
        index.stamp = IndexStamp::get(&metadata).ok();
        Ok(index)
    }

    fn decode(pair: Pair, bytes: Vec<u8>, count: usize, trailer: u64) -> io::Result<Self> {
        if !frame_count_is_supported(count) || bytes.len() != INDEX_BASE_LEN + INDEX_ROW_LEN * count
        {
            return Err(invalid("index length does not match frame count"));
        }
        let index = Self {
            pair,
            bytes,
            count,
            trailer,
            stamp: None,
        };
        index.validate()?;
        Ok(index)
    }

    pub(super) fn byte_len(&self) -> usize {
        self.bytes.len()
    }

    pub(super) fn unchanged(&self) -> bool {
        if let Some(stamp) = &self.stamp
            && let Ok(metadata) = fs::symlink_metadata(&self.pair.index)
            && metadata.is_file()
            && let Ok(current) = IndexStamp::get(&metadata)
        {
            return current == *stamp;
        }
        false
    }

    fn validate(&self) -> io::Result<()> {
        let bytes = &self.bytes;
        if &bytes[..4] != MAGIC_INDEX || le_u32(&bytes[4..8]) != 1 {
            return Err(invalid("invalid index magic or version"));
        }
        if le_u32(&bytes[8..12]) as usize != self.count {
            return Err(invalid("index count differs from pack count"));
        }
        let key_at = bytes.len() - 64;
        let checksum_at = bytes.len() - 32;
        if bytes[key_at..checksum_at] != self.pair.key {
            return Err(invalid("index key differs from filename"));
        }
        if blake3::hash(&bytes[..checksum_at]).as_bytes() != &bytes[checksum_at..] {
            return Err(invalid("index checksum mismatch"));
        }
        if (1..self.count).any(|i| self.id(i - 1) >= self.id(i)) {
            return Err(invalid("index ids must be strictly increasing"));
        }
        let mut end = 0;
        for shard in 0..=u8::MAX {
            while end < self.count && self.id(end)[0] == shard {
                end += 1;
            }
            if self.fanout(shard) != end {
                return Err(invalid("index fanout does not match ids"));
            }
        }
        let mut rows: Vec<u32> =
            (0..u32::try_from(self.count).expect("bounded frame count")).collect();
        rows.sort_unstable_by_key(|&i| self.frame(i as usize).offset);
        let mut next = HEADER_LEN as u64;
        let mut payload = 0;
        for row in rows {
            let frame = self.frame(row as usize);
            let (start, end) = frame
                .extent(self.trailer)
                .ok_or_else(|| invalid("invalid index extent"))?;
            if start != next {
                return Err(invalid("pack frames overlap or leave a gap"));
            }
            next = end;
            payload += u64::from(frame.len);
        }
        if next != self.trailer || payload > MAX_TOTAL_PAYLOAD {
            return Err(invalid("index extents do not cover a bounded pack body"));
        }
        Ok(())
    }

    fn fanout(&self, shard: u8) -> usize {
        let start = 12 + usize::from(shard) * 4;
        le_u32(&self.bytes[start..start + 4]) as usize
    }

    fn bucket(&self, shard: u8) -> std::ops::Range<usize> {
        let start = shard.checked_sub(1).map_or(0, |prev| self.fanout(prev));
        start..self.fanout(shard)
    }

    fn id(&self, row: usize) -> &Hash {
        let at = FANOUT_END + row * 32;
        self.bytes[at..at + 32].try_into().expect("index id width")
    }

    fn frame(&self, row: usize) -> Frame {
        let offset_at = FANOUT_END + self.count * 32 + 8 * row;
        let len_at = FANOUT_END + self.count * 40 + 4 * row;
        Frame {
            offset: u64::from_le_bytes(
                self.bytes[offset_at..offset_at + 8]
                    .try_into()
                    .expect("index offset width"),
            ),
            len: le_u32(&self.bytes[len_at..len_at + 4]),
        }
    }

    pub(super) fn ids(&self, shard: Option<u8>) -> impl Iterator<Item = Hash> + '_ {
        shard
            .map_or(0..self.count, |byte| self.bucket(byte))
            .map(|i| *self.id(i))
    }

    pub(super) fn find(&self, id: &Hash) -> Option<Frame> {
        let mut range = self.bucket(id[0]);
        let mut end = range.end;
        while range.start < end {
            let mid = range.start + (end - range.start) / 2;
            match self.id(mid).cmp(id) {
                std::cmp::Ordering::Less => range.start = mid + 1,
                std::cmp::Ordering::Equal => return Some(self.frame(mid)),
                std::cmp::Ordering::Greater => end = mid,
            }
        }
        None
    }

    pub(super) fn check_index_version(&self) -> StoreResult<()> {
        let metadata = fs::symlink_metadata(&self.pair.index)?;
        if !metadata.is_file() {
            return Err(self.pair.error("index is not a regular file"));
        }
        if self.stamp.is_none() || IndexStamp::get(&metadata).ok() != self.stamp {
            let mut file = open_regular(&self.pair.index)?;
            read_version::<8>(&mut file, *MAGIC_INDEX, "local index")
                .map_err(|e| self.pair.context(e))?;
        }
        Ok(())
    }

    pub(super) fn open_frame(&self, frame: Frame) -> StoreResult<File> {
        let mut file = open_regular(&self.pair.pack)?;
        let (count, trailer, _) = read_header(&mut file).map_err(|e| self.pair.context(e))?;
        if count != self.count || trailer != self.trailer {
            return Err(self.pair.error("pack size or count changed"));
        }
        let (start, _) = frame
            .extent(trailer)
            .ok_or_else(|| self.pair.error("invalid frame extent"))?;
        file.seek(SeekFrom::Start(start))?;
        let len = read_frame_header(&mut file).map_err(|e| self.pair.error(e))?;
        if len != frame.len {
            return Err(self.pair.error("index and pack disagree on frame length"));
        }
        Ok(file)
    }

    pub(super) fn matches(&self, rows: &[(Hash, Frame)]) -> bool {
        self.count == rows.len()
            && rows
                .iter()
                .enumerate()
                .all(|(i, (id, frame))| self.id(i) == id && self.frame(i) == *frame)
    }
}

pub(super) fn open_regular(path: &Path) -> io::Result<File> {
    if !fs::symlink_metadata(path)?.is_file() {
        return Err(invalid("expected a regular file"));
    }
    let file = File::open(path)?;
    if !file.metadata()?.is_file() {
        return Err(invalid("expected a regular file"));
    }
    Ok(file)
}

fn read_version<const N: usize>(
    reader: &mut impl Read,
    magic: [u8; 4],
    kind: &str,
) -> StoreResult<[u8; N]> {
    let mut header = [0; N];
    let read = read_header_prefix(reader, &mut header)?;
    if read < 8 {
        return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
    }
    if header[..4] != magic {
        return Err(invalid(format!("invalid {kind} magic")).into());
    }
    let version = le_u32(&header[4..8]);
    if version != 1 {
        return Err(StoreError::IncompatibleRepoFormat {
            found: Some(format!("{kind} version {version}")),
        });
    }
    if read != N {
        return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
    }
    Ok(header)
}

fn frame_count_is_supported(count: usize) -> bool {
    count <= MAX_ENTRIES as usize
}

fn read_header(file: &mut File) -> StoreResult<(usize, u64, [u8; HEADER_LEN])> {
    let header = read_version::<HEADER_LEN>(file, *MAGIC, "local pack")?;
    let count = le_u32(&header[8..12]);
    if !frame_count_is_supported(count as usize) {
        return Err(invalid("local pack frame count exceeds the limit").into());
    }
    let trailer = file
        .metadata()?
        .len()
        .checked_sub(TRAILER_LEN as u64)
        .ok_or_else(|| invalid("local pack has no trailer"))?;
    let frames = u64::from(count) * FRAME_LEN;
    if trailer < HEADER_LEN as u64 + frames
        || trailer > HEADER_LEN as u64 + frames + MAX_TOTAL_PAYLOAD
    {
        return Err(invalid("local pack size disagrees with frame count or payload limit").into());
    }
    Ok((count as usize, trailer, header))
}

fn read_frame_header(reader: &mut impl Read) -> io::Result<u32> {
    let mut header = [0; ENTRY_FRAME_LEN];
    reader.read_exact(&mut header)?;
    if header[0] != 0 {
        return Err(invalid("local pack frame is not raw"));
    }
    Ok(le_u32(&header[1..]))
}

fn le_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes.try_into().expect("u32 width"))
}

pub(super) fn invalid(message: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub(in crate::store) fn canonical_id(bytes: &[u8]) -> StoreResult<Hash> {
    if bytes.len() >= serialize::BLOB_PROLOGUE_LEN && bytes[0] == ObjectType::Blob as u8 {
        let head = serialize::blob_prologue(bytes.len() - serialize::BLOB_PROLOGUE_LEN)?;
        if bytes.starts_with(&head) {
            return Ok(*blake3::hash(bytes).as_bytes());
        }
    }
    let object = serialize::deserialize(bytes)?;
    if matches!(object, Object::Delta(_)) {
        return Err(invalid("delta object in local pack").into());
    }
    Ok(id_from_object(&object, bytes))
}

pub(super) fn scan(pack: &mut File) -> StoreResult<(Hash, Vec<(Hash, Frame)>)> {
    pack.rewind()?;
    let (count, trailer, header) = read_header(pack)?;
    let mut digest = blake3::Hasher::new();
    digest.update(&header);
    let mut rows = Vec::with_capacity(count);
    let mut next = HEADER_LEN as u64;
    for _ in 0..count {
        let len = read_frame_header(pack)?;
        let frame = Frame {
            offset: next + FRAME_LEN,
            len,
        };
        let (_, end) = frame
            .extent(trailer)
            .ok_or_else(|| invalid("invalid raw frame extent"))?;
        let mut bytes = vec![0; len as usize];
        pack.read_exact(&mut bytes)?;
        digest.update(&[0]);
        digest.update(&len.to_le_bytes());
        digest.update(&bytes);
        rows.push((canonical_id(&bytes)?, frame));
        next = end;
    }
    let mut expected = [0; TRAILER_LEN];
    pack.read_exact(&mut expected)?;
    if next != trailer || digest.finalize().as_bytes() != &expected || pack.read(&mut [0])? != 0 {
        return Err(invalid("invalid pack trailer").into());
    }
    digest.update(&expected);
    rows.sort_unstable_by_key(|(id, _)| *id);
    if rows.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(invalid("duplicate id in local pack").into());
    }
    Ok((*digest.finalize().as_bytes(), rows))
}

pub(super) fn encode(key: Hash, rows: &[(Hash, Frame)]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(INDEX_BASE_LEN + INDEX_ROW_LEN * rows.len());
    bytes.extend_from_slice(MAGIC_INDEX);
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(
        &u32::try_from(rows.len())
            .expect("bounded frame count")
            .to_le_bytes(),
    );
    let mut end = 0;
    for shard in 0..=u8::MAX {
        while end < rows.len() && rows[end].0[0] == shard {
            end += 1;
        }
        bytes.extend_from_slice(
            &u32::try_from(end)
                .expect("bounded frame count")
                .to_le_bytes(),
        );
    }
    for (id, _) in rows {
        bytes.extend_from_slice(id);
    }
    for (_, frame) in rows {
        bytes.extend_from_slice(&frame.offset.to_le_bytes());
    }
    for (_, frame) in rows {
        bytes.extend_from_slice(&frame.len.to_le_bytes());
    }
    bytes.extend_from_slice(&key);
    let checksum = blake3::hash(&bytes);
    bytes.extend_from_slice(checksum.as_bytes());
    bytes
}

#[cfg(feature = "fuzzing")]
pub(in crate::store) fn fuzz_index(bytes: &[u8]) {
    let count = bytes.len().saturating_sub(INDEX_BASE_LEN) / INDEX_ROW_LEN;
    let mut index = bytes.to_vec();
    if index.len() >= INDEX_BASE_LEN && index.len() == INDEX_BASE_LEN + INDEX_ROW_LEN * count {
        // Also reach row validation when a mutation invalidates the checksum.
        let body = index.len() - 32;
        let checksum = blake3::hash(&index[..body]);
        index[body..].copy_from_slice(checksum.as_bytes());
    }
    let key = index
        .get(index.len().saturating_sub(64)..index.len().saturating_sub(32))
        .and_then(|bytes| bytes.try_into().ok())
        .unwrap_or_default();
    let pair = Pair::new(Path::new(""), key);
    let _ = Index::decode(pair, index, count, HEADER_LEN as u64 + 64 * 1024);
}

#[cfg(test)]
mod tests {
    use super::{FRAME_LEN, Frame, HEADER_LEN, Index, Pair, encode};
    use crate::store::local_pack::LocalPacks;
    use std::path::Path;
    use std::sync::Arc;

    #[test]
    fn cache_evicts_the_oldest_index_at_its_byte_and_entry_limits() {
        fn index(tag: u8, size: usize) -> Arc<Index> {
            Arc::new(Index {
                pair: Pair::new(Path::new(""), [tag; 32]),
                bytes: vec![0; size],
                count: 0,
                trailer: 0,
                stamp: None,
            })
        }

        let cache = LocalPacks::new(true);
        let mib = 1024 * 1024;
        for tag in 1..=4 {
            cache.remember(index(tag, 16 * mib));
        }
        assert_eq!(cache.known.lock().unwrap().len(), 4);
        cache.remember(index(5, 32 * mib));
        cache.remember(index(6, 64 * mib + 1));
        {
            let known = cache.known.lock().unwrap();
            assert_eq!(known.len(), 3);
            assert_eq!(known[0].pair.key, [5; 32]);
            assert_eq!(known[1].pair.key, [4; 32]);
            assert_eq!(known[2].pair.key, [3; 32]);
        }
        cache.forget(&[5; 32]);
        {
            let known = cache.known.lock().unwrap();
            assert_eq!(known.len(), 2);
            assert_eq!(known[0].pair.key, [4; 32]);
            assert_eq!(known[1].pair.key, [3; 32]);
        }

        let cache = LocalPacks::new(true);
        for tag in 0..65 {
            cache.remember(index(tag, 1_100));
        }
        let known = cache.known.lock().unwrap();
        assert_eq!(known.len(), 64);
        assert_eq!(known.last().unwrap().pair.key, [1; 32]);
    }

    #[test]
    fn frame_extent_requires_a_complete_payload_after_the_header() {
        let offset = HEADER_LEN as u64 + FRAME_LEN;
        let frame = Frame { offset, len: 6 };
        assert_eq!(
            frame.extent(offset + 6),
            Some((HEADER_LEN as u64, offset + 6))
        );
        assert_eq!(frame.extent(offset + 5), None);
        assert_eq!(Frame { offset, len: 5 }.extent(offset + 6), None);
        let too_early = Frame {
            offset: offset - 1,
            ..frame
        };
        assert_eq!(too_early.extent(offset + 6), None);
    }

    #[test]
    fn index_lookup_requires_distinct_sorted_ids_in_each_fanout_bucket() {
        let mut first = [0x40; 32];
        let mut last = first;
        last[31] = 2;
        first[31] = 0;
        let ids = [[0; 32], first, last];
        let len = 6;
        let mut next = HEADER_LEN as u64;
        let rows = ids.map(|id| {
            let offset = next + FRAME_LEN;
            next = offset + u64::from(len);
            (id, Frame { offset, len })
        });
        let pair = Pair::new(Path::new(""), [0; 32]);
        let bytes = encode(pair.key, &rows);
        let index = Index::decode(pair.clone(), bytes, rows.len(), next).unwrap();

        for (id, frame) in rows {
            assert_eq!(index.find(&id), Some(frame));
        }
        let mut missing = first;
        missing[31] = 1;
        assert_eq!(index.find(&missing), None);

        let mut unsorted = rows;
        unsorted.swap(1, 2);
        let mut duplicate = rows;
        duplicate[2].0 = duplicate[1].0;
        for invalid in [unsorted, duplicate] {
            let bytes = encode(pair.key, &invalid);
            let error = Index::decode(pair.clone(), bytes, rows.len(), next).unwrap_err();
            assert!(error.to_string().contains("strictly increasing"), "{error}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn pack_headers_enforce_the_frame_count_and_body_size_limits() {
        use super::{
            File, MAGIC, MAX_ENTRIES, MAX_TOTAL_PAYLOAD, StoreResult, TRAILER_LEN, read_header,
        };
        use std::io::{Seek, Write};

        fn read(
            file: &mut File,
            count: u32,
            body_len: u64,
        ) -> StoreResult<(usize, u64, [u8; HEADER_LEN])> {
            file.rewind().unwrap();
            file.write_all(MAGIC).unwrap();
            file.write_all(&1_u32.to_le_bytes()).unwrap();
            file.write_all(&count.to_le_bytes()).unwrap();
            // Set the logical length without writing the potentially large body.
            file.set_len(HEADER_LEN as u64 + body_len + TRAILER_LEN as u64)
                .unwrap();
            file.rewind().unwrap();
            read_header(file)
        }

        let mut file = tempfile::tempfile().unwrap();
        let frames = u64::from(MAX_ENTRIES) * FRAME_LEN;
        let (count, _, _) = read(&mut file, MAX_ENTRIES, frames).unwrap();
        assert_eq!(count, MAX_ENTRIES as usize);
        let over_limit = MAX_ENTRIES + 1;
        let error = read(&mut file, over_limit, frames + FRAME_LEN).unwrap_err();
        assert!(error.to_string().contains("frame count exceeds"));

        let frames = 2 * FRAME_LEN;
        assert!(read(&mut file, 2, frames - 1).is_err());
        assert!(read(&mut file, 2, frames).is_ok());
        assert!(read(&mut file, 2, frames + MAX_TOTAL_PAYLOAD).is_ok());
        assert!(read(&mut file, 2, frames + MAX_TOTAL_PAYLOAD + 1).is_err());
    }
}
