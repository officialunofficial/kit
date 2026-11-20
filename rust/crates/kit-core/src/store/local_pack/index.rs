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

pub(super) const MAGIC_INDEX: &[u8; 4] = b"KITX";
pub(super) const FANOUT_END: usize = 12 + 256 * 4;
pub(super) const INDEX_BASE_LEN: usize = FANOUT_END + 64;
pub(super) const INDEX_ROW_LEN: usize = 44;
const FRAME_LEN: u64 = ENTRY_FRAME_LEN as u64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::store) struct Frame {
    pub(super) offset: u64,
    pub(super) len: u32,
}

impl Frame {
    pub(super) fn extent(self, trailer: u64) -> Option<(u64, u64)> {
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

    pub(super) fn index_error(&self, error: impl std::fmt::Display) -> StoreError {
        self.error(format_args!(
            "{error}. If the index is damaged, run `kit closure repair-indexes`"
        ))
    }

    pub(super) fn index_context(&self, error: StoreError) -> StoreError {
        match error {
            StoreError::IncompatibleRepoFormat { .. } => self.context(error),
            other => self.index_error(other),
        }
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
    stamp: Option<Stamp>,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct Stamp {
    modified: std::time::SystemTime,
    len: u64,
    #[cfg(unix)]
    identity: (u64, u64),
    #[cfg(unix)]
    changed: (i64, i64),
}

impl Stamp {
    pub(super) fn get(metadata: &fs::Metadata) -> io::Result<Self> {
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt;

        Ok(Self {
            modified: metadata.modified()?,
            len: metadata.len(),
            #[cfg(unix)]
            identity: (metadata.dev(), metadata.ino()),
            #[cfg(unix)]
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        })
    }

    pub(super) fn settled(&self) -> bool {
        #[cfg(unix)]
        {
            use std::time::{Duration, SystemTime};
            let (seconds, nanos) = self.changed;
            let Ok(seconds) = u64::try_from(seconds) else {
                return false;
            };
            let Ok(nanos) = u32::try_from(nanos) else {
                return false;
            };
            SystemTime::UNIX_EPOCH
                .checked_add(Duration::new(seconds, nanos))
                .and_then(|changed| changed.elapsed().ok())
                .is_some_and(|age| age >= Duration::from_secs(1))
        }
        #[cfg(not(unix))]
        false
    }

    pub(super) fn same_file(&self, other: &Self) -> bool {
        #[cfg(unix)]
        return self.identity == other.identity && self.len == other.len;
        #[cfg(not(unix))]
        return self == other;
    }
}

impl Index {
    pub(super) fn open(pair: &Pair) -> StoreResult<Self> {
        Self::load(pair).or_else(|error| {
            // A damaged member can hide the other member's version.
            if !matches!(error, StoreError::IncompatibleRepoFormat { .. }) {
                pair.check_versions()?;
            }
            Err(pair.index_context(error))
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
        index.stamp = Stamp::get(&metadata).ok();
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
        validate_fanout_bounds(&bytes[12..FANOUT_END], self.count)?;
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

    pub(super) fn entries(&self) -> impl Iterator<Item = (Hash, Frame)> + '_ {
        (0..self.count).map(|i| (*self.id(i), self.frame(i)))
    }

    pub(super) fn ids(&self, shard: Option<u8>) -> impl Iterator<Item = Hash> + '_ {
        shard
            .map_or(0..self.count, |byte| self.bucket(byte))
            .map(|i| *self.id(i))
    }

    #[cfg(test)]
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
            return Err(self.pair.index_error("index is not a regular file"));
        }
        if self.stamp.is_none() || Stamp::get(&metadata).ok() != self.stamp {
            let mut file = open_regular(&self.pair.index)?;
            read_version::<8>(&mut file, *MAGIC_INDEX, "local index")
                .map_err(|e| self.pair.index_context(e))?;
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

pub(super) fn read_version<const N: usize>(
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

pub(super) fn read_header(file: &mut File) -> StoreResult<(usize, u64, [u8; HEADER_LEN])> {
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

pub(super) fn read_frame_header(reader: &mut impl Read) -> io::Result<u32> {
    let mut header = [0; ENTRY_FRAME_LEN];
    reader.read_exact(&mut header)?;
    if header[0] != 0 {
        return Err(invalid("local pack frame is not raw"));
    }
    Ok(le_u32(&header[1..]))
}

pub(super) fn validate_fanout_bounds(fanout: &[u8], count: usize) -> io::Result<()> {
    let mut prev = 0;
    for bucket in fanout.chunks_exact(4) {
        let end = le_u32(bucket) as usize;
        if end < prev || end > count {
            return Err(invalid("invalid index fanout"));
        }
        prev = end;
    }
    if prev != count {
        return Err(invalid("index fanout does not reach frame count"));
    }
    Ok(())
}

pub(super) fn le_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes.try_into().expect("u32 width"))
}

pub(in crate::store) fn invalid(
    message: impl Into<Box<dyn std::error::Error + Send + Sync>>,
) -> io::Error {
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
    scan_checked(pack, &|| Ok(()))
}

pub(super) fn scan_checked(
    pack: &mut File,
    checkpoint: &dyn Fn() -> StoreResult<()>,
) -> StoreResult<(Hash, Vec<(Hash, Frame)>)> {
    checkpoint()?;
    pack.rewind()?;
    let (count, trailer, header) = read_header(pack)?;
    let mut digest = blake3::Hasher::new();
    digest.update(&header);
    let mut rows = Vec::with_capacity(count);
    let mut next = HEADER_LEN as u64;
    for _ in 0..count {
        checkpoint()?;
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
    use crate::object::KitError;
    use crate::serialize;
    use crate::store::StoreError;
    use std::path::Path;

    #[test]
    fn packed_blob_identity_rejects_a_short_object_header() {
        let bytes = serialize::blob_prologue(0).unwrap();
        assert!(matches!(
            super::canonical_id(&bytes[..1]),
            Err(StoreError::Decode(KitError::EmptyData))
        ));
    }

    #[test]
    fn packed_blob_identity_rejects_a_truncated_payload() {
        let bytes = serialize::blob_prologue(20).unwrap();
        assert!(matches!(
            super::canonical_id(&bytes),
            Err(StoreError::Decode(KitError::UnexpectedEof))
        ));
    }

    #[test]
    fn packed_blob_identity_rejects_trailing_payload_bytes() {
        let mut bytes = serialize::blob_prologue(1).unwrap().to_vec();
        bytes.extend_from_slice(b"ab");
        assert!(matches!(
            super::canonical_id(&bytes),
            Err(StoreError::Decode(KitError::TrailingData))
        ));
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
    fn index_decode_refuses_truncated_and_extended_indexes() {
        let pair = Pair::new(Path::new(""), [0; 32]);
        let mut short = encode(pair.key, &[]);
        short.pop();
        let mut long = encode(pair.key, &[]);
        long.push(0);
        for bytes in [Vec::new(), short, long] {
            let error = Index::decode(pair.clone(), bytes, 0, HEADER_LEN as u64).unwrap_err();
            assert!(
                error.to_string().contains("length does not match"),
                "{error}"
            );
        }
    }

    #[test]
    fn index_validation_rejects_bad_magic_versions_and_unindexed_bytes() {
        let pair = Pair::new(Path::new(""), [0; 32]);
        let bytes = encode(pair.key, &[]);
        let end = HEADER_LEN as u64;
        assert!(Index::decode(pair.clone(), bytes.clone(), 0, end + 1).is_err());
        for offset in [0, 4] {
            let mut invalid = bytes.clone();
            invalid[offset] ^= 1;
            let checksum_at = invalid.len() - 32;
            let checksum = blake3::hash(&invalid[..checksum_at]);
            invalid[checksum_at..].copy_from_slice(checksum.as_bytes());
            assert!(Index::decode(pair.clone(), invalid, 0, end).is_err());
        }
    }

    #[test]
    fn index_validation_accepts_the_payload_limit_and_refuses_more() {
        let at_limit = u32::try_from(super::MAX_RAW_OBJECT_SIZE).unwrap();
        let decode = |lengths: &[u32]| {
            let mut end = HEADER_LEN as u64;
            let rows: Vec<_> = lengths
                .iter()
                .enumerate()
                .map(|(i, &len)| {
                    let id = [u8::try_from(i).unwrap(); 32];
                    let offset = end + FRAME_LEN;
                    end = offset + u64::from(len);
                    (id, Frame { offset, len })
                })
                .collect();
            let pair = Pair::new(Path::new(""), [0; 32]);
            let bytes = encode(pair.key, &rows);
            Index::decode(pair, bytes, rows.len(), end)
        };
        assert!(decode(&[at_limit; 4]).is_ok());
        assert!(decode(&[at_limit, at_limit, at_limit, at_limit, 6]).is_err());
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

#[cfg(test)]
mod reader_bounds_tests {
    #[cfg(unix)]
    use super::Stamp;
    use super::{FANOUT_END, validate_fanout_bounds};

    #[test]
    fn locator_fanout_stays_monotonic_and_ends_at_the_row_count() {
        let check = |buckets: &[u32], count| {
            let mut bytes = [0; FANOUT_END - 12];
            for (i, bucket) in bytes.chunks_exact_mut(4).enumerate() {
                bucket.copy_from_slice(&buckets[i.min(buckets.len() - 1)].to_le_bytes());
            }
            validate_fanout_bounds(&bytes, count)
        };
        assert!(check(&[0], 0).is_ok());
        assert!(check(&[0, 1, 1, 2], 2).is_ok());
        assert!(check(&[0, 1, 0, 2], 2).is_err());
        assert!(check(&[0, 3, 2], 2).is_err());
        assert!(check(&[0, 1], 2).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn file_identity_distinguishes_inode_and_length_but_allows_timestamp_changes() {
        use std::time::{Duration, SystemTime};

        let file = tempfile::tempfile().unwrap();
        let first = Stamp::get(&file.metadata().unwrap()).unwrap();
        file.set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(1))
            .unwrap();
        let touched = Stamp::get(&file.metadata().unwrap()).unwrap();
        assert_ne!(first, touched);
        assert!(first.same_file(&touched));
        file.set_len(1).unwrap();
        assert!(!first.same_file(&Stamp::get(&file.metadata().unwrap()).unwrap()));
        let other = tempfile::tempfile().unwrap();
        assert!(!first.same_file(&Stamp::get(&other.metadata().unwrap()).unwrap()));
    }

    #[cfg(unix)]
    #[test]
    fn only_a_past_directory_stamp_can_settle() {
        use std::time::{Duration, SystemTime};

        let file = tempfile::tempfile().unwrap();
        let mut stamp = Stamp::get(&file.metadata().unwrap()).unwrap();
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();
        let future = now + Duration::from_secs(15);
        stamp.changed = (i64::try_from(future.as_secs()).unwrap(), 0);
        assert!(!stamp.settled());
        stamp.changed = (i64::try_from(now.as_secs() - 15).unwrap(), 0);
        assert!(stamp.settled());
    }
}
