//! Canonical byte (de)serialization for [`Object`].
//!
//! Spec: `docs/specs/SPEC-OBJECTS.md`. The byte layout produced here is the
//! v1 on-disk format; the golden-vector tests in `tests/golden.rs` pin
//! it byte-for-byte.
//!
//! Every deserializer:
//! * Validates the 6-byte v1 prologue first.
//! * Enforces per-type bounds (entry counts, identity len, etc.).
//! * Rejects non-empty trailing bytes via [`KitError::TrailingData`].

use crate::hash::{HASH_LEN, Hash};
use crate::object::{
    Blob, ChunkedBlob, ChunkedBlobBuilder, Commit, Delta, EntryMode, IDENTITY_MAX_LEN, Identity,
    IdentityKind, KitError, MAGIC, Object, ObjectType, Remix, RemixSource, TAG_NAME_MAX_LEN, Tag,
    Tree, TreeEntry,
};

const PROLOGUE_LEN: usize = 6;

/// Decode-side cap on tree entry count; writers (and the git
/// importer) must refuse anything larger or the store gains an
/// undecodable signed object.
pub const MAX_TREE_ENTRIES: u32 = 1_000_000;
const MAX_PARENTS: u32 = 1_000;
const MAX_REMIX_SOURCES: u32 = 10_000;
/// Cap on a `ChunkedBlob`'s `total_size`: 128 GiB (SPEC-OBJECTS §7).
/// Readers and writers both enforce it. A reader that holds a whole file
/// in memory has its own, lower cap, [`crate::worktree::MAX_FILE_BYTES`].
pub const MAX_CHUNKED_TOTAL_SIZE: u64 = 128 * 1024 * 1024 * 1024;
/// Cap on a `ChunkedBlob`'s chunk count: [`MAX_CHUNKED_TOTAL_SIZE`] cut
/// at the 16 KiB `FastCDC` minimum chunk size, 8,388,608. Readers and
/// writers both enforce it, and `crate::verify` bounds a disclosure
/// bundle's claimed chunk count with it.
pub const MAX_CHUNKS: u32 = 8_388_608;
/// Bytes of a `ChunkedBlob` manifest before its entries: the 6-byte
/// prologue, `total_size`, `chunk_size` and `chunk_count`.
pub const CHUNKED_HEADER_LEN: usize = 22;
/// Bytes of one `ChunkedBlob` manifest entry: a 32-byte chunk id and the
/// `u64` end offset of the chunk. A manifest of `n` chunks is
/// `CHUNKED_HEADER_LEN + CHUNKED_ENTRY_LEN * n` bytes long.
pub const CHUNKED_ENTRY_LEN: usize = 40;
/// The longest span one chunk may cover: a Blob object of at most
/// [`crate::store::MAX_RAW_OBJECT_SIZE`] bytes, less its 10-byte prologue.
pub const MAX_CHUNK_LEN: u64 = crate::store::MAX_RAW_OBJECT_SIZE as u64 - 10;

// ---------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------

/// Serialize an [`Object`] to its canonical byte form. Allocates fresh
/// each call; the result is fully owned.
///
/// Returns [`KitError::OversizePayload`] if any length-prefixed field
/// exceeds the wire-format `u32` cap, and [`KitError::InvalidIdentity`]
/// if the object carries a structurally invalid [`Identity`].
///
/// # Caller precondition: ordering
///
/// The writer does not reorder or validate entry/source ordering — it
/// encodes them verbatim — but [`deserialize`] enforces a strict
/// ascending order (`Tree` entries by `name`, `Remix` sources by
/// `(upstream_id, commit_hash)`). An `Object` built by hand with
/// out-of-order `Tree::entries` or `Remix::sources` will therefore
/// serialize cleanly yet fail to round-trip (`deserialize` rejects it
/// with `InvalidEntryOrder` / `InvalidSourceOrder`). Callers that bypass
/// the ordered-building helpers MUST ensure [`Tree::is_sorted`] /
/// [`Remix::sources_sorted`] hold before serializing — otherwise the
/// resulting (possibly signed) bytes are undecodable.
pub fn serialize(obj: &Object) -> Result<Vec<u8>, KitError> {
    let mut buf = Vec::with_capacity(PROLOGUE_LEN + estimated_body_len(obj));
    write_prologue(&mut buf, obj.object_type());
    match obj {
        Object::Blob(b) => write_blob(&mut buf, b)?,
        Object::Tree(t) => write_tree(&mut buf, t)?,
        Object::Commit(c) => write_commit(&mut buf, c)?,
        Object::Remix(r) => write_remix(&mut buf, r)?,
        Object::ChunkedBlob(cb) => write_chunked_blob(&mut buf, cb)?,
        Object::Delta(d) => write_delta(&mut buf, d)?,
        Object::Tag(t) => write_tag(&mut buf, t)?,
    }
    Ok(buf)
}

/// The exact byte prefix of `serialize(Object::Blob(..))` for a payload
/// of `len` bytes: 6-byte object prologue plus the `u32` LE data
/// length. Lets ingest write a chunk as `prologue ‖ payload` straight
/// from the source buffer — no `Blob` allocation, no serialize copy.
/// Equivalence with [`serialize`] is pinned by proptest and,
/// transitively, the golden blob vectors.
///
/// # Errors
///
/// [`KitError::OversizePayload`] if `len` exceeds the wire-format
/// `u32` cap.
pub fn blob_prologue(len: usize) -> Result<[u8; PROLOGUE_LEN + 4], KitError> {
    let len_le = checked_u32("blob.data", len)?.to_le_bytes();
    let mut out = [0u8; PROLOGUE_LEN + 4];
    out[0] = ObjectType::Blob as u8;
    out[1..5].copy_from_slice(&MAGIC);
    out[5] = ObjectType::Blob.schema_version();
    out[6..10].copy_from_slice(&len_le);
    Ok(out)
}

/// Deserialize bytes into an owned [`Object`]. Validates the prologue
/// and every per-type bound; rejects trailing data.
pub fn deserialize(data: &[u8]) -> Result<Object, KitError> {
    if data.len() < PROLOGUE_LEN {
        return Err(KitError::EmptyData);
    }
    let tag = ObjectType::from_u8(data[0])?;
    if data[1..5] != MAGIC {
        return Err(KitError::InvalidMagic);
    }
    if data[5] != tag.schema_version() {
        return Err(KitError::UnsupportedObjectVersion);
    }
    let mut r = Reader::new(&data[PROLOGUE_LEN..]);
    let obj = match tag {
        ObjectType::Blob => Object::Blob(read_blob(&mut r)?),
        ObjectType::Tree => Object::Tree(read_tree(&mut r)?),
        ObjectType::Commit => Object::Commit(read_commit(&mut r)?),
        ObjectType::Remix => Object::Remix(read_remix(&mut r)?),
        ObjectType::ChunkedBlob => Object::ChunkedBlob(read_chunked_blob(&mut r)?),
        ObjectType::Delta => Object::Delta(read_delta(&mut r)?),
        ObjectType::Tag => Object::Tag(read_tag(&mut r)?),
    };
    if r.remaining() != 0 {
        return Err(KitError::TrailingData);
    }
    Ok(obj)
}

// ---------------------------------------------------------------------
// Writers
// ---------------------------------------------------------------------

fn write_prologue(buf: &mut Vec<u8>, t: ObjectType) {
    buf.push(t as u8);
    buf.extend_from_slice(&MAGIC);
    buf.push(t.schema_version());
}

fn write_u16_le(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn write_u32_le(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn write_u64_le(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn checked_u32(field: &'static str, len: usize) -> Result<u32, KitError> {
    u32::try_from(len).map_err(|_| KitError::OversizePayload { field, len })
}

fn write_lp_bytes(buf: &mut Vec<u8>, field: &'static str, data: &[u8]) -> Result<(), KitError> {
    write_u32_le(buf, checked_u32(field, data.len())?);
    buf.extend_from_slice(data);
    Ok(())
}

fn write_identity(buf: &mut Vec<u8>, id: &Identity) -> Result<(), KitError> {
    if !id.is_valid() {
        return Err(KitError::InvalidIdentity);
    }
    buf.push(id.kind as u8);
    // `is_valid` already enforces 1..=IDENTITY_MAX_LEN, so the cast is
    // safe — but keep the guard so the encoder can never silently lose
    // bytes if `is_valid` is ever loosened.
    let len = u16::try_from(id.bytes.len()).map_err(|_| KitError::InvalidIdentity)?;
    write_u16_le(buf, len);
    buf.extend_from_slice(&id.bytes);
    Ok(())
}

fn write_blob(buf: &mut Vec<u8>, b: &Blob) -> Result<(), KitError> {
    write_lp_bytes(buf, "blob.data", &b.data)
}

fn write_tree(buf: &mut Vec<u8>, t: &Tree) -> Result<(), KitError> {
    write_u32_le(buf, checked_u32("tree.entries", t.entries.len())?);
    for e in &t.entries {
        write_lp_bytes(buf, "tree.entry.name", &e.name)?;
        buf.push(e.mode as u8);
        buf.extend_from_slice(&e.object_hash);
    }
    Ok(())
}

fn write_commit(buf: &mut Vec<u8>, c: &Commit) -> Result<(), KitError> {
    buf.extend_from_slice(&c.tree_hash);
    write_u32_le(buf, checked_u32("commit.parents", c.parents.len())?);
    for p in &c.parents {
        buf.extend_from_slice(p);
    }
    write_identity(buf, &c.author)?;
    write_lp_bytes(buf, "commit.message", &c.message)?;
    write_u64_le(buf, c.timestamp);
    buf.extend_from_slice(&c.signer);
    buf.extend_from_slice(&c.message_hash);
    buf.extend_from_slice(&c.content_digest);
    buf.extend_from_slice(&c.signature);
    Ok(())
}

fn write_remix(buf: &mut Vec<u8>, r: &Remix) -> Result<(), KitError> {
    buf.extend_from_slice(&r.tree_hash);
    write_u32_le(buf, checked_u32("remix.parents", r.parents.len())?);
    for p in &r.parents {
        buf.extend_from_slice(p);
    }
    write_u32_le(buf, checked_u32("remix.sources", r.sources.len())?);
    for s in &r.sources {
        buf.extend_from_slice(&s.upstream_id);
        buf.extend_from_slice(&s.commit_hash);
    }
    write_identity(buf, &r.author)?;
    write_lp_bytes(buf, "remix.message", &r.message)?;
    write_u64_le(buf, r.timestamp);
    buf.extend_from_slice(&r.signer);
    buf.extend_from_slice(&r.signature);
    Ok(())
}

/// Reject pack-only / non-storable target types. A tag MUST point at a
/// type that can live in the object store (`Delta` is pack-only).
fn check_tag_target_type(t: ObjectType) -> Result<(), KitError> {
    if matches!(t, ObjectType::Delta) {
        return Err(KitError::TagTargetTypeInvalid(t as u8));
    }
    Ok(())
}

fn write_tag(buf: &mut Vec<u8>, t: &Tag) -> Result<(), KitError> {
    if !t.name_is_valid() {
        return Err(KitError::TagNameInvalid);
    }
    check_tag_target_type(t.target_type)?;
    buf.extend_from_slice(&t.target);
    buf.push(t.target_type as u8);
    write_lp_bytes(buf, "tag.name", &t.name)?;
    write_identity(buf, &t.tagger)?;
    write_lp_bytes(buf, "tag.message", &t.message)?;
    write_u64_le(buf, t.timestamp);
    buf.extend_from_slice(&t.signer);
    buf.extend_from_slice(&t.signature);
    Ok(())
}

/// Check the count and the size of a `ChunkedBlob` manifest header against
/// decode checks 1 and 3 of SPEC-OBJECTS §7. This is the header step of the
/// manifest decoder and of [`crate::merkle::ChunkedIdFold`]; the entries
/// carry the rest of the checks. The whole header check, which needs the
/// chunk size too, is [`check_chunked_total_size`], run by a disclosure
/// verifier that holds no entries.
///
/// # Errors
/// [`KitError::TooManyChunks`] above [`MAX_CHUNKS`], and
/// [`KitError::ChunkedBlobTotalSizeInvalid`] for a `total_size` above
/// [`MAX_CHUNKED_TOTAL_SIZE`].
pub fn check_chunked_header(total_size: u64, chunk_count: u32) -> Result<(), KitError> {
    if chunk_count > MAX_CHUNKS {
        return Err(KitError::TooManyChunks);
    }
    if total_size > MAX_CHUNKED_TOTAL_SIZE {
        return Err(KitError::ChunkedBlobTotalSizeInvalid);
    }
    Ok(())
}

/// Check one manifest entry against decode check 4 of SPEC-OBJECTS §7: the
/// chunk at `index` ends at `end`, and the chunk before it ended at
/// `prev_end` (`0` for the first). In order: the end increases, the span fits
/// in one Blob object, the end is at most `total_size`, and in a fixed-size
/// layout the end is `min((index + 1) * chunk_size, total_size)`. The
/// manifest decoder, [`ChunkedBlob::new`] and
/// [`crate::merkle::ChunkedIdFold`] all run this one function, so each
/// refuses at the same entry with the same error.
///
/// # Errors
/// [`KitError::ChunkEndNotIncreasing`], [`KitError::ChunkLengthAboveLimit`],
/// [`KitError::ChunkEndAboveTotalSize`] and [`KitError::FixedChunkEnd`], in
/// that order.
pub fn check_chunk_entry(
    index: u32,
    chunk_size: u32,
    total_size: u64,
    prev_end: u64,
    end: u64,
) -> Result<(), KitError> {
    if end <= prev_end {
        return Err(KitError::ChunkEndNotIncreasing { index });
    }
    if end - prev_end > MAX_CHUNK_LEN {
        return Err(KitError::ChunkLengthAboveLimit { index });
    }
    if end > total_size {
        return Err(KitError::ChunkEndAboveTotalSize { index });
    }
    if crate::chunker::Chunker::from_chunk_size(chunk_size).is_none() {
        let fixed_end = u64::from(index)
            .checked_add(1)
            .and_then(|n| n.checked_mul(u64::from(chunk_size)))
            .ok_or(KitError::FixedChunkEnd { index })?
            .min(total_size);
        if end != fixed_end {
            return Err(KitError::FixedChunkEnd { index });
        }
    }
    Ok(())
}

/// Check decode check 5 of SPEC-OBJECTS §7 once every entry has passed
/// [`check_chunk_entry`]: the last end equals `total_size`, and with no
/// chunks `total_size` is `0`. `last_end` is `0` when there are no chunks.
///
/// # Errors
/// [`KitError::ChunkedBlobNoChunks`] for a non-zero `total_size`
/// with no chunks, and [`KitError::ChunkedBlobLastEnd`] for a last end
/// below `total_size`.
pub fn check_last_end(total_size: u64, chunk_count: usize, last_end: u64) -> Result<(), KitError> {
    if chunk_count == 0 {
        if total_size != 0 {
            return Err(KitError::ChunkedBlobNoChunks);
        }
    } else if last_end != total_size {
        return Err(KitError::ChunkedBlobLastEnd);
    }
    Ok(())
}

/// Refuse a manifest that [`deserialize`] would refuse, so a writer never
/// stores an undecodable manifest. [`ChunkedBlob::new`] already runs these
/// checks; this is the second line of defence.
fn write_chunked_blob(buf: &mut Vec<u8>, cb: &ChunkedBlob) -> Result<(), KitError> {
    let chunk_count = u32::try_from(cb.chunks().len()).map_err(|_| KitError::TooManyChunks)?;
    check_chunked_header(cb.total_size(), chunk_count)?;
    let mut prev_end = 0;
    for (index, &end) in (0..chunk_count).zip(cb.ends()) {
        check_chunk_entry(index, cb.chunk_size(), cb.total_size(), prev_end, end)?;
        prev_end = end;
    }
    check_last_end(cb.total_size(), cb.chunks().len(), prev_end)?;
    write_u64_le(buf, cb.total_size());
    write_u32_le(buf, cb.chunk_size());
    write_u32_le(buf, chunk_count);
    for (chunk, end) in cb.entries() {
        buf.extend_from_slice(&chunk);
        write_u64_le(buf, end);
    }
    Ok(())
}

fn write_delta(buf: &mut Vec<u8>, d: &Delta) -> Result<(), KitError> {
    buf.extend_from_slice(&d.base_hash);
    write_u32_le(buf, d.result_size);
    write_lp_bytes(buf, "delta.instructions", &d.instructions)
}

fn estimated_body_len(obj: &Object) -> usize {
    match obj {
        Object::Blob(b) => 4 + b.data.len(),
        Object::Tree(t) => {
            4 + t
                .entries
                .iter()
                .map(|e| 4 + e.name.len() + 1 + 32)
                .sum::<usize>()
        }
        Object::Commit(c) => {
            32 + 4
                + c.parents.len() * 32
                + 1
                + 2
                + c.author.bytes.len()
                + 4
                + c.message.len()
                + 8
                + 32
                + 32
                + 32
                + 64
        }
        Object::Remix(r) => {
            32 + 4
                + r.parents.len() * 32
                + 4
                + r.sources.len() * 64
                + 1
                + 2
                + r.author.bytes.len()
                + 4
                + r.message.len()
                + 8
                + 32
                + 64
        }
        Object::ChunkedBlob(cb) => 8 + 4 + 4 + cb.chunks().len() * CHUNKED_ENTRY_LEN,
        Object::Delta(d) => 32 + 4 + 4 + d.instructions.len(),
        Object::Tag(t) => {
            32 + 1
                + 4
                + t.name.len()
                + 1
                + 2
                + t.tagger.bytes.len()
                + 4
                + t.message.len()
                + 8
                + 32
                + 64
        }
    }
}

// ---------------------------------------------------------------------
// Reader
// ---------------------------------------------------------------------

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    fn need(&self, n: usize) -> Result<(), KitError> {
        if self.remaining() < n {
            Err(KitError::UnexpectedEof)
        } else {
            Ok(())
        }
    }

    fn read_u8(&mut self) -> Result<u8, KitError> {
        self.need(1)?;
        let v = self.data[self.pos];
        self.pos += 1;
        Ok(v)
    }

    fn read_u16(&mut self) -> Result<u16, KitError> {
        self.need(2)?;
        let mut a = [0u8; 2];
        a.copy_from_slice(&self.data[self.pos..self.pos + 2]);
        self.pos += 2;
        Ok(u16::from_le_bytes(a))
    }

    fn read_u32(&mut self) -> Result<u32, KitError> {
        self.need(4)?;
        let mut a = [0u8; 4];
        a.copy_from_slice(&self.data[self.pos..self.pos + 4]);
        self.pos += 4;
        Ok(u32::from_le_bytes(a))
    }

    fn read_u64(&mut self) -> Result<u64, KitError> {
        self.need(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(&self.data[self.pos..self.pos + 8]);
        self.pos += 8;
        Ok(u64::from_le_bytes(a))
    }

    fn read_hash(&mut self) -> Result<Hash, KitError> {
        self.need(HASH_LEN)?;
        let mut h = [0u8; HASH_LEN];
        h.copy_from_slice(&self.data[self.pos..self.pos + HASH_LEN]);
        self.pos += HASH_LEN;
        Ok(h)
    }

    fn read_fixed<const N: usize>(&mut self) -> Result<[u8; N], KitError> {
        self.need(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(&self.data[self.pos..self.pos + N]);
        self.pos += N;
        Ok(out)
    }

    fn read_lp_bytes(&mut self) -> Result<Vec<u8>, KitError> {
        let len = self.read_u32()? as usize;
        self.need(len)?;
        let v = self.data[self.pos..self.pos + len].to_vec();
        self.pos += len;
        Ok(v)
    }

    fn read_identity(&mut self) -> Result<Identity, KitError> {
        let kind = IdentityKind::from_u8(self.read_u8()?)?;
        let len = self.read_u16()?;
        if len == 0 {
            return Err(KitError::InvalidIdentity);
        }
        if len > IDENTITY_MAX_LEN {
            return Err(KitError::IdentityTooLarge);
        }
        match kind {
            IdentityKind::Ed25519 if len != 32 => return Err(KitError::InvalidIdentity),
            _ => {}
        }
        let len = len as usize;
        self.need(len)?;
        let bytes = self.data[self.pos..self.pos + len].to_vec();
        self.pos += len;
        let id = Identity { kind, bytes };
        // Enforce the full structural invariant at the read boundary so a
        // malformed object from disk/remote can't deserialize with an
        // invalid payload (e.g. a binary `DidKey` that isn't a printable
        // multibase string). `is_valid` is the single source of truth and
        // the serialize side already gates on it.
        if !id.is_valid() {
            return Err(KitError::InvalidIdentity);
        }
        Ok(id)
    }
}

// ---------------------------------------------------------------------
// Readers
// ---------------------------------------------------------------------

fn read_blob(r: &mut Reader<'_>) -> Result<Blob, KitError> {
    Ok(Blob {
        data: r.read_lp_bytes()?,
    })
}

fn read_tree(r: &mut Reader<'_>) -> Result<Tree, KitError> {
    let count = r.read_u32()?;
    if count > MAX_TREE_ENTRIES {
        return Err(KitError::TooManyEntries);
    }
    // Cheap upper bound: each entry is at least name_len(4) + mode(1) +
    // hash(32) = 37 bytes plus a 1-byte name. Reject impossible counts
    // before we allocate the entry vec.
    if (count as usize).saturating_mul(4 + 1 + 1 + HASH_LEN) > r.remaining() {
        return Err(KitError::UnexpectedEof);
    }
    let mut entries: Vec<TreeEntry> = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let name = r.read_lp_bytes()?;
        if !TreeEntry::validate_name(&name) {
            return Err(KitError::InvalidEntryName);
        }
        if let Some(prev) = entries.last()
            && prev.name.as_slice() >= name.as_slice()
        {
            return Err(KitError::InvalidEntryOrder);
        }
        let mode = EntryMode::from_u8(r.read_u8()?)?;
        let object_hash = r.read_hash()?;
        entries.push(TreeEntry {
            name,
            mode,
            object_hash,
        });
    }
    Ok(Tree { entries })
}

fn read_commit(r: &mut Reader<'_>) -> Result<Commit, KitError> {
    let tree_hash = r.read_hash()?;
    let parent_count = r.read_u32()?;
    if parent_count > MAX_PARENTS {
        return Err(KitError::TooManyParents);
    }
    // Cheap upper bound: each parent is HASH_LEN bytes on the wire. If
    // the remaining buffer can't even hold the parent hashes, the
    // header is lying and we must not pre-allocate for it.
    if (parent_count as usize).saturating_mul(HASH_LEN) > r.remaining() {
        return Err(KitError::UnexpectedEof);
    }
    let mut parents = Vec::with_capacity(parent_count as usize);
    for _ in 0..parent_count {
        parents.push(r.read_hash()?);
    }
    let author = r.read_identity()?;
    let message = r.read_lp_bytes()?;
    let timestamp = r.read_u64()?;
    let signer = r.read_fixed::<32>()?;
    let message_hash = r.read_hash()?;
    let content_digest = r.read_hash()?;
    let signature = r.read_fixed::<64>()?;
    Ok(Commit {
        tree_hash,
        parents,
        author,
        signer,
        message,
        timestamp,
        message_hash,
        content_digest,
        signature,
    })
}

fn read_remix(r: &mut Reader<'_>) -> Result<Remix, KitError> {
    let tree_hash = r.read_hash()?;
    let parent_count = r.read_u32()?;
    if parent_count > MAX_PARENTS {
        return Err(KitError::TooManyParents);
    }
    // Cheap upper bound: each parent is HASH_LEN bytes on the wire.
    if (parent_count as usize).saturating_mul(HASH_LEN) > r.remaining() {
        return Err(KitError::UnexpectedEof);
    }
    let mut parents = Vec::with_capacity(parent_count as usize);
    for _ in 0..parent_count {
        parents.push(r.read_hash()?);
    }
    let source_count = r.read_u32()?;
    if source_count > MAX_REMIX_SOURCES {
        return Err(KitError::TooManySources);
    }
    // Each source is two hashes (upstream_id + commit_hash) = 2 *
    // HASH_LEN bytes. Reject impossible counts before allocating.
    if (source_count as usize).saturating_mul(2 * HASH_LEN) > r.remaining() {
        return Err(KitError::UnexpectedEof);
    }
    let mut sources = Vec::with_capacity(source_count as usize);
    for _ in 0..source_count {
        let upstream_id = r.read_hash()?;
        let commit_hash = r.read_hash()?;
        sources.push(RemixSource {
            upstream_id,
            commit_hash,
        });
    }
    let author = r.read_identity()?;
    let message = r.read_lp_bytes()?;
    let timestamp = r.read_u64()?;
    let signer = r.read_fixed::<32>()?;
    let signature = r.read_fixed::<64>()?;
    // Sort check: strict ascending by (upstream_id, commit_hash).
    if sources.len() > 1 {
        for w in sources.windows(2) {
            let a = &w[0];
            let b = &w[1];
            let bad = match a.upstream_id.cmp(&b.upstream_id) {
                core::cmp::Ordering::Greater => true,
                core::cmp::Ordering::Equal => a.commit_hash >= b.commit_hash,
                core::cmp::Ordering::Less => false,
            };
            if bad {
                return Err(KitError::InvalidSourceOrder);
            }
        }
    }
    Ok(Remix {
        tree_hash,
        parents,
        sources,
        author,
        signer,
        message,
        timestamp,
        signature,
    })
}

fn read_tag(r: &mut Reader<'_>) -> Result<Tag, KitError> {
    let target = r.read_hash()?;
    let target_type = ObjectType::from_u8(r.read_u8()?)?;
    check_tag_target_type(target_type)?;
    // `name` is length-prefixed; bound it by TAG_NAME_MAX_LEN before we
    // copy so a bogus header can't force a large allocation.
    let name_len = r.read_u32()? as usize;
    if name_len == 0 || name_len > TAG_NAME_MAX_LEN as usize {
        return Err(KitError::TagNameInvalid);
    }
    r.need(name_len)?;
    let name = r.data[r.pos..r.pos + name_len].to_vec();
    r.pos += name_len;
    if name.iter().any(|&b| matches!(b, 0 | b'/' | b'\\')) {
        return Err(KitError::TagNameInvalid);
    }
    let tagger = r.read_identity()?;
    let message = r.read_lp_bytes()?;
    let timestamp = r.read_u64()?;
    let signer = r.read_fixed::<32>()?;
    let signature = r.read_fixed::<64>()?;
    Ok(Tag {
        target,
        target_type,
        name,
        tagger,
        signer,
        message,
        timestamp,
        signature,
    })
}

fn read_chunked_blob(r: &mut Reader<'_>) -> Result<ChunkedBlob, KitError> {
    let total_size = r.read_u64()?;
    let chunk_size = r.read_u32()?;
    let chunk_count = r.read_u32()?;
    // Decode check 1, then check 2 before any allocation: the entries are
    // exactly what remains.
    if chunk_count > MAX_CHUNKS {
        return Err(KitError::TooManyChunks);
    }
    if (chunk_count as usize).saturating_mul(CHUNKED_ENTRY_LEN) != r.remaining() {
        return Err(KitError::ChunkedBlobLength);
    }
    // Decode checks 3, 4 and 5.
    let mut builder = ChunkedBlobBuilder::new(total_size, chunk_size, chunk_count as usize)?;
    for _ in 0..chunk_count {
        let chunk = r.read_hash()?;
        let end = r.read_u64()?;
        builder.push(chunk, end)?;
    }
    builder.finish()
}

/// Reject a `total_size` that the chunk layout cannot produce. Readers
/// size buffers and disk writes from `total_size`, so it must be bounded
/// before any caller sees it (SPEC-OBJECTS §7).
pub(crate) fn check_chunked_total_size(
    total_size: u64,
    chunk_size: u32,
    chunk_count: u32,
) -> Result<(), KitError> {
    let count = u64::from(chunk_count);
    let size = u64::from(chunk_size);
    let valid = total_size <= MAX_CHUNKED_TOTAL_SIZE
        && if count == 0 {
            total_size == 0
        } else {
            // Each chunk holds at least one byte. With a fixed size, every
            // chunk but the last holds exactly `chunk_size` bytes and the
            // last holds between one and `chunk_size` bytes. A value that
            // names a content-defined chunker is not a size.
            if crate::chunker::Chunker::from_chunk_size(chunk_size).is_some() {
                total_size >= count
            } else {
                total_size > (count - 1) * size && total_size <= count * size
            }
        };
    if valid {
        Ok(())
    } else {
        Err(KitError::ChunkedBlobTotalSizeInvalid)
    }
}

fn read_delta(r: &mut Reader<'_>) -> Result<Delta, KitError> {
    let base_hash = r.read_hash()?;
    let result_size = r.read_u32()?;
    let instructions = r.read_lp_bytes()?;
    Ok(Delta {
        base_hash,
        result_size,
        instructions,
    })
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::{ZERO, hash};
    use proptest::prelude::*;

    fn ed25519_id() -> Identity {
        Identity::ed25519([0xAA; 32])
    }

    proptest! {
        /// `blob_prologue(len) ‖ payload` must be byte-identical to
        /// `serialize(Object::Blob(payload))` — the zero-copy chunk
        /// write path depends on this equivalence, which transitively
        /// pins it to the golden blob vectors.
        #[test]
        fn blob_prologue_plus_payload_equals_serialize_blob(
            payload in proptest::collection::vec(any::<u8>(), 0..2048)
        ) {
            let via_serialize = serialize(&Object::Blob(Blob {
                data: payload.clone(),
            })).unwrap();
            let header = blob_prologue(payload.len()).unwrap();
            let mut via_parts = header.to_vec();
            via_parts.extend_from_slice(&payload);
            prop_assert_eq!(via_parts, via_serialize);
        }
    }

    #[test]
    fn blob_prologue_rejects_oversize_len() {
        assert!(blob_prologue(u32::MAX as usize + 1).is_err());
        assert!(blob_prologue(0).is_ok());
    }

    #[test]
    fn blob_roundtrip() {
        let obj = Object::Blob(Blob {
            data: b"hello world".to_vec(),
        });
        let bytes = serialize(&obj).expect("valid blob serialises");
        // Prologue
        assert_eq!(bytes[0], 0x01);
        assert_eq!(&bytes[1..5], b"KOB1");
        assert_eq!(bytes[5], 0x01);
        let parsed = deserialize(&bytes).unwrap();
        assert_eq!(obj, parsed);
    }

    #[test]
    fn empty_blob_size_is_10() {
        let obj = Object::Blob(Blob { data: vec![] });
        let bytes = serialize(&obj).unwrap();
        assert_eq!(bytes.len(), 10);
        assert_eq!(deserialize(&bytes).unwrap(), obj);
    }

    #[test]
    fn empty_tree_roundtrip() {
        let obj = Object::Tree(Tree { entries: vec![] });
        let bytes = serialize(&obj).unwrap();
        assert_eq!(deserialize(&bytes).unwrap(), obj);
    }

    #[test]
    fn tree_with_three_entries_roundtrip() {
        let obj = Object::Tree(Tree {
            entries: vec![
                TreeEntry {
                    name: b"alpha".to_vec(),
                    mode: EntryMode::Blob,
                    object_hash: hash(b"a"),
                },
                TreeEntry {
                    name: b"beta".to_vec(),
                    mode: EntryMode::Tree,
                    object_hash: hash(b"b"),
                },
                TreeEntry {
                    name: b"gamma".to_vec(),
                    mode: EntryMode::Executable,
                    object_hash: hash(b"g"),
                },
            ],
        });
        assert_eq!(deserialize(&serialize(&obj).unwrap()).unwrap(), obj);
    }

    #[test]
    fn commit_with_one_parent_roundtrip() {
        let obj = Object::Commit(Commit::new_unannotated(
            hash(b"tree"),
            vec![hash(b"parent")],
            ed25519_id(),
            [0xAA; 32],
            b"initial".to_vec(),
            1_711_300_000,
            [0xBB; 64],
        ));
        assert_eq!(deserialize(&serialize(&obj).unwrap()).unwrap(), obj);
    }

    #[test]
    fn root_commit_roundtrip() {
        let obj = Object::Commit(Commit::new_unannotated(
            hash(b"tree"),
            vec![],
            ed25519_id(),
            [0x11; 32],
            b"genesis".to_vec(),
            1_000_000,
            [0x22; 64],
        ));
        assert_eq!(deserialize(&serialize(&obj).unwrap()).unwrap(), obj);
    }

    #[test]
    fn commit_with_opaque_identity_roundtrip() {
        let mid = vec![42u8, 0, 0, 0, 0, 0, 0, 0];
        let obj = Object::Commit(Commit::new_unannotated(
            hash(b"tree"),
            vec![],
            Identity::opaque(mid.clone()),
            [0xAA; 32],
            b"opaque author".to_vec(),
            1_700_000_000,
            [0xBB; 64],
        ));
        let parsed = deserialize(&serialize(&obj).unwrap()).unwrap();
        if let Object::Commit(c) = &parsed {
            assert_eq!(c.author.kind, IdentityKind::Opaque);
            assert_eq!(c.author.bytes, mid);
        } else {
            panic!("not a commit");
        }
        assert_eq!(parsed, obj);
    }

    #[test]
    fn remix_with_one_source_roundtrip() {
        let obj = Object::Remix(Remix {
            tree_hash: hash(b"tree"),
            parents: vec![],
            sources: vec![RemixSource {
                upstream_id: hash(b"project-a"),
                commit_hash: hash(b"commit-x"),
            }],
            author: ed25519_id(),
            signer: [0xCC; 32],
            message: b"remixed".to_vec(),
            timestamp: 1_711_300_100,
            signature: [0xDD; 64],
        });
        assert_eq!(deserialize(&serialize(&obj).unwrap()).unwrap(), obj);
    }

    #[test]
    fn chunked_blob_roundtrip() {
        let obj = Object::ChunkedBlob(
            crate::object::testing::spread(
                3 * 65536,
                65536,
                vec![hash(b"c1"), hash(b"c2"), hash(b"c3")],
            )
            .unwrap(),
        );
        let bytes = serialize(&obj).unwrap();
        assert_eq!(bytes[0], 0x05);
        assert_eq!(deserialize(&bytes).unwrap(), obj);
    }

    #[test]
    fn chunked_blob_cdc_marker_roundtrips() {
        let obj = Object::ChunkedBlob(
            crate::object::testing::spread(100_000, 0, vec![hash(b"x"), hash(b"y")]).unwrap(),
        );
        assert_eq!(deserialize(&serialize(&obj).unwrap()).unwrap(), obj);
    }

    fn sample_tag() -> Tag {
        Tag {
            target: hash(b"target-commit"),
            target_type: ObjectType::Commit,
            name: b"v1.0.0".to_vec(),
            tagger: ed25519_id(),
            signer: [0xAA; 32],
            message: b"release 1.0.0".to_vec(),
            timestamp: 1_711_300_000,
            signature: [0xCC; 64],
        }
    }

    #[test]
    fn tag_roundtrip() {
        let obj = Object::Tag(sample_tag());
        let bytes = serialize(&obj).unwrap();
        assert_eq!(bytes[0], 0x07, "tag object_type tag");
        assert_eq!(&bytes[1..5], b"KOB1");
        assert_eq!(bytes[5], 0x01);
        assert_eq!(deserialize(&bytes).unwrap(), obj);
    }

    #[test]
    fn tag_empty_message_roundtrip() {
        let mut t = sample_tag();
        t.message = vec![];
        let obj = Object::Tag(t);
        assert_eq!(deserialize(&serialize(&obj).unwrap()).unwrap(), obj);
    }

    #[test]
    fn tag_rejects_empty_name() {
        let mut t = sample_tag();
        t.name = vec![];
        assert_eq!(serialize(&Object::Tag(t)), Err(KitError::TagNameInvalid));
    }

    #[test]
    fn tag_rejects_delta_target_type() {
        let mut t = sample_tag();
        t.target_type = ObjectType::Delta;
        assert_eq!(
            serialize(&Object::Tag(t)),
            Err(KitError::TagTargetTypeInvalid(ObjectType::Delta as u8))
        );
    }

    #[test]
    fn tag_decode_rejects_forbidden_name_byte() {
        // Hand-craft a tag whose name embeds a `/`. The writer would
        // reject it, so build the wire bytes directly.
        let mut buf = vec![0x07, b'K', b'O', b'B', b'1', 0x01];
        buf.extend_from_slice(&[0u8; 32]); // target
        buf.push(ObjectType::Commit as u8); // target_type
        buf.extend_from_slice(&3u32.to_le_bytes()); // name_len
        buf.extend_from_slice(b"a/b");
        assert_eq!(deserialize(&buf), Err(KitError::TagNameInvalid));
    }

    // ---- Negative tests ----

    #[test]
    fn deserialize_empty_input() {
        assert_eq!(deserialize(&[]), Err(KitError::EmptyData));
    }

    #[test]
    fn rejects_invalid_object_type() {
        let bad = [0xFF, b'K', b'O', b'B', b'1', 0x01];
        assert_eq!(deserialize(&bad), Err(KitError::InvalidObjectType(0xFF)));
    }

    #[test]
    fn rejects_bad_magic() {
        let bad = [0x01, b'X', b'Y', b'Z', b'W', 0x01, 0, 0, 0, 0];
        assert_eq!(deserialize(&bad), Err(KitError::InvalidMagic));
    }

    #[test]
    fn rejects_unsupported_schema_version() {
        let bad = [0x01, b'K', b'O', b'B', b'1', 0x02, 0, 0, 0, 0];
        assert_eq!(deserialize(&bad), Err(KitError::UnsupportedObjectVersion));
    }

    #[test]
    fn rejects_truncated_blob() {
        // length=100 but only 2 bytes follow
        let bad = [
            0x01, b'K', b'O', b'B', b'1', 0x01, 0x64, 0x00, 0x00, 0x00, 0xAA, 0xBB,
        ];
        assert_eq!(deserialize(&bad), Err(KitError::UnexpectedEof));
    }

    #[test]
    fn rejects_unsorted_tree_entries() {
        // Build an unsorted tree by hand — can't go through serialize()
        // because writers don't validate ordering today.
        let mut buf = vec![0x02, b'K', b'O', b'B', b'1', 0x01];
        buf.extend_from_slice(&2u32.to_le_bytes());
        // entry "z.txt"
        buf.extend_from_slice(&5u32.to_le_bytes());
        buf.extend_from_slice(b"z.txt");
        buf.push(EntryMode::Blob as u8);
        buf.extend_from_slice(&[0u8; 32]);
        // entry "a.txt"
        buf.extend_from_slice(&5u32.to_le_bytes());
        buf.extend_from_slice(b"a.txt");
        buf.push(EntryMode::Blob as u8);
        buf.extend_from_slice(&[0u8; 32]);
        assert_eq!(deserialize(&buf), Err(KitError::InvalidEntryOrder));
    }

    #[test]
    fn rejects_trailing_bytes() {
        let obj = Object::Blob(Blob {
            data: b"hello".to_vec(),
        });
        let mut bytes = serialize(&obj).unwrap();
        bytes.push(0xFF);
        assert_eq!(deserialize(&bytes), Err(KitError::TrailingData));
    }

    #[test]
    fn rejects_zero_length_identity() {
        let mut buf = vec![0x03, b'K', b'O', b'B', b'1', 0x01];
        buf.extend_from_slice(&[0u8; 32]); // tree_hash
        buf.extend_from_slice(&0u32.to_le_bytes()); // parent_count
        buf.push(IdentityKind::Opaque as u8);
        buf.extend_from_slice(&0u16.to_le_bytes()); // len = 0
        assert_eq!(deserialize(&buf), Err(KitError::InvalidIdentity));
    }

    #[test]
    fn rejects_unknown_identity_kind() {
        let mut buf = vec![0x03, b'K', b'O', b'B', b'1', 0x01];
        buf.extend_from_slice(&[0u8; 32]);
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.push(0xEE); // unknown kind
        buf.extend_from_slice(&4u16.to_le_bytes());
        buf.extend_from_slice(b"xxxx");
        assert_eq!(deserialize(&buf), Err(KitError::UnknownIdentityKind(0xEE)));
    }

    #[test]
    fn rejects_ed25519_with_wrong_length() {
        let mut buf = vec![0x03, b'K', b'O', b'B', b'1', 0x01];
        buf.extend_from_slice(&[0u8; 32]);
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.push(IdentityKind::Ed25519 as u8);
        buf.extend_from_slice(&8u16.to_le_bytes());
        buf.extend_from_slice(b"12345678");
        assert_eq!(deserialize(&buf), Err(KitError::InvalidIdentity));
    }

    #[test]
    fn rejects_oversize_identity() {
        let mut buf = vec![0x03, b'K', b'O', b'B', b'1', 0x01];
        buf.extend_from_slice(&[0u8; 32]);
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.push(IdentityKind::Opaque as u8);
        buf.extend_from_slice(&(IDENTITY_MAX_LEN + 1).to_le_bytes());
        buf.extend(core::iter::repeat_n(0u8, IDENTITY_MAX_LEN as usize + 1));
        assert_eq!(deserialize(&buf), Err(KitError::IdentityTooLarge));
    }

    #[test]
    fn rejects_too_many_tree_entries() {
        let mut buf = vec![0x02, b'K', b'O', b'B', b'1', 0x01];
        buf.extend_from_slice(&(MAX_TREE_ENTRIES + 1).to_le_bytes());
        assert_eq!(deserialize(&buf), Err(KitError::TooManyEntries));
    }

    // ---- Fallible-serialize tests ----

    #[test]
    fn serialize_rejects_invalid_identity_in_commit() {
        // Empty payload is structurally invalid for every kind.
        let bad_id = Identity {
            kind: IdentityKind::Opaque,
            bytes: Vec::new(),
        };
        let obj = Object::Commit(Commit::new_unannotated(
            hash(b"tree"),
            vec![],
            bad_id,
            [0; 32],
            b"x".to_vec(),
            0,
            [0; 64],
        ));
        assert_eq!(serialize(&obj), Err(KitError::InvalidIdentity));
    }

    #[test]
    fn read_identity_rejects_non_multibase_didkey() {
        // Wire format: [u8 kind][u16 LE len][payload]. A DidKey payload must
        // be a printable-ASCII multibase string, so a malformed object with a
        // binary/whitespace DidKey payload must be rejected at the read
        // boundary, not silently deserialized.
        let id_bytes = |payload: &[u8]| {
            let mut b = vec![0x02u8]; // IdentityKind::DidKey
            let len = u16::try_from(payload.len()).expect("test payload fits u16");
            b.extend_from_slice(&len.to_le_bytes());
            b.extend_from_slice(payload);
            b
        };
        // NUL, high byte, and whitespace payloads all reject.
        for bad in [b"z\x00ab".as_slice(), b"z\xff", b"z6Mk has space"] {
            let buf = id_bytes(bad);
            assert_eq!(
                Reader::new(&buf).read_identity(),
                Err(KitError::InvalidIdentity),
                "should reject DidKey payload {bad:?} at the read boundary"
            );
        }
        // A real did:key multibase payload round-trips.
        let good = id_bytes(b"z6MkExample");
        let id = Reader::new(&good).read_identity().unwrap();
        assert_eq!(id.kind, IdentityKind::DidKey);
        assert_eq!(id.bytes, b"z6MkExample");
    }

    #[test]
    fn serialize_rejects_invalid_identity_in_remix() {
        // Ed25519 with non-32-byte payload.
        let bad_id = Identity {
            kind: IdentityKind::Ed25519,
            bytes: vec![0u8; 16],
        };
        let obj = Object::Remix(Remix {
            tree_hash: ZERO,
            parents: vec![],
            sources: vec![],
            author: bad_id,
            signer: [0; 32],
            message: b"x".to_vec(),
            timestamp: 0,
            signature: [0; 64],
        });
        assert_eq!(serialize(&obj), Err(KitError::InvalidIdentity));
    }

    /// `read_commit` claims `parent_count = MAX_PARENTS` (`1_000`) but
    /// the remaining buffer is too small to ever hold that many
    /// 32-byte parent hashes. The pre-allocation guard must reject the
    /// header before the parent vec is sized from attacker input.
    #[test]
    fn rejects_truncated_commit_parents() {
        let mut buf = vec![0x03, b'K', b'O', b'B', b'1', 0x01];
        buf.extend_from_slice(&[0u8; 32]); // tree_hash
        // Within MAX_PARENTS (1_000) so the existing TooManyParents
        // guard doesn't fire — we want to confirm the capacity-vs-
        // remaining check rejects too. 1_000 parents = 32_000 bytes,
        // but only a single 32-byte hash follows.
        buf.extend_from_slice(&1_000u32.to_le_bytes()); // parent_count
        buf.extend_from_slice(&[0xAA; 32]); // only one parent worth
        assert_eq!(deserialize(&buf), Err(KitError::UnexpectedEof));
    }

    /// `read_remix` claims `source_count = MAX_REMIX_SOURCES` (`10_000`)
    /// but the remaining buffer cannot accommodate even one source
    /// (which is 64 bytes — two hashes). Reject without allocating.
    #[test]
    fn rejects_truncated_remix_sources() {
        let mut buf = vec![0x04, b'K', b'O', b'B', b'1', 0x01];
        buf.extend_from_slice(&[0u8; 32]); // tree_hash
        buf.extend_from_slice(&0u32.to_le_bytes()); // parent_count
        // 10_000 sources × 64 bytes = 640_000 bytes required, but the
        // buffer is empty after this point.
        buf.extend_from_slice(&10_000u32.to_le_bytes()); // source_count
        assert_eq!(deserialize(&buf), Err(KitError::UnexpectedEof));
    }

    #[test]
    fn rejects_too_many_commit_parents() {
        let mut buf = vec![0x03, b'K', b'O', b'B', b'1', 0x01];
        buf.extend_from_slice(&[0u8; 32]); // tree_hash
        buf.extend_from_slice(&(MAX_PARENTS + 1).to_le_bytes()); // parent_count
        assert_eq!(deserialize(&buf), Err(KitError::TooManyParents));
    }

    #[test]
    fn rejects_too_many_remix_parents() {
        let mut buf = vec![0x04, b'K', b'O', b'B', b'1', 0x01];
        buf.extend_from_slice(&[0u8; 32]); // tree_hash
        buf.extend_from_slice(&(MAX_PARENTS + 1).to_le_bytes()); // parent_count
        assert_eq!(deserialize(&buf), Err(KitError::TooManyParents));
    }

    #[test]
    fn rejects_too_many_remix_sources() {
        let mut buf = vec![0x04, b'K', b'O', b'B', b'1', 0x01];
        buf.extend_from_slice(&[0u8; 32]); // tree_hash
        buf.extend_from_slice(&0u32.to_le_bytes()); // parent_count
        buf.extend_from_slice(&(MAX_REMIX_SOURCES + 1).to_le_bytes()); // source_count
        assert_eq!(deserialize(&buf), Err(KitError::TooManySources));
    }

    /// The 22-byte prologue and header of a manifest.
    fn chunked_header(total: u64, chunk_size: u32, count: u32) -> Vec<u8> {
        let mut buf = vec![0x05, b'K', b'O', b'B', b'1', 0x02];
        buf.extend_from_slice(&total.to_le_bytes());
        buf.extend_from_slice(&chunk_size.to_le_bytes());
        buf.extend_from_slice(&count.to_le_bytes());
        buf
    }

    /// A manifest whose chunk `i` is `hash(le32(i))` and ends at `ends[i]`.
    fn chunked_bytes(total: u64, chunk_size: u32, ends: &[u64]) -> Vec<u8> {
        let mut buf = chunked_header(total, chunk_size, u32::try_from(ends.len()).unwrap());
        for (i, end) in ends.iter().enumerate() {
            buf.extend_from_slice(&hash(&u32::try_from(i).unwrap().to_le_bytes()));
            buf.extend_from_slice(&end.to_le_bytes());
        }
        buf
    }

    #[test]
    fn rejects_too_many_chunks() {
        assert_eq!(
            deserialize(&chunked_header(1024, 0, MAX_CHUNKS + 1)),
            Err(KitError::TooManyChunks)
        );
    }

    /// The manifest is version 2, and the old version is refused.
    #[test]
    fn a_manifest_is_schema_version_2() {
        let mut bytes = chunked_bytes(10, 0, &[10]);
        assert_eq!(bytes[5], 0x02);
        assert!(deserialize(&bytes).is_ok());
        bytes[5] = 0x01;
        assert_eq!(deserialize(&bytes), Err(KitError::UnsupportedObjectVersion));
    }

    /// Decode check 2: the entries are exactly what remains, checked before
    /// any allocation, so a short or long body is a length error.
    #[test]
    fn rejects_a_chunk_list_of_the_wrong_length() {
        let mut short = chunked_header(1024, 0, 2);
        short.extend_from_slice(&[0xAA; 40]); // one entry of two
        assert_eq!(deserialize(&short), Err(KitError::ChunkedBlobLength));
        let mut long = chunked_bytes(10, 0, &[10]);
        long.push(0);
        assert_eq!(deserialize(&long), Err(KitError::ChunkedBlobLength));
        // A header at the chunk cap with no entries fails on the length,
        // not on an allocation.
        assert_eq!(
            deserialize(&chunked_header(MAX_CHUNKED_TOTAL_SIZE, 0, MAX_CHUNKS)),
            Err(KitError::ChunkedBlobLength)
        );
        // Fewer than 22 bytes is a truncated header.
        assert_eq!(
            deserialize(&chunked_header(1, 0, 0)[..20]),
            Err(KitError::UnexpectedEof)
        );
    }

    #[test]
    fn rejects_chunked_blob_total_size_beyond_the_bound() {
        for total in [u64::MAX, 1 << 62, MAX_CHUNKED_TOTAL_SIZE + 1] {
            assert_eq!(
                deserialize(&chunked_bytes(total, 0, &[1, 2])),
                Err(KitError::ChunkedBlobTotalSizeInvalid)
            );
        }
    }

    /// Decode check 4, per entry, in the order the checks run.
    #[test]
    fn rejects_each_bad_entry_with_its_own_error() {
        // Not increasing: a repeated end, and a zero end.
        assert_eq!(
            deserialize(&chunked_bytes(10, 0, &[5, 5, 10])),
            Err(KitError::ChunkEndNotIncreasing { index: 1 })
        );
        assert_eq!(
            deserialize(&chunked_bytes(10, 0, &[0, 10])),
            Err(KitError::ChunkEndNotIncreasing { index: 0 })
        );
        // A span above one Blob object.
        assert_eq!(
            deserialize(&chunked_bytes(MAX_CHUNK_LEN + 1, 0, &[MAX_CHUNK_LEN + 1])),
            Err(KitError::ChunkLengthAboveLimit { index: 0 })
        );
        // An end past the total.
        assert_eq!(
            deserialize(&chunked_bytes(10, 0, &[11])),
            Err(KitError::ChunkEndAboveTotalSize { index: 0 })
        );
        // A fixed layout that does not end at `min((i + 1) * size, total)`.
        assert_eq!(
            deserialize(&chunked_bytes(196_608, 65_536, &[65_536, 100_000, 196_608])),
            Err(KitError::FixedChunkEnd { index: 1 })
        );
        // Decode check 5: the last end is the total, and no chunks mean no
        // bytes.
        assert_eq!(
            deserialize(&chunked_bytes(10, 0, &[4, 9])),
            Err(KitError::ChunkedBlobLastEnd)
        );
        assert_eq!(
            deserialize(&chunked_bytes(1, 0, &[])),
            Err(KitError::ChunkedBlobNoChunks)
        );
        // Good manifests of both layouts.
        assert!(deserialize(&chunked_bytes(10, 0, &[3, 4, 10])).is_ok());
        assert!(deserialize(&chunked_bytes(131_073, 65_536, &[65_536, 131_072, 131_073])).is_ok());
        assert!(deserialize(&chunked_bytes(0, 0, &[])).is_ok());
    }

    /// Each manifest entry is a 32-byte id then the end, little-endian.
    #[test]
    fn a_manifest_is_laid_out_as_22_plus_40_per_chunk() {
        let cb = ChunkedBlob::new(10, 0, [([1u8; 32], 4), ([2u8; 32], 10)]).unwrap();
        let bytes = serialize(&Object::ChunkedBlob(cb)).unwrap();
        assert_eq!(bytes.len(), CHUNKED_HEADER_LEN + 2 * CHUNKED_ENTRY_LEN);
        assert_eq!(&bytes[..6], &[0x05, b'K', b'O', b'B', b'1', 0x02]);
        assert_eq!(&bytes[6..14], &10u64.to_le_bytes());
        assert_eq!(&bytes[14..18], &0u32.to_le_bytes());
        assert_eq!(&bytes[18..22], &2u32.to_le_bytes());
        assert_eq!(&bytes[22..54], &[1u8; 32]);
        assert_eq!(&bytes[54..62], &4u64.to_le_bytes());
        assert_eq!(&bytes[62..94], &[2u8; 32]);
        assert_eq!(&bytes[94..102], &10u64.to_le_bytes());
    }

    /// `ChunkedBlob::new` refuses every manifest the reader refuses, so no
    /// value the writer sees is undecodable.
    #[test]
    fn new_refuses_a_manifest_the_reader_refuses() {
        // `new` builds the entries before the cap, then refuses the next one.
        assert_eq!(
            ChunkedBlob::new(
                MAX_CHUNKED_TOTAL_SIZE,
                0,
                (0..=u64::from(MAX_CHUNKS)).map(|i| ([0u8; 32], i + 1))
            ),
            Err(KitError::TooManyChunks)
        );
        assert_eq!(
            ChunkedBlob::new(MAX_CHUNKED_TOTAL_SIZE + 1, 0, [([1u8; 32], 5)]),
            Err(KitError::ChunkedBlobTotalSizeInvalid)
        );
        assert_eq!(
            ChunkedBlob::new(10, 0, [([1u8; 32], 5), ([1u8; 32], 5)]),
            Err(KitError::ChunkEndNotIncreasing { index: 1 })
        );
        assert_eq!(
            ChunkedBlob::new(10, 0, [([1u8; 32], 11)]),
            Err(KitError::ChunkEndAboveTotalSize { index: 0 })
        );
        assert_eq!(
            ChunkedBlob::new(10, 0, [([1u8; 32], 5)]),
            Err(KitError::ChunkedBlobLastEnd)
        );
        // A fixed size the chunks cannot fill, and one they overfill.
        assert_eq!(
            ChunkedBlob::new(131_072, 65_536, [([1u8; 32], 65_536)]),
            Err(KitError::ChunkedBlobLastEnd)
        );
        assert_eq!(
            ChunkedBlob::new(65_536, 65_536, [([1u8; 32], 65_536), ([2u8; 32], 65_537)]),
            Err(KitError::ChunkEndAboveTotalSize { index: 1 })
        );
        // Zero chunks mean zero bytes.
        assert_eq!(
            ChunkedBlob::new(1, 0, Vec::new()),
            Err(KitError::ChunkedBlobNoChunks)
        );
    }

    /// The bounds themselves still build, serialize and decode.
    #[test]
    fn a_manifest_at_the_bound_round_trips() {
        let count = MAX_CHUNKED_TOTAL_SIZE.div_ceil(MAX_CHUNK_LEN);
        let at_bound = Object::ChunkedBlob(
            ChunkedBlob::new(
                MAX_CHUNKED_TOTAL_SIZE,
                0,
                (1..=count).map(|i| {
                    (
                        hash(&i.to_le_bytes()),
                        (i * MAX_CHUNK_LEN).min(MAX_CHUNKED_TOTAL_SIZE),
                    )
                }),
            )
            .unwrap(),
        );
        assert_eq!(deserialize(&serialize(&at_bound).unwrap()), Ok(at_bound));
        let empty = Object::ChunkedBlob(ChunkedBlob::new(0, 0, Vec::new()).unwrap());
        assert_eq!(deserialize(&serialize(&empty).unwrap()), Ok(empty));
    }

    /// The writer checks every entry too, as a second line of defence: a
    /// value built past `new` is still refused before any byte is written.
    #[test]
    fn serialize_refuses_a_manifest_the_reader_refuses() {
        let over_size = Object::ChunkedBlob(ChunkedBlob::new_unchecked(
            MAX_CHUNKED_TOTAL_SIZE + 1,
            0,
            vec![[1u8; 32]],
            vec![MAX_CHUNKED_TOTAL_SIZE + 1],
        ));
        assert_eq!(
            serialize(&over_size),
            Err(KitError::ChunkedBlobTotalSizeInvalid)
        );
        let flat = Object::ChunkedBlob(ChunkedBlob::new_unchecked(
            10,
            0,
            vec![[1u8; 32], [2u8; 32]],
            vec![5, 5],
        ));
        assert_eq!(
            serialize(&flat),
            Err(KitError::ChunkEndNotIncreasing { index: 1 })
        );
        let short =
            Object::ChunkedBlob(ChunkedBlob::new_unchecked(10, 0, vec![[1u8; 32]], vec![5]));
        assert_eq!(serialize(&short), Err(KitError::ChunkedBlobLastEnd));
    }

    /// The capacity hint of a manifest is its exact encoded length, so
    /// `serialize` allocates once.
    #[test]
    fn the_capacity_estimate_of_a_manifest_is_its_encoded_length() {
        for count in [0usize, 1, 3] {
            let cb =
                crate::object::testing::spread(count as u64, 0, vec![[1u8; 32]; count]).unwrap();
            let obj = Object::ChunkedBlob(cb);
            assert_eq!(
                PROLOGUE_LEN + estimated_body_len(&obj),
                serialize(&obj).unwrap().len()
            );
        }
    }

    #[test]
    fn check_chunked_header_applies_the_decode_rules() {
        assert_eq!(
            check_chunked_header(MAX_CHUNKED_TOTAL_SIZE, MAX_CHUNKS),
            Ok(())
        );
        assert_eq!(
            check_chunked_header(MAX_CHUNKED_TOTAL_SIZE, MAX_CHUNKS + 1),
            Err(KitError::TooManyChunks)
        );
        assert_eq!(
            check_chunked_header(MAX_CHUNKED_TOTAL_SIZE + 1, 2),
            Err(KitError::ChunkedBlobTotalSizeInvalid)
        );
        // The header run by the decoder and the fold is checks 1 and 3: it
        // does not see the layout.
        assert_eq!(check_chunked_header(1, 2), Ok(()));
    }

    /// SPEC-OBJECTS section 7: the header layouts, as `(total_size,
    /// chunk_size, chunk_count)`, that the header-only check accepts and
    /// refuses. The reference check in `scripts/golden/objects_ref.py` holds
    /// the same table.
    #[test]
    fn check_chunked_total_size_matches_the_layout_table() {
        const ACCEPTED: &[(u64, u32, u32)] = &[
            (0, 0, 0),
            (3, 0, 3),
            (196_608, 65_536, 3),
            (131_073, 65_536, 3),
            (1, 65_536, 1),
            (65_536, 65_536, 1),
            (1 << 30, 0, 2),
            ((1 << 30) + 1, 0, 2),
            (128 << 30, 0, 2),
            (0, 0x8000_0002, 0),
            (3, 0x8000_0002, 3),
            (128 << 30, 0x8000_0002, 2),
            (1, 0x8000_0001, 1),
        ];
        const REFUSED: &[(u64, u32, u32)] = &[
            (1, 0, 0),
            (2, 0, 3),
            ((128 << 30) + 1, 0, 2),
            (196_609, 65_536, 3),
            (131_072, 65_536, 3),
            (65_536, 65_536, 2),
            (1, 65_536, 2),
            (0, 65_536, 1),
            (1, 0x8000_0002, 0),
            (2, 0x8000_0002, 3),
            ((128 << 30) + 1, 0x8000_0002, 2),
            (3, 0x8000_0001, 3),
        ];
        for &(total, size, count) in ACCEPTED {
            assert_eq!(
                check_chunked_total_size(total, size, count),
                Ok(()),
                "({total}, {size}, {count}) must be accepted"
            );
        }
        for &(total, size, count) in REFUSED {
            assert_eq!(
                check_chunked_total_size(total, size, count),
                Err(KitError::ChunkedBlobTotalSizeInvalid),
                "({total}, {size}, {count}) must be refused"
            );
        }
    }

    #[test]
    fn rejects_remix_out_of_order_sources() {
        // read_remix's decode-path sort check: sources must be strictly
        // ascending by (upstream_id, commit_hash) (SPEC-OBJECTS remix
        // source ordering). The encoder (write_remix) does not itself
        // sort or validate — it trusts the caller — so a decode-path
        // regression here would only be caught by feeding a crafted
        // (but encoder-producible) out-of-order Remix through
        // `serialize` + `deserialize`, not by round-tripping a
        // well-formed one.
        let sources = vec![
            RemixSource {
                upstream_id: [2u8; 32],
                commit_hash: [0u8; 32],
            },
            RemixSource {
                upstream_id: [1u8; 32], // decreases -> violates strict ascending order
                commit_hash: [0u8; 32],
            },
        ];
        let remix = Remix {
            tree_hash: hash(b"tree"),
            parents: vec![],
            sources,
            author: Identity::ed25519([0u8; 32]),
            signer: [0u8; 32],
            message: b"msg".to_vec(),
            timestamp: 0,
            signature: [0u8; 64],
        };
        let bytes = serialize(&Object::Remix(remix)).unwrap();
        assert_eq!(deserialize(&bytes), Err(KitError::InvalidSourceOrder));
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn checked_u32_rejects_oversize() {
        // Direct unit test on the bounds helper — we cannot allocate a
        // Vec with > u32::MAX entries in a unit test, so exercise the
        // guard surface itself. This pins the field-name string so
        // downstream consumers can grep on it. 32-bit targets cannot
        // even construct `n`, so the test is gated on pointer width.
        let n: usize = u32::MAX as usize + 1;
        let err = checked_u32("blob.data", n).unwrap_err();
        assert_eq!(
            err,
            KitError::OversizePayload {
                field: "blob.data",
                len: n,
            }
        );
    }

    // -- Property tests -------------------------------------------------
    //
    // Round-trip invariants exercised against arbitrary inputs via
    // `proptest`. The example tests above cover specific vectors and
    // the goldens pin wire bytes; the properties below catch the
    // boundary cases the examples miss (empty payloads, max-length
    // strings, non-ASCII bytes, etc.).
    proptest::proptest! {
        /// Any blob round-trips byte-for-byte through serialize/deserialize.
        #[test]
        fn proptest_blob_roundtrip(data in proptest::collection::vec(proptest::num::u8::ANY, 0..4096)) {
            let obj = Object::Blob(Blob { data });
            let bytes = serialize(&obj).expect("blob serialises");
            let parsed = deserialize(&bytes).expect("blob deserialises");
            proptest::prop_assert_eq!(obj, parsed);
        }

        /// Any commit (single parent, fixed identity) round-trips
        /// byte-for-byte. Covers arbitrary tree hashes, arbitrary parent
        /// hashes, arbitrary message bytes including non-UTF-8 sequences
        /// (commit messages are bytes per SPEC-OBJECTS §5). Signer + sig
        /// arrays are constructed from a u8 seed (proptest only ships
        /// `uniform32` natively; 64-byte signatures get a tiled seed).
        #[test]
        fn proptest_commit_roundtrip(
            tree in proptest::array::uniform32(proptest::num::u8::ANY),
            parent in proptest::array::uniform32(proptest::num::u8::ANY),
            signer in proptest::array::uniform32(proptest::num::u8::ANY),
            msg in proptest::collection::vec(proptest::num::u8::ANY, 0..2048),
            sig_seed in proptest::num::u8::ANY,
            ts in 0u64..u64::from(u32::MAX),
        ) {
            let mut sig = [0u8; 64];
            sig.fill(sig_seed);
            let commit = Commit::new_unannotated(
                tree,
                vec![parent],
                ed25519_id(),
                signer,
                msg,
                ts,
                sig,
            );
            let obj = Object::Commit(commit);
            let bytes = serialize(&obj).expect("commit serialises");
            let parsed = deserialize(&bytes).expect("commit deserialises");
            proptest::prop_assert_eq!(obj, parsed);
        }
    }
}

/// Kani proof harnesses (`cargo kani -p kit-core --no-default-features
/// -Z stubbing --harness serialize_`, see `delta.rs`), the model-checked counterpart of the `tree` fuzz target.
///
/// `deserialize` is verified compositionally: the prologue/dispatch/
/// trailing-byte logic with the per-type readers replaced by
/// nondeterministic stand-ins, and each reader on its own. Monolithic
/// runs are out of reach: CBMC symbolically executes every `match` arm
/// (even with a pinned tag), and the count-driven readers'
/// `Vec::with_capacity(count)` with a symbolic count runs out of memory
/// even at 0..=4-byte bodies, so `read_tree` is checked with the entry
/// count pinned to 1 (every other byte symbolic). Inputs are checked at
/// every concrete length up to the stated bound (one call per length),
/// which keeps slice lengths constant for CBMC.
#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// Calls `$f::<N>()` for each listed literal `N`.
    macro_rules! each_len {
        ($f:ident; $($n:literal)*) => { $( $f::<$n>(); )* };
    }

    /// Advance the reader by a nondeterministic amount within bounds.
    fn consume_any(r: &mut Reader<'_>) {
        let n: usize = kani::any_where(|&n| n <= r.remaining());
        r.pos += n;
    }
    fn any_blob(r: &mut Reader<'_>) -> Result<Blob, KitError> {
        consume_any(r);
        if kani::any() {
            Ok(Blob { data: Vec::new() })
        } else {
            Err(KitError::UnexpectedEof)
        }
    }
    fn any_tree(r: &mut Reader<'_>) -> Result<Tree, KitError> {
        consume_any(r);
        if kani::any() {
            Ok(Tree {
                entries: Vec::new(),
            })
        } else {
            Err(KitError::InvalidEntryOrder)
        }
    }
    fn any_err_commit(r: &mut Reader<'_>) -> Result<Commit, KitError> {
        consume_any(r);
        Err(KitError::UnexpectedEof)
    }
    fn any_err_remix(r: &mut Reader<'_>) -> Result<Remix, KitError> {
        consume_any(r);
        Err(KitError::UnexpectedEof)
    }
    fn any_err_chunked(r: &mut Reader<'_>) -> Result<ChunkedBlob, KitError> {
        consume_any(r);
        Err(KitError::UnexpectedEof)
    }
    fn any_err_delta(r: &mut Reader<'_>) -> Result<Delta, KitError> {
        consume_any(r);
        Err(KitError::UnexpectedEof)
    }
    fn any_err_tag(r: &mut Reader<'_>) -> Result<Tag, KitError> {
        consume_any(r);
        Err(KitError::UnexpectedEof)
    }

    fn prologue_at<const N: usize>() -> bool {
        let data: [u8; N] = kani::any();
        deserialize(&data).is_ok()
    }

    /// Prologue (§2), dispatch, and the §11 trailing-byte rule: for every
    /// input of <= 12 bytes (tag, magic, version, body symbolic) and any
    /// behaviour of the per-type readers (each consumes a nondeterministic
    /// in-bounds prefix and succeeds or fails), `deserialize` never
    /// panics/overflows/reads OOB.
    #[kani::proof]
    #[kani::stub(read_blob, any_blob)]
    #[kani::stub(read_tree, any_tree)]
    #[kani::stub(read_commit, any_err_commit)]
    #[kani::stub(read_remix, any_err_remix)]
    #[kani::stub(read_chunked_blob, any_err_chunked)]
    #[kani::stub(read_delta, any_err_delta)]
    #[kani::stub(read_tag, any_err_tag)]
    #[kani::unwind(6)]
    fn serialize_prologue_no_panic() {
        each_len!(prologue_at; 0 1 2 3 4 5 6 7 8 9 10 11);
        kani::cover!(prologue_at::<12>(), "ok");
    }

    fn readers_at<const N: usize>() -> bool {
        let body: [u8; N] = kani::any();
        let mut ok = false;
        let mut r = Reader::new(&body);
        ok |= read_blob(&mut r).is_ok();
        assert!(r.pos <= N);
        ok |= read_commit(&mut Reader::new(&body)).is_ok();
        ok |= read_remix(&mut Reader::new(&body)).is_ok();
        ok |= read_tag(&mut Reader::new(&body)).is_ok();
        ok |= read_chunked_blob(&mut Reader::new(&body)).is_ok();
        ok |= read_delta(&mut Reader::new(&body)).is_ok();
        ok
    }

    /// The non-tree readers (§3, §5–§8) on every body of 0..=12 bytes:
    /// no panic/overflow/OOB. Only blobs can succeed this short (cover);
    /// the others need >= 16-byte bodies, so this bound reaches their
    /// truncation paths only.
    #[kani::proof]
    #[kani::unwind(3)]
    fn serialize_read_other_types_no_panic() {
        each_len!(readers_at; 0 1 2 3 4 5 6 7 8 9 10 11);
        kani::cover!(readers_at::<12>(), "ok_blob");
    }

    /// Nondeterministic stand-in for `TreeEntry::validate_name` in the
    /// reader harnesses: sound for decoder panic-freedom (the real check
    /// is pure and returns a `bool`). The real function is verified
    /// against a §4.1 model by `serialize_validate_name_matches_spec`.
    fn any_name_ok(_name: &[u8]) -> bool {
        kani::any()
    }

    /// `read_tree` on a 42-byte body — the exact size of a one-entry tree
    /// with a 1-byte name — with count = 1 and every other byte symbolic
    /// (so `name_len`, mode and hash range freely): no panic/overflow/OOB,
    /// the reader stays in bounds, and an `Ok` tree has exactly one
    /// entry whose name length and hash match the wire bytes. §4.1 is
    /// stubbed (`any_name_ok`). (Re-encoding the result and comparing all
    /// 42 bytes, or count ∈ {1, 2}, ran out of memory, as did a
    /// `write_tree` → `read_tree` round-trip with real §4.1 checks; the
    /// writer side is covered by the unit and proptest round-trips.)
    #[kani::proof]
    #[kani::stub(TreeEntry::validate_name, any_name_ok)]
    #[kani::unwind(3)]
    fn serialize_read_tree_one_entry() {
        let mut body: [u8; 42] = kani::any();
        body[..4].copy_from_slice(&1u32.to_le_bytes());
        let mut r = Reader::new(&body);
        let got = read_tree(&mut r);
        assert!(r.pos <= body.len());
        if let Ok(t) = got {
            assert_eq!(t.entries.len(), 1);
            let e = &t.entries[0];
            let name_len = u32::from_le_bytes([body[4], body[5], body[6], body[7]]) as usize;
            assert_eq!(e.name.len(), name_len);
            assert_eq!(r.pos, 8 + name_len + 1 + HASH_LEN);
            kani::cover!(r.remaining() == 0, "one_entry_consumes_body");
        }
    }

    /// Independent transcription of SPEC-OBJECTS §4.1.
    fn spec_name_ok(n: &[u8]) -> bool {
        if n.is_empty() || n.len() > 255 {
            return false;
        }
        if n.iter()
            .any(|&b| b == 0 || b == b'/' || b == b'\\' || b == b':')
        {
            return false;
        }
        if n == b"." || n == b".." || matches!(n[n.len() - 1], b'.' | b' ') {
            return false;
        }
        let up: Vec<u8> = n.iter().map(u8::to_ascii_uppercase).collect();
        if up == b".KIT" || up == b".GIT" {
            return false;
        }
        if up.len() >= 5
            && (up[..4] == *b"KIT~" || up[..4] == *b"GIT~")
            && up[4..].iter().all(u8::is_ascii_digit)
        {
            return false;
        }
        let stem = match up.iter().position(|&b| b == b'.') {
            Some(i) => &up[..i],
            None => &up[..],
        };
        let reserved3 = [b"CON", b"PRN", b"AUX", b"NUL"];
        if reserved3.iter().any(|r| stem == r.as_slice()) {
            return false;
        }
        !(stem.len() == 4
            && (stem[..3] == *b"COM" || stem[..3] == *b"LPT")
            && (b'1'..=b'9').contains(&stem[3]))
    }

    fn name_at<const L: usize>() {
        let n: [u8; L] = kani::any();
        assert_eq!(TreeEntry::validate_name(&n), spec_name_ok(&n));
    }

    /// `TreeEntry::validate_name` agrees with the §4.1 model on every
    /// name of 0..=8 bytes. The bound covers `.kit`, `COM1`, `LPT9.x`,
    /// `con.txt`-style stems, the 8.3 aliases up to `kit~1234` and every
    /// trailing-byte rule.
    #[kani::proof]
    #[kani::unwind(10)]
    fn serialize_validate_name_matches_spec() {
        each_len!(name_at; 0 1 2 3 4 5 6 7 8);
        kani::cover!(TreeEntry::validate_name(b"com0.x"), "com0_allowed");
        kani::cover!(!TreeEntry::validate_name(b"kit~123"), "short_alias_refused");
    }

    fn blob_rt<const N: usize>() {
        let data: [u8; N] = kani::any();
        let bytes = serialize(&Object::Blob(Blob {
            data: data.to_vec(),
        }))
        .expect("encodes");
        match deserialize(&bytes) {
            Ok(Object::Blob(b)) => assert_eq!(b.data, data),
            _ => panic!("own blob encoding must deserialize to the same blob"),
        }
    }

    /// `deserialize` path (prologue §2 + real blob reader §3 + §11
    /// trailing rule): `deserialize(serialize(blob)) == blob` for every
    /// blob of 0..=4 symbolic bytes. The other per-type readers are
    /// stubbed (CBMC does not constant-fold the dispatch through the
    /// heap buffer and otherwise exhausts memory on unreachable arms); a
    /// mis-dispatch would reach a stub that never returns a blob and so
    /// fail the assertion.
    #[kani::proof]
    #[kani::stub(read_tree, any_tree)]
    #[kani::stub(read_commit, any_err_commit)]
    #[kani::stub(read_remix, any_err_remix)]
    #[kani::stub(read_chunked_blob, any_err_chunked)]
    #[kani::stub(read_delta, any_err_delta)]
    #[kani::stub(read_tag, any_err_tag)]
    #[kani::unwind(6)]
    fn serialize_blob_roundtrip() {
        each_len!(blob_rt; 0 1 2 3 4);
    }

    /// Canary (§11 trailing bytes): the checker must falsify "a valid
    /// blob encoding with one extra byte still deserializes", showing
    /// the trailing-data rejection the prologue harness relies on is live.
    #[kani::proof]
    #[kani::stub(read_tree, any_tree)]
    #[kani::stub(read_commit, any_err_commit)]
    #[kani::stub(read_remix, any_err_remix)]
    #[kani::stub(read_chunked_blob, any_err_chunked)]
    #[kani::stub(read_delta, any_err_delta)]
    #[kani::stub(read_tag, any_err_tag)]
    #[kani::unwind(6)]
    #[kani::should_panic]
    fn serialize_canary_trailing_byte_accepted() {
        let mut bytes = serialize(&Object::Blob(Blob {
            data: vec![kani::any()],
        }))
        .expect("encodes");
        bytes.push(kani::any());
        assert!(deserialize(&bytes).is_ok());
    }
}
