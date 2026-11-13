//! Blob-content I/O: reading back what the worktree walker stored.
//!
//! A file's content lives either in a single inline [`Blob`](crate::object::Blob)
//! or behind a [`ChunkedBlob`](crate::object::ChunkedBlob) manifest. [`LoadedBlob`]
//! is the one-read-per-object view over both shapes; [`read_blob`] is the one-shot
//! full-content convenience on top of it. Extracted from `worktree.rs` —
//! this cluster reconstructs content and has nothing to do with walking a worktree.

use std::borrow::Cow;
use std::io;

use crate::hash::Hash;
use crate::object::{ChunkedBlob, Object};

use super::{WorktreeError, WorktreeResult};

/// Reassemble the full byte content of a `Blob` or `ChunkedBlob` object
/// addressed by `hash`.
///
/// A plain [`Blob`](crate::object::Blob) returns its bytes directly. A
/// [`ChunkedBlob`] manifest is reassembled
/// by concatenating each referenced chunk (every chunk must itself be a
/// `Blob`). This is the shared counterpart to [`store_file_object`](super::store_file_object) and
/// backs `kit diff` and conflict rendering so they reconstruct large-file
/// content the same way. [`write_blob`] writes content too large to hold.
///
/// # Errors
/// - [`WorktreeError::Store`] if `hash` or any chunk is missing.
/// - [`WorktreeError::Io`] if `hash` (or a chunk) resolves to an object
///   that is neither a `Blob` nor a `ChunkedBlob` of `Blob`s.
/// - [`WorktreeError::Object`] if the concatenated chunks do not total
///   the manifest's `total_size` (SPEC-OBJECTS §7).
/// - [`WorktreeError::ContentTooLarge`] if the manifest's `total_size` is
///   above [`MAX_FILE_BYTES`](super::MAX_FILE_BYTES).
pub fn read_blob<S: crate::store::ObjectSource + ?Sized>(
    store: &S,
    hash: &Hash,
) -> WorktreeResult<Vec<u8>> {
    LoadedBlob::load(store, hash)?.into_content(store)
}

/// [`read_blob`] for a blob too large to hold: write the content of the
/// `Blob` or `ChunkedBlob` at `hash` to `out`, one chunk at a time.
///
/// # Errors
/// As [`LoadedBlob::write_content`], and as [`read_blob`] for a missing or
/// wrong-type object.
pub fn write_blob<S: crate::store::ObjectSource + ?Sized, W: io::Write>(
    store: &S,
    hash: &Hash,
    out: &mut W,
) -> WorktreeResult<()> {
    LoadedBlob::load(store, hash)?.write_content(store, out)
}

/// A blob's top-level object, read from the store exactly once and held so
/// a caller needing several views of the same blob — byte length, bounded
/// prefix, full content — pays a single top-level `read_object` instead of
/// one per view. `diff --stat` is the motivating caller: its text-vs-binary
/// sniff needs a prefix, then either the length (binary row) or the full
/// content (text row), and taking each view through a separate store-level
/// read re-read (and re-hash-verified) the same object two times per
/// changed file, a per-entry cost that dominates a many-small-files
/// diffstat.
///
/// Chunk objects are still read on demand: [`Self::len`] reads none,
/// [`Self::prefix`] reads only leading chunks, [`Self::into_content`]
/// reads them all.
///
/// One read stays undeduped by design: [`Self::prefix`] on a chunked blob
/// reads the leading chunk(s) to sniff, and [`Self::into_content`] reads
/// every chunk (including that same leading one) to reassemble — a caller
/// doing both, as `diff --stat` does, reads the first chunk twice. Caching
/// it would need either interior mutability or a consuming-prefix API, to
/// save an O(1) read on an O(n-chunks) path; not worth it.
#[derive(Debug)]
pub enum LoadedBlob {
    /// An inline [`Blob`](crate::object::Blob): its full content, already
    /// in hand.
    Inline(Vec<u8>),
    /// A [`ChunkedBlob`] manifest: content lives in chunk objects, read
    /// only when a view needs them.
    Chunked(ChunkedBlob),
}

impl LoadedBlob {
    /// Read the top-level object addressed by `hash` — one store read.
    ///
    /// # Errors
    /// - [`WorktreeError::Store`] if `hash` is missing.
    /// - [`WorktreeError::Io`] if `hash` resolves to an object that is
    ///   neither a `Blob` nor a `ChunkedBlob`.
    pub fn load<S: crate::store::ObjectSource + ?Sized>(
        store: &S,
        hash: &Hash,
    ) -> WorktreeResult<Self> {
        match store.read_object(hash)? {
            Object::Blob(b) => Ok(Self::Inline(b.data)),
            Object::ChunkedBlob(manifest) => Ok(Self::Chunked(manifest)),
            other => Err(not_a_blob("object", hash, &other)),
        }
    }

    /// Content byte length from what is already in hand — an inline blob's
    /// data length, a chunked blob's manifest `total_size` — no chunk
    /// reads. `total_size` is trustworthy without re-verifying against the
    /// chunks: every reassembly path enforces it via
    /// [`ChunkedBlob::check_reassembled_size`], so a manifest with a wrong
    /// `total_size` cannot have been durably written.
    #[must_use]
    pub fn len(&self) -> u64 {
        match self {
            Self::Inline(data) => data.len() as u64,
            Self::Chunked(manifest) => manifest.total_size(),
        }
    }

    /// Whether the content is zero bytes long.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Up to `max_len` leading content bytes. Inline data is borrowed (no
    /// copy, no reads); a chunked blob reads only as many leading chunks
    /// as it takes to cover `max_len`, then stops — one chunk in practice,
    /// since every chunk but possibly the last is at least
    /// [`crate::chunker::MIN_SIZE`] bytes, well above the sniff windows
    /// callers use (e.g. [`crate::ops::diff::BINARY_SNIFF_LEN`]).
    ///
    /// # Errors
    /// - [`WorktreeError::Store`] if a needed chunk is missing.
    /// - [`WorktreeError::Io`] if a needed chunk is not a `Blob`.
    pub fn prefix<S: crate::store::ObjectSource + ?Sized>(
        &self,
        store: &S,
        max_len: usize,
    ) -> WorktreeResult<Cow<'_, [u8]>> {
        match self {
            Self::Inline(data) => Ok(Cow::Borrowed(&data[..data.len().min(max_len)])),
            Self::Chunked(manifest) => {
                let cap = usize::try_from(manifest.total_size())
                    .unwrap_or(max_len)
                    .min(max_len);
                let mut data = Vec::with_capacity(cap);
                for chunk in manifest.chunks() {
                    if data.len() >= max_len {
                        break;
                    }
                    data.extend_from_slice(&read_chunk(store, chunk)?);
                }
                data.truncate(max_len);
                Ok(Cow::Owned(data))
            }
        }
    }

    /// The full content: inline data as-is (no further reads), a chunked
    /// blob reassembled by reading every chunk, with the result length
    /// enforced against the manifest's `total_size` (SPEC-OBJECTS §7).
    ///
    /// # Errors
    /// - [`WorktreeError::Store`] if a chunk is missing.
    /// - [`WorktreeError::Io`] if a chunk is not a `Blob`.
    /// - [`WorktreeError::Object`] if the concatenated chunks do not total
    ///   the manifest's `total_size`. The read stops at the first chunk
    ///   that takes the running length past `total_size`.
    /// - [`WorktreeError::ContentTooLarge`] if the manifest's `total_size`
    ///   is above [`MAX_FILE_BYTES`](super::MAX_FILE_BYTES), before any
    ///   chunk is read.
    pub fn into_content<S: crate::store::ObjectSource + ?Sized>(
        self,
        store: &S,
    ) -> WorktreeResult<Vec<u8>> {
        match self {
            Self::Inline(data) => Ok(data),
            Self::Chunked(manifest) => {
                if manifest.total_size() > super::MAX_FILE_BYTES {
                    return Err(WorktreeError::ContentTooLarge {
                        size: manifest.total_size(),
                    });
                }
                let mut data = Vec::new();
                Self::Chunked(manifest).write_content(store, &mut data)?;
                Ok(data)
            }
        }
    }

    /// Write the full content to `out`, one chunk at a time. Memory is one
    /// chunk, whatever the blob's size, so this is the reader for a blob that
    /// is too large to hold. The length is enforced against the manifest's
    /// `total_size` as for [`Self::into_content`]; a failure can come after
    /// `out` has received a prefix of the content.
    ///
    /// # Errors
    /// As [`Self::into_content`], except that no size is too large, plus
    /// [`WorktreeError::Io`] if `out` fails.
    pub fn write_content<S: crate::store::ObjectSource + ?Sized, W: io::Write>(
        &self,
        store: &S,
        out: &mut W,
    ) -> WorktreeResult<()> {
        match self {
            Self::Inline(data) => Ok(out.write_all(data)?),
            Self::Chunked(manifest) => {
                let mut written: u64 = 0;
                for chunk in manifest.chunks() {
                    let part = read_chunk(store, chunk)?;
                    // Stop at the first chunk that passes `total_size`, so a
                    // manifest that repeats one chunk cannot write without
                    // end.
                    written = written.saturating_add(part.len() as u64);
                    if written > manifest.total_size() {
                        return Err(crate::object::KitError::ChunkedBlobSizeMismatch {
                            expected: manifest.total_size(),
                            actual: written,
                        }
                        .into());
                    }
                    out.write_all(&part)?;
                }
                if written != manifest.total_size() {
                    return Err(crate::object::KitError::ChunkedBlobSizeMismatch {
                        expected: manifest.total_size(),
                        actual: written,
                    }
                    .into());
                }
                Ok(())
            }
        }
    }

    /// The empty blob: what a diff side with no object (an add's old side,
    /// a delete's new side) loads as. Zero length, empty prefix, empty
    /// content — no store reads.
    #[must_use]
    pub fn empty() -> Self {
        Self::Inline(Vec::new())
    }
}

/// One chunk of a [`ChunkedBlob`]: must deserialize to an inline `Blob`.
fn read_chunk<S: crate::store::ObjectSource + ?Sized>(
    store: &S,
    chunk: &Hash,
) -> WorktreeResult<Vec<u8>> {
    match store.read_object(chunk)? {
        Object::Blob(b) => Ok(b.data),
        other => Err(not_a_blob("chunk", chunk, &other)),
    }
}

/// Read one manifest chunk's raw bytes, requiring a `Blob`, in
/// [`crate::store::StoreError`]'s domain rather than [`WorktreeError`]'s
/// (see [`read_chunk`] for the `WorktreeError` counterpart, kept separate
/// since its error also carries the hash and the historical `"chunk ..."`
/// wording). The single "read a manifest chunk" primitive shared by every
/// `StoreError`-domain caller — [`content_fingerprint`],
/// [`ContentCursor::remaining`], and [`chunked_content_eq`] — that
/// previously each hand-rolled the same match.
fn read_blob_chunk<S: crate::store::ObjectSource + ?Sized>(
    store: &S,
    chunk: &Hash,
) -> Result<Vec<u8>, crate::store::StoreError> {
    match store.read_object(chunk)? {
        Object::Blob(b) => Ok(b.data),
        _ => Err(crate::store::StoreError::Io(io::Error::other(
            "manifest chunk is not a Blob",
        ))),
    }
}

/// The "expected a blob, found something else" error shared by every
/// [`LoadedBlob`] read path; `what` is `"object"` for a top-level hash and
/// `"chunk"` for a manifest chunk, preserving the historical wording of
/// both messages.
fn not_a_blob(what: &str, hash: &Hash, got: &Object) -> WorktreeError {
    WorktreeError::Io(io::Error::other(format!(
        "{what} {} is not a blob (got {})",
        crate::hash::to_hex(hash),
        got.object_type().name()
    )))
}

/// Representation-independent content identity: byte length and raw BLAKE3.
/// Reads each chunk once and verifies the complete manifest length. Memory is
/// bounded by the manifest and one chunk, independent of reassembled size.
///
/// # Errors
/// Missing, corrupt, wrong-type chunks and inconsistent lengths are errors.
pub fn content_fingerprint<S: crate::store::ObjectSource + ?Sized>(
    store: &S,
    hash: &Hash,
) -> Result<(u64, Hash), crate::store::StoreError> {
    use crate::store::StoreError;
    let mut hasher = crate::hash::Hasher::new();
    match store.read_object(hash)? {
        Object::Blob(b) => {
            hasher.update(&b.data);
            Ok((b.data.len() as u64, hasher.finalize()))
        }
        Object::ChunkedBlob(manifest) => {
            let mut size = 0usize;
            for chunk in manifest.chunks() {
                let data = read_blob_chunk(store, chunk)?;
                size = size
                    .checked_add(data.len())
                    .ok_or(StoreError::ObjectTooLarge)?;
                hasher.update(&data);
            }
            manifest.check_reassembled_size(size as u64)?;
            Ok((size as u64, hasher.finalize()))
        }
        _ => Err(StoreError::Io(io::Error::other(
            "content object is not a Blob or ChunkedBlob",
        ))),
    }
}

/// Compare file content independently of inline/chunked storage layout.
/// Equal object IDs are a fast path; different IDs require verified content.
///
/// A `ChunkedBlob`-vs-`ChunkedBlob` pair (the large-file case) takes a
/// further internal fast path (`chunked_content_eq`, private to this
/// module), which skips reading any chunk both sides reference by the
/// same hash instead of reassembling and byte-comparing every chunk of
/// both blobs — see that function's doc for what it trusts and what it
/// still fully verifies. Any other pairing
/// (inline vs inline, or a mixed inline/chunked pair) keeps the exact
/// byte-cursor walk this function has always used.
///
/// The chunked fast path's "same hash means same bytes, skip the read"
/// trust holds only as far as `store: &S`'s reads are actually
/// hash-verified — true of every `ObjectSource` in this crate today
/// except [`crate::store::DisplaySource`] (used for read-only diff/show
/// rendering, and not passed to `content_eq` by any current caller). A
/// future caller doing so would trade that verification away for this
/// fast path exactly as much as it already does for every other generic
/// `ObjectSource` consumer.
///
/// # Errors
/// Propagates errors from [`content_fingerprint`].
pub fn content_eq<S: crate::store::ObjectSource + ?Sized>(
    store: &S,
    a: &Hash,
    b: &Hash,
) -> Result<bool, crate::store::StoreError> {
    if a == b {
        return Ok(true);
    }
    let obj_a = store.read_object(a)?;
    let obj_b = store.read_object(b)?;
    if let (Object::ChunkedBlob(ma), Object::ChunkedBlob(mb)) = (&obj_a, &obj_b) {
        return chunked_content_eq(store, ma, mb);
    }
    let mut left = ContentCursor::from_object(obj_a)?;
    let mut right = ContentCursor::from_object(obj_b)?;
    let mut equal = true;
    loop {
        let a = left.remaining(store)?;
        let b = right.remaining(store)?;
        if a.is_empty() && b.is_empty() {
            return Ok(equal);
        }
        if a.is_empty() || b.is_empty() {
            equal = false;
            let alen = a.len();
            let blen = b.len();
            left.offset += alen;
            right.offset += blen;
        } else {
            let count = a.len().min(b.len());
            equal &= a[..count] == b[..count];
            left.offset += count;
            right.offset += count;
        }
    }
}

/// Compare two [`ChunkedBlob`] manifests for content equality, skipping
/// any chunk both sides reference by the same content-addressed hash:
/// identical hash means identical bytes by construction — the same trust
/// [`content_eq`]'s own `a == b` whole-object fast path already relies
/// on, just applied per chunk instead of per object. Only chunks that
/// diverge (a different hash at the same aligned position) are actually
/// read and byte-compared, so a change confined to part of a large file
/// costs only that part on both sides, not the whole file. An in-place
/// edit of unchanged length walks straight past the shared, unaffected
/// tail with no reads once the edited region resyncs by hash again.
///
/// `total_size` is trusted without re-summing actual chunk bytes only for
/// a side whose chunks were *partly* skipped by id — the same trust
/// [`LoadedBlob::len`] already documents: every reassembly path enforces
/// it via [`ChunkedBlob::check_reassembled_size`], so a manifest with a
/// wrong `total_size` cannot have been durably written through kit's own
/// writers. A side every one of whose chunks gets actually read
/// (no id ever matched a boundary on that side — the case an append or a
/// wholly-rewritten file hits) has its real byte count checked against
/// its declared `total_size` before returning, exactly like the old
/// byte-cursor walk did, and errors the same way
/// ([`crate::object::KitError::ChunkedBlobSizeMismatch`]) if they
/// disagree. Only a side that *did* skip at least one chunk by id skips
/// this check for that side, since the skipped chunks' real lengths were
/// never read to sum: two manifests whose declared `total_size` fields
/// agree with each other but not with their own chunks, and whose chunk
/// sequences also line up entirely (or partly, from the first divergence
/// on) by hash, can still slip through unnoticed on that account. An
/// append or truncation, meanwhile, needs zero chunk reads at all before
/// even reaching this check: the two sides' declared sizes differ, so
/// `content_eq` returns `Ok(false)` above before the merge walk starts.
///
/// # Errors
/// [`crate::store::StoreError`] if a chunk that must be read (either
/// side has no matching chunk to skip against) is missing, corrupt, or
/// not a `Blob`; [`crate::object::KitError::ChunkedBlobSizeMismatch`]
/// if a side with no skipped chunks has a `total_size` that disagrees
/// with its chunks' real byte sum.
fn chunked_content_eq<S: crate::store::ObjectSource + ?Sized>(
    store: &S,
    ma: &ChunkedBlob,
    mb: &ChunkedBlob,
) -> Result<bool, crate::store::StoreError> {
    if ma.total_size() != mb.total_size() {
        return Ok(false);
    }

    let mut ia = 0usize;
    let mut ib = 0usize;
    let mut buf_a: Vec<u8> = Vec::new();
    let mut buf_b: Vec<u8> = Vec::new();
    let mut pos_a = 0usize;
    let mut pos_b = 0usize;
    let mut equal = true;
    // Real bytes actually read (never chunks skipped by id) per side,
    // and whether any chunk on that side WAS skipped by id — see the
    // doc comment above for what these guard.
    let mut read_a: u64 = 0;
    let mut read_b: u64 = 0;
    let mut skipped_a = false;
    let mut skipped_b = false;

    loop {
        // Both cursors sit at a chunk boundary: skip a run of chunks
        // that match by id, with no read on either side.
        while pos_a == buf_a.len()
            && pos_b == buf_b.len()
            && ia < ma.chunks().len()
            && ib < mb.chunks().len()
            && ma.chunks()[ia] == mb.chunks()[ib]
        {
            ia += 1;
            ib += 1;
            skipped_a = true;
            skipped_b = true;
        }

        if pos_a == buf_a.len() {
            buf_a = match ma.chunks().get(ia) {
                Some(h) => {
                    ia += 1;
                    let data = read_blob_chunk(store, h)?;
                    read_a = read_a
                        .checked_add(data.len() as u64)
                        .ok_or(crate::store::StoreError::ObjectTooLarge)?;
                    data
                }
                None => Vec::new(),
            };
            pos_a = 0;
        }
        if pos_b == buf_b.len() {
            buf_b = match mb.chunks().get(ib) {
                Some(h) => {
                    ib += 1;
                    let data = read_blob_chunk(store, h)?;
                    read_b = read_b
                        .checked_add(data.len() as u64)
                        .ok_or(crate::store::StoreError::ObjectTooLarge)?;
                    data
                }
                None => Vec::new(),
            };
            pos_b = 0;
        }

        let a_rest = &buf_a[pos_a..];
        let b_rest = &buf_b[pos_b..];
        if a_rest.is_empty() && b_rest.is_empty() {
            if ia >= ma.chunks().len() && ib >= mb.chunks().len() {
                if !skipped_a && read_a != ma.total_size() {
                    return Err(crate::object::KitError::ChunkedBlobSizeMismatch {
                        expected: ma.total_size(),
                        actual: read_a,
                    }
                    .into());
                }
                if !skipped_b && read_b != mb.total_size() {
                    return Err(crate::object::KitError::ChunkedBlobSizeMismatch {
                        expected: mb.total_size(),
                        actual: read_b,
                    }
                    .into());
                }
                return Ok(equal);
            }
            // A zero-length trailing chunk on one or both sides; loop
            // again to pull the next one via the boundary checks above.
            continue;
        }

        let count = a_rest.len().min(b_rest.len());
        if count == 0 {
            // One side has run out of chunks for good; drain the other
            // (matching the byte-cursor path's behavior) so a read
            // error later in its remaining chunks still surfaces.
            equal = false;
            pos_a = buf_a.len();
            pos_b = buf_b.len();
            continue;
        }
        if a_rest[..count] != b_rest[..count] {
            equal = false;
        }
        pos_a += count;
        pos_b += count;
    }
}

/// Compare stored content to bytes without reassembling chunked storage.
///
/// # Errors
/// Propagates errors from [`content_fingerprint`].
pub fn content_eq_bytes<S: crate::store::ObjectSource + ?Sized>(
    store: &S,
    object: &Hash,
    bytes: &[u8],
) -> Result<bool, crate::store::StoreError> {
    let mut cursor = ContentCursor::load(store, object)?;
    let mut offset = 0usize;
    let mut equal = true;
    loop {
        let chunk = cursor.remaining(store)?;
        if chunk.is_empty() {
            return Ok(equal && offset == bytes.len());
        }
        let end = offset
            .checked_add(chunk.len())
            .ok_or(crate::store::StoreError::ObjectTooLarge)?;
        equal &= bytes.get(offset..end) == Some(chunk);
        offset = end;
        cursor.offset += chunk.len();
    }
}

/// Compare stored content to the rest of `reader`, one stored chunk at a time.
/// Memory is one chunk, whatever the content's size. The read stops at the
/// first difference.
///
/// # Errors
/// Propagates errors from reading the stored content or `reader`.
pub fn content_eq_reader<S: crate::store::ObjectSource + ?Sized, R: io::Read>(
    store: &S,
    object: &Hash,
    reader: &mut R,
) -> Result<bool, crate::store::StoreError> {
    let mut cursor = ContentCursor::load(store, object)?;
    let mut scratch = Vec::new();
    loop {
        let chunk = cursor.remaining(store)?;
        if chunk.is_empty() {
            // The stored content ended: the reader must end too.
            let mut probe = [0u8; 1];
            return Ok(reader.read(&mut probe)? == 0);
        }
        scratch.resize(chunk.len(), 0);
        match reader.read_exact(&mut scratch) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(false),
            Err(e) => return Err(e.into()),
        }
        if scratch != chunk {
            return Ok(false);
        }
        let len = chunk.len();
        cursor.offset += len;
    }
}

struct ContentCursor {
    data: Vec<u8>,
    offset: usize,
    chunks: std::vec::IntoIter<Hash>,
    expected: u64,
    loaded: u64,
}

impl ContentCursor {
    fn load<S: crate::store::ObjectSource + ?Sized>(
        store: &S,
        hash: &Hash,
    ) -> Result<Self, crate::store::StoreError> {
        Self::from_object(store.read_object(hash)?)
    }

    /// Build a cursor from an already-read top-level object, saving the
    /// caller a second `read_object` when it needed the object anyway
    /// (e.g. [`content_eq`] deciding whether the chunked fast path
    /// applies).
    fn from_object(object: Object) -> Result<Self, crate::store::StoreError> {
        let (data, chunks, expected) = match object {
            Object::Blob(b) => {
                let size = b.data.len() as u64;
                (b.data, Vec::new(), size)
            }
            Object::ChunkedBlob(m) => {
                let size = m.total_size();
                (Vec::new(), m.into_chunks(), size)
            }
            _ => {
                return Err(crate::store::StoreError::Io(io::Error::other(
                    "content object is not a Blob or ChunkedBlob",
                )));
            }
        };
        let loaded = data.len() as u64;
        Ok(Self {
            data,
            offset: 0,
            chunks: chunks.into_iter(),
            expected,
            loaded,
        })
    }

    fn remaining<S: crate::store::ObjectSource + ?Sized>(
        &mut self,
        store: &S,
    ) -> Result<&[u8], crate::store::StoreError> {
        while self.offset == self.data.len() {
            let Some(hash) = self.chunks.next() else {
                if self.loaded != self.expected {
                    return Err(crate::object::KitError::ChunkedBlobSizeMismatch {
                        expected: self.expected,
                        actual: self.loaded,
                    }
                    .into());
                }
                return Ok(&[]);
            };
            let data = read_blob_chunk(store, &hash)?;
            self.loaded = self
                .loaded
                .checked_add(data.len() as u64)
                .ok_or(crate::store::StoreError::ObjectTooLarge)?;
            self.data = data;
            self.offset = 0;
        }
        Ok(&self.data[self.offset..])
    }
}

#[cfg(test)]
mod equality_tests {
    use super::*;
    use crate::{layout::RepoLayout, object::Blob, serialize, store::ObjectStore};

    fn put(store: &ObjectStore, object: &Object) -> Hash {
        store.write(&serialize::serialize(object).unwrap()).unwrap()
    }

    #[test]
    fn large_inline_fixed_and_cdc_content_agree() {
        let dir = tempfile::tempdir().unwrap();
        let store = ObjectStore::init(&RepoLayout::single(dir.path())).unwrap();
        let data = vec![7; usize::try_from(super::super::CHUNK_THRESHOLD + 17).unwrap()];
        let inline = put(&store, &Object::Blob(Blob { data: data.clone() }));
        let cdc = super::super::store_file_object(&store, &data).unwrap();
        let chunks = data
            .chunks(65_536)
            .map(|b| put(&store, &Object::Blob(Blob { data: b.to_vec() })))
            .collect();
        let fixed = put(
            &store,
            &Object::ChunkedBlob(ChunkedBlob::new(data.len() as u64, 65_536, chunks).unwrap()),
        );
        assert_ne!(inline, cdc);
        assert_ne!(fixed, cdc);
        assert!(content_eq(&store, &inline, &fixed).unwrap());
        assert!(content_eq(&store, &fixed, &cdc).unwrap());
        assert!(content_eq_bytes(&store, &fixed, &data).unwrap());
        assert_eq!(
            content_fingerprint(&store, &inline).unwrap(),
            content_fingerprint(&store, &cdc).unwrap()
        );
        let mut changed = data;
        changed[65_536] = 8;
        assert!(!content_eq_bytes(&store, &fixed, &changed).unwrap());
    }

    #[test]
    fn invalid_chunks_are_errors_even_after_content_differs() {
        let dir = tempfile::tempdir().unwrap();
        let store = ObjectStore::init(&RepoLayout::single(dir.path())).unwrap();
        let a = put(
            &store,
            &Object::Blob(Blob {
                data: b"a".to_vec(),
            }),
        );
        let b = put(
            &store,
            &Object::Blob(Blob {
                data: b"b".to_vec(),
            }),
        );
        for (total_size, chunks) in [(2, vec![a]), (2, vec![a, [42; 32]])] {
            let bad = put(
                &store,
                &Object::ChunkedBlob(ChunkedBlob::new(total_size, 0, chunks).unwrap()),
            );
            assert!(content_eq(&store, &bad, &b).is_err());
            assert!(content_eq_bytes(&store, &bad, b"b").is_err());
            assert!(content_fingerprint(&store, &bad).is_err());
        }
    }

    fn chunk(store: &ObjectStore, data: &[u8]) -> Hash {
        put(
            store,
            &Object::Blob(Blob {
                data: data.to_vec(),
            }),
        )
    }

    fn manifest(store: &ObjectStore, parts: &[&[u8]]) -> ChunkedBlob {
        let total_size: u64 = parts.iter().map(|p| p.len() as u64).sum();
        ChunkedBlob::new(
            total_size,
            0,
            parts.iter().map(|p| chunk(store, p)).collect(),
        )
        .unwrap()
    }

    fn fresh_store() -> (tempfile::TempDir, ObjectStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = ObjectStore::init(&RepoLayout::single(dir.path())).unwrap();
        (dir, store)
    }

    /// A manifest above the in-memory limit is refused from its header,
    /// before any chunk is read.
    #[test]
    fn into_content_refuses_content_above_the_memory_limit() {
        let (_dir, store) = fresh_store();
        let source = CountingSource {
            store: &store,
            reads: std::cell::Cell::new(0),
        };
        let manifest = crate::object::ChunkedBlob::new(
            crate::worktree::MAX_FILE_BYTES + 1,
            0,
            vec![[1u8; 32], [2u8; 32]],
        )
        .unwrap();
        let err = LoadedBlob::Chunked(manifest)
            .into_content(&source)
            .unwrap_err();
        assert!(
            matches!(err, WorktreeError::ContentTooLarge { size }
                if size == crate::worktree::MAX_FILE_BYTES + 1),
            "got {err}"
        );
        assert_eq!(source.reads.get(), 0);

        // At the limit the reader goes on to the chunks, which are missing.
        let at_limit = ChunkedBlob::new(
            crate::worktree::MAX_FILE_BYTES,
            0,
            vec![[1u8; 32], [2u8; 32]],
        )
        .unwrap();
        let err = LoadedBlob::Chunked(at_limit)
            .into_content(&source)
            .unwrap_err();
        assert!(matches!(err, WorktreeError::Store(_)), "got {err}");
        assert_eq!(source.reads.get(), 1);
    }

    /// A source that counts chunk reads, to show where a read loop stops.
    struct CountingSource<'a> {
        store: &'a ObjectStore,
        reads: std::cell::Cell<usize>,
    }

    impl crate::store::ObjectSource for CountingSource<'_> {
        fn read(&self, h: &Hash) -> crate::store::StoreResult<Vec<u8>> {
            self.store.read(h)
        }

        fn read_object(&self, h: &Hash) -> crate::store::StoreResult<Object> {
            self.reads.set(self.reads.get() + 1);
            self.store.read_object(h)
        }
    }

    /// A manifest that repeats one chunk must fail as soon as the running
    /// length passes `total_size`, not after it read every repeat.
    #[test]
    fn into_content_stops_when_the_running_length_passes_total_size() {
        let (_dir, store) = fresh_store();
        // The header allows one byte at least per chunk, so the chunks hold
        // more than `total_size` here.
        let repeated = chunk(&store, &[7u8; 1000]);
        let manifest = ChunkedBlob::new(1000, 0, vec![repeated; 1000]).unwrap();
        let source = CountingSource {
            store: &store,
            reads: std::cell::Cell::new(0),
        };
        let err = LoadedBlob::Chunked(manifest)
            .into_content(&source)
            .unwrap_err();
        assert!(
            matches!(
                err,
                WorktreeError::Object(crate::object::KitError::ChunkedBlobSizeMismatch { .. })
            ),
            "got {err:?}"
        );
        assert!(
            source.reads.get() <= 2,
            "read {} chunks",
            source.reads.get()
        );
    }

    /// A writer that records the size of each write.
    #[derive(Default)]
    struct SizedWrites {
        bytes: Vec<u8>,
        writes: Vec<usize>,
    }

    impl io::Write for SizedWrites {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.bytes.extend_from_slice(buf);
            self.writes.push(buf.len());
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn write_content_streams_one_chunk_per_write() {
        let (_dir, store) = fresh_store();
        let parts: [&[u8]; 3] = [&[1; 300], &[2; 200], &[3; 100]];
        let h = put(&store, &Object::ChunkedBlob(manifest(&store, &parts)));
        let mut out = SizedWrites::default();
        write_blob(&store, &h, &mut out).unwrap();
        assert_eq!(out.writes, vec![300, 200, 100], "no write holds the file");
        assert_eq!(out.bytes, read_blob(&store, &h).unwrap());

        let inline = chunk(&store, b"inline bytes");
        let mut out = SizedWrites::default();
        write_blob(&store, &inline, &mut out).unwrap();
        assert_eq!(out.bytes, b"inline bytes");
    }

    #[test]
    fn write_content_rejects_a_short_total_size() {
        let (_dir, store) = fresh_store();
        let a = chunk(&store, &[1; 100]);
        let bad = |total_size| ChunkedBlob::new(total_size, 0, vec![a, a]).unwrap();
        for total_size in [150, 250] {
            let mut out = SizedWrites::default();
            let err = LoadedBlob::Chunked(bad(total_size))
                .write_content(&store, &mut out)
                .unwrap_err();
            assert!(
                matches!(
                    err,
                    WorktreeError::Object(crate::object::KitError::ChunkedBlobSizeMismatch { .. })
                ),
                "got {err:?}"
            );
        }
    }

    #[test]
    fn write_content_reports_a_failed_writer() {
        struct Broken;
        impl io::Write for Broken {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed"))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let (_dir, store) = fresh_store();
        let h = put(
            &store,
            &Object::ChunkedBlob(manifest(&store, &[&[1; 10], &[2; 10]])),
        );
        let err = write_blob(&store, &h, &mut Broken).unwrap_err();
        assert!(matches!(err, WorktreeError::Io(_)), "got {err:?}");
    }

    /// A reader that returns one byte per read.
    struct OneByte<'a>(&'a [u8]);

    impl io::Read for OneByte<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = self.0.len().min(1).min(buf.len());
            buf[..n].copy_from_slice(&self.0[..n]);
            self.0 = &self.0[n..];
            Ok(n)
        }
    }

    #[test]
    fn content_eq_reader_compares_without_reassembling() {
        let (_dir, store) = fresh_store();
        let parts: [&[u8]; 3] = [&[1; 300], &[2; 200], &[3; 100]];
        let stored = put(&store, &Object::ChunkedBlob(manifest(&store, &parts)));
        let whole: Vec<u8> = parts.concat();
        let eq = |bytes: &[u8]| content_eq_reader(&store, &stored, &mut io::Cursor::new(bytes));

        assert!(eq(&whole).unwrap());
        // A reader that splits its reads differently from the chunks.
        assert!(content_eq_reader(&store, &stored, &mut OneByte(&whole)).unwrap());

        let mut last = whole.clone();
        *last.last_mut().unwrap() ^= 1;
        assert!(!eq(&last).unwrap(), "a changed last byte differs");
        let mut first = whole.clone();
        first[0] ^= 1;
        assert!(!eq(&first).unwrap(), "a changed first byte differs");
        assert!(!eq(&whole[..whole.len() - 1]).unwrap(), "a short reader");
        assert!(
            !eq(&[whole.clone(), vec![0]].concat()).unwrap(),
            "a long reader"
        );
        assert!(!eq(&[]).unwrap());

        let inline = chunk(&store, b"abc");
        assert!(content_eq_reader(&store, &inline, &mut io::Cursor::new(b"abc")).unwrap());
        assert!(!content_eq_reader(&store, &inline, &mut io::Cursor::new(b"abd")).unwrap());
    }

    #[test]
    fn content_eq_reader_reports_a_failed_read() {
        struct Failing;
        impl io::Read for Failing {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other("disk gone"))
            }
        }
        let (_dir, store) = fresh_store();
        let stored = put(
            &store,
            &Object::ChunkedBlob(manifest(&store, &[&[1; 10], &[2; 10]])),
        );
        let err = content_eq_reader(&store, &stored, &mut Failing).unwrap_err();
        assert!(err.to_string().contains("disk gone"), "got {err}");
    }

    #[test]
    fn content_eq_reader_stops_at_the_first_difference() {
        let (_dir, store) = fresh_store();
        let a = chunk(&store, &[1; 100]);
        let stored = put(
            &store,
            &Object::ChunkedBlob(ChunkedBlob::new(100 * 1000, 0, vec![a; 1000]).unwrap()),
        );
        let source = CountingSource {
            store: &store,
            reads: std::cell::Cell::new(0),
        };
        let mut other = vec![1u8; 100 * 1000];
        other[150] = 9;
        assert!(!content_eq_reader(&source, &stored, &mut io::Cursor::new(other)).unwrap());
        assert!(
            source.reads.get() <= 4,
            "read {} chunks",
            source.reads.get()
        );
    }

    // Direct tests of `chunked_content_eq`'s merge logic against small,
    // hand-built manifests — fast and deterministic, independent of real
    // FastCDC boundaries, covering the id-skip fast path, the
    // read-and-resync fallback, and the documented total_size trust gap.

    #[test]
    fn chunked_fast_path_all_chunks_match_by_id() {
        let (_dir, store) = fresh_store();
        let x = chunk(&store, b"hello ");
        let y = chunk(&store, b"world");
        let ma = ChunkedBlob::new(11, 0, vec![x, y]).unwrap();
        let mb = ma.clone();
        assert!(super::chunked_content_eq(&store, &ma, &mb).unwrap());
    }

    #[test]
    fn chunked_fully_misaligned_but_equal_content() {
        let (_dir, store) = fresh_store();
        // "ab"+"cd" vs "a"+"bcd" — no chunk hash ever matches, so every
        // byte is read and compared through the resync fallback, yet the
        // reassembled content is identical.
        let ma = manifest(&store, &[b"ab", b"cd"]);
        let mb = manifest(&store, &[b"a", b"bcd"]);
        assert!(super::chunked_content_eq(&store, &ma, &mb).unwrap());
        assert!(super::chunked_content_eq(&store, &mb, &ma).unwrap());
    }

    #[test]
    fn chunked_shared_prefix_then_misaligned_equal_suffix() {
        let (_dir, store) = fresh_store();
        let x = chunk(&store, b"shared-prefix-");
        let ma = ChunkedBlob::new(
            14 + 4,
            0,
            [x].into_iter()
                .chain(manifest(&store, &[b"ab", b"cd"]).into_chunks())
                .collect(),
        )
        .unwrap();
        let mb = ChunkedBlob::new(
            14 + 4,
            0,
            [x].into_iter()
                .chain(manifest(&store, &[b"a", b"bcd"]).into_chunks())
                .collect(),
        )
        .unwrap();
        // `x` is skipped by id; "ab"+"cd" vs "a"+"bcd" is read and resynced.
        assert!(super::chunked_content_eq(&store, &ma, &mb).unwrap());
    }

    #[test]
    fn chunked_append_differs_via_total_size_without_reading() {
        let (_dir, store) = fresh_store();
        let x = chunk(&store, b"shared");
        let ma = ChunkedBlob::new(6, 0, vec![x]).unwrap();
        let y = chunk(&store, b"-more");
        let mb = ChunkedBlob::new(11, 0, vec![x, y]).unwrap();
        assert!(!super::chunked_content_eq(&store, &ma, &mb).unwrap());
        assert!(!super::chunked_content_eq(&store, &mb, &ma).unwrap());
    }

    #[test]
    fn chunked_same_total_size_different_content_after_shared_prefix() {
        let (_dir, store) = fresh_store();
        let x = chunk(&store, b"shared-");
        let ma = ChunkedBlob::new(7 + 2, 0, vec![x, chunk(&store, b"ab")]).unwrap();
        let mb = ChunkedBlob::new(7 + 2, 0, vec![x, chunk(&store, b"ba")]).unwrap();
        assert!(!super::chunked_content_eq(&store, &ma, &mb).unwrap());
    }

    #[test]
    fn chunked_split_differently_but_actually_different_content() {
        let (_dir, store) = fresh_store();
        let x = chunk(&store, b"shared-");
        let ma = ChunkedBlob::new(7 + 4, 0, vec![x, chunk(&store, b"abcd")]).unwrap();
        let mb = ChunkedBlob::new(
            7 + 4,
            0,
            vec![x, chunk(&store, b"ab"), chunk(&store, b"cX")],
        )
        .unwrap();
        assert!(!super::chunked_content_eq(&store, &ma, &mb).unwrap());
    }

    #[test]
    fn chunked_empty_manifests_are_equal() {
        let (_dir, store) = fresh_store();
        let ma = ChunkedBlob::new(0, 0, vec![]).unwrap();
        let mb = ma.clone();
        assert!(super::chunked_content_eq(&store, &ma, &mb).unwrap());
    }

    /// Documents the accepted trust gap: `total_size` is not re-summed
    /// from actual chunk bytes on the chunked fast path (mirroring
    /// `LoadedBlob::len`'s existing trust). Two manifests whose chunk
    /// sequence fully matches by id, but whose shared `total_size`
    /// field is wrong for that sequence, are reported equal without
    /// ever reading a chunk to notice. A manifest this malformed cannot
    /// be produced by any of kit's own writers (`check_reassembled_size`
    /// gates every one); this can only arise from an object constructed
    /// directly, bypassing them, as this test does.
    #[test]
    fn chunked_wrong_shared_total_size_is_not_detected_when_ids_fully_match() {
        let (_dir, store) = fresh_store();
        let x = chunk(&store, b"ab"); // 2 real bytes
        // 999 is wrong on both sides, identically.
        let ma = ChunkedBlob::new(999, 0, vec![x]).unwrap();
        let mb = ma.clone();
        assert!(super::chunked_content_eq(&store, &ma, &mb).unwrap());
    }

    /// The case the fast path must *not* let slip past: no chunk on
    /// either side is ever skipped by id (every hash differs), so both
    /// sides get fully read — and a wrong `total_size` on a side that
    /// was fully read must still surface as
    /// `ChunkedBlobSizeMismatch`, exactly like the old byte-cursor walk.
    /// Regression test for a gap an independent review found: an
    /// earlier version of `chunked_content_eq` only ever compared the
    /// two manifests' declared `total_size` fields against *each
    /// other*, never against either side's own real chunk bytes, so two
    /// fully-diverging (no id ever matches) manifests that happened to
    /// declare the same wrong `total_size` were reported merely
    /// "unequal" instead of erroring.
    #[test]
    fn chunked_wrong_total_size_is_detected_when_no_chunk_is_skipped() {
        let (_dir, store) = fresh_store();
        // Real chunk bytes: 90 bytes on each side ("a" x90 vs "b" x90),
        // so no chunk hash ever matches — nothing is ever skipped.
        let a90 = vec![b'a'; 90];
        let b90 = vec![b'b'; 90];
        // 100 is wrong (the real sum is 90), and equal on both sides.
        let ma = ChunkedBlob::new(100, 0, vec![chunk(&store, &a90)]).unwrap();
        let mb = ChunkedBlob::new(100, 0, vec![chunk(&store, &b90)]).unwrap();
        let err = super::chunked_content_eq(&store, &ma, &mb).unwrap_err();
        assert!(
            matches!(
                err,
                crate::store::StoreError::Decode(
                    crate::object::KitError::ChunkedBlobSizeMismatch { .. }
                )
            ),
            "expected ChunkedBlobSizeMismatch, got {err:?}"
        );
    }

    /// The same wrong-`total_size` gap, but on only one side: the other
    /// side's declared size is accurate for its own real chunk bytes.
    /// Content is unequal either way (lengths differ once both are read
    /// out to their real end), but the malformed side must still error
    /// rather than silently compare as "not equal".
    #[test]
    fn chunked_wrong_total_size_on_one_side_only_is_detected() {
        let (_dir, store) = fresh_store();
        let a80 = vec![b'a'; 80];
        let b100 = vec![b'b'; 100];
        // 100 is wrong for ma (the real sum is 80) and correct for mb.
        let ma = ChunkedBlob::new(100, 0, vec![chunk(&store, &a80)]).unwrap();
        let mb = ChunkedBlob::new(100, 0, vec![chunk(&store, &b100)]).unwrap();
        let err = super::chunked_content_eq(&store, &ma, &mb).unwrap_err();
        assert!(
            matches!(
                err,
                crate::store::StoreError::Decode(
                    crate::object::KitError::ChunkedBlobSizeMismatch { .. }
                )
            ),
            "expected ChunkedBlobSizeMismatch, got {err:?}"
        );
    }

    /// End-to-end sanity check through the public `content_eq` entry
    /// point (not the private merge function directly) over real
    /// `FastCDC`-chunked content: an append, a single-byte in-place edit,
    /// and a truncation each produce a different manifest and must all
    /// compare unequal, exactly matching a ground-truth byte comparison.
    #[test]
    fn content_eq_real_chunked_mutations_match_ground_truth() {
        let (_dir, store) = fresh_store();
        let threshold = usize::try_from(super::super::CHUNK_THRESHOLD).unwrap();
        // Deterministic pseudo-random bytes so FastCDC sees real cut
        // points instead of one run-length-maxed chunk.
        let mut data = Vec::with_capacity(threshold * 3);
        let mut state: u64 = 0x1234_5678_9abc_def0;
        for _ in 0..threshold * 3 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            data.push((state >> 56) as u8);
        }

        let base = super::super::store_file_object(&store, &data).unwrap();

        let mut appended = data.clone();
        appended.extend_from_slice(b"appended tail bytes");
        let appended_hash = super::super::store_file_object(&store, &appended).unwrap();

        let mut edited = data.clone();
        let mid = edited.len() / 2;
        edited[mid] ^= 0xFF;
        let edited_hash = super::super::store_file_object(&store, &edited).unwrap();

        let truncated = &data[..data.len() - 500];
        let truncated_hash = super::super::store_file_object(&store, truncated).unwrap();

        let unchanged_hash = super::super::store_file_object(&store, &data).unwrap();

        assert_eq!(base, unchanged_hash, "identical content dedups to one id");
        assert!(content_eq(&store, &base, &unchanged_hash).unwrap());

        for (name, other, other_bytes) in [
            ("append", appended_hash, appended.as_slice()),
            ("edit", edited_hash, edited.as_slice()),
            ("truncate", truncated_hash, truncated),
        ] {
            assert_ne!(base, other, "{name}: expected a different object id");
            assert_eq!(
                content_eq(&store, &base, &other).unwrap(),
                data == other_bytes,
                "{name}: content_eq must match ground truth"
            );
            assert!(
                !content_eq(&store, &base, &other).unwrap(),
                "{name}: bytes differ"
            );
        }
    }

    /// A mid-file insertion against real `FastCDC` output: unlike
    /// `content_eq_real_chunked_mutations_match_ground_truth`'s
    /// single-byte edit (which may or may not shift a chunk boundary),
    /// inserting new bytes shifts every downstream offset, which
    /// reliably forces `FastCDC` to re-cut several chunks around the
    /// insertion point before content-defined chunking resyncs on the
    /// unchanged bytes further on. This is the scenario
    /// `chunked_content_eq`'s doc comment describes ("a change confined
    /// to part of a large file... resyncs by hash again") and, per an
    /// independent review, the only other resync coverage exercised
    /// hand-built or fixed-vs-CDC manifests, never two independently
    /// `FastCDC`-chunked real files. Confirms at the manifest level
    /// that a real divergence-then-resync actually occurred (shared
    /// first and last chunk hashes, a different chunk in between) before
    /// checking `content_eq` against ground truth.
    #[test]
    fn content_eq_real_chunked_insertion_forces_boundary_resync() {
        let (_dir, store) = fresh_store();
        let threshold = usize::try_from(super::super::CHUNK_THRESHOLD).unwrap();
        let mut data = Vec::with_capacity(threshold * 4);
        let mut state: u64 = 0x0BAD_C0DE_F00D_CAFE;
        for _ in 0..threshold * 4 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            data.push((state >> 56) as u8);
        }

        let mut inserted = data.clone();
        let at = data.len() / 2;
        let mut new_bytes = vec![0u8; 4096];
        let mut s: u64 = 0xFACE_FEED_1234_5678;
        for b in &mut new_bytes {
            s = s.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            *b = (s >> 56) as u8;
        }
        inserted.splice(at..at, new_bytes.iter().copied());

        let base_hash = super::super::store_file_object(&store, &data).unwrap();
        let inserted_hash = super::super::store_file_object(&store, &inserted).unwrap();
        assert_ne!(base_hash, inserted_hash);

        let Object::ChunkedBlob(base_manifest) = store.read_object(&base_hash).unwrap() else {
            panic!("expected base to be chunked (data.len() > CHUNK_THRESHOLD)");
        };
        let Object::ChunkedBlob(inserted_manifest) = store.read_object(&inserted_hash).unwrap()
        else {
            panic!("expected inserted to be chunked");
        };
        assert!(
            base_manifest.chunks().len() > 2 && inserted_manifest.chunks().len() > 2,
            "fixture too small to exercise multiple chunks"
        );
        assert_eq!(
            base_manifest.chunks().first(),
            inserted_manifest.chunks().first(),
            "the unaffected prefix must still share its leading chunk by id"
        );
        assert_eq!(
            base_manifest.chunks().last(),
            inserted_manifest.chunks().last(),
            "content-defined chunking must resync on the unaffected suffix"
        );
        assert_ne!(
            base_manifest.chunks(),
            inserted_manifest.chunks(),
            "the insertion must actually shift chunk boundaries somewhere in the middle"
        );

        assert!(
            !content_eq(&store, &base_hash, &inserted_hash).unwrap(),
            "content genuinely differs after the insertion"
        );
    }

    /// A manifest that declares more bytes than its chunks hold, set
    /// against a two-chunk manifest: the short side runs out of chunks
    /// while the other still has bytes, and the size check names it.
    #[test]
    fn chunked_content_eq_drains_the_longer_side_when_one_runs_out_of_chunks() {
        let (_dir, store) = fresh_store();
        let short = ChunkedBlob::new(10, 0, vec![chunk(&store, b"aaaa")]).unwrap();
        let long = ChunkedBlob::new(
            10,
            0,
            vec![chunk(&store, b"aaaab"), chunk(&store, b"bbbbb")],
        )
        .unwrap();
        let err = super::chunked_content_eq(&store, &short, &long).unwrap_err();
        assert!(
            matches!(
                err,
                crate::store::StoreError::Decode(
                    crate::object::KitError::ChunkedBlobSizeMismatch {
                        expected: 10,
                        actual: 4
                    }
                )
            ),
            "got {err:?}"
        );
    }

    /// After one side has run out of chunks, a zero-length chunk on the
    /// other does not end the walk: the chunks behind it are still read,
    /// so a missing one surfaces.
    #[test]
    fn chunked_content_eq_reads_past_a_zero_length_chunk_on_one_side() {
        let (_dir, store) = fresh_store();
        let shared = chunk(&store, b"abcde");
        let empty = chunk(&store, b"");
        let missing = [0xEE; 32];
        let a = ChunkedBlob::new(5, 0, vec![shared]).unwrap();
        let b = ChunkedBlob::new(5, 0, vec![shared, empty, missing]).unwrap();
        let err = super::chunked_content_eq(&store, &a, &b).unwrap_err();
        assert!(
            matches!(err, crate::store::StoreError::ObjectNotFound(_)),
            "got {err:?}"
        );
    }

    /// The length of a chunked blob is its declared `total_size`.
    #[test]
    fn a_chunked_blob_is_as_long_as_its_total_size() {
        let (_dir, store) = fresh_store();
        let manifest = ChunkedBlob::new(7, 0, vec![chunk(&store, b"abcdefg")]).unwrap();
        assert_eq!(LoadedBlob::Chunked(manifest).len(), 7);
    }
}
