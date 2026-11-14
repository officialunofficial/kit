//! KDSP v2 multi-chunk range proofs (SPEC-DISCLOSURE §8).
//!
//! The decoder borrows its inner bundles. Verification retains only small
//! summaries and the requested output, so it never keeps decoded chunks
//! from earlier bundles alive while checking later bundles.

use super::{
    CommitContext, DisclosedPayload, PayloadWire, Selector, Step, VerifyError, encode_disclosure,
    verify_disclosure, verify_disclosure_reusing_context,
};
use crate::hash::Hash;
use crate::merkle;
use crate::object::{EntryMode, KitError, Object};
use crate::store::{ObjectSource, StoreError};
use commonware_codec::{EncodeSize, Write};

use super::MAX_BUNDLE_BYTES;

const MAGIC: &[u8; 4] = b"KDSP";
const VERSION: u8 = 2;
const MAX_CHUNK_BUNDLES: usize = 1_000_000;

/// An authenticated byte range spanning at least two chunks.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DisclosedSpan {
    /// Trusted commit id.
    pub commit_id: Hash,
    /// Root tree id from the signed commit.
    pub tree_hash: Hash,
    /// Authenticated path and entry modes.
    pub path: Vec<(Vec<u8>, EntryMode)>,
    /// `ChunkedBlob` leaf id.
    pub leaf_id: Hash,
    /// Public key embedded in the commit.
    pub signer: [u8; 32],
    /// Whether the embedded signature verifies; key trust is caller policy.
    pub signature_valid: bool,
    /// Absolute content offset.
    pub offset: u64,
    /// Verified content bytes in the requested range.
    pub bytes: Vec<u8>,
    /// First included chunk index.
    pub first: u32,
    /// Last included chunk index.
    pub last: u32,
    /// Authenticated absolute beginning of the first chunk.
    pub span_start: u64,
    /// Authenticated bare chunk BMT root.
    pub chunk_inner_root: Hash,
}

/// First failed KDSP check, in SPEC-DISCLOSURE §8.2 order.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SpanError {
    /// Container exceeds 64 MiB.
    #[error("span_too_large")]
    TooLarge,
    /// Wrong magic.
    #[error("span_magic")]
    Magic,
    /// Wrong version.
    #[error("span_version")]
    Version,
    /// Truncated field, invalid varint, or oversized vector.
    #[error("span_encoding")]
    Encoding,
    /// Extra bytes after the declared vectors.
    #[error("span_trailing_bytes")]
    TrailingBytes,
    /// Embedded commit id differs from the trusted id.
    #[error("span_commit")]
    Commit,
    /// Zero length or overflowed endpoint.
    #[error("span_range_arithmetic")]
    RangeArithmetic,
    /// Fewer than two chunk bundles.
    #[error("span_chunk_count")]
    ChunkCount,
    /// An inner KDPB failed verification.
    #[error("span_inner_invalid: {0}")]
    InnerInvalid(#[source] VerifyError),
    /// An inner payload is not Chunk.
    #[error("span_chunk_selector")]
    ChunkSelector,
    /// Inner path or leaf differs from the first bundle's.
    #[error("span_leaf_context")]
    LeafContext,
    /// Inner chunk metadata or root differs from the first bundle's.
    #[error("span_chunk_context")]
    ChunkContext,
    /// Chunk indices are not consecutive and ascending.
    #[error("span_chunk_order")]
    ChunkOrder,
    /// A chunk does not end where the next one starts.
    #[error("span_chunk_chain")]
    ChunkChain,
    /// The range is outside the span of the included chunks.
    #[error("span_range_outside")]
    RangeOutside,
    /// The final included chunk is unnecessary.
    #[error("span_last_unneeded")]
    LastUnneeded,
}

impl SpanError {
    /// Stable language-independent golden reject label.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        match self {
            Self::TooLarge => "span_too_large",
            Self::Magic => "span_magic",
            Self::Version => "span_version",
            Self::Encoding => "span_encoding",
            Self::TrailingBytes => "span_trailing_bytes",
            Self::Commit => "span_commit",
            Self::RangeArithmetic => "span_range_arithmetic",
            Self::ChunkCount => "span_chunk_count",
            Self::InnerInvalid(_) => "span_inner_invalid",
            Self::ChunkSelector => "span_chunk_selector",
            Self::LeafContext => "span_leaf_context",
            Self::ChunkContext => "span_chunk_context",
            Self::ChunkOrder => "span_chunk_order",
            Self::ChunkChain => "span_chunk_chain",
            Self::RangeOutside => "span_range_outside",
            Self::LastUnneeded => "span_last_unneeded",
        }
    }
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], SpanError> {
        if n > self.0.len() {
            return Err(SpanError::Encoding);
        }
        let (part, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(part)
    }

    fn u64(&mut self) -> Result<u64, SpanError> {
        let bytes: [u8; 8] = self.take(8)?.try_into().map_err(|_| SpanError::Encoding)?;
        Ok(u64::from_be_bytes(bytes))
    }

    /// Strict minimal LEB128, capped at u32 and at `limit`.
    fn length(&mut self, limit: usize) -> Result<usize, SpanError> {
        let mut value = 0u32;
        for i in 0..5 {
            let byte = self.take(1)?[0];
            if (i > 0 && byte == 0) || (i == 4 && byte > 15) {
                return Err(SpanError::Encoding);
            }
            value |= u32::from(byte & 0x7f) << (7 * i);
            if byte & 0x80 == 0 {
                let n = value as usize;
                return (n <= limit).then_some(n).ok_or(SpanError::Encoding);
            }
        }
        Err(SpanError::Encoding)
    }

    fn vector(&mut self) -> Result<&'a [u8], SpanError> {
        let n = self.length(self.0.len().min(MAX_BUNDLE_BYTES))?;
        self.take(n)
    }
}

struct Decoded<'a> {
    commit: Hash,
    offset: u64,
    len: u64,
    chunks: Vec<&'a [u8]>,
}

fn decode(bytes: &[u8]) -> Result<Decoded<'_>, SpanError> {
    if bytes.len() > MAX_BUNDLE_BYTES {
        return Err(SpanError::TooLarge);
    }
    let mut reader = Reader(bytes);
    if reader.take(4)? != MAGIC {
        return Err(SpanError::Magic);
    }
    if reader.take(1)? != [VERSION] {
        return Err(SpanError::Version);
    }
    let commit = reader
        .take(32)?
        .try_into()
        .map_err(|_| SpanError::Encoding)?;
    let offset = reader.u64()?;
    let len = reader.u64()?;
    let count = reader.length(MAX_CHUNK_BUNDLES)?;
    // Each vector takes at least one length byte. This bound is checked
    // before even an empty Vec is constructed from an untrusted count.
    if count > reader.0.len() {
        return Err(SpanError::Encoding);
    }
    let mut chunks = Vec::new();
    for _ in 0..count {
        chunks.push(reader.vector()?);
    }
    if !reader.0.is_empty() {
        return Err(SpanError::TrailingBytes);
    }
    Ok(Decoded {
        commit,
        offset,
        len,
        chunks,
    })
}

/// Encode a KDSP v2 container from already encoded KDPB v3 `Chunk` bundles.
///
/// Encoding does not authenticate or validate the supplied bundles. Callers
/// must verify the result against a trusted commit id before using it.
#[must_use]
pub fn encode_span(commit: Hash, offset: u64, len: u64, chunks: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    commit.write(&mut out);
    offset.write(&mut out);
    len.write(&mut out);
    let mut count = chunks.len();
    loop {
        #[allow(clippy::cast_possible_truncation)] // Mask keeps the value within seven bits.
        let byte = (count & 0x7f) as u8;
        count >>= 7;
        out.push(if count == 0 { byte } else { byte | 0x80 });
        if count == 0 {
            break;
        }
    }
    for chunk in chunks {
        (*chunk).write(&mut out);
    }
    out
}

/// What the verifier keeps of one verified chunk bundle: small and fixed
/// size, so a container of many chunks never holds earlier chunk bytes.
struct Summary {
    selector_ok: bool,
    leaf_ok: bool,
    index: u32,
    start: u64,
    end: u64,
    total_size: u64,
    chunk_size: u32,
    inner_root: Option<Hash>,
}

// This seam lets unit tests exercise inconsistent decoded summaries that
// genuine authenticated KDPB bundles cannot produce.
fn check_summaries(summaries: &[Summary], offset: u64, end: u64) -> Result<(), SpanError> {
    let (Some(first), Some(last)) = (summaries.first(), summaries.last()) else {
        return Err(SpanError::ChunkCount);
    };
    if summaries.iter().any(|s| !s.selector_ok) {
        return Err(SpanError::ChunkSelector);
    }
    if summaries.iter().any(|s| !s.leaf_ok) {
        return Err(SpanError::LeafContext);
    }
    if summaries.iter().any(|s| {
        (s.total_size, s.chunk_size, s.inner_root)
            != (first.total_size, first.chunk_size, first.inner_root)
    }) {
        return Err(SpanError::ChunkContext);
    }
    if summaries.iter().enumerate().any(|(i, s)| {
        u32::try_from(i)
            .ok()
            .and_then(|i| first.index.checked_add(i))
            != Some(s.index)
    }) {
        return Err(SpanError::ChunkOrder);
    }
    if summaries
        .windows(2)
        .any(|pair| pair[0].end != pair[1].start)
    {
        return Err(SpanError::ChunkChain);
    }
    if offset < first.start || offset >= first.end || end > last.end {
        return Err(SpanError::RangeOutside);
    }
    if end <= last.start {
        return Err(SpanError::LastUnneeded);
    }
    Ok(())
}

/// What the first bundle authenticated; later bundles must agree with it.
struct Head {
    context: CommitContext,
    tree_hash: Hash,
    path: Vec<(Vec<u8>, EntryMode)>,
    leaf_id: Hash,
    signer: [u8; 32],
    signature_valid: bool,
}

/// Verify a multi-chunk range against a trusted commit id.
///
/// # Errors
///
/// Returns the first failed [`SpanError`] check in SPEC-DISCLOSURE §8.2
/// table order. No partial content escapes on any error.
pub fn verify_disclosure_span(trusted: &Hash, bytes: &[u8]) -> Result<DisclosedSpan, SpanError> {
    let decoded = decode(bytes)?;
    if &decoded.commit != trusted {
        return Err(SpanError::Commit);
    }
    let end = decoded
        .offset
        .checked_add(decoded.len)
        .filter(|_| decoded.len != 0)
        .ok_or(SpanError::RangeArithmetic)?;
    if decoded.chunks.len() < 2 {
        return Err(SpanError::ChunkCount);
    }
    let mut head: Option<Head> = None;
    let mut summaries = Vec::with_capacity(decoded.chunks.len());
    let mut output = Vec::new();
    for bundle in decoded.chunks {
        let inner = match &head {
            None => verify_disclosure(trusted, bundle),
            Some(head) => verify_disclosure_reusing_context(trusted, bundle, &head.context),
        }
        .map_err(SpanError::InnerInvalid)?;
        let leaf_ok = head
            .as_ref()
            .is_none_or(|head| inner.path == head.path && inner.leaf_id == head.leaf_id);
        if head.is_none() {
            head = Some(Head {
                context: CommitContext::from_disclosed(&inner),
                tree_hash: inner.tree_hash,
                path: inner.path.clone(),
                leaf_id: inner.leaf_id,
                signer: inner.signer,
                signature_valid: inner.signature_valid,
            });
        }
        let mut summary = Summary {
            selector_ok: false,
            leaf_ok,
            index: 0,
            start: 0,
            end: 0,
            total_size: 0,
            chunk_size: 0,
            inner_root: inner.chunk_inner_root,
        };
        if let DisclosedPayload::Chunk {
            total_size,
            chunk_size,
            index,
            start,
            end: chunk_end,
            bytes: chunk_bytes,
        } = inner.payload
        {
            summary.selector_ok = true;
            summary.index = index;
            summary.start = start;
            summary.end = chunk_end;
            summary.total_size = total_size;
            summary.chunk_size = chunk_size;
            // The bundle verified: `chunk_bytes` is one Blob whose content is
            // exactly `chunk_end - start` bytes long.
            let content = chunk_bytes.get(10..).unwrap_or_default();
            let from = decoded.offset.max(start);
            let to = end.min(chunk_end);
            if from < to {
                let a = usize::try_from(from - start).map_err(|_| SpanError::RangeOutside)?;
                let b = usize::try_from(to - start).map_err(|_| SpanError::RangeOutside)?;
                output.extend_from_slice(content.get(a..b).ok_or(SpanError::RangeOutside)?);
            }
        }
        summaries.push(summary);
    }
    check_summaries(&summaries, decoded.offset, end)?;
    if u64::try_from(output.len()) != Ok(decoded.len) {
        return Err(SpanError::RangeOutside);
    }
    let (Some(head), Some(first), Some(last)) = (head, summaries.first(), summaries.last()) else {
        return Err(SpanError::ChunkCount);
    };
    Ok(DisclosedSpan {
        commit_id: *trusted,
        tree_hash: head.tree_hash,
        path: head.path,
        leaf_id: head.leaf_id,
        signer: head.signer,
        signature_valid: head.signature_valid,
        offset: decoded.offset,
        bytes: output,
        first: first.index,
        last: last.index,
        span_start: first.start,
        chunk_inner_root: first.inner_root.ok_or(SpanError::ChunkContext)?,
    })
}

/// Encoded representation chosen for a requested range.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RangeProof {
    /// One KDPB v3 Range bundle.
    Kdpb(Vec<u8>),
    /// One KDSP v2 container.
    Kdsp(Vec<u8>),
}

/// Proof format, independent of encoded bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RangeProofKind {
    /// The range lies within one chunk (or a plain Blob): one KDPB v3 bundle.
    Kdpb,
    /// The range crosses a chunk boundary: one KDSP v2 container.
    Kdsp,
}

/// Pure prefetch plan for a chunked file. `needed_chunk_indices` contains
/// each chunk the range touches, in ascending order.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Plan {
    /// Proof format the range requires.
    pub kind: RangeProofKind,
    /// Index of the chunk containing the first requested byte.
    pub first: usize,
    /// Index of the chunk containing the last requested byte.
    pub last: usize,
    /// Every chunk index that must be read: `first..=last`.
    pub needed_chunk_indices: Vec<usize>,
}

/// Typed builder and planner failures.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RangeProofError {
    /// The requested length is zero.
    #[error("range length must be nonzero")]
    ZeroLength,
    /// `offset + len` (or a running chunk offset) overflows `u64`.
    #[error("range endpoint overflow")]
    OffsetOverflow,
    /// The range extends past the end of the file.
    #[error("range is outside the file")]
    OutOfBounds,
    /// A manifest chunk is not a canonical nonempty Blob.
    #[error("chunk {index} is not a canonical nonempty Blob")]
    InvalidChunk {
        /// Index of the offending chunk.
        index: usize,
    },
    /// The encoded proof would exceed the 64 MiB cap.
    #[error("encoded proof exceeds 64 MiB")]
    ProofTooLarge,
    /// The object source failed.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// A disclosure-building step failed.
    #[error(transparent)]
    Verify(#[from] VerifyError),
    /// A source object failed to decode.
    #[error(transparent)]
    Decode(#[from] KitError),
}

/// Plan a range from canonical chunk content lengths. The end is exclusive;
/// an end exactly on a chunk boundary does not need the next chunk.
///
/// # Errors
///
/// Zero length, overflow, empty/zero chunks, or an out-of-file range.
pub fn plan_range_proof(
    chunk_lengths: &[u64],
    offset: u64,
    len: u64,
) -> Result<Plan, RangeProofError> {
    if len == 0 {
        return Err(RangeProofError::ZeroLength);
    }
    let end = offset
        .checked_add(len)
        .ok_or(RangeProofError::OffsetOverflow)?;
    let mut cursor = 0u64;
    let mut first = None;
    let mut last = None;
    for (i, &length) in chunk_lengths.iter().enumerate() {
        if length == 0 {
            return Err(RangeProofError::InvalidChunk { index: i });
        }
        let next = cursor
            .checked_add(length)
            .ok_or(RangeProofError::OffsetOverflow)?;
        if first.is_none() && offset < next {
            first = Some(i);
        }
        if first.is_some() && end <= next {
            last = Some(i);
            break;
        }
        cursor = next;
    }
    let first = first.ok_or(RangeProofError::OutOfBounds)?;
    let last = last.ok_or(RangeProofError::OutOfBounds)?;
    Ok(Plan {
        kind: if first == last {
            RangeProofKind::Kdpb
        } else {
            RangeProofKind::Kdsp
        },
        first,
        last,
        needed_chunk_indices: (first..=last).collect(),
    })
}

fn chunk_payload(
    cb: &crate::object::ChunkedBlob,
    index: u32,
    bytes: Vec<u8>,
) -> Result<PayloadWire, RangeProofError> {
    let position = index.checked_add(1).ok_or(VerifyError::TooManyChunks)?;
    let (start, end) = cb.span(index).ok_or(VerifyError::ChunkIndexOutOfRange {
        index,
        leaf_count: u32::try_from(cb.chunks().len()).map_or(u32::MAX, |n| n.saturating_add(1)),
    })?;
    Ok(PayloadWire::Chunk {
        total_size: cb.total_size(),
        chunk_size: cb.chunk_size(),
        index,
        start,
        end,
        inner_root: merkle::chunked_inner_root(cb),
        proof: merkle::build_chunks_multi_proof(cb, [0, position]).map_err(VerifyError::from)?,
        bytes,
    })
}

fn varint_size(mut n: usize) -> usize {
    let mut size = 1;
    while n >= 128 {
        n >>= 7;
        size += 1;
    }
    size
}

/// Whether a KDSP container of `count` bundles whose framed bundles take
/// `container_size` bytes fits the 64 MiB cap: the magic, the version, the
/// commit id, the offset and the length, the count, then the bundles.
fn span_container_fits(count: usize, container_size: usize) -> bool {
    (4 + 1 + 32 + 8 + 8 + varint_size(count))
        .checked_add(container_size)
        .is_some_and(|n| n <= MAX_BUNDLE_BYTES)
}

fn encoded_disclosure_size(
    commit_bytes: &[u8],
    steps: &[Step],
    payload: &PayloadWire,
) -> Result<usize, RangeProofError> {
    let payload_size = match payload {
        PayloadWire::Object { bytes } => bytes.as_slice().encode_size(),
        PayloadWire::Chunk { proof, bytes, .. } => {
            8 + 4 + 4 + 8 + 8 + 32 + proof.encode_size() + bytes.as_slice().encode_size()
        }
        PayloadWire::Range { chunk, slice, .. } => {
            chunk.encode_size() + 8 + 8 + slice.as_slice().encode_size()
        }
    };
    4usize
        .checked_add(1 + 32 + 1)
        .and_then(|n| n.checked_add(commit_bytes.encode_size()))
        .and_then(|n| n.checked_add(steps.encode_size()))
        .and_then(|n| n.checked_add(payload_size))
        .filter(|&n| n <= MAX_BUNDLE_BYTES)
        .ok_or(RangeProofError::ProofTooLarge)
}

/// Build the smallest representation for a range, reading only the chunks the
/// range touches: the manifest's ends locate the first one, so no chunk before
/// the range is read.
///
/// # Errors
///
/// Returns [`RangeProofError`] for invalid ranges, source objects, a chunk
/// whose length differs from its span, or an encoded result that exceeds the
/// KDPB/KDSP 64 MiB cap.
pub fn build_range_proof_from<S: ObjectSource + ?Sized>(
    source: &S,
    commit_id: &Hash,
    path: &[&[u8]],
    offset: u64,
    len: u64,
) -> Result<RangeProof, RangeProofError> {
    if len == 0 {
        return Err(RangeProofError::ZeroLength);
    }
    let end = offset
        .checked_add(len)
        .ok_or(RangeProofError::OffsetOverflow)?;
    let (commit_bytes, steps, leaf_id) = super::build_prefix(source, commit_id, path)?;
    let cb = match source.read_object(&leaf_id)? {
        Object::Blob(_) => {
            let payload = super::build_payload(source, &leaf_id, Selector::Range { offset, len })?;
            encoded_disclosure_size(&commit_bytes, &steps, &payload)?;
            let proof = encode_disclosure(commit_id, &commit_bytes, &steps, &payload);
            return Ok(RangeProof::Kdpb(proof));
        }
        Object::ChunkedBlob(cb) => cb,
        _ => return Err(VerifyError::SelectorLeafMismatch.into()),
    };
    if end > cb.total_size() {
        return Err(RangeProofError::OutOfBounds);
    }
    let first = cb.chunk_at(offset).ok_or(RangeProofError::OutOfBounds)?;
    let last = cb.chunk_at(end - 1).ok_or(RangeProofError::OutOfBounds)?;
    if first == last {
        let payload = super::build_chunked_range_payload(source, &cb, offset, len)?;
        encoded_disclosure_size(&commit_bytes, &steps, &payload)?;
        let proof = encode_disclosure(commit_id, &commit_bytes, &steps, &payload);
        return Ok(RangeProof::Kdpb(proof));
    }

    // The container is magic, version, commit, offset and len, then the count
    // and the bundles. Track its exact size so a range too large for the cap
    // is refused before more chunks are read.
    let mut container_size = 0usize;
    let mut chunks = Vec::new();
    for index in first..=last {
        let id = cb.chunks()[index as usize];
        let (chunk_bytes, content_len) = checked_blob_source(source, &id, index as usize)?;
        cb.check_chunk_length(index, content_len)?;
        let payload = chunk_payload(&cb, index, chunk_bytes)?;
        let bundle_size = encoded_disclosure_size(&commit_bytes, &steps, &payload)?;
        container_size = container_size
            .checked_add(varint_size(bundle_size))
            .and_then(|n| n.checked_add(bundle_size))
            .ok_or(RangeProofError::ProofTooLarge)?;
        if !span_container_fits(chunks.len() + 1, container_size) {
            return Err(RangeProofError::ProofTooLarge);
        }
        chunks.push(encode_disclosure(
            commit_id,
            &commit_bytes,
            &steps,
            &payload,
        ));
    }
    let refs: Vec<&[u8]> = chunks.iter().map(Vec::as_slice).collect();
    let proof = encode_span(*commit_id, offset, len, &refs);
    if proof.len() > MAX_BUNDLE_BYTES {
        return Err(RangeProofError::ProofTooLarge);
    }
    Ok(RangeProof::Kdsp(proof))
}

fn checked_blob_source<S: ObjectSource + ?Sized>(
    source: &S,
    id: &Hash,
    index: usize,
) -> Result<(Vec<u8>, u64), RangeProofError> {
    let bytes = source.read(id)?;
    let Object::Blob(blob) = crate::serialize::deserialize(&bytes)? else {
        return Err(RangeProofError::InvalidChunk { index });
    };
    let len = u64::try_from(blob.data.len()).map_err(|_| RangeProofError::OffsetOverflow)?;
    if len == 0 {
        return Err(RangeProofError::InvalidChunk { index });
    }
    Ok((bytes, len))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::hash::ZERO;
    use crate::layout::RepoLayout;
    use crate::object::{Blob, Commit, Identity, Tree, TreeEntry};
    use crate::sign::{KeyPair, sign_commit};
    use crate::store::{ObjectStore, StoreResult};
    use std::cell::RefCell;

    /// The size the builder charges against the 64 MiB cap is the length of
    /// the encoded bundle, for every payload kind.
    #[test]
    fn encoded_disclosure_size_is_the_encoded_length() {
        use crate::merkle::Proof;
        use crate::verify::ChunkHdr;
        let id = [7u8; 32];
        let commit_bytes = vec![1u8; 300];
        let proof = Proof {
            leaf_count: 5,
            siblings: vec![[2u8; 32]; 3],
        };
        let payloads = [
            PayloadWire::Object {
                bytes: vec![3u8; 200],
            },
            PayloadWire::Chunk {
                total_size: 100,
                chunk_size: 0,
                index: 1,
                start: 10,
                end: 20,
                inner_root: [4u8; 32],
                proof: proof.clone(),
                bytes: vec![5u8; 150],
            },
            PayloadWire::Range {
                chunk: None,
                offset_in_blob: 3,
                len: 4,
                slice: vec![6u8; 90],
            },
            PayloadWire::Range {
                chunk: Some(ChunkHdr {
                    total_size: 100,
                    chunk_size: 0,
                    index: 1,
                    start: 10,
                    end: 20,
                    inner_root: [4u8; 32],
                    chunk_id: [8u8; 32],
                    proof,
                }),
                offset_in_blob: 3,
                len: 4,
                slice: vec![6u8; 90],
            },
        ];
        for payload in &payloads {
            let encoded = crate::verify::encode_disclosure(&id, &commit_bytes, &[], payload);
            assert_eq!(
                encoded_disclosure_size(&commit_bytes, &[], payload).unwrap(),
                encoded.len()
            );
        }
    }

    const VALID: &[u8] =
        include_bytes!("../../../../tests/golden/http-objects/span_two_chunks.bin");
    const FIRST_ZERO: &[u8] =
        include_bytes!("../../../../tests/golden/http-objects/span_first_zero.bin");

    fn valid() -> (Hash, Decoded<'static>) {
        let decoded = decode(VALID).unwrap();
        (decoded.commit, decoded)
    }

    fn verify(bytes: &[u8]) -> &'static str {
        let (trusted, _) = valid();
        verify_disclosure_span(&trusted, bytes)
            .unwrap_err()
            .reason()
    }

    #[test]
    fn structural_checks_precede_crypto_and_follow_table_order() {
        let (trusted, d) = valid();
        let mut trailing_and_bad_commit = VALID.to_vec();
        trailing_and_bad_commit[5] ^= 1;
        trailing_and_bad_commit.push(0);
        assert_eq!(verify(&trailing_and_bad_commit), "span_trailing_bytes");

        let mut wrong_magic = VALID.to_vec();
        wrong_magic[0] = b'X';
        wrong_magic[4] = 1;
        assert_eq!(verify(&wrong_magic), "span_magic");
        assert_eq!(verify(&VALID[..4]), "span_encoding");
        assert_eq!(verify(&[b'K', b'D', b'S', b'P', 2]), "span_encoding");
        // Version 1 carried an anchor: it is not version 2.
        assert_eq!(verify(&[b'K', b'D', b'S', b'P', 1]), "span_version");

        let mut wrong_commit = VALID.to_vec();
        wrong_commit[5] ^= 1;
        assert_eq!(verify(&wrong_commit), "span_commit");
        assert_eq!(
            verify(&encode_span(trusted, d.offset, 0, &d.chunks)),
            "span_range_arithmetic"
        );
        assert_eq!(
            verify(&encode_span(trusted, u64::MAX, 2, &d.chunks)),
            "span_range_arithmetic"
        );
        assert_eq!(
            verify(&encode_span(trusted, d.offset, d.len, &d.chunks[..1])),
            "span_chunk_count"
        );
        assert_eq!(
            verify(&encode_span(trusted, d.offset, d.len, &[])),
            "span_chunk_count"
        );
    }

    #[test]
    fn every_spec_reason_has_its_own_stable_label() {
        let reasons = [
            SpanError::TooLarge,
            SpanError::Magic,
            SpanError::Version,
            SpanError::Encoding,
            SpanError::TrailingBytes,
            SpanError::Commit,
            SpanError::RangeArithmetic,
            SpanError::ChunkCount,
            SpanError::InnerInvalid(VerifyError::BadMagic),
            SpanError::ChunkSelector,
            SpanError::LeafContext,
            SpanError::ChunkContext,
            SpanError::ChunkOrder,
            SpanError::ChunkChain,
            SpanError::RangeOutside,
            SpanError::LastUnneeded,
        ];
        let labels = [
            "span_too_large",
            "span_magic",
            "span_version",
            "span_encoding",
            "span_trailing_bytes",
            "span_commit",
            "span_range_arithmetic",
            "span_chunk_count",
            "span_inner_invalid",
            "span_chunk_selector",
            "span_leaf_context",
            "span_chunk_context",
            "span_chunk_order",
            "span_chunk_chain",
            "span_range_outside",
            "span_last_unneeded",
        ];
        for (error, label) in reasons.into_iter().zip(labels) {
            assert_eq!(error.reason(), label);
        }
    }

    /// Summaries that genuine authenticated bundles cannot produce still
    /// map to their own reason, in the order of the table.
    #[test]
    fn cross_bundle_reasons_include_defence_in_depth() {
        let root = [7; 32];
        let good = |index, start, end| Summary {
            selector_ok: true,
            leaf_ok: true,
            index,
            start,
            end,
            total_size: 100,
            chunk_size: 0,
            inner_root: Some(root),
        };
        let check = |cases: &[Summary], offset, end| {
            check_summaries(cases, offset, end).map_err(|e| e.reason())
        };
        let mut cases = vec![good(4, 0, 10), good(5, 10, 20)];
        assert_eq!(check(&cases, 5, 15), Ok(()));
        assert_eq!(check(&[], 5, 15), Err("span_chunk_count"));

        cases[1].selector_ok = false;
        cases[0].leaf_ok = false;
        assert_eq!(check(&cases, 5, 15), Err("span_chunk_selector"));
        cases[1].selector_ok = true;
        assert_eq!(check(&cases, 5, 15), Err("span_leaf_context"));
        cases[0].leaf_ok = true;

        for forge in [
            |s: &mut Summary| s.total_size += 1,
            |s: &mut Summary| s.chunk_size += 1,
            |s: &mut Summary| s.inner_root = Some([8; 32]),
            |s: &mut Summary| s.inner_root = None,
        ] {
            let mut forged = vec![good(4, 0, 10), good(5, 10, 20)];
            forge(&mut forged[1]);
            assert_eq!(check(&forged, 5, 15), Err("span_chunk_context"));
        }

        cases[1].index = 6;
        assert_eq!(check(&cases, 5, 15), Err("span_chunk_order"));
        cases[1].index = 5;
        // The chain: one chunk ends where the next one starts.
        cases[1].start = 11;
        assert_eq!(check(&cases, 5, 15), Err("span_chunk_chain"));
        cases[1].start = 9;
        assert_eq!(check(&cases, 5, 15), Err("span_chunk_chain"));
        cases[1].start = 10;
        // The range lies in `[start_first, end_last)` and starts in the first
        // chunk.
        assert_eq!(check(&cases, 10, 15), Err("span_range_outside"));
        assert_eq!(check(&cases, 5, 21), Err("span_range_outside"));
        // The last chunk is needed: the range must reach into it.
        assert_eq!(check(&cases, 5, 10), Err("span_last_unneeded"));
        assert_eq!(check(&cases, 5, 11), Ok(()));
        assert_eq!(check(&cases, 9, 20), Ok(()));
    }

    #[test]
    fn verified_bundle_failures_follow_selector_and_offset_checks() {
        let (trusted, d) = valid();
        let bad_inner = encode_span(trusted, d.offset, d.len, &[b"KDSP", d.chunks[1]]);
        assert_eq!(verify(&bad_inner), "span_inner_invalid");

        // A verified KDPB bundle whose payload is a Range, not a Chunk.
        let (id, commit_bytes, steps, payload) =
            super::super::decode_disclosure(d.chunks[0]).unwrap();
        let PayloadWire::Chunk {
            total_size,
            chunk_size,
            index,
            start,
            end,
            inner_root,
            proof,
            bytes,
        } = payload
        else {
            panic!("chunk payload");
        };
        let chunk_id = crate::hash::hash(&bytes);
        let slice = super::super::extract_bao_slice(&bytes, 10, 1).unwrap();
        let range = encode_disclosure(
            &id,
            &commit_bytes,
            &steps,
            &PayloadWire::Range {
                chunk: Some(super::super::ChunkHdr {
                    total_size,
                    chunk_size,
                    index,
                    start,
                    end,
                    inner_root,
                    chunk_id,
                    proof,
                }),
                offset_in_blob: 0,
                len: 1,
                slice,
            },
        );
        assert!(verify_disclosure(&trusted, &range).is_ok());
        let wrong_selector = encode_span(trusted, d.offset, d.len, &[&range, d.chunks[1]]);
        assert_eq!(verify(&wrong_selector), "span_chunk_selector");

        let start = verify_disclosure_span(&trusted, VALID).unwrap().span_start;
        let outside = encode_span(trusted, start - 1, d.len, &d.chunks);
        assert_eq!(verify(&outside), "span_range_outside");
        // The same chunks in the wrong order, or one chunk twice.
        let swapped = encode_span(trusted, d.offset, d.len, &[d.chunks[1], d.chunks[0]]);
        assert_eq!(verify(&swapped), "span_chunk_order");
        let twice = encode_span(trusted, d.offset, d.len, &[d.chunks[0], d.chunks[0]]);
        assert_eq!(verify(&twice), "span_chunk_order");
    }

    #[test]
    fn strict_varints_and_vector_bounds() {
        let (_, d) = valid();
        // The count follows magic, version, commit, offset and length.
        let count_at = 4 + 1 + 32 + 8 + 8;
        let mut nonminimal = VALID[..count_at].to_vec();
        nonminimal.extend_from_slice(&[0x82, 0]);
        nonminimal.extend_from_slice(&VALID[count_at + 1..]);
        assert_eq!(verify(&nonminimal), "span_encoding");

        let mut over_u32 = VALID[..count_at].to_vec();
        over_u32.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0x10]);
        assert_eq!(verify(&over_u32), "span_encoding");

        let mut count_over_remaining = VALID[..count_at].to_vec();
        count_over_remaining.extend_from_slice(&[0xff, 0xff, 0x03]);
        assert_eq!(verify(&count_over_remaining), "span_encoding");

        let mut length_over_remaining = VALID[..count_at].to_vec();
        length_over_remaining.extend_from_slice(&[2, 0xff, 0xff, 0x03]);
        assert_eq!(verify(&length_over_remaining), "span_encoding");

        let mut count_over_bytes = encode_span(d.commit, d.offset, d.len, &[]);
        *count_over_bytes.last_mut().unwrap() = 2;
        assert_eq!(verify(&count_over_bytes), "span_encoding");
    }

    #[test]
    fn exact_boundaries_and_last_chunk_needed() {
        let d = decode(FIRST_ZERO).unwrap();
        let first = verify_disclosure(&d.commit, d.chunks[0]).unwrap();
        let DisclosedPayload::Chunk { bytes, .. } = first.payload else {
            panic!("chunk")
        };
        let Object::Blob(blob) = crate::serialize::deserialize(&bytes).unwrap() else {
            panic!("blob")
        };
        let edge = blob.data.len() as u64;
        let prior_only = encode_span(d.commit, edge - 1, 1, &d.chunks);
        assert_eq!(verify(&prior_only), "span_last_unneeded");
        let at_edge = encode_span(d.commit, edge - 1, 2, &d.chunks);
        assert_eq!(
            verify_disclosure_span(&d.commit, &at_edge)
                .unwrap()
                .bytes
                .len(),
            2
        );
        let last = verify_disclosure(&d.commit, d.chunks[1]).unwrap();
        let DisclosedPayload::Chunk { bytes, .. } = last.payload else {
            panic!("chunk")
        };
        let Object::Blob(blob) = crate::serialize::deserialize(&bytes).unwrap() else {
            panic!("blob")
        };
        let to_span_end = encode_span(d.commit, edge - 1, blob.data.len() as u64 + 1, &d.chunks);
        assert_eq!(
            verify_disclosure_span(&d.commit, &to_span_end)
                .unwrap()
                .bytes
                .len() as u64,
            blob.data.len() as u64 + 1
        );
        // One byte past the last chunk is outside the span.
        let past = encode_span(d.commit, edge - 1, blob.data.len() as u64 + 2, &d.chunks);
        assert_eq!(verify(&past), "span_range_outside");
    }

    #[test]
    fn pure_plan_respects_exact_edges() {
        let one = plan_range_proof(&[10, 20, 30], 5, 5).unwrap();
        assert_eq!(
            (one.kind, one.first, one.last),
            (RangeProofKind::Kdpb, 0, 0)
        );
        let two = plan_range_proof(&[10, 20, 30], 9, 2).unwrap();
        assert_eq!(
            (two.kind, two.first, two.last),
            (RangeProofKind::Kdsp, 0, 1)
        );
        let later = plan_range_proof(&[10, 20, 30], 12, 18).unwrap();
        assert_eq!(
            (later.kind, later.first, later.last),
            (RangeProofKind::Kdpb, 1, 1)
        );
        assert_eq!(later.needed_chunk_indices, vec![1]);
        assert!(matches!(
            plan_range_proof(&[10], 0, 0),
            Err(RangeProofError::ZeroLength)
        ));
    }

    struct CountingSource<'a> {
        store: &'a ObjectStore,
        reads: RefCell<Vec<Hash>>,
    }

    impl ObjectSource for CountingSource<'_> {
        fn read(&self, h: &Hash) -> StoreResult<Vec<u8>> {
            self.reads.borrow_mut().push(*h);
            self.store.read(h)
        }
    }

    /// A commit over a file `name` whose chunk blobs are `lens` bytes each,
    /// content-defined, so each chunk's content is its index plus one.
    fn commit_over_chunks(
        store: &ObjectStore,
        name: &[u8],
        chunk_size: u32,
        lens: &[u64],
    ) -> (Hash, Vec<Hash>) {
        let mut chunk_ids = Vec::new();
        for (i, &len) in lens.iter().enumerate() {
            let bytes = crate::serialize::serialize(&Object::Blob(Blob {
                data: vec![u8::try_from(i).unwrap() + 1; usize::try_from(len).unwrap()],
            }))
            .unwrap();
            chunk_ids.push(store.write(&bytes).unwrap());
        }
        let manifest = crate::object::testing::sized(
            chunk_size,
            chunk_ids
                .iter()
                .copied()
                .zip(lens.iter().copied())
                .collect(),
        )
        .unwrap();
        let leaf_id = store
            .write(&crate::serialize::serialize(&Object::ChunkedBlob(manifest)).unwrap())
            .unwrap();
        (commit_naming(store, &[name], leaf_id), chunk_ids)
    }

    /// A signed commit whose tree names `leaf_id` under every one of `names`,
    /// which must be in order.
    fn commit_naming(store: &ObjectStore, names: &[&[u8]], leaf_id: Hash) -> Hash {
        let tree = Tree {
            entries: names
                .iter()
                .map(|name| TreeEntry {
                    name: name.to_vec(),
                    mode: EntryMode::Blob,
                    object_hash: leaf_id,
                })
                .collect(),
        };
        let tree_hash = store
            .write(&crate::serialize::serialize(&Object::Tree(tree)).unwrap())
            .unwrap();
        let kp = KeyPair::from_seed([3; 32]);
        let mut commit = Commit {
            tree_hash,
            parents: vec![],
            author: Identity::ed25519(kp.public.0),
            signer: kp.public.0,
            message: b"span unit".to_vec(),
            timestamp: 1,
            message_hash: ZERO,
            content_digest: ZERO,
            signature: [0; 64],
        };
        commit.signature = sign_commit(&commit, &kp).unwrap().0;
        store
            .write(&crate::serialize::serialize(&Object::Commit(commit)).unwrap())
            .unwrap()
    }

    /// The builder finds the chunk that holds the offset from the manifest's
    /// ends and reads only the chunks the range touches: none before it, and
    /// none after it.
    #[test]
    fn builder_reads_only_the_chunks_the_range_touches() {
        let temp = tempfile::TempDir::new().unwrap();
        let store = ObjectStore::init(&RepoLayout::single(temp.path())).unwrap();
        let (commit_id, chunk_ids) = commit_over_chunks(&store, b"file", 2048, &[2048; 4]);
        let source = CountingSource {
            store: &store,
            reads: RefCell::new(Vec::new()),
        };
        // A range across the first boundary reads chunks 1 and 2 of 4.
        let RangeProof::Kdsp(proof) =
            build_range_proof_from(&source, &commit_id, &[b"file"], 2047, 2).unwrap()
        else {
            panic!("expected KDSP")
        };
        let span = verify_disclosure_span(&commit_id, &proof).unwrap();
        assert_eq!(span.bytes, [1, 2]);
        assert_eq!((span.first, span.last, span.span_start), (0, 1, 0));
        let reads = source.reads.borrow().clone();
        assert_eq!(reads.iter().filter(|h| **h == chunk_ids[0]).count(), 1);
        assert_eq!(reads.iter().filter(|h| **h == chunk_ids[1]).count(), 1);
        assert!(!reads.contains(&chunk_ids[2]));
        assert!(!reads.contains(&chunk_ids[3]));

        // A range in the last chunk reads that chunk alone.
        source.reads.borrow_mut().clear();
        let RangeProof::Kdpb(proof) =
            build_range_proof_from(&source, &commit_id, &[b"file"], 6200, 1).unwrap()
        else {
            panic!("expected KDPB")
        };
        let d = verify_disclosure(&commit_id, &proof).unwrap();
        let DisclosedPayload::Range {
            bytes,
            absolute_offset,
            start,
            ..
        } = d.payload
        else {
            panic!("range payload")
        };
        assert_eq!((bytes, absolute_offset, start), (vec![4], 6200, Some(6144)));
        let reads = source.reads.borrow().clone();
        assert!(reads.contains(&chunk_ids[3]));
        for earlier in &chunk_ids[..3] {
            assert!(!reads.contains(earlier));
        }
    }

    /// A range outside the file, or with a zero or overflowing length, is a
    /// typed error before any chunk is read.
    #[test]
    fn builder_refuses_ranges_the_file_cannot_hold() {
        let temp = tempfile::TempDir::new().unwrap();
        let store = ObjectStore::init(&RepoLayout::single(temp.path())).unwrap();
        let (commit_id, _) = commit_over_chunks(&store, b"file", 0, &[10, 20]);
        let build =
            |offset, len| build_range_proof_from(&store, &commit_id, &[b"file"], offset, len);
        assert!(matches!(build(0, 0), Err(RangeProofError::ZeroLength)));
        assert!(matches!(
            build(u64::MAX, 2),
            Err(RangeProofError::OffsetOverflow)
        ));
        assert!(matches!(build(30, 1), Err(RangeProofError::OutOfBounds)));
        assert!(matches!(build(29, 2), Err(RangeProofError::OutOfBounds)));
        assert!(matches!(build(29, 1), Ok(RangeProof::Kdpb(_))));
        assert!(matches!(build(9, 2), Ok(RangeProof::Kdsp(_))));
    }

    /// The size check of a container is exact: the header it charges is the
    /// header `encode_span` writes, and the cap itself is allowed.
    #[test]
    fn container_size_check_has_exact_bounds() {
        let bundle = [0u8; 5];
        for count in [2usize, 127, 128, 16_384] {
            let bundles = vec![&bundle[..]; count];
            let encoded = encode_span([1; 32], 2, 3, &bundles);
            let framed: usize = bundles.iter().map(|b| varint_size(b.len()) + b.len()).sum();
            // The cap is the encoded length: it fits there and not one byte less.
            assert_eq!(encoded.len(), 53 + varint_size(count) + framed);
            let header = encoded.len() - framed;
            assert!(span_container_fits(count, MAX_BUNDLE_BYTES - header));
            assert!(!span_container_fits(count, MAX_BUNDLE_BYTES - header + 1));
        }
        assert!(!span_container_fits(2, usize::MAX));
    }

    /// Two bundles of one file named under two paths do not make a range:
    /// the same leaf under another path is another file.
    #[test]
    fn a_span_of_two_paths_for_one_leaf_is_refused() {
        let temp = tempfile::TempDir::new().unwrap();
        let store = ObjectStore::init(&RepoLayout::single(temp.path())).unwrap();
        let (_, chunk_ids) = commit_over_chunks(&store, b"a", 2048, &[2048; 2]);
        let manifest =
            crate::object::testing::sized(2048, chunk_ids.into_iter().zip([2048, 2048]).collect())
                .unwrap();
        let leaf = store
            .write(&crate::serialize::serialize(&Object::ChunkedBlob(manifest)).unwrap())
            .unwrap();
        let commit_id = commit_naming(&store, &[b"a", b"b"], leaf);
        let bundle = |path: &[u8], index| {
            crate::verify::build_disclosure(&store, &commit_id, &[path], Selector::Chunk(index))
                .unwrap()
        };
        let same = encode_span(commit_id, 2000, 100, &[&bundle(b"a", 0), &bundle(b"a", 1)]);
        assert!(verify_disclosure_span(&commit_id, &same).is_ok());
        let two = encode_span(commit_id, 2000, 100, &[&bundle(b"a", 0), &bundle(b"b", 1)]);
        assert_eq!(
            verify_disclosure_span(&commit_id, &two)
                .unwrap_err()
                .reason(),
            "span_leaf_context"
        );
    }

    /// A chunk blob whose length is not its span is refused by the builder
    /// before it makes a bundle the verifier would refuse.
    #[test]
    fn builder_refuses_a_chunk_that_is_not_its_span() {
        let temp = tempfile::TempDir::new().unwrap();
        let store = ObjectStore::init(&RepoLayout::single(temp.path())).unwrap();
        let blob = |n: usize| {
            store
                .write(
                    &crate::serialize::serialize(&Object::Blob(Blob { data: vec![1; n] })).unwrap(),
                )
                .unwrap()
        };
        // Spans of 10 and 10 bytes over blobs of 10 and 12.
        let cb = crate::object::testing::spread(20, 0, vec![blob(10), blob(12)]).unwrap();
        let leaf = store
            .write(&crate::serialize::serialize(&Object::ChunkedBlob(cb)).unwrap())
            .unwrap();
        let tree = Tree {
            entries: vec![TreeEntry {
                name: b"f".to_vec(),
                mode: EntryMode::Blob,
                object_hash: leaf,
            }],
        };
        let tree_hash = store
            .write(&crate::serialize::serialize(&Object::Tree(tree)).unwrap())
            .unwrap();
        let kp = KeyPair::from_seed([4; 32]);
        let mut commit = Commit {
            tree_hash,
            parents: vec![],
            author: Identity::ed25519(kp.public.0),
            signer: kp.public.0,
            message: b"lengths".to_vec(),
            timestamp: 1,
            message_hash: ZERO,
            content_digest: ZERO,
            signature: [0; 64],
        };
        commit.signature = sign_commit(&commit, &kp).unwrap().0;
        let commit_id = store
            .write(&crate::serialize::serialize(&Object::Commit(commit)).unwrap())
            .unwrap();
        // A range across both chunks reads chunk 1, whose blob is too long.
        assert!(matches!(
            build_range_proof_from(&store, &commit_id, &[b"f"], 5, 10),
            Err(RangeProofError::Decode(KitError::ChunkLengthMismatch {
                index: 1,
                expected: 10,
                actual: 12,
            }))
        ));
    }

    #[test]
    fn inner_commit_bytes_must_hash_to_the_trusted_id() {
        let (trusted, d) = valid();
        let (id, commit_bytes, steps, payload) =
            super::super::decode_disclosure(d.chunks[1]).unwrap();
        let mut altered = commit_bytes.clone();
        altered.push(0);
        let forged = encode_disclosure(&id, &altered, &steps, &payload);
        let container = encode_span(trusted, d.offset, d.len, &[d.chunks[0], &forged]);
        let error = verify_disclosure_span(&trusted, &container).unwrap_err();
        assert_eq!(error.reason(), "span_inner_invalid");
        assert!(matches!(
            error,
            SpanError::InnerInvalid(VerifyError::CommitBytesHashMismatch)
        ));
    }

    #[test]
    fn span_goldens_have_exact_metadata_planned_lengths() {
        use super::super::proof_size::{PrefixStep, chunked_range_proof_size};
        for bytes in [
            include_bytes!("../../../../tests/golden/http-objects/span_two_chunks.bin").as_slice(),
            include_bytes!("../../../../tests/golden/http-objects/span_three_chunks.bin")
                .as_slice(),
            include_bytes!("../../../../tests/golden/http-objects/span_first_zero.bin").as_slice(),
        ] {
            let span = decode(bytes).unwrap();
            let (_, commit, steps, first) =
                super::super::decode_disclosure(span.chunks[0]).unwrap();
            let PayloadWire::Chunk {
                index,
                start,
                proof,
                ..
            } = first
            else {
                panic!("chunk")
            };
            // The chunks before the first only place its span: one stand-in
            // length for each, summing to its start.
            let mut lengths: Vec<u64> = Vec::new();
            if index > 0 {
                lengths.push(start - (u64::from(index) - 1));
                lengths.extend(std::iter::repeat_n(1, index as usize - 1));
            }
            for bundle in &span.chunks {
                let (_, _, _, PayloadWire::Chunk { bytes, .. }) =
                    super::super::decode_disclosure(bundle).unwrap()
                else {
                    panic!("chunk")
                };
                lengths.push(bytes.len() as u64 - 10);
            }
            let metadata: Vec<PrefixStep> = steps
                .iter()
                .map(|step| PrefixStep {
                    name_len: step.name.len(),
                    position: step.position,
                    leaf_count: step.proof.leaf_count,
                })
                .collect();
            let plan = chunked_range_proof_size(
                commit.len() as u64,
                &metadata,
                proof.leaf_count - 1,
                &lengths,
                span.offset,
                span.len,
            )
            .unwrap();
            assert_eq!(plan.kind, RangeProofKind::Kdsp);
            assert_eq!(plan.encoded_size, bytes.len() as u64);
        }
    }
}
