//! `UploadPack` stream framing (SPEC-TRANSPORT §4.2).
//!
//! [`UploadValidator`] checks framing only. The header names a 32-byte
//! `pack_id` and a size within the cap. Each chunk repeats the `pack_id`, sits
//! at the next offset, stays within the declared size and stays within the
//! chunk cap. The `last` chunk ends exactly at the declared size. The
//! validator never hashes. The pack writer checks BLAKE3 before the pack
//! becomes visible.

use kit_core::protocol::PackKey;

/// The caps on one upload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UploadLimits {
    /// The largest `total_bytes` a header may declare.
    pub max_total_bytes: u64,
    /// The most chunks accepted, the `last` one included.
    pub max_chunks: u32,
}

/// Why an upload stream is rejected. Each variant has one fixed reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UploadError {
    /// The `pack_id` is absent (`None`) or not 32 bytes long.
    BadPackId(Option<usize>),
    /// A chunk names another pack than the header.
    PackIdMismatch,
    /// The header has no `total_bytes`.
    TotalMissing,
    /// The declared size is over the cap.
    TotalTooLarge,
    /// More chunks than the cap arrived without `last`.
    TooManyChunks,
    /// A chunk has no `offset`.
    OffsetMissing,
    /// A chunk's `offset` is not the running byte count.
    OffsetGap,
    /// The running byte count overflowed.
    ByteCountOverflow,
    /// The chunks carry more bytes than the header declared.
    Overrun,
    /// A chunk arrived after the `last` one.
    AfterLast,
    /// The stream ended without a `last` chunk.
    NoLast,
    /// The `last` chunk arrived before the declared byte count.
    LengthMismatch,
    /// The received bytes do not hash to the `pack_id`.
    DigestMismatch,
}

impl UploadError {
    /// The reply text. Every one goes out with `ERROR_CODE_INVALID_REQUEST`.
    pub(crate) const fn message(self) -> &'static str {
        match self {
            Self::BadPackId(None) => "pack_id missing",
            Self::BadPackId(Some(_)) => "pack_id must be 32 bytes",
            Self::PackIdMismatch => "PackChunk.pack_id does not match UploadPack",
            Self::TotalMissing => "UploadPack.total_bytes is required",
            Self::TotalTooLarge => "UploadPack.total_bytes exceeds server cap",
            Self::TooManyChunks => "too many PackChunk frames before last=true",
            Self::OffsetMissing => "PackChunk.offset is required",
            Self::OffsetGap => "PackChunk.offset is not the expected next offset",
            Self::ByteCountOverflow => "PackChunk byte count overflow",
            Self::Overrun => "PackChunk data exceeds declared total_bytes",
            Self::AfterLast => "PackChunk after last=true",
            Self::NoLast => "pack chunk read failed",
            Self::LengthMismatch => "PackChunk stream ended before declared total_bytes",
            Self::DigestMismatch => "uploaded pack bytes do not match UploadPack.pack_id",
        }
    }
}

/// Where an upload stands after a chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Progress {
    /// The `last` chunk arrived and the byte count matches the header.
    pub(crate) complete: bool,
}

/// Validates the framing of one upload, chunk by chunk, without buffering
/// or hashing. After an error the stream is dead: every later call returns
/// the same error.
#[derive(Debug, Clone)]
pub(crate) struct UploadValidator {
    key: PackKey,
    declared: u64,
    received: u64,
    chunks: u32,
    max_chunks: u32,
    complete: bool,
    failed: Option<UploadError>,
}

impl UploadValidator {
    /// Start from the header's `pack_id` and `total_bytes`.
    ///
    /// # Errors
    /// [`UploadError::BadPackId`], [`UploadError::TotalMissing`] or
    /// [`UploadError::TotalTooLarge`].
    pub(crate) fn new(
        pack_id: Option<&[u8]>,
        total_bytes: Option<u64>,
        limits: UploadLimits,
    ) -> Result<Self, UploadError> {
        let key = pack_key(pack_id)?;
        let declared = total_bytes.ok_or(UploadError::TotalMissing)?;
        if declared > limits.max_total_bytes {
            return Err(UploadError::TotalTooLarge);
        }
        Ok(Self {
            key,
            declared,
            received: 0,
            chunks: 0,
            max_chunks: limits.max_chunks,
            complete: false,
            failed: None,
        })
    }

    /// Account for one chunk that carries `data_len` bytes.
    ///
    /// # Errors
    /// The first framing error. A failed chunk counts for nothing.
    pub(crate) fn push(
        &mut self,
        chunk_pack_id: Option<&[u8]>,
        offset: Option<u64>,
        data_len: usize,
        last: bool,
    ) -> Result<Progress, UploadError> {
        if let Some(err) = self.failed {
            return Err(err);
        }
        let result = self.accept(chunk_pack_id, offset, data_len, last);
        if let Err(err) = result {
            self.failed = Some(err);
        }
        result
    }

    fn accept(
        &mut self,
        chunk_pack_id: Option<&[u8]>,
        offset: Option<u64>,
        data_len: usize,
        last: bool,
    ) -> Result<Progress, UploadError> {
        if self.complete {
            return Err(UploadError::AfterLast);
        }
        self.chunks = self.chunks.saturating_add(1);
        if self.chunks > self.max_chunks {
            return Err(UploadError::TooManyChunks);
        }
        if pack_key(chunk_pack_id)? != self.key {
            return Err(UploadError::PackIdMismatch);
        }
        let offset = offset.ok_or(UploadError::OffsetMissing)?;
        if offset != self.received {
            return Err(UploadError::OffsetGap);
        }
        let received = u64::try_from(data_len)
            .ok()
            .and_then(|len| self.received.checked_add(len))
            .ok_or(UploadError::ByteCountOverflow)?;
        if received > self.declared {
            return Err(UploadError::Overrun);
        }
        if last && received != self.declared {
            return Err(UploadError::LengthMismatch);
        }
        self.received = received;
        self.complete = last;
        Ok(Progress { complete: last })
    }

    /// The pack id that the header declared.
    pub(crate) const fn key(&self) -> PackKey {
        self.key
    }
}

fn pack_key(id: Option<&[u8]>) -> Result<PackKey, UploadError> {
    let id = id.ok_or(UploadError::BadPackId(None))?;
    <[u8; 32]>::try_from(id)
        .map(PackKey::new)
        .map_err(|_| UploadError::BadPackId(Some(id.len())))
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIMITS: UploadLimits = UploadLimits {
        max_total_bytes: 100,
        max_chunks: 3,
    };
    const ID: [u8; 32] = [7; 32];

    fn validator(total: u64) -> UploadValidator {
        UploadValidator::new(Some(&ID), Some(total), LIMITS).unwrap()
    }

    #[test]
    fn header_errors() {
        let new = |id: Option<&[u8]>, total| UploadValidator::new(id, total, LIMITS).unwrap_err();
        assert_eq!(new(None, Some(1)), UploadError::BadPackId(None));
        assert_eq!(new(Some(&[1; 5]), Some(1)), UploadError::BadPackId(Some(5)));
        assert_eq!(new(Some(&ID), None), UploadError::TotalMissing);
        assert_eq!(new(Some(&ID), Some(101)), UploadError::TotalTooLarge);
        assert!(UploadValidator::new(Some(&ID), Some(100), LIMITS).is_ok());
    }

    #[test]
    fn contiguous_chunks_complete_at_the_declared_size() {
        let mut v = validator(10);
        assert!(!v.push(Some(&ID), Some(0), 4, false).unwrap().complete);
        assert!(v.push(Some(&ID), Some(4), 6, true).unwrap().complete);
        assert_eq!(v.key(), PackKey::new(ID));
    }

    #[test]
    fn an_empty_pack_is_one_empty_last_chunk() {
        let mut v = validator(0);
        assert!(v.push(Some(&ID), Some(0), 0, true).unwrap().complete);
    }

    #[test]
    fn chunk_errors() {
        let case = |chunk: (Option<&[u8]>, Option<u64>, usize, bool)| {
            validator(10)
                .push(chunk.0, chunk.1, chunk.2, chunk.3)
                .unwrap_err()
        };
        assert_eq!(
            case((None, Some(0), 1, false)),
            UploadError::BadPackId(None)
        );
        assert_eq!(
            case((Some(&[8; 32]), Some(0), 1, false)),
            UploadError::PackIdMismatch
        );
        assert_eq!(
            case((Some(&ID), None, 1, false)),
            UploadError::OffsetMissing
        );
        assert_eq!(case((Some(&ID), Some(1), 1, false)), UploadError::OffsetGap);
        assert_eq!(case((Some(&ID), Some(0), 11, true)), UploadError::Overrun);
        assert_eq!(
            case((Some(&ID), Some(0), 9, true)),
            UploadError::LengthMismatch
        );
    }

    #[test]
    fn the_chunk_cap_counts_the_last_chunk() {
        let mut v = validator(4);
        for i in 0..3 {
            v.push(Some(&ID), Some(i), 1, false).unwrap();
        }
        assert_eq!(
            v.push(Some(&ID), Some(3), 1, true).unwrap_err(),
            UploadError::TooManyChunks
        );
    }

    #[test]
    fn a_chunk_after_last_is_refused() {
        let mut v = validator(1);
        v.push(Some(&ID), Some(0), 1, true).unwrap();
        assert_eq!(
            v.push(Some(&ID), Some(1), 0, true).unwrap_err(),
            UploadError::AfterLast
        );
    }

    #[test]
    fn a_dead_stream_keeps_its_first_error() {
        let mut v = validator(10);
        let first = v.push(Some(&ID), Some(5), 1, false).unwrap_err();
        assert_eq!(first, UploadError::OffsetGap);
        assert_eq!(v.push(Some(&ID), Some(0), 1, false).unwrap_err(), first);
    }

    #[test]
    fn a_failed_chunk_counts_for_nothing() {
        let mut v = validator(10);
        let _ = v.push(Some(&ID), Some(0), 11, false);
        assert_eq!(v.received, 0);
    }
}
