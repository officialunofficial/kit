//! Plain-blob attestation packs. Entries yielded by [`read`] are provisional
//! until it succeeds: a sink must stage them until the key and trailer pass.
//! This module never writes objects or decides signature trust. Compressed
//! entries require `kit-core/pack-zstd`, enabled by the native kit binaries.
//! Builds without that feature reject compressed entries.

use crate::{envelope, store::MAX_ENVELOPE_SIZE, verify::extract_primary_commit_hash};
use kit_core::{
    hash::{self, Hash},
    object::{Blob, Object},
    pack::{DecodeLimits, NoExternalBases, PackWriter, decode_frame_with},
    serialize,
};
use std::io::Read;

/// Canonical blob bytes decoded per pack, including ten-byte blob headers.
pub const MAX_PACK_DECODED_BYTES: u64 = 64 * 1024 * 1024;
/// Canonical blob bytes decoded during a complete attestation fetch.
pub const MAX_FETCH_DECODED_BYTES: u64 = 512 * 1024 * 1024;

/// Shared across every pack of one fetch, including rejected packs.
/// Charges are checked before allocation and never refunded on failure.
#[derive(Debug)]
pub struct DecodeBudget {
    remaining: u64,
    pack_limit: u64,
}
impl Default for DecodeBudget {
    fn default() -> Self {
        Self {
            remaining: MAX_FETCH_DECODED_BYTES,
            pack_limit: MAX_PACK_DECODED_BYTES,
        }
    }
}
impl DecodeBudget {
    /// A stricter fetch allowance; values above the default cannot raise it.
    /// The starting allowance also caps a pack, so a larger pack is rejected
    /// rather than deferred on every fresh fetch.
    #[must_use]
    pub const fn new(bytes: u64) -> Self {
        Self {
            pack_limit: if bytes < MAX_PACK_DECODED_BYTES {
                bytes
            } else {
                MAX_PACK_DECODED_BYTES
            },
            remaining: if bytes < MAX_FETCH_DECODED_BYTES {
                bytes
            } else {
                MAX_FETCH_DECODED_BYTES
            },
        }
    }
    /// Unspent canonical-byte allowance.
    #[must_use]
    pub const fn remaining(&self) -> u64 {
        self.remaining
    }
}

/// Attestation pack failures, independent of the envelope API's error enum.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PackError {
    /// Stop the attestation fetch without marking the deferred pack processed.
    #[error("attestation fetch decoded-byte budget exhausted")]
    FetchBudget,
    /// A bound, framing rule, object kind, or digest did not match.
    #[error("invalid attestation pack: {0}")]
    Invalid(&'static str),
    /// The input stopped or could not be read.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// Canonical pack or object decoding failed.
    #[error(transparent)]
    Pack(#[from] kit_core::pack::PackError),
    /// Envelope or statement decoding failed.
    #[error(transparent)]
    Envelope(#[from] crate::Error),
}

fn subject(bytes: &[u8]) -> Result<Hash, PackError> {
    let env = envelope::decode_expecting(bytes, envelope::PAYLOAD_TYPE_IN_TOTO)?;
    let value: serde_json::Value =
        serde_json::from_slice(&env.payload).map_err(|_| PackError::Invalid("statement JSON"))?;
    if value.get("_type").and_then(serde_json::Value::as_str) != Some(crate::IN_TOTO_TYPE)
        || value
            .get("predicateType")
            .and_then(serde_json::Value::as_str)
            .is_none()
        || !value
            .get("predicate")
            .is_some_and(serde_json::Value::is_object)
    {
        return Err(PackError::Invalid("in-toto statement"));
    }
    Ok(extract_primary_commit_hash(&env.payload)?)
}

/// Build a deterministic raw-only pack of strict in-toto envelopes.
/// `max_bytes` is the remote's pack cap; split candidates before calling this.
///
/// # Errors
/// Invalid envelopes, oversized output, or pack encoding failures.
pub fn build(envelopes: &[&[u8]], max_bytes: u64) -> Result<Vec<u8>, PackError> {
    let mut writer = PackWriter::new_raw_only();
    let mut size = 44u64;
    let mut decoded = 0u64;
    for bytes in envelopes {
        subject(bytes)?;
        size = size
            .checked_add(bytes.len() as u64 + 15)
            .ok_or(PackError::Invalid("pack length"))?;
        decoded += bytes.len() as u64 + 10;
        if size > max_bytes || decoded > MAX_PACK_DECODED_BYTES {
            return Err(PackError::Invalid("pack cap"));
        }
        let raw = serialize::serialize(&Object::Blob(Blob {
            data: bytes.to_vec(),
        }))
        .map_err(|_| PackError::Invalid("blob encoding"))?;
        writer.push_raw(hash::hash(&raw), &raw)?;
    }
    if size > max_bytes {
        return Err(PackError::Invalid("pack cap"));
    }
    Ok(writer.finish()?)
}

/// Stream a pack, retaining only one bounded frame and decoded envelope.
/// Check the declared length against `max_bytes` before reading any byte.
/// The sink receives `(subject, attestation_id, canonical_envelope)` and must
/// discard all staged entries on error. Pass the same budget to every pack in
/// a fetch; rejected packs consume the allowance too. It checks local subject presence and
/// saves under its worktree lock only after success. No signatures are trusted.
///
/// # Errors
/// Wrong length, key, trailer, type, size, canonical encoding, or input I/O.
#[allow(clippy::too_many_lines)]
pub fn read(
    input: &mut impl Read,
    declared_len: u64,
    max_bytes: u64,
    expected_key: Hash,
    budget: &mut DecodeBudget,
    mut sink: impl FnMut(Hash, Hash, &[u8]),
) -> Result<(), PackError> {
    let pack_limit = budget.pack_limit;
    read_capped(
        input,
        declared_len,
        max_bytes,
        expected_key,
        budget,
        pack_limit,
        &mut sink,
    )
}

#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
fn read_capped(
    input: &mut impl Read,
    declared_len: u64,
    max_bytes: u64,
    expected_key: Hash,
    budget: &mut DecodeBudget,
    pack_limit: u64,
    sink: &mut impl FnMut(Hash, Hash, &[u8]),
) -> Result<(), PackError> {
    if declared_len < 44 || declared_len > max_bytes {
        return Err(PackError::Invalid("pack length"));
    }
    let mut full = blake3::Hasher::new();
    let mut prefix = blake3::Hasher::new();
    let mut header = [0u8; 12];
    input.read_exact(&mut header)?;
    full.update(&header);
    prefix.update(&header);
    let number = |b: &[u8]| u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    let version = number(&header[4..8]);
    let count = number(&header[8..]);
    if &header[..4] != b"KIT\0"
        || !matches!(version, 1 | 2)
        || count > 10_000_000
        || u64::from(count) > (declared_len - 44) / 5
    {
        return Err(PackError::Invalid("header"));
    }
    let mut remaining = declared_len - 44;
    let mut payload_total = 0u64;
    let mut decoded_total = 0u64;
    for _ in 0..count {
        if remaining < 5 {
            return Err(PackError::Invalid("frame length"));
        }
        let mut frame_header = [0u8; 5];
        input.read_exact(&mut frame_header)?;
        let kind = frame_header[0];
        let len = u64::from(number(&frame_header[1..]));
        if kind != 0 && !(kind == 3 && version == 2) {
            return Err(PackError::Invalid("non-raw entry"));
        }
        remaining -= 5;
        charge_wire_payload(&mut payload_total, len)?;
        // The compressed wire bound is ZSTD_COMPRESSBOUND of the maximum
        // canonical blob, plus its four-byte claim. Check before allocation.
        let canonical_max = MAX_ENVELOPE_SIZE as u64 + 10;
        let wire_max = if kind == 0 {
            canonical_max
        } else {
            canonical_max + (canonical_max >> 8) + 4
        };
        if len > remaining || len > wire_max {
            return Err(PackError::Invalid("frame cap"));
        }
        let mut claim = [0u8; 4];
        if kind == 3 {
            if len < 4 {
                return Err(PackError::Invalid("compressed header"));
            }
            input.read_exact(&mut claim)?;
            if u64::from(number(&claim)) > canonical_max {
                return Err(PackError::Invalid("decoded cap"));
            }
        }
        let decoded_len = if kind == 0 {
            len
        } else {
            u64::from(number(&claim))
        };
        decoded_total += decoded_len;
        if decoded_total > pack_limit {
            return Err(PackError::Invalid("pack decoded budget"));
        }
        budget.remaining = budget
            .remaining
            .checked_sub(decoded_len)
            .ok_or(PackError::FetchBudget)?;
        let frame_len = usize::try_from(len + 5).map_err(|_| PackError::Invalid("frame cap"))?;
        let mut frame = Vec::with_capacity(frame_len);
        frame.extend_from_slice(&frame_header);
        if kind == 3 {
            frame.extend_from_slice(&claim);
        }
        frame.resize(frame_len, 0);
        let start = if kind == 3 { 9 } else { 5 };
        input.read_exact(&mut frame[start..])?;
        full.update(&frame);
        prefix.update(&frame);
        remaining -= len;
        let (_, raw) = decode_frame_with(
            &frame,
            version,
            &mut NoExternalBases,
            DecodeLimits::default().with_max_decoded_bytes(canonical_max),
        )?;
        // Decode has already checked the canonical object bytes. Avoid a
        // second owned Blob copy; its ten-byte header precedes the content.
        if raw.first() != Some(&1) {
            return Err(PackError::Invalid("non-blob object"));
        }
        let bytes = raw.get(10..).ok_or(PackError::Invalid("blob header"))?;
        let bound = subject(bytes)?;
        sink(bound, envelope::attestation_id(bytes), bytes);
    }
    if remaining != 0 {
        return Err(PackError::Invalid("trailing entries"));
    }
    let mut trailer = [0u8; 32];
    input.read_exact(&mut trailer)?;
    full.update(&trailer);
    if prefix.finalize().as_bytes() != &trailer || full.finalize().as_bytes() != &expected_key {
        return Err(PackError::Invalid("digest"));
    }
    let mut extra = [0u8; 1];
    if input.read(&mut extra)? != 0 {
        return Err(PackError::Invalid("trailing bytes"));
    }
    Ok(())
}

// Keep cumulative wire accounting separate so its 4 GiB boundary can be
// exercised without decoding a multi-gigabyte pack.
fn charge_wire_payload(total: &mut u64, len: u64) -> Result<(), PackError> {
    *total += len;
    if *total > 1u64 << 32 {
        return Err(PackError::Invalid("frame cap"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wire_payload_cap_is_inclusive_and_accumulates_each_frame() {
        let mut total = 0;
        charge_wire_payload(&mut total, 17).unwrap();
        charge_wire_payload(&mut total, 23).unwrap();
        assert_eq!(total, 40);
        total = u64::from(u32::MAX);
        charge_wire_payload(&mut total, 1).unwrap();
        assert_eq!(total, 1u64 << 32);
        assert!(matches!(
            charge_wire_payload(&mut total, 1),
            Err(PackError::Invalid("frame cap"))
        ));
    }

    #[test]
    fn decoded_budgets_stop_before_the_next_frame_is_decoded() {
        let envelope = include_bytes!("../../../tests/golden/attest/envelope_basic.json");
        let pack = build(&[envelope, envelope], 4096).unwrap();
        let size = envelope.len() as u64 + 10;
        let mut budget = DecodeBudget {
            remaining: size,
            ..DecodeBudget::default()
        };
        let mut seen = 0;
        assert!(
            read(
                &mut pack.as_slice(),
                pack.len() as u64,
                4096,
                hash::hash(&pack),
                &mut budget,
                |_, _, _| seen += 1
            )
            .is_err()
        );
        assert_eq!(seen, 1);
        assert_eq!(budget.remaining, 0);
        let mut budget = DecodeBudget::default();
        let mut seen = 0;
        assert!(
            read_capped(
                &mut pack.as_slice(),
                pack.len() as u64,
                4096,
                hash::hash(&pack),
                &mut budget,
                size,
                &mut |_, _, _| seen += 1
            )
            .is_err()
        );
        assert_eq!(seen, 1);
    }

    #[test]
    fn fetch_budget_is_shared_across_packs_and_corrupt_trailers() {
        let envelope = include_bytes!("../../../tests/golden/attest/envelope_basic.json");
        let mut pack = build(&[envelope], 4096).unwrap();
        let size = envelope.len() as u64 + 10;
        let mut budget = DecodeBudget {
            remaining: size * 2 - 1,
            ..DecodeBudget::default()
        };
        assert!(
            read(
                &mut pack.as_slice(),
                pack.len() as u64,
                4096,
                hash::hash(&pack),
                &mut budget,
                |_, _, _| {}
            )
            .is_ok()
        );
        assert!(matches!(
            read(
                &mut pack.as_slice(),
                pack.len() as u64,
                4096,
                hash::hash(&pack),
                &mut budget,
                |_, _, _| {}
            ),
            Err(PackError::FetchBudget)
        ));
        let last = pack.len() - 1;
        pack[last] ^= 1;
        let mut budget = DecodeBudget {
            remaining: size,
            ..DecodeBudget::default()
        };
        assert!(
            read(
                &mut pack.as_slice(),
                pack.len() as u64,
                4096,
                hash::hash(&pack),
                &mut budget,
                |_, _, _| {}
            )
            .is_err()
        );
        assert_eq!(budget.remaining, 0);
    }

    #[test]
    fn compressed_claim_is_charged_before_inflation_and_failures_keep_the_charge() {
        let mut bytes = b"KIT\0".to_vec();
        bytes.extend(2u32.to_le_bytes());
        bytes.extend(1u32.to_le_bytes());
        bytes.push(3);
        bytes.extend(4u32.to_le_bytes());
        bytes.extend(100u32.to_le_bytes());
        let mut budget = DecodeBudget {
            remaining: 99,
            ..DecodeBudget::default()
        };
        let err = read(
            &mut bytes.as_slice(),
            100,
            100,
            [0; 32],
            &mut budget,
            |_, _, _| {},
        )
        .unwrap_err();
        assert!(matches!(err, PackError::FetchBudget));
        assert_eq!(budget.remaining, 99);
        budget.remaining = 100;
        assert!(
            read(
                &mut bytes.as_slice(),
                100,
                100,
                [0; 32],
                &mut budget,
                |_, _, _| {}
            )
            .is_err()
        );
        assert_eq!(budget.remaining, 0);
    }
}
