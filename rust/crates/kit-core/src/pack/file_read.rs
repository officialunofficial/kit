//! Unpacking a [`VerifiedPack`] from its file, one window at a time
//! (SPEC-PACKFILE §11, "Unpacking from a file").
//!
//! The reader never holds the whole pack. Step 1 scans the frame headers
//! through a small buffer and refuses an oversized frame from its header,
//! having read at most one scan buffer of its payload. It keeps only where each window of entries
//! starts and ends. Steps 2 and 3 then run per window: read the window's
//! frames into one buffer, stage and commit them, and drop every decoded
//! byte before the next window. A delta whose base an earlier window stored
//! reads that base back from the store.
//!
//! Memory is bounded by constants, not by the pack's length: a window of at
//! most [`STAGE_WINDOW_BYTES`] (or one frame of at most [`MAX_FRAME_PAYLOAD`]),
//! the per-entry charge [`PACK_ENTRY_READ_COST`], the per-window state, and
//! one entry's decode at a time ([`RESIDENT_ENTRY_MAX`]).

use super::spool::VerifiedPack;
use super::window::WindowSource;
use super::{
    BaseUses, DELTA_BASE_LEN, EMPTY_PACK_LEN, ENTRY_FRAME_LEN, EncodedPayload, Entry, HEADER_LEN,
    FetchDecodeBudget, MAGIC, MAX_ENTRIES, MAX_RAW_OBJECT_SIZE, MAX_TOTAL_PAYLOAD, MEMORY_FLOOR,
    PACK_ENTRY_RESIDENT_COST, PackError, PackReader, ResidentBudget, STAGE_WINDOW, TRAILER_LEN,
    UnpackReport, VERSION, VERSION_V2, ZSTD_LEN_PREFIX, decoded_bytes_cap, encoded_payload,
    replay_window, stage_raw_entries, zstd_entry_len,
};
use super::{DeltaBaseSource, ObjectSpool, UnpackSink};
use crate::store::ObjectStore;
use std::collections::HashMap;
use std::io::{BufReader, Read};
use std::sync::atomic::AtomicU64;

/// Wire bytes of frames that the file-backed reader holds in one window,
/// beside the 65,536 entries a window holds at most. A frame
/// larger than this gets a window of its own.
pub const STAGE_WINDOW_BYTES: u64 = 64 << 20;

/// Bytes the file-backed reader charges per pack entry for the whole read,
/// before it allocates anything: what an entry costs beyond its window's
/// state, the list of signed objects included. Measured at up to about 286
/// bytes on the 0.8 reader's worst shape (deltas on in-pack bases), so the
/// charge keeps some headroom. A test that counts the real peak heap use
/// pins it.
pub const PACK_ENTRY_READ_COST: usize = 320;

/// The largest single entry any reader admits: a 1 GiB base, a 1 GiB
/// decoded zstd delta stream and a 1 GiB target. It caps the decoded share
/// of the file-backed reader's budget.
pub const RESIDENT_ENTRY_MAX: u64 = 3 * MAX_RAW_OBJECT_SIZE as u64;

/// The zstd compress bound of `len` bytes, as `ZSTD_COMPRESSBOUND` defines it.
const fn zstd_compress_bound(len: u64) -> u64 {
    let small = if len < (128 << 10) {
        ((128 << 10) - len) >> 11
    } else {
        0
    };
    len + (len >> 8) + small
}

/// The largest payload of a raw (`0x00`) frame: the largest object.
pub const MAX_RAW_FRAME_PAYLOAD: u64 = MAX_RAW_OBJECT_SIZE as u64;

/// The largest payload of any frame: a zstd (`0x03`, `0x04`) or delta
/// (`0x02`) frame, which is at most the zstd compress bound of the largest
/// object plus the 32-byte base and the length prefix. No writer emits more:
/// a writer keeps a frame only when it is smaller than the object, and a delta
/// only when it is smaller than its target.
pub const MAX_FRAME_PAYLOAD: u64 = zstd_compress_bound(MAX_RAW_OBJECT_SIZE as u64)
    + DELTA_BASE_LEN as u64
    + ZSTD_LEN_PREFIX as u64;

/// The largest payload a frame of type `etype` may carry: a writer refuses to
/// emit more, and the file-backed reader refuses more from the frame header.
#[must_use]
pub const fn max_frame_payload(etype: u8) -> u64 {
    if etype == 0x00 {
        MAX_RAW_FRAME_PAYLOAD
    } else {
        MAX_FRAME_PAYLOAD
    }
}

/// The most the file-backed reader admits for any pack read from a store
/// whose path is short: [`PACK_ENTRY_READ_COST`] for each of [`MAX_ENTRIES`]
/// entries, [`PACK_ENTRY_RESIDENT_COST`] for each slot of one window, and the
/// decoded share of at most [`RESIDENT_ENTRY_MAX`]. About 6.04 GiB. Each
/// window slot adds 2 bytes per character of the store's path.
pub const UNPACK_MEMORY_CAP: u64 = PACK_ENTRY_READ_COST as u64 * MAX_ENTRIES as u64
    + PACK_ENTRY_RESIDENT_COST as u64 * STAGE_WINDOW as u64
    + RESIDENT_ENTRY_MAX;

/// The bytes a window of payloads may hold: [`STAGE_WINDOW_BYTES`], or one
/// frame of the largest payload.
const WINDOW_CAP: u64 = if STAGE_WINDOW_BYTES > MAX_FRAME_PAYLOAD + ENTRY_FRAME_LEN as u64 {
    STAGE_WINDOW_BYTES
} else {
    MAX_FRAME_PAYLOAD + ENTRY_FRAME_LEN as u64
};

/// Buffer of the header scan. A skip past the buffer discards it, so the
/// next frame header costs one read of this size: small enough that the scan
/// of a pack of 64 KiB frames reads a sixteenth of it, large enough that a
/// buffer holds about a hundred small frames.
pub(super) const SCAN_BUFFER: usize = 4 << 10;

/// The decoded bytes the file-backed reader holds at once for a pack of
/// `pack_len` bytes: `max(2 GiB, 16 × pack_len)` like the slice reader's whole
/// cap, but at most [`RESIDENT_ENTRY_MAX`]. The entries are charged apart.
pub(super) fn decoded_share(pack_len: u64) -> u64 {
    (MEMORY_FLOOR as u64)
        .max(pack_len.saturating_mul(16))
        .min(RESIDENT_ENTRY_MAX)
}

/// The bookkeeping the file-backed reader charges for a pack of `entries`
/// entries read into a store whose path is `path_len` characters long:
/// [`PACK_ENTRY_READ_COST`] per entry, and per window slot
/// [`PACK_ENTRY_RESIDENT_COST`] plus 2 bytes per path character.
pub(super) fn bookkeeping(entries: usize, path_len: usize) -> Option<usize> {
    let slot = PACK_ENTRY_RESIDENT_COST.checked_add(path_len.checked_mul(2)?)?;
    PACK_ENTRY_READ_COST
        .checked_mul(entries)?
        .checked_add(slot.checked_mul(entries.min(STAGE_WINDOW))?)
}

/// The budget of one file-backed read: the bookkeeping, reserved before any
/// of it is allocated, plus the decoded share. `decoded_cap` bounds the
/// decoded bytes the whole read may charge.
pub(super) fn file_budget(
    pack_len: u64,
    entries: usize,
    path_len: usize,
    owned_bytes: Option<&AtomicU64>,
    decoded_cap: u64,
) -> Result<ResidentBudget<'_>, PackError> {
    let book = bookkeeping(entries, path_len).ok_or(PackError::PackfileTooLarge)?;
    let share =
        usize::try_from(decoded_share(pack_len)).map_err(|_| PackError::PackfileTooLarge)?;
    let cap = book.checked_add(share).ok_or(PackError::PackfileTooLarge)?;
    let budget = ResidentBudget::new(cap, owned_bytes).with_decoded_cap(decoded_cap);
    budget.reserve_bookkeeping(book)?;
    Ok(budget)
}

/// How a read cuts the pack into windows. Tests use small ones.
#[derive(Debug, Clone, Copy)]
pub(super) struct WindowShape {
    pub(super) entries: usize,
    pub(super) bytes: u64,
}

impl WindowShape {
    pub(super) const DEFAULT: Self = Self {
        entries: STAGE_WINDOW,
        bytes: STAGE_WINDOW_BYTES,
    };
}

/// One window of entries: where its frames start and end in the pack.
#[derive(Debug, Clone, Copy)]
struct Span {
    start: u64,
    end: u64,
    entries: u32,
}

/// A sequential reader over a verified pack's bytes from `pos`.
struct Cursor<'a> {
    pack: &'a VerifiedPack,
    pos: u64,
}

impl Read for Cursor<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let left = self.pack.len().saturating_sub(self.pos);
        let n = usize::try_from(left).map_or(buf.len(), |left| left.min(buf.len()));
        if n == 0 {
            return Ok(0);
        }
        self.pack.read_at(self.pos, &mut buf[..n])?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl std::io::Seek for Cursor<'_> {
    fn seek(&mut self, to: std::io::SeekFrom) -> std::io::Result<u64> {
        let pos = match to {
            std::io::SeekFrom::Start(pos) => Some(pos),
            std::io::SeekFrom::Current(by) => self.pos.checked_add_signed(by),
            std::io::SeekFrom::End(by) => self.pack.len().checked_add_signed(by),
        };
        self.pos = pos.ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
        Ok(self.pos)
    }
}

/// Read errors from the header scan: a short read is a framing error.
fn scan_error(error: std::io::Error) -> PackError {
    if error.kind() == std::io::ErrorKind::UnexpectedEof {
        PackError::UnexpectedEof
    } else {
        PackError::Io(error)
    }
}

/// The header checks of SPEC-PACKFILE §1 and §5 without the trailer, which
/// the spool already checked: magic, version, at most [`MAX_ENTRIES`]
/// entries, and at most one entry per [`ENTRY_FRAME_LEN`] body bytes, so a
/// small file cannot claim millions of entries. Returns the version and the
/// entry count.
fn read_header(pack: &VerifiedPack) -> Result<(u32, u32), PackError> {
    let len = pack.len();
    if len < EMPTY_PACK_LEN as u64 {
        return Err(PackError::PackfileTooShort);
    }
    let mut header = [0u8; HEADER_LEN];
    pack.read_at(0, &mut header).map_err(scan_error)?;
    if &header[..4] != MAGIC.as_slice() {
        return Err(PackError::InvalidMagic);
    }
    let version = u32::from_le_bytes(header[4..8].try_into().expect("4 bytes"));
    if version != VERSION && version != VERSION_V2 {
        return Err(PackError::UnsupportedVersion(version));
    }
    let count = u32::from_le_bytes(header[8..12].try_into().expect("4 bytes"));
    if count > MAX_ENTRIES {
        return Err(PackError::TooManyObjects(count));
    }
    let body_after_header = len - EMPTY_PACK_LEN as u64;
    if u64::from(count) * ENTRY_FRAME_LEN as u64 > body_after_header {
        return Err(PackError::TooManyObjects(count));
    }
    Ok((version, count))
}

/// Step 1: walk the frame headers of `count` entries in order and cut them
/// into windows. Each frame is checked from its header alone: its type, its
/// payload against [`max_frame_payload`] and the payload sum against
/// [`MAX_TOTAL_PAYLOAD`], and its end against the trailer. The scan skips
/// each payload: it reads at most one [`SCAN_BUFFER`] past a frame header.
fn scan_frames(
    pack: &VerifiedPack,
    version: u32,
    count: u32,
    shape: WindowShape,
) -> Result<Vec<Span>, PackError> {
    let split = pack.len() - TRAILER_LEN as u64;
    let mut reader = BufReader::with_capacity(
        SCAN_BUFFER,
        Cursor {
            pack,
            pos: HEADER_LEN as u64,
        },
    );
    let mut windows = Vec::new();
    let mut pos = HEADER_LEN as u64;
    let mut current = Span {
        start: pos,
        end: pos,
        entries: 0,
    };
    let mut total_payload: u64 = 0;
    for _ in 0..count {
        if split - pos < ENTRY_FRAME_LEN as u64 {
            return Err(PackError::UnexpectedEof);
        }
        let mut frame = [0u8; ENTRY_FRAME_LEN];
        reader.read_exact(&mut frame).map_err(scan_error)?;
        let etype = frame[0];
        let payload_len = u64::from(u32::from_le_bytes(frame[1..5].try_into().expect("4 bytes")));
        total_payload = total_payload.saturating_add(payload_len);
        if total_payload > MAX_TOTAL_PAYLOAD {
            return Err(PackError::PackfileTooLarge);
        }
        match etype {
            0x00 | 0x02 => {}
            0x03 | 0x04 if version == VERSION_V2 => {}
            other => return Err(PackError::InvalidEntryType(other)),
        }
        if payload_len > max_frame_payload(etype) {
            return Err(PackError::PackfileTooLarge);
        }
        if payload_len > split - pos - ENTRY_FRAME_LEN as u64 {
            return Err(PackError::UnexpectedEof);
        }
        if (etype == 0x02 || etype == 0x04) && payload_len < DELTA_BASE_LEN as u64 {
            return Err(PackError::DeltaEntryTruncated);
        }
        let frame_len = ENTRY_FRAME_LEN as u64 + payload_len;
        if current.entries > 0
            && (current.entries as usize >= shape.entries
                || current.end - current.start + frame_len > shape.bytes)
        {
            windows.push(current);
            current = Span {
                start: pos,
                end: pos,
                entries: 0,
            };
        }
        current.end += frame_len;
        current.entries += 1;
        reader
            .seek_relative(i64::try_from(payload_len).expect("a payload length fits i64"))
            .map_err(scan_error)?;
        pos += frame_len;
    }
    if current.entries > 0 {
        windows.push(current);
    }
    if pos != split {
        return Err(PackError::TrailingData);
    }
    Ok(windows)
}

/// The entries of one window, parsed from its bytes. Step 1 checked their
/// framing, so a mismatch here means the file changed under the reader.
fn window_entries(bytes: &[u8], version: u32, count: u32) -> Result<Vec<Entry<'_>>, PackError> {
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(count as usize)
        .map_err(|_| PackError::PackfileTooLarge)?;
    let mut at = 0usize;
    for _ in 0..count {
        let frame = bytes
            .get(at..at + ENTRY_FRAME_LEN)
            .ok_or(PackError::PackfileCorrupted)?;
        let payload_len = u32::from_le_bytes(frame[1..5].try_into().expect("4 bytes")) as usize;
        let start = at + ENTRY_FRAME_LEN;
        let payload = bytes
            .get(start..start + payload_len)
            .ok_or(PackError::PackfileCorrupted)?;
        entries.push(encoded_payload(frame[0], version, payload)?);
        at = start + payload_len;
    }
    if at != bytes.len() {
        return Err(PackError::PackfileCorrupted);
    }
    Ok(entries)
}

/// What a read reports to a test after each window commits: the decoded
/// bytes still charged once the window's buffers are gone.
#[cfg(test)]
pub(super) type BoundaryHook<'h> = &'h mut dyn FnMut(usize);

impl PackReader {
    /// Unpack a pack that a [`super::PackSpool`] verified into `store`, reading
    /// it from its file one window at a time. Returns the counts of raw and
    /// delta entries and the signed objects stored; [`UnpackReport::stored`]
    /// stays empty.
    ///
    /// The trailer is not hashed again: the spool checked it with the key.
    /// The header, the framing and every entry are checked as
    /// [`Self::read`] checks them, and an oversized frame is refused from its
    /// header ([`max_frame_payload`]). Memory does not grow with the pack's
    /// length: see the module docs.
    ///
    /// # Errors
    ///
    /// The [`PackError`] variants of [`Self::read`] for a malformed pack,
    /// [`PackError::PackfileTooLarge`] past a limit, and [`PackError::Io`]
    /// when the file cannot be read. A failure leaves the windows committed
    /// before it in the store; they hold verified objects.
    pub fn read_verified(
        pack: &VerifiedPack,
        store: &ObjectStore,
    ) -> Result<UnpackReport, PackError> {
        read_file(
            pack,
            store,
            WindowShape::DEFAULT,
            None,
            #[cfg(test)]
            None,
        )
    }

    /// Decode a verified wire pack into private staging. Earlier objects
    /// in this pack and in the pending publication windows (the open one and any
    /// still sealing) can be bases. What the pack decodes counts against
    /// `fetch`, which spans every pack of the fetch.
    ///
    /// # Errors
    /// The same decode errors as `read_verified`, or a local spool failure.
    #[doc(hidden)]
    pub fn stage_verified(
        pack: &VerifiedPack,
        store: &ObjectStore,
        pending: &[&ObjectSpool],
        spool: &ObjectSpool,
        fetch: &mut FetchDecodeBudget,
    ) -> Result<UnpackReport, PackError> {
        decode_file(
            pack,
            store,
            WindowShape::DEFAULT,
            None,
            Some((pending, spool)),
            Some(fetch),
            #[cfg(test)]
            None,
        )
    }
}

pub(super) fn read_file(
    pack: &VerifiedPack,
    store: &ObjectStore,
    shape: WindowShape,
    owned_bytes: Option<&AtomicU64>,
    #[cfg(test)] boundary: Option<BoundaryHook<'_>>,
) -> Result<UnpackReport, PackError> {
    decode_file(
        pack,
        store,
        shape,
        owned_bytes,
        None,
        None,
        #[cfg(test)]
        boundary,
    )
}

/// Read `pack` window by window. With a `fetch` budget, the pack's decoded
/// cap is what the fetch has left, and what the pack decodes, a failed pack
/// included, comes off it.
pub(super) fn decode_file(
    pack: &VerifiedPack,
    store: &ObjectStore,
    shape: WindowShape,
    owned_bytes: Option<&AtomicU64>,
    staging: Option<(&[&ObjectSpool], &ObjectSpool)>,
    mut fetch: Option<&mut FetchDecodeBudget>,
    #[cfg(test)] boundary: Option<BoundaryHook<'_>>,
) -> Result<UnpackReport, PackError> {
    let (version, count) = read_header(pack)?;
    let decoded_cap = match fetch.as_deref_mut() {
        Some(fetch) => fetch.admit(pack.len()),
        None => decoded_bytes_cap(usize::try_from(pack.len()).unwrap_or(usize::MAX)),
    };
    let budget = file_budget(
        pack.len(),
        count as usize,
        store.objects_root_len(),
        owned_bytes,
        decoded_cap,
    )?;
    let result = decode_windows(
        pack,
        store,
        (version, count, shape),
        staging,
        &budget,
        #[cfg(test)]
        boundary,
    );
    if let Some(fetch) = fetch {
        fetch.settle(budget.decoded_so_far());
    }
    result
}

fn decode_windows(
    pack: &VerifiedPack,
    store: &ObjectStore,
    (version, count, shape): (u32, u32, WindowShape),
    staging: Option<(&[&ObjectSpool], &ObjectSpool)>,
    budget: &ResidentBudget<'_>,
    #[cfg(test)] mut boundary: Option<BoundaryHook<'_>>,
) -> Result<UnpackReport, PackError> {
    let windows = scan_frames(pack, version, count, shape)?;
    let mut report = UnpackReport::default();
    report
        .signed
        .try_reserve_exact(count as usize)
        .map_err(|_| PackError::PackfileTooLarge)?;

    let mut first_position = 0usize;
    for span in windows {
        let window_len = span.end - span.start;
        if window_len > WINDOW_CAP {
            return Err(PackError::PackfileTooLarge);
        }
        let bytes = (&*pack).read_window(span.start, window_len)?;
        let frames = window_entries(&bytes, version, span.entries)?;
        // The decoded bytes of the window's compressed entries are charged
        // before any of them is decompressed.
        let mut uses: HashMap<_, BaseUses> = HashMap::new();
        for (offset, entry) in frames.iter().enumerate() {
            match *entry {
                Entry::Raw(EncodedPayload::Zstd(payload))
                | Entry::Delta {
                    stream: EncodedPayload::Zstd(payload),
                    ..
                } => budget.charge_decoded(zstd_entry_len(payload)?)?,
                Entry::Raw(EncodedPayload::Plain(_)) | Entry::Delta { .. } => {}
            }
            if let Entry::Delta { base, .. } = *entry {
                let usage = uses.entry(base).or_default();
                usage.remaining += 1;
                usage.last_position = first_position + offset;
            }
        }
        let batch = staging.is_none().then(|| store.batch());
        let sink: &dyn UnpackSink = match staging {
            Some((_, spool)) => spool,
            None => batch.as_ref().expect("direct write batch"),
        };
        let mut bases = FileBases {
            store,
            staging,
            first_position,
        };
        {
            // A base or target is kept only while a later entry of this
            // window names it: `uses` and `in_pack` are this window's.
            let raw_frames: Vec<_> = frames
                .iter()
                .enumerate()
                .filter_map(|(offset, entry)| match entry {
                    Entry::Raw(payload) => Some((first_position + offset, *payload)),
                    Entry::Delta { .. } => None,
                })
                .collect();
            let raw_results = stage_raw_entries(sink, &raw_frames, &uses, budget);
            let mut in_pack = HashMap::new();
            replay_window(
                &frames,
                first_position,
                raw_results,
                &mut uses,
                &mut in_pack,
                &mut report,
                budget,
                &mut bases,
                sink,
                false,
            )?;
        }
        #[cfg(test)]
        if let Some(hook) = boundary.as_mut() {
            hook(budget.used.load(std::sync::atomic::Ordering::Relaxed));
        }
        if let Some(batch) = batch {
            batch.commit()?;
        }
        first_position += span.entries as usize;
    }
    Ok(report)
}

/// Read a base from an earlier decode window, an earlier accepted wire pack
/// in the publication window, or the durable store, in that order.
struct FileBases<'a> {
    store: &'a ObjectStore,
    staging: Option<(&'a [&'a ObjectSpool], &'a ObjectSpool)>,
    first_position: usize,
}

impl DeltaBaseSource for FileBases<'_> {
    const VERIFIED: bool = true;

    fn base(&mut self, id: &crate::hash::Hash) -> Result<Option<Vec<u8>>, PackError> {
        self.base_with_retry_admission(id, |_| Ok(()))
    }

    fn base_with_retry_admission(
        &mut self,
        id: &crate::hash::Hash,
        mut admit: impl FnMut(usize) -> Result<(), PackError>,
    ) -> Result<Option<Vec<u8>>, PackError> {
        if let Some((pending, spool)) = self.staging {
            if let Some(bytes) = spool.read_before(id, self.first_position, &mut admit)? {
                return Ok(Some(bytes));
            }
            for pending in pending {
                if let Some(bytes) = pending.read_before(id, usize::MAX, &mut admit)? {
                    return Ok(Some(bytes));
                }
            }
        }
        self.store.base_with_retry_admission(id, admit)
    }
}
