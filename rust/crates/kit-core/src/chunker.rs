//! `FastCDC` content-defined chunker.
//!
//! Spec reference: `docs/specs/SPEC-FASTCDC.md`. Frozen v1 parameters:
//!
//! * Gear seed: ASCII `"KITFCDC"` interpreted as a big-endian `u64`
//!   (`0x004B_4954_4643_4443`). Splitmix64-derived 256-entry table.
//! * `MIN_SIZE = 16 KiB`, `AVG_SIZE = 64 KiB`, `MAX_SIZE = 256 KiB`.
//! * `MASK_S = 0x0001_FFFF` (strict, used while `i < AVG_SIZE`).
//! * `MASK   = 0x0000_FFFF` (informative; not used directly — we only
//!   need the strict and loose masks at runtime).
//! * `MASK_L = 0x0000_7FFF` (loose, used while `AVG_SIZE <= i < MAX_SIZE`).
//! * Rolling hash: `h = (h << 1) +% gear[byte]`. Cut when `(h & mask) == 0`,
//!   else force a cut at `MAX_SIZE`. Never cut before `MIN_SIZE`.
//!
//! The spec hard-codes the masks; we pin them as constants here so any
//! accidental change lights up in the golden tests immediately.
//!
//! All chunk boundaries are fully determined by the input bytes plus the
//! constants above. Any change breaks `chunked_blob` reproducibility
//! (see `SPEC-FASTCDC.md` §2 determinism contract).

/// Frozen splitmix64 seed for v1 — ASCII `"KITFCDC"` as big-endian u64.
///
/// The seed sets the chunk boundaries, so every chunked blob id depends on
/// it. Do not change it.
pub const SEED: u64 = 0x004B_4954_4643_4443;

/// Minimum chunk size (`16 KiB`). `cut` will not return a value below
/// this for non-final chunks.
pub const MIN_SIZE: usize = 0x4000;
/// Average target chunk size (`64 KiB`). The mask transition from strict
/// to loose happens here.
pub const AVG_SIZE: usize = 0x10000;
/// Maximum chunk size (`256 KiB`). `cut` always returns at most this.
pub const MAX_SIZE: usize = 0x40000;

/// Strict mask (used while `i < AVG_SIZE`). Fewer cuts → bias the chunker
/// toward `AVG_SIZE`.
pub const MASK_S: u64 = 0x0001_FFFF;
/// Loose mask (used while `AVG_SIZE <= i < MAX_SIZE`). More cuts → avoid
/// running into the `MAX_SIZE` forced boundary.
pub const MASK_L: u64 = 0x0000_7FFF;

/// 256-entry gear table, derived once at first use from [`SEED`] via
/// splitmix64. Wrapping arithmetic throughout — see SPEC-FASTCDC §3 for
/// the exact derivation.
fn gear_table() -> &'static [u64; 256] {
    use std::sync::OnceLock;
    static TABLE: OnceLock<[u64; 256]> = OnceLock::new();
    TABLE.get_or_init(build_gear_table)
}

fn build_gear_table() -> [u64; 256] {
    let mut state: u64 = SEED;
    let mut table = [0u64; 256];
    for entry in &mut table {
        // splitmix64 with the standard gamma. All ops are wrapping.
        state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^= z >> 31;
        *entry = z;
    }
    table
}

/// One chunk's position in the source buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkBoundary {
    pub offset: usize,
    pub length: usize,
}

/// `FastCDC` chunker parameters. Construct with [`FastCdc::v1`] for the
/// frozen v1 constants; other constructors exist mainly for tests that
/// exercise the algorithm at smaller sizes.
#[derive(Debug, Clone, Copy)]
pub struct FastCdc {
    min_size: usize,
    avg_size: usize,
    max_size: usize,
    mask_s: u64,
    mask_l: u64,
}

impl FastCdc {
    /// Construct the v1 chunker (`16 KiB / 64 KiB / 256 KiB`,
    /// strict/loose `0x0001_FFFF` / `0x0000_7FFF`).
    #[must_use]
    pub const fn v1() -> Self {
        Self {
            min_size: MIN_SIZE,
            avg_size: AVG_SIZE,
            max_size: MAX_SIZE,
            mask_s: MASK_S,
            mask_l: MASK_L,
        }
    }

    /// Construct a chunker with custom parameters. `avg_size` MUST be a
    /// power of two; the strict/loose masks are derived as
    /// `mask = (1 << log2(avg)) - 1; mask_s = mask | (mask << 1); mask_l = mask >> 1`.
    /// Returns [`crate::object::KitError::InvalidIdentity`] re-purposed as a generic
    /// "bad parameter" error if the constraints are violated — but in
    /// practice this constructor is only used by tests, where the inputs
    /// are constants, so we panic instead for a clearer failure mode.
    ///
    /// # Panics
    ///
    /// Panics if `min < avg < max` is not strictly satisfied or `avg` is
    /// not a power of two.
    #[must_use]
    pub fn custom(min: usize, avg: usize, max: usize) -> Self {
        assert!(min < avg && avg < max, "FastCdc: require min<avg<max");
        assert!(avg.is_power_of_two(), "FastCdc: avg must be a power of 2");
        let bits = avg.trailing_zeros();
        let mask: u64 = (1u64 << bits) - 1;
        Self {
            min_size: min,
            avg_size: avg,
            max_size: max,
            mask_s: mask | (mask << 1),
            mask_l: mask >> 1,
        }
    }

    #[must_use]
    pub const fn min_size(&self) -> usize {
        self.min_size
    }
    #[must_use]
    pub const fn avg_size(&self) -> usize {
        self.avg_size
    }
    #[must_use]
    pub const fn max_size(&self) -> usize {
        self.max_size
    }

    /// Find the cut point in `data`. Returns the length of the first
    /// chunk. Semantics:
    ///
    /// * `data.len() <= min_size` → returns `data.len()` (no early cut).
    /// * `min_size < i <= avg_size` → strict mask, fewer boundaries.
    /// * `avg_size < i <= max_size` → loose mask, more boundaries.
    /// * Otherwise → forced cut at `min(max_size, data.len())`.
    #[must_use]
    pub fn cut(&self, data: &[u8]) -> usize {
        if data.len() <= self.min_size {
            return data.len();
        }
        let table = gear_table();
        let mut hash: u64 = 0;
        let avg_end = self.avg_size.min(data.len());
        let mut i = self.min_size;
        while i < avg_end {
            hash = (hash << 1).wrapping_add(table[data[i] as usize]);
            if (hash & self.mask_s) == 0 {
                return i;
            }
            i += 1;
        }
        let max_end = self.max_size.min(data.len());
        while i < max_end {
            hash = (hash << 1).wrapping_add(table[data[i] as usize]);
            if (hash & self.mask_l) == 0 {
                return i;
            }
            i += 1;
        }
        max_end
    }
}

/// Iterator over chunk boundaries in a contiguous byte slice.
#[derive(Debug)]
pub struct ChunkIterator<'a> {
    cdc: FastCdc,
    data: &'a [u8],
    offset: usize,
}

impl<'a> ChunkIterator<'a> {
    #[must_use]
    pub fn new(cdc: FastCdc, data: &'a [u8]) -> Self {
        Self {
            cdc,
            data,
            offset: 0,
        }
    }
}

impl Iterator for ChunkIterator<'_> {
    type Item = ChunkBoundary;
    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.data.len() {
            return None;
        }
        let remaining = &self.data[self.offset..];
        let length = self.cdc.cut(remaining);
        let boundary = ChunkBoundary {
            offset: self.offset,
            length,
        };
        self.offset += length;
        Some(boundary)
    }
}

/// Bytes of input each worker thread cuts per round in [`FastCdc::cut_ends`].
/// A worker starts at an arbitrary offset inside the chain, so its first
/// cuts are usually wrong and are thrown away; the chain converges within
/// a chunk or two. At 2 MiB per worker that waste is a few percent of the
/// work. It also sets [`ChunkReader`]'s window: `threads * PARALLEL_SEGMENT`.
const PARALLEL_SEGMENT: usize = 2 * 1024 * 1024;

/// Upper bound on cutter threads. Caps [`ChunkReader`]'s window at
/// `MAX_CUT_THREADS * PARALLEL_SEGMENT` (16 MiB).
const MAX_CUT_THREADS: usize = 8;

/// Number of threads [`ChunkReader::new`] and [`FastCdc::chunk_ends`] cut
/// with: the available parallelism, capped at [`MAX_CUT_THREADS`]. Targets
/// without threads (wasm32) report no parallelism and get `1`.
fn cut_threads() -> usize {
    std::thread::available_parallelism()
        .map_or(1, std::num::NonZeroUsize::get)
        .min(MAX_CUT_THREADS)
}

impl FastCdc {
    /// Whether a cut started at `pos` in a `len`-byte buffer is final.
    /// [`FastCdc::cut`] reads at most `max_size` bytes, so the cut is final
    /// once `max_size` bytes are present or the input has ended.
    const fn cut_is_final(&self, len: usize, pos: usize, eof: bool) -> bool {
        pos < len && (eof || len - pos >= self.max_size)
    }

    /// Follow the cut chain from `from`, starting new cuts only below
    /// `stop`. Returns `from` followed by every chunk end.
    fn chain(&self, data: &[u8], from: usize, stop: usize, eof: bool) -> Vec<usize> {
        let mut ends = vec![from];
        let mut pos = from;
        while pos < stop && self.cut_is_final(data.len(), pos, eof) {
            pos += self.cut(&data[pos..]);
            ends.push(pos);
        }
        ends
    }

    /// Chunk end offsets of `data`, with the chain starting at offset `0`,
    /// split across `threads` threads. The result is identical to calling
    /// [`FastCdc::cut`] repeatedly from offset `0`.
    ///
    /// Each thread follows the chain from the start of its own segment.
    /// A single pass then walks the true chain. When a true cut lands on a
    /// position some thread also cut from, that thread's later cuts are
    /// the true cuts, because `cut` is a pure function of the bytes from
    /// that position. The pass computes the rest itself.
    ///
    /// Without `eof`, only final cuts are returned (see
    /// `FastCdc::cut_is_final`): the bytes after the last returned end
    /// belong to a chunk that may still grow.
    #[must_use]
    pub fn cut_ends(&self, data: &[u8], eof: bool, threads: usize) -> Vec<usize> {
        self.cut_ends_beside(data, eof, threads, || ()).0
    }

    /// [`FastCdc::cut_ends`], running `beside` on the calling thread while
    /// the worker threads cut. Without workers, `beside` runs first.
    fn cut_ends_beside<T>(
        &self,
        data: &[u8],
        eof: bool,
        threads: usize,
        beside: impl FnOnce() -> T,
    ) -> (Vec<usize>, T) {
        let segment = PARALLEL_SEGMENT.max(self.max_size);
        if threads <= 1 || data.len() < 2 * segment {
            let side = beside();
            let mut ends = self.chain(data, 0, data.len(), eof);
            ends.remove(0);
            return (ends, side);
        }
        let segment = data.len().div_ceil(threads).max(segment);
        let (specs, side) = std::thread::scope(|scope| {
            let workers: Vec<_> = (0..data.len().div_ceil(segment))
                .map(|t| {
                    let from = t * segment;
                    let stop = (from + segment).min(data.len());
                    scope.spawn(move || self.chain(data, from, stop, eof))
                })
                .collect();
            let side = beside();
            let specs: Vec<Vec<usize>> = workers
                .into_iter()
                .map(|w| w.join().unwrap_or_else(|e| std::panic::resume_unwind(e)))
                .collect();
            (specs, side)
        });
        let mut ends = Vec::new();
        let mut pos = 0;
        while self.cut_is_final(data.len(), pos, eof) {
            let spec = &specs[pos / segment];
            if let Ok(k) = spec.binary_search(&pos)
                && k + 1 < spec.len()
            {
                ends.extend_from_slice(&spec[k + 1..]);
                pos = spec[spec.len() - 1];
                continue;
            }
            pos += self.cut(&data[pos..]);
            ends.push(pos);
        }
        (ends, side)
    }

    /// Chunk end offsets of all of `data`, cut on `cut_threads` threads.
    /// Identical to [`chunk_boundaries`] for the v1 chunker.
    #[must_use]
    pub fn chunk_ends(&self, data: &[u8]) -> Vec<usize> {
        self.cut_ends(data, true, cut_threads())
    }
}

/// Streaming variant of [`ChunkIterator`] that pulls from a [`Read`]
/// instead of requiring the whole input as an in-memory slice.
///
/// The reader holds two fixed buffers. While [`FastCdc::cut_ends`] cuts
/// the current window on `threads` threads, the calling thread reads the
/// next window's bytes from the source into the other buffer, so reading
/// overlaps cutting. A window starts with the previous window's uncut
/// tail, which is shorter than `max_size` because every cut that starts
/// `max_size` or more bytes before the end is final. Each buffer
/// reserves `max_size` bytes at the front for that tail. Memory is
/// bounded by the two buffers, independent of the total input length.
///
/// The output is byte-identical to [`ChunkIterator`] over the same bytes,
/// whatever the thread count and however the source splits its reads.
/// The `streaming_matches_in_memory_*` tests pin this.
///
/// Each buffer holds `max_size` plus `WINDOW_MULTIPLE * max_size` new
/// bytes (1.25 MiB for `FastCdc::v1()`) with one thread, or `max_size`
/// plus `threads * PARALLEL_SEGMENT` (at most 16.25 MiB) with more.
///
/// [`Read`]: std::io::Read
const WINDOW_MULTIPLE: usize = 4;

#[derive(Debug)]
pub struct ChunkReader<R> {
    cdc: FastCdc,
    reader: R,
    threads: usize,
    /// The window being handed out: `cur[start..end]` is not yet consumed.
    cur: Vec<u8>,
    start: usize,
    end: usize,
    /// The next window's new bytes, at `next[max_size..max_size + next_len]`.
    next: Vec<u8>,
    next_len: usize,
    /// The source has returned EOF.
    eof: bool,
    /// The first window has been read.
    primed: bool,
    /// Chunk ends in `cur` not yet handed out, in order.
    ends: std::collections::VecDeque<usize>,
}

/// Read from `reader` into `buf` until it is full or the reader reports
/// EOF. `read` can return short of the requested length without
/// signalling EOF, so this loops until one of the two. Returns the byte
/// count and whether EOF was reached.
fn read_full(reader: &mut impl std::io::Read, buf: &mut [u8]) -> std::io::Result<(usize, bool)> {
    let mut n = 0;
    while n < buf.len() {
        match reader.read(&mut buf[n..])? {
            0 => return Ok((n, true)),
            k => n += k,
        }
    }
    Ok((n, false))
}

impl<R: std::io::Read> ChunkReader<R> {
    /// Reader that cuts on `cut_threads` threads.
    #[must_use]
    pub fn new(cdc: FastCdc, reader: R) -> Self {
        Self::with_threads(cdc, reader, cut_threads())
    }

    /// Reader that cuts on exactly `threads` threads (`0` is treated as `1`).
    #[must_use]
    pub fn with_threads(cdc: FastCdc, reader: R, threads: usize) -> Self {
        let threads = threads.clamp(1, MAX_CUT_THREADS);
        let fresh = if threads == 1 {
            cdc.max_size() * WINDOW_MULTIPLE
        } else {
            (threads * PARALLEL_SEGMENT).max(cdc.max_size() * WINDOW_MULTIPLE)
        };
        let len = cdc.max_size() + fresh;
        Self {
            cdc,
            reader,
            threads,
            cur: vec![0u8; len],
            start: 0,
            end: 0,
            next: vec![0u8; len],
            next_len: 0,
            eof: false,
            primed: false,
            ends: std::collections::VecDeque::new(),
        }
    }

    /// Start a new window: the uncut tail of `cur` followed by the bytes
    /// read ahead into `next`. Cut it while reading the window after it.
    fn refill(&mut self) -> std::io::Result<()> {
        debug_assert!(self.ends.is_empty());
        let max = self.cdc.max_size();
        if !self.primed {
            let (n, eof) = read_full(&mut self.reader, &mut self.next[max..])?;
            self.next_len = n;
            self.eof = eof;
            self.primed = true;
        }
        let tail = self.end - self.start;
        debug_assert!(tail < max || (tail == 0 && max == 0));
        self.next[max - tail..max].copy_from_slice(&self.cur[self.start..self.end]);
        std::mem::swap(&mut self.cur, &mut self.next);
        self.start = max - tail;
        self.end = max + self.next_len;
        self.next_len = 0;

        let final_window = self.eof;
        let (cdc, threads) = (self.cdc, self.threads);
        let window = &self.cur[self.start..self.end];
        let (ends, read) = if final_window {
            (cdc.cut_ends(window, true, threads), Ok((0, true)))
        } else {
            let (reader, next) = (&mut self.reader, &mut self.next[max..]);
            cdc.cut_ends_beside(window, false, threads, || read_full(reader, next))
        };
        let (n, eof) = read?;
        self.next_len = n;
        self.eof = eof;
        let start = self.start;
        self.ends.extend(ends.into_iter().map(|e| start + e));
        Ok(())
    }

    /// Read the next chunk as a borrow into the internal window, or
    /// `None` at end of input. The returned slice is only valid until the
    /// next call — [`next_chunk`](Self::next_chunk) copies it out for
    /// callers that need an owned `Vec`.
    ///
    /// # Errors
    /// Propagates the underlying reader's I/O errors.
    pub fn next_chunk_ref(&mut self) -> std::io::Result<Option<&[u8]>> {
        while self.ends.is_empty() {
            if self.start == self.end && self.eof && self.next_len == 0 && self.primed {
                return Ok(None);
            }
            self.refill()?;
        }
        let Some(end) = self.ends.pop_front() else {
            return Ok(None);
        };
        let chunk_start = self.start;
        self.start = end;
        Ok(Some(&self.cur[chunk_start..end]))
    }

    /// Read and return the next chunk's owned bytes, or `None` at end of
    /// input. Mirrors `Iterator` exhaustion semantics but is fallible
    /// because filling the window can fail.
    ///
    /// # Errors
    /// Propagates the underlying reader's I/O errors.
    pub fn next_chunk(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        Ok(self.next_chunk_ref()?.map(<[u8]>::to_vec))
    }
}

/// Convenience: collect all chunk *end* offsets from `data` using the
/// frozen v1 chunker. The returned vector starts with the length of the
/// first chunk and ends with `data.len()`. An empty input yields an
/// empty vector. Used by goldens to pin boundaries deterministically
/// without exposing the `ChunkBoundary` struct in serialised form.
#[must_use]
pub fn chunk_boundaries(data: &[u8]) -> Vec<usize> {
    let cdc = FastCdc::v1();
    let mut out = Vec::new();
    let mut offset = 0usize;
    while offset < data.len() {
        let len = cdc.cut(&data[offset..]);
        offset += len;
        out.push(offset);
    }
    out
}

/// Hash the entire 256-entry gear table as little-endian `u64` bytes
/// (2 048 bytes total) with BLAKE3. Useful as a cheap "did we get the
/// seed right" check — see SPEC-FASTCDC §8 vector 1.
#[must_use]
pub fn gear_table_digest() -> [u8; 32] {
    let table = gear_table();
    let mut bytes = [0u8; 256 * 8];
    for (i, v) in table.iter().enumerate() {
        bytes[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
    }
    crate::hash::hash(&bytes)
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic xorshift64* PRNG for test-data generation. We avoid
    /// `rand` here to keep test inputs explicit and reproducible
    /// without committing to a specific `rand` version.
    struct Prng(u64);
    impl Prng {
        fn new(seed: u64) -> Self {
            Self(seed.max(1))
        }
        fn next_u64(&mut self) -> u64 {
            // splitmix64 (same primitive used to derive the gear table —
            // a different seed gives an unrelated stream).
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        }
        fn fill(&mut self, dst: &mut [u8]) {
            for chunk in dst.chunks_mut(8) {
                let bytes = self.next_u64().to_le_bytes();
                let n = chunk.len();
                chunk.copy_from_slice(&bytes[..n]);
            }
        }
    }

    #[test]
    fn gear_table_is_unique_and_nonzero() {
        let table = gear_table();
        let mut seen = std::collections::HashSet::new();
        for &v in table {
            assert_ne!(v, 0, "gear table entry is zero");
            assert!(seen.insert(v), "duplicate gear table entry");
        }
        assert_eq!(seen.len(), 256);
    }

    #[test]
    fn min_max_size_constraints() {
        let cdc = FastCdc::v1();
        let mut data = vec![0u8; 512 * 1024];
        Prng::new(0xCAFE_BABE).fill(&mut data);

        let mut total = 0usize;
        let mut count = 0usize;
        for b in ChunkIterator::new(cdc, &data) {
            assert!(b.length <= MAX_SIZE);
            // Only the final chunk is allowed to be smaller than min.
            if b.offset + b.length < data.len() {
                assert!(b.length >= MIN_SIZE, "chunk under MIN_SIZE: {}", b.length);
            }
            total += b.length;
            count += 1;
        }
        assert_eq!(total, data.len());
        assert!(count > 1);
    }

    #[test]
    fn small_input_is_single_chunk() {
        let cdc = FastCdc::v1();
        let small = b"hello, this is a tiny file";
        assert_eq!(cdc.cut(small), small.len());
        let boundaries: Vec<_> = ChunkIterator::new(cdc, small).collect();
        assert_eq!(boundaries.len(), 1);
        assert_eq!(boundaries[0].offset, 0);
        assert_eq!(boundaries[0].length, small.len());
    }

    #[test]
    fn empty_input_iterator_is_empty() {
        let cdc = FastCdc::v1();
        assert_eq!(cdc.cut(b""), 0);
        let none: Vec<_> = ChunkIterator::new(cdc, b"").collect();
        assert!(none.is_empty());
    }

    #[test]
    fn cut_at_exactly_min_size_returns_full() {
        let cdc = FastCdc::custom(1024, 4096, 16384);
        let mut data = vec![0u8; 1024];
        Prng::new(99).fill(&mut data);
        assert_eq!(cdc.cut(&data), data.len());
    }

    #[test]
    fn cut_forces_boundary_at_max_size() {
        // All-zero buffer, gear hash never trips a natural cut → forced
        // cut at max_size.
        let cdc = FastCdc::custom(4, 8, 16);
        let data = [0u8; 64];
        let len = cdc.cut(&data);
        assert!(len <= 16, "cut returned {len} > max=16");
    }

    #[test]
    fn boundary_stability_single_byte_insert() {
        // Insert one byte at offset 32 KiB; expect <=3 chunks differ.
        let cdc = FastCdc::v1();
        let mut original = vec![0u8; 64 * 1024];
        Prng::new(0xBEEF).fill(&mut original);
        let insert_point = 32 * 1024;
        let mut modified = Vec::with_capacity(original.len() + 1);
        modified.extend_from_slice(&original[..insert_point]);
        modified.push(0xFF);
        modified.extend_from_slice(&original[insert_point..]);

        let orig_chunks: Vec<_> = ChunkIterator::new(cdc, &original).collect();
        let mod_chunks: Vec<_> = ChunkIterator::new(cdc, &modified).collect();

        let max_chunks = orig_chunks.len().max(mod_chunks.len());
        let mut differing = 0usize;
        for i in 0..max_chunks {
            match (orig_chunks.get(i), mod_chunks.get(i)) {
                (Some(o), Some(m)) => {
                    let os = &original[o.offset..o.offset + o.length];
                    let ms = &modified[m.offset..m.offset + m.length];
                    if os != ms {
                        differing += 1;
                    }
                }
                _ => differing += 1,
            }
        }
        assert!(
            differing <= 3,
            "expected <=3 differing chunks, got {differing}"
        );
    }

    #[test]
    fn different_avg_size_yields_different_boundaries() {
        let mut data = vec![0u8; 100 * 1024];
        Prng::new(0xABCD).fill(&mut data);
        let small = FastCdc::custom(8 * 1024, 32 * 1024, 128 * 1024);
        let large = FastCdc::v1();

        let s: Vec<_> = ChunkIterator::new(small, &data)
            .map(|b| b.offset + b.length)
            .collect();
        let l: Vec<_> = ChunkIterator::new(large, &data)
            .map(|b| b.offset + b.length)
            .collect();
        assert!(
            s != l,
            "expected different boundaries for different avg_size"
        );
    }

    #[test]
    fn chunk_boundaries_helper_matches_iterator() {
        let mut data = vec![0u8; 200 * 1024];
        Prng::new(0xFEED_FACE).fill(&mut data);
        let from_helper = chunk_boundaries(&data);
        let from_iter: Vec<usize> = ChunkIterator::new(FastCdc::v1(), &data)
            .map(|b| b.offset + b.length)
            .collect();
        assert_eq!(from_helper, from_iter);
    }

    #[test]
    fn streaming_matches_in_memory_iterator() {
        let mut data = vec![0u8; 500 * 1024];
        Prng::new(0x5713_EA31).fill(&mut data);

        let in_memory: Vec<Vec<u8>> = ChunkIterator::new(FastCdc::v1(), &data)
            .map(|b| data[b.offset..b.offset + b.length].to_vec())
            .collect();

        let mut reader = ChunkReader::new(FastCdc::v1(), std::io::Cursor::new(&data));
        let mut streamed = Vec::new();
        while let Some(chunk) = reader.next_chunk().unwrap() {
            streamed.push(chunk);
        }

        assert_eq!(in_memory, streamed);
    }

    /// Drain a reader through `next_chunk` (owned) or `next_chunk_ref`.
    fn drain<R: std::io::Read>(mut reader: ChunkReader<R>, owned: bool) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        if owned {
            while let Some(chunk) = reader.next_chunk().unwrap() {
                out.push(chunk);
            }
        } else {
            while let Some(chunk) = reader.next_chunk_ref().unwrap() {
                out.push(chunk.to_vec());
            }
        }
        out
    }

    #[test]
    fn streaming_matches_in_memory_iterator_across_multiple_refills() {
        // Push enough input through that every thread count refills its
        // window several times, so the tail carried across refills is
        // exercised, and check both the owned and the borrowed paths.
        // `Cursor` fills a whole window in one `read`.
        let mut data = vec![0u8; 13 * 1024 * 1024 + 12_345];
        Prng::new(0xC0FF_EE01).fill(&mut data);

        let in_memory: Vec<Vec<u8>> = ChunkIterator::new(FastCdc::v1(), &data)
            .map(|b| data[b.offset..b.offset + b.length].to_vec())
            .collect();
        assert!(in_memory.len() > 100, "got {} chunks", in_memory.len());

        for threads in [1, 2, 3] {
            for owned in [true, false] {
                let reader =
                    ChunkReader::with_threads(FastCdc::v1(), std::io::Cursor::new(&data), threads);
                assert_eq!(
                    in_memory,
                    drain(reader, owned),
                    "threads {threads}, owned {owned}: diverged from ChunkIterator"
                );
            }
        }
    }

    #[test]
    fn streaming_empty_input_yields_no_chunks() {
        let mut reader = ChunkReader::new(FastCdc::v1(), std::io::Cursor::new(&[] as &[u8]));
        assert!(reader.next_chunk().unwrap().is_none());
    }

    #[test]
    fn streaming_small_input_is_single_chunk() {
        let small = b"hello, this is a tiny file";
        let mut reader = ChunkReader::new(FastCdc::v1(), std::io::Cursor::new(&small[..]));
        let chunk = reader.next_chunk().unwrap().expect("one chunk");
        assert_eq!(chunk, small);
        assert!(reader.next_chunk().unwrap().is_none());
    }

    /// A reader that only ever yields a handful of bytes per `read` call,
    /// to exercise `ChunkReader::fill`'s short-read loop (a real `File`
    /// on a slow filesystem or a network stream behaves this way).
    struct StingyReader<'a> {
        data: &'a [u8],
        pos: usize,
    }
    impl std::io::Read for StingyReader<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = (self.data.len() - self.pos).min(buf.len()).min(7);
            buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
            self.pos += n;
            Ok(n)
        }
    }

    #[test]
    fn streaming_reader_buffer_stays_bounded_regardless_of_input_size() {
        // Ingest memory must not scale with file size: the two buffers are
        // fixed allocations, set by the chunker's parameters and the thread
        // count, that never grow or reallocate.
        let mut data = vec![0u8; 20 * 1024 * 1024];
        Prng::new(0x8000_0008).fill(&mut data);
        for (threads, fresh) in [
            (1, WINDOW_MULTIPLE * MAX_SIZE),
            (4, 4 * PARALLEL_SEGMENT),
            (64, MAX_CUT_THREADS * PARALLEL_SEGMENT),
        ] {
            let window = MAX_SIZE + fresh;
            let mut reader =
                ChunkReader::with_threads(FastCdc::v1(), std::io::Cursor::new(&data), threads);
            let mut chunk_count = 0usize;
            while let Some(_chunk) = reader.next_chunk().unwrap() {
                assert_eq!(reader.cur.len(), window, "threads {threads}");
                assert_eq!(reader.next.len(), window, "threads {threads}");
                assert!(reader.end - reader.start <= window, "threads {threads}");
                chunk_count += 1;
            }
            assert!(
                chunk_count > 1,
                "threads {threads}: expected multiple chunks"
            );
        }
    }

    #[test]
    fn streaming_matches_in_memory_iterator_under_short_reads() {
        let mut data = vec![0u8; 300 * 1024];
        Prng::new(0x5713_EA32).fill(&mut data);

        let in_memory: Vec<Vec<u8>> = ChunkIterator::new(FastCdc::v1(), &data)
            .map(|b| data[b.offset..b.offset + b.length].to_vec())
            .collect();

        let reader = ChunkReader::with_threads(
            FastCdc::v1(),
            StingyReader {
                data: &data,
                pos: 0,
            },
            1,
        );
        assert_eq!(in_memory, drain(reader, true));
    }

    #[test]
    fn parallel_streaming_matches_in_memory_iterator_under_short_reads() {
        // Large enough that two threads take the parallel path.
        let mut data = vec![0u8; 5 * 1024 * 1024];
        Prng::new(0x5713_EA33).fill(&mut data);
        let in_memory: Vec<Vec<u8>> = ChunkIterator::new(FastCdc::v1(), &data)
            .map(|b| data[b.offset..b.offset + b.length].to_vec())
            .collect();
        let reader = ChunkReader::with_threads(
            FastCdc::v1(),
            StingyReader {
                data: &data,
                pos: 0,
            },
            2,
        );
        assert_eq!(in_memory, drain(reader, false));
    }

    /// Sequential chunk ends of `data` from offset `0`.
    fn sequential_ends(cdc: &FastCdc, data: &[u8]) -> Vec<usize> {
        ChunkIterator::new(*cdc, data)
            .map(|b| b.offset + b.length)
            .collect()
    }

    #[test]
    fn cut_ends_matches_sequential_for_every_thread_count() {
        // Pseudo-random bytes, a long zero run (forced max-size cuts that
        // line up with segment starts), and an odd total length.
        let mut data = vec![0u8; 9 * 1024 * 1024 + 777];
        Prng::new(0x009A_11E1).fill(&mut data);
        data[3 * 1024 * 1024..4 * 1024 * 1024 + 99].fill(0);
        for cdc in [FastCdc::v1(), FastCdc::custom(64, 256, 1024)] {
            let expected = sequential_ends(&cdc, &data);
            for threads in 1..=MAX_CUT_THREADS + 1 {
                assert_eq!(
                    cdc.cut_ends(&data, true, threads),
                    expected,
                    "threads {threads}, max {}",
                    cdc.max_size()
                );
            }
        }
        assert_eq!(
            FastCdc::v1().chunk_ends(&data),
            sequential_ends(&FastCdc::v1(), &data)
        );
    }

    #[test]
    fn cut_ends_without_eof_returns_only_final_cuts() {
        // Without EOF, `cut_ends` returns a prefix of the full chain, and
        // every chunk it returns started at least `max_size` bytes before
        // the end of the buffer.
        let mut data = vec![0u8; 7 * 1024 * 1024];
        Prng::new(0x000F_1AA1).fill(&mut data);
        let cdc = FastCdc::v1();
        let full = sequential_ends(&cdc, &data);
        for len in [
            0,
            1000,
            MAX_SIZE,
            MAX_SIZE + 1,
            5 * 1024 * 1024 + 3,
            data.len(),
        ] {
            for threads in [1, 2, 4] {
                let ends = cdc.cut_ends(&data[..len], false, threads);
                assert_eq!(ends[..], full[..ends.len()], "len {len}, threads {threads}");
                let last_start = ends.len().checked_sub(2).map_or(0, |i| ends[i]);
                if !ends.is_empty() {
                    assert!(len - last_start >= MAX_SIZE, "len {len}, threads {threads}");
                }
            }
        }
    }

    /// Pinned v1 gear-table digest, harvested once from the splitmix64
    /// derivation seeded with "KITFCDC". Drift = a v2 break.
    const EXPECTED_GEAR_DIGEST_HEX: &str =
        "2c8b776fb264316106cef8f45ebd30bf6c2cb7a704c095ce9adc4b4b84ab75ff";

    #[test]
    fn gear_table_digest_is_stable() {
        // SPEC-FASTCDC §8 vector 1: any change to the seed or splitmix
        // derivation moves this digest. CI flags drift loud and early.
        let hex = crate::hash::to_hex(&gear_table_digest());
        assert_eq!(
            hex, EXPECTED_GEAR_DIGEST_HEX,
            "gear table digest changed; refuse to drift silently"
        );
    }

    // -- Property tests -------------------------------------------------
    //
    // Determinism + cap invariants exercised against arbitrary inputs
    // via `proptest`. The example tests above cover specific PRNG seeds;
    // the properties below catch the boundary cases the examples miss
    // (very-short data, repeating patterns, etc.).
    proptest::proptest! {
        /// FastCDC is deterministic: two passes over the same bytes
        /// produce the same chunk boundaries. This is the core SPEC-
        /// FASTCDC §2 contract that makes `chunked_blob` content-
        /// addressable.
        #[test]
        fn proptest_determinism(data in proptest::collection::vec(proptest::num::u8::ANY, 0..256 * 1024)) {
            let cdc = FastCdc::v1();
            let pass1: Vec<_> = ChunkIterator::new(cdc, &data).collect();
            let pass2: Vec<_> = ChunkIterator::new(cdc, &data).collect();
            proptest::prop_assert_eq!(pass1, pass2);
        }

        /// Boundaries cover the input exactly: sum of lengths equals
        /// input length; offsets are non-overlapping and monotonic.
        #[test]
        fn proptest_boundaries_partition_input(
            data in proptest::collection::vec(proptest::num::u8::ANY, 0..256 * 1024),
        ) {
            let cdc = FastCdc::v1();
            let boundaries: Vec<_> = ChunkIterator::new(cdc, &data).collect();
            let mut expected_offset = 0usize;
            for b in &boundaries {
                proptest::prop_assert_eq!(b.offset, expected_offset);
                expected_offset += b.length;
            }
            proptest::prop_assert_eq!(expected_offset, data.len());
        }

        /// `ChunkReader` (streaming) produces byte-identical chunks to
        /// `ChunkIterator` (in-memory) for arbitrary input — the
        /// correctness contract that streaming ingest depends on:
        /// content addressing must not change based on how a file was
        /// read.
        #[test]
        fn proptest_streaming_matches_in_memory(
            data in proptest::collection::vec(proptest::num::u8::ANY, 0..256 * 1024),
        ) {
            let cdc = FastCdc::v1();
            let in_memory: Vec<Vec<u8>> = ChunkIterator::new(cdc, &data)
                .map(|b| data[b.offset..b.offset + b.length].to_vec())
                .collect();

            let mut reader = ChunkReader::new(cdc, std::io::Cursor::new(&data));
            let mut streamed = Vec::new();
            while let Some(chunk) = reader.next_chunk().unwrap() {
                streamed.push(chunk);
            }
            proptest::prop_assert_eq!(in_memory, streamed);
        }
    }
}
