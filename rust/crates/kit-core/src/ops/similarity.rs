//! Rename detection by content similarity, after git's `diffcore-rename`.
//!
//! [`detect_renames`] first pairs identical content with
//! [`detect_content_renames`]. It then scores the deleted and added regular
//! files that are left, and pairs those at or above a threshold.
//!
//! The score is git's. Content splits into spans that end at a newline or
//! after 64 bytes. Each span hashes into one of 107,927 buckets, and a file's
//! signature counts the bytes in each bucket. Two files share, per bucket,
//! the smaller of their two counts. The score is the shared bytes against the
//! larger file, on a scale of [`MAX_SCORE`]. In a text file (no NUL in the
//! first [`BINARY_SNIFF_LEN`] bytes) a CR before an LF is skipped. The
//! signature reads the reassembled bytes, so it does not depend on how a blob
//! is chunked.
//!
//! Pairing follows git too. A deleted file and an added file that are the
//! only ones left with their basename pair first, when their score is at
//! least halfway between the threshold and [`MAX_SCORE`]. If more than
//! `limit` squared pairs are left to score, the similarity pass stops there
//! and [`RenameReport::limit_needed`] says how large a limit would have
//! been enough. Otherwise each destination keeps its four best sources, and
//! the candidates pair best score first, with each path in at most one pair.

use std::collections::HashMap;

use crate::hash::Hash;
use crate::object::EntryMode;
use crate::store::{ObjectSource, StoreError};
use crate::worktree::{LoadedBlob, WorktreeError};

use super::diff::{BINARY_SNIFF_LEN, DiffEntry, DiffKind, detect_content_renames, is_binary};

/// The top of the score scale: identical signatures. git's `MAX_SCORE`.
pub const MAX_SCORE: u32 = 60_000;

/// The default threshold, 50%. git's `DEFAULT_RENAME_SCORE`.
pub const DEFAULT_MIN_SCORE: u32 = MAX_SCORE / 2;

/// The default candidate limit. git's `diff.renameLimit` default.
pub const DEFAULT_RENAME_LIMIT: usize = 1000;

/// The bucket count of a span hash. git's `HASHBASE`.
const HASHBASE: u32 = 107_927;

/// The longest span, in bytes.
const MAX_SPAN: u32 = 64;

/// How many sources each destination keeps. git's `NUM_CANDIDATE_PER_DST`.
const CANDIDATES_PER_DST: usize = 4;

/// What [`detect_renames`] looks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RenameOptions {
    /// The lowest score that pairs, out of [`MAX_SCORE`]. At [`MAX_SCORE`]
    /// only identical content pairs.
    pub min_score: u32,
    /// The similarity pass runs only when the deleted files times the added
    /// files left after the exact and basename passes is at most `limit`
    /// squared. `0` means no limit.
    pub limit: usize,
}

impl Default for RenameOptions {
    fn default() -> Self {
        Self {
            min_score: DEFAULT_MIN_SCORE,
            limit: DEFAULT_RENAME_LIMIT,
        }
    }
}

/// What [`detect_renames`] did beyond pairing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RenameReport {
    /// Set when the limit stopped the similarity pass: the larger of the
    /// deleted and added file counts that were left, which is the smallest
    /// limit that would have let the pass run.
    pub limit_needed: Option<usize>,
}

/// Parse a threshold in git's grammar into a score.
///
/// Digits followed by `%` are a percent. Digits without `%` are a decimal
/// fraction, so `5` and `50` are 50% and `100` is 10%. One `.` may come
/// before or among the digits. A value at or above 100% is [`MAX_SCORE`].
/// The whole text must parse; an empty text is `None`.
#[must_use]
pub fn parse_rename_score(text: &str) -> Option<u32> {
    let mut num: u64 = 0;
    let mut scale: u64 = 1;
    let mut dot = false;
    let mut digits = false;
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'.' if !dot => {
                scale = 1;
                dot = true;
            }
            b'%' => {
                // `%` ends the value.
                if i + 1 != bytes.len() {
                    return None;
                }
                scale = if dot { scale * 100 } else { 100 };
            }
            c @ b'0'..=b'9' => {
                digits = true;
                if scale < 100_000 {
                    scale *= 10;
                    num = num * 10 + u64::from(c - b'0');
                }
            }
            _ => return None,
        }
        i += 1;
    }
    if !digits {
        return None;
    }
    let score = if num >= scale {
        u64::from(MAX_SCORE)
    } else {
        u64::from(MAX_SCORE) * num / scale
    };
    u32::try_from(score).ok()
}

/// A score as the whole percent git prints.
#[must_use]
pub fn percent(score: u32) -> u8 {
    u8::try_from(u64::from(score.min(MAX_SCORE)) * 100 / u64::from(MAX_SCORE)).unwrap_or(100)
}

/// Pair deleted and added files into renames: identical content first, then
/// by similarity as `options` asks. Each rename entry carries its
/// [`DiffEntry::similarity`]. Entries stay sorted by path.
///
/// # Errors
/// A missing or invalid object of a candidate aborts detection without
/// changing `entries`.
pub fn detect_renames<S: ObjectSource + ?Sized>(
    store: &S,
    entries: &mut Vec<DiffEntry>,
    options: &RenameOptions,
) -> Result<RenameReport, StoreError> {
    let mut work = entries.clone();
    detect_content_renames(store, &mut work)?;
    let report = if options.min_score >= MAX_SCORE {
        RenameReport::default()
    } else {
        similarity_pass(store, &mut work, options)?
    };
    *entries = work;
    Ok(report)
}

/// One deleted or added file that may pair.
struct Side {
    /// Index in the entry list.
    index: usize,
    path: String,
    hash: Hash,
    /// Whether the mode is a regular or executable file.
    regular: bool,
}

fn similarity_pass<S: ObjectSource + ?Sized>(
    store: &S,
    entries: &mut Vec<DiffEntry>,
    options: &RenameOptions,
) -> Result<RenameReport, StoreError> {
    let mut sources: Vec<Side> = Vec::new();
    let mut dests: Vec<Side> = Vec::new();
    for (index, e) in entries.iter().enumerate() {
        match (e.kind, e.old_hash, e.new_hash) {
            (DiffKind::Removed, Some(hash), _) => sources.push(Side {
                index,
                path: e.path.clone(),
                hash,
                regular: is_regular(e.old_mode),
            }),
            (DiffKind::Added, _, Some(hash)) => dests.push(Side {
                index,
                path: e.path.clone(),
                hash,
                regular: is_regular(e.new_mode),
            }),
            _ => {}
        }
    }
    if sources.is_empty() || dests.is_empty() {
        return Ok(RenameReport::default());
    }

    let mut cache = Signatures::default();
    let mut src_used = vec![false; sources.len()];
    let mut dst_used = vec![false; dests.len()];
    // (source, destination, score)
    let mut pairs: Vec<(usize, usize, u32)> = Vec::new();

    // Unique basenames on both sides pair first, at a higher bar.
    let basename_min = options.min_score + (MAX_SCORE - options.min_score) / 2;
    let src_names = unique_basenames(&sources);
    let dst_names = unique_basenames(&dests);
    for (si, src) in sources.iter().enumerate() {
        let base = basename(&src.path);
        let (Some(Some(s)), Some(Some(d))) = (src_names.get(base), dst_names.get(base)) else {
            continue;
        };
        debug_assert_eq!(*s, si);
        let di = *d;
        if dst_used[di] {
            continue;
        }
        let found = cache.score(store, src, &dests[di], basename_min)?;
        if found >= basename_min {
            src_used[si] = true;
            dst_used[di] = true;
            pairs.push((si, di, found));
        }
    }

    let left_src = src_used.iter().filter(|u| !**u).count();
    let left_dst = dst_used.iter().filter(|u| !**u).count();
    let mut report = RenameReport::default();
    if left_src > 0 && left_dst > 0 {
        let limit = options.limit as u128;
        if options.limit != 0 && (left_src as u128) * (left_dst as u128) > limit * limit {
            report.limit_needed = Some(left_src.max(left_dst));
        } else {
            pairs.extend(matrix_pass(
                store, &mut cache, &sources, &dests, &src_used, &dst_used, options,
            )?);
        }
    }

    if pairs.is_empty() {
        return Ok(report);
    }
    let mut consumed = vec![false; entries.len()];
    let mut renamed = Vec::with_capacity(pairs.len());
    for (si, di, score) in pairs {
        let (src, dst) = (&entries[sources[si].index], &entries[dests[di].index]);
        renamed.push(DiffEntry {
            path: dst.path.clone(),
            kind: DiffKind::Renamed,
            old_hash: src.old_hash,
            new_hash: dst.new_hash,
            old_mode: src.old_mode,
            new_mode: dst.new_mode,
            old_path: Some(src.path.clone()),
            similarity: Some(percent(score)),
        });
        consumed[sources[si].index] = true;
        consumed[dests[di].index] = true;
    }
    let mut out: Vec<DiffEntry> = entries
        .drain(..)
        .enumerate()
        .filter_map(|(i, e)| (!consumed[i]).then_some(e))
        .collect();
    out.extend(renamed);
    out.sort_by(|a, b| a.path.cmp(&b.path));
    *entries = out;
    Ok(report)
}

/// Score every unpaired destination against every unpaired source, keep each
/// destination's best few, and pair best first.
fn matrix_pass<S: ObjectSource + ?Sized>(
    store: &S,
    cache: &mut Signatures,
    sources: &[Side],
    dests: &[Side],
    src_used: &[bool],
    dst_used: &[bool],
    options: &RenameOptions,
) -> Result<Vec<(usize, usize, u32)>, StoreError> {
    // (score, same basename, destination, source)
    let mut candidates: Vec<(u32, bool, usize, usize)> = Vec::new();
    for (di, dst) in dests.iter().enumerate() {
        if dst_used[di] {
            continue;
        }
        let mut best: Vec<(u32, bool, usize, usize)> = Vec::new();
        for (si, src) in sources.iter().enumerate() {
            if src_used[si] {
                continue;
            }
            let found = cache.score(store, src, dst, options.min_score)?;
            if found < options.min_score {
                continue;
            }
            best.push((found, basename(&src.path) == basename(&dst.path), di, si));
        }
        best.sort_by(rank);
        best.truncate(CANDIDATES_PER_DST);
        candidates.extend(best);
    }
    // A stable sort keeps destination order, then source order, for ties.
    candidates.sort_by(rank);
    let mut src_taken = src_used.to_vec();
    let mut dst_taken = dst_used.to_vec();
    let mut pairs = Vec::new();
    for (score, _, di, si) in candidates {
        if dst_taken[di] || src_taken[si] {
            continue;
        }
        dst_taken[di] = true;
        src_taken[si] = true;
        pairs.push((si, di, score));
    }
    Ok(pairs)
}

/// Best first: higher score, then a same-basename pair.
fn rank(a: &(u32, bool, usize, usize), b: &(u32, bool, usize, usize)) -> std::cmp::Ordering {
    b.0.cmp(&a.0).then(b.1.cmp(&a.1))
}

fn is_regular(mode: Option<EntryMode>) -> bool {
    matches!(mode, Some(EntryMode::Blob | EntryMode::Executable))
}

fn basename(path: &str) -> &str {
    path.rsplit_once('/').map_or(path, |(_, b)| b)
}

/// Each basename mapped to the one side that has it, or `None` when more
/// than one has it.
fn unique_basenames(sides: &[Side]) -> HashMap<&str, Option<usize>> {
    let mut map: HashMap<&str, Option<usize>> = HashMap::new();
    for (i, side) in sides.iter().enumerate() {
        map.entry(basename(&side.path))
            .and_modify(|slot| *slot = None)
            .or_insert(Some(i));
    }
    map
}

/// A file's size and span signature: `(bucket, bytes)` sorted by bucket.
struct Signature {
    size: u64,
    spans: Vec<(u32, u64)>,
}

/// Loaded blobs and signatures, by object id, for one detection.
#[derive(Default)]
struct Signatures {
    blobs: HashMap<Hash, LoadedBlob>,
    spans: HashMap<Hash, Signature>,
}

impl Signatures {
    fn size<S: ObjectSource + ?Sized>(
        &mut self,
        store: &S,
        hash: &Hash,
    ) -> Result<u64, StoreError> {
        if let Some(sig) = self.spans.get(hash) {
            return Ok(sig.size);
        }
        if let Some(blob) = self.blobs.get(hash) {
            return Ok(blob.len());
        }
        let blob = LoadedBlob::load(store, hash).map_err(store_error)?;
        let size = blob.len();
        self.blobs.insert(*hash, blob);
        Ok(size)
    }

    fn signature<S: ObjectSource + ?Sized>(
        &mut self,
        store: &S,
        hash: &Hash,
    ) -> Result<&Signature, StoreError> {
        if !self.spans.contains_key(hash) {
            let blob = match self.blobs.remove(hash) {
                Some(blob) => blob,
                None => LoadedBlob::load(store, hash).map_err(store_error)?,
            };
            let sig = signature_of(store, &blob)?;
            self.spans.insert(*hash, sig);
        }
        Ok(&self.spans[hash])
    }

    /// git's `estimate_similarity`: zero for a non-regular side or sizes
    /// too far apart to reach `min_score`.
    fn score<S: ObjectSource + ?Sized>(
        &mut self,
        store: &S,
        src: &Side,
        dst: &Side,
        min_score: u32,
    ) -> Result<u32, StoreError> {
        if !src.regular || !dst.regular {
            return Ok(0);
        }
        let src_size = self.size(store, &src.hash)?;
        let dst_size = self.size(store, &dst.hash)?;
        let max = u128::from(src_size.max(dst_size));
        let delta = max - u128::from(src_size.min(dst_size));
        if max * u128::from(MAX_SCORE - min_score.min(MAX_SCORE)) < delta * u128::from(MAX_SCORE) {
            return Ok(0);
        }
        if dst_size == 0 {
            return Ok(0);
        }
        let copied = {
            let a = self.signature(store, &src.hash)?.spans.clone();
            let b = &self.signature(store, &dst.hash)?.spans;
            shared_bytes(&a, b)
        };
        let scaled = u128::from(copied) * u128::from(MAX_SCORE) / max;
        Ok(u32::try_from(scaled.min(u128::from(MAX_SCORE))).unwrap_or(MAX_SCORE))
    }
}

fn store_error(e: WorktreeError) -> StoreError {
    match e {
        WorktreeError::Store(e) => e,
        other => StoreError::Io(std::io::Error::other(other.to_string())),
    }
}

/// Per bucket, the smaller of the two byte counts, summed. git's
/// `src_copied`.
fn shared_bytes(a: &[(u32, u64)], b: &[(u32, u64)]) -> u64 {
    let (mut i, mut j, mut shared) = (0, 0, 0u64);
    while i < a.len() && j < b.len() {
        match a[i].0.cmp(&b[j].0) {
            std::cmp::Ordering::Less => i += 1,
            std::cmp::Ordering::Greater => j += 1,
            std::cmp::Ordering::Equal => {
                shared += a[i].1.min(b[j].1);
                i += 1;
                j += 1;
            }
        }
    }
    shared
}

fn signature_of<S: ObjectSource + ?Sized>(
    store: &S,
    blob: &LoadedBlob,
) -> Result<Signature, StoreError> {
    let text = !is_binary(&blob.prefix(store, BINARY_SNIFF_LEN).map_err(store_error)?);
    let mut hasher = SpanHasher::new(text);
    blob.write_content(store, &mut hasher)
        .map_err(store_error)?;
    Ok(Signature {
        size: blob.len(),
        spans: hasher.finish(),
    })
}

/// Content of a signature, fed in pieces: git's `hash_chars`.
pub(crate) struct SpanHasher {
    text: bool,
    accum1: u32,
    accum2: u32,
    len: u32,
    /// A CR that ended the last piece, held until the next byte shows
    /// whether an LF follows.
    pending_cr: bool,
    buckets: HashMap<u32, u64>,
}

impl SpanHasher {
    pub(crate) fn new(text: bool) -> Self {
        Self {
            text,
            accum1: 0,
            accum2: 0,
            len: 0,
            pending_cr: false,
            buckets: HashMap::new(),
        }
    }

    pub(crate) fn update(&mut self, data: &[u8]) {
        let mut rest = data;
        if self.pending_cr {
            self.pending_cr = false;
            if rest.first() != Some(&b'\n') {
                self.byte(b'\r');
            }
        }
        while let Some((&c, tail)) = rest.split_first() {
            rest = tail;
            if self.text && c == b'\r' {
                match rest.first() {
                    Some(b'\n') => continue,
                    None => {
                        self.pending_cr = true;
                        break;
                    }
                    Some(_) => {}
                }
            }
            self.byte(c);
        }
    }

    fn byte(&mut self, c: u8) {
        let old1 = self.accum1;
        self.accum1 = (self.accum1 << 7) ^ (self.accum2 >> 25);
        self.accum2 = (self.accum2 << 7) ^ (old1 >> 25);
        self.accum1 = self.accum1.wrapping_add(u32::from(c));
        self.len += 1;
        if self.len < MAX_SPAN && c != b'\n' {
            return;
        }
        self.flush();
    }

    fn flush(&mut self) {
        let bucket = self.accum1.wrapping_add(self.accum2.wrapping_mul(0x61)) % HASHBASE;
        *self.buckets.entry(bucket).or_default() += u64::from(self.len);
        self.len = 0;
        self.accum1 = 0;
        self.accum2 = 0;
    }

    pub(crate) fn finish(mut self) -> Vec<(u32, u64)> {
        if self.pending_cr {
            self.pending_cr = false;
            self.byte(b'\r');
        }
        if self.len > 0 {
            self.flush();
        }
        let mut spans: Vec<(u32, u64)> = self.buckets.into_iter().collect();
        spans.sort_unstable();
        spans
    }
}

impl std::io::Write for SpanHasher {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::object::{Blob, Object};
    use crate::serialize;
    use crate::store::MemorySource;
    use proptest::prelude::*;
    use std::fmt::Write as _;

    fn put(store: &mut MemorySource, object: &Object) -> Hash {
        let bytes = serialize::serialize(object).unwrap();
        let id = crate::object::object_id_from_bytes(&bytes);
        store.insert(id, bytes).unwrap();
        id
    }

    fn inline(store: &mut MemorySource, data: &[u8]) -> Hash {
        put(
            store,
            &Object::Blob(Blob {
                data: data.to_vec(),
            }),
        )
    }

    /// `data` stored as a manifest whose chunks end at `cuts`.
    fn chunked(store: &mut MemorySource, data: &[u8], cuts: &[usize]) -> Hash {
        let mut bounds: Vec<usize> = cuts.iter().map(|c| c % (data.len() + 1)).collect();
        bounds.push(0);
        bounds.push(data.len());
        bounds.sort_unstable();
        bounds.dedup();
        let chunks: Vec<(Hash, u64)> = bounds
            .windows(2)
            .map(|w| (inline(store, &data[w[0]..w[1]]), (w[1] - w[0]) as u64))
            .collect();
        let manifest = crate::object::testing::sized(0, chunks).unwrap();
        put(store, &Object::ChunkedBlob(manifest))
    }

    fn removed(path: &str, hash: Hash) -> DiffEntry {
        DiffEntry {
            path: path.into(),
            kind: DiffKind::Removed,
            old_hash: Some(hash),
            new_hash: None,
            old_mode: Some(EntryMode::Blob),
            new_mode: None,
            old_path: None,
            similarity: None,
        }
    }

    fn added(path: &str, hash: Hash) -> DiffEntry {
        DiffEntry {
            path: path.into(),
            kind: DiffKind::Added,
            old_hash: None,
            new_hash: Some(hash),
            old_mode: None,
            new_mode: Some(EntryMode::Blob),
            old_path: None,
            similarity: None,
        }
    }

    fn lines(range: std::ops::RangeInclusive<u32>) -> Vec<u8> {
        range
            .fold(String::new(), |mut s, n| {
                let _ = writeln!(s, "{n}");
                s
            })
            .into_bytes()
    }

    fn sig(data: &[u8]) -> Vec<(u32, u64)> {
        let mut h = SpanHasher::new(!is_binary(data));
        h.update(data);
        h.finish()
    }

    #[test]
    fn parse_follows_git_grammar() {
        assert_eq!(parse_rename_score("50%"), Some(30_000));
        assert_eq!(parse_rename_score("5"), Some(30_000));
        assert_eq!(parse_rename_score("50"), Some(30_000));
        assert_eq!(parse_rename_score("9"), Some(54_000));
        assert_eq!(parse_rename_score("100"), Some(6_000));
        assert_eq!(parse_rename_score("100%"), Some(MAX_SCORE));
        assert_eq!(parse_rename_score("150%"), Some(MAX_SCORE));
        assert_eq!(parse_rename_score(".95"), Some(57_000));
        assert_eq!(parse_rename_score("0.95"), Some(57_000));
        assert_eq!(parse_rename_score("0"), Some(0));
        for bad in ["", "%", "x", "5x", "50%%", "5%0", "1.2.3", "-5"] {
            assert_eq!(parse_rename_score(bad), None, "{bad}");
        }
    }

    #[test]
    fn percent_truncates_like_git() {
        assert_eq!(percent(MAX_SCORE), 100);
        assert_eq!(percent(MAX_SCORE - 1), 99);
        assert_eq!(percent(54_000), 90);
        assert_eq!(percent(0), 0);
    }

    #[test]
    fn a_text_file_skips_cr_before_lf() {
        assert_eq!(sig(b"a\r\nb\r\n"), sig(b"a\nb\n"));
        // A lone CR counts, and so does a CR at the very end.
        assert_ne!(sig(b"a\rb\n"), sig(b"ab\n"));
        assert_ne!(sig(b"a\n\r"), sig(b"a\n"));
        // A binary file keeps every CR.
        assert_ne!(sig(b"\0a\r\nb\r\n"), sig(b"\0a\nb\n"));
    }

    #[test]
    fn a_cr_split_from_its_lf_still_skips() {
        let whole = sig(b"one\r\ntwo\r\n");
        let mut h = SpanHasher::new(true);
        h.update(b"one\r");
        h.update(b"\ntwo\r");
        h.update(b"\n");
        assert_eq!(h.finish(), whole);
    }

    #[test]
    fn a_long_line_splits_into_64_byte_spans() {
        let spans = sig(&[b'a'; 130]);
        assert_eq!(spans.iter().map(|s| s.1).sum::<u64>(), 130);
    }

    #[test]
    fn one_edited_line_in_twenty_scores_90() {
        let mut store = MemorySource::default();
        let a = inline(&mut store, &lines(1..=20));
        let edited = String::from_utf8(lines(1..=20))
            .unwrap()
            .replace("\n5\n", "\nfive\n");
        let b = inline(&mut store, edited.as_bytes());
        let mut entries = vec![removed("a.txt", a), added("b.txt", b)];
        detect_renames(&store, &mut entries, &RenameOptions::default()).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].kind, DiffKind::Renamed);
        assert_eq!(entries[0].old_path.as_deref(), Some("a.txt"));
        assert_eq!(entries[0].similarity, Some(90));
    }

    #[test]
    fn the_limit_skips_the_similarity_pass_and_reports_the_need() {
        let mut store = MemorySource::default();
        let mut entries = Vec::new();
        for i in 1..=3u32 {
            let old = inline(&mut store, &lines(i..=30));
            let mut new_body = lines(i..=29);
            new_body.extend_from_slice(b"z\n");
            let new = inline(&mut store, &new_body);
            entries.push(removed(&format!("f{i}"), old));
            entries.push(added(&format!("g{i}"), new));
        }
        entries.sort_by(|a, b| a.path.cmp(&b.path));
        let original = entries.clone();
        let options = RenameOptions {
            limit: 2,
            ..RenameOptions::default()
        };
        let report = detect_renames(&store, &mut entries, &options).unwrap();
        assert_eq!(report.limit_needed, Some(3));
        assert_eq!(entries, original);
        let report = detect_renames(&store, &mut entries, &RenameOptions::default()).unwrap();
        assert_eq!(report.limit_needed, None);
        assert_eq!(entries.len(), 3);
        assert!(entries.iter().all(|e| e.similarity == Some(96)));
    }

    #[test]
    fn a_missing_object_leaves_entries_unchanged() {
        let mut store = MemorySource::default();
        let a = inline(&mut store, &lines(1..=20));
        let mut entries = vec![removed("a.txt", a), added("b.txt", [7; 32])];
        let original = entries.clone();
        assert!(detect_renames(&store, &mut entries, &RenameOptions::default()).is_err());
        assert_eq!(entries, original);
    }

    /// Random line-based content: a few distinct lines, so edits keep a
    /// share of them.
    fn content() -> impl Strategy<Value = Vec<u8>> {
        prop::collection::vec(0u16..40, 0..40).prop_map(|ns| {
            ns.iter()
                .fold(String::new(), |mut s, n| {
                    let _ = writeln!(s, "line {n}");
                    s
                })
                .into_bytes()
        })
    }

    fn renames(entries: &[DiffEntry]) -> Vec<(String, String, u8)> {
        let mut out: Vec<(String, String, u8)> = entries
            .iter()
            .filter(|e| e.kind == DiffKind::Renamed)
            .map(|e| {
                (
                    e.old_path.clone().unwrap(),
                    e.path.clone(),
                    e.similarity.unwrap(),
                )
            })
            .collect();
        out.sort();
        out
    }

    fn setup(store: &mut MemorySource, olds: &[Vec<u8>], news: &[Vec<u8>]) -> Vec<DiffEntry> {
        let mut entries = Vec::new();
        for (i, c) in olds.iter().enumerate() {
            entries.push(removed(&format!("o{i}"), inline(store, c)));
        }
        for (i, c) in news.iter().enumerate() {
            entries.push(added(&format!("n{i}"), inline(store, c)));
        }
        entries.sort_by(|a, b| a.path.cmp(&b.path));
        entries
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: std::env::var("KIT_PROPTEST_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(64),
            failure_persistence: None,
            .. ProptestConfig::default()
        })]

        /// The score reads bytes, never chunk boundaries.
        #[test]
        fn chunking_does_not_change_the_score(
            a in content(),
            b in content(),
            cuts_a in prop::collection::vec(0usize..2000, 0..6),
            cuts_b in prop::collection::vec(0usize..2000, 0..6),
        ) {
            let mut store = MemorySource::default();
            let (ia, ib) = (inline(&mut store, &a), inline(&mut store, &b));
            let (ca, cb) = (chunked(&mut store, &a, &cuts_a), chunked(&mut store, &b, &cuts_b));
            let mut plain = vec![removed("x", ia), added("y", ib)];
            let mut split = vec![removed("x", ca), added("y", cb)];
            detect_renames(&store, &mut plain, &RenameOptions::default()).unwrap();
            detect_renames(&store, &mut split, &RenameOptions::default()).unwrap();
            prop_assert_eq!(renames(&plain), renames(&split));
        }

        /// Every exact rename is still found, at 100%, and each path is in
        /// at most one pair.
        #[test]
        fn exact_renames_are_kept_and_pairs_are_one_to_one(
            olds in prop::collection::vec(content(), 1..5),
            news in prop::collection::vec(content(), 1..5),
        ) {
            let mut store = MemorySource::default();
            let mut exact = setup(&mut store, &olds, &news);
            detect_content_renames(&store, &mut exact).unwrap();
            let mut full = setup(&mut store, &olds, &news);
            detect_renames(&store, &mut full, &RenameOptions::default()).unwrap();
            let found = renames(&full);
            for e in exact.iter().filter(|e| e.kind == DiffKind::Renamed) {
                let key = (e.old_path.clone().unwrap(), e.path.clone(), 100);
                prop_assert!(found.contains(&key), "{:?} not in {:?}", key, found);
            }
            let mut srcs: Vec<&String> = found.iter().map(|r| &r.0).collect();
            let mut dsts: Vec<&String> = found.iter().map(|r| &r.1).collect();
            let (ns, nd) = (srcs.len(), dsts.len());
            srcs.dedup();
            dsts.dedup();
            dsts.sort();
            dsts.dedup();
            prop_assert_eq!(srcs.len(), ns);
            prop_assert_eq!(dsts.len(), nd);
            // Every entry is accounted for: renames take two, the rest one.
            prop_assert_eq!(full.len() + found.len(), olds.len() + news.len());
        }

        /// Swapping the sides swaps each pair and keeps its score.
        #[test]
        fn swapping_sides_swaps_the_pair(a in content(), b in content()) {
            let mut store = MemorySource::default();
            let (ia, ib) = (inline(&mut store, &a), inline(&mut store, &b));
            let mut fwd = vec![removed("x", ia), added("y", ib)];
            let mut back = vec![removed("y", ib), added("x", ia)];
            detect_renames(&store, &mut fwd, &RenameOptions::default()).unwrap();
            detect_renames(&store, &mut back, &RenameOptions::default()).unwrap();
            let fwd: Vec<(String, String, u8)> = renames(&fwd);
            let back: Vec<(String, String, u8)> = renames(&back)
                .into_iter()
                .map(|(s, d, p)| (d, s, p))
                .collect();
            prop_assert_eq!(fwd, back);
        }

        /// A higher threshold never adds a rename. The paths have distinct
        /// basenames: the basename pass raises its bar with the threshold,
        /// so with shared basenames a higher threshold can free a source for
        /// another pair, in git as here.
        #[test]
        fn raising_the_threshold_never_adds_a_rename(
            olds in prop::collection::vec(content(), 1..4),
            news in prop::collection::vec(content(), 1..4),
            low in 0u32..=MAX_SCORE,
            step in 0u32..=MAX_SCORE,
        ) {
            let high = low.saturating_add(step).min(MAX_SCORE);
            let mut store = MemorySource::default();
            let entries = setup(&mut store, &olds, &news);
            let found = |min_score: u32| {
                let mut entries = entries.clone();
                let options = RenameOptions { min_score, ..RenameOptions::default() };
                detect_renames(&store, &mut entries, &options).unwrap();
                renames(&entries)
            };
            let (at_low, at_high) = (found(low), found(high));
            for pair in &at_high {
                prop_assert!(at_low.contains(pair), "{:?} not in {:?}", pair, at_low);
            }
        }
    }
}
