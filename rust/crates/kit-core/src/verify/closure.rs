//! Full-disclosure (closure profile) verification: prove that a served
//! object set is exactly the content a commit (or remix, or tag) id
//! commits to.
//!
//! The root id is the only trust anchor. The [`ClosureManifest`] is a
//! convenience index of pack hashes — a verifier that already has the
//! packs can call [`verify_closure_packs`] directly. Wire format and
//! verifier obligations are pinned in `docs/specs/SPEC-DISCLOSURE.md`.

use std::borrow::Cow;
use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ops::Range;

use bytes::Buf as _;
use commonware_codec::Copying;
use commonware_codec::{EncodeSize, ReadExt, Write};

use crate::hash::{HASH_LEN, Hash, hash};
use crate::list_decode::read_list;
use crate::object::{Object, ObjectType};
use crate::ops::graph::{ChildKind, ClosureMode, type_bit, typed_children};
use crate::pack::{self, PackEntries, PackEntry, PackWriter, pack_key};
use crate::store::{ObjectStore, StoreError};
use crate::verify::VerifyError;

/// Hard cap on the number of packs a closure manifest may list.
pub const MAX_CLOSURE_PACKS: usize = 65_536;

/// Largest valid encoded [`ClosureManifest`]: the fixed header, a
/// four-byte length prefix and [`MAX_CLOSURE_PACKS`] pack keys.
pub const MAX_MANIFEST_BYTES: u64 = 5 + 32 + 1 + 4 + MAX_CLOSURE_PACKS as u64 * 32;

const MANIFEST_MAGIC: &[u8; 4] = b"KCLM";
const MANIFEST_VERSION: u8 = 1;
const MODE_SNAPSHOT: u8 = 0;
const MODE_HISTORY: u8 = 1;

/// Fan-out threshold (per available thread) for [`index_supplied_objects`]/
/// [`index_pack_entries`]. Deliberately much higher than
/// `pack::stage_raw_entries`'s `ENTRIES_PER_THREAD` (8): that fan-out's
/// per-entry work is a zstd decompression (tens of microseconds), so a
/// `std::thread::scope` spawn pays for itself almost immediately. Here
/// each entry is a small canonical-object deserialize plus one
/// BLAKE3/BMT id derivation — often under a microsecond — so thread
/// creation itself dominates below a few thousand entries. Measured via
/// `closure_verify_fanout` (`rust/benches/benches/`) on a 4-core box:
/// 64-1024 entries lost 2-4x to spawn overhead at `ENTRIES_PER_THREAD =
/// 8`; only past ~4096 entries did fan-out clearly win (~10%). This
/// value keeps every closure below that size on the plain sequential
/// path and only pays thread cost for genuinely large closures.
#[cfg(not(target_arch = "wasm32"))]
const CLOSURE_ENTRIES_PER_THREAD: usize = 1024;

/// Provides a pull-based source for canonical object bytes.
pub trait ObjectSource {
    /// Returns canonical bytes for `id`, or `Ok(None)` when it is absent.
    /// Implementations MUST NOT use their own identity decision as the
    /// verification result; the closure walker always deserializes the bytes
    /// and re-derives the object id itself.
    ///
    /// The walk asks for each id once, except a chunked-file manifest, which
    /// it asks for a second time to check its chunk lengths. A source must
    /// serve a manifest again, and a source that counts fetches counts it
    /// twice.
    ///
    /// # Errors
    ///
    /// Returns a source error when the requested object cannot be fetched.
    fn fetch(&mut self, id: &Hash) -> Result<Option<Cow<'_, [u8]>>, VerifyError>;
}

/// Outcome of walking a supplied object set from `root` in `mode`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClosureReport {
    /// The id the walk started from.
    pub root: Hash,
    /// Walk mode used.
    pub mode: ClosureMode,
    /// Objects whose id was recomputed and that were reachable from `root`.
    pub verified: usize,
    /// Referenced by a reachable object but not supplied, sorted.
    pub missing: Vec<Hash>,
    /// Reachable objects that do not fit: an object of a type that the
    /// reference to it forbids, a `ChunkedBlob` whose chunk lengths do not
    /// add up to its `total_size`, and, for a streaming fetch-by-id path,
    /// bytes that failed to deserialize or whose derived id did not match
    /// the requested id. Sorted by reported id. The map and pack paths
    /// preserve the `missing` + `unreferenced` result for parsable bit flips.
    pub corrupt: Vec<(Hash, String)>,
    /// Supplied but not reachable from `root`, sorted. Bytes that decode to
    /// no object are listed under the BLAKE3 of those bytes. A DA provider
    /// may legitimately serve a superset; this field is reported, not an
    /// error.
    pub unreferenced: Vec<Hash>,
    /// Whether the verifier could enumerate every supplied object to compute
    /// [`Self::unreferenced`]. Streaming sources set this to `false` and
    /// leave that list empty; map- and pack-backed paths set it to `true`.
    pub unreferenced_checked: bool,
}

impl ClosureReport {
    /// Complete iff nothing referenced is missing or corrupt.
    /// Unreferenced extras do not fail completeness.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.missing.is_empty() && self.corrupt.is_empty()
    }
}

/// Encoded closure plus the raw-only packs it indexes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClosureExport {
    /// [`ClosureManifest`] bytes.
    pub manifest: Vec<u8>,
    /// Raw-only v1 packs, in the order listed by the manifest.
    pub packs: Vec<Vec<u8>>,
}

/// Convenience index of a closure export: magic `"KCLM"`, version 1,
/// root id, mode, and the [`pack_key`] of each pack in order.
///
/// The caller supplies the trusted root to [`verify_closure_manifest`];
/// the manifest does not authenticate the objects and is not itself a
/// trust anchor. It only tells a verifier which pack hashes to expect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClosureManifest {
    /// Commit, remix, or tag id the closure is claimed to cover.
    pub root: Hash,
    /// Snapshot or history.
    pub mode: ClosureMode,
    /// `pack_key` of each pack, in export order. At most
    /// [`MAX_CLOSURE_PACKS`] entries.
    pub packs: Vec<Hash>,
}

impl ClosureManifest {
    /// Encode to `"KCLM" ‖ version ‖ root ‖ mode ‖ packs`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(5 + 32 + 1 + self.packs.encode_size());
        out.extend_from_slice(MANIFEST_MAGIC);
        out.push(MANIFEST_VERSION);
        self.root.write(&mut out);
        mode_byte(self.mode).write(&mut out);
        self.packs.write(&mut out);
        out
    }

    /// Decode, rejecting unknown version/mode and trailing bytes.
    ///
    /// # Errors
    ///
    /// [`VerifyError::ClosureManifestBadMagic`],
    /// [`VerifyError::ClosureManifestUnsupportedVersion`], or
    /// [`VerifyError::ClosureManifestMalformed`].
    pub fn decode(bytes: &[u8]) -> Result<Self, VerifyError> {
        if bytes.len() < 5 || bytes[..4] != *MANIFEST_MAGIC {
            return Err(VerifyError::ClosureManifestBadMagic);
        }
        let version = bytes[4];
        if version != MANIFEST_VERSION {
            return Err(VerifyError::ClosureManifestUnsupportedVersion(version));
        }
        let mut r = Copying(&bytes[5..]);
        let root = Hash::read(&mut r).map_err(|_| VerifyError::ClosureManifestMalformed)?;
        let mode_b = u8::read(&mut r).map_err(|_| VerifyError::ClosureManifestMalformed)?;
        let mode = match mode_b {
            MODE_SNAPSHOT => ClosureMode::Snapshot,
            MODE_HISTORY => ClosureMode::History,
            _ => return Err(VerifyError::ClosureManifestMalformed),
        };
        let packs = read_list::<Hash>(&mut r, MAX_CLOSURE_PACKS, HASH_LEN, &())
            .map_err(|_| VerifyError::ClosureManifestMalformed)?;
        if r.has_remaining() {
            return Err(VerifyError::ClosureManifestMalformed);
        }
        Ok(Self { root, mode, packs })
    }
}

fn mode_byte(mode: ClosureMode) -> u8 {
    match mode {
        ClosureMode::Snapshot => MODE_SNAPSHOT,
        ClosureMode::History => MODE_HISTORY,
    }
}

struct MapObjectSource<'a> {
    objects: BTreeMap<Hash, &'a [u8]>,
}

impl ObjectSource for MapObjectSource<'_> {
    fn fetch(&mut self, id: &Hash) -> Result<Option<Cow<'_, [u8]>>, VerifyError> {
        Ok(self.objects.get(id).map(|bytes| Cow::Borrowed(*bytes)))
    }
}

struct PackObjectSource<'a> {
    packs: Vec<&'a [u8]>,
    index: BTreeMap<Hash, (usize, Range<usize>)>,
}

impl ObjectSource for PackObjectSource<'_> {
    fn fetch(&mut self, id: &Hash) -> Result<Option<Cow<'_, [u8]>>, VerifyError> {
        let Some((pack_index, range)) = self.index.get(id) else {
            return Ok(None);
        };
        Ok(Some(Cow::Borrowed(&self.packs[*pack_index][range.clone()])))
    }
}

impl ObjectSource for &ObjectStore {
    fn fetch(&mut self, id: &Hash) -> Result<Option<Cow<'_, [u8]>>, VerifyError> {
        // `read_raw_for_verification` is deliberately used instead of
        // `ObjectStore::read`: the latter discards mismatching bytes, while
        // this walker must see them so it can report `corrupt` under the
        // requested id. The walker is the only identity authority here.
        match (*self).read_raw_for_verification(id) {
            Ok(bytes) => Ok(Some(Cow::Owned(bytes))),
            Err(StoreError::ObjectNotFound(_)) => Ok(None),
            Err(error) => Err(VerifyError::Store(error)),
        }
    }
}

/// What the shared walker does when a root turns out not to be a
/// commit, remix or tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RootRule {
    /// Abort with [`VerifyError::ClosureRootWrongType`] (closure callers).
    Fail,
    /// Record it in [`Walk::bad_roots`] and keep walking (push verification).
    Record,
}

const TYPE_CONFLICT: &str = "referenced as object types that no single object can have";

/// What the walk knows about one reached id.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Reach {
    /// Object types that every edge into the id allows ([`ChildKind::mask`]).
    allowed: u8,
    /// Content length when the id decoded as a `Blob`, or when the caller's
    /// frontier reported it ([`Known::Blob`]).
    blob_len: Option<u64>,
    /// The frontier stopped at the id without a content length
    /// ([`Known::Yes`]).
    frontier: bool,
}

/// The caller's answer for one id at the frontier of [`crate::verify::verify_push`] and the
/// other closure walks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Known {
    /// Not known: the walk fetches it.
    No,
    /// Known, and its closure was verified: a frontier stop. The walk cannot
    /// check a chunk answered this way against its span, so a chunk of a
    /// manifest the walk reads must be answered [`Known::Blob`] instead; a
    /// manifest with a chunk answered `Yes` is reported corrupt.
    Yes,
    /// Known, and it is a `Blob` of this content length: a frontier stop
    /// that also lets the walk check the length against the span of the
    /// chunk that names it.
    Blob(u64),
}

/// Outcome of the shared [`walk`].
#[derive(Debug, Default)]
pub(crate) struct Walk {
    /// Fetched objects whose id was re-derived and matched.
    pub(crate) verified: usize,
    /// Frontier stops: ids for which `known` held; never fetched.
    pub(crate) skipped_known: usize,
    /// Referenced (or a root) but absent from the source, sorted.
    pub(crate) missing: Vec<Hash>,
    /// Undecodable or mis-identified bytes, sorted by requested id.
    pub(crate) corrupt: Vec<(Hash, String)>,
    /// Roots that are not a commit/remix/tag ([`RootRule::Record`]), sorted.
    pub(crate) bad_roots: Vec<(Hash, ObjectType)>,
    /// Every id the walk reached, including frontier stops.
    pub(crate) visited: BTreeMap<Hash, Reach>,
    /// Largest queue length seen, so tests can pin that an id is queued
    /// at most once.
    #[cfg(test)]
    pub(crate) peak_queue: usize,
}

/// The one closure BFS. Every closure and push verifier in this crate
/// walks through here, taking its edges from [`children`](crate::ops::graph::children)`(obj, mode)`.
///
/// Starting from every id in `roots`, each id is queued and visited at
/// most once (an id is marked reached when it is queued, so a tree whose
/// entries repeat one id does not grow the queue):
/// - `known(id)` not [`Known::No`]: a frontier stop, counted and neither
///   fetched nor descended;
/// - otherwise fetched once from `source`, deserialized and re-hashed
///   ([`crate::object::id_from_object`]); absent → `missing`, bad bytes
///   or a different derived id → `corrupt` (not descended);
/// - a root must be a commit/remix/tag (`root_rule`);
/// - `visit` sees each verified object, then its children are queued and
///   its bytes dropped;
/// - after the walk, each manifest is fetched a second time, one at a time,
///   and checked for its chunk lengths.
///
/// `known` is the caller's frontier contract: it may hold only for ids
/// whose whole closure in `mode` was already verified *in the same
/// repository*. See [`crate::verify::verify_push`].
///
/// # Errors
///
/// [`VerifyError::TooManyClosureObjects`] once more than
/// [`pack::MAX_ENTRIES`] distinct ids are reached (checked as they are
/// queued, which bounds the queue), [`VerifyError::ClosureRootWrongType`] under
/// [`RootRule::Fail`], a source error, or the first error `visit` returns.
pub(crate) fn walk(
    roots: &[Hash],
    mode: ClosureMode,
    source: &mut impl ObjectSource,
    mut known: impl FnMut(&Hash) -> Known,
    root_rule: RootRule,
    mut visit: impl FnMut(&Hash, &Object) -> Result<(), VerifyError>,
) -> Result<Walk, VerifyError> {
    let root_set: BTreeSet<Hash> = roots.iter().copied().collect();
    let mut out = Walk::default();
    let mut queue: VecDeque<Hash> = VecDeque::new();
    // Chunked blobs whose chunk lengths are checked once every chunk is read.
    // Only their ids are kept: each manifest is read again, one at a time.
    let mut manifests: Vec<Hash> = Vec::new();
    for root in roots {
        reach(&mut out, &mut queue, *root, ChildKind::Any)?;
    }

    while let Some(id) = queue.pop_front() {
        match known(&id) {
            Known::No => {}
            answer => {
                out.skipped_known += 1;
                if let Some(reach) = out.visited.get_mut(&id) {
                    match answer {
                        // A known blob is held to the edges into it as a
                        // blob the walk reads is.
                        Known::Blob(len) => {
                            if admit_type(reach, &mut out.corrupt, id, ObjectType::Blob) {
                                reach.blob_len = Some(len);
                            }
                        }
                        _ => reach.frontier = true,
                    }
                }
                continue;
            }
        }

        let Some(bytes) = source.fetch(&id)? else {
            out.missing.push(id);
            continue;
        };
        let object = match decode_checked(&id, bytes.as_ref()) {
            Ok(object) => object,
            Err(reason) => {
                out.corrupt.push((id, reason));
                continue;
            }
        };
        if root_set.contains(&id) {
            match &object {
                Object::Commit(_) | Object::Remix(_) | Object::Tag(_) => {}
                other => match root_rule {
                    RootRule::Fail => {
                        return Err(VerifyError::ClosureRootWrongType(other.object_type()));
                    }
                    RootRule::Record => out.bad_roots.push((id, other.object_type())),
                },
            }
        }
        let Some(reach_entry) = out.visited.get_mut(&id) else {
            continue;
        };
        if !admit_type(reach_entry, &mut out.corrupt, id, object.object_type()) {
            continue;
        }
        if let Object::Blob(blob) = &object {
            reach_entry.blob_len = Some(blob.data.len() as u64);
        }
        visit(&id, &object)?;

        let child_ids = typed_children(&object, mode);
        if matches!(object, Object::ChunkedBlob(_)) {
            manifests.push(id);
        }
        out.verified += 1;
        drop(object);
        drop(bytes);
        for (child, kind) in child_ids {
            reach(&mut out, &mut queue, child, kind)?;
        }
    }

    check_chunk_lengths(&mut out, &manifests, source)?;

    out.missing.sort_unstable();
    out.missing.dedup();
    out.corrupt.sort_by_key(|(id, _)| *id);
    out.bad_roots.sort_by_key(|(id, _)| *id);
    Ok(out)
}

/// Decode `bytes` and check that they hash to `id`. The error is the reason
/// the walk reports under `id`.
fn decode_checked(id: &Hash, bytes: &[u8]) -> Result<Object, String> {
    let object = crate::serialize::deserialize(bytes).map_err(|error| error.to_string())?;
    let derived = crate::object::id_from_object(&object, bytes);
    if derived != *id {
        return Err(format!(
            "object bytes hash to {}, expected {}",
            crate::hash::to_hex(&derived),
            crate::hash::to_hex(id)
        ));
    }
    Ok(object)
}

/// Hold an id of object type `ty` to the types its edges allow. Returns
/// whether `ty` is allowed, and narrows the allowed set to it. A refusal is
/// reported once, as corrupt, and empties the set; a set an earlier
/// disagreement emptied was reported then.
fn admit_type(
    reach: &mut Reach,
    corrupt: &mut Vec<(Hash, String)>,
    id: Hash,
    ty: ObjectType,
) -> bool {
    let bit = type_bit(ty);
    if reach.allowed & bit == 0 {
        if reach.allowed != 0 {
            corrupt.push((
                id,
                format!("{ty:?} object where the referencing entry requires another type"),
            ));
            reach.allowed = 0;
        }
        return false;
    }
    reach.allowed &= bit;
    true
}

/// Mark `id` reached through an edge that allows `kind`. An id joins
/// `out.visited` when first queued and is never queued again. Dequeue order
/// is therefore exactly the order of first occurrence a queue with
/// duplicates would have produced, so the fetch sequence is unchanged; only
/// repeats are no longer stored. A repeat still narrows the types the id may
/// have, so an id reached through two edges that disagree is reported once.
fn reach(
    out: &mut Walk,
    queue: &mut VecDeque<Hash>,
    id: Hash,
    kind: ChildKind,
) -> Result<(), VerifyError> {
    let full = out.visited.len() >= pack::MAX_ENTRIES as usize;
    match out.visited.entry(id) {
        Entry::Vacant(slot) => {
            if full {
                return Err(VerifyError::TooManyClosureObjects);
            }
            slot.insert(Reach {
                allowed: kind.mask(),
                blob_len: None,
                frontier: false,
            });
            queue.push_back(id);
            #[cfg(test)]
            {
                out.peak_queue = out.peak_queue.max(queue.len());
            }
        }
        Entry::Occupied(mut slot) => {
            let reach = slot.get_mut();
            let before = reach.allowed;
            reach.allowed &= kind.mask();
            if before != 0 && reach.allowed == 0 {
                out.corrupt.push((id, TYPE_CONFLICT.to_string()));
            }
        }
    }
    Ok(())
}

/// Report each chunked blob that has a chunk whose content length is not the
/// length of its span, `end - start` (SPEC-OBJECTS §7). Every chunk is checked
/// on its own, in both layouts, and the lowest wrong index is reported, even
/// when another chunk of the manifest is missing. A chunk that was not read as
/// a blob is not measured: it is already missing or corrupt. A chunk the
/// frontier stopped at without a length ([`Known::Yes`]) cannot be checked, so
/// its manifest is reported corrupt.
///
/// The walk keeps only the ids of its manifests. Each is fetched again here
/// and held alone while it is checked, so the walk holds one manifest at a
/// time, not every manifest of the closure.
fn check_chunk_lengths(
    out: &mut Walk,
    manifests: &[Hash],
    source: &mut impl ObjectSource,
) -> Result<(), VerifyError> {
    for id in manifests {
        let id = *id;
        let Some(bytes) = source.fetch(&id)? else {
            out.corrupt
                .push((id, "manifest absent when its chunks were checked".into()));
            continue;
        };
        let manifest = match decode_checked(&id, bytes.as_ref()) {
            Ok(Object::ChunkedBlob(manifest)) => manifest,
            Ok(_) => {
                out.corrupt.push((
                    id,
                    "manifest changed type when its chunks were checked".into(),
                ));
                continue;
            }
            Err(reason) => {
                out.corrupt.push((id, reason));
                continue;
            }
        };
        drop(bytes);
        let mut wrong = None;
        let mut unconfirmed = None;
        for (index, (chunk, end)) in (0u32..).zip(manifest.entries()) {
            let reach = out.visited.get(&chunk);
            match reach.and_then(|r| r.blob_len) {
                Some(len) => {
                    let span_len = end - manifest.span(index).map_or(0, |(start, _)| start);
                    if wrong.is_none() && len != span_len {
                        wrong = Some((index, len, span_len));
                    }
                }
                None if reach.is_some_and(|r| r.frontier) => {
                    unconfirmed.get_or_insert(index);
                }
                None => {}
            }
        }
        if let Some((index, len, span_len)) = wrong {
            out.corrupt.push((
                id,
                format!("chunk {index} holds {len} bytes, but its span is {span_len} bytes"),
            ));
        } else if let Some(index) = unconfirmed {
            out.corrupt.push((
                id,
                format!("chunk {index} was reported known without its length, so its span cannot be checked"),
            ));
        }
    }
    Ok(())
}

/// Single-root closure walk: [`walk`] with no frontier, no visitor and a
/// hard root-type rule.
fn walk_closure(
    root: &Hash,
    mode: ClosureMode,
    source: &mut impl ObjectSource,
) -> Result<(ClosureReport, BTreeMap<Hash, Reach>), VerifyError> {
    let walked = walk(
        std::slice::from_ref(root),
        mode,
        source,
        |_| Known::No,
        RootRule::Fail,
        |_, _| Ok(()),
    )?;
    Ok((
        ClosureReport {
            root: *root,
            mode,
            verified: walked.verified,
            missing: walked.missing,
            corrupt: walked.corrupt,
            unreferenced: Vec::new(),
            unreferenced_checked: false,
        },
        walked.visited,
    ))
}

/// Supplied ids the walk did not reach, plus each undecodable item under the
/// BLAKE3 of its bytes, sorted. No id derives from bytes that do not decode,
/// so such an item is never referenced.
fn unreferenced_ids<'a>(
    supplied: impl Iterator<Item = &'a Hash>,
    undecodable: Vec<Hash>,
    visited: &BTreeMap<Hash, Reach>,
) -> Vec<Hash> {
    let mut out: Vec<Hash> = supplied
        .filter(|id| !visited.contains_key(*id))
        .copied()
        .chain(undecodable)
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

/// Result of indexing [`verify_closure`]'s supplied object set:
/// derived-id → bytes, plus the BLAKE3 of each item that does not decode.
type SuppliedIndex<'a> = (BTreeMap<Hash, &'a [u8]>, Vec<Hash>);

/// Result of indexing [`verify_closure_packs`]'s recorded entries:
/// derived-id → `(pack_index, payload_range)`, plus anything that
/// the BLAKE3 of each entry that does not decode.
type PackIndex = (BTreeMap<Hash, (usize, Range<usize>)>, Vec<Hash>);

/// Deserialize `bytes` as a canonical object and derive its id, or
/// return the BLAKE3 of the raw bytes when they do not decode. Pure and
/// independent per call — the per-item step shared by every branch
/// below, and by [`walk_closure`]'s own (deliberately separate)
/// re-derivation.
fn classify_object(bytes: &[u8]) -> Result<Hash, Hash> {
    match crate::serialize::deserialize(bytes) {
        Err(_) => Err(hash(bytes)),
        Ok(obj) => Ok(crate::object::id_from_object(&obj, bytes)),
    }
}

/// Indexes `verify_closure`'s supplied object set by derived id: a
/// pure map over independent byte slices, same shape as
/// `pack::stage_raw_entries`'s raw-entry fan-out. Runs a plain
/// sequential loop below a small-set threshold, and fans out across a
/// scoped thread pool at or above it (native builds only — wasm32 has
/// no threads).
fn index_supplied_objects<'a>(items: &[&'a [u8]]) -> SuppliedIndex<'a> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        let threads = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
        if threads > 1 && items.len() >= CLOSURE_ENTRIES_PER_THREAD.saturating_mul(threads) {
            return index_supplied_objects_parallel(items, threads);
        }
    }
    index_supplied_objects_sequential(items)
}

fn index_supplied_objects_sequential<'a>(items: &[&'a [u8]]) -> SuppliedIndex<'a> {
    let mut by_id = BTreeMap::new();
    let mut undecodable = Vec::new();
    for bytes in items {
        match classify_object(bytes) {
            Ok(id) => {
                by_id.insert(id, *bytes);
            }
            Err(id) => undecodable.push(id),
        }
    }
    (by_id, undecodable)
}

/// Parallel branch of [`index_supplied_objects`]: split `items` into
/// `threads` contiguous chunks and process each chunk on its own
/// scoped thread. `std::thread::scope` (not a persistent pool) is
/// deliberate — `kit-core` stays dependency-neutral and wasm-clean
/// (see `pack::stage_raw_entries_parallel`'s doc for the same
/// reasoning) — and this call is already gated by
/// [`index_supplied_objects`]'s threshold so the per-call spawn cost is
/// only paid when there is enough work to amortize it.
#[cfg(not(target_arch = "wasm32"))]
fn index_supplied_objects_parallel<'a>(items: &[&'a [u8]], threads: usize) -> SuppliedIndex<'a> {
    let chunk_size = items.len().div_ceil(threads).max(1);
    let mut by_id = BTreeMap::new();
    let mut undecodable = Vec::new();
    std::thread::scope(|scope| {
        let handles: Vec<_> = items
            .chunks(chunk_size)
            .map(|chunk| {
                scope.spawn(move || {
                    chunk
                        .iter()
                        .map(|bytes| classify_object(bytes).map(|id| (id, *bytes)))
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        for handle in handles {
            for result in handle
                .join()
                .expect("closure object indexing worker thread panicked")
            {
                match result {
                    Ok((id, bytes)) => {
                        by_id.insert(id, bytes);
                    }
                    Err(id) => undecodable.push(id),
                }
            }
        }
    });
    (by_id, undecodable)
}

/// Indexes `verify_closure_packs`'s recorded `(pack_index,
/// payload_range)` entries by derived id — the pack-backed
/// counterpart of [`index_supplied_objects`], same threshold and
/// `std::thread::scope` shape.
fn index_pack_entries(packs: &[&[u8]], refs: &[(usize, Range<usize>)]) -> PackIndex {
    #[cfg(not(target_arch = "wasm32"))]
    {
        let threads = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
        if threads > 1 && refs.len() >= CLOSURE_ENTRIES_PER_THREAD.saturating_mul(threads) {
            return index_pack_entries_parallel(packs, refs, threads);
        }
    }
    index_pack_entries_sequential(packs, refs)
}

fn index_pack_entries_sequential(packs: &[&[u8]], refs: &[(usize, Range<usize>)]) -> PackIndex {
    let mut index = BTreeMap::new();
    let mut undecodable = Vec::new();
    for (pack_index, range) in refs {
        let bytes = &packs[*pack_index][range.clone()];
        match classify_object(bytes) {
            Ok(id) => {
                index.insert(id, (*pack_index, range.clone()));
            }
            Err(id) => undecodable.push(id),
        }
    }
    (index, undecodable)
}

#[cfg(not(target_arch = "wasm32"))]
fn index_pack_entries_parallel(
    packs: &[&[u8]],
    refs: &[(usize, Range<usize>)],
    threads: usize,
) -> PackIndex {
    let chunk_size = refs.len().div_ceil(threads).max(1);
    let mut index = BTreeMap::new();
    let mut undecodable = Vec::new();
    std::thread::scope(|scope| {
        let handles: Vec<_> = refs
            .chunks(chunk_size)
            .map(|chunk| {
                scope.spawn(move || {
                    chunk
                        .iter()
                        .map(|(pack_index, range)| {
                            let bytes = &packs[*pack_index][range.clone()];
                            classify_object(bytes).map(|id| (id, *pack_index, range.clone()))
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        for handle in handles {
            for result in handle
                .join()
                .expect("closure pack indexing worker thread panicked")
            {
                match result {
                    Ok((id, pack_index, range)) => {
                        index.insert(id, (pack_index, range));
                    }
                    Err(id) => undecodable.push(id),
                }
            }
        }
    });
    (index, undecodable)
}

/// Walks a closure by fetching each requested id only when the BFS reaches it.
/// Bytes are deserialized, re-hashed, and discarded after their child ids are
/// extracted, so the walk retains object ids rather than the complete object
/// set. A fetch-by-id source that returns bytes whose derived id differs from
/// the requested id reports `corrupt` under the requested id; this is
/// intentionally different from the map path's
/// `missing` + `unreferenced` classification for a parsable bit flip.
///
/// The root itself missing yields `missing = [root]`, `verified = 0`. The
/// root, when present and correctly identified, MUST deserialize as a
/// `Commit`, `Remix`, or `Tag`. Since a streaming source cannot enumerate
/// objects it never fetched, the returned report has an empty `unreferenced`
/// list and `unreferenced_checked = false`.
///
/// # Errors
///
/// [`VerifyError::TooManyClosureObjects`] if the walk visits more than
/// [`pack::MAX_ENTRIES`] ids; [`VerifyError::ClosureRootWrongType`] if the
/// root is present but not a commit/remix/tag; or a source error.
pub fn verify_closure_streaming(
    root: &Hash,
    mode: ClosureMode,
    source: &mut impl ObjectSource,
) -> Result<ClosureReport, VerifyError> {
    walk_closure(root, mode, source).map(|(report, _visited)| report)
}

/// Verifies a closure by reading the local [`ObjectStore`] on demand.
///
/// The source reads only ids reached by the BFS. It uses the store's raw
/// capped read so a file whose bytes no longer match its filename remains
/// available to the walker; the walker then re-derives the id and reports a
/// hash mismatch as `corrupt` under the requested id. This is the deliberate
/// store-backed counterpart to the map path, whose parsable bit-flip behavior
/// remains `missing` plus `unreferenced`.
///
/// # Errors
///
/// Returns [`VerifyError::TooManyClosureObjects`] if the walk visits more than
/// [`pack::MAX_ENTRIES`] ids, [`VerifyError::ClosureRootWrongType`] if the root
/// is not a commit/remix/tag, or [`VerifyError::Store`] for a store failure.
pub fn verify_closure_store(
    store: &ObjectStore,
    root: &Hash,
    mode: ClosureMode,
) -> Result<ClosureReport, VerifyError> {
    let mut source = store;
    verify_closure_streaming(root, mode, &mut source)
}

/// Re-hashes every supplied object and walks from `root` with
/// [`children`](crate::ops::graph::children)`(obj, mode)`. Store-less: the caller provides the
/// object bytes. The map path is implemented by the same
/// pull-based walker as [`verify_closure_streaming`], with an in-memory
/// source keyed by each successfully derived id, followed by the
/// supplied-set `unreferenced` pass.
///
/// Bytes that fail to deserialize are `unreferenced` under the BLAKE3 of
/// those bytes. A parsable bit flip is `missing` (the requested id)
/// plus `unreferenced` (the derived id). The root itself missing yields `missing = [root]`,
/// `verified = 0`. The root, when present, MUST deserialize as a
/// `Commit`, `Remix`, or `Tag`.
///
/// # Errors
///
/// [`VerifyError::TooManyClosureObjects`] if more than
/// [`pack::MAX_ENTRIES`] objects are supplied;
/// [`VerifyError::ClosureRootWrongType`] if the root is present but
/// not a commit/remix/tag.
pub fn verify_closure<'a>(
    root: &Hash,
    mode: ClosureMode,
    objects: impl IntoIterator<Item = &'a [u8]>,
) -> Result<ClosureReport, VerifyError> {
    // Bail as soon as the cap is exceeded rather than draining `objects`
    // first: it's a caller-supplied `IntoIterator`, so for an adversarial
    // or merely huge lazy source this keeps the old per-item fail-fast
    // bound instead of paying to produce every item before rejecting.
    let mut items: Vec<&'a [u8]> = Vec::new();
    for (supplied, bytes) in objects.into_iter().enumerate() {
        if supplied >= pack::MAX_ENTRIES as usize {
            return Err(VerifyError::TooManyClosureObjects);
        }
        items.push(bytes);
    }
    let (by_id, undecodable) = index_supplied_objects(&items);

    let mut source = MapObjectSource { objects: by_id };
    let (mut report, visited) = walk_closure(root, mode, &mut source)?;
    report.unreferenced = unreferenced_ids(source.objects.keys(), undecodable, &visited);
    report.unreferenced_checked = true;
    Ok(report)
}

/// Iterates each pack with [`PackEntries`]. Any delta or compressed
/// entry is a profile violation — the closure profile is raw-only so a
/// wasm verifier (no `pack-zstd`) can consume it. Raw payloads are indexed
/// by their derived ids and served as borrowed slices into the original
/// pack buffers.
///
/// # Errors
///
/// [`VerifyError::ClosureProfileViolation`] on a non-`0x00` entry;
/// [`VerifyError::Pack`] on framing errors; plus
/// [`verify_closure`]'s errors.
pub fn verify_closure_packs(
    root: &Hash,
    mode: ClosureMode,
    packs: &[&[u8]],
) -> Result<ClosureReport, VerifyError> {
    // Step 1 (sequential, cheap): walk each pack's frames to validate
    // the raw-only profile and record every entry's `(pack_index,
    // payload_range)` in encounter order. This never decompresses —
    // `is_raw_only` (computed by `PackEntries::new`'s header scan) is
    // required before the loop even starts, so every entry this loop
    // reaches is already known to be an uncompressed `0x00` frame; the
    // `PackEntry::Delta` arm below is unreachable in practice and kept
    // only as defense in depth.
    let mut refs: Vec<(usize, Range<usize>)> = Vec::new();
    let mut supplied = 0usize;
    for (pack_index, pack) in packs.iter().enumerate() {
        let entries = PackEntries::new(pack)?;
        if !entries.is_raw_only() {
            return Err(VerifyError::ClosureProfileViolation {
                pack_index,
                entry_index: entries.first_non_raw_index().unwrap_or(0) as usize,
            });
        }
        let mut entries = entries;
        let mut entry_index = 0usize;
        while let Some(entry) = entries.next() {
            if supplied >= pack::MAX_ENTRIES as usize {
                return Err(VerifyError::TooManyClosureObjects);
            }
            supplied += 1;
            let payload_range = entries
                .last_payload_range()
                .ok_or(VerifyError::Pack(pack::PackError::UnexpectedEof))?;
            match entry? {
                PackEntry::Raw { .. } => refs.push((pack_index, payload_range)),
                PackEntry::Delta { .. } => {
                    return Err(VerifyError::ClosureProfileViolation {
                        pack_index,
                        entry_index,
                    });
                }
            }
            entry_index += 1;
        }
    }

    // Step 2 (fanned out above a size threshold): deserialize + derive
    // the id of every recorded entry — the actual CPU-bound work
    // (canonical decode + a BLAKE3/BMT id derivation per object),
    // independent per entry since each only reads its own payload
    // range.
    let (index, undecodable) = index_pack_entries(packs, &refs);
    let mut source = PackObjectSource {
        packs: packs.to_vec(),
        index,
    };
    let (mut report, visited) = walk_closure(root, mode, &mut source)?;
    report.unreferenced = unreferenced_ids(source.index.keys(), undecodable, &visited);
    report.unreferenced_checked = true;
    Ok(report)
}

/// Decode the manifest, reject it if its `root` is not `expected_root`,
/// check pack count and `pack_key` equality in order, then
/// [`verify_closure_packs`]. `mode` comes from the manifest (it only
/// widens or narrows the walk; the report carries it). The caller
/// supplies the trusted root; the manifest is a locator, never a
/// trust anchor.
///
/// # Errors
///
/// Manifest decode errors, [`VerifyError::ClosureRootMismatch`],
/// [`VerifyError::ClosurePackCountMismatch`],
/// [`VerifyError::ClosurePackKeyMismatch`], plus
/// [`verify_closure_packs`]'s errors.
pub fn verify_closure_manifest(
    expected_root: &Hash,
    manifest: &[u8],
    packs: &[&[u8]],
) -> Result<ClosureReport, VerifyError> {
    let decoded = ClosureManifest::decode(manifest)?;
    if decoded.root != *expected_root {
        return Err(VerifyError::ClosureRootMismatch {
            expected: *expected_root,
            got: decoded.root,
        });
    }
    if decoded.packs.len() != packs.len() {
        return Err(VerifyError::ClosurePackCountMismatch {
            expected: decoded.packs.len(),
            got: packs.len(),
        });
    }
    for (index, (want, got)) in decoded.packs.iter().zip(packs.iter()).enumerate() {
        if pack_key(got) != *want {
            return Err(VerifyError::ClosurePackKeyMismatch { index });
        }
    }
    verify_closure_packs(&decoded.root, decoded.mode, packs)
}

/// Walk `store` in `mode`, write raw-only packs of the reachable
/// objects in sorted id order, and return the encoded manifest plus
/// packs. Native-only (`ObjectStore`).
///
/// Packs split before a pack would pass a limit a reader applies, see
/// [`pack::PackFill::seals_before`]: [`pack::MAX_TOTAL_PAYLOAD`] of payload,
/// [`crate::protocol::PACK_BODY_LIMIT`] bytes in all or [`pack::MAX_WRITE_ENTRIES`]
/// entries.
///
/// # Errors
///
/// Store errors, [`crate::pack::PackError`] from the raw-only writer, or
/// [`VerifyError::ClosureRootWrongType`] if `root` is not a
/// commit/remix/tag.
pub fn export_closure(
    store: &ObjectStore,
    root: &Hash,
    mode: ClosureMode,
) -> Result<ClosureExport, VerifyError> {
    export_closure_with_limits(
        store,
        root,
        mode,
        pack::MAX_TOTAL_PAYLOAD,
        pack::MAX_ENTRIES,
    )
}

pub(crate) fn export_closure_with_limits(
    store: &ObjectStore,
    root: &Hash,
    mode: ClosureMode,
    max_pack_payload: u64,
    max_entries: u32,
) -> Result<ClosureExport, VerifyError> {
    let obj = store.read_object(root)?;
    match &obj {
        Object::Commit(_) | Object::Remix(_) | Object::Tag(_) => {}
        other => return Err(VerifyError::ClosureRootWrongType(other.object_type())),
    }

    let hashes = match mode {
        ClosureMode::Snapshot => crate::ops::graph::reachable_snapshot(store, root)?,
        ClosureMode::History => crate::ops::graph::reachable_objects(store, root)?,
    };

    let mut packs: Vec<Vec<u8>> = Vec::new();
    let mut writer = PackWriter::new_raw_only();
    for h in &hashes {
        let bytes = store.read(h)?;
        // A raw-only pack stores every object as is, so a reader decodes none.
        if pack::PackFill::of(&writer).seals_before(
            pack::Incoming::raw(bytes.len() as u64, 0),
            max_pack_payload,
            None,
            max_entries as usize,
        ) {
            packs.push(writer.finish()?);
            writer = PackWriter::new_raw_only();
        }
        writer.push_raw(*h, &bytes)?;
    }
    if writer.entry_count() > 0 {
        packs.push(writer.finish()?);
    }
    if packs.len() > MAX_CLOSURE_PACKS {
        return Err(VerifyError::TooManyClosureObjects);
    }

    let manifest = ClosureManifest {
        root: *root,
        mode,
        packs: packs.iter().map(|p| pack_key(p)).collect(),
    };
    Ok(ClosureExport {
        manifest: manifest.encode(),
        packs,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::borrow::Cow;
    use std::fs;

    use crate::hash::ZERO;
    use crate::layout::RepoLayout;
    use crate::object::{Blob, Commit, EntryMode, Identity, Object, ObjectType, Tree, TreeEntry};
    use crate::object::{Remix, Tag};
    use crate::sign::{KeyPair, sign_commit, sign_remix, sign_tag};

    #[test]
    fn largest_manifest_fits_the_manifest_byte_limit() {
        let manifest = ClosureManifest {
            root: ZERO,
            mode: ClosureMode::History,
            packs: vec![ZERO; MAX_CLOSURE_PACKS],
        };
        let encoded = manifest.encode();
        assert!(encoded.len() as u64 <= MAX_MANIFEST_BYTES);
        assert_eq!(ClosureManifest::decode(&encoded).unwrap(), manifest);
    }
    use crate::worktree::store_file_object;
    use tempfile::TempDir;

    fn fixture() -> (TempDir, ObjectStore, Hash, Hash) {
        let dir = TempDir::new().unwrap();
        let store = ObjectStore::init(&RepoLayout::single(dir.path())).unwrap();
        let blob = store_file_object(&store, b"hello closure").unwrap();
        let tree = Tree {
            entries: vec![TreeEntry {
                name: b"f.txt".to_vec(),
                mode: EntryMode::Blob,
                object_hash: blob,
            }],
        };
        let tree_hash = store
            .write(&crate::serialize::serialize(&Object::Tree(tree)).unwrap())
            .unwrap();
        let kp = KeyPair::from_seed([0x11; 32]);
        let mut commit = Commit {
            tree_hash,
            parents: vec![],
            author: Identity::ed25519(kp.public.0),
            signer: kp.public.0,
            message: b"closure unit".to_vec(),
            timestamp: 1,
            message_hash: ZERO,
            content_digest: ZERO,
            signature: [0u8; 64],
        };
        commit.signature = sign_commit(&commit, &kp).unwrap().0;
        let commit_id = store
            .write(&crate::serialize::serialize(&Object::Commit(commit)).unwrap())
            .unwrap();
        (dir, store, commit_id, blob)
    }

    fn two_commit_fixture() -> (TempDir, ObjectStore, Hash, Hash) {
        let (dir, store, c1, _) = fixture();
        let blob2 = store_file_object(&store, b"second commit only").unwrap();
        let tree2 = Tree {
            entries: vec![TreeEntry {
                name: b"g.txt".to_vec(),
                mode: EntryMode::Blob,
                object_hash: blob2,
            }],
        };
        let tree2_hash = store
            .write(&crate::serialize::serialize(&Object::Tree(tree2)).unwrap())
            .unwrap();
        let kp = KeyPair::from_seed([0x11; 32]);
        let mut commit = Commit {
            tree_hash: tree2_hash,
            parents: vec![c1],
            author: Identity::ed25519(kp.public.0),
            signer: kp.public.0,
            message: b"child".to_vec(),
            timestamp: 2,
            message_hash: ZERO,
            content_digest: ZERO,
            signature: [0u8; 64],
        };
        commit.signature = sign_commit(&commit, &kp).unwrap().0;
        let c2 = store
            .write(&crate::serialize::serialize(&Object::Commit(commit)).unwrap())
            .unwrap();
        (dir, store, c1, c2)
    }

    struct CountingSource {
        objects: BTreeMap<Hash, Vec<u8>>,
        missing: BTreeSet<Hash>,
        fetches: BTreeMap<Hash, usize>,
    }

    impl CountingSource {
        fn from_store(store: &ObjectStore) -> Self {
            let mut objects = BTreeMap::new();
            for id in store.iter_object_hashes().unwrap() {
                objects.insert(id, store.read(&id).unwrap());
            }
            Self {
                objects,
                missing: BTreeSet::new(),
                fetches: BTreeMap::new(),
            }
        }

        fn fetched_ids(&self) -> BTreeSet<Hash> {
            self.fetches.keys().copied().collect()
        }
    }

    impl ObjectSource for CountingSource {
        fn fetch(&mut self, id: &Hash) -> Result<Option<Cow<'_, [u8]>>, VerifyError> {
            *self.fetches.entry(*id).or_default() += 1;
            if self.missing.contains(id) {
                return Ok(None);
            }
            let bytes = self
                .objects
                .get(id)
                .unwrap_or_else(|| panic!("unexpected object fetch: {}", crate::hash::to_hex(id)));
            Ok(Some(Cow::Borrowed(bytes)))
        }
    }

    #[test]
    fn repeated_child_ids_are_queued_once() {
        // A tree whose entries all name one blob (plus a commit naming the
        // tree twice over its parents) must not grow the queue per
        // reference: every id is queued once, fetched once, and the fetch
        // order is the first-occurrence BFS order.
        const ENTRIES: usize = 10_000;
        let blob_bytes = crate::serialize::serialize(&Object::Blob(Blob {
            data: b"shared".to_vec(),
        }))
        .unwrap();
        let blob = hash(&blob_bytes);
        let tree = Object::Tree(Tree {
            entries: (0..ENTRIES)
                .map(|i| TreeEntry {
                    name: format!("f{i:05}").into_bytes(),
                    mode: EntryMode::Blob,
                    object_hash: blob,
                })
                .collect(),
        });
        let tree_bytes = crate::serialize::serialize(&tree).unwrap();
        let tree_id = crate::object::id_from_object(&tree, &tree_bytes);
        let kp = KeyPair::from_seed([0x11; 32]);
        let mut commit = Commit {
            tree_hash: tree_id,
            parents: vec![],
            author: Identity::ed25519(kp.public.0),
            signer: kp.public.0,
            message: b"fan-in".to_vec(),
            timestamp: 1,
            message_hash: ZERO,
            content_digest: ZERO,
            signature: [0u8; 64],
        };
        commit.signature = sign_commit(&commit, &kp).unwrap().0;
        let commit_bytes = crate::serialize::serialize(&Object::Commit(commit)).unwrap();
        let root = hash(&commit_bytes);

        let mut source = CountingSource {
            objects: BTreeMap::from([
                (blob, blob_bytes),
                (tree_id, tree_bytes),
                (root, commit_bytes),
            ]),
            missing: BTreeSet::new(),
            fetches: BTreeMap::new(),
        };
        let walked = walk(
            &[root, root],
            ClosureMode::History,
            &mut source,
            |_| Known::No,
            RootRule::Fail,
            |_, _| Ok(()),
        )
        .unwrap();
        assert_eq!(walked.verified, 3);
        assert!(walked.peak_queue <= 1, "peak queue {}", walked.peak_queue);
        assert!(source.fetches.values().all(|n| *n == 1));
        assert_eq!(
            walked.visited.keys().copied().collect::<BTreeSet<_>>(),
            BTreeSet::from([root, tree_id, blob]),
            "reached set must equal the visited set"
        );
    }

    #[test]
    fn export_verify_round_trip_snapshot_and_history() {
        let (_d, store, _c1, c2) = two_commit_fixture();
        for mode in [ClosureMode::Snapshot, ClosureMode::History] {
            let export = export_closure(&store, &c2, mode).unwrap();
            let packs: Vec<&[u8]> = export.packs.iter().map(Vec::as_slice).collect();
            let report = verify_closure_manifest(&c2, &export.manifest, &packs).unwrap();
            assert!(report.is_complete(), "{mode:?}: {report:?}");
            assert!(report.unreferenced.is_empty());
            assert!(report.unreferenced_checked);
            assert_eq!(report.root, c2);
            assert_eq!(report.mode, mode);
            assert!(report.verified >= 3);
        }
    }

    fn object(object: &Object) -> (Hash, Vec<u8>) {
        let bytes = crate::serialize::serialize(object).unwrap();
        (crate::object::id_from_object(object, &bytes), bytes)
    }

    fn blob(data: &[u8]) -> (Hash, Vec<u8>) {
        object(&Object::Blob(Blob {
            data: data.to_vec(),
        }))
    }

    fn tree(entries: &[(&[u8], EntryMode, Hash)]) -> (Hash, Vec<u8>) {
        object(&Object::Tree(Tree {
            entries: entries
                .iter()
                .map(|(name, mode, object_hash)| TreeEntry {
                    name: name.to_vec(),
                    mode: *mode,
                    object_hash: *object_hash,
                })
                .collect(),
        }))
    }

    fn chunked(total_size: u64, chunks: &[Hash]) -> (Hash, Vec<u8>) {
        object(&Object::ChunkedBlob(
            crate::object::testing::spread(total_size, 0, chunks.to_vec()).unwrap(),
        ))
    }

    fn commit_over(tree_hash: Hash, parents: Vec<Hash>) -> (Hash, Vec<u8>) {
        let kp = KeyPair::from_seed([0x11; 32]);
        let mut commit = Commit {
            tree_hash,
            parents,
            author: Identity::ed25519(kp.public.0),
            signer: kp.public.0,
            message: b"modes".to_vec(),
            timestamp: 1,
            message_hash: ZERO,
            content_digest: ZERO,
            signature: [0u8; 64],
        };
        commit.signature = sign_commit(&commit, &kp).unwrap().0;
        object(&Object::Commit(commit))
    }

    /// Snapshot closure of `root` over `objects` (the map path).
    fn closure_of(root: Hash, objects: &[&(Hash, Vec<u8>)]) -> ClosureReport {
        verify_closure(
            &root,
            ClosureMode::Snapshot,
            objects.iter().map(|(_, bytes)| bytes.as_slice()),
        )
        .unwrap()
    }

    fn corrupt_ids(report: &ClosureReport) -> Vec<Hash> {
        report.corrupt.iter().map(|(id, _)| *id).collect()
    }

    #[test]
    fn matching_entry_modes_are_complete() {
        let file = blob(b"file");
        let part = blob(b"part");
        let big = chunked(8, &[part.0, part.0]);
        let sub = tree(&[(b"f", EntryMode::Blob, file.0)]);
        let root_tree = tree(&[
            (b"big", EntryMode::Blob, big.0),
            (b"exec", EntryMode::Executable, file.0),
            (b"link", EntryMode::Symlink, file.0),
            (b"sub", EntryMode::Tree, sub.0),
        ]);
        let root = commit_over(root_tree.0, vec![]);
        let report = closure_of(root.0, &[&root, &root_tree, &sub, &big, &part, &file]);
        assert!(report.is_complete(), "{report:?}");
        assert_eq!(report.verified, 6);
        assert!(report.unreferenced.is_empty());
    }

    #[test]
    fn tree_mode_naming_a_blob_is_corrupt() {
        let file = blob(b"file");
        let root_tree = tree(&[(b"d", EntryMode::Tree, file.0)]);
        let root = commit_over(root_tree.0, vec![]);
        let report = closure_of(root.0, &[&root, &root_tree, &file]);
        assert_eq!(corrupt_ids(&report), vec![file.0], "{report:?}");
        assert!(!report.is_complete());
        assert_eq!(report.verified, 2, "the mistyped object is not accepted");
    }

    #[test]
    fn file_modes_naming_a_tree_or_a_commit_are_corrupt() {
        let file = blob(b"file");
        let sub = tree(&[(b"f", EntryMode::Blob, file.0)]);
        let parent = commit_over(sub.0, vec![]);
        for mode in [EntryMode::Blob, EntryMode::Executable, EntryMode::Symlink] {
            for target in [&sub, &parent] {
                let root_tree = tree(&[(b"x", mode, target.0)]);
                let root = commit_over(root_tree.0, vec![]);
                let report = closure_of(root.0, &[&root, &root_tree, &sub, &parent, &file]);
                assert_eq!(corrupt_ids(&report), vec![target.0], "{mode:?} {report:?}");
            }
        }
    }

    #[test]
    fn chunk_naming_a_non_blob_is_corrupt() {
        let part = blob(b"part");
        let inner = chunked(4, &[part.0]);
        let sub = tree(&[(b"f", EntryMode::Blob, part.0)]);
        for target in [&inner, &sub] {
            let outer = chunked(4, &[target.0]);
            let root_tree = tree(&[(b"big", EntryMode::Blob, outer.0)]);
            let root = commit_over(root_tree.0, vec![]);
            let report = closure_of(root.0, &[&root, &root_tree, &outer, &inner, &sub, &part]);
            assert_eq!(corrupt_ids(&report), vec![target.0], "{report:?}");
        }
    }

    #[test]
    fn each_chunk_must_hold_its_span() {
        let one = blob(b"12345");
        let two = blob(b"1234567");
        // The spans of the two chunks as their ends, and whether they fit
        // blobs of 5 and 7 bytes.
        for (ends, ok) in [
            ([5, 12], true),
            ([6, 12], false),
            ([5, 13], false),
            ([5, 11], false),
        ] {
            let big = object(&Object::ChunkedBlob(
                crate::object::ChunkedBlob::new(ends[1], 0, [(one.0, ends[0]), (two.0, ends[1])])
                    .unwrap(),
            ));
            let root_tree = tree(&[(b"big", EntryMode::Blob, big.0)]);
            let root = commit_over(root_tree.0, vec![]);
            let report = closure_of(root.0, &[&root, &root_tree, &big, &one, &two]);
            assert_eq!(report.is_complete(), ok, "ends {ends:?}: {report:?}");
            if !ok {
                assert_eq!(corrupt_ids(&report), vec![big.0]);
            }
        }
    }

    #[test]
    fn every_manifest_of_a_closure_is_checked_for_its_chunk_lengths() {
        let one = blob(b"12345");
        let two = blob(b"1234567");
        let three = blob(b"123");
        let manifest = |chunks: [(Hash, u64); 2]| {
            object(&Object::ChunkedBlob(
                crate::object::ChunkedBlob::new(chunks[1].1, 0, chunks).unwrap(),
            ))
        };
        // Each of two manifests has a chunk that is not its span long, and a
        // third manifest is right.
        let bad_one = manifest([(one.0, 6), (two.0, 13)]);
        let bad_two = manifest([(three.0, 4), (two.0, 11)]);
        let good = manifest([(one.0, 5), (two.0, 12)]);
        let root_tree = tree(&[
            (b"a", EntryMode::Blob, bad_one.0),
            (b"b", EntryMode::Blob, bad_two.0),
            (b"c", EntryMode::Blob, good.0),
        ]);
        let root = commit_over(root_tree.0, vec![]);
        let report = closure_of(
            root.0,
            &[
                &root, &root_tree, &bad_one, &bad_two, &good, &one, &two, &three,
            ],
        );
        let mut expected = vec![bad_one.0, bad_two.0];
        expected.sort_unstable();
        assert_eq!(corrupt_ids(&report), expected, "{report:?}");
        assert_eq!(report.verified, 8, "{report:?}");
    }

    #[test]
    fn chunk_lengths_are_checked_beside_an_absent_chunk() {
        let one = blob(b"12345");
        let two = blob(b"1234567");
        // Chunk 1 is absent. A chunk 0 that fits its span adds nothing; one that
        // does not makes the manifest corrupt all the same (SPEC-DISCLOSURE
        // §7.4 item 10).
        for (first_end, corrupt) in [(5, false), (6, true)] {
            let big = object(&Object::ChunkedBlob(
                crate::object::ChunkedBlob::new(12, 0, [(one.0, first_end), (two.0, 12)]).unwrap(),
            ));
            let root_tree = tree(&[(b"big", EntryMode::Blob, big.0)]);
            let root = commit_over(root_tree.0, vec![]);
            let report = closure_of(root.0, &[&root, &root_tree, &big, &one]);
            assert_eq!(report.missing, vec![two.0]);
            assert_eq!(
                corrupt_ids(&report),
                if corrupt { vec![big.0] } else { vec![] },
                "{report:?}"
            );
        }
    }

    #[test]
    fn one_id_named_with_two_incompatible_modes_is_corrupt_once() {
        let file = blob(b"file");
        // Both entries name the subtree: one as a file, one as a tree.
        let sub = tree(&[(b"f", EntryMode::Blob, file.0)]);
        let root_tree = tree(&[
            (b"a", EntryMode::Tree, sub.0),
            (b"b", EntryMode::Blob, sub.0),
        ]);
        let root = commit_over(root_tree.0, vec![]);
        let report = closure_of(root.0, &[&root, &root_tree, &sub, &file]);
        assert_eq!(corrupt_ids(&report), vec![sub.0], "{report:?}");

        // The blob is decoded first as a file, then named as a tree entry.
        let deeper = tree(&[(b"x", EntryMode::Tree, file.0)]);
        let root_tree = tree(&[
            (b"a", EntryMode::Blob, file.0),
            (b"sub", EntryMode::Tree, deeper.0),
        ]);
        let root = commit_over(root_tree.0, vec![]);
        let report = closure_of(root.0, &[&root, &root_tree, &deeper, &file]);
        assert_eq!(corrupt_ids(&report), vec![file.0], "{report:?}");
    }

    #[test]
    fn a_decoded_commit_named_as_a_file_later_is_corrupt() {
        let empty = tree(&[]);
        let parent = commit_over(empty.0, vec![]);
        // The parent is decoded as a commit before a deeper entry names it as a file.
        let deeper = tree(&[(b"x", EntryMode::Blob, parent.0)]);
        let root_tree = tree(&[(b"d", EntryMode::Tree, deeper.0)]);
        let root = commit_over(root_tree.0, vec![parent.0]);
        let objects = [&root, &root_tree, &deeper, &parent, &empty];
        let report = verify_closure(
            &root.0,
            ClosureMode::History,
            objects.iter().map(|(_, bytes)| bytes.as_slice()),
        )
        .unwrap();
        assert_eq!(corrupt_ids(&report), vec![parent.0], "{report:?}");
    }

    fn remix_over(tree_hash: Hash) -> (Hash, Vec<u8>) {
        let kp = KeyPair::from_seed([0x11; 32]);
        let mut remix = Remix {
            tree_hash,
            parents: vec![],
            sources: vec![],
            author: Identity::ed25519(kp.public.0),
            signer: kp.public.0,
            message: b"remix".to_vec(),
            timestamp: 1,
            signature: [0u8; 64],
        };
        remix.signature = sign_remix(&remix, &kp).unwrap().0;
        object(&Object::Remix(remix))
    }

    fn tag_of(target: Hash, target_type: ObjectType) -> (Hash, Vec<u8>) {
        let kp = KeyPair::from_seed([0x11; 32]);
        let mut tag = Tag {
            target,
            target_type,
            name: b"v1".to_vec(),
            tagger: Identity::ed25519(kp.public.0),
            signer: kp.public.0,
            message: b"tag".to_vec(),
            timestamp: 1,
            signature: [0u8; 64],
        };
        tag.signature = sign_tag(&tag, &kp).unwrap().0;
        object(&Object::Tag(tag))
    }

    #[test]
    fn commit_and_remix_trees_must_be_trees() {
        let file = blob(b"file");
        let tree_obj = tree(&[(b"f", EntryMode::Blob, file.0)]);
        for make in [commit_over_noparents, remix_over] {
            let ok = make(tree_obj.0);
            let report = closure_of(ok.0, &[&ok, &tree_obj, &file]);
            assert!(report.is_complete(), "{report:?}");

            let bad = make(file.0);
            let report = closure_of(bad.0, &[&bad, &file]);
            assert_eq!(corrupt_ids(&report), vec![file.0], "{report:?}");
        }
    }

    fn commit_over_noparents(tree_hash: Hash) -> (Hash, Vec<u8>) {
        commit_over(tree_hash, vec![])
    }

    #[test]
    fn tag_target_must_have_the_recorded_type() {
        let file = blob(b"file");
        let tree_obj = tree(&[(b"f", EntryMode::Blob, file.0)]);
        let commit = commit_over(tree_obj.0, vec![]);
        let tag = tag_of(commit.0, ObjectType::Commit);
        let report = closure_of(tag.0, &[&tag, &commit, &tree_obj, &file]);
        assert!(report.is_complete(), "{report:?}");
        assert_eq!(report.verified, 4);

        // The tag records a commit; the target is a tree.
        let lying = tag_of(tree_obj.0, ObjectType::Commit);
        let report = closure_of(lying.0, &[&lying, &tree_obj, &file]);
        assert_eq!(corrupt_ids(&report), vec![tree_obj.0], "{report:?}");
    }

    #[test]
    fn history_on_snapshot_reports_parent_missing() {
        let (_d, store, c1, c2) = two_commit_fixture();
        let export = export_closure(&store, &c2, ClosureMode::Snapshot).unwrap();
        let packs: Vec<&[u8]> = export.packs.iter().map(Vec::as_slice).collect();
        let report = verify_closure_packs(&c2, ClosureMode::History, &packs).unwrap();
        assert!(
            report.missing.contains(&c1),
            "parent must be missing: {report:?}"
        );
        assert!(!report.is_complete());
        assert!(report.unreferenced_checked);
    }

    #[test]
    fn snapshot_on_history_reports_parent_unreferenced() {
        let (_d, store, c1, c2) = two_commit_fixture();
        let export = export_closure(&store, &c2, ClosureMode::History).unwrap();
        let packs: Vec<&[u8]> = export.packs.iter().map(Vec::as_slice).collect();
        let report = verify_closure_packs(&c2, ClosureMode::Snapshot, &packs).unwrap();
        assert!(
            report.unreferenced.contains(&c1),
            "parent commit is history-only: {report:?}"
        );
        assert!(report.is_complete());
        assert!(report.unreferenced_checked);
    }

    #[test]
    fn streaming_fetches_each_reachable_object_once_and_only() {
        let (_d, store, c1, c2) = two_commit_fixture();
        let snapshot_expected = crate::ops::graph::reachable_snapshot(&store, &c2).unwrap();
        let mut snapshot_source = CountingSource::from_store(&store);
        let snapshot =
            verify_closure_streaming(&c2, ClosureMode::Snapshot, &mut snapshot_source).unwrap();
        assert!(snapshot.is_complete(), "{snapshot:?}");
        assert_eq!(snapshot_source.fetched_ids(), snapshot_expected);
        assert!(snapshot_source.fetches.values().all(|count| *count == 1));

        let mut history_source = CountingSource::from_store(&store);
        let history =
            verify_closure_streaming(&c2, ClosureMode::History, &mut history_source).unwrap();
        let history_expected = crate::ops::graph::reachable_objects(&store, &c2).unwrap();
        assert!(history.is_complete(), "{history:?}");
        assert_eq!(history_source.fetched_ids(), history_expected);
        assert!(history_source.fetches.values().all(|count| *count == 1));

        let parent_closure = crate::ops::graph::reachable_snapshot(&store, &c1).unwrap();
        let history_only: BTreeSet<Hash> = history_expected
            .difference(&snapshot_expected)
            .copied()
            .collect();
        assert_eq!(history_only, parent_closure);
    }

    #[test]
    fn streaming_reports_missing_and_corrupt_under_requested_id() {
        let (_d, store, root, blob) = fixture();

        let mut missing_source = CountingSource::from_store(&store);
        missing_source.missing.insert(blob);
        let missing =
            verify_closure_streaming(&root, ClosureMode::Snapshot, &mut missing_source).unwrap();
        assert!(missing.missing.contains(&blob), "{missing:?}");
        assert!(missing.corrupt.is_empty(), "{missing:?}");
        assert!(!missing.unreferenced_checked);

        let mut corrupt_source = CountingSource::from_store(&store);
        let bytes = corrupt_source.objects.get_mut(&blob).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        let corrupt =
            verify_closure_streaming(&root, ClosureMode::Snapshot, &mut corrupt_source).unwrap();
        assert!(
            corrupt.corrupt.iter().any(|(id, _)| *id == blob),
            "{corrupt:?}"
        );
        assert!(!corrupt.missing.contains(&blob), "{corrupt:?}");

        let mut malformed_source = CountingSource::from_store(&store);
        malformed_source
            .objects
            .insert(blob, b"not an object".to_vec());
        let malformed =
            verify_closure_streaming(&root, ClosureMode::Snapshot, &mut malformed_source).unwrap();
        assert!(
            malformed.corrupt.iter().any(|(id, _)| *id == blob),
            "{malformed:?}"
        );
        assert!(!malformed.missing.contains(&blob), "{malformed:?}");
    }

    struct MismatchSource {
        objects: BTreeMap<Hash, Vec<u8>>,
        mismatch_id: Hash,
        mismatch_bytes: Vec<u8>,
    }

    impl ObjectSource for MismatchSource {
        fn fetch(&mut self, id: &Hash) -> Result<Option<Cow<'_, [u8]>>, VerifyError> {
            if *id == self.mismatch_id {
                return Ok(Some(Cow::Borrowed(self.mismatch_bytes.as_slice())));
            }
            Ok(self.objects.get(id).map(|b| Cow::Borrowed(b.as_slice())))
        }
    }

    #[test]
    fn streaming_reports_mismatched_source_bytes_under_the_requested_id() {
        let (_d, store, root, blob) = fixture();
        let blob_bytes = store.read(&blob).unwrap();
        let derived = crate::object::id_from_object(
            &crate::serialize::deserialize(&blob_bytes).unwrap(),
            &blob_bytes,
        );
        assert_eq!(derived, blob);

        let mut objects = BTreeMap::new();
        for id in store.iter_object_hashes().unwrap() {
            if id != blob {
                objects.insert(id, store.read(&id).unwrap());
            }
        }
        let mut source = MismatchSource {
            objects,
            mismatch_id: blob,
            mismatch_bytes: crate::serialize::serialize(&Object::Blob(Blob {
                data: b"different blob".to_vec(),
            }))
            .unwrap(),
        };
        let other_id = crate::object::id_from_object(
            &crate::serialize::deserialize(&source.mismatch_bytes).unwrap(),
            &source.mismatch_bytes,
        );
        assert_ne!(other_id, blob);

        let (report, _) = walk_closure(&root, ClosureMode::Snapshot, &mut source).unwrap();
        assert!(
            report.corrupt.iter().any(|(id, _)| *id == blob),
            "walker must classify the mismatch under the requested id: {report:?}"
        );
    }

    #[test]
    fn map_path_keeps_parsable_bit_flip_as_missing_and_unreferenced() {
        let (_d, store, root, blob) = fixture();
        let mut objects = Vec::new();
        let mut flipped_bytes = None;
        for id in store.iter_object_hashes().unwrap() {
            let mut bytes = store.read(&id).unwrap();
            if id == blob {
                let last = bytes.len() - 1;
                bytes[last] ^= 0x01;
                flipped_bytes = Some(bytes.clone());
            }
            objects.push(bytes);
        }
        let flipped = flipped_bytes.expect("flipped blob");
        let flipped_object = crate::serialize::deserialize(&flipped).unwrap();
        let flipped_id = crate::object::id_from_object(&flipped_object, &flipped);
        assert_ne!(flipped_id, blob);

        let report = verify_closure(
            &root,
            ClosureMode::Snapshot,
            objects.iter().map(Vec::as_slice),
        )
        .unwrap();
        assert!(report.missing.contains(&blob), "{report:?}");
        assert!(report.unreferenced.contains(&flipped_id), "{report:?}");
        assert!(report.corrupt.is_empty(), "{report:?}");
        assert!(report.unreferenced_checked);
    }

    #[test]
    fn store_streaming_reports_missing_and_corrupt_files() {
        let (_d, store, root, blob) = fixture();
        fs::remove_file(store.path_for(&blob)).unwrap();
        let missing = verify_closure_store(&store, &root, ClosureMode::Snapshot).unwrap();
        assert!(missing.missing.contains(&blob), "{missing:?}");
        assert!(!missing.unreferenced_checked);

        let (_d, store, root, blob) = fixture();
        let path = store.path_for(&blob);
        let mut bytes = fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        fs::write(path, bytes).unwrap();
        let corrupt = verify_closure_store(&store, &root, ClosureMode::Snapshot).unwrap();
        assert!(
            corrupt.corrupt.iter().any(|(id, _)| *id == blob),
            "{corrupt:?}"
        );
        assert!(!corrupt.missing.contains(&blob), "{corrupt:?}");
        assert!(!corrupt.unreferenced_checked);
    }

    #[test]
    fn missing_root_is_reported() {
        let root = [0xAB; 32];
        let report = verify_closure(&root, ClosureMode::Snapshot, std::iter::empty()).unwrap();
        assert_eq!(report.missing, vec![root]);
        assert_eq!(report.verified, 0);
        assert!(!report.is_complete());
        assert!(report.unreferenced_checked);
    }

    #[test]
    fn undecodable_object_is_unreferenced_not_corrupt() {
        let (_d, store, commit_id, _) = fixture();
        let export = export_closure(&store, &commit_id, ClosureMode::Snapshot).unwrap();
        let mut objects: Vec<Vec<u8>> = Vec::new();
        for pack in &export.packs {
            for entry in PackEntries::new(pack).unwrap() {
                let PackEntry::Raw { bytes } = entry.unwrap() else {
                    panic!("raw-only");
                };
                objects.push(bytes.into_owned());
            }
        }
        objects.push(b"not an object".to_vec());
        let junk = hash(b"not an object");
        let report = verify_closure(
            &commit_id,
            ClosureMode::Snapshot,
            objects.iter().map(Vec::as_slice),
        )
        .unwrap();
        assert!(report.corrupt.is_empty(), "{report:?}");
        assert!(report.is_complete(), "{report:?}");
        assert_eq!(report.unreferenced, vec![junk]);

        let mut w = PackWriter::new_raw_only();
        for bytes in &objects {
            w.push_raw(hash(bytes), bytes).unwrap();
        }
        let pack = w.finish().unwrap();
        let report = verify_closure_packs(&commit_id, ClosureMode::Snapshot, &[&pack]).unwrap();
        assert!(report.is_complete(), "{report:?}");
        assert_eq!(report.unreferenced, vec![junk]);
    }

    #[test]
    fn unreferenced_extra_is_still_complete() {
        let (_d, store, commit_id, _) = fixture();
        let extra = crate::serialize::serialize(&Object::Blob(Blob {
            data: b"unrelated".to_vec(),
        }))
        .unwrap();
        let export = export_closure(&store, &commit_id, ClosureMode::Snapshot).unwrap();
        let mut objects: Vec<Vec<u8>> = Vec::new();
        for pack in &export.packs {
            for entry in PackEntries::new(pack).unwrap() {
                let PackEntry::Raw { bytes } = entry.unwrap() else {
                    panic!("raw-only");
                };
                objects.push(bytes.into_owned());
            }
        }
        objects.push(extra);
        let report = verify_closure(
            &commit_id,
            ClosureMode::Snapshot,
            objects.iter().map(Vec::as_slice),
        )
        .unwrap();
        assert!(report.is_complete());
        assert_eq!(report.unreferenced.len(), 1);
        assert!(report.unreferenced_checked);
    }

    #[test]
    fn wrong_root_type_is_typed_error() {
        let blob = crate::serialize::serialize(&Object::Blob(Blob {
            data: b"not a commit".to_vec(),
        }))
        .unwrap();
        let id =
            crate::object::id_from_object(&crate::serialize::deserialize(&blob).unwrap(), &blob);
        let err = verify_closure(&id, ClosureMode::Snapshot, std::iter::once(blob.as_slice()))
            .unwrap_err();
        assert!(matches!(
            err,
            VerifyError::ClosureRootWrongType(ObjectType::Blob)
        ));
    }

    #[test]
    fn delta_pack_is_profile_violation() {
        let base = crate::serialize::serialize(&Object::Blob(Blob {
            data: b"delta-base-xxxx".to_vec(),
        }))
        .unwrap();
        let target = crate::serialize::serialize(&Object::Blob(Blob {
            data: b"delta-target-yy".to_vec(),
        }))
        .unwrap();
        let base_hash = hash(&base);
        let stream = crate::delta::encode(&base, &target).unwrap();
        let mut w = PackWriter::new();
        w.push_raw(base_hash, &base).unwrap();
        w.push_delta(&base_hash, &stream).unwrap();
        let pack = w.finish().unwrap();
        let err = verify_closure_packs(&[0u8; 32], ClosureMode::Snapshot, &[pack.as_slice()])
            .unwrap_err();
        assert!(matches!(
            err,
            VerifyError::ClosureProfileViolation {
                pack_index: 0,
                entry_index: 1
            }
        ));
    }

    #[test]
    fn manifest_with_a_huge_pack_count_and_short_input_is_malformed() {
        use commonware_codec::Encode as _;
        let m = ClosureManifest {
            root: [0u8; 32],
            mode: ClosureMode::Snapshot,
            packs: vec![],
        };
        let mut bytes = m.encode();
        // The empty pack list is the last byte: a zero length prefix.
        assert_eq!(bytes.pop(), Some(0));
        bytes.extend_from_slice(&MAX_CLOSURE_PACKS.encode());
        bytes.extend_from_slice(&[0u8; 100]);
        assert!(matches!(
            ClosureManifest::decode(&bytes),
            Err(VerifyError::ClosureManifestMalformed)
        ));
    }

    #[test]
    fn manifest_rejects_unknown_version_trailing_and_mode() {
        let m = ClosureManifest {
            root: [0u8; 32],
            mode: ClosureMode::Snapshot,
            packs: vec![],
        };
        let mut bytes = m.encode();
        bytes.push(0xFF);
        assert!(matches!(
            ClosureManifest::decode(&bytes),
            Err(VerifyError::ClosureManifestMalformed)
        ));
        let mut v2 = m.encode();
        v2[4] = 2;
        assert!(matches!(
            ClosureManifest::decode(&v2),
            Err(VerifyError::ClosureManifestUnsupportedVersion(2))
        ));
        assert!(matches!(
            ClosureManifest::decode(b"XXXX\x01"),
            Err(VerifyError::ClosureManifestBadMagic)
        ));
        let mut bad_mode = m.encode();
        // magic(4)+version(1)+root(32)+mode
        bad_mode[5 + 32] = 9;
        assert!(matches!(
            ClosureManifest::decode(&bad_mode),
            Err(VerifyError::ClosureManifestMalformed)
        ));
    }

    #[test]
    fn manifest_pack_key_mismatch() {
        let (_d, store, commit_id, _) = fixture();
        let export = export_closure(&store, &commit_id, ClosureMode::Snapshot).unwrap();
        let mut decoded = ClosureManifest::decode(&export.manifest).unwrap();
        decoded.packs[0] = [0xFF; 32];
        let bad = decoded.encode();
        let packs: Vec<&[u8]> = export.packs.iter().map(Vec::as_slice).collect();
        let err = verify_closure_manifest(&commit_id, &bad, &packs).unwrap_err();
        assert!(matches!(
            err,
            VerifyError::ClosurePackKeyMismatch { index: 0 }
        ));
    }

    #[test]
    fn manifest_root_mismatch() {
        let (_d, store, commit_id, _) = fixture();
        let export = export_closure(&store, &commit_id, ClosureMode::Snapshot).unwrap();
        let packs: Vec<&[u8]> = export.packs.iter().map(Vec::as_slice).collect();
        let other = [0x11u8; 32];
        let err = verify_closure_manifest(&other, &export.manifest, &packs).unwrap_err();
        assert!(matches!(
            err,
            VerifyError::ClosureRootMismatch { expected, got }
                if expected == other && got == commit_id
        ));
    }

    #[test]
    fn raw_only_pack_round_trips_through_pack_reader() {
        let (_d, store, commit_id, _) = fixture();
        let export = export_closure(&store, &commit_id, ClosureMode::Snapshot).unwrap();
        assert!(!export.packs.is_empty());
        for pack in &export.packs {
            assert_eq!(&pack[..4], b"KIT\0");
            assert_eq!(
                u32::from_le_bytes(pack[4..8].try_into().unwrap()),
                pack::VERSION
            );
            let entries = PackEntries::new(pack).unwrap();
            assert!(entries.is_raw_only());
            let (_dir, dest) = {
                let d = TempDir::new().unwrap();
                let s = ObjectStore::init(&RepoLayout::single(d.path())).unwrap();
                (d, s)
            };
            crate::pack::PackReader::read(pack, &dest).unwrap();
        }
    }

    /// A closure with enough objects to be a meaningfully different
    /// shape from every other (tiny) fixture in this module. With
    /// `CLOSURE_ENTRIES_PER_THREAD` tuned for real fan-out wins (see
    /// its doc — only past ~4096 entries per thread), this fixture
    /// stays below the live dispatch threshold on any real machine, so
    /// these tests instead call `index_supplied_objects_sequential`/
    /// `_parallel` directly to exercise and cross-check the parallel
    /// branch's correctness regardless of threshold.
    const LARGE_FIXTURE_N: usize = 200;

    fn large_fixture() -> (TempDir, ObjectStore, Hash, usize) {
        let dir = TempDir::new().unwrap();
        let store = ObjectStore::init(&RepoLayout::single(dir.path())).unwrap();
        let mut entries = Vec::with_capacity(LARGE_FIXTURE_N);
        for i in 0..LARGE_FIXTURE_N {
            let blob =
                store_file_object(&store, format!("large closure blob #{i}").as_bytes()).unwrap();
            entries.push(TreeEntry {
                name: format!("f{i:04}.txt").into_bytes(),
                mode: EntryMode::Blob,
                object_hash: blob,
            });
        }
        let tree_hash = store
            .write(&crate::serialize::serialize(&Object::Tree(Tree { entries })).unwrap())
            .unwrap();
        let kp = KeyPair::from_seed([0x22; 32]);
        let mut commit = Commit {
            tree_hash,
            parents: vec![],
            author: Identity::ed25519(kp.public.0),
            signer: kp.public.0,
            message: b"large closure fan-out fixture".to_vec(),
            timestamp: 1,
            message_hash: ZERO,
            content_digest: ZERO,
            signature: [0u8; 64],
        };
        commit.signature = sign_commit(&commit, &kp).unwrap().0;
        let commit_id = store
            .write(&crate::serialize::serialize(&Object::Commit(commit)).unwrap())
            .unwrap();
        let total = store.iter_object_hashes().unwrap().len();
        (dir, store, commit_id, total)
    }

    #[test]
    fn large_object_set_parallel_path_matches_sequential_map() {
        let (_d, store, commit_id, total) = large_fixture();
        let threads = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);

        let objects: Vec<Vec<u8>> = store
            .iter_object_hashes()
            .unwrap()
            .into_iter()
            .map(|id| store.read(&id).unwrap())
            .collect();

        let report = verify_closure(
            &commit_id,
            ClosureMode::Snapshot,
            objects.iter().map(Vec::as_slice),
        )
        .unwrap();
        assert!(report.is_complete(), "{report:?}");
        assert_eq!(report.verified, total);
        assert!(report.unreferenced.is_empty());

        let refs: Vec<&[u8]> = objects.iter().map(Vec::as_slice).collect();
        let (seq_by_id, mut seq_corrupt) = index_supplied_objects_sequential(&refs);
        let (par_by_id, mut par_corrupt) = index_supplied_objects_parallel(&refs, threads.max(2));
        seq_corrupt.sort_unstable();
        par_corrupt.sort_unstable();
        assert_eq!(seq_by_id, par_by_id);
        assert_eq!(seq_corrupt, par_corrupt);
        assert!(seq_corrupt.is_empty());
    }

    #[test]
    fn large_object_set_parallel_path_matches_sequential_packs() {
        let (_d, store, commit_id, total) = large_fixture();
        let export = export_closure(&store, &commit_id, ClosureMode::Snapshot).unwrap();
        let packs: Vec<&[u8]> = export.packs.iter().map(Vec::as_slice).collect();

        let report = verify_closure_packs(&commit_id, ClosureMode::Snapshot, &packs).unwrap();
        assert!(report.is_complete(), "{report:?}");
        assert_eq!(report.verified, total);
        assert!(report.unreferenced.is_empty());
        assert!(report.unreferenced_checked);
    }

    #[test]
    fn large_object_set_parallel_path_classifies_corrupt_entry_correctly() {
        // A bit-flipped (but still parsable) object doesn't exercise
        // `classify_object`'s error arm at all — it just derives a
        // different id — so it wouldn't touch `index_supplied_objects_*`'s
        // `corrupt` bookkeeping. Replace one entry with bytes that fail to
        // deserialize entirely instead, and call the parallel indexer
        // directly (`large_fixture`'s object count stays under the live
        // dispatch threshold — see its doc) so this actually runs the
        // parallel branch's per-chunk corrupt handling, whichever
        // thread-chunk the corrupt entry lands in.
        let (_d, store, _commit_id, total) = large_fixture();
        let mut objects: Vec<Vec<u8>> = store
            .iter_object_hashes()
            .unwrap()
            .into_iter()
            .map(|id| store.read(&id).unwrap())
            .collect();
        let corrupt_index = total / 2;
        objects[corrupt_index] = b"not an object".to_vec();
        let expected_corrupt_id = hash(&objects[corrupt_index]);

        let refs: Vec<&[u8]> = objects.iter().map(Vec::as_slice).collect();
        let threads = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
        let (seq_by_id, mut seq_corrupt) = index_supplied_objects_sequential(&refs);
        let (par_by_id, mut par_corrupt) = index_supplied_objects_parallel(&refs, threads.max(2));
        seq_corrupt.sort_unstable();
        par_corrupt.sort_unstable();

        assert_eq!(par_by_id, seq_by_id);
        assert_eq!(par_corrupt, seq_corrupt);
        assert_eq!(seq_corrupt.len(), 1, "{seq_corrupt:?}");
        assert_eq!(seq_corrupt[0], expected_corrupt_id);
        assert_eq!(
            seq_by_id.len(),
            total - 1,
            "the corrupt entry must not be indexed"
        );
    }
}
