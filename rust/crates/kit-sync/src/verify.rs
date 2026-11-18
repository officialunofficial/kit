//! Post-fetch signature verification of newly introduced objects.
//!
//! A hostile remote can otherwise push an unsigned or forged history that a
//! clone, pull or fetch would silently materialise. Every commit, remix and
//! tag a fetch introduces, and every one in the history of each tip it
//! publishes, is checked with the same function `kit verify` uses, failing
//! closed.

use std::collections::{HashMap, HashSet};

use kit_core::hash::{self, Hash};
use kit_core::object::{Object, ObjectType};
use kit_core::sign;
use kit_core::store::{ObjectStore, StoreError};
use rayon::prelude::*;

use crate::error::SyncError;
use crate::observer::{Observer, SyncEvent};

/// Entries-per-thread budget below which [`verify_new_object_signatures`]
/// checks signatures sequentially instead of fanning out across rayon's
/// thread pool, for a pool of a given size. Same crossover shape as
/// `remote_dispatch/mod.rs`'s `PACK_FANOUT_ENTRIES_PER_THREAD` (rayon's
/// pool-dispatch overhead loses to a plain loop below a few entries per
/// thread and wins clearly above it) but tuned lower: each entry here is
/// only a `store.read_object` (disk read + BLAKE3 re-hash) plus one
/// Ed25519 check — cheaper per item than the zstd-compression
/// fan-out `PACK_FANOUT_ENTRIES_PER_THREAD` guards, so fewer entries per
/// thread are enough to amortize dispatch. Measured with `cargo bench -p
/// kit-benches --bench verify_fanout`.
const VERIFY_FANOUT_ENTRIES_PER_THREAD: usize = 2;

/// The total entry count [`verify_new_object_signatures`] fans out across
/// rayon at — see [`VERIFY_FANOUT_ENTRIES_PER_THREAD`].
fn verify_fanout_threshold() -> usize {
    crate::fanout::threshold(VERIFY_FANOUT_ENTRIES_PER_THREAD)
}

/// Chunk size [`verify_new_object_signatures`]'s parallel path processes
/// `stored` in — deliberately decoupled from [`verify_fanout_threshold`]
/// (a small, pool-size-scaled crossover picked to amortize rayon's
/// per-dispatch overhead) rather than reusing it as the chunk size too.
/// The two constants answer different questions: `verify_fanout_threshold`
/// asks "is this worth parallelizing at all?"; this asks "how much wasted
/// verification work should a hostile fetch's first bad signature be
/// allowed to force?" A large legitimate fetch (thousands of newly-signed
/// objects) pays one rayon dispatch per chunk, so reusing the tiny
/// crossover threshold as the chunk size (as few as `2 * num_threads`,
/// e.g. 16 on an 8-core host) meant a 10,000-object fetch paid roughly
/// 625 separate dispatches — thread-pool coordination overhead with no
/// benefit, since the hostile-input bound doesn't need a chunk anywhere
/// near that small. 512 keeps the bound meaningful (a hostile remote can
/// force at most 512 extra reads/Ed25519-verifies past the object that
/// actually fails — a small, fixed amount of wasted CPU regardless of
/// fetch size) while cutting a 10,000-object fetch to ~20 dispatches.
const VERIFY_CHUNK_CAP: usize = 512;

/// The chunk size [`verify_new_object_signatures`]'s parallel path uses —
/// see [`VERIFY_CHUNK_CAP`]. `.max(verify_fanout_threshold())` guards the
/// (currently unreachable on any real host) case of a thread pool large
/// enough that the crossover threshold itself would exceed the cap —
/// a chunk should never be smaller than the count that justified
/// parallelizing it in the first place.
fn verify_chunk_size() -> usize {
    VERIFY_CHUNK_CAP.max(verify_fanout_threshold())
}

/// Verify the Ed25519 signature on every commit/remix/tag in `stored` —
/// the digests [`unpack_downloaded_packs`] just wrote, i.e. the objects
/// this fetch actually introduced. Uses the exact same check
/// `kit verify <rev>` runs manually
/// ([`kit_core::sign::verify_commit`]/`verify_remix`/`verify_tag`), so
/// clone/pull/fetch cannot publish a remote-tracking ref to a hostile
/// remote's unsigned or forged history (THREAT-MODEL §3.1) without the
/// caller explicitly opting out. Blob/Tree/ChunkedBlob/Delta objects carry
/// no signature and are skipped.
///
/// `require_signed = false` (the explicit opt-out) short-circuits to
/// `Ok(())` without reading any object — a no-op, not a "verify but
/// ignore the result".
///
/// Each entry's read + verify is independent of every other's, so at or
/// above [`verify_fanout_threshold`] entries this fans out across rayon's
/// global thread pool (mirroring `add.rs`'s hash fan-out and
/// `remote_dispatch/mod.rs`'s pack-build fan-out) instead of running one
/// entry at a time — `store.read_object`'s BLAKE3 re-hash and
/// `verify_commit`/`verify_remix`/`verify_tag`'s Ed25519 check are both
/// CPU-bound, so a large fetch's verification pass parallelizes cleanly
/// across cores.
///
/// The parallel path processes `signed` in runs of at most
/// [`verify_chunk_size`] entries, verifying each run in full before
/// starting the next, rather than fanning the whole slice out in one
/// `par_iter` — rayon's `try_for_each` only best-effort short-circuits
/// (already-dispatched work keeps running once an error is found), so a
/// single flat fan-out over a very large hostile fetch could still force
/// reading and Ed25519-verifying a large fraction of the batch past the
/// first invalid signature before the rejection propagates. Runs bound
/// that wasted work to at most one run, and the run containing the first
/// invalid entry is always the one whose error is returned, since later
/// runs are never started.
///
/// A run also holds at most [`VERIFY_INFLIGHT_BYTES`] of objects, each
/// charged twice its recorded size (its bytes and the parsed object are
/// held at once), decided from the sizes before any object is read. An
/// object over the budget is checked alone. So the check's memory does
/// not grow with the pack or with the number of workers.
///
/// Within each run (or the whole slice, below the fan-out threshold),
/// [`verify_slice`] first checks every signature in one
/// [`sign::verify_ed25519_batch`] call per worker thread. The batch accepts
/// exactly the signatures [`sign::verify_ed25519`] accepts (SPEC-SIGNING
/// §1), so fetch and `kit verify` never disagree. Only when a batch fails
/// does [`verify_slice`] check each object on its own to name the bad one.
pub(crate) fn verify_new_object_signatures(
    store: &ObjectStore,
    signed: &[(Hash, u32)],
    require_signed: bool,
) -> Result<(), SyncError> {
    if !require_signed {
        return Ok(());
    }
    let mut start = 0;
    for len in verify_runs(signed, verify_chunk_size(), VERIFY_INFLIGHT_BYTES) {
        let run = &signed[start..start + len];
        start += len;
        let hashes: Vec<Hash> = run.iter().map(|(h, _)| *h).collect();
        #[cfg(test)]
        test_counts::note_run(
            run[0].0,
            run.iter().map(|&(_, size)| verify_charge(size)).sum(),
        );
        verify_slice(store, &hashes, hashes.len() >= verify_fanout_threshold())?;
    }
    Ok(())
}

/// Bytes the parallel signature check may hold at once, 256 MiB.
pub(crate) const VERIFY_INFLIGHT_BYTES: u64 = 256 << 20;

/// What checking one object costs in memory: its bytes and the parsed object.
fn verify_charge(size: u32) -> u64 {
    2 * u64::from(size)
}

/// Split `signed` into consecutive runs of at most `max_entries` objects
/// whose summed [`verify_charge`] stays within `budget`. An object over the
/// budget is a run of its own.
fn verify_runs(signed: &[(Hash, u32)], max_entries: usize, budget: u64) -> Vec<usize> {
    let mut runs = Vec::new();
    let (mut held, mut count) = (0u64, 0usize);
    for &(_, size) in signed {
        let charge = verify_charge(size);
        if count > 0 && (count >= max_entries || held.saturating_add(charge) > budget) {
            runs.push(count);
            (held, count) = (0, 0);
        }
        held = held.saturating_add(charge);
        count += 1;
    }
    if count > 0 {
        runs.push(count);
    }
    runs
}

/// What the signature checks of tests did: the objects read in full, and
/// each run's first object and charge. Keyed by object, so tests running at
/// once see only their own.
#[cfg(test)]
pub(crate) mod test_counts {
    use std::sync::Mutex;

    use kit_core::hash::Hash;

    static READS: Mutex<Vec<Hash>> = Mutex::new(Vec::new());
    static RUNS: Mutex<Vec<(Hash, u64)>> = Mutex::new(Vec::new());

    pub(super) fn note_read(hash: Hash) {
        READS.lock().unwrap().push(hash);
    }

    pub(super) fn note_run(first: Hash, charge: u64) {
        RUNS.lock().unwrap().push((first, charge));
    }

    /// How many times each of `hashes` was read in full.
    pub(crate) fn reads_of(hashes: &[Hash]) -> usize {
        let reads = READS.lock().unwrap();
        reads.iter().filter(|h| hashes.contains(h)).count()
    }

    /// The charge of each run that started at one of `hashes`.
    pub(crate) fn runs_from(hashes: &[Hash]) -> Vec<u64> {
        let runs = RUNS.lock().unwrap();
        runs.iter()
            .filter(|(first, _)| hashes.contains(first))
            .map(|&(_, charge)| charge)
            .collect()
    }
}

/// Verify the signature on a single already-read object through
/// [`sign::verify_object_signature`] (commit/remix/tag; Blob/Tree/
/// ChunkedBlob/Delta carry no signature and pass), the same check
/// `kit verify` runs.
fn verify_one_object(h: Hash, obj: &Object) -> Result<(), SyncError> {
    sign::verify_object_signature(obj).map_err(|e| SyncError::UnsignedOrInvalidObject {
        hash: hash::to_hex(&h),
        reason: e.to_string(),
    })
}

/// A signed object's public key, signing digest and signature.
type BatchEntry = ([u8; 32], Hash, [u8; 64]);

/// The [`BatchEntry`] of each signed object, skipping objects that carry
/// no signature, or `None` when a signing digest cannot be computed. The
/// per-object fallback then reports that object.
fn batch_entries(entries: &[(Hash, Object)]) -> Option<Vec<BatchEntry>> {
    entries
        .iter()
        .filter_map(|(_, obj)| match obj {
            Object::Commit(c) => {
                Some(sign::commit_signing_hash(c).map(|digest| (c.signer, digest, c.signature)))
            }
            Object::Remix(r) => {
                Some(sign::remix_signing_hash(r).map(|digest| (r.signer, digest, r.signature)))
            }
            Object::Tag(t) => {
                Some(sign::tag_signing_hash(t).map(|digest| (t.signer, digest, t.signature)))
            }
            Object::Blob(_) | Object::Tree(_) | Object::ChunkedBlob(_) | Object::Delta(_) => None,
        })
        .collect::<Result<_, _>>()
        .ok()
}

/// Check `batch` with one [`sign::verify_ed25519_batch`] call per worker
/// thread, or one call when `parallel` is unset.
fn verify_batch(batch: &[BatchEntry], parallel: bool) -> bool {
    let check = |sub: &[BatchEntry]| {
        let refs: Vec<_> = sub.iter().map(|(p, m, s)| (p, &m[..], s)).collect();
        sign::verify_ed25519_batch(&refs).is_ok()
    };
    if !parallel {
        return check(batch);
    }
    let size = batch
        .len()
        .div_ceil(rayon::current_num_threads().max(1))
        .max(1);
    batch.par_chunks(size).all(check)
}

/// Read every object in `hashes` (in parallel iff `parallel`), then verify
/// their signatures. Only Commit/Remix/Tag entries are retained.
///
/// The signed objects are checked as a batch first. If the batch fails,
/// each object is checked with [`verify_one_object`], in parallel iff
/// `parallel`, so the first failure names the offending hash.
fn verify_slice(store: &ObjectStore, hashes: &[Hash], parallel: bool) -> Result<(), SyncError> {
    // The caller lists the commits, remixes and tags an unpack stored, so
    // no blob is read here. An object of another kind is still dropped
    // right after it is read, rather than kept for the rest of the call.
    let read_signed_one = |h: &Hash| -> Result<Option<(Hash, Object)>, SyncError> {
        let obj = store.read_object(h)?;
        #[cfg(test)]
        test_counts::note_read(*h);
        Ok(match obj {
            Object::Commit(_) | Object::Remix(_) | Object::Tag(_) => Some((*h, obj)),
            Object::Blob(_) | Object::Tree(_) | Object::ChunkedBlob(_) | Object::Delta(_) => None,
        })
    };
    let entries: Vec<(Hash, Object)> = if parallel {
        hashes
            .par_iter()
            .filter_map(|h| read_signed_one(h).transpose())
            .collect::<Result<_, _>>()?
    } else {
        hashes
            .iter()
            .filter_map(|h| read_signed_one(h).transpose())
            .collect::<Result<_, _>>()?
    };

    verify_entries(&entries, parallel)
}

/// Verify the signature of every entry in `entries`, as a batch first, and
/// object by object only when the batch fails, so the first failure names
/// the offending hash. In parallel iff `parallel`.
fn verify_entries(entries: &[(Hash, Object)], parallel: bool) -> Result<(), SyncError> {
    if batch_entries(entries).is_some_and(|batch| verify_batch(&batch, parallel)) {
        return Ok(());
    }
    if parallel {
        entries
            .par_iter()
            .try_for_each(|(h, obj)| verify_one_object(*h, obj))
    } else {
        entries
            .iter()
            .try_for_each(|(h, obj)| verify_one_object(*h, obj))
    }
}

/// The objects whose history has been verified in full, which a walk need
/// not read again. A fetch starts it from the tips earlier signed fetches
/// recorded ([`crate::anchor`]). An object enters it only once the walk that
/// reached it has succeeded. It lives for one fetch (and the pull after it)
/// and holds the union of the histories that fetch verified: each walk is
/// capped, the union is not, so a remote with many unrelated branches costs
/// 32 bytes of id per signed object it delivered.
pub(crate) type VerifiedHistory = HashSet<Hash>;

/// Checks the signatures of one chunk of a history walk.
type ChunkCheck<'a> = dyn Fn(&[(Hash, Object)]) -> Result<(), SyncError> + 'a;

/// The signature failures one fetch found in history walks: each object
/// whose history holds an object that failed its signature check, mapped to
/// that object's hex id and the failure. A walk that reaches one of them
/// fails at once with the same failure, so many tags over one bad history
/// cost one walk. It lives for one fetch. Each failure is stored once, and
/// each object holds only its index.
#[derive(Default)]
pub(crate) struct FailedHistory {
    /// Each failure: the failing object's hex id and the reason.
    failures: Vec<(String, String)>,
    /// The index in `failures` of each failure's hex id.
    index: HashMap<String, u32>,
    /// Each object whose history holds a failure, and that failure's index.
    at: HashMap<Hash, u32>,
}

impl FailedHistory {
    /// The failure in the history of `h`: the failing object's hex id and
    /// the reason.
    pub(crate) fn get(&self, h: &Hash) -> Option<&(String, String)> {
        self.at.get(h).map(|&i| &self.failures[i as usize])
    }

    /// Add `at` and every object on the walk path from the walk's tip to it,
    /// each with the failure of `hash`. At most `cap` objects are held; past
    /// that the memory is cleared, which makes later walks longer only.
    fn remember(
        &mut self,
        via: &HashMap<Hash, Hash>,
        at: Hash,
        hash: &str,
        reason: &str,
        cap: usize,
    ) {
        let mut next = Some(at);
        let mut failure = self.failure(hash, reason);
        while let Some(h) = next {
            if self.at.len() >= cap {
                self.at.clear();
                self.failures.clear();
                self.index.clear();
                failure = self.failure(hash, reason);
            }
            self.at.insert(h, failure);
            next = via.get(&h).copied();
        }
    }

    /// The index of the failure of `hash`, added when new.
    fn failure(&mut self, hash: &str, reason: &str) -> u32 {
        if let Some(&i) = self.index.get(hash) {
            return i;
        }
        let i = u32::try_from(self.failures.len()).unwrap_or(u32::MAX);
        self.failures.push((hash.to_owned(), reason.to_owned()));
        self.index.insert(hash.to_owned(), i);
        i
    }
}

/// The missing objects one fetch found in history walks and closure checks:
/// each object whose closure lacks a missing object, mapped to that object.
/// A walk that reaches one of them ends at once as at the missing object.
/// Unlike a signature failure, this holds only while the object is missing,
/// so its owner drops an entry once the store holds its object.
pub(crate) type MissingHistory = HashMap<Hash, Hash>;

/// Verify the signature of every commit, remix and tag in the history of
/// `tip`: `tip` itself, the parents of each commit and remix, and the target
/// of each tag, recursively. Trees and blobs carry no signature and name no
/// signed object, so where a parent, a tag or `tip` names one the walk reads
/// only its type and goes no further. Remix `sources` are foreign-repo pointers and are not
/// followed (SPEC-OBJECTS §6).
///
/// [`verify_new_object_signatures`] checks the objects of the packs one run
/// applies, but a ref can name history that no such pack carries: objects a
/// refused pack left in the store, objects another remote or a fetch without
/// verification wrote, or a pack the applied-pack record skips. Fetch runs
/// this on each tip right before it publishes the tip, so what a ref names
/// is checked whatever path its objects took into the store.
///
/// An object in `verified` had its whole history verified, by an earlier
/// walk or by the signed fetch that recorded it, so the walk stops there.
/// This makes the walk a range check: it reads the commits between `tip` and
/// what was verified before. When the walk succeeds, every object it
/// visited joins `verified`; when it fails, `verified` is unchanged.
///
/// One walk visits at most [`kit_core::ops::graph::MAX_REACHABLE`] objects,
/// the cap of the closure check fetch runs first over a superset of this
/// history. A longer history is [`SyncError::ClosureTooLarge`], never a
/// partial check. The signed objects are checked in chunks of
/// [`verify_chunk_size`] as the walk reads them, so at most one chunk of
/// decoded objects is held at a time, and `observer` is polled for
/// cancellation after each full chunk.
pub(crate) fn verify_history_signatures(
    store: &ObjectStore,
    observer: &dyn Observer<SyncEvent>,
    tip: &Hash,
    verified: &mut VerifiedHistory,
) -> Result<(), SyncError> {
    let mut walk = HistoryWalk {
        verified,
        anchored: None,
        failed: None,
        missing: None,
        cap: kit_core::ops::graph::MAX_REACHABLE,
        read: 0,
    };
    walk.run(store, observer, tip)
}

/// One [`verify_history_signatures`] walk, with the knobs the tag phase of a
/// fetch adds: more verified history, a memory of failures and missing
/// objects, and a cap it can lower in a test.
pub(crate) struct HistoryWalk<'a> {
    pub(crate) verified: &'a mut VerifiedHistory,
    /// More objects whose history was verified in full, which the walk stops
    /// at like `verified` but does not copy into it.
    pub(crate) anchored: Option<&'a HashSet<Hash>>,
    /// When set, a walk fails at once on an object it holds, and a failed
    /// walk adds the failing object and the objects on its walk path to it.
    pub(crate) failed: Option<&'a mut FailedHistory>,
    /// When set, a walk ends at once on an object it holds, as at a missing
    /// object, and a walk that finds an object missing adds that object and
    /// the objects on its walk path to it.
    pub(crate) missing: Option<&'a mut MissingHistory>,
    /// The most objects one walk visits.
    pub(crate) cap: usize,
    /// Commits, remixes and tags the walk read in full, counted on success
    /// and failure.
    pub(crate) read: usize,
}

impl HistoryWalk<'_> {
    /// Walk the history of `tip` as [`verify_history_signatures`] describes.
    pub(crate) fn run(
        &mut self,
        store: &ObjectStore,
        observer: &dyn Observer<SyncEvent>,
        tip: &Hash,
    ) -> Result<(), SyncError> {
        let mut progress_at = std::time::Instant::now();
        observer.event(&SyncEvent::SignatureProgress { done: 0 });
        let chunk = verify_chunk_size();
        let check = |entries: &[(Hash, Object)]| {
            verify_entries(entries, entries.len() >= verify_fanout_threshold())
        };
        let tracking = self.failed.is_some() || self.missing.is_some();
        // The object that first named each one, to find the walk path to a
        // failing or missing object. Kept only when either is remembered.
        let mut via: HashMap<Hash, Hash> = HashMap::new();
        let mut seen: HashSet<Hash> = HashSet::new();
        let mut pending = vec![*tip];
        let mut entries: Vec<(Hash, Object)> = Vec::new();
        while let Some(h) = pending.pop() {
            if self.verified.contains(&h)
                || self.anchored.is_some_and(|anchored| anchored.contains(&h))
                || !seen.insert(h)
            {
                continue;
            }
            if let Some(failed) = self.failed.as_deref_mut()
                && let Some((hash, reason)) = failed.get(&h).cloned()
            {
                failed.remember(&via, h, &hash, &reason, self.cap);
                return Err(SyncError::UnsignedOrInvalidObject { hash, reason });
            }
            if let Some(object) = self.missing.as_deref().and_then(|m| m.get(&h).copied()) {
                return Err(self.missing_at(&via, h, object));
            }
            if seen.len() > self.cap {
                return Err(SyncError::ClosureTooLarge(self.cap));
            }
            // A leaf carries no signature and names no signed object, so only
            // its type prologue is read, like the closure check does: a parent or
            // tag target that is a large blob costs no full read.
            let ty = match store.object_type(&h) {
                Err(StoreError::ObjectNotFound(_)) => return Err(self.missing_at(&via, h, h)),
                ty => ty?,
            };
            if !matches!(ty, ObjectType::Commit | ObjectType::Remix | ObjectType::Tag) {
                continue;
            }
            let obj = match store.read_object(&h) {
                Err(StoreError::ObjectNotFound(_)) => return Err(self.missing_at(&via, h, h)),
                obj => obj?,
            };
            self.read += 1;
            let before = pending.len();
            match &obj {
                Object::Commit(c) => pending.extend(&c.parents),
                Object::Remix(r) => pending.extend(&r.parents),
                // The target is followed whatever type the tag declares: the
                // walk decides by the type of the object it reads, so a tag
                // that calls a commit a tree does not hide it.
                Object::Tag(t) => pending.push(t.target),
                Object::Blob(_) | Object::Tree(_) | Object::ChunkedBlob(_) | Object::Delta(_) => {
                    continue;
                }
            }
            if tracking {
                for child in &pending[before..] {
                    via.entry(*child).or_insert(h);
                }
            }
            entries.push((h, obj));
            if entries.len() >= chunk {
                self.check_chunk(&entries, &check, &via)?;
                if progress_at.elapsed() >= std::time::Duration::from_millis(100) {
                    observer.event(&SyncEvent::SignatureProgress { done: self.read });
                    progress_at = std::time::Instant::now();
                }
                entries.clear();
                if observer.cancelled() {
                    return Err(SyncError::Interrupted);
                }
            }
        }
        self.check_chunk(&entries, &check, &via)?;
        observer.event(&SyncEvent::SignatureProgress { done: self.read });
        self.verified.extend(seen);
        Ok(())
    }

    /// The error of a walk that reached `at`, whose closure lacks `object`,
    /// remembered on the walk path when missing objects are remembered.
    fn missing_at(&mut self, via: &HashMap<Hash, Hash>, at: Hash, object: Hash) -> SyncError {
        if let Some(missing) = self.missing.as_deref_mut() {
            remember_missing(missing, via, at, object, self.cap);
        }
        SyncError::Store(StoreError::ObjectNotFound(hash::to_hex(&object)))
    }

    /// Check one chunk, and remember a signature failure when failures are
    /// remembered.
    fn check_chunk(
        &mut self,
        entries: &[(Hash, Object)],
        check: &ChunkCheck<'_>,
        via: &HashMap<Hash, Hash>,
    ) -> Result<(), SyncError> {
        let result = check(entries);
        if let Err(SyncError::UnsignedOrInvalidObject { hash, reason }) = &result
            && let Some(failed) = self.failed.as_deref_mut()
            && let Some(at) = kit_core::refs::parse_lowercase_hash(hash.as_bytes())
        {
            failed.remember(via, at, hash, reason, self.cap);
        }
        result
    }
}

/// Add `at` and every object on the walk path from the walk's tip to it to
/// `missing`, each mapped to the missing `object`. `missing` holds at most
/// `cap` objects; past that it is cleared, which makes later walks longer
/// only.
pub(crate) fn remember_missing(
    missing: &mut MissingHistory,
    via: &HashMap<Hash, Hash>,
    at: Hash,
    object: Hash,
    cap: usize,
) {
    let mut next = Some(at);
    while let Some(h) = next {
        if missing.len() >= cap {
            missing.clear();
        }
        missing.insert(h, object);
        next = via.get(&h).copied();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observer::NoopObserver;
    use kit_core::object::Object;

    fn h(seed: &str) -> Hash {
        hash::hash(seed.as_bytes())
    }

    /// Each object with its stored size, as an unpack lists signed objects.
    fn sized(store: &ObjectStore, hashes: &[Hash]) -> Vec<(Hash, u32)> {
        hashes
            .iter()
            .map(|h| {
                let len = store.object_len(h).unwrap();
                (*h, u32::try_from(len).unwrap())
            })
            .collect()
    }

    // ---- verify_new_object_signatures — sequential/rayon fan-out parity ----

    /// A validly-signed, independently-hashing commit — every `seed`
    /// produces a distinct object, matching the bench fixtures'
    /// no-dedup convention.
    fn signed_commit_bytes(kp: &kit_core::sign::KeyPair, seed: usize) -> Vec<u8> {
        use kit_core::object::{Commit, Identity};
        let mut c = Commit::new_unannotated(
            hash::hash(format!("tree #{seed}").as_bytes()),
            Vec::new(),
            Identity::ed25519(kp.public.0),
            kp.public.0,
            format!("packmap fanout test fixture #{seed}").into_bytes(),
            1_700_000_000 + seed as u64,
            [0u8; 64],
        );
        c.signature = kit_core::sign::sign_commit(&c, kp).unwrap().0;
        kit_core::serialize::serialize(&Object::Commit(c)).unwrap()
    }

    /// Large enough that `stored.len()` clears
    /// [`verify_fanout_threshold`] on any realistic thread-pool size
    /// (`VERIFY_FANOUT_ENTRIES_PER_THREAD` * rayon's pool size), so
    /// these tests exercise the `par_iter` branch rather than the
    /// sequential one the integration tests in
    /// `tests/verify_signatures_on_fetch.rs` already cover.
    const LARGE_BATCH: usize = 512;

    #[test]
    fn verify_new_object_signatures_accepts_a_large_validly_signed_batch() {
        let dir = tempfile::tempdir().unwrap();
        let layout = kit_core::layout::RepoLayout::single(dir.path());
        let store = ObjectStore::init(&layout).unwrap();
        let kp = kit_core::sign::KeyPair::generate().unwrap();
        let stored: Vec<Hash> = (0..LARGE_BATCH)
            .map(|i| store.write(&signed_commit_bytes(&kp, i)).unwrap())
            .collect();
        assert!(stored.len() >= verify_fanout_threshold());

        verify_new_object_signatures(&store, &sized(&store, &stored), true)
            .expect("every commit in the batch is validly signed");
    }

    /// Regression for `verify_slice`'s read step: a chunk mixing unsigned
    /// object kinds (Blob/Tree — neither carries a signature) with signed
    /// commits must still verify correctly. `verify_slice` reads every
    /// hash to learn its type but only *retains* Commit/Remix/Tag entries
    /// afterward (dropping Blob/Tree/ChunkedBlob/Delta immediately) — this
    /// pins that the filtering doesn't drop a commit it should have kept,
    /// doesn't get confused by interleaving, and both a validly-signed and
    /// a tampered commit are still correctly accepted/rejected when
    /// surrounded by unsigned entries on both sides.
    #[test]
    fn verify_new_object_signatures_mixed_with_unsigned_object_kinds() {
        let dir = tempfile::tempdir().unwrap();
        let layout = kit_core::layout::RepoLayout::single(dir.path());
        let store = ObjectStore::init(&layout).unwrap();
        let kp = kit_core::sign::KeyPair::generate().unwrap();

        let batch = store.batch();
        let blob = |seed: usize| -> Hash {
            batch
                .write(
                    &kit_core::serialize::serialize(&Object::Blob(kit_core::object::Blob {
                        data: format!("unsigned blob fixture #{seed}").into_bytes(),
                    }))
                    .unwrap(),
                )
                .unwrap()
        };

        // Blob, commit, blob, commit, ... — unsigned entries on both
        // sides of every signed one, so a filtering bug that drops or
        // misattributes a neighbor would show up either direction.
        let mut stored: Vec<Hash> = Vec::with_capacity(2 * LARGE_BATCH);
        for i in 0..LARGE_BATCH {
            stored.push(blob(i));
            stored.push(batch.write(&signed_commit_bytes(&kp, i)).unwrap());
        }
        batch.commit().unwrap();
        assert!(stored.len() >= verify_fanout_threshold());

        verify_new_object_signatures(&store, &sized(&store, &stored), true)
            .expect("unsigned entries must not affect verifying the signed ones");

        // Tamper one of the commits — must still be caught even though
        // it's surrounded by unsigned entries the check skips.
        let commit_index = 2 * (LARGE_BATCH / 2) + 1;
        let Object::Commit(mut c) = store.read_object(&stored[commit_index]).unwrap() else {
            panic!("expected commit");
        };
        c.signature[0] ^= 0xff;
        let tampered_bytes = kit_core::serialize::serialize(&Object::Commit(c)).unwrap();
        stored[commit_index] = store.write(&tampered_bytes).unwrap();

        let err = verify_new_object_signatures(&store, &sized(&store, &stored), true)
            .expect_err("a tampered commit must still be caught alongside unsigned entries");
        assert!(matches!(err, SyncError::UnsignedOrInvalidObject { .. }));
    }

    #[test]
    fn verify_new_object_signatures_rejects_one_bad_signature_in_a_large_batch() {
        let dir = tempfile::tempdir().unwrap();
        let layout = kit_core::layout::RepoLayout::single(dir.path());
        let store = ObjectStore::init(&layout).unwrap();
        let kp = kit_core::sign::KeyPair::generate().unwrap();
        let mut stored: Vec<Hash> = (0..LARGE_BATCH)
            .map(|i| store.write(&signed_commit_bytes(&kp, i)).unwrap())
            .collect();
        assert!(stored.len() >= verify_fanout_threshold());

        // Tamper one commit's signature in place — content-addressing stays
        // intact (re-written under a new hash), only the crypto is wrong,
        // same attacker model as `tamper_head_commit_signature` in the
        // integration test.
        let Object::Commit(mut c) = store.read_object(&stored[LARGE_BATCH / 2]).unwrap() else {
            panic!("expected commit");
        };
        c.signature[0] ^= 0xff;
        let tampered_bytes = kit_core::serialize::serialize(&Object::Commit(c)).unwrap();
        let tampered_hash = store.write(&tampered_bytes).unwrap();
        stored[LARGE_BATCH / 2] = tampered_hash;

        let err = verify_new_object_signatures(&store, &sized(&store, &stored), true)
            .expect_err("a batch with one bad signature must be rejected");
        assert!(matches!(err, SyncError::UnsignedOrInvalidObject { .. }));
    }

    #[test]
    fn verify_new_object_signatures_never_reads_past_the_chunk_containing_the_first_bad_signature()
    {
        // Regression for the chunked fan-out: a hostile remote must not be
        // able to force verification work past the chunk containing the
        // first invalid signature. The first `chunk_size` entries are a
        // validly-signed batch with one tampered signature; every entry
        // after that names a digest that was NEVER written to the store.
        // If the implementation ever started a second chunk, reading one
        // of those would surface as a store error (`ObjectNotFound`), not
        // `UnsignedOrInvalidObject` — so this test fails deterministically
        // if chunking regresses back to a single flat fan-out (or any
        // other shape that can read beyond the first failing chunk).
        let dir = tempfile::tempdir().unwrap();
        let layout = kit_core::layout::RepoLayout::single(dir.path());
        let store = ObjectStore::init(&layout).unwrap();
        let kp = kit_core::sign::KeyPair::generate().unwrap();
        let chunk_size = verify_chunk_size();

        let mut stored: Vec<Hash> = (0..chunk_size)
            .map(|i| store.write(&signed_commit_bytes(&kp, i)).unwrap())
            .collect();
        let Object::Commit(mut c) = store.read_object(&stored[0]).unwrap() else {
            panic!("expected commit");
        };
        c.signature[0] ^= 0xff;
        let tampered_bytes = kit_core::serialize::serialize(&Object::Commit(c)).unwrap();
        let tampered_hash = store.write(&tampered_bytes).unwrap();
        stored[0] = tampered_hash;
        let mut signed = sized(&store, &stored);
        signed.extend((0..chunk_size * 3).map(|i| (h(&format!("never-written-{i}")), 100)));

        let err = verify_new_object_signatures(&store, &signed, true)
            .expect_err("the tampered signature in the first chunk must reject the fetch");
        match err {
            SyncError::UnsignedOrInvalidObject { hash: got, .. } => {
                assert_eq!(got, hash::to_hex(&tampered_hash));
            }
            other => panic!("expected UnsignedOrInvalidObject, got {other:?}"),
        }
    }

    /// A commit over the tree `seed` names, parented on `parents`, signed
    /// with `kp` when `signed`.
    fn history_commit(
        store: &impl kit_core::store::ObjectSink,
        kp: &kit_core::sign::KeyPair,
        seed: usize,
        parents: Vec<Hash>,
        signed: bool,
    ) -> Hash {
        use kit_core::object::{Commit, Identity};
        let mut c = Commit::new_unannotated(
            h(&format!("tree #{seed}")),
            parents,
            Identity::ed25519(kp.public.0),
            kp.public.0,
            format!("history #{seed}").into_bytes(),
            1_700_000_000 + seed as u64,
            [0u8; 64],
        );
        if signed {
            c.signature = kit_core::sign::sign_commit(&c, kp).unwrap().0;
        }
        store
            .put(&kit_core::serialize::serialize(&Object::Commit(c)).unwrap())
            .unwrap()
    }

    /// The walk reaches the root below more than one chunk of signed
    /// commits, through a merge's first parent, and names it when it is
    /// unsigned.
    #[test]
    fn verify_history_signatures_finds_an_unsigned_root_below_a_long_history() {
        let dir = tempfile::tempdir().unwrap();
        let store = ObjectStore::init(&kit_core::layout::RepoLayout::single(dir.path())).unwrap();
        let kp = kit_core::sign::KeyPair::generate().unwrap();
        let line = |root_signed: bool, offset: usize| {
            let batch = store.batch();
            let root = history_commit(&batch, &kp, offset, Vec::new(), root_signed);
            let mut tip = root;
            for seed in 1..verify_chunk_size() + 8 {
                tip = history_commit(&batch, &kp, offset + seed, vec![tip], true);
            }
            batch.commit().unwrap();
            (root, tip)
        };
        let (_, clean) = line(true, 0);
        verify_history_signatures(&store, &NoopObserver, &clean, &mut VerifiedHistory::new())
            .expect("every commit is signed");
        let (unsigned, forged) = line(false, 10_000);
        let merge = history_commit(&store, &kp, 20_000, vec![forged, clean], true);
        match verify_history_signatures(&store, &NoopObserver, &merge, &mut VerifiedHistory::new())
        {
            Err(SyncError::UnsignedOrInvalidObject { hash: got, .. }) => {
                assert_eq!(got, hash::to_hex(&unsigned));
            }
            other => panic!("expected UnsignedOrInvalidObject, got {other:?}"),
        }
    }

    /// A walk that succeeds adds what it visited to the verified set, and a
    /// later walk stops at it without reading it. A walk that fails leaves
    /// the set as it was, and a cancelled one stops after a full chunk.
    #[test]
    fn verify_history_signatures_reuses_only_a_successful_walk() {
        struct Cancelled;
        impl Observer<SyncEvent> for Cancelled {
            fn event(&self, _: &SyncEvent) {}
            fn cancelled(&self) -> bool {
                true
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let store = ObjectStore::init(&kit_core::layout::RepoLayout::single(dir.path())).unwrap();
        let kp = kit_core::sign::KeyPair::generate().unwrap();
        let root = history_commit(&store, &kp, 0, Vec::new(), true);
        let mut tip = root;
        for seed in 1..verify_chunk_size() + 8 {
            tip = history_commit(&store, &kp, seed, vec![tip], true);
        }
        assert!(matches!(
            verify_history_signatures(&store, &Cancelled, &tip, &mut VerifiedHistory::new()),
            Err(SyncError::Interrupted)
        ));

        let mut verified = VerifiedHistory::new();
        verify_history_signatures(&store, &NoopObserver, &tip, &mut verified).unwrap();
        assert!(verified.contains(&root) && verified.contains(&tip));
        let before = verified.clone();
        let unsigned = history_commit(&store, &kp, 20_000, vec![tip], false);
        assert!(matches!(
            verify_history_signatures(&store, &NoopObserver, &unsigned, &mut verified),
            Err(SyncError::UnsignedOrInvalidObject { .. })
        ));
        assert_eq!(verified, before);

        // The root is gone, and a walk over the verified history does not
        // read it.
        store.remove_object(&root).unwrap();
        let next = history_commit(&store, &kp, 30_000, vec![tip], true);
        verify_history_signatures(&store, &NoopObserver, &next, &mut verified).unwrap();
        assert!(verified.contains(&next));
    }

    /// A tag is checked and so is the commit it names, whatever type the tag
    /// declares for it. A tag that names a tree is checked itself, and the
    /// walk reads only the tree's type and stops there.
    #[test]
    fn verify_history_signatures_checks_a_tag_and_its_target() {
        use kit_core::object::{Identity, Tag};
        let dir = tempfile::tempdir().unwrap();
        let store = ObjectStore::init(&kit_core::layout::RepoLayout::single(dir.path())).unwrap();
        let kp = kit_core::sign::KeyPair::generate().unwrap();
        let tag = |target: Hash, target_type: ObjectType| {
            let mut t = Tag {
                target,
                target_type,
                name: b"v1".to_vec(),
                tagger: Identity::ed25519(kp.public.0),
                signer: kp.public.0,
                message: b"release".to_vec(),
                timestamp: 1_700_000_000,
                signature: [0u8; 64],
            };
            t.signature = kit_core::sign::sign_tag(&t, &kp).unwrap().0;
            store
                .write(&kit_core::serialize::serialize(&Object::Tag(t)).unwrap())
                .unwrap()
        };
        let unsigned = history_commit(&store, &kp, 0, Vec::new(), false);
        let over_unsigned = tag(unsigned, ObjectType::Commit);
        assert!(matches!(
            verify_history_signatures(&store, &NoopObserver, &over_unsigned, &mut VerifiedHistory::new()),
            Err(SyncError::UnsignedOrInvalidObject { hash: got, .. }) if got == hash::to_hex(&unsigned)
        ));
        let signed = history_commit(&store, &kp, 1, Vec::new(), true);
        verify_history_signatures(
            &store,
            &NoopObserver,
            &tag(signed, ObjectType::Commit),
            &mut VerifiedHistory::new(),
        )
        .unwrap();
        let tree = store
            .write(
                &kit_core::serialize::serialize(&Object::Tree(kit_core::object::Tree {
                    entries: Vec::new(),
                }))
                .unwrap(),
            )
            .unwrap();
        verify_history_signatures(
            &store,
            &NoopObserver,
            &tag(tree, ObjectType::Tree),
            &mut VerifiedHistory::new(),
        )
        .unwrap();
        // A tag that declares a tree but names the unsigned commit.
        assert!(matches!(
            verify_history_signatures(&store, &NoopObserver, &tag(unsigned, ObjectType::Tree), &mut VerifiedHistory::new()),
            Err(SyncError::UnsignedOrInvalidObject { hash: got, .. }) if got == hash::to_hex(&unsigned)
        ));
    }

    /// Runs of the check hold at most `VERIFY_INFLIGHT_BYTES` of objects: a
    /// batch of signed objects recorded at 1 MiB each is checked in runs of at
    /// most 128, and one recorded over the budget runs alone.
    #[test]
    fn the_signature_check_runs_within_its_inflight_budget() {
        let dir = tempfile::tempdir().unwrap();
        let layout = kit_core::layout::RepoLayout::single(dir.path());
        let store = ObjectStore::init(&layout).unwrap();
        let kp = kit_core::sign::KeyPair::generate().unwrap();
        let hashes: Vec<Hash> = (0..300)
            .map(|i| store.write(&signed_commit_bytes(&kp, 10_000 + i)).unwrap())
            .collect();
        let mut signed: Vec<(Hash, u32)> = hashes.iter().map(|&h| (h, 1 << 20)).collect();
        signed[200].1 = u32::MAX;

        verify_new_object_signatures(&store, &signed, true).unwrap();

        // 128 objects fill the budget; the 72 up to the large one, the large
        // one alone, then the 99 after it.
        let mib = 1 << 20;
        assert_eq!(
            test_counts::runs_from(&hashes),
            vec![256 * mib, 144 * mib, verify_charge(u32::MAX), 198 * mib]
        );
        assert_eq!(test_counts::reads_of(&hashes), 300);
    }

    #[test]
    fn verify_new_object_signatures_require_signed_false_skips_a_large_batch() {
        // `require_signed = false` must short-circuit to `Ok(())` without
        // reading the store at all, regardless of batch size — pass a
        // digest list naming objects that were never written, so any
        // attempted read would panic/error and fail the test.
        let dir = tempfile::tempdir().unwrap();
        let layout = kit_core::layout::RepoLayout::single(dir.path());
        let store = ObjectStore::init(&layout).unwrap();
        let signed: Vec<(Hash, u32)> = (0..LARGE_BATCH)
            .map(|i| (h(&format!("never-written-{i}")), 100))
            .collect();

        verify_new_object_signatures(&store, &signed, false)
            .expect("require_signed=false must no-op regardless of batch size");
    }
}
