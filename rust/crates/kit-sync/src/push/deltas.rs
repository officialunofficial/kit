//! The delta streams of one push: encoded under a memory budget and kept in
//! one spool file, so no plan holds them in memory.

use std::cell::RefCell;
use std::collections::HashMap;
use std::path::PathBuf;

use kit_core::delta;
use kit_core::hash::Hash;
use kit_core::store::{ObjectStore, StoreError};
use kit_core::transfer::{self, DeltaCandidate, DeltaSpool, PackPlan, PlannedDelta};

/// Bytes the parallel delta encoders of a push may hold at once, each
/// charged its real peak ([`encoder_peak`]). One encoder over the budget runs
/// alone.
pub(crate) const DELTA_INFLIGHT_BYTES: u64 = 256 << 20;

/// Plans the packs of one push. Every plan it makes, split probes included,
/// shares one [`DeltaSpool`], created in the store's spool directory when
/// the first delta is encoded and dropped with the push: a `(target, base)`
/// pair is encoded once per push, and a plan holds where each stream lies,
/// not its bytes.
#[derive(Debug)]
pub(crate) struct DeltaEncoder {
    dir: PathBuf,
    spool: RefCell<Option<DeltaSpool>>,
}

impl DeltaEncoder {
    /// An encoder whose spool goes in `dir`.
    pub(crate) fn new(dir: PathBuf) -> Self {
        Self {
            dir,
            spool: RefCell::new(None),
        }
    }

    /// [`transfer::plan_pack_with`] for `tip` against `base`, with every delta
    /// stream in the push's spool. Each run of encoders writes its streams to
    /// the spool before the next run starts, so the streams held at once are
    /// one run's, within [`DELTA_INFLIGHT_BYTES`].
    pub(crate) fn plan(
        &self,
        store: &ObjectStore,
        tip: Hash,
        base: Option<Hash>,
    ) -> Result<PackPlan, StoreError> {
        transfer::plan_pack_with(store, tip, base, |store, candidates| {
            self.encode(store, candidates)
        })
    }

    /// [`transfer::plan_pack_tips`] for `tips` against `base`, with every
    /// delta stream in the push's spool, as [`Self::plan`].
    pub(crate) fn plan_tips(
        &self,
        store: &ObjectStore,
        tips: &[Hash],
        base: Option<Hash>,
    ) -> Result<PackPlan, StoreError> {
        transfer::plan_pack_tips(store, tips, base, |store, candidates| {
            self.encode(store, candidates)
        })
    }

    /// The `encode_deltas` callback of a planner: one result per candidate,
    /// in order, each stream in the push's spool.
    pub(crate) fn encode(
        &self,
        store: &ObjectStore,
        candidates: &[DeltaCandidate],
    ) -> Result<Vec<Option<PlannedDelta>>, StoreError> {
        let mut slot = self.spool.borrow_mut();
        if slot.is_none() {
            *slot = Some(DeltaSpool::create(&self.dir)?);
        }
        let spool = slot.as_mut().expect("the spool was just created");
        encode_in_runs(store, candidates, |run, bases| {
            spool.encode(store, run, |store, fresh| encode_run(store, fresh, bases))
        })
    }
}

/// The most heap one encoder holds: the target, the base, the output
/// reserved at its worst case ([`delta::max_encoded_len`]), and the block
/// index, one slot per 16-byte block of the base, rounded up to the power of
/// two the map allocates, at the 16-byte entry plus one control byte of
/// each slot.
pub(crate) fn encoder_peak(target_len: u64, base_len: u64) -> u64 {
    let blocks = base_len / 16;
    let slots = (blocks.saturating_mul(8) / 7 + 1).next_power_of_two();
    let output = delta::max_encoded_len(usize::try_from(target_len).unwrap_or(usize::MAX)) as u64;
    target_len
        .saturating_add(base_len)
        .saturating_add(output)
        .saturating_add(slots.saturating_mul(17))
}

/// Split `charges` into consecutive runs whose sum stays within `budget`. A
/// single charge over the budget is a run of its own.
pub(crate) fn admit_runs(charges: &[u64], budget: u64) -> Vec<usize> {
    let mut runs = Vec::new();
    let (mut held, mut count) = (0u64, 0usize);
    for &charge in charges {
        if count > 0 && held.saturating_add(charge) > budget {
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

/// Diffs every delta candidate `plan_pack_with` found, with each stream
/// held in memory: the in-memory counterpart of [`DeltaEncoder::plan`],
/// which tests compare it with.
#[cfg(test)]
pub(crate) fn encode_delta_candidates_batch(
    store: &ObjectStore,
    candidates: &[DeltaCandidate],
) -> Result<Vec<Option<PlannedDelta>>, StoreError> {
    encode_in_runs(store, candidates, |run, bases| {
        encode_run(store, run, bases)
    })
}

/// Hand `candidates` to `run_fn` in runs, and return its results in order.
///
/// Takes at most [`DELTA_CANDIDATE_BATCH_CAP`] candidates at a time.
/// Repeated bases share a cache capped at [`DELTA_BASE_CACHE_BYTES`];
/// one-use bases and bases that do not fit are read by each encoder.
/// Metadata checks avoid reading nonfitting bases twice. The cache is
/// dropped before the next batch. Within a batch, the runs are consecutive
/// candidates whose summed [`encoder_peak`] stays within
/// [`DELTA_INFLIGHT_BYTES`], sized from the store's metadata before any
/// object is read; one encoder over the budget runs alone.
fn encode_in_runs(
    store: &ObjectStore,
    candidates: &[DeltaCandidate],
    mut run_fn: impl FnMut(
        &[DeltaCandidate],
        &HashMap<Hash, Vec<u8>>,
    ) -> Result<Vec<Option<PlannedDelta>>, StoreError>,
) -> Result<Vec<Option<PlannedDelta>>, StoreError> {
    let mut results = Vec::with_capacity(candidates.len());
    for batch in candidates.chunks(DELTA_CANDIDATE_BATCH_CAP) {
        let base_bytes = cache_delta_bases(store, batch, DELTA_BASE_CACHE_BYTES)?;
        let charges = batch
            .iter()
            .map(|c| {
                Ok(encoder_peak(
                    store.object_len(&c.target)?,
                    store.object_len(&c.base)?,
                ))
            })
            .collect::<Result<Vec<_>, StoreError>>()?;
        let mut start = 0;
        for run in admit_runs(&charges, DELTA_INFLIGHT_BYTES) {
            results.extend(run_fn(&batch[start..start + run], &base_bytes)?);
            start += run;
        }
    }
    Ok(results)
}

/// Diff each candidate of one run: sequentially below
/// [`delta_plan_fanout_threshold`], via rayon's global thread pool at or
/// above it. Each candidate's `delta::encode` is independent of every
/// other's, so a push touching many changed blobs parallelizes the diffing
/// itself, not just the downstream zstd pass. A base in `bases` is not read
/// again. Order matches `run` 1:1.
fn encode_run(
    store: &ObjectStore,
    run: &[DeltaCandidate],
    bases: &HashMap<Hash, Vec<u8>>,
) -> Result<Vec<Option<PlannedDelta>>, StoreError> {
    crate::fanout::try_map_seq_or_par(run, delta_plan_fanout_threshold(), |&c| {
        match bases.get(&c.base) {
            Some(bytes) => transfer::encode_delta_candidate_with_base(store, c, bytes),
            None => transfer::encode_delta_candidate(store, c),
        }
    })
}

/// Entries-per-thread budget below which [`encode_run`]
/// diffs candidates sequentially instead of fanning out across rayon's
/// thread pool. Each entry pays two disk reads (target + base) plus
/// `delta::encode`'s block-hash-table build and greedy scan over the
/// target's full length.
///
/// `cargo bench -p kit-benches --bench delta_plan_fanout` on a 4-core
/// host, isolating `delta::encode` over synthetic 64 KiB
/// (FastCDC-average-sized) near-duplicate chunks:
///
///   n=256: sequential 46.99ms -> rayon 14.79ms (3.18x)
///   n=64:  sequential 11.65ms -> rayon  3.67ms (3.18x)
///   n=8:   sequential  1.38ms -> rayon  0.70ms (1.97x)
///   n=2:   sequential  0.34ms -> rayon  0.33ms (roughly flat)
///   n=1:   sequential  0.17ms -> rayon  0.17ms (roughly flat)
///
/// Each candidate already costs ~0.17ms, comfortably above rayon's
/// microsecond-scale dispatch overhead, so the crossover falls at the
/// smallest candidate count worth fanning out at all.
const DELTA_PLAN_FANOUT_ENTRIES_PER_THREAD: usize = 1;

/// The candidate count [`encode_run`] fans out across
/// rayon at — see [`DELTA_PLAN_FANOUT_ENTRIES_PER_THREAD`].
pub(crate) fn delta_plan_fanout_threshold() -> usize {
    crate::fanout::threshold(DELTA_PLAN_FANOUT_ENTRIES_PER_THREAD)
}

/// Maximum number of candidates whose base objects are cached together.
pub(crate) const DELTA_CANDIDATE_BATCH_CAP: usize = 64;

/// Maximum retained payload bytes for reused bases, independent of blob sizes.
pub(crate) const DELTA_BASE_CACHE_BYTES: usize = 64 * 1024 * 1024;

pub(crate) fn cache_delta_bases(
    store: &ObjectStore,
    candidates: &[DeltaCandidate],
    byte_budget: usize,
) -> Result<HashMap<Hash, Vec<u8>>, StoreError> {
    let mut counts = std::collections::BTreeMap::<Hash, usize>::new();
    for candidate in candidates {
        *counts.entry(candidate.base).or_default() += 1;
    }
    let mut cache = HashMap::new();
    let mut remaining = byte_budget;
    for (base, count) in counts {
        if count < 2 || remaining == 0 {
            continue;
        }
        if store.object_len(&base)? > remaining as u64 {
            continue;
        }
        let bytes = store.read(&base)?;
        // Recheck after reading: metadata is only an optimization, never
        // authority for the retained byte bound if a file changes meanwhile.
        if bytes.len() <= remaining {
            remaining -= bytes.len();
            cache.insert(base, bytes);
        }
    }
    Ok(cache)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoders_start_in_runs_within_the_budget_and_a_large_one_runs_alone() {
        assert_eq!(admit_runs(&[], 10), Vec::<usize>::new());
        assert_eq!(admit_runs(&[3, 3, 3, 3], 10), vec![3, 1]);
        assert_eq!(admit_runs(&[3, 30, 3], 10), vec![1, 1, 1]);
        assert_eq!(admit_runs(&[10, 0, 1], 10), vec![2, 1]);
    }

    /// The charge covers what one encode really allocates: the output never
    /// grows past its reservation, and the index slots are counted at the
    /// map's power-of-two rounding.
    #[test]
    fn an_encoder_charge_covers_its_inputs_output_and_index() {
        let base = vec![7u8; 64 << 10];
        let target: Vec<u8> = (0u32..64 << 10)
            .map(|i| u8::try_from(i * 31 % 251).unwrap())
            .collect();
        let stream = delta::encode(&base, &target).unwrap();
        assert!(stream.len() <= delta::max_encoded_len(target.len()));
        let peak = encoder_peak(target.len() as u64, base.len() as u64);
        let blocks = (base.len() / 16) as u64;
        assert!(peak >= (target.len() + base.len() + stream.len()) as u64 + blocks * 17);
        assert!(peak < 6 * (64 << 10));
    }
}
