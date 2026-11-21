//! Copy-then-retire for local packs (SPEC-GC "Local pack maintenance").
//!
//! After the mark, gc classifies every published pair that the wholly dead
//! retirement leaves alone. An input is rewritten, merged, or retired as
//! covered. Its surviving entries go to new packs, then the old pair goes.
//!
//! One rule decides every entry of an input:
//! - an unreachable entry is dropped only when its own pack is past grace;
//! - a live entry is dropped only when a pair that stays holds a verified,
//!   durable copy of it;
//! - anything else is copied.
//!
//! So a copy never shortens an object's grace, and no run relies on a copy in
//! a pair it retires itself.

use std::cmp::Ordering;
use std::collections::{BTreeSet, HashMap};
use std::path::Path;
use std::sync::Arc;

use super::{Frame, Index, LocalPackWriter, Location, Pair, visit_pairs};
use crate::hash::Hash;
use crate::ops::gc::{GcReport, LiveSet};
use crate::pack::{ENTRY_FRAME_LEN, HEADER_LEN, TRAILER_LEN};
use crate::store::{ObjectStore, PruneGuard, StoreError, StoreResult};

use super::gc::Stamp;

/// A pack below both bounds is small. Policy, not format.
const SMALL_PAYLOAD: u64 = 16 << 20;
const SMALL_ENTRIES: usize = 16_384;
/// Small packs merge only when at least this many exist.
const SMALL_PAIRS: usize = 8;
/// A pack is rewritten when a quarter of its payload is reclaimable.
const RECLAIM_FRACTION: u64 = 4;
/// Output caps, the same as the fetch window seals.
pub(super) const OUTPUT_PAYLOAD: u64 = 64 << 20;
pub(super) const OUTPUT_ENTRIES: usize = 65_536;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Class {
    Covered,
    Mixed,
    Small,
}

/// The class a report counts: by what the run actually copies.
fn final_class(class: Class, copies: bool) -> Class {
    match (class, copies) {
        (_, false) => Class::Covered,
        (Class::Covered, true) => Class::Mixed,
        (class, true) => class,
    }
}

fn count(report: &mut GcReport, class: Class) {
    match class {
        Class::Covered => report.packs_retired_covered += 1,
        Class::Mixed => report.packs_rewritten += 1,
        Class::Small => report.packs_merged += 1,
    }
}

#[derive(Clone)]
struct Member {
    pair: Pair,
    pack: Stamp,
    locator: Stamp,
    index: Arc<Index>,
    live_bytes: u64,
    dead_bytes: u64,
    entries: usize,
    old: bool,
}

#[derive(Clone, Copy)]
struct Entry {
    id: Hash,
    frame: Frame,
}

#[derive(Clone, Copy)]
struct Dropped {
    entry: Entry,
    /// The member of the plan that holds the covering copy.
    by: usize,
}

struct Input {
    member: usize,
    class: Class,
    survivors: Vec<Entry>,
    /// Live entries covered by a pair that stays, pending verification.
    dropped: Vec<Dropped>,
    /// Payload bytes of unreachable entries dropped because the pack is
    /// past grace.
    dead_dropped: u64,
}

impl Input {
    fn dropped_bytes(&self) -> u64 {
        self.dropped
            .iter()
            .map(|dropped| u64::from(dropped.entry.frame.len))
            .sum::<u64>()
            + self.dead_dropped
    }
}

/// The inputs of one run, and the pairs that stay.
pub(super) struct CopyPlan {
    members: Vec<Member>,
    inputs: Vec<Input>,
}

/// A pair that an input relies on, with the stamps seen when it was chosen.
#[derive(Clone)]
struct Dep {
    pair: Pair,
    pack: Stamp,
    locator: Stamp,
}

impl Dep {
    fn of(pair: &Pair) -> StoreResult<Self> {
        let stamp = |path: &Path| {
            Stamp::read(path)
                .ok_or_else(|| pair.error("a published member is missing or not a regular file"))
        };
        Ok(Self {
            pair: pair.clone(),
            pack: stamp(&pair.pack)?,
            locator: stamp(&pair.index)?,
        })
    }

    fn of_member(member: &Member) -> Self {
        Self {
            pair: member.pair.clone(),
            pack: member.pack.clone(),
            locator: member.locator.clone(),
        }
    }

    /// Both members under their final names, unchanged since they were stamped.
    fn current(&self) -> bool {
        self.pack.unchanged(&self.pair.pack) && self.locator.unchanged(&self.pair.index)
    }
}

struct Relied {
    key: Hash,
    pack: Stamp,
    locator: Stamp,
    class: Class,
    duplicate_bytes: u64,
    covering: Vec<Dep>,
    outputs: Vec<Dep>,
}

/// What a run copied, and what each input that it did not keep relies on.
pub(super) struct Copied {
    outputs: Vec<Dep>,
    inputs: Vec<Relied>,
}

/// An input that is still safe to retire under the exclusive lock.
pub(super) struct Selected {
    at: usize,
    pub(super) pair: Pair,
}

struct Work {
    survivors: Vec<Entry>,
    dropped: Vec<Dropped>,
    kept: bool,
    /// Writer numbers of the outputs that hold this input's survivors.
    relies: BTreeSet<usize>,
}

impl CopyPlan {
    /// Plan the run. `retiring` names the pairs that the wholly dead
    /// retirement takes: they never count as staying, and they are not inputs.
    pub(super) fn plan(
        store: &ObjectStore,
        live: &LiveSet,
        now: u64,
        grace: u64,
        retiring: impl Fn(&Hash) -> bool,
    ) -> StoreResult<Option<Self>> {
        let mut members = Vec::new();
        visit_pairs(&store.pack_dir(), |pair| {
            if retiring(&pair.key) {
                return Ok(());
            }
            let (Some(pack), Some(locator)) = (Stamp::read(&pair.pack), Stamp::read(&pair.index))
            else {
                return Ok(());
            };
            let index = Index::open(&pair)?;
            let (mut live_bytes, mut dead_bytes, mut entries) = (0, 0, 0);
            for (id, frame) in index.entries() {
                entries += 1;
                if live.contains(&id) {
                    live_bytes += u64::from(frame.len);
                } else {
                    dead_bytes += u64::from(frame.len);
                }
            }
            let old = pack.old_enough(now, grace);
            // An aged pack with no live entry is the wholly dead retirement's.
            // If that retirement kept it because it is damaged, so does this.
            if live_bytes == 0 && old {
                return Ok(());
            }
            members.push(Member {
                pair,
                pack,
                locator,
                index: Arc::new(index),
                live_bytes,
                dead_bytes,
                entries,
                old,
            });
            Ok(())
        })?;

        let (holders, covered) = find_holders(&members, live);
        let classes = classify(&members, &covered);
        let staying: Vec<bool> = classes.iter().map(Option::is_none).collect();
        let mut inputs = Vec::new();
        for (at, class) in classes.iter().enumerate() {
            if let Some(class) = *class
                && let Some(input) = plan_input(&members, at, class, live, &holders, &staying)
            {
                inputs.push(input);
            }
        }
        if inputs.is_empty() {
            return Ok(None);
        }
        Ok(Some(Self { members, inputs }))
    }

    /// Dry run: report what a real run would do, assuming every covering copy
    /// verifies.
    pub(super) fn preview(&self, report: &mut GcReport) {
        let (mut freed, mut entries, mut payload) = (0, 0, 0);
        for input in &self.inputs {
            let member = &self.members[input.member];
            freed += member.pack.len + member.locator.len;
            count(
                report,
                final_class(input.class, !input.survivors.is_empty()),
            );
            report.duplicate_bytes_reclaimed += input.dropped_bytes();
            entries += input.survivors.len() as u64;
            payload += input
                .survivors
                .iter()
                .map(|entry| u64::from(entry.frame.len))
                .sum::<u64>();
        }
        report.survivor_bytes_copied += payload;
        report.bytes_reclaimed += freed.saturating_sub(file_bytes(entries, payload));
    }

    /// Verify coverage, copy the survivors and publish them. The shared
    /// `format` guard lives only inside this call.
    pub(super) fn execute(
        &self,
        store: &ObjectStore,
        report: &mut GcReport,
    ) -> StoreResult<Copied> {
        let mut work: Vec<Work> = self
            .inputs
            .iter()
            .map(|input| Work {
                survivors: input.survivors.clone(),
                dropped: Vec::with_capacity(input.dropped.len()),
                kept: false,
                relies: BTreeSet::new(),
            })
            .collect();
        self.verify_coverage(&mut work, report)?;
        let (outputs, copied) = self.copy(store, &mut work, report)?;
        report.survivor_bytes_copied += copied;

        let mut inputs = Vec::new();
        for (input, work) in self.inputs.iter().zip(&work) {
            if work.kept {
                continue;
            }
            let member = &self.members[input.member];
            let covering: BTreeSet<usize> = work.dropped.iter().map(|dropped| dropped.by).collect();
            inputs.push(Relied {
                key: member.pair.key,
                pack: member.pack.clone(),
                locator: member.locator.clone(),
                class: final_class(input.class, !work.survivors.is_empty()),
                duplicate_bytes: input.dead_dropped
                    + work
                        .dropped
                        .iter()
                        .map(|dropped| u64::from(dropped.entry.frame.len))
                        .sum::<u64>(),
                covering: covering
                    .into_iter()
                    .map(|by| Dep::of_member(&self.members[by]))
                    .collect(),
                outputs: work
                    .relies
                    .iter()
                    .filter_map(|&number| outputs[number].clone())
                    .collect(),
            });
        }
        Ok(Copied {
            outputs: outputs.into_iter().flatten().collect(),
            inputs,
        })
    }

    /// Read and hash the covering copy of every live entry that the run
    /// drops. A copy that fails verification counts as no copy.
    fn verify_coverage(&self, work: &mut [Work], report: &mut GcReport) -> StoreResult<()> {
        let mut verdicts: HashMap<Hash, bool> = HashMap::new();
        for (input, work) in self.inputs.iter().zip(work) {
            for dropped in &input.dropped {
                let id = dropped.entry.id;
                let ok = if let Some(ok) = verdicts.get(&id) {
                    *ok
                } else {
                    // The covering pair frames the id at its own offset.
                    let covering = &self.members[dropped.by];
                    let ok = match covering.index.find(&id) {
                        None => false,
                        Some(frame) => {
                            let location = Location::Packed(Arc::clone(&covering.index), frame);
                            match ObjectStore::raw_at(&location)
                                .and_then(|bytes| ObjectStore::verify_at(&location, &id, &bytes))
                            {
                                Ok(()) => true,
                                Err(error) if is_damage(&error) => {
                                    report.skipped_pack_errors.push(error.to_string());
                                    false
                                }
                                Err(error) => return Err(error),
                            }
                        }
                    };
                    verdicts.insert(id, ok);
                    ok
                };
                if ok {
                    work.dropped.push(*dropped);
                } else {
                    work.survivors.push(dropped.entry);
                }
            }
            work.survivors
                .sort_unstable_by_key(|entry| entry.frame.offset);
        }
        Ok(())
    }

    /// Write every survivor into rolling output packs, oldest input first.
    /// Returns the published outputs by writer number, and the payload bytes
    /// copied.
    fn copy(
        &self,
        store: &ObjectStore,
        work: &mut [Work],
        report: &mut GcReport,
    ) -> StoreResult<(Vec<Option<Dep>>, u64)> {
        if work.iter().all(|work| work.survivors.is_empty()) {
            return Ok((Vec::new(), 0));
        }
        let guard = store.prune_guard()?;
        let mut rolling = Rolling::new(store, &guard);
        let mut order: Vec<usize> = (0..self.inputs.len()).collect();
        order.sort_by_key(|&at| {
            let member = &self.members[self.inputs[at].member];
            (member.pack.modified, member.pair.key)
        });
        for at in order {
            let member = &self.members[self.inputs[at].member];
            for entry in &work[at].survivors {
                if let Some(output) = rolling.home(&entry.id) {
                    work[at].relies.insert(output);
                    continue;
                }
                let location = Location::Packed(Arc::clone(&member.index), entry.frame);
                let written = ObjectStore::raw_at(&location)
                    .and_then(|bytes| rolling.write(&entry.id, &bytes));
                match written {
                    Ok(Some(output)) => {
                        work[at].relies.insert(output);
                    }
                    Ok(None) => {
                        let error = member.pair.error("frame does not match its index id");
                        report.skipped_pack_errors.push(error.to_string());
                        work[at].kept = true;
                        break;
                    }
                    Err(error) if is_damage(&error) => {
                        report.skipped_pack_errors.push(error.to_string());
                        work[at].kept = true;
                        break;
                    }
                    Err(error) => return Err(error),
                }
            }
        }
        let (pairs, ids, copied) = rolling.finish()?;
        let mut outputs = Vec::new();
        for (pair, ids) in pairs.into_iter().zip(ids) {
            let Some(pair) = pair else {
                outputs.push(None);
                continue;
            };
            // The publication reopened the index. Check that it lists every
            // survivor assigned to this output.
            let index = Index::open(&pair)?;
            if ids.iter().any(|id| index.find(id).is_none()) {
                return Err(pair.index_error("output index does not list every survivor"));
            }
            outputs.push(Some(Dep::of(&pair)?));
        }
        drop(guard);
        Ok((outputs, copied))
    }
}

impl Copied {
    /// The inputs that are still safe to retire. Call under the exclusive
    /// lock, with `retiring` naming the pairs the wholly dead retirement takes.
    pub(super) fn select(&self, dir: &Path, retiring: &dyn Fn(&Hash) -> bool) -> Vec<Selected> {
        // An output with the key of an input is that input: it stays.
        let outputs: BTreeSet<Hash> = self.outputs.iter().map(|dep| dep.pair.key).collect();
        let candidates: BTreeSet<Hash> = self
            .inputs
            .iter()
            .map(|input| input.key)
            .filter(|key| !outputs.contains(key))
            .collect();
        let mut selected = Vec::new();
        for (at, input) in self.inputs.iter().enumerate() {
            if !candidates.contains(&input.key) {
                continue;
            }
            let pair = Pair::new(dir, input.key);
            if !input.pack.unchanged(&pair.pack) || !input.locator.unchanged(&pair.index) {
                continue;
            }
            // Never rely on a pair that this run retires, and rely only on
            // pairs whose both members still carry their stamps.
            let blocked = input.covering.iter().chain(&input.outputs).any(|dep| {
                retiring(&dep.pair.key) || candidates.contains(&dep.pair.key) || !dep.current()
            });
            if !blocked {
                selected.push(Selected { at, pair });
            }
        }
        selected
    }

    /// Every pair that a selected input relies on, once each.
    pub(super) fn deps(&self, selected: &[Selected]) -> Vec<&Pair> {
        let mut seen = BTreeSet::new();
        selected
            .iter()
            .flat_map(|selected| {
                let input = &self.inputs[selected.at];
                input.covering.iter().chain(&input.outputs)
            })
            .filter(|dep| seen.insert(dep.pair.key))
            .map(|dep| &dep.pair)
            .collect()
    }

    pub(super) fn report(&self, selected: &[Selected], report: &mut GcReport) {
        let mut freed = 0;
        for selected in selected {
            let input = &self.inputs[selected.at];
            freed += input.pack.len + input.locator.len;
            count(report, input.class);
            report.duplicate_bytes_reclaimed += input.duplicate_bytes;
        }
        let written: u64 = self
            .outputs
            .iter()
            .map(|dep| dep.pack.len + dep.locator.len)
            .sum();
        report.bytes_reclaimed += freed.saturating_sub(written);
    }
}

/// The ids of live entries that two or more pairs hold, with those pairs, and
/// for each pair the live bytes whose home is another pair. The home of an id
/// is its holder with the youngest pack, then the lowest key. Streams one
/// first-byte bucket at a time.
fn find_holders(members: &[Member], live: &LiveSet) -> (HashMap<Hash, Vec<usize>>, Vec<u64>) {
    let mut holders = HashMap::new();
    let mut covered = vec![0_u64; members.len()];
    let mut rows: Vec<(Hash, usize, u32)> = Vec::new();
    for shard in 0..=u8::MAX {
        rows.clear();
        for (at, member) in members.iter().enumerate() {
            if member.live_bytes != 0 {
                rows.extend(
                    member
                        .index
                        .bucket_entries(shard)
                        .filter(|(id, _)| live.contains(id))
                        .map(|(id, frame)| (id, at, frame.len)),
                );
            }
        }
        rows.sort_unstable_by_key(|row| (row.0, row.1));
        for run in rows.chunk_by(|a, b| a.0 == b.0) {
            if run.len() > 1 {
                let home = run
                    .iter()
                    .map(|row| row.1)
                    .max_by(|&a, &b| prefer(&members[a], &members[b]))
                    .expect("a run holds a row");
                for &(_, at, len) in run {
                    if at != home {
                        covered[at] += u64::from(len);
                    }
                }
                holders.insert(run[0].0, run.iter().map(|row| row.1).collect());
            }
        }
    }
    (holders, covered)
}

/// `Greater` for the pair that is the better home: younger, then lower key.
fn prefer(a: &Member, b: &Member) -> Ordering {
    a.pack
        .modified
        .cmp(&b.pack.modified)
        .then_with(|| b.pair.key.cmp(&a.pair.key))
}

/// The class of each member that becomes an input. A member that stays has
/// none.
fn classify(members: &[Member], covered: &[u64]) -> Vec<Option<Class>> {
    let mut classes = vec![None; members.len()];
    let mut small = Vec::new();
    for (at, member) in members.iter().enumerate() {
        let payload = member.live_bytes + member.dead_bytes;
        let dead_is_gone = member.dead_bytes == 0 || member.old;
        if covered[at] == member.live_bytes && dead_is_gone {
            classes[at] = Some(Class::Covered);
            continue;
        }
        let reclaimable = covered[at] + if member.old { member.dead_bytes } else { 0 };
        if member.old && reclaimable * RECLAIM_FRACTION >= payload {
            classes[at] = Some(Class::Mixed);
        } else if payload < SMALL_PAYLOAD && member.entries < SMALL_ENTRIES {
            small.push(at);
        }
    }
    if small.len() >= SMALL_PAIRS {
        for at in small {
            classes[at] = Some(Class::Small);
        }
    }
    classes
}

/// Decide each entry of one input against the pairs that stay.
fn plan_input(
    members: &[Member],
    at: usize,
    class: Class,
    live: &LiveSet,
    holders: &HashMap<Hash, Vec<usize>>,
    staying: &[bool],
) -> Option<Input> {
    let member = &members[at];
    let (mut survivors, mut dropped, mut dead_dropped) = (Vec::new(), Vec::new(), 0);
    for (id, frame) in member.index.entries() {
        let entry = Entry { id, frame };
        if !live.contains(&id) {
            // Only the pack's own age lets an unreachable entry go.
            if member.old {
                dead_dropped += u64::from(frame.len);
            } else {
                survivors.push(entry);
            }
            continue;
        }
        let by = holders.get(&id).and_then(|held| {
            held.iter()
                .copied()
                .filter(|&other| staying[other])
                .max_by(|&a, &b| prefer(&members[a], &members[b]))
        });
        match by {
            Some(by) => dropped.push(Dropped { entry, by }),
            None => survivors.push(entry),
        }
    }
    // Copying a pack whole and retiring the original gains nothing.
    if class != Class::Small && dropped.is_empty() && dead_dropped == 0 {
        return None;
    }
    survivors.sort_unstable_by_key(|entry| entry.frame.offset);
    Some(Input {
        member: at,
        class,
        survivors,
        dropped,
        dead_dropped,
    })
}

/// File bytes of a pair holding `entries` entries and `payload` bytes.
fn file_bytes(entries: u64, payload: u64) -> u64 {
    use super::index::{INDEX_BASE_LEN, INDEX_ROW_LEN};
    if entries == 0 {
        return 0;
    }
    (HEADER_LEN + TRAILER_LEN + INDEX_BASE_LEN) as u64
        + payload
        + entries * (ENTRY_FRAME_LEN + INDEX_ROW_LEN) as u64
}

/// An entry that cannot be read or verified is damage in its pack. Anything
/// else, such as a failed disk read, stops the run.
fn is_damage(error: &StoreError) -> bool {
    use std::io::ErrorKind;
    match error {
        StoreError::LocalPackDamaged { .. }
        | StoreError::HashMismatch { .. }
        | StoreError::Decode(_) => true,
        StoreError::Io(error) => {
            matches!(
                error.kind(),
                ErrorKind::UnexpectedEof | ErrorKind::InvalidData
            )
        }
        _ => false,
    }
}

/// The pairs published by writer number, the ids assigned to each, and the
/// payload bytes copied.
pub(super) type Finished = (Vec<Option<Pair>>, Vec<Vec<Hash>>, u64);

/// Output packs that roll over at the caps.
pub(super) struct Rolling<'a> {
    store: &'a ObjectStore,
    guard: &'a PruneGuard,
    writer: Option<LocalPackWriter<'a>>,
    max_entries: usize,
    max_payload: u64,
    entries: usize,
    payload: u64,
    /// By writer number: the published pair, none for an empty writer.
    pairs: Vec<Option<Pair>>,
    /// By writer number: the ids assigned to it.
    ids: Vec<Vec<Hash>>,
    homes: HashMap<Hash, usize>,
    copied: u64,
}

impl<'a> Rolling<'a> {
    fn new(store: &'a ObjectStore, guard: &'a PruneGuard) -> Self {
        Self::capped(store, guard, OUTPUT_ENTRIES, OUTPUT_PAYLOAD)
    }

    pub(super) fn capped(
        store: &'a ObjectStore,
        guard: &'a PruneGuard,
        max_entries: usize,
        max_payload: u64,
    ) -> Self {
        Self {
            store,
            guard,
            writer: None,
            max_entries,
            max_payload,
            entries: 0,
            payload: 0,
            pairs: Vec::new(),
            ids: Vec::new(),
            homes: HashMap::new(),
            copied: 0,
        }
    }

    /// The writer that already holds `id` in this run.
    fn home(&self, id: &Hash) -> Option<usize> {
        self.homes.get(id).copied()
    }

    /// Write one object. `None` if the writer derives another id than the
    /// index gave. An id counts once per run.
    pub(super) fn write(&mut self, id: &Hash, bytes: &[u8]) -> StoreResult<Option<usize>> {
        let len = bytes.len() as u64;
        if self.writer.is_some()
            && (self.entries == self.max_entries || self.payload + len > self.max_payload)
        {
            self.seal()?;
        }
        if self.writer.is_none() {
            self.writer = Some(LocalPackWriter::new(self.store, self.guard)?);
            self.ids.push(Vec::new());
            self.entries = 0;
            self.payload = 0;
        }
        let writer = self.writer.as_mut().expect("an open writer");
        if &writer.write(bytes)? != id {
            return Ok(None);
        }
        let number = self.ids.len() - 1;
        self.entries += 1;
        self.payload += len;
        self.copied += len;
        self.ids[number].push(*id);
        self.homes.insert(*id, number);
        Ok(Some(number))
    }

    fn seal(&mut self) -> StoreResult<()> {
        if let Some(writer) = self.writer.take() {
            self.pairs.push(writer.publish_pair()?);
        }
        Ok(())
    }

    pub(super) fn finish(mut self) -> StoreResult<Finished> {
        self.seal()?;
        Ok((self.pairs, self.ids, self.copied))
    }
}

#[cfg(test)]
mod select_tests {
    use super::*;
    use crate::store::local_pack::tests::{blob, fresh, publish_objects};

    fn pair(store: &crate::store::ObjectStore, label: &str) -> Pair {
        publish_objects(store, &[blob(label.as_bytes()).as_slice()]).0
    }

    fn relied(pair: &Pair, covering: &[&Pair], outputs: &[&Pair]) -> Relied {
        let dep = Dep::of(pair).unwrap();
        Relied {
            key: pair.key,
            pack: dep.pack,
            locator: dep.locator,
            class: Class::Mixed,
            duplicate_bytes: 0,
            covering: covering.iter().map(|p| Dep::of(p).unwrap()).collect(),
            outputs: outputs.iter().map(|p| Dep::of(p).unwrap()).collect(),
        }
    }

    #[test]
    fn an_input_that_relies_on_a_pair_the_run_retires_or_also_copies_stays() {
        let (_dir, _layout, store) = fresh();
        let (input, covering, other, output, spare) = (
            pair(&store, "input"),
            pair(&store, "covering"),
            pair(&store, "other"),
            pair(&store, "output"),
            pair(&store, "spare"),
        );
        let dir = store.pack_dir();
        let output_dep = || vec![Dep::of(&output).unwrap()];

        // Control: nothing blocks it.
        let copied = Copied {
            outputs: output_dep(),
            inputs: vec![relied(&input, &[&covering], &[&output])],
        };
        assert_eq!(copied.select(&dir, &|_| false).len(), 1);

        // The covering pair is a wholly dead retirement of this run.
        let retiring = covering.key;
        assert!(copied.select(&dir, &|key| *key == retiring).is_empty());

        // The covering pair is itself an input of this run. Only that input,
        // which relies on a pair that stays, may go.
        let copied = Copied {
            outputs: output_dep(),
            inputs: vec![
                relied(&input, &[&covering], &[&output]),
                relied(&covering, &[&other], &[&output]),
            ],
        };
        let selected = copied.select(&dir, &|_| false);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].pair.key, covering.key);

        // An output that carries an input's key leaves that input in place.
        let copied = Copied {
            outputs: vec![Dep::of(&spare).unwrap()],
            inputs: vec![relied(&spare, &[&covering], &[&spare])],
        };
        assert!(copied.select(&dir, &|_| false).is_empty());
    }

    #[test]
    fn only_an_early_end_or_invalid_data_in_a_read_is_damage() {
        use std::io::{Error, ErrorKind};

        for kind in [ErrorKind::UnexpectedEof, ErrorKind::InvalidData] {
            assert!(is_damage(&StoreError::Io(Error::from(kind))), "{kind:?}");
        }
        for kind in [
            ErrorKind::PermissionDenied,
            ErrorKind::NotFound,
            ErrorKind::TimedOut,
            ErrorKind::Other,
        ] {
            assert!(!is_damage(&StoreError::Io(Error::from(kind))), "{kind:?}");
        }
    }

    #[test]
    fn a_pack_is_small_below_sixteen_mib_and_below_sixteen_thousand_entries() {
        let (_dir, _layout, store) = fresh();
        let pair = pair(&store, "member");
        let index = Arc::new(Index::open(&pair).unwrap());
        let member = |payload: u64, entries: usize| Member {
            pair: pair.clone(),
            pack: Stamp::read(&pair.pack).unwrap(),
            locator: Stamp::read(&pair.index).unwrap(),
            index: Arc::clone(&index),
            live_bytes: 0,
            dead_bytes: payload,
            entries,
            old: false,
        };
        let cases = [
            ("payload - 1", SMALL_PAYLOAD - 1, 10, true),
            ("payload", SMALL_PAYLOAD, 10, false),
            ("entries - 1", 100, SMALL_ENTRIES - 1, true),
            ("entries", 100, SMALL_ENTRIES, false),
        ];
        for (label, payload, entries, small) in cases {
            // Seven small packs make eight only when the edge pack counts.
            let mut members = vec![member(500, 1); 7];
            members.push(member(payload, entries));
            let classes = classify(&members, &[0; 8]);
            assert_eq!(
                classes.iter().flatten().count(),
                if small { 8 } else { 0 },
                "{label}"
            );
        }
    }
}
