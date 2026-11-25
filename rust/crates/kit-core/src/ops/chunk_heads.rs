//! Parallel chunk head reads for the push plan, the closure presence check
//! and the chunk check of `gc`.
//!
//! The first two walk a manifest's chunks and read the first bytes of each
//! chunk object, to learn that it is a blob and how long it is; `gc` reads
//! the type of each chunk it keeps. Each read is an
//! `open` and a short `read` on its own file, so a walk that reads one chunk
//! after another is bound by disk latency, not by CPU. This module reads the
//! heads of a window of chunks at once and then applies the results in manifest
//! order, so the outcome, including which error is reported, is the one of a
//! serial loop.
//!
//! Memory is bounded by the window: [`WINDOW`] chunks, whatever the size of
//! the manifest. The length cache the callers bring keeps its own bound, and
//! entries reach it in manifest order, as in a serial loop.
//!
//! Threads come from `std::thread::scope`: `kit-core` has no thread-pool
//! dependency and stays usable on wasm, where the heads are read one by one.

use std::collections::HashMap;

use super::graph::chunk_blob_len;
use crate::hash::Hash;
use crate::object::ChunkedBlob;
use crate::store::{ClosureSource, StoreError};

/// The bounds of a walk. The tests run it with small ones, so a manifest of a
/// few dozen chunks takes several rounds and reaches the parallel path.
#[derive(Clone, Copy)]
#[cfg_attr(target_arch = "wasm32", allow(dead_code))]
struct Tuning {
    /// Chunks of a manifest taken in one round. A round holds at most this
    /// many slots, reads and results, a few MiB, whatever the manifest's size.
    window: usize,
    /// Fewer reads than this in a round run on the calling thread: starting
    /// threads costs more than the reads save.
    min_parallel_reads: usize,
}

impl Tuning {
    const DEFAULT: Self = Self {
        window: 16 * 1024,
        min_parallel_reads: 64,
    };
}

/// Most heads in flight at once. A read waits on the disk and uses almost no
/// CPU, so the count is not sized by cores: the walk is faster the more reads
/// the device holds in flight, until its queue is full. 32 is the depth the
/// profile of a cold 16 GiB push used.
#[cfg(not(target_arch = "wasm32"))]
const HEAD_WORKERS: usize = 32;

/// What a walk remembers about the chunks it has measured.
pub(crate) trait LenCache {
    /// The remembered length of the blob `chunk`.
    fn len_of(&self, chunk: &Hash) -> Option<u64>;
    /// Remember the length of `chunk`, if there is room and it is not
    /// remembered. Must keep what an earlier call stored.
    fn remember(&mut self, chunk: Hash, len: u64);
}

/// What a round does for one chunk of its window.
#[derive(Clone, Copy)]
enum Slot {
    /// No head is wanted for this chunk.
    Unchecked,
    /// The length is in the cache.
    Known(u64),
    /// The length comes from read number `n` of the round.
    Read(usize),
}

/// Walk the chunks of `blob` in order. For each chunk that `wants_head` names,
/// take its length from `cache`, or read its head, and check it against the
/// chunk's span ([`ChunkedBlob::check_chunk_length`]). Then call `visit` with
/// the cache, the chunk's index and the chunk, for every chunk.
///
/// The result is that of this serial loop, in manifest order:
///
/// ```text
/// for (index, chunk) in chunks {
///     if wants_head(index, &chunk) {
///         let len = cache.len_of(&chunk) or chunk_blob_len(chunk)?;   // then cache.remember
///         blob.check_chunk_length(index, len)?;
///     }
///     visit(cache, index, chunk)?;
/// }
/// ```
///
/// `wants_head` and the cache lookups for a round are decided before any
/// `visit` of that round runs, so `visit` must not change what they answer for
/// a later chunk of the round. Both callers' `visit` only marks a chunk as
/// listed, which neither reads.
///
/// The reads of a round run in parallel. The error returned is the first one
/// in manifest order, whether it comes from a read, a length check or `visit`:
/// results are applied in order and the walk stops at the first failure. A
/// failed read also stops the rest of its round early. A chunk id that a round
/// lists twice is read once.
///
/// # Errors
///
/// A head read error, a length mismatch and `visit`'s own error.
pub(crate) fn for_each_checked_chunk<C: LenCache>(
    store: &(impl ClosureSource + ?Sized),
    blob: &ChunkedBlob,
    cache: &mut C,
    wants_head: impl Fn(u32, &Hash) -> bool,
    visit: impl FnMut(&mut C, u32, Hash) -> Result<(), StoreError>,
) -> Result<(), StoreError> {
    walk_chunks(store, blob, cache, wants_head, visit, Tuning::DEFAULT)
}

/// [`for_each_checked_chunk`] with the bounds of `tuning`.
fn walk_chunks<C: LenCache>(
    store: &(impl ClosureSource + ?Sized),
    blob: &ChunkedBlob,
    cache: &mut C,
    wants_head: impl Fn(u32, &Hash) -> bool,
    mut visit: impl FnMut(&mut C, u32, Hash) -> Result<(), StoreError>,
    tuning: Tuning,
) -> Result<(), StoreError> {
    let mut indexed = (0u32..).zip(blob.chunks().iter().copied());
    let mut window: Vec<(u32, Hash)> = Vec::new();
    let mut slots: Vec<Slot> = Vec::new();
    let mut reads: Vec<(u32, Hash)> = Vec::new();
    let mut read_of: HashMap<Hash, usize> = HashMap::new();
    loop {
        window.clear();
        window.extend(indexed.by_ref().take(tuning.window.max(1)));
        if window.is_empty() {
            return Ok(());
        }

        // Plan the round: what each chunk needs, and the reads to run.
        slots.clear();
        reads.clear();
        read_of.clear();
        for &(index, chunk) in &window {
            slots.push(if !wants_head(index, &chunk) {
                Slot::Unchecked
            } else if let Some(len) = cache.len_of(&chunk) {
                Slot::Known(len)
            } else {
                Slot::Read(*read_of.entry(chunk).or_insert_with(|| {
                    reads.push((index, chunk));
                    reads.len() - 1
                }))
            });
        }
        let mut results = read_heads(store, &reads, tuning);

        // Apply it in manifest order.
        for (&(index, chunk), &slot) in window.iter().zip(&slots) {
            match slot {
                Slot::Unchecked => {}
                Slot::Known(len) => blob.check_chunk_length(index, len)?,
                Slot::Read(n) => {
                    let len = match results[n].take() {
                        Some(Ok(len)) => {
                            // A chunk the round lists twice reads this slot twice.
                            results[n] = Some(Ok(len));
                            len
                        }
                        Some(Err(error)) => return Err(error),
                        // The round stopped before this read, so a read before
                        // it failed and the walk has returned already. Reading
                        // here keeps a release build right regardless.
                        None => {
                            debug_assert!(false, "a read the round skipped was reached");
                            chunk_blob_len(store, &chunk, index)?
                        }
                    };
                    cache.remember(chunk, len);
                    blob.check_chunk_length(index, len)?;
                }
            }
            visit(cache, index, chunk)?;
        }
    }
}

/// The result of one head read, or `None` when the round stopped before it.
type HeadResult = Option<Result<u64, StoreError>>;

/// Read the heads of `reads`, in parallel when there are enough. Slot `i`
/// holds the result for `reads[i]`. Every slot before the first failed read is
/// `Some(Ok(_))` and the first failed read is `Some(Err(_))`. Slots after it
/// may be `Some` or `None`.
#[cfg_attr(target_arch = "wasm32", allow(unused_variables))]
fn read_heads(
    store: &(impl ClosureSource + ?Sized),
    reads: &[(u32, Hash)],
    tuning: Tuning,
) -> Vec<HeadResult> {
    let mut out: Vec<HeadResult> = (0..reads.len()).map(|_| None).collect();
    #[cfg(not(target_arch = "wasm32"))]
    {
        let workers = HEAD_WORKERS.min(reads.len());
        if workers > 1 && reads.len() >= tuning.min_parallel_reads {
            let read = |&(index, chunk): &(u32, Hash)| chunk_blob_len(store, &chunk, index);
            run_parallel(reads, workers, &read, &mut out);
            count_reads(&out);
            return out;
        }
    }
    for (slot, &(index, chunk)) in out.iter_mut().zip(reads) {
        let result = chunk_blob_len(store, &chunk, index);
        let failed = result.is_err();
        *slot = Some(result);
        if failed {
            break;
        }
    }
    count_reads(&out);
    out
}

/// Up to `workers` threads claim items in order from a shared counter: the
/// calling thread and `workers - 1` scoped threads. A thread that cannot be
/// started is left out, so a limit on threads leaves fewer workers and never
/// a failure. Once `run` fails for an item, it starts for no item after it,
/// and it has started for every item before it already, so the lowest failed
/// item is always the one that is reported. Slot `i` of `out` takes the
/// result for `items[i]`.
#[cfg(not(target_arch = "wasm32"))]
fn run_parallel<R: Sync, T: Send, E: Send>(
    items: &[R],
    workers: usize,
    run: &(impl Fn(&R) -> Result<T, E> + Sync),
    out: &mut [Option<Result<T, E>>],
) {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let next = AtomicUsize::new(0);
    let first_failed = AtomicUsize::new(usize::MAX);
    let work = || {
        let mut done: Vec<(usize, Result<T, E>)> = Vec::new();
        loop {
            let i = next.fetch_add(1, Ordering::Relaxed);
            if i >= items.len() || i > first_failed.load(Ordering::Relaxed) {
                return done;
            }
            let result = run(&items[i]);
            if result.is_err() {
                first_failed.fetch_min(i, Ordering::Relaxed);
            }
            done.push((i, result));
        }
    };
    std::thread::scope(|scope| {
        let handles: Vec<_> = (1..workers)
            .filter_map(|_| std::thread::Builder::new().spawn_scoped(scope, work).ok())
            .collect();
        let mut finished = vec![work()];
        for handle in handles {
            finished.push(handle.join().expect("a parallel reader panicked"));
        }
        for (i, result) in finished.into_iter().flatten() {
            out[i] = Some(result);
        }
    });
}

/// Run `check` on every item of `items`, in order, and return the first
/// error, as a serial loop does. A window of items runs up to
/// `HEAD_WORKERS` checks at once, for a check that opens a file and reads a
/// few bytes, as a head read does; a window too small to gain from threads
/// runs on the calling thread. Memory is bounded by the window, whatever the
/// number of items.
///
/// # Errors
///
/// The first error of `check` in item order.
pub(crate) fn try_each_in_order<R: Sync, E: Send>(
    items: &[R],
    check: impl Fn(&R) -> Result<(), E> + Sync,
) -> Result<(), E> {
    let tuning = Tuning::DEFAULT;
    for window in items.chunks(tuning.window) {
        #[cfg(not(target_arch = "wasm32"))]
        {
            let workers = HEAD_WORKERS.min(window.len());
            if workers > 1 && window.len() >= tuning.min_parallel_reads {
                let mut out: Vec<Option<Result<(), E>>> = (0..window.len()).map(|_| None).collect();
                run_parallel(window, workers, &check, &mut out);
                // Every slot before the first failure is filled, so the
                // first error here is the first in item order.
                for result in out.into_iter().flatten() {
                    result?;
                }
                continue;
            }
        }
        window.iter().try_for_each(&check)?;
    }
    Ok(())
}

/// Count the reads a round ran, for the tests that pin how many there are.
/// The reads run on other threads, so the count is made here, on the thread
/// that owns the test's counter.
#[cfg(test)]
fn count_reads(out: &[HeadResult]) {
    let ran = out.iter().flatten().count();
    super::graph::CHUNK_TYPE_READS.with(|reads| reads.set(reads.get() + ran));
}

#[cfg(not(test))]
fn count_reads(_: &[HeadResult]) {}

#[cfg(test)]
mod tests;
