//! A pack of many minimal entries must stay inside the per-entry charge.
//!
//! A minimal blob entry takes a few bytes on the wire. Ten million of them
//! fit in a pack of about 150 MB, yet each one needs bookkeeping in memory.
//! `PackReader::read` charges `PACK_ENTRY_RESIDENT_COST` bytes per entry to
//! its budget. `PackReader::read_verified` charges `PACK_ENTRY_READ_COST`
//! per entry for the whole read, and `PACK_ENTRY_RESIDENT_COST` plus two
//! bytes per store path character once per window slot. These tests count
//! the real peak heap use of a read and check that the charge covers it.
//! zstd allocates its contexts through C `malloc`, which the counter does not
//! see: a constant per thread for the compressed commits, not per entry.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers
#![allow(unsafe_code)] // the counting allocator below wraps `System`

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use kit_core::layout::RepoLayout;
use kit_core::object::{Blob, Object};
use kit_core::object::{Commit, Identity};
use kit_core::pack::{
    PACK_ENTRY_READ_COST, PACK_ENTRY_RESIDENT_COST, PackSpool, STAGE_WINDOW_BYTES, VerifiedPack,
};
use kit_core::protocol::{PACK_BODY_LIMIT, PackKey};
use kit_core::{ObjectStore, PackReader, PackWriter, delta, hash::hash, pack_key, serialize};

/// Tracks live heap bytes and their peak.
struct CountingAlloc;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn grow(by: usize) {
    let live = LIVE.fetch_add(by, Ordering::Relaxed) + by;
    PEAK.fetch_max(live, Ordering::Relaxed);
}

// SAFETY: every method forwards to `System` with the unchanged layout and
// pointer, so `System`'s contract holds. The counters have no effect on the
// allocation itself.
unsafe impl GlobalAlloc for CountingAlloc {
    // SAFETY: the caller upholds the `GlobalAlloc::alloc` contract. The call
    // forwards the same layout to `System`.
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        grow(layout.size());
        // SAFETY: the caller upholds the `GlobalAlloc::alloc` contract for `layout`.
        unsafe { System.alloc(layout) }
    }

    // SAFETY: the caller passes a pointer and layout from a matching `alloc`.
    // The call forwards both to `System` unchanged.
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        // SAFETY: the caller passes a pointer and layout from a matching `alloc`.
        unsafe { System.dealloc(ptr, layout) }
    }

    // SAFETY: the caller passes a pointer and layout from a matching `alloc`.
    // The call forwards them with the new size to `System` unchanged.
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        grow(new_size);
        // SAFETY: the caller passes a pointer and layout from a matching `alloc`.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOC: CountingAlloc = CountingAlloc;

const ENTRIES: u32 = 30_000;
// The file reader has a separate per-entry charge and does not keep `stored`.
const FILE_ENTRIES: u32 = 1_025;

fn tiny_blob_pack(count: u32) -> Vec<u8> {
    let mut writer = PackWriter::new_raw_only();
    for i in 0..count {
        let bytes = serialize::serialize(&Object::Blob(Blob {
            data: i.to_le_bytes().to_vec(),
        }))
        .unwrap();
        writer.push_raw(hash(&bytes), &bytes).unwrap();
    }
    writer.finish().unwrap()
}

/// The tests share the counting allocator, so they run one at a time.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// A short fixed root for the store, so the staged paths stay short.
fn short_root() -> std::path::PathBuf {
    if cfg!(unix) {
        std::path::PathBuf::from("/tmp")
    } else {
        std::env::temp_dir()
    }
}

/// Reads a pack of `ENTRIES` tiny blobs into a store whose directory path is
/// `path_len` characters long, or as short as it gets when `path_len` is
/// zero, and checks the peak heap use per entry against the charge.
fn assert_inside_the_charge(path_len: usize) {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let pack = tiny_blob_pack(ENTRIES);
    let base = tempfile::Builder::new()
        .prefix("k")
        .tempdir_in(short_root())
        .unwrap();
    let mut dir = base.path().to_path_buf();
    if path_len > 0 {
        // One padding directory brings the store path to `path_len` characters.
        let pad = path_len.saturating_sub(dir.as_os_str().len() + 1);
        dir.push("p".repeat(pad));
        std::fs::create_dir_all(&dir).unwrap();
    }
    let store = ObjectStore::init(&RepoLayout::single(&dir)).unwrap();

    let baseline = LIVE.load(Ordering::Relaxed);
    PEAK.store(baseline, Ordering::Relaxed);
    let report = PackReader::read(&pack, &store).unwrap();
    let peak = PEAK.load(Ordering::Relaxed) - baseline;

    assert_eq!(report.stored.len(), ENTRIES as usize);
    let per_entry = peak / ENTRIES as usize;
    eprintln!(
        "measured {per_entry} bytes per entry under {} characters, charged {PACK_ENTRY_RESIDENT_COST}",
        dir.as_os_str().len()
    );
    assert!(
        per_entry <= PACK_ENTRY_RESIDENT_COST,
        "a read used {per_entry} bytes per entry, above the {PACK_ENTRY_RESIDENT_COST} charged"
    );
}

#[test]
fn many_tiny_entries_stay_inside_the_per_entry_charge() {
    assert_inside_the_charge(0);
}

#[test]
fn many_tiny_entries_with_a_long_store_path_stay_inside_the_per_entry_charge() {
    assert_inside_the_charge(100);
}

/// Entries a window of the file reader holds at most.
const STAGE_WINDOW: usize = 65_536;

/// The kinds of pack the file reader's charge is measured on.
#[derive(Clone, Copy, Debug)]
enum Shape {
    /// Distinct tiny blobs.
    Raw,
    /// Pairs of a tiny blob and a delta on it.
    DeltaOnInPackBase,
    /// Deltas, each on a distinct blob already in the store.
    DeltaOnStoreBase,
    /// Distinct commits, each a signed object the report lists.
    Commits,
}

fn tiny_blob(i: u32, extra: u8) -> Vec<u8> {
    let mut data = i.to_le_bytes().to_vec();
    data.extend_from_slice(&[extra; 12]);
    serialize::serialize(&Object::Blob(Blob { data })).unwrap()
}

fn tiny_commit(i: u32) -> Vec<u8> {
    serialize::serialize(&Object::Commit(Commit::new_unannotated(
        [0; 32],
        Vec::new(),
        Identity::ed25519([1; 32]),
        [1; 32],
        b"m".to_vec(),
        u64::from(i),
        [0; 64],
    )))
    .unwrap()
}

/// A pack of `entries` entries of `shape`, and the objects the store must hold
/// first. Returns the pack, the seed objects and the longest frame.
///
/// The objects repeat every `distinct` entries. With `distinct` a window's
/// worth of entries, the first window stores a window of new objects and
/// each later window finds its objects stored. The peak is the same as for
/// a pack of all distinct objects: the reader holds one window's state at a
/// time, and reserves all it keeps for every entry before the first window.
fn pack_of(shape: Shape, entries: u32, distinct: u32) -> (Vec<u8>, Vec<Vec<u8>>, usize) {
    let mut writer = PackWriter::new();
    let mut seed = Vec::new();
    let mut longest = 0usize;
    let mut note = |len: usize| longest = longest.max(len + 5);
    match shape {
        Shape::Raw => {
            for i in 0..entries {
                let bytes = tiny_blob(i % distinct, 0);
                note(bytes.len());
                writer.push_raw(hash(&bytes), &bytes).unwrap();
            }
        }
        Shape::DeltaOnInPackBase => {
            for i in 0..entries.div_ceil(2) {
                let pair = i % distinct.div_ceil(2);
                let base = tiny_blob(pair, 0);
                note(base.len());
                writer.push_raw(hash(&base), &base).unwrap();
                if 2 * i + 1 < entries {
                    let stream = delta::encode(&base, &tiny_blob(pair, 1)).unwrap();
                    note(32 + stream.len());
                    writer.push_delta(&hash(&base), &stream).unwrap();
                }
            }
        }
        Shape::DeltaOnStoreBase => {
            for i in 0..entries {
                let base = tiny_blob(i % distinct, 0);
                let stream = delta::encode(&base, &tiny_blob(i % distinct, 1)).unwrap();
                note(32 + stream.len());
                writer.push_delta(&hash(&base), &stream).unwrap();
                if i < distinct {
                    seed.push(base);
                }
            }
        }
        Shape::Commits => {
            for i in 0..entries {
                let bytes = tiny_commit(i % distinct);
                note(bytes.len());
                writer.push_raw(hash(&bytes), &bytes).unwrap();
            }
        }
    }
    (writer.finish().unwrap(), seed, longest)
}

fn verified(pack: &[u8], dir: &std::path::Path) -> VerifiedPack {
    let mut spool = PackSpool::create(dir, PACK_BODY_LIMIT).unwrap();
    spool.begin(Some(pack.len() as u64)).unwrap();
    for piece in pack.chunks(1 << 20) {
        spool.write(piece).unwrap();
    }
    spool.finish(&PackKey::new(pack_key(pack))).unwrap()
}

/// Reads a pack of `entries` entries of `shape` from a file into a store
/// whose directory path is `path_len` characters long (or as short as it
/// gets at zero), and checks the real peak heap use against the charge: the
/// bookkeeping the reader reserves, plus the one window of frames it holds,
/// which the reader bounds apart. The objects repeat every `distinct`
/// entries (see [`pack_of`]). Returns the peak.
fn assert_file_read_inside_the_charge(
    shape: Shape,
    entries: u32,
    path_len: usize,
    distinct: u32,
) -> usize {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (pack, seed, longest) = pack_of(shape, entries, distinct);
    let base = tempfile::Builder::new()
        .prefix("k")
        .tempdir_in(short_root())
        .unwrap();
    let mut dir = base.path().to_path_buf();
    if path_len > 0 {
        let pad = path_len.saturating_sub(dir.as_os_str().len() + 1);
        dir.push("p".repeat(pad));
        std::fs::create_dir_all(&dir).unwrap();
    }
    let store = ObjectStore::init(&RepoLayout::single(&dir)).unwrap();
    // Seed canonical loose objects without durable writes. This is fixture
    // setup, outside the measured read; the reader still stages and syncs
    // every distinct result through the real store, including its queue.
    let objects = RepoLayout::single(&dir).objects_dir();
    for bytes in &seed {
        let hex = kit_core::hash::to_hex(&hash(bytes));
        let shard = objects.join(&hex[..2]);
        std::fs::create_dir_all(&shard).unwrap();
        std::fs::write(shard.join(&hex[2..]), bytes).unwrap();
    }
    drop(seed);
    let file = verified(&pack, &dir.join("spool"));
    let pack_len = pack.len();
    drop(pack);

    let objects_path = dir.join(".kit").join("objects").as_os_str().len();
    let slot = PACK_ENTRY_RESIDENT_COST + 2 * objects_path;
    let n = entries as usize;
    let charge = PACK_ENTRY_READ_COST * n + slot * n.min(STAGE_WINDOW);
    let window = usize::try_from(STAGE_WINDOW_BYTES)
        .unwrap()
        .min(pack_len)
        .min(STAGE_WINDOW * longest);

    let baseline = LIVE.load(Ordering::Relaxed);
    PEAK.store(baseline, Ordering::Relaxed);
    let report = PackReader::read_verified(&file, &store).unwrap();
    let peak = PEAK.load(Ordering::Relaxed) - baseline;

    assert_eq!((report.raw_count + report.delta_count) as usize, n);
    let beyond_window = peak.saturating_sub(window);
    let per_slot_part = slot * n.min(STAGE_WINDOW);
    eprintln!(
        "{shape:?} x {n} under {} characters: peak {peak} B, window {window} B, \
         {} B per entry past the window and the charged slots, charged {charge} B",
        dir.as_os_str().len(),
        beyond_window.saturating_sub(per_slot_part) / n
    );
    assert!(
        beyond_window <= charge,
        "a file read of {n} {shape:?} entries used {beyond_window} bytes past its window, \
         above the {charge} charged"
    );
    peak
}

/// Objects repeat every window of entries, so a pack of millions of entries
/// writes one window of files (see [`pack_of`]).
const WINDOW_OF_OBJECTS: u32 = 65_536;

const SHAPES: [Shape; 4] = [
    Shape::Raw,
    Shape::DeltaOnInPackBase,
    Shape::DeltaOnStoreBase,
    Shape::Commits,
];

#[test]
fn a_file_read_of_tiny_raw_entries_stays_inside_the_charge() {
    assert_file_read_inside_the_charge(Shape::Raw, FILE_ENTRIES, 0, FILE_ENTRIES);
}

#[test]
fn a_file_read_of_tiny_raw_entries_under_a_260_character_path_stays_inside_the_charge() {
    assert_file_read_inside_the_charge(Shape::Raw, FILE_ENTRIES, 260, FILE_ENTRIES);
}

#[test]
fn a_file_read_of_in_pack_deltas_stays_inside_the_charge() {
    assert_file_read_inside_the_charge(Shape::DeltaOnInPackBase, FILE_ENTRIES, 0, FILE_ENTRIES);
}

#[test]
fn a_file_read_of_in_pack_deltas_under_a_260_character_path_stays_inside_the_charge() {
    assert_file_read_inside_the_charge(Shape::DeltaOnInPackBase, FILE_ENTRIES, 260, FILE_ENTRIES);
}

#[test]
fn a_file_read_of_store_deltas_stays_inside_the_charge() {
    assert_file_read_inside_the_charge(Shape::DeltaOnStoreBase, FILE_ENTRIES, 0, FILE_ENTRIES);
}

#[test]
fn a_file_read_of_store_deltas_under_a_260_character_path_stays_inside_the_charge() {
    assert_file_read_inside_the_charge(Shape::DeltaOnStoreBase, FILE_ENTRIES, 260, FILE_ENTRIES);
}

#[test]
fn a_file_read_of_commits_stays_inside_the_charge() {
    assert_file_read_inside_the_charge(Shape::Commits, FILE_ENTRIES, 0, FILE_ENTRIES);
}

#[test]
fn a_file_read_of_commits_under_a_260_character_path_stays_inside_the_charge() {
    assert_file_read_inside_the_charge(Shape::Commits, FILE_ENTRIES, 260, FILE_ENTRIES);
}

/// Past one window, the only memory that grows with the entry count is what
/// the reader reserves per entry before the first window: the report's
/// `signed` list of `(Hash, u32)`. A read of two windows of distinct objects
/// peaks at most that, plus 4 bytes per entry and 1 MiB of slack, above a
/// read of one, so no state of the whole read (a map of every entry, say)
/// can hide behind objects that repeat across windows.
fn assert_only_the_reservation_grows_past_a_window(shape: Shape) {
    let n = WINDOW_OF_OBJECTS;
    let one = assert_file_read_inside_the_charge(shape, n, 0, n);
    let two = assert_file_read_inside_the_charge(shape, 2 * n, 0, 2 * n);
    let growth = two.saturating_sub(one);
    let per_entry = std::mem::size_of::<(kit_core::hash::Hash, u32)>() + 4;
    let allowed = per_entry * n as usize + (1 << 20);
    eprintln!("{shape:?}: peak of one window {one} B, of two {two} B, growth {growth} B");
    assert!(
        growth <= allowed,
        "{shape:?} grew {growth} bytes, allowed {allowed}"
    );
}

#[test]
#[ignore = "writes 196,608 objects of each kind; run in the ignored lane"]
fn past_one_window_of_raw_entries_and_commits_only_the_reservation_grows() {
    assert_only_the_reservation_grows_past_a_window(Shape::Raw);
    assert_only_the_reservation_grows_past_a_window(Shape::Commits);
}

#[test]
#[ignore = "writes 196,608 objects and bases of each kind; run in the ignored lane"]
fn past_one_window_of_deltas_only_the_reservation_grows() {
    assert_only_the_reservation_grows_past_a_window(Shape::DeltaOnInPackBase);
    assert_only_the_reservation_grows_past_a_window(Shape::DeltaOnStoreBase);
}

/// Millions of entries, each kind of pack. They read millions of entries,
/// so they run in the ignored lane.
#[test]
#[ignore = "reads 1,048,576 entries of each kind; run in the ignored lane"]
fn a_file_read_of_a_million_entries_stays_inside_the_charge() {
    for shape in SHAPES {
        assert_file_read_inside_the_charge(shape, 1_048_576, 0, WINDOW_OF_OBJECTS);
    }
}

/// The count just past a hash map's resize, 7/8 × 2^21 + 1.
#[test]
#[ignore = "reads 1,835,009 entries of each kind; run in the ignored lane"]
fn a_file_read_just_past_a_map_resize_stays_inside_the_charge() {
    for shape in SHAPES {
        assert_file_read_inside_the_charge(shape, 1_835_009, 0, WINDOW_OF_OBJECTS);
    }
}

#[test]
#[ignore = "reads 2,500,000 entries of each kind; run in the ignored lane"]
fn a_file_read_of_two_and_a_half_million_entries_stays_inside_the_charge() {
    for shape in SHAPES {
        assert_file_read_inside_the_charge(shape, 2_500_000, 0, WINDOW_OF_OBJECTS);
    }
}
