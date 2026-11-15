//! Peak heap of packs on disk: sealing a spooled pack and reading a verified
//! one do not grow with the pack's length.
//!
//! A counting allocator records the live heap and its peak. Each test writes
//! or reads about 1 GiB, or millions of entries, so they run in the ignored
//! lane, one at a time. zstd allocates its contexts through C `malloc`, which
//! the counter does not see; these packs hold no compressed entries.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers
#![allow(unsafe_code)] // the counting allocator below wraps `System`

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use kit_core::layout::RepoLayout;
use kit_core::object::{Blob, Object};
use kit_core::pack::{
    PACK_ENTRY_READ_COST, PACK_ENTRY_RESIDENT_COST, PackSpool, SpooledPack, VerifiedPack,
};
use kit_core::protocol::{PACK_BODY_LIMIT, PackKey};
use kit_core::{ObjectStore, PackReader, PackWriter, hash::hash, serialize};

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

const MIB: usize = 1 << 20;

/// The tests share the counting allocator, so they run one at a time.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Peak heap above the live heap at the start, while `f` runs.
fn peak_of<T>(f: impl FnOnce() -> T) -> (T, usize) {
    let baseline = LIVE.load(Ordering::Relaxed);
    PEAK.store(baseline, Ordering::Relaxed);
    let out = f();
    (out, PEAK.load(Ordering::Relaxed) - baseline)
}

/// Fill `out` with incompressible bytes from `seed`.
fn noise(seed: u64, out: &mut [u8]) {
    let mut state = seed | 1;
    for chunk in out.chunks_mut(8) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        chunk.copy_from_slice(&state.to_le_bytes()[..chunk.len()]);
    }
}

/// 1 GiB of distinct, incompressible 64 KiB blobs.
const BIG_ENTRIES: u32 = 16_384;
const BIG_ENTRY: usize = 64 << 10;

/// Spool a pack of [`BIG_ENTRIES`] blobs of [`BIG_ENTRY`] bytes into `dir`.
/// Each object is serialized from one reused data buffer.
fn spool_big_pack(dir: &std::path::Path) -> SpooledPack {
    let mut data = vec![0u8; BIG_ENTRY];
    let mut w = PackWriter::spool(dir).unwrap();
    for i in 0..BIG_ENTRIES {
        noise(u64::from(i) + 1, &mut data);
        let bytes = serialize::serialize(&Object::Blob(Blob { data })).unwrap();
        w.push_raw(hash(&bytes), &bytes).unwrap();
        let Object::Blob(Blob { data: back }) = serialize::deserialize(&bytes).unwrap() else {
            unreachable!()
        };
        data = back;
    }
    w.finish_spool().unwrap()
}

fn verified_spooled(pack: &SpooledPack, dir: &std::path::Path) -> VerifiedPack {
    let mut spool = PackSpool::create(dir, PACK_BODY_LIMIT).unwrap();
    spool.begin(Some(pack.len())).unwrap();
    let mut buf = vec![0u8; MIB];
    let mut at = 0u64;
    while at < pack.len() {
        let n = buf.len().min(usize::try_from(pack.len() - at).unwrap());
        pack.read_at(at, &mut buf[..n]).unwrap();
        spool.write(&buf[..n]).unwrap();
        at += n as u64;
    }
    spool.finish(&PackKey::new(pack.key())).unwrap()
}

/// Building and sealing a 1 GiB pack in a spool holds a few MiB: the spool's
/// buffer, the read buffer of the hash pass, and one object at a time. The
/// pack is raw entries; a writer also keeps a few dozen bytes per distinct
/// delta base, which this does not measure.
#[test]
#[ignore = "writes a 1 GiB pack; run in the ignored lane"]
fn sealing_a_1_gib_spooled_pack_holds_under_8_mib() {
    let _serial = serial();
    let dir = tempfile::tempdir().unwrap();
    let (pack, peak) = peak_of(|| spool_big_pack(dir.path()));
    eprintln!(
        "spool and seal a {}-byte pack: peak heap {peak} bytes",
        pack.len()
    );
    assert!(pack.len() > 1 << 30);
    assert!(peak < 8 * MIB, "peak heap {peak} bytes");
}

/// Reading a verified 1 GiB pack of 64 KiB entries holds one 64 MiB window of
/// frames and the per-entry charge, where the slice reader holds the whole
/// pack.
#[test]
#[ignore = "reads a 1 GiB pack; run in the ignored lane"]
fn reading_a_verified_1_gib_pack_holds_under_96_mib_and_the_entry_charge() {
    let _serial = serial();
    let dir = tempfile::tempdir().unwrap();
    let spooled = spool_big_pack(&dir.path().join("w"));
    let file = verified_spooled(&spooled, &dir.path().join("r"));
    drop(spooled);
    let store = ObjectStore::init(&RepoLayout::single(dir.path().join("repo"))).unwrap();
    let (report, peak) = peak_of(|| PackReader::read_verified(&file, &store).unwrap());
    assert_eq!(report.raw_count, BIG_ENTRIES);
    let bound = 96 * MIB + PACK_ENTRY_READ_COST * BIG_ENTRIES as usize;
    eprintln!(
        "read_verified of a {}-byte pack of {BIG_ENTRIES} entries: peak heap {peak} bytes, bound {bound}",
        file.len()
    );
    assert!(peak < bound, "peak heap {peak} bytes");
}

/// Reading a verified pack of 2.5 million tiny entries holds at most a
/// window, the window slots' charge and the per-entry charge.
///
/// The blobs repeat every window of 65,536 entries: the first window stores
/// a window of new objects, and later ones find theirs stored. The reader
/// holds one window's state at a time and reserves what it keeps per entry
/// before the first window, so the peak is that of distinct objects.
#[test]
#[ignore = "reads 2.5 million entries; run in the ignored lane"]
fn reading_a_verified_pack_of_two_and_a_half_million_entries_stays_inside_its_charge() {
    const N: u32 = 2_500_000;
    let _serial = serial();
    let dir = tempfile::Builder::new()
        .prefix("k")
        .tempdir_in(if cfg!(unix) {
            std::path::PathBuf::from("/tmp")
        } else {
            std::env::temp_dir()
        })
        .unwrap();
    let mut w = PackWriter::spool(&dir.path().join("w")).unwrap();
    for i in 0..N {
        let bytes = serialize::serialize(&Object::Blob(Blob {
            data: (i % 65_536).to_le_bytes().to_vec(),
        }))
        .unwrap();
        w.push_raw(hash(&bytes), &bytes).unwrap();
    }
    let spooled = w.finish_spool().unwrap();
    let file = verified_spooled(&spooled, &dir.path().join("r"));
    drop(spooled);
    let store = ObjectStore::init(&RepoLayout::single(dir.path())).unwrap();
    let objects_path = dir.path().join(".kit").join("objects").as_os_str().len();
    let (report, peak) = peak_of(|| PackReader::read_verified(&file, &store).unwrap());
    assert_eq!(report.raw_count, N);
    let slots = (PACK_ENTRY_RESIDENT_COST + 2 * objects_path) * 65_536;
    let bound = 64 * MIB + slots + PACK_ENTRY_READ_COST * N as usize;
    eprintln!(
        "read_verified of a {}-byte pack of {N} entries: peak heap {peak} bytes, bound {bound}",
        file.len()
    );
    assert!(peak <= bound, "peak heap {peak} bytes");
}
