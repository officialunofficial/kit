//! Cumulative decode budgets of the pack readers on hostile packs.
//!
//! - The window reader refuses once the zstd claims it has yielded add up past
//!   its budget, though each entry fits.
//! - A fetch decodes at most its budget, however many packs it spreads that
//!   over.
#![allow(clippy::unwrap_used, clippy::cast_possible_truncation)]

use std::path::Path;

use kit_core::layout::RepoLayout;
use kit_core::object::{Blob, Object};
use kit_core::pack::{
    self, FetchDecodeBudget, MIN_TOTAL_DECODED, ObjectSpool, PackSpool, VerifiedPack, window,
};
use kit_core::protocol::{PACK_BODY_LIMIT, PackKey};
use kit_core::serialize;
use kit_core::{
    DecodeLimits, NoExternalBases, ObjectStore, PackEntry, PackError, PackReader,
    decode_entries_with, hash::hash,
};

const MIB: usize = 1 << 20;

fn build_pack(version: u32, frames: &[(u8, Vec<u8>)]) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(pack::MAGIC);
    p.extend_from_slice(&version.to_le_bytes());
    p.extend_from_slice(&(frames.len() as u32).to_le_bytes());
    for (kind, payload) in frames {
        p.push(*kind);
        p.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        p.extend_from_slice(payload);
    }
    let trailer = hash(&p);
    p.extend_from_slice(&trailer);
    p
}

fn blob(data: Vec<u8>) -> Vec<u8> {
    serialize::serialize(&Object::Blob(Blob { data })).unwrap()
}

/// `[u32 LE uncompressed_len][zstd frame]`, the 0x03 payload.
fn zstd_payload(bytes: &[u8]) -> Vec<u8> {
    let mut out = (bytes.len() as u32).to_le_bytes().to_vec();
    out.extend_from_slice(&zstd::bulk::compress(bytes, 19).unwrap());
    out
}

fn verified(bytes: &[u8], dir: &Path) -> VerifiedPack {
    let mut spool = PackSpool::create(dir, PACK_BODY_LIMIT).unwrap();
    spool.begin(Some(bytes.len() as u64)).unwrap();
    spool.write(bytes).unwrap();
    spool.finish(&PackKey::new(pack::pack_key(bytes))).unwrap()
}

/// 64 zstd entries, each claiming 16 MiB through RLE blocks, against a
/// `WindowReader` whose `max_decoded_bytes` is 32 MiB. Each entry fits the
/// budget alone; the sum of 1 GiB does not.
#[test]
fn window_reader_sums_decoded_bytes() {
    const ENTRIES: usize = 64;
    const CLAIM: usize = 16 * MIB;
    const BUDGET: u64 = 32 * MIB as u64;
    let object = blob(vec![0u8; CLAIM - serialize::BLOB_PROLOGUE_LEN]);
    assert_eq!(object.len(), CLAIM);
    let payload = zstd_payload(&object);
    drop(object);
    let frames: Vec<_> = (0..ENTRIES).map(|_| (0x03u8, payload.clone())).collect();
    let pack = build_pack(pack::VERSION_V2, &frames);
    let limits = DecodeLimits::default().with_max_decoded_bytes(BUDGET);

    // The buffered decoders charge the cumulative claim up front.
    let buffered = decode_entries_with(&pack, &mut NoExternalBases, limits, |_| Ok(()));
    assert!(matches!(buffered, Err(PackError::PackfileTooLarge)));

    let mut source = pack.as_slice();
    let mut delivered = 0u64;
    let result = window::read_all(
        &mut source,
        pack.len() as u64,
        64 << 10,
        limits,
        None,
        |entry| {
            if let PackEntry::Raw { bytes } = entry {
                delivered += bytes.len() as u64;
            }
            Ok(())
        },
    );
    assert!(
        matches!(result, Err(PackError::PackfileTooLarge)),
        "WindowReader delivered {delivered} bytes against a {BUDGET}-byte budget without refusing"
    );
    assert!(delivered <= BUDGET, "it stopped within the budget");

    // A budget that holds the sum reads the pack to the end.
    let limits = DecodeLimits::default().with_max_decoded_bytes((ENTRIES * CLAIM) as u64);
    let mut source = pack.as_slice();
    let mut entries = 0usize;
    window::read_all(
        &mut source,
        pack.len() as u64,
        64 << 10,
        limits,
        None,
        |_| {
            entries += 1;
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(entries, ENTRIES);
}

/// Bytes zstd cannot shrink, so an entry of them is as long on the wire as it
/// claims, and longer than a window.
fn incompressible(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x.to_le_bytes()[0]
        })
        .collect()
}

/// Four entries of 100 KiB each, longer than a 64 KiB window, so the reader
/// carries each across windows. Each is under the budget of 250 KiB, even
/// with its wire bytes beside it, and the sum is not. The plain reader and
/// one with an entry geometry, which restarts itself after each carried
/// entry, both keep the total across that.
#[test]
fn window_reader_sums_claims_of_entries_longer_than_a_window() {
    const CLAIM: usize = 100 << 10;
    let frames: Vec<_> = (0..4)
        .map(|n| (0x03u8, zstd_payload(&incompressible(CLAIM, n + 1))))
        .collect();
    let pack = build_pack(pack::VERSION_V2, &frames);
    assert!(frames[0].1.len() > 64 << 10, "an entry fills a window");
    let read = |limits: DecodeLimits| {
        let mut source = pack.as_slice();
        let mut entries = 0usize;
        let result = window::read_all(
            &mut source,
            pack.len() as u64,
            64 << 10,
            limits,
            None,
            |_| {
                entries += 1;
                Ok(())
            },
        );
        (result, entries)
    };
    let geometry = (CLAIM as u64 + (64 << 10), CLAIM as u64);
    for (name, limits) in [
        ("plain", DecodeLimits::default()),
        (
            "geometry",
            DecodeLimits::default().with_entry_geometry(geometry.0, geometry.1),
        ),
    ] {
        let (result, entries) = read(limits.with_max_decoded_bytes(250 << 10));
        assert!(
            matches!(result, Err(PackError::PackfileTooLarge)),
            "{name}: {result:?} after {entries} entries"
        );
        assert!(entries < 4, "{name}: stopped before the last entry");
        let (result, entries) = read(limits.with_max_decoded_bytes(4 * CLAIM as u64 + (200 << 10)));
        result.unwrap_or_else(|error| panic!("{name}: a budget for the sum reads it: {error:?}"));
        assert_eq!(entries, 4, "{name}");
    }
}

/// A pack of one zstd entry per claim, each claim passing the pack's own cap
/// and then failing on the bogus frame, so the test needs no object bigger
/// than the claim's few bytes.
fn claiming_pack(claims: &[u32]) -> Vec<u8> {
    let frames: Vec<_> = claims
        .iter()
        .map(|claim| {
            let mut payload = claim.to_le_bytes().to_vec();
            payload.extend_from_slice(&zstd::bulk::compress(b"tiny", 3).unwrap());
            (0x03u8, payload)
        })
        .collect();
    build_pack(pack::VERSION_V2, &frames)
}

/// A pack that stays under its own cap can still be one of a million. With a
/// budget of 2 GiB and a few tens of bytes of pack, the first pack takes the
/// 2 GiB and the next, which is small, may decode what its own length adds and
/// not its 1 GiB claim. Alone, the same pack passes.
#[test]
fn a_fetch_decodes_no_more_than_its_budget() {
    let gib = 1u32 << 30;
    assert_eq!(MIN_TOTAL_DECODED, 2 * u64::from(gib));
    let dir = tempfile::tempdir().unwrap();
    let store = ObjectStore::init(&RepoLayout::single(dir.path().join("repo"))).unwrap();
    let first = verified(&claiming_pack(&[gib, gib]), dir.path());
    let second = verified(&claiming_pack(&[gib]), dir.path());

    let stage = |pack: &VerifiedPack, fetch: &mut FetchDecodeBudget| {
        let staged = ObjectSpool::new(dir.path()).unwrap();
        PackReader::stage_verified(pack, &store, &[], &staged, fetch)
    };
    let mut fetch = FetchDecodeBudget::with_limit(MIN_TOTAL_DECODED);
    // The frames are bogus, so the pack fails after its claims were charged,
    // and a failed pack still spent them.
    let error = stage(&first, &mut fetch).unwrap_err();
    assert!(
        !matches!(error, PackError::PackfileTooLarge),
        "the first pack is within the budget: {error:?}"
    );
    let error = stage(&second, &mut fetch).unwrap_err();
    assert!(
        matches!(error, PackError::PackfileTooLarge),
        "the budget is spent: {error:?}"
    );

    let error = stage(
        &second,
        &mut FetchDecodeBudget::with_limit(MIN_TOTAL_DECODED),
    )
    .unwrap_err();
    assert!(
        !matches!(error, PackError::PackfileTooLarge),
        "alone it fits: {error:?}"
    );
}

/// The zstd entry that expands most, a 64 MiB blob of zeros, takes a few
/// kilobytes of pack. A fetch of it fits a budget that starts empty, since the
/// length of the pack adds more than it decodes.
#[test]
fn a_fetch_of_the_most_compressible_pack_needs_no_floor() {
    let dir = tempfile::tempdir().unwrap();
    let store = ObjectStore::init(&RepoLayout::single(dir.path().join("repo"))).unwrap();
    let object = blob(vec![0u8; 64 * MIB - serialize::BLOB_PROLOGUE_LEN]);
    let bytes = build_pack(pack::VERSION_V2, &[(0x03u8, zstd_payload(&object))]);
    drop(object);
    let pack = verified(&bytes, dir.path());
    let staged = ObjectSpool::new(dir.path()).unwrap();
    PackReader::stage_verified(
        &pack,
        &store,
        &[],
        &staged,
        &mut FetchDecodeBudget::with_limit(0),
    )
    .unwrap();
}

/// The pack that expands most per wire byte is a zstd delta entry whose stream
/// is 256 COPYs of one 64 KiB block, the shortest stream for its result: 16 MiB,
/// the most the planner deltas, from a base of the same size, the most it reads
/// from the store. The stream is regular, so zstd packs it into a few dozen
/// bytes. The decoded bytes it counts per wire byte stay at most half of what
/// each wire byte adds to a fetch, so a pack a kit writer makes never runs a
/// fetch out.
#[test]
fn a_pack_a_kit_writer_makes_fits_the_fetch_ratio() {
    const BLOCK: usize = 64 << 10;
    const COPY_LEN: usize = u16::MAX as usize;
    const COPIES: usize = 256;
    let block = incompressible(BLOCK, 7);
    let mut stream = vec![1u8];
    stream.extend_from_slice(&(BLOCK as u32).to_le_bytes());
    stream.extend_from_slice(&((COPIES * COPY_LEN) as u32).to_le_bytes());
    for _ in 0..COPIES {
        stream.push(0x80);
        stream.extend_from_slice(&0u32.to_le_bytes());
        stream.extend_from_slice(&u16::MAX.to_le_bytes());
    }
    let result = kit_core::delta::decode(&block, &stream).unwrap();
    assert_eq!(result.len(), COPIES * COPY_LEN);
    let mut payload = vec![0u8; 32];
    payload.extend_from_slice(&zstd_payload(&stream));
    let wire = (pack::ENTRY_FRAME_LEN + payload.len()) as u64;
    // The stream's claim, the result, and the 16 MiB base read from the store.
    let decoded = (stream.len() + result.len() + 16 * MIB) as u64;
    let ratio = decoded / wire;
    assert!(
        ratio * 2 <= FetchDecodeBudget::PER_WIRE_BYTE,
        "{decoded} decoded bytes from {wire} wire bytes is {ratio} times"
    );
}
