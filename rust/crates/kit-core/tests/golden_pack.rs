//! Chunker / delta / packfile goldens.
//!
//! These tests assert that:
//!
//! 1. [`kit_core::chunker`] produces the pinned chunk boundaries for
//!    the splitmix64-derived inputs stored at
//!    `rust/tests/golden/fastcdc/fastcdc_boundaries_*.bin`.
//! 2. [`kit_core::delta`] encodes a SPEC-DELTA stream that round-trips
//!    through [`kit_core::delta::decode`] and pins to a fixed byte
//!    prefix for a deterministic input.
//! 3. [`kit_core::pack`] writes a SPEC-PACKFILE v1 pack that the
//!    reader resolves end-to-end and that pins to a fixed byte prefix
//!    for a deterministic input.
//!
//! Goldens for do NOT live on disk — they're inline byte
//! arrays so the spec change → test failure feedback is immediate.
//! The exception is the C-encoded v2 fixtures under
//! `rust/tests/golden/pack-v2/` (see [`pack_v2_fixtures`]), which exist
//! so decode-only builds have real compressed bytes to read.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::fs;
use std::path::PathBuf;

use kit_core::chunker::{ChunkIterator, FastCdc, chunk_boundaries};
use kit_core::delta;
use kit_core::hash;
use kit_core::layout::RepoLayout;
use kit_core::pack::{PackReader, PackWriter, pack_key};
use kit_core::store::ObjectStore;

fn fastcdc_dir() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop(); // crates/
    d.pop(); // rust/
    d.push("tests");
    d.push("golden");
    d.push("fastcdc");
    d
}

/// Splitmix64 byte stream. Pinned — changing this invalidates the
/// checked-in boundary goldens.
fn splitmix_bytes(seed: u64, total: usize) -> Vec<u8> {
    let mut buf = vec![0u8; total];
    let mut state: u64 = seed;
    let mut i = 0usize;
    while i < total {
        state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^= z >> 31;
        let bytes = z.to_le_bytes();
        let end = (i + 8).min(total);
        buf[i..end].copy_from_slice(&bytes[..end - i]);
        i = end;
    }
    buf
}

fn parse_boundaries_json(s: &str) -> Vec<usize> {
    // Minimal one-line parser: trim brackets/whitespace, split on `,`.
    let trimmed = s.trim();
    let inner = trimmed
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(trimmed);
    inner
        .split(',')
        .map(|t| {
            t.trim()
                .parse::<usize>()
                .unwrap_or_else(|_| panic!("bad boundary token: {t:?}"))
        })
        .collect()
}

#[test]
fn fastcdc_boundaries_1mib_match_golden() {
    let raw = fs::read_to_string(fastcdc_dir().join("fastcdc_boundaries_1mib.bin"))
        .expect("missing fastcdc_boundaries_1mib.bin");
    let expected = parse_boundaries_json(&raw);
    let data = splitmix_bytes(0xA5A5_F00D_DEAD_BEEF, 1024 * 1024);
    let actual = chunk_boundaries(&data);
    assert_eq!(
        actual, expected,
        "1 MiB FastCDC boundaries diverged from pinned golden"
    );
}

#[test]
fn fastcdc_boundaries_256k_match_golden() {
    let raw = fs::read_to_string(fastcdc_dir().join("fastcdc_boundaries_256k.bin"))
        .expect("missing fastcdc_boundaries_256k.bin");
    let expected = parse_boundaries_json(&raw);
    let data = splitmix_bytes(0xCAFE_BABE_1234_5678, 256 * 1024);
    let actual = chunk_boundaries(&data);
    assert_eq!(
        actual, expected,
        "256 KiB FastCDC boundaries diverged from pinned golden"
    );
}

#[test]
fn fastcdc_iterator_total_equals_input_length() {
    // Sanity, plus exercises the Iterator API in tests/.
    let data = splitmix_bytes(0xDEAD_BEEF, 200 * 1024);
    let total: usize = ChunkIterator::new(FastCdc::v1(), &data)
        .map(|b| b.length)
        .sum();
    assert_eq!(total, data.len());
}

#[test]
fn delta_basic_pin_bytes_and_roundtrip() {
    // SPEC-DELTA pure-INSERT pin: base="aaa", target="zzz".
    // Stream MUST be: [0x01][3,0,0,0][3,0,0,0][3]['z','z','z'] = 13 bytes.
    let stream = delta::encode(b"aaa", b"zzz").unwrap();
    let expected: [u8; 13] = [
        0x01, // version
        0x03, 0x00, 0x00, 0x00, // base_len = 3
        0x03, 0x00, 0x00, 0x00, // result_len = 3
        0x03, // INSERT length 3
        b'z', b'z', b'z',
    ];
    assert_eq!(
        stream,
        expected.to_vec(),
        "delta basic INSERT bytes drifted"
    );
    let restored = delta::decode(b"aaa", &stream).unwrap();
    assert_eq!(restored, b"zzz");
}

#[test]
fn delta_pure_copy_pin_bytes() {
    // Hand-build a one-COPY stream: base = 16 bytes; result = base[..16].
    // Expected pin = [ver=1][base_len=16 LE][result_len=16 LE][0x80][0,0,0,0][16,0]
    let base: Vec<u8> = (0..16u8).collect();
    let expected: [u8; 16] = [
        0x01, // version
        0x10, 0x00, 0x00, 0x00, // base_len = 16
        0x10, 0x00, 0x00, 0x00, // result_len = 16
        0x80, // COPY opcode
        0x00, 0x00, 0x00, 0x00, // offset = 0
        0x10, 0x00, // length = 16
    ];
    // The encoder must actually emit this pinned COPY-only stream for a
    // pure-copy edit (base == result) — an INSERT-only encoder would
    // still round-trip via `decode` but would never produce this byte
    // shape, so pin `encode`'s output directly instead of only
    // exercising `decode` on a hand-built stream.
    let encoded = delta::encode(&base, &base).unwrap();
    assert_eq!(
        encoded, expected,
        "encode must emit the pinned COPY opcode stream"
    );

    let restored = delta::decode(&base, &expected).unwrap();
    assert_eq!(restored, base);
}

#[test]
fn pack_basic_pin_bytes_roundtrip() {
    // A minimal one-raw-entry pack of an empty kit blob.
    let blob = kit_core::object::Object::Blob(kit_core::object::Blob {
        data: b"hi".to_vec(),
    });
    let blob_bytes = kit_core::serialize::serialize(&blob).unwrap();
    let blob_hash = hash::hash(&blob_bytes);

    let mut w = PackWriter::new();
    w.push_raw(blob_hash, &blob_bytes).unwrap();
    let pack = w.finish().unwrap();

    // Pin the framing: header (12 bytes) + entry frame (5 bytes) +
    // blob payload + 32-byte trailer.
    let entry_payload_len = blob_bytes.len();
    let expected_pack_len = 12 + 5 + entry_payload_len + 32;
    assert_eq!(pack.len(), expected_pack_len);

    // Header.
    assert_eq!(&pack[0..4], b"KIT\0");
    assert_eq!(u32::from_le_bytes(pack[4..8].try_into().unwrap()), 1);
    assert_eq!(u32::from_le_bytes(pack[8..12].try_into().unwrap()), 1);

    // First entry frame.
    assert_eq!(pack[12], 0x00);
    assert_eq!(
        u32::from_le_bytes(pack[13..17].try_into().unwrap()) as usize,
        entry_payload_len
    );
    assert_eq!(&pack[17..17 + entry_payload_len], blob_bytes.as_slice());

    // Trailer = BLAKE3 of everything before it.
    let split = pack.len() - 32;
    let trailer = hash::hash(&pack[..split]);
    assert_eq!(&pack[split..], trailer.as_slice());

    // Pack key matches.
    assert_eq!(pack_key(&pack), hash::hash(&pack));

    // Roundtrip through reader.
    let dir = tempfile::TempDir::new().unwrap();
    let store = ObjectStore::init(&RepoLayout::single(dir.path())).unwrap();
    let report = PackReader::read(&pack, &store).unwrap();
    assert_eq!(report.raw_count, 1);
    assert_eq!(report.delta_count, 0);
    assert_eq!(report.stored, vec![blob_hash]);
}

#[test]
fn empty_pack_pin_bytes() {
    // 12-byte header + 32-byte trailer = 44 bytes.
    let pack = PackWriter::new().finish().unwrap();
    assert_eq!(pack.len(), 44);
    assert_eq!(&pack[0..4], b"KIT\0");
    assert_eq!(u32::from_le_bytes(pack[4..8].try_into().unwrap()), 1);
    assert_eq!(u32::from_le_bytes(pack[8..12].try_into().unwrap()), 0);
    let trailer = hash::hash(&pack[..12]);
    assert_eq!(&pack[12..], trailer.as_slice());
}

/// The exact 61 bytes `pack_basic_pin_bytes_roundtrip` builds via
/// `PackWriter` — captured as a literal byte-for-byte pin BEFORE
/// v2/zstd changes landed. Unlike that test (which
/// re-derives the pack through the current `PackWriter` and would
/// silently drift if writer and reader changed in lockstep), this
/// array can never change: it is the one fixed point
/// `v1_pack_still_reads_bit_identical` decodes against, so any v1
/// framing regression shows up as a decode failure here even if
/// `PackWriter` itself is buggy in a way that's invisible to
/// self-roundtrip tests.
const PINNED_V1_SINGLE_RAW_PACK: [u8; 61] = [
    0x4b, 0x49, 0x54, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00,
    0x00, 0x01, 0x4b, 0x4f, 0x42, 0x31, 0x01, 0x02, 0x00, 0x00, 0x00, 0x68, 0x69, 0x43, 0x26, 0x17,
    0x39, 0x22, 0xa2, 0x84, 0x72, 0x0d, 0x40, 0x84, 0x7b, 0xa4, 0x65, 0x86, 0xc6, 0x1a, 0x1a, 0x34,
    0x0e, 0x51, 0xe7, 0x4a, 0x70, 0x37, 0x1c, 0xca, 0xc1, 0x2c, 0xf7, 0x45, 0xec,
];

#[test]
fn v1_pack_still_reads_bit_identical() {
    // No-regression guardrail for (SPEC-PACKFILE v2,
    // zstd-compressed entries): a pre-existing v1 pack, pinned as raw
    // bytes captured before the v2 changes, MUST decode to exactly the
    // same result after those changes as it did before. `PackWriter`
    // now sometimes emits `version = 2`, and `PackReader` now handles
    // `0x03`/`0x04` — none of that may perturb how a plain `version =
    // 1`, all-`0x00`/`0x02` pack like this one is read.
    let blob = kit_core::object::Object::Blob(kit_core::object::Blob {
        data: b"hi".to_vec(),
    });
    let blob_bytes = kit_core::serialize::serialize(&blob).unwrap();
    let blob_hash = hash::hash(&blob_bytes);

    let pack = &PINNED_V1_SINGLE_RAW_PACK;
    assert_eq!(u32::from_le_bytes(pack[4..8].try_into().unwrap()), 1);
    assert_eq!(
        pack[12], 0x00,
        "sanity: pinned pack's only entry is 0x00 raw"
    );

    let dir = tempfile::TempDir::new().unwrap();
    let store = ObjectStore::init(&RepoLayout::single(dir.path())).unwrap();
    let report = PackReader::read(pack.as_slice(), &store).unwrap();
    assert_eq!(report.raw_count, 1);
    assert_eq!(report.delta_count, 0);
    assert_eq!(report.stored, vec![blob_hash]);
    assert_eq!(store.read(&blob_hash).unwrap(), blob_bytes);
}

#[test]
#[cfg(feature = "pack-zstd")]
fn pack_v2_compressed_raw_pin_bytes_roundtrip() {
    // Minimal v2 pack: one highly-compressible raw entry, forced into
    // the 0x03 zstd-raw path by the §3.3 writer policy.
    let payload = vec![0x42u8; 4096];
    let blob = kit_core::object::Object::Blob(kit_core::object::Blob { data: payload });
    let blob_bytes = kit_core::serialize::serialize(&blob).unwrap();
    let blob_hash = hash::hash(&blob_bytes);

    let mut w = PackWriter::new();
    w.push_raw(blob_hash, &blob_bytes).unwrap();
    let pack = w.finish().unwrap();

    // Header: version = 2.
    assert_eq!(&pack[0..4], b"KIT\0");
    assert_eq!(u32::from_le_bytes(pack[4..8].try_into().unwrap()), 2);
    assert_eq!(u32::from_le_bytes(pack[8..12].try_into().unwrap()), 1);

    // Entry frame: type 0x03, payload = [4B uncompressed_len][zstd frame].
    assert_eq!(pack[12], 0x03);
    let entry_payload_len = u32::from_le_bytes(pack[13..17].try_into().unwrap()) as usize;
    let uncompressed_len = u32::from_le_bytes(pack[17..21].try_into().unwrap()) as usize;
    assert_eq!(uncompressed_len, blob_bytes.len());
    // The whole point of compression: on-wire payload is much smaller
    // than the 4096+ byte original for this maximally-repetitive input.
    assert!(
        entry_payload_len < blob_bytes.len() / 4,
        "expected substantial compression, on-wire={entry_payload_len} raw={}",
        blob_bytes.len()
    );

    // Trailer.
    let split = pack.len() - 32;
    let trailer = hash::hash(&pack[..split]);
    assert_eq!(&pack[split..], trailer.as_slice());
    assert_eq!(pack_key(&pack), hash::hash(&pack));

    // Roundtrip through reader: recovered bytes are byte-identical to
    // the pre-compression original.
    let dir = tempfile::TempDir::new().unwrap();
    let store = ObjectStore::init(&RepoLayout::single(dir.path())).unwrap();
    let report = PackReader::read(&pack, &store).unwrap();
    assert_eq!(report.raw_count, 1);
    assert_eq!(report.delta_count, 0);
    assert_eq!(report.stored, vec![blob_hash]);
    assert_eq!(store.read(&blob_hash).unwrap(), blob_bytes);
}

#[test]
#[cfg(feature = "pack-zstd")]
fn pack_v2_compressed_delta_pin_bytes_roundtrip() {
    // Minimal v2 pack: a raw base plus one delta entry whose stream is
    // highly-compressible, forced into the 0x04 zstd-delta path.
    let base_blob = kit_core::object::Object::Blob(kit_core::object::Blob {
        data: b"delta base filler, deliberately unrelated to the target".to_vec(),
    });
    let base_bytes = kit_core::serialize::serialize(&base_blob).unwrap();
    let base_hash = hash::hash(&base_bytes);

    let target_blob = kit_core::object::Object::Blob(kit_core::object::Blob {
        data: vec![0x42u8; 4096],
    });
    let target_bytes = kit_core::serialize::serialize(&target_blob).unwrap();
    let target_hash = hash::hash(&target_bytes);

    let stream = delta::encode(&base_bytes, &target_bytes).unwrap();
    assert!(
        stream.len() >= 64,
        "sanity: stream must clear the compression-candidate floor"
    );

    let mut w = PackWriter::new();
    w.push_raw(base_hash, &base_bytes).unwrap();
    w.push_delta(&base_hash, &stream).unwrap();
    let pack = w.finish().unwrap();

    assert_eq!(u32::from_le_bytes(pack[4..8].try_into().unwrap()), 2);
    assert_eq!(u32::from_le_bytes(pack[8..12].try_into().unwrap()), 2);

    // First entry: raw base (0x00, base_bytes is short and not worth
    // compressing).
    assert_eq!(pack[12], 0x00);
    let base_payload_len = u32::from_le_bytes(pack[13..17].try_into().unwrap()) as usize;
    assert_eq!(&pack[17..17 + base_payload_len], base_bytes.as_slice());

    // Second entry: 0x04 zstd-delta, payload = [32B base_hash]
    // [4B uncompressed_len][zstd frame].
    let second_offset = 12 + 5 + base_payload_len;
    assert_eq!(pack[second_offset], 0x04);
    let second_payload_offset = second_offset + 5;
    assert_eq!(
        &pack[second_payload_offset..second_payload_offset + 32],
        base_hash.as_slice(),
        "0x04's base_hash must be uncompressed and in the same position as 0x02's"
    );
    let uncompressed_len_offset = second_payload_offset + 32;
    let uncompressed_len = u32::from_le_bytes(
        pack[uncompressed_len_offset..uncompressed_len_offset + 4]
            .try_into()
            .unwrap(),
    ) as usize;
    assert_eq!(uncompressed_len, stream.len());

    // Trailer.
    let split = pack.len() - 32;
    let trailer = hash::hash(&pack[..split]);
    assert_eq!(&pack[split..], trailer.as_slice());

    // Roundtrip through reader.
    let dir = tempfile::TempDir::new().unwrap();
    let store = ObjectStore::init(&RepoLayout::single(dir.path())).unwrap();
    let report = PackReader::read(&pack, &store).unwrap();
    assert_eq!(report.raw_count, 1);
    assert_eq!(report.delta_count, 1);
    assert_eq!(report.stored, vec![base_hash, target_hash]);
    assert_eq!(store.read(&target_hash).unwrap(), target_bytes);
}

/// SPEC-PACKFILE v2 committed fixtures (`rust/tests/golden/pack-v2/`,
/// §10 vector 20).
///
/// The writer-driven v2 pins above need `pack-zstd` to build their packs,
/// so a decode-only build had no real v2 bytes to read. These fixtures are
/// produced once by the C encoder (`KIT_WRITE_GOLDEN=1 cargo test -p
/// kit-core --test golden_pack`, default features) and read back by every
/// build that has a decoder. `MANIFEST.txt`
/// pins the BLAKE3 of every file; each `.json` sidecar lists the entries'
/// wire types, object ids and byte digests, plus the zstd frame offsets
/// for an independent `zstd -d` cross-check.
mod pack_v2_fixtures {
    use std::fs;
    use std::ops::Range;
    use std::path::PathBuf;

    use kit_core::hash::{self, from_hex, to_hex};
    use kit_core::pack::PackReader;
    use serde_json::Value;

    pub(super) fn dir() -> PathBuf {
        let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.pop(); // crates/
        d.pop(); // rust/
        d.extend(["tests", "golden", "pack-v2"]);
        d
    }

    /// `(wire type, payload range)` for every entry, from the framing alone.
    pub(super) fn frames(pack: &[u8]) -> Vec<(u8, Range<usize>)> {
        let count = u32::from_le_bytes(pack[8..12].try_into().unwrap());
        let mut pos = 12;
        (0..count)
            .map(|_| {
                let etype = pack[pos];
                let len = u32::from_le_bytes(pack[pos + 1..pos + 5].try_into().unwrap()) as usize;
                pos += 5 + len;
                (etype, pos - len..pos)
            })
            .collect()
    }

    fn manifest() -> Vec<(String, String)> {
        fs::read_to_string(dir().join("MANIFEST.txt"))
            .expect("missing pack-v2/MANIFEST.txt")
            .lines()
            .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
            .map(|l| {
                let mut parts = l.split_whitespace();
                (
                    parts.next().unwrap().to_string(),
                    parts.next().unwrap().to_string(),
                )
            })
            .collect()
    }

    /// Read a fixture file, asserting its BLAKE3 matches `MANIFEST.txt`.
    fn load(file: &str) -> Vec<u8> {
        let want = manifest()
            .into_iter()
            .find(|(f, _)| f == file)
            .unwrap_or_else(|| panic!("{file} is not listed in MANIFEST.txt"))
            .1;
        let bytes = fs::read(dir().join(file)).unwrap_or_else(|e| panic!("read {file}: {e}"));
        assert_eq!(to_hex(&hash::hash(&bytes)), want, "{file}: digest drift");
        bytes
    }

    fn sidecar(name: &str) -> Value {
        serde_json::from_slice(&load(&format!("{name}.json"))).unwrap()
    }

    fn hex_field(v: &Value, key: &str) -> hash::Hash {
        from_hex(v[key].as_str().unwrap()).unwrap()
    }

    #[cfg(feature = "pack-zstd")]
    mod write {
        use std::fmt::Write as _;
        use std::fs;

        use kit_core::delta;
        use kit_core::hash::{self, Hash, ZERO, to_hex};
        use kit_core::object::{Blob, Commit, EntryMode, Identity, Object, Tree, TreeEntry};
        use kit_core::pack::{PackWriter, pack_key};
        use kit_core::sign::{KeyPair, sign_commit};
        use serde_json::json;

        use super::{dir, frames};

        /// One pushed object: its serialized bytes and, for a delta push,
        /// the base it is encoded against.
        struct Push {
            bytes: Vec<u8>,
            delta_base: Option<Vec<u8>>,
        }

        fn raw(obj: &Object) -> Push {
            Push {
                bytes: kit_core::serialize::serialize(obj).unwrap(),
                delta_base: None,
            }
        }

        fn delta_of(base: &Push, obj: &Object) -> Push {
            Push {
                bytes: kit_core::serialize::serialize(obj).unwrap(),
                delta_base: Some(base.bytes.clone()),
            }
        }

        fn blob(data: Vec<u8>) -> Object {
            Object::Blob(Blob { data })
        }

        fn id(bytes: &[u8]) -> Hash {
            let obj = kit_core::serialize::deserialize(bytes).unwrap();
            kit_core::object::id_from_object(&obj, bytes)
        }

        /// LCG filler the §3.3 writer policy declines to compress.
        fn noise(seed: u32, len: usize) -> Vec<u8> {
            let mut s = seed;
            (0..len)
                .map(|_| {
                    s = s.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                    s.to_be_bytes()[1]
                })
                .collect()
        }

        fn fixtures() -> Vec<(&'static str, &'static str, Vec<Push>)> {
            // The inputs of `pack_v2_compressed_raw_pin_bytes_roundtrip`.
            let raw_4k = vec![raw(&blob(vec![0x42; 4096]))];

            // The inputs of `pack_v2_compressed_delta_pin_bytes_roundtrip`.
            let base = raw(&blob(
                b"delta base filler, deliberately unrelated to the target".to_vec(),
            ));
            let target = delta_of(&base, &blob(vec![0x42; 4096]));
            let delta_repeat = vec![base, target];

            // 0x00, 0x03, 0x02 and 0x04 in one pack; the 0x04 entry's base
            // is the 0x02 entry's target (an in-pack delta chain).
            let a_data = noise(7, 200);
            let a = raw(&blob(a_data.clone()));
            let b = raw(&blob(b"kit pack v2 fixture line\n".repeat(120)));
            let mut c_data = a_data;
            c_data[100] ^= 0xFF;
            let c = delta_of(&a, &blob(c_data.clone()));
            let mut d_data = c_data;
            d_data.extend_from_slice(&[0x61; 4096]);
            let d = delta_of(&c, &blob(d_data));
            let mixed = vec![a, b, c, d];

            // A compressible tree and an Ed25519-signed commit over it.
            let leaf = raw(&blob(b"shared leaf".to_vec()));
            let leaf_id = id(&leaf.bytes);
            let tree = raw(&Object::Tree(Tree {
                entries: (0..64)
                    .map(|i| TreeEntry {
                        name: format!("module_{i:03}.rs").into_bytes(),
                        mode: EntryMode::Blob,
                        object_hash: leaf_id,
                    })
                    .collect(),
            }));
            let kp = KeyPair::from_seed([0x07; 32]);
            let mut commit = Commit {
                tree_hash: id(&tree.bytes),
                parents: vec![],
                author: Identity::ed25519(kp.public.0),
                signer: kp.public.0,
                message: b"pack-v2 fixture: compressible commit message. ".repeat(20),
                timestamp: 1_726_300_000,
                message_hash: ZERO,
                content_digest: ZERO,
                signature: [0u8; 64],
            };
            commit.signature = sign_commit(&commit, &kp).unwrap().0;
            let tree_and_commit = vec![leaf, tree, raw(&Object::Commit(commit))];

            // Literal-heavy blobs (16-symbol noise: Huffman-compressible,
            // few LZ matches) so the frames carry the 4-byte (14-bit) and
            // 5-byte (18-bit) literals-section headers: ~10 KiB, 64 KiB and
            // 263 KiB (several 128 KiB blocks).
            let hex16 = |seed: u32, len: usize| -> Vec<u8> {
                noise(seed, len)
                    .iter()
                    .map(|b| b"0123456789abcdef"[usize::from(b & 15)])
                    .collect()
            };
            let large_literals = vec![
                raw(&blob(hex16(11, 10 * 1024))),
                raw(&blob(hex16(12, 64 * 1024))),
                raw(&blob(hex16(13, 263 * 1024))),
            ];

            vec![
                ("raw_4k_repeat", "one 0x03 zstd-raw entry", raw_4k),
                (
                    "delta_repeat",
                    "a 0x00 base and a 0x04 zstd-delta entry against it",
                    delta_repeat,
                ),
                (
                    "mixed",
                    "0x00, 0x03, 0x02 and 0x04 entries; the 0x04 base is the 0x02 target",
                    mixed,
                ),
                (
                    "tree_and_commit",
                    "a 0x00 leaf blob, a 0x03 tree and a 0x03 Ed25519-signed commit",
                    tree_and_commit,
                ),
                (
                    "large_literals",
                    "three 0x03 blobs (10 KiB, 64 KiB, 263 KiB) whose frames use the \
                     4- and 5-byte literals-section headers",
                    large_literals,
                ),
            ]
        }

        fn entry_json(
            pack: &[u8],
            etype: u8,
            range: std::ops::Range<usize>,
            p: &Push,
        ) -> serde_json::Value {
            let mut e = json!({
                "type": etype,
                "id": to_hex(&id(&p.bytes)),
                "len": p.bytes.len(),
                "blake3_of_bytes": to_hex(&hash::hash(&p.bytes)),
            });
            let prefix = match etype {
                0x03 => 0,
                0x04 => 32,
                _ => return e,
            };
            let len_at = range.start + prefix;
            let claim = u32::from_le_bytes(pack[len_at..len_at + 4].try_into().unwrap());
            let decoded = match &p.delta_base {
                None => p.bytes.clone(),
                Some(base) => delta::encode(base, &p.bytes).unwrap(),
            };
            e["uncompressed_len"] = json!(claim);
            e["frame_offset"] = json!(len_at + 4);
            e["frame_len"] = json!(range.end - len_at - 4);
            e["decoded_blake3"] = json!(to_hex(&hash::hash(&decoded)));
            e
        }

        fn write_all() {
            let dir = dir();
            fs::create_dir_all(&dir).unwrap();
            let mut manifest = String::from(
                "# SPEC-PACKFILE fixtures. The zstd packs are written by the C encoder (pack-zstd);\n\
                 # the boundary_ packs need no encoder.\n\
                 # Produced by `KIT_WRITE_GOLDEN=1 cargo test -p kit-core --test golden_pack`\n\
                 # Format: <file> <blake3-hex-of-file-bytes>\n\
                 # See docs/specs/SPEC-PACKFILE.md section 10, vectors 20 to 22.\n",
            );
            for (name, description, pushes) in fixtures() {
                let mut w = PackWriter::new();
                for p in &pushes {
                    match &p.delta_base {
                        None => {
                            w.push_raw(id(&p.bytes), &p.bytes).unwrap();
                        }
                        Some(base) => {
                            let stream = delta::encode(base, &p.bytes).unwrap();
                            w.push_delta(&id(base), &stream).unwrap();
                        }
                    }
                }
                let pack = w.finish().unwrap();
                let entries: Vec<_> = frames(&pack)
                    .into_iter()
                    .zip(&pushes)
                    .map(|((etype, range), p)| entry_json(&pack, etype, range, p))
                    .collect();
                let sidecar = json!({
                    "name": name,
                    "description": description,
                    "bin": format!("{name}.bin"),
                    "size": pack.len(),
                    "version": u32::from_le_bytes(pack[4..8].try_into().unwrap()),
                    "pack_key": to_hex(&pack_key(&pack)),
                    "entries": entries,
                });
                write_vector(&dir, &mut manifest, name, pack, &sidecar);
            }
            for (name, pack, sidecar) in boundary_vectors() {
                write_vector(&dir, &mut manifest, &name, pack, &sidecar);
            }
            fs::write(dir.join("MANIFEST.txt"), manifest).unwrap();
        }

        /// Write `<name>.bin` and `<name>.json`, and list both in the manifest.
        fn write_vector(
            dir: &std::path::Path,
            manifest: &mut String,
            name: &str,
            pack: Vec<u8>,
            sidecar: &serde_json::Value,
        ) {
            let json_bytes = serde_json::to_string_pretty(sidecar).unwrap() + "\n";
            for (file, bytes) in [
                (format!("{name}.bin"), pack),
                (format!("{name}.json"), json_bytes.into_bytes()),
            ] {
                let _ = writeln!(manifest, "{file} {}", to_hex(&hash::hash(&bytes)));
                fs::write(dir.join(&file), bytes).unwrap();
            }
        }

        /// A version 1 pack from `(entry type, payload)` frames, with a valid
        /// trailer. Nothing checks the entry rules, so a test can frame a
        /// pack that a reader must refuse.
        fn framed_pack(entries: &[(u8, Vec<u8>)]) -> Vec<u8> {
            let mut pack = b"KIT\0".to_vec();
            pack.extend(1u32.to_le_bytes());
            pack.extend(u32::try_from(entries.len()).unwrap().to_le_bytes());
            for (etype, payload) in entries {
                pack.push(*etype);
                pack.extend(u32::try_from(payload.len()).unwrap().to_le_bytes());
                pack.extend(payload);
            }
            let trailer = hash::hash(&pack);
            pack.extend(trailer);
            pack
        }

        /// A pack whose only entry declares `declared` payload bytes and
        /// carries none, with a valid trailer.
        fn declared_length_pack(declared: u32) -> Vec<u8> {
            let mut pack = b"KIT\0".to_vec();
            pack.extend(1u32.to_le_bytes());
            pack.extend(1u32.to_le_bytes());
            pack.push(0x00);
            pack.extend(declared.to_le_bytes());
            let trailer = hash::hash(&pack);
            pack.extend(trailer);
            pack
        }

        /// Vectors 21 and 22 of SPEC-PACKFILE section 10. They need no zstd
        /// frame, so every build can read them.
        fn boundary_vectors() -> Vec<(String, Vec<u8>, serde_json::Value)> {
            let sidecar = |name: &str, description: &str, pack: &[u8], expected: &str| {
                json!({
                    "name": name,
                    "description": description,
                    "bin": format!("{name}.bin"),
                    "size": pack.len(),
                    "version": 1,
                    "pack_key": to_hex(&pack_key(pack)),
                    "expected": expected,
                })
            };
            let mut vectors = Vec::new();
            for (name, declared) in [
                ("boundary_payload_high_bit", 1u32 << 31),
                ("boundary_payload_u32_max", u32::MAX),
            ] {
                let pack = declared_length_pack(declared);
                let mut side = sidecar(
                    name,
                    "A payload length that the short pack cannot hold, with a valid trailer.",
                    &pack,
                    "UnexpectedEof",
                );
                side["declared_payload_len"] = json!(declared);
                vectors.push((name.to_owned(), pack, side));
            }

            let a = raw(&blob(b"base".to_vec()));
            let b = raw(&blob(b"middle".to_vec()));
            let c = raw(&blob(b"target".to_vec()));
            let raw_frame = |p: &Push| (0x00, p.bytes.clone());
            // A `0x02` entry: the id of the base, then the delta stream.
            let delta_frame = |base: &Push, target: &Push| {
                let mut payload = id(&base.bytes).to_vec();
                payload.extend(delta::encode(&base.bytes, &target.bytes).unwrap());
                (0x02, payload)
            };
            let earlier = framed_pack(&[raw_frame(&a), delta_frame(&a, &b), delta_frame(&b, &c)]);
            let mut side = sidecar(
                "boundary_earlier_delta_base",
                "Raw A, delta B on A, delta C on B: each base is an earlier entry.",
                &earlier,
                "Complete",
            );
            side["entries"] = json!(
                [(0x00_u8, &a), (0x02, &b), (0x02, &c)]
                    .iter()
                    .map(|(etype, p)| json!({
                        "type": etype,
                        "id": to_hex(&id(&p.bytes)),
                        "len": p.bytes.len(),
                        "blake3_of_bytes": to_hex(&hash::hash(&p.bytes)),
                    }))
                    .collect::<Vec<_>>()
            );
            vectors.push(("boundary_earlier_delta_base".to_owned(), earlier, side));

            let later = framed_pack(&[raw_frame(&a), delta_frame(&b, &c), delta_frame(&a, &b)]);
            let mut side = sidecar(
                "boundary_later_delta_base",
                "Delta B moved after delta C: the framing is valid and the base of C comes later.",
                &later,
                "DeltaBaseMissing",
            );
            side["framing_entries"] = json!(3);
            vectors.push(("boundary_later_delta_base".to_owned(), later, side));
            vectors
        }

        #[test]
        fn write_pack_v2_goldens_if_requested() {
            if std::env::var("KIT_WRITE_GOLDEN").is_ok() {
                write_all();
            }
        }
    }

    /// Every committed v2 fixture decodes to the sidecar's objects through
    /// both [`PackEntries`] and [`PackReader::read`].
    #[test]
    #[cfg(feature = "pack-zstd")]
    fn pack_v2_fixtures_decode() {
        use std::collections::HashMap;

        use kit_core::pack::{PackEntries, PackEntry, pack_key};

        let names: Vec<String> = manifest()
            .into_iter()
            .filter_map(|(f, _)| f.strip_suffix(".bin").map(str::to_string))
            .filter(|name| !name.starts_with("boundary_"))
            .collect();
        assert_eq!(names.len(), 5, "MANIFEST.txt lists {names:?}");
        for name in names {
            let pack = load(&format!("{name}.bin"));
            let side = sidecar(&name);
            assert_eq!(to_hex(&pack_key(&pack)), side["pack_key"].as_str().unwrap());
            let want = side["entries"].as_array().unwrap();
            let wire = frames(&pack);
            assert_eq!(wire.len(), want.len(), "{name}: entry count");
            for ((etype, _), w) in wire.iter().zip(want) {
                assert_eq!(u64::from(*etype), w["type"].as_u64().unwrap(), "{name}");
            }
            assert!(
                wire.iter().any(|(t, _)| *t == 0x03 || *t == 0x04),
                "{name}: fixture must exercise the zstd decoder"
            );

            let mut resolved: HashMap<hash::Hash, Vec<u8>> = HashMap::new();
            for (entry, w) in PackEntries::new(&pack).unwrap().zip(want) {
                let (object, decoded) = match entry.unwrap() {
                    PackEntry::Raw { bytes } => (bytes.to_vec(), bytes.into_owned()),
                    PackEntry::Delta { base, stream } => (
                        kit_core::delta::decode(&resolved[&base], &stream).unwrap(),
                        stream.into_owned(),
                    ),
                };
                if let Some(d) = w["decoded_blake3"].as_str() {
                    assert_eq!(to_hex(&hash::hash(&decoded)), d, "{name}: decoded payload");
                }
                assert_eq!(object.len() as u64, w["len"].as_u64().unwrap(), "{name}");
                assert_eq!(
                    hash::hash(&object),
                    hex_field(w, "blake3_of_bytes"),
                    "{name}"
                );
                let obj = kit_core::serialize::deserialize(&object).unwrap();
                let id = kit_core::object::id_from_object(&obj, &object);
                assert_eq!(id, hex_field(w, "id"), "{name}: object id");
                resolved.insert(id, object);
            }
            assert_eq!(resolved.len(), want.len(), "{name}: every entry decoded");

            let dir = tempfile::TempDir::new().unwrap();
            let store = super::ObjectStore::init(&super::RepoLayout::single(dir.path())).unwrap();
            let report = PackReader::read(&pack, &store).unwrap();
            let ids: Vec<_> = want.iter().map(|w| hex_field(w, "id")).collect();
            assert_eq!(report.stored, ids, "{name}: stored ids");
            for w in want {
                let bytes = store.read(&hex_field(w, "id")).unwrap();
                assert_eq!(
                    hash::hash(&bytes),
                    hex_field(w, "blake3_of_bytes"),
                    "{name}"
                );
            }
        }
    }

    /// Vector 21: a payload length of `2^31` or `2^32 - 1` in a short pack
    /// is read as an unsigned length. It does not wrap, and the general
    /// reader refuses it as a short read.
    #[test]
    fn unsigned_payload_boundaries_are_short_reads() {
        use kit_core::pack::{
            DecodeLimits, NoExternalBases, PackEntries, PackError, decode_entries_with,
        };

        for name in ["boundary_payload_high_bit", "boundary_payload_u32_max"] {
            let pack = load(&format!("{name}.bin"));
            let side = sidecar(name);
            assert_eq!(side["expected"], "UnexpectedEof", "{name}");
            let declared = u32::from_le_bytes(pack[13..17].try_into().unwrap());
            assert_eq!(u64::from(declared), side["declared_payload_len"], "{name}");
            // The trailer is valid, so only the length can be at fault.
            let split = pack.len() - 32;
            assert_eq!(hash::hash(&pack[..split]), pack[split..], "{name}: trailer");
            assert!(matches!(
                PackEntries::new(&pack),
                Err(PackError::UnexpectedEof)
            ));
            assert!(matches!(
                decode_entries_with(&pack, &mut NoExternalBases, DecodeLimits::default(), |_| {
                    Ok(())
                }),
                Err(PackError::UnexpectedEof)
            ));
        }
    }

    /// Vector 22: a delta whose base is an earlier delta result resolves.
    /// Moving that base after the delta leaves it without an earlier base.
    #[test]
    fn earlier_reconstructed_delta_is_an_eligible_base() {
        use kit_core::pack::{
            DecodeLimits, NoExternalBases, PackEntries, PackError, decode_entries_with,
        };

        let pack = load("boundary_earlier_delta_base.bin");
        let side = sidecar("boundary_earlier_delta_base");
        let mut objects = Vec::new();
        let report = decode_entries_with(
            &pack,
            &mut NoExternalBases,
            DecodeLimits::default(),
            |entry| {
                objects.push(entry.bytes.to_vec());
                Ok(())
            },
        )
        .unwrap();
        assert_eq!((report.raw_count, report.delta_count), (1, 2));
        let want = side["entries"].as_array().unwrap();
        assert_eq!(objects.len(), want.len());
        for (object, w) in objects.iter().zip(want) {
            assert_eq!(hash::hash(object), hex_field(w, "blake3_of_bytes"));
            let obj = kit_core::serialize::deserialize(object).unwrap();
            assert_eq!(
                kit_core::object::id_from_object(&obj, object),
                hex_field(w, "id")
            );
        }

        let later = load("boundary_later_delta_base.bin");
        let side = sidecar("boundary_later_delta_base");
        assert_eq!(side["expected"], "DeltaBaseMissing");
        // The framing is valid: only the order of the bases is wrong.
        let count = usize::try_from(side["framing_entries"].as_u64().unwrap()).unwrap();
        assert_eq!(PackEntries::new(&later).unwrap().count(), count);
        assert!(matches!(
            decode_entries_with(
                &later,
                &mut NoExternalBases,
                DecodeLimits::default(),
                |_| { Ok(()) }
            ),
            Err(PackError::DeltaBaseMissing(_))
        ));
    }

    /// SPEC-DISCLOSURE §7.2: the closure profile is raw-only and rejects a
    /// compressed entry from the type scan, without decompressing it —
    /// whichever decoder is compiled in. A frame corrupted beyond decoding
    /// still yields the profile violation, not a zstd error.
    #[test]
    fn closure_profile_still_rejects_compressed_entries() {
        use kit_core::ClosureMode;
        use kit_core::verify::{VerifyError, verify_closure_packs};

        let pack = load("raw_4k_repeat.bin");
        let root = hex_field(&sidecar("raw_4k_repeat")["entries"][0], "id");
        let mut corrupt = pack.clone();
        let (_, range) = frames(&corrupt)[0].clone();
        corrupt[range.start + 4..range.end].fill(0xEE);
        let split = corrupt.len() - 32;
        let trailer = hash::hash(&corrupt[..split]);
        corrupt[split..].copy_from_slice(&trailer);
        for p in [&pack, &corrupt] {
            let err = verify_closure_packs(&root, ClosureMode::Snapshot, &[p.as_slice()]);
            assert!(
                matches!(
                    err,
                    Err(VerifyError::ClosureProfileViolation {
                        pack_index: 0,
                        entry_index: 0
                    })
                ),
                "got {err:?}"
            );
        }
    }

    /// With no decoder compiled in, a compressed entry still fails closed.
    #[test]
    #[cfg(not(feature = "pack-zstd"))]
    fn compressed_fixture_fails_closed_without_a_decoder() {
        let pack = load("raw_4k_repeat.bin");
        let dir = tempfile::TempDir::new().unwrap();
        let store = super::ObjectStore::init(&super::RepoLayout::single(dir.path())).unwrap();
        let err = PackReader::read(&pack, &store).unwrap_err();
        assert!(
            matches!(err, kit_core::pack::PackError::ZstdDecompress(_)),
            "got {err:?}"
        );
    }
}
