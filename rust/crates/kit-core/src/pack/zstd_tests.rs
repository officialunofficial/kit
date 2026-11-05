//! SPEC-PACKFILE §3.3/§3.4 zstd entry decoding: the one-frame rule, the
//! window and block bounds, and the reserved-field checks.
//!
//! Frames the tests need without an encoder are hand-built from raw
//! blocks (RFC 8878 §3.1.1.2).

use super::*;

/// The RFC 8878 frame magic, for hand-built frames.
#[cfg(feature = "pack-zstd")]
const MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];
/// A skippable frame (magic `0x184D2A50`) with an empty body.
#[cfg(feature = "pack-zstd")]
const SKIPPABLE: [u8; 8] = [0x50, 0x2A, 0x4D, 0x18, 0, 0, 0, 0];

/// A `0x03`-style entry payload: `[u32 LE claim][frame]`.
#[cfg(feature = "pack-zstd")]
fn entry(claim: usize, frame: &[u8]) -> Vec<u8> {
    let mut p = u32::try_from(claim).unwrap().to_le_bytes().to_vec();
    p.extend_from_slice(frame);
    p
}

#[cfg(feature = "pack-zstd")]
fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

/// A frame of raw (stored) blocks. `fcs` writes a 4-byte
/// `Frame_Content_Size`; `window_log: None` sets `Single_Segment`
/// (which requires `fcs`), `Some(log)` writes a window descriptor.
#[cfg(feature = "pack-zstd")]
fn raw_block_frame(content: &[u8], fcs: Option<u32>, window_log: Option<u8>) -> Vec<u8> {
    let mut f = MAGIC.to_vec();
    let fcs_flag = if fcs.is_some() { 0b10 << 6 } else { 0 };
    let single = if window_log.is_none() { 0x20 } else { 0 };
    f.push(fcs_flag | single);
    if let Some(log) = window_log {
        f.push((log - 10) << 3);
    }
    if let Some(n) = fcs {
        f.extend_from_slice(&n.to_le_bytes());
    }
    if content.is_empty() {
        f.extend_from_slice(&[1, 0, 0]); // last raw block, size 0
    }
    let mut blocks = content.chunks(128 * 1024).peekable();
    while let Some(block) = blocks.next() {
        let last = u32::from(blocks.peek().is_none());
        let header = (u32::try_from(block.len()).unwrap() << 3) | last;
        f.extend_from_slice(&header.to_le_bytes()[..3]);
        f.extend_from_slice(block);
    }
    f
}

#[cfg(feature = "pack-zstd")]
#[test]
fn peek_delta_header_reads_lengths_without_applying_instructions() {
    let mut header = vec![delta::STREAM_VERSION];
    header.extend_from_slice(&512u32.to_le_bytes());
    header.extend_from_slice(&u32::MAX.to_le_bytes());
    header.push(0); // Invalid instruction: header inspection must not apply it.
    assert_eq!(
        peek_delta_header(&raw_block_frame(&header, None, Some(23))).unwrap(),
        (512, u32::MAX)
    );
    let mut split = MAGIC.to_vec();
    split.extend_from_slice(&[0, 0]);
    for (index, byte) in header[..delta::HEADER_LEN].iter().enumerate() {
        split.extend_from_slice(&(8u32 | u32::from(index == 8)).to_le_bytes()[..3]);
        split.push(*byte);
    }
    assert_eq!(peek_delta_header(&split).unwrap(), (512, u32::MAX));
    for length in 0..delta::HEADER_LEN {
        assert!(peek_delta_header(&raw_block_frame(&header[..length], None, Some(23))).is_err());
    }
    header[0] = 2;
    assert!(matches!(
        peek_delta_header(&raw_block_frame(&header, None, Some(23))),
        Err(PackError::DeltaApply(KitError::UnsupportedObjectVersion))
    ));
    assert!(peek_delta_header(&[]).is_err());
    header[0] = delta::STREAM_VERSION;
    assert!(peek_delta_header(&raw_block_frame(&header, None, Some(24))).is_err());
}

/// The variant class a decode ended in.
#[cfg(feature = "pack-zstd")]
fn class(r: &Result<Vec<u8>, PackError>) -> &'static str {
    match r {
        Ok(_) => "ok",
        Err(PackError::ZstdEntryTruncated) => "ZstdEntryTruncated",
        Err(PackError::DecompressedSizeOverCap(_)) => "DecompressedSizeOverCap",
        Err(PackError::DecompressedSizeMismatch(..)) => "DecompressedSizeMismatch",
        Err(PackError::ZstdDecompress(_)) => "ZstdDecompress",
        Err(e) => panic!("unexpected zstd entry error {e:?}"),
    }
}

/// The C decoder alone would accept concatenated frames and skip
/// skippable ones. SPEC-PACKFILE §3.3 allows exactly one frame.
#[cfg(feature = "pack-zstd")]
#[test]
fn decoder_enforces_one_frame() {
    let a = zstd::bulk::compress(&[1u8; 100], 3).unwrap();
    let b = zstd::bulk::compress(&[2u8; 100], 3).unwrap();
    assert_eq!(zstd_decompress_capped(&a, 100).unwrap(), vec![1u8; 100]);
    let mut pre_rfc = a.clone();
    pre_rfc[0] = 0x27; // v0.7 frame magic 0xFD2FB527
    for (case, frame, cap) in [
        ("two frames", cat(&[&a, &b]), 200),
        ("frame + skippable", cat(&[&a, &SKIPPABLE]), 100),
        ("skippable + frame", cat(&[&SKIPPABLE, &a]), 100),
        ("lone skippable", SKIPPABLE.to_vec(), 0),
        ("trailing byte", cat(&[&a, &[0]]), 100),
        ("pre-RFC magic", pre_rfc, 100),
    ] {
        let r = zstd_decompress_capped(&frame, cap);
        assert!(
            matches!(r, Err(PackError::ZstdDecompress(_))),
            "{case}: {r:?}"
        );
    }
}

/// `PackWriter` only compresses with the C encoder. A build without it
/// writes v1 packs.
#[cfg(not(feature = "pack-zstd"))]
#[test]
fn raw_only_writer_when_no_c_zstd() {
    let blob = crate::serialize::serialize(&crate::object::Object::Blob(crate::object::Blob {
        data: vec![0x42; 4096],
    }))
    .unwrap();
    assert!(maybe_compress(&blob).is_none());
    let mut w = PackWriter::new();
    w.push_raw(hash::hash(&blob), &blob).unwrap();
    let pack = w.finish().unwrap();
    assert_eq!(
        u32::from_le_bytes(pack[VERSION_OFFSET..VERSION_OFFSET + 4].try_into().unwrap()),
        VERSION
    );
    assert_eq!(pack[HEADER_LEN], 0x00);
}

/// This same public decoder fixture runs in C-only and Rust-only builds.
/// A short budget must reject the claim before reading a corrupt frame.
#[cfg(feature = "pack-zstd")]
#[test]
fn entry_budget_and_error_classes() {
    let object = crate::serialize::serialize(&crate::object::Object::Blob(crate::object::Blob {
        data: vec![b'A'; 1500],
    }))
    .unwrap();
    let mut zstd = cat(&[&MAGIC, &[0, 0]]); // 1 KiB window
    for (index, part) in object.chunks(1024).enumerate() {
        let last = u32::from(index == 1);
        let header = (u32::try_from(part.len()).unwrap() << 3) | last;
        zstd.extend_from_slice(&header.to_le_bytes()[..3]);
        zstd.extend_from_slice(part);
    }
    let make_frame = |bytes: &[u8], claim: usize| {
        let mut frame = vec![0x03];
        frame.extend_from_slice(&u32::try_from(bytes.len() + 4).unwrap().to_le_bytes());
        frame.extend_from_slice(&u32::try_from(claim).unwrap().to_le_bytes());
        frame.extend_from_slice(bytes);
        frame
    };
    let limits = DecodeLimits::default().with_max_decoded_bytes(object.len() as u64);
    let frame = make_frame(&zstd, object.len());
    assert_eq!(
        decode_frame_with(&frame, VERSION_V2, &mut NoExternalBases, limits).unwrap(),
        (hash::hash(&object), object.clone())
    );
    let mut pack = super::MAGIC.to_vec();
    pack.extend_from_slice(&VERSION_V2.to_le_bytes());
    pack.extend_from_slice(&2u32.to_le_bytes());
    pack.extend_from_slice(&frame);
    pack.extend_from_slice(&frame);
    pack.extend_from_slice(&hash::hash(&pack));
    let cumulative = (object.len() * 2) as u64;
    assert!(
        decode_entries_with(
            &pack,
            &mut NoExternalBases,
            DecodeLimits::default().with_max_decoded_bytes(cumulative),
            |_| Ok(())
        )
        .is_ok()
    );
    let mut sink_calls = 0;
    assert!(matches!(
        decode_entries_with(
            &pack,
            &mut NoExternalBases,
            DecodeLimits::default().with_max_decoded_bytes(cumulative - 1),
            |_| {
                sink_calls += 1;
                Ok(())
            }
        ),
        Err(PackError::PackfileTooLarge)
    ));
    assert_eq!(
        sink_calls, 0,
        "cumulative claims rejected before first sink call"
    );
    let short = DecodeLimits::default().with_max_decoded_bytes(object.len() as u64 - 1);
    for bytes in [&zstd[..], &b"invalid zstd"[..]] {
        assert!(matches!(
            decode_frame_with(
                &make_frame(bytes, object.len()),
                VERSION_V2,
                &mut NoExternalBases,
                short
            ),
            Err(PackError::PackfileTooLarge)
        ));
    }
    assert!(matches!(
        decode_frame_with(
            &make_frame(&zstd, MAX_RAW_OBJECT_SIZE + 1),
            VERSION_V2,
            &mut NoExternalBases,
            limits
        ),
        Err(PackError::DecompressedSizeOverCap(_))
    ));
    assert!(matches!(
        decode_frame_with(
            &make_frame(&zstd, object.len() + 1),
            VERSION_V2,
            &mut NoExternalBases,
            DecodeLimits::default().with_max_decoded_bytes(object.len() as u64 + 1)
        ),
        Err(PackError::DecompressedSizeMismatch(..))
    ));
}

#[cfg(feature = "pack-zstd")]
mod adversarial {
    use super::*;
    use zstd::zstd_safe::CParameter;

    /// Decode `payload` through the full entry checks.
    fn decode(_case: &str, payload: &[u8]) -> Result<Vec<u8>, PackError> {
        decompress_zstd_entry(payload)
    }

    fn compress_with(content: &[u8], params: &[CParameter]) -> Vec<u8> {
        let mut c = zstd::bulk::Compressor::new(ZSTD_LEVEL).unwrap();
        for p in params {
            c.set_parameter(*p).unwrap();
        }
        c.compress(content).unwrap()
    }

    /// Compressed blocks bound the output loosely, at 128 KiB each. A claim
    /// past that bound is a wrong claim on a sound frame, not a corrupt frame.
    #[test]
    fn a_claim_past_the_blocks_of_a_sound_frame_is_a_size_mismatch() {
        let content = b"a long run of compressible text, repeated. ".repeat(5000);
        let frame = compress_with(&content, &[CParameter::WindowLog(18)]);
        assert!(content.len() > 128 << 10 && content.len() < 256 << 10);
        for claim in [content.len() + 1, 300 << 10] {
            let got = decode("claim past the blocks", &entry(claim, &frame));
            assert!(
                matches!(
                    got,
                    Err(PackError::DecompressedSizeMismatch(c, d)) if c == claim && d == content.len()
                ),
                "{got:?}"
            );
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)] // one flat table
    fn rejects_adversarial_frames() {
        let content = b"adversarial frame content, repeated. ".repeat(40);
        let n = content.len();
        let frame = compress_with(&content, &[]);
        let no_fcs = compress_with(&content, &[CParameter::ContentSizeFlag(false)]);
        let checked = compress_with(&content, &[CParameter::ChecksumFlag(true)]);
        let mut bad_sum = checked.clone();
        *bad_sum.last_mut().unwrap() ^= 1;
        let mut dict = MAGIC.to_vec();
        dict.extend_from_slice(&[0x21, 7, 100]); // single segment, 1-byte dict id 7, fcs 100
        dict.extend_from_slice(&(100u32 << 3 | 1).to_le_bytes()[..3]);
        dict.extend_from_slice(&[3; 100]);
        let mut reserved = raw_block_frame(&[3; 100], Some(100), None);
        reserved[4] |= 0x08;

        let cases: Vec<(&str, Vec<u8>, &str)> = vec![
            ("valid", entry(n, &frame), "ok"),
            ("valid, checksummed", entry(n, &checked), "ok"),
            ("valid, no fcs", entry(n, &no_fcs), "ok"),
            (
                "valid, raw blocks",
                entry(3, &raw_block_frame(b"abc", Some(3), None)),
                "ok",
            ),
            (
                "payload shorter than prefix",
                vec![1, 2],
                "ZstdEntryTruncated",
            ),
            (
                "claim over MAX_RAW_OBJECT_SIZE",
                entry(MAX_RAW_OBJECT_SIZE + 1, &frame),
                "DecompressedSizeOverCap",
            ),
            ("empty frame", entry(n, &[]), "ZstdDecompress"),
            (
                "truncated frame",
                entry(n, &frame[..frame.len() - 3]),
                "ZstdDecompress",
            ),
            ("header only", entry(n, &frame[..6]), "ZstdDecompress"),
            (
                "two concatenated frames",
                entry(2 * n, &cat(&[&frame, &frame])),
                "ZstdDecompress",
            ),
            (
                "frame + 1 trailing byte",
                entry(n, &cat(&[&frame, &[0]])),
                "ZstdDecompress",
            ),
            (
                "lone skippable frame",
                entry(0, &SKIPPABLE),
                "ZstdDecompress",
            ),
            (
                "frame + skippable",
                entry(n, &cat(&[&frame, &SKIPPABLE])),
                "ZstdDecompress",
            ),
            (
                "skippable + frame",
                entry(n, &cat(&[&SKIPPABLE, &frame])),
                "ZstdDecompress",
            ),
            ("checksum mismatch", entry(n, &bad_sum), "ZstdDecompress"),
            (
                "claim > frame content size",
                entry(n + 1, &frame),
                "DecompressedSizeMismatch",
            ),
            (
                "claim < frame content size",
                entry(n - 1, &frame),
                "ZstdDecompress",
            ),
            (
                "no fcs, claim > actual",
                entry(n + 1, &no_fcs),
                "DecompressedSizeMismatch",
            ),
            (
                "no fcs, claim < actual",
                entry(n - 1, &no_fcs),
                "ZstdDecompress",
            ),
            (
                "fcs below content",
                entry(1001, &raw_block_frame(&[9; 1000], Some(999), Some(10))),
                "ZstdDecompress",
            ),
            (
                "fcs above content",
                entry(1001, &raw_block_frame(&[9; 1000], Some(1001), Some(10))),
                "ZstdDecompress",
            ),
            (
                "dictionary id, no dictionary",
                entry(100, &dict),
                "ZstdDecompress",
            ),
            (
                "reserved descriptor bit",
                entry(100, &reserved),
                "ZstdDecompress",
            ),
        ];
        for (case, payload, want) in cases {
            let got = decode(case, &payload);
            assert_eq!(class(&got), want, "{case}: {got:?}");
            if want == "ok" {
                let expect: &[u8] = if case.contains("raw blocks") {
                    b"abc"
                } else {
                    &content
                };
                assert_eq!(got.unwrap(), expect, "{case}");
            }
        }
    }

    /// Setting a `Symbol_Compression_Modes` reserved bit can leave the
    /// decoded bytes unchanged. The block walker rejects the frame anyway.
    #[test]
    fn rejects_reserved_sequence_mode_bits() {
        let content = b"sequence modes reserved bits. ".repeat(50);
        let frame = compress_with(&content, &[]);
        assert!(check_zstd_frame_bounds(&frame).is_ok());
        let mut hits = 0;
        for i in 0..frame.len() {
            let mut f = frame.clone();
            f[i] |= 1;
            if check_zstd_frame_bounds(&f)
                != Err("zstd sequences section has its reserved mode bits set")
            {
                continue;
            }
            hits += 1;
            let r = decode(&format!("mode byte {i}"), &entry(content.len(), &f));
            assert_eq!(class(&r), "ZstdDecompress", "{r:?}");
        }
        assert!(hits >= 1, "the frame's sequences section was never hit");
    }

    /// The decoder enforces the 8 MiB window and the RFC block maximum.
    #[test]
    fn enforces_window_and_block_limits() {
        for (case, content, window_log, accepted) in [
            ("window at limit", vec![5u8; 1024], 23, true),
            ("window above limit", vec![5u8; 1024], 24, false),
            ("huge window", vec![5u8; 1024], 31, false),
            ("raw block at window", vec![4u8; 1024], 10, true),
            ("raw block over window", vec![4u8; 1025], 10, false),
            (
                "raw block at absolute limit",
                vec![4u8; 128 << 10],
                23,
                true,
            ),
            (
                "multi-block over window total",
                vec![4u8; 256 << 10],
                23,
                true,
            ),
        ] {
            let result = decode(
                case,
                &entry(
                    content.len(),
                    &raw_block_frame(&content, None, Some(window_log)),
                ),
            );
            if accepted {
                assert_eq!(result.unwrap(), content, "{case}");
            } else {
                assert_eq!(class(&result), "ZstdDecompress", "{case}");
            }
        }
        for size in [1024u32, 1025] {
            let mut frame = cat(&[&MAGIC, &[0, 0]]); // 1 KiB window
            frame.extend_from_slice(&((size << 3) | 3).to_le_bytes()[..3]);
            frame.push(b'A');
            let result = decode("RLE block window bound", &entry(size as usize, &frame));
            assert_eq!(
                class(&result),
                if size == 1024 { "ok" } else { "ZstdDecompress" }
            );
        }
    }

    /// The heap-regression attack classes must return the same stable variant.
    #[test]
    fn rejects_oversized_literals_and_block_bodies() {
        let literals_header = ((512u32 << 10) << 4) | 0x0d;
        let mut literals = literals_header.to_le_bytes()[..3].to_vec();
        literals.extend_from_slice(&[b'A', 0]);
        let mut compressed = ((1024u16 << 4) | 4).to_le_bytes().to_vec();
        compressed.extend_from_slice(&[b'A'; 1024]);
        compressed.push(0);
        for (case, kind, size, body, window) in [
            ("oversized literals", 2u32, literals.len(), literals, 0),
            (
                "compressed body over window",
                2,
                compressed.len(),
                compressed,
                0,
            ),
            (
                "raw over 128 KiB",
                0,
                (128 << 10) + 1,
                vec![b'A'; (128 << 10) + 1],
                0x68,
            ),
            ("RLE over 128 KiB", 1, (128 << 10) + 1, vec![b'A'], 0x68),
        ] {
            let mut frame = cat(&[&MAGIC, &[0, window]]);
            let header = (u32::try_from(size).unwrap() << 3) | (kind << 1) | 1;
            frame.extend_from_slice(&header.to_le_bytes()[..3]);
            frame.extend_from_slice(&body);
            assert_eq!(
                class(&decode(case, &entry(1024, &frame))),
                "ZstdDecompress",
                "{case}"
            );
        }
    }
}
