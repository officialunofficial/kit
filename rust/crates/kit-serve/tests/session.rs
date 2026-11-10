//! Frame-level tests of the ssh session, with in-memory frame sources and
//! sinks over a repository in a temp directory.
#![allow(clippy::unwrap_used, clippy::unnecessary_wraps)] // unwrap is the assertion in tests

mod common;

use std::collections::VecDeque;

use common::*;
use kit_core::hash::hash;
use kit_core::protocol::{PackKey, Transport as _, TransportError};
use kit_core::refs::RefWriteCondition;
use kit_rpc::kit::common::v1::RefExpectation;
use kit_rpc::kit::rpc::v1::ErrorCode;
use kit_rpc::kit::rpc::v1::ssh::DownloadPackHeader;
use kit_serve::{
    DOWNLOAD_CHUNK_MAX, FRAME_BUDGET_EXCEEDED, FrameIoError, MAX_BYTES_PER_CONN,
    MAX_FRAMES_PER_CONN, MAX_REF_NAME_BYTES, REF_NAME_OUTSIDE_REFS, ReadFrames, SessionConfig,
    SessionEnd, UploadLimits, frame_byte_estimate, serve_session, upload_limits,
};
use kit_transport_file::FileTransport;

// ------------------------------------------------------------- handshake

#[test]
fn handshake_rejects_non_hello_first_frame() {
    let fx = Fixture::new();
    let mut src = VecSource(VecDeque::from([Ok(frame(list_refs(None)))]));
    let mut sink = VecSink::default();
    let end = fx.serve(&mut src, &mut sink, &SessionConfig::new(SERVER_ID));
    assert_eq!(end, SessionEnd::ProtocolError);
    assert_eq!(sink.frames.len(), 1);
    assert_error(
        &sink.frames[0],
        ErrorCode::InvalidRequest,
        "first frame must be Hello",
    );
}

#[test]
fn handshake_rejects_unsupported_proto() {
    let fx = Fixture::new();
    let unspecified = Some(Body::Hello(Box::default()));
    let mut src = VecSource(VecDeque::from([Ok(frame(unspecified))]));
    let mut sink = VecSink::default();
    let end = fx.serve(&mut src, &mut sink, &SessionConfig::new(SERVER_ID));
    assert_eq!(end, SessionEnd::ProtocolError);
    assert_eq!(sink.frames.len(), 1);
    assert_error(
        &sink.frames[0],
        ErrorCode::InvalidRequest,
        "unsupported proto_version 0",
    );
}

/// An unreadable first frame, even a clean end of stream, gets no frame and
/// ends the session with a protocol error.
#[test]
fn handshake_read_failure_is_silent_protocol_error() {
    let fx = Fixture::new();
    for err in [FrameIoError::Eof, FrameIoError::Malformed] {
        let mut sink = VecSink::default();
        let mut src = VecSource(VecDeque::from([Err(err)]));
        let end = fx.serve(&mut src, &mut sink, &SessionConfig::new(SERVER_ID));
        assert_eq!(end, SessionEnd::ProtocolError);
        assert!(sink.frames.is_empty());
    }
    let mut sink = VecSink {
        fail_after: Some(0),
        ..VecSink::default()
    };
    let end = fx.serve(&mut script([]), &mut sink, &SessionConfig::new(SERVER_ID));
    assert_eq!(end, SessionEnd::ProtocolError, "HelloResponse write failed");
}

#[test]
fn stop_after_hello_ends_clean() {
    let fx = Fixture::new();
    let mut cfg = SessionConfig::new(SERVER_ID);
    cfg.stop_after_hello = true;
    let mut sink = VecSink::default();
    let end = fx.serve(&mut script([list_refs(None)]), &mut sink, &cfg);
    assert_eq!(end, SessionEnd::Clean);
    assert_eq!(sink.frames.len(), 1, "only the HelloResponse");
    assert!(matches!(sink.frames[0].body, Some(Body::HelloResponse(_))));
}

#[test]
fn close_and_eof_end_clean() {
    let fx = Fixture::new();
    let (end, frames) = fx.run([close(), list_refs(None)]);
    assert_eq!(end, SessionEnd::Clean);
    assert!(frames.is_empty(), "nothing after Close is answered");
    let (end, frames) = fx.run([]);
    assert_eq!(end, SessionEnd::Clean);
    assert!(frames.is_empty());
}

// ------------------------------------------------------ loop and budgets

#[test]
fn malformed_frame_emits_parse_error_and_ends() {
    let fx = Fixture::new();
    for err in [FrameIoError::Malformed, FrameIoError::Io] {
        let mut src = script([]);
        src.0.push_back(Err(err));
        src.0.push_back(Ok(frame(list_refs(None))));
        let mut sink = VecSink::default();
        let end = fx.serve(&mut src, &mut sink, &SessionConfig::new(SERVER_ID));
        assert_eq!(end, SessionEnd::ProtocolError);
        assert_eq!(sink.frames.len(), 2);
        assert_error(
            &sink.frames[1],
            ErrorCode::InvalidRequest,
            "frame parse error",
        );
    }
}

#[test]
fn timeout_from_source_ends_timeout() {
    let fx = Fixture::new();
    // At the handshake.
    let mut sink = VecSink::default();
    let mut src = VecSource(VecDeque::from([Err(FrameIoError::Timeout)]));
    let end = fx.serve(&mut src, &mut sink, &SessionConfig::new(SERVER_ID));
    assert_eq!(end, SessionEnd::Timeout);
    assert!(sink.frames.is_empty());

    // Between verbs: no error frame.
    let mut src = script([list_refs(None)]);
    src.0.push_back(Err(FrameIoError::Timeout));
    let mut sink = VecSink::default();
    let end = fx.serve(&mut src, &mut sink, &SessionConfig::new(SERVER_ID));
    assert_eq!(end, SessionEnd::Timeout);
    assert_eq!(sink.frames.len(), 2, "HelloResponse and ListRefsResponse");

    // Inside an upload: the pack never becomes visible and no temp file stays.
    let (bytes, id) = valid_pack();
    let mut src = script([
        upload_header(&id, Some(bytes.len() as u64)),
        chunk(&id, Some(0), &bytes[..4], false),
    ]);
    src.0.push_back(Err(FrameIoError::Timeout));
    let mut sink = VecSink::default();
    let end = fx.serve(&mut src, &mut sink, &SessionConfig::new(SERVER_ID));
    assert_eq!(end, SessionEnd::Timeout);
    assert_eq!(sink.frames.len(), 1, "only the HelloResponse");
    assert!(!fx.pack_present(id));
    assert!(fx.files().iter().all(|p| !p.starts_with("packs")));
}

#[test]
fn sink_failure_after_handshake_ends_io_error() {
    let fx = Fixture::new();
    let mut sink = VecSink {
        fail_after: Some(1),
        ..VecSink::default()
    };
    let src = &mut script([list_refs(None), list_refs(None)]);
    let end = fx.serve(src, &mut sink, &SessionConfig::new(SERVER_ID));
    assert_eq!(end, SessionEnd::IoError);
    assert_eq!(sink.frames.len(), 1);
}

#[test]
fn frame_budget_exceeded_ends_protocol_error() {
    let fx = Fixture::new();
    let n = MAX_FRAMES_PER_CONN as usize;
    // Empty frames cost no repository call. Each gets "empty frame".
    let (end, frames) = fx.run(core::iter::repeat_n(None, n + 2));
    assert_eq!(end, SessionEnd::ProtocolError);
    assert_eq!(frames.len(), n + 1);
    assert_error(&frames[n - 1], ErrorCode::InvalidRequest, "empty frame");
    assert_error(&frames[n], ErrorCode::InvalidRequest, FRAME_BUDGET_EXCEEDED);
}

/// The requests of a fetch that finds `branches` branches unchanged: one
/// listing, then a packmap read and a pack list node download per branch.
fn unchanged_fetch(branches: usize, node: &[u8]) -> Vec<Option<Body>> {
    let mut bodies = vec![list_refs(Some("refs/heads/"))];
    for _ in 0..branches {
        bodies.push(read_ref("refs/kit/packmap/b"));
        bodies.push(download(Some(node)));
    }
    bodies
}

/// SPEC-TRANSPORT §4.4: an unchanged fetch of 4,999 branches fits one
/// session (9,999 frames); one of 5,000 branches (10,001 frames) is refused
/// with the budget reply, and the session ends.
#[test]
fn the_largest_unchanged_fetch_fits_one_session_and_one_more_branch_does_not() {
    let largest = (MAX_FRAMES_PER_CONN as usize - 1) / 2;
    assert_eq!(largest, 4_999);
    let fx = Fixture::new();
    let (pack, id) = valid_pack();
    fx.seed(&[("refs/kit/packmap/b", id)], &[&pack]);

    let (end, frames) = fx.run(unchanged_fetch(largest, &id));
    assert_eq!(end, SessionEnd::Clean);
    assert!(
        frames
            .iter()
            .all(|f| !matches!(&f.body, Some(Body::Error(_)))),
        "no request of the fetch was refused"
    );

    let (end, frames) = fx.run(unchanged_fetch(largest + 1, &id));
    assert_eq!(end, SessionEnd::ProtocolError);
    let last = frames.last().unwrap();
    assert_error(last, ErrorCode::InvalidRequest, FRAME_BUDGET_EXCEEDED);
    let refused = frames
        .iter()
        .filter(|f| matches!(&f.body, Some(Body::Error(_))))
        .count();
    assert_eq!(refused, 1, "only the frame over the budget is refused");
}

#[test]
fn byte_budget_exceeded_ends_protocol_error() {
    let fx = Fixture::new();
    let header = |total| {
        Some(Body::DownloadPackHeader(Box::new(DownloadPackHeader {
            total_bytes: Some(total),
            ..Default::default()
        })))
    };
    // A header that the client sends is charged its declared size, then
    // refused.
    let half = MAX_BYTES_PER_CONN / 2 + 1;
    let (end, frames) = fx.run([header(half), header(half), list_refs(None)]);
    assert_eq!(end, SessionEnd::ProtocolError);
    assert_eq!(frames.len(), 2);
    assert_error(
        &frames[0],
        ErrorCode::InvalidRequest,
        "unexpected request frame",
    );
    assert_error(
        &frames[1],
        ErrorCode::InvalidRequest,
        "per-connection byte budget exceeded",
    );

    // An upload header is charged before its own size check.
    let (_, id) = valid_pack();
    let (end, frames) = fx.run([upload_header(&id, Some(MAX_BYTES_PER_CONN + 1))]);
    assert_eq!(end, SessionEnd::ProtocolError);
    assert_error(
        &frames[0],
        ErrorCode::InvalidRequest,
        "per-connection byte budget exceeded",
    );
}

#[test]
fn frame_byte_estimate_follows_the_cost_rules() {
    let est = |body| frame_byte_estimate(&frame(body));
    assert_eq!(est(chunk(&[0; 32], Some(0), &[7; 100], false)), 100);
    assert_eq!(est(upload_header(&[0; 32], Some(12_345))), 12_345);
    assert_eq!(est(upload_header(&[0; 32], None)), 0);
    assert_eq!(est(list_refs(None)), 64);
    assert_eq!(est(None), 64);
    assert_eq!(
        upload_limits(),
        UploadLimits {
            max_total_bytes: 1024 * 1024 * 1024,
            max_chunks: 10_000,
        }
    );
}

#[test]
fn misplaced_frames_get_fixed_errors() {
    let fx = Fixture::new();
    let (end, frames) = fx.run([
        chunk(&[1; 32], Some(0), b"x", true),
        hello(),
        None,
        Some(Body::HelloResponse(Box::default())),
        Some(Body::Error(Box::default())),
    ]);
    assert_eq!(end, SessionEnd::Clean);
    let want = [
        "PackChunk arrived without UploadPack header",
        "Hello after handshake",
        "empty frame",
        "unexpected request frame",
        "unexpected request frame",
    ];
    assert_eq!(frames.len(), want.len());
    for (f, message) in frames.iter().zip(want) {
        assert_error(f, ErrorCode::InvalidRequest, message);
    }
}

// ------------------------------------------------------------ simple verbs

#[test]
fn pack_key_from_id_rejects_bad_length_as_invalid_request() {
    let fx = Fixture::new();
    let missing = Some(Body::PackExists(Box::default()));
    let (end, frames) = fx.run([
        exists(&[0; 16]),
        missing,
        download(Some(&[0; 16])),
        download(None),
        exists(&[7; 32]),
    ]);
    assert_eq!(end, SessionEnd::Clean);
    let bad = [
        "pack_id must be 32 bytes",
        "pack_id missing",
        "pack_id must be 32 bytes",
        "pack_id missing",
    ];
    for (f, message) in frames.iter().zip(bad) {
        assert_error(f, ErrorCode::InvalidRequest, message);
    }
    let Some(Body::PackExistsResponse(resp)) = &frames[4].body else {
        panic!("a correct 32-byte id still decodes");
    };
    assert_eq!(resp.exists, Some(false));
}

#[test]
fn update_ref_field_errors_keep_their_messages() {
    let fx = Fixture::new();
    let main = "refs/heads/main";
    let (end, frames) = fx.run([
        update(main, &[1; 5], Some(RefExpectation::Any), None),
        update(main, &[1; 32], None, None),
        update(main, &[1; 32], Some(RefExpectation::Match), None),
        update(main, &[1; 32], Some(RefExpectation::Match), Some(&[2; 31])),
        // `new_id` is checked before the expectation.
        update(main, &[], None, None),
        update(
            "refs/heads/.hidden",
            &[1; 32],
            Some(RefExpectation::Any),
            None,
        ),
    ]);
    assert_eq!(end, SessionEnd::Clean);
    let want = [
        "new_id must be 32 bytes",
        "UpdateRef.expectation is required",
        "MATCH expectation requires a 32-byte expected_id",
        "MATCH expectation requires a 32-byte expected_id",
        "new_id must be 32 bytes",
        "update ref failed",
    ];
    assert_eq!(frames.len(), want.len());
    for (f, message) in frames.iter().zip(want) {
        assert_error(f, ErrorCode::InvalidRequest, message);
    }
}

/// SPEC-TRANSPORT §4.2.1: the ssh wire ignores `expected_id` for `ANY` and
/// `MISSING`.
#[test]
fn any_and_missing_ignore_expected_id() {
    let fx = Fixture::new();
    let (end, frames) = fx.run([
        update(
            "refs/heads/a",
            &[1; 32],
            Some(RefExpectation::Any),
            Some(&[9; 3]),
        ),
        update(
            "refs/heads/b",
            &[1; 32],
            Some(RefExpectation::Missing),
            Some(&[9; 32]),
        ),
        read_ref("refs/heads/b"),
    ]);
    assert_eq!(end, SessionEnd::Clean);
    assert!(matches!(frames[0].body, Some(Body::UpdateRefResponse(_))));
    assert!(matches!(frames[1].body, Some(Body::UpdateRefResponse(_))));
    let Some(Body::ReadRefResponse(resp)) = &frames[2].body else {
        panic!("expected ReadRefResponse");
    };
    assert_eq!(resp.object_id.as_deref(), Some(&[1; 32][..]));
}

#[test]
fn read_and_list_refs() {
    let fx = Fixture::new();
    fx.seed(
        &[("refs/heads/main", [1; 32]), ("refs/tags/v1", [2; 32])],
        &[],
    );
    let (end, frames) = fx.run([
        read_ref("refs/heads/main"),
        read_ref("refs/heads/absent"),
        read_ref("refs/heads/.hidden"),
        list_refs(Some("refs/heads/")),
        list_refs(None),
        list_refs(Some("/bad")),
    ]);
    assert_eq!(end, SessionEnd::Clean);
    let read = |f: &kit_rpc::kit::rpc::v1::ssh::SshFrame| match &f.body {
        Some(Body::ReadRefResponse(r)) => r.object_id.clone(),
        other => panic!("expected ReadRefResponse, got {other:?}"),
    };
    assert_eq!(read(&frames[0]), Some(vec![1; 32]));
    assert_eq!(read(&frames[1]), Some(Vec::new()), "absent is empty");
    assert_error(&frames[2], ErrorCode::Internal, "read ref failed");
    assert_eq!(listed_names(&frames[3]), ["main"]);
    assert_eq!(
        listed_names(&frames[4]),
        ["refs/heads/main", "refs/tags/v1"]
    );
    assert_error(&frames[5], ErrorCode::Internal, "list refs failed");
}

/// Two writers race a create-only update. The loser's reply carries the
/// winner's id in `details` and classifies as a conflict through the shared
/// client mapping.
#[test]
fn cas_conflict_carries_current_id_in_details() {
    let fx = Fixture::new();
    let (winner, loser) = ([0xA1u8; 32], [0xB2u8; 32]);
    let main = "refs/heads/main";
    let (end, frames) = fx.run([
        update(main, &winner, Some(RefExpectation::Missing), None),
        update(main, &loser, Some(RefExpectation::Missing), None),
        read_ref(main),
    ]);
    assert_eq!(end, SessionEnd::Clean);
    assert!(matches!(frames[0].body, Some(Body::UpdateRefResponse(_))));
    let err = error(&frames[1]).clone();
    assert!(err.code.is_some_and(|c| c == ErrorCode::InvalidRequest));
    assert_eq!(err.details.as_deref(), Some(&winner[..]));
    assert!(matches!(
        kit_rpc::map_update_ref_error(err, RefWriteCondition::Missing, "ssh"),
        TransportError::RefConflict
    ));
    let Some(Body::ReadRefResponse(resp)) = &frames[2].body else {
        panic!("expected ReadRefResponse");
    };
    assert_eq!(
        resp.object_id.as_deref(),
        Some(&winner[..]),
        "nothing clobbered"
    );
    let tx = FileTransport::new(fx.root());
    assert_eq!(tx.read_ref(main).unwrap(), Some(winner));
}

#[test]
fn match_conflict_reports_the_current_value() {
    let fx = Fixture::new();
    let (current, stale, next) = ([0x11u8; 32], [0x22u8; 32], [0x33u8; 32]);
    let main = "refs/heads/main";
    fx.seed(&[(main, current)], &[]);
    let (_, frames) = fx.run([
        update(main, &next, Some(RefExpectation::Match), Some(&stale)),
        read_ref(main),
    ]);
    let err = error(&frames[0]);
    assert!(err.code.is_some_and(|c| c == ErrorCode::InvalidRequest));
    assert_eq!(err.details.as_deref(), Some(&current[..]));
    assert_eq!(
        err.message.as_deref(),
        Some("ref update conflict: expectation does not match current ref value")
    );
    let Some(Body::ReadRefResponse(resp)) = &frames[1].body else {
        panic!("expected ReadRefResponse");
    };
    assert_eq!(resp.object_id.as_deref(), Some(&current[..]));
}

/// No current value means empty `details`, so a strict client surfaces the
/// message as a remote error.
#[test]
fn match_conflict_on_an_absent_ref_has_empty_details() {
    let fx = Fixture::new();
    let ghost = "refs/heads/ghost";
    let (_, frames) = fx.run([
        update(
            ghost,
            &[0x44; 32],
            Some(RefExpectation::Match),
            Some(&[0x55; 32]),
        ),
        read_ref(ghost),
    ]);
    let err = error(&frames[0]).clone();
    assert!(err.code.is_some_and(|c| c == ErrorCode::InvalidRequest));
    assert_eq!(err.details.as_deref().map_or(0, <[u8]>::len), 0);
    let mapped = kit_rpc::map_update_ref_error(err, RefWriteCondition::Match([0x55; 32]), "ssh");
    match mapped {
        TransportError::RemoteError(msg) => {
            assert!(msg.contains("absent"), "message should say absent: {msg}");
        }
        other => panic!("expected RemoteError, got {other:?}"),
    }
    let Some(Body::ReadRefResponse(resp)) = &frames[1].body else {
        panic!("expected ReadRefResponse");
    };
    assert_eq!(resp.object_id.as_deref(), Some(&[][..]));
    assert_eq!(FileTransport::new(fx.root()).read_ref(ghost).unwrap(), None);
}

// ---------------------------------------------------------------- uploads

#[test]
fn upload_accepts_valid_chunks() {
    let fx = Fixture::new();
    let (bytes, id) = valid_pack();
    let (end, frames) = fx.run([
        upload_header(&id, Some(bytes.len() as u64)),
        chunk(&id, Some(0), &bytes[..5], false),
        chunk(&id, Some(5), &bytes[5..], true),
        exists(&id),
    ]);
    assert_eq!(end, SessionEnd::Clean);
    assert!(matches!(frames[0].body, Some(Body::UploadPackResponse(_))));
    let Some(Body::PackExistsResponse(resp)) = &frames[1].body else {
        panic!("expected PackExistsResponse");
    };
    assert_eq!(resp.exists, Some(true));
    assert!(fx.pack_present(id));
}

/// Each malformed stream gets its message, stores nothing and leaves the
/// session in frame sync.
#[test]
fn upload_rejects_malformed_streams() {
    let (bytes, id) = valid_pack();
    let len = bytes.len() as u64;
    let wrong = b"wrong pack bytes";
    let cases: Vec<(Vec<Option<Body>>, &str)> = vec![
        (
            vec![upload_header(&id, None)],
            "UploadPack.total_bytes is required",
        ),
        (
            vec![upload_header(&[1; 7], Some(len))],
            "pack_id must be 32 bytes",
        ),
        (
            vec![
                upload_header(&id, Some(len)),
                chunk(&id, Some(1), &bytes, true),
            ],
            "PackChunk.offset is not the expected next offset",
        ),
        (
            vec![
                upload_header(&id, Some(len)),
                chunk(&id, None, &bytes, true),
            ],
            "PackChunk.offset is required",
        ),
        (
            vec![
                upload_header(&id, Some(len)),
                chunk(&[0xAA; 32], Some(0), &bytes, true),
            ],
            "PackChunk.pack_id does not match UploadPack",
        ),
        (
            vec![
                upload_header(&id, Some(len - 1)),
                chunk(&id, Some(0), &bytes, true),
            ],
            "PackChunk data exceeds declared total_bytes",
        ),
        (
            vec![
                upload_header(&id, Some(len)),
                chunk(&id, Some(0), &bytes[..bytes.len() - 1], true),
            ],
            "PackChunk stream ended before declared total_bytes",
        ),
        (
            vec![
                upload_header(&id, Some(wrong.len() as u64)),
                chunk(&id, Some(0), wrong, true),
            ],
            "uploaded pack bytes do not match UploadPack.pack_id",
        ),
        (
            vec![upload_header(&id, Some(len)), list_refs(None)],
            "expected PackChunk after UploadPack",
        ),
        (
            vec![upload_header(&id, Some(len))],
            "pack chunk read failed",
        ),
    ];
    for (bodies, message) in cases {
        let fx = Fixture::new();
        let mut bodies = bodies;
        let eof = bodies.len() == 1 && message == "pack chunk read failed";
        if !eof {
            bodies.push(exists(&id));
        }
        let (end, frames) = fx.run(bodies);
        assert_eq!(end, SessionEnd::Clean, "{message}");
        assert_error(&frames[0], ErrorCode::InvalidRequest, message);
        assert!(!fx.pack_present(id), "{message}: nothing stored");
        assert!(
            fx.files().iter().all(|p| !p.starts_with("packs")),
            "{message}: no temp file left"
        );
        if !eof {
            assert!(
                matches!(frames[1].body, Some(Body::PackExistsResponse(_))),
                "{message}"
            );
        }
    }
}

/// An oversized header trips the byte budget before the upload cap.
#[test]
fn declared_size_over_the_cap() {
    let fx = Fixture::new();
    let (_, id) = valid_pack();
    let (end, frames) = fx.run([upload_header(&id, Some(MAX_BYTES_PER_CONN + 1))]);
    assert_eq!(end, SessionEnd::ProtocolError);
    assert_error(
        &frames[0],
        ErrorCode::InvalidRequest,
        "per-connection byte budget exceeded",
    );
}

fn one_byte_chunks(data: &[u8], upto: usize) -> Vec<Option<Body>> {
    let id = hash(data);
    let mut bodies = vec![upload_header(&id, Some(data.len() as u64))];
    for i in 0..upto {
        bodies.push(chunk(
            &id,
            Some(i as u64),
            &data[i..=i],
            i + 1 == data.len(),
        ));
    }
    bodies
}

#[test]
fn too_many_chunks_is_rejected() {
    let fx = Fixture::new();
    let n = MAX_FRAMES_PER_CONN as usize;
    let data = pack_bytes(n + 1, 3);
    let id = hash(&data);
    let (end, frames) = fx.run(one_byte_chunks(&data, n + 1));
    assert_eq!(end, SessionEnd::Clean);
    assert_eq!(frames.len(), 1);
    assert_error(
        &frames[0],
        ErrorCode::InvalidRequest,
        "too many PackChunk frames before last=true",
    );
    assert!(!fx.pack_present(id));
}

#[test]
fn an_upload_at_the_chunk_cap_goes_through() {
    let fx = Fixture::new();
    let n = MAX_FRAMES_PER_CONN as usize;
    let data = pack_bytes(n, 4);
    let (_, frames) = fx.run(one_byte_chunks(&data, n));
    assert!(matches!(frames[0].body, Some(Body::UploadPackResponse(_))));
    assert!(fx.pack_present(hash(&data)));
}

/// SPEC-REFS §3: a name over 512 bytes is refused by name on reads and
/// writes.
#[test]
fn over_long_ref_names_are_refused_by_name() {
    let fx = Fixture::new();
    // The longest legal name, in components that a file name can hold.
    let longest = format!(
        "refs/heads/{}/{}/{}",
        "a".repeat(200),
        "a".repeat(200),
        "a".repeat(99)
    );
    assert_eq!(longest.len(), MAX_REF_NAME_BYTES);
    let over = format!("{longest}a");
    let (end, frames) = fx.run([
        update(&over, &[1; 32], Some(RefExpectation::Any), None),
        read_ref(&over),
        // Field errors still come first.
        update(&over, &[1; 5], Some(RefExpectation::Any), None),
        update(&longest, &[1; 32], Some(RefExpectation::Any), None),
        read_ref(&longest),
        list_refs(Some(&over)),
    ]);
    assert_eq!(end, SessionEnd::Clean);
    assert_error(&frames[0], ErrorCode::InvalidRequest, "ref name too long");
    assert_error(&frames[1], ErrorCode::InvalidRequest, "ref name too long");
    assert_error(
        &frames[2],
        ErrorCode::InvalidRequest,
        "new_id must be 32 bytes",
    );
    assert!(matches!(frames[3].body, Some(Body::UpdateRefResponse(_))));
    let Some(Body::ReadRefResponse(resp)) = &frames[4].body else {
        panic!("expected ReadRefResponse");
    };
    assert_eq!(resp.object_id.as_deref(), Some(&[1; 32][..]));
    assert_error(&frames[5], ErrorCode::Internal, "list refs failed");
}

/// SPEC-REFS §2: a valid name outside `refs/` is refused by name on reads
/// and writes. A name that fails the grammar keeps its generic reply. A
/// listing is not restricted, and it finds nothing outside `refs/`.
#[test]
fn ref_names_outside_refs_are_refused_by_name() {
    let fx = Fixture::new();
    let (end, frames) = fx.run([
        update("main", &[1; 32], Some(RefExpectation::Any), None),
        read_ref("main"),
        update("packs/x", &[1; 32], Some(RefExpectation::Missing), None),
        read_ref("heads/main"),
        // Field errors still come first.
        update("main", &[1; 5], Some(RefExpectation::Any), None),
        // Grammar failures.
        read_ref(".main"),
        update(".main", &[1; 32], Some(RefExpectation::Any), None),
        list_refs(Some("heads/")),
    ]);
    assert_eq!(end, SessionEnd::Clean);
    for f in &frames[..4] {
        assert_error(f, ErrorCode::InvalidRequest, REF_NAME_OUTSIDE_REFS);
    }
    assert_error(
        &frames[4],
        ErrorCode::InvalidRequest,
        "new_id must be 32 bytes",
    );
    assert_error(&frames[5], ErrorCode::Internal, "read ref failed");
    assert_error(&frames[6], ErrorCode::InvalidRequest, "update ref failed");
    assert!(listed_names(&frames[7]).is_empty());
    assert!(
        fx.files()
            .iter()
            .all(|p| p.starts_with(".kit") || p.starts_with("refs"))
    );
}

/// SPEC-REFS §4: prefixes match at component boundaries.
#[test]
fn list_refs_prefixes_match_at_component_boundaries() {
    let fx = Fixture::new();
    fx.seed(
        &[
            ("refs/heads/feat/x", [1; 32]),
            ("refs/heads/featx", [2; 32]),
            ("refs/heads/main", [3; 32]),
        ],
        &[],
    );
    let prefixes = [
        "refs/heads",
        "refs/heads/",
        "refs/heads/feat",
        "refs/heads/ma",
        "refs/heads/main",
        "refs//",
    ];
    let (_, frames) = fx.run(prefixes.map(|p| list_refs(Some(p))));
    let names: Vec<Vec<String>> = frames.iter().map(listed_names).collect();
    let heads = ["feat/x", "featx", "main"].map(String::from).to_vec();
    assert_eq!(names[0], heads);
    assert_eq!(names[1], heads);
    assert_eq!(names[2], ["x"]);
    assert!(names[3].is_empty());
    // A ref named exactly the prefix is not listed.
    assert!(names[4].is_empty());
    assert_eq!(names[5], ["heads/feat/x", "heads/featx", "heads/main"]);
}

/// A stray file under `refs/` is skipped by every listing. A read of its
/// exact name is a storage failure, because reads are strict.
#[test]
fn stray_file_under_refs_is_skipped_by_listings() {
    let fx = Fixture::new();
    let tx = FileTransport::new(fx.root());
    tx.update_ref("refs/heads/main", RefWriteCondition::Any, &[0x11; 32])
        .unwrap();
    std::fs::write(fx.root().join("refs/heads/README"), b"not a ref\n").unwrap();
    let (end, frames) = fx.run([
        list_refs(Some("refs/heads/")),
        list_refs(Some("refs/tags/")),
        list_refs(None),
        read_ref("refs/heads/README"),
        update(
            "refs/heads/main",
            &[0x12; 32],
            Some(RefExpectation::Match),
            Some(&[0x11; 32]),
        ),
    ]);
    assert_eq!(end, SessionEnd::Clean);
    assert_eq!(listed_names(&frames[0]), ["main"]);
    assert!(listed_names(&frames[1]).is_empty());
    assert_eq!(listed_names(&frames[2]), ["refs/heads/main"]);
    assert_error(&frames[3], ErrorCode::Internal, "read ref failed");
    assert!(matches!(frames[4].body, Some(Body::UpdateRefResponse(_))));
}

/// A storage failure answers `upload failed` only once the stream has been
/// read to its `last` chunk, so the session stays in frame sync.
#[test]
fn storage_failure_drains_then_answers_upload_failed() {
    let fx = Fixture::new();
    // A file where the pack directory belongs: no upload can start.
    std::fs::write(fx.root().join("packs"), b"in the way").unwrap();
    let data = pack_bytes(3_000, 5);
    let id = hash(&data);
    let (end, frames) = fx.run([
        upload_header(&id, Some(data.len() as u64)),
        chunk(&id, Some(0), &data[..1_000], false),
        chunk(&id, Some(1_000), &data[1_000..2_000], false),
        chunk(&id, Some(2_000), &data[2_000..], true),
        exists(&id),
    ]);
    assert_eq!(end, SessionEnd::Clean);
    assert_eq!(frames.len(), 2);
    assert_error(&frames[0], ErrorCode::Internal, "upload failed");
    let Some(Body::PackExistsResponse(resp)) = &frames[1].body else {
        panic!("expected PackExistsResponse");
    };
    assert_eq!(resp.exists, Some(false));
}

#[test]
fn invalid_upload_is_rejected_before_storage() {
    let fx = Fixture::new();
    let bogus = [0x77; 32];
    let (end, frames) = fx.run([
        upload_header(&bogus, Some(5)),
        chunk(&bogus, Some(0), b"wrong", true),
    ]);
    assert_eq!(end, SessionEnd::Clean);
    assert_error(
        &frames[0],
        ErrorCode::InvalidRequest,
        "uploaded pack bytes do not match UploadPack.pack_id",
    );
    assert!(
        !FileTransport::new(fx.root())
            .pack_exists(&PackKey::new(bogus))
            .unwrap()
    );
    assert!(
        fx.files().iter().all(|p| !p.starts_with("packs")),
        "no pack or temp file left: {:?}",
        fx.files()
    );
}

#[test]
fn rejected_upload_does_not_overwrite_an_existing_pack() {
    let fx = Fixture::new();
    let (bytes, id) = valid_pack();
    FileTransport::new(fx.root())
        .upload_pack(&bytes, &PackKey::new(id))
        .unwrap();
    let (end, frames) = fx.run([
        upload_header(&id, Some(5)),
        chunk(&id, Some(0), b"wrong", true),
        download(Some(&id)),
    ]);
    assert_eq!(end, SessionEnd::Clean);
    assert!(matches!(frames[0].body, Some(Body::Error(_))));
    assert_eq!(downloaded(&frames[1..], &id), bytes);
}

/// The session writes the pack and ref files and nothing else: no replay or
/// quota rows and no temp files, after uploads (good and bad) and ref
/// writes.
#[test]
fn session_writes_only_packs_and_refs() {
    let fx = Fixture::new();
    let (bytes, id) = valid_pack();
    fx.seed(&[("refs/heads/main", [1; 32])], &[&bytes]);
    let (_, frames) = fx.run([
        upload_header(&id, Some(5)),
        chunk(&id, Some(0), b"wrong", true),
        download(Some(&id)),
    ]);
    assert_eq!(downloaded(&frames[1..], &id), bytes);
    let hex = kit_core::hash::to_hex(&id);
    assert_eq!(
        fx.files(),
        [
            // The repo lock and the lock of the stripe that holds
            // `refs/heads/main`.
            std::path::PathBuf::from(".kit/refs/.lock"),
            std::path::PathBuf::from(".kit/refs/refs-ec.lock"),
            std::path::PathBuf::from("packs").join(hex),
            std::path::PathBuf::from("refs/heads/main"),
        ],
    );
}

// -------------------------------------------------------------- downloads

#[test]
fn download_emits_header_then_contiguous_chunks_last() {
    let fx = Fixture::new();
    let max = DOWNLOAD_CHUNK_MAX;
    let big = pack_bytes(2 * max + 123, 11);
    let id = hash(&big);
    fx.seed(&[], &[&big, b""]);
    let (end, frames) = fx.run([download(Some(&id))]);
    assert_eq!(end, SessionEnd::Clean);
    assert_eq!(frames.len(), 4, "a header and three chunks");
    let chunks: Vec<(u64, usize)> = frames[1..]
        .iter()
        .map(|f| match &f.body {
            Some(Body::PackChunk(c)) => (c.offset.unwrap(), c.data.as_ref().unwrap().len()),
            _ => panic!("chunk"),
        })
        .collect();
    let max64 = max as u64;
    assert_eq!(chunks, [(0, max), (max64, max), (2 * max64, 123)]);
    assert_eq!(downloaded(&frames, &id), big);

    // The empty pack: one empty `last` chunk.
    let empty = hash(b"");
    let (_, frames) = fx.run([download(Some(&empty))]);
    assert_eq!(frames.len(), 2);
    assert!(downloaded(&frames, &empty).is_empty());

    // A missing pack.
    let (_, frames) = fx.run([download(Some(&[9; 32]))]);
    assert_error(&frames[0], ErrorCode::KeyNotFound, "pack not found");
}

/// A read that fails after the header is answered `pack read failed`, and
/// the session goes on.
#[test]
fn download_read_failure_after_header_is_internal() {
    let fx = Fixture::new();
    let data = pack_bytes(10_000, 2);
    let id = hash(&data);
    fx.seed(&[], &[&data]);
    let path = fx.root().join("packs").join(kit_core::hash::to_hex(&id));
    let mut sink = VecSink {
        // Cut the pack short once the header is out.
        after_send: Some(Box::new(move |sent| {
            if sent == 2 {
                std::fs::write(&path, b"abc").unwrap();
            }
        })),
        ..VecSink::default()
    };
    let end = fx.serve(
        &mut script([download(Some(&id)), list_refs(None)]),
        &mut sink,
        &SessionConfig::new(SERVER_ID),
    );
    assert_eq!(end, SessionEnd::Clean);
    let frames = &sink.frames[1..];
    let Some(Body::DownloadPackHeader(h)) = &frames[0].body else {
        panic!("expected DownloadPackHeader");
    };
    assert_eq!(h.total_bytes, Some(10_000));
    assert_error(&frames[1], ErrorCode::Internal, "pack read failed");
    assert!(matches!(frames[2].body, Some(Body::ListRefsResponse(_))));
}

// ----------------------------------------------------------------- framing

/// `ReadFrames` maps framing errors: a truncated length prefix is a clean
/// end of stream. Anything else that is unreadable is malformed.
#[test]
fn read_frames_maps_framing_errors() {
    use kit_serve::FrameSource as _;
    let next = |bytes: Vec<u8>| ReadFrames(std::io::Cursor::new(bytes)).next_frame();
    assert!(matches!(next(Vec::new()), Err(FrameIoError::Eof)));
    assert!(matches!(next(vec![1, 0]), Err(FrameIoError::Eof)));
    let too_long = (kit_rpc::MAX_FRAME_BYTES + 1).to_le_bytes().to_vec();
    assert!(matches!(next(too_long), Err(FrameIoError::Malformed)));
    assert!(matches!(
        next(vec![5, 0, 0, 0, 1]),
        Err(FrameIoError::Malformed)
    ));
    assert!(matches!(
        next(vec![1, 0, 0, 0, 0xff]),
        Err(FrameIoError::Malformed)
    ));

    // Over the byte stream: a garbage frame after `Hello` is answered
    // "frame parse error" and ends the session.
    let fx = Fixture::new();
    let mut input = Vec::new();
    kit_rpc::write_frame(&mut input, &frame(hello())).unwrap();
    input.extend_from_slice(&[1, 0, 0, 0, 0xff]);
    let mut src = ReadFrames(std::io::Cursor::new(input));
    let mut sink = VecSink::default();
    let cfg = SessionConfig::new(SERVER_ID);
    let end = serve_session(&fx.repo, None, &mut src, &mut sink, &cfg);
    assert_eq!(end, SessionEnd::ProtocolError);
    assert_error(
        &sink.frames[1],
        ErrorCode::InvalidRequest,
        "frame parse error",
    );
}
