#![allow(clippy::doc_markdown, clippy::needless_raw_string_hashes)]
//! Transport-level integration tests against a mockito HTTP server.
//!
//! Every verb + CAS path + retry behaviour is exercised here. These
//! tests never hit the real network: mockito spins up an in-process
//! HTTP server on a random port, and we point `S3Transport` at it via
//! `with_parts`. Credentials are stubbed.
//!
//! SigV4 byte-parity is covered by `sigv4_golden.rs` — this file
//! focuses on the status-code → [`TransportError`] mapping and retry
//! loop correctness.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use kit_core::hash::{Hash, to_hex};
use kit_core::protocol::{
    BackoffIterator, PACK_BODY_LIMIT, PackBody, PackKey, PackSink, Transport, TransportError,
};
use kit_core::refs::RefWriteCondition;
use kit_transport_s3::S3Transport;
use kit_transport_s3::sigv4::Credentials;

fn demo_creds() -> Credentials {
    Credentials {
        access_key_id: "AKIA_TEST".into(),
        secret_access_key: "secret".into(),
        region: "us-east-1".into(),
    }
}

fn fixed_clock() -> i64 {
    // Any fixed value works — the server does not verify signatures.
    1_711_300_000
}

fn fast_backoff() -> BackoffIterator {
    BackoffIterator::with(Duration::from_millis(1), Duration::from_millis(1), 5)
}

fn noop_sleep(_: Duration) {}

fn sample_hash() -> Hash {
    [0x42u8; 32]
}

fn sample_key() -> PackKey {
    PackKey::new(sample_hash())
}

fn build_transport(endpoint: &str) -> S3Transport {
    let mut t = S3Transport::with_parts(endpoint, "bucket", None, demo_creds())
        .expect("construct transport");
    t.set_clock(fixed_clock);
    t.set_sleeper(noop_sleep);
    t.set_backoff(fast_backoff);
    t
}

fn build_transport_with_prefix(endpoint: &str, prefix: &str) -> S3Transport {
    let mut t = S3Transport::with_parts(endpoint, "bucket", Some(prefix.to_owned()), demo_creds())
        .expect("construct transport");
    t.set_clock(fixed_clock);
    t.set_sleeper(noop_sleep);
    t.set_backoff(fast_backoff);
    t
}

// -- deletes -----------------------------------------------------------------

/// Every delete is refused, a head alone or a head with its chain ref, and
/// no request reaches the store.
#[test]
fn every_delete_is_refused_before_any_request() {
    let mut server = mockito::Server::new();
    let none: Vec<_> = ["GET", "HEAD", "PUT", "POST", "DELETE"]
        .into_iter()
        .map(|method| {
            server
                .mock(method, mockito::Matcher::Any)
                .expect(0)
                .create()
        })
        .collect();
    let t = build_transport(&server.url());
    let refused = |e: TransportError| matches!(e, TransportError::Unsupported(m) if m == kit_transport_s3::S3_DELETE_REFUSED);
    assert!(refused(
        t.delete_ref("refs/heads/main", &sample_hash()).unwrap_err()
    ));
    for map in [Some(&sample_hash()), None] {
        assert!(refused(
            t.delete_refs("refs/tags/v1", &sample_hash(), "refs/kit/tagmap/v1", map,)
                .unwrap_err()
        ));
    }
    for mock in none {
        mock.assert();
    }
}

// -- uploadPack --------------------------------------------------------------

#[test]
fn upload_pack_200_ok() {
    let mut server = mockito::Server::new();
    let m = server
        .mock("PUT", mockito::Matcher::Any)
        .with_status(200)
        .create();
    let t = build_transport(&server.url());
    t.upload_pack(
        &kit_core::protocol::SliceBody(b"pack-bytes"),
        &sample_key(),
        None,
    )
    .unwrap();
    m.assert();
}

#[test]
fn upload_pack_uses_url_prefix_namespace() {
    let mut server = mockito::Server::new();
    let hex = to_hex(sample_key().as_bytes());
    let m = server
        .mock("PUT", format!("/bucket/repo-a/packs/{hex}").as_str())
        .with_status(200)
        .create();
    let t = build_transport_with_prefix(&server.url(), "repo-a");
    t.upload_pack(
        &kit_core::protocol::SliceBody(b"pack-bytes"),
        &sample_key(),
        None,
    )
    .unwrap();
    m.assert();
}

#[test]
fn upload_pack_201_created() {
    let mut server = mockito::Server::new();
    let m = server
        .mock("PUT", mockito::Matcher::Any)
        .with_status(201)
        .create();
    let t = build_transport(&server.url());
    t.upload_pack(&kit_core::protocol::SliceBody(b"x"), &sample_key(), None)
        .unwrap();
    m.assert();
}

#[test]
fn upload_pack_403_access_denied() {
    let mut server = mockito::Server::new();
    let _m = server
        .mock("PUT", mockito::Matcher::Any)
        .with_status(403)
        .create();
    let t = build_transport(&server.url());
    assert!(matches!(
        t.upload_pack(&kit_core::protocol::SliceBody(b"x"), &sample_key(), None),
        Err(TransportError::AccessDenied)
    ));
}

#[test]
fn upload_pack_5xx_retries_then_fails() {
    // mockito lets us install multiple matching expectations; without
    // `expect()` each mock is by default fulfilled exactly once, so
    // stacking five 500s simulates the exhausted-retry case.
    let mut server = mockito::Server::new();
    let _m = server
        .mock("PUT", mockito::Matcher::Any)
        .with_status(500)
        .expect(6) // initial attempt + 5 retries
        .create();
    let t = build_transport(&server.url());
    match t.upload_pack(&kit_core::protocol::SliceBody(b"x"), &sample_key(), None) {
        Err(TransportError::ServerError { status: 500 }) => {}
        other => panic!("expected ServerError 500, got {other:?}"),
    }
}

#[test]
fn upload_pack_5xx_then_200_succeeds() {
    let mut server = mockito::Server::new();
    let _m_fail = server
        .mock("PUT", mockito::Matcher::Any)
        .with_status(503)
        .create();
    let _m_ok = server
        .mock("PUT", mockito::Matcher::Any)
        .with_status(200)
        .create();
    let t = build_transport(&server.url());
    t.upload_pack(&kit_core::protocol::SliceBody(b"x"), &sample_key(), None)
        .unwrap();
}

/// A body over `PACK_BODY_LIMIT` is refused before any byte of it is read
/// and before any request.
#[test]
fn upload_pack_refuses_a_body_over_the_limit_before_reading_it() {
    let server = mockito::Server::new();
    let t = build_transport(&server.url());
    let body = Recorded::new(Vec::new()).claiming(PACK_BODY_LIMIT + 1);
    assert!(matches!(
        t.upload_pack(&body, &sample_key(), None),
        Err(TransportError::PayloadTooLarge(_))
    ));
    assert!(body.reads().is_empty());
}

/// The request is signed over the SHA-256 of exactly the bytes it streams,
/// with their length as `Content-Length`. The body spans several chunks.
#[test]
fn upload_pack_signs_the_sha256_of_the_streamed_bytes() {
    let bytes = pattern(600 * 1024 + 7);
    let mut server = mockito::Server::new();
    let m = server
        .mock("PUT", mockito::Matcher::Any)
        .match_header("x-amz-content-sha256", sha256_hex(&bytes).as_str())
        .match_header("content-length", bytes.len().to_string().as_str())
        .match_body(bytes.clone())
        .with_status(200)
        .create();
    let t = build_transport(&server.url());
    let body = Recorded::new(bytes);
    t.upload_pack(&body, &sample_key(), None).unwrap();
    m.assert();
    assert_eq!(body.reads(), [0, 0], "one hash pass, then one send");
}

/// A retried `PUT` reads the body again from offset 0 and sends the same
/// bytes under the same payload hash.
#[test]
fn upload_pack_retry_sends_the_body_again_from_offset_zero() {
    let bytes = pattern(300 * 1024);
    let mut server = mockito::Server::new();
    let failed = server
        .mock("PUT", mockito::Matcher::Any)
        .match_header("x-amz-content-sha256", sha256_hex(&bytes).as_str())
        .match_body(bytes.clone())
        .with_status(503)
        .create();
    let ok = server
        .mock("PUT", mockito::Matcher::Any)
        .match_header("x-amz-content-sha256", sha256_hex(&bytes).as_str())
        .match_body(bytes.clone())
        .with_status(200)
        .create();
    let t = build_transport(&server.url());
    let body = Recorded::new(bytes);
    t.upload_pack(&body, &sample_key(), None).unwrap();
    failed.assert();
    ok.assert();
    assert_eq!(body.reads(), [0, 0, 0], "a hash pass, then one per attempt");
}

/// A body that holds fewer bytes than its length is refused by the hash
/// pass, before any request.
#[test]
fn upload_pack_refuses_a_short_body_before_any_request() {
    let mut server = mockito::Server::new();
    let m = server
        .mock("PUT", mockito::Matcher::Any)
        .with_status(200)
        .expect(0)
        .create();
    let t = build_transport(&server.url());
    let body = Recorded::new(pattern(10)).claiming(11);
    assert!(matches!(
        t.upload_pack(&body, &sample_key(), None),
        Err(TransportError::ProtocolError)
    ));
    m.assert();
}

/// A body that ends early while it is sent is a local error: the request
/// ends and is not retried.
#[test]
fn upload_pack_body_cut_while_sending_is_not_retried() {
    let mut server = mockito::Server::new();
    let m = server
        .mock("PUT", mockito::Matcher::Any)
        .with_status(200)
        .expect_at_most(1)
        .create();
    let t = build_transport(&server.url());
    let body = Recorded::new(pattern(700 * 1024)).cut_after_first_read(400 * 1024);
    assert!(matches!(
        t.upload_pack(&body, &sample_key(), None),
        Err(TransportError::ProtocolError)
    ));
    assert_eq!(body.reads(), [0, 0], "the hash pass and one send, no retry");
    m.assert();
}

// -- downloadPack ------------------------------------------------------------

#[test]
fn download_pack_200_returns_body() {
    let mut server = mockito::Server::new();
    let _m = server
        .mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body(b"pack-body")
        .create();
    let t = build_transport(&server.url());
    let got = t.download_blob(&sample_key(), None, u64::MAX).unwrap();
    assert_eq!(got, b"pack-body");
}

/// A blob longer than the caller's bound is refused at its declared length.
#[test]
fn download_blob_refuses_a_body_over_its_bound() {
    let mut server = mockito::Server::new();
    let _m = server
        .mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body(vec![7u8; 4096])
        .create();
    let t = build_transport(&server.url());
    assert!(matches!(
        t.download_blob(&sample_key(), None, 100),
        Err(TransportError::PayloadTooLarge(4096))
    ));
    assert_eq!(
        t.download_blob(&sample_key(), None, 4096).unwrap().len(),
        4096
    );
}

#[test]
fn download_pack_404_pack_not_found() {
    let mut server = mockito::Server::new();
    let _m = server
        .mock("GET", mockito::Matcher::Any)
        .with_status(404)
        .create();
    let t = build_transport(&server.url());
    assert!(matches!(
        t.download_blob(&sample_key(), None, u64::MAX),
        Err(TransportError::PackNotFound)
    ));
}

#[test]
fn download_pack_403_access_denied() {
    let mut server = mockito::Server::new();
    let _m = server
        .mock("GET", mockito::Matcher::Any)
        .with_status(403)
        .create();
    let t = build_transport(&server.url());
    assert!(matches!(
        t.download_blob(&sample_key(), None, u64::MAX),
        Err(TransportError::AccessDenied)
    ));
}

/// A `200` body reaches the sink with its length declared first, a chunk
/// at a time.
#[test]
fn download_pack_streams_a_200_body_into_the_sink() {
    let bytes = pattern(700 * 1024 + 3);
    let mut server = mockito::Server::new();
    let _m = server
        .mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body(bytes.clone())
        .create();
    let t = build_transport(&server.url());
    let mut sink = Sink::new(u64::MAX);
    t.download_pack(&sample_key(), None, &mut sink).unwrap();
    assert_eq!(sink.begins, [Some(bytes.len() as u64)]);
    assert!(sink.writes > 1, "{} writes", sink.writes);
    assert_eq!(sink.bytes, bytes);
}

/// No error answer's body reaches the sink, whether the error is final or
/// retried.
#[test]
fn download_pack_error_bodies_never_reach_the_sink() {
    for (status, expected) in [(404, 1), (403, 1), (400, 1), (500, 6), (503, 6)] {
        let mut server = mockito::Server::new();
        let m = server
            .mock("GET", mockito::Matcher::Any)
            .with_status(status)
            .with_body(vec![b'e'; 64 * 1024])
            .expect(expected)
            .create();
        let t = build_transport(&server.url());
        let mut sink = Sink::new(u64::MAX);
        let result = t.download_pack(&sample_key(), None, &mut sink);
        assert!(result.is_err(), "{status}: {result:?}");
        m.assert();
        assert!(sink.begins.is_empty(), "{status}: {:?}", sink.begins);
        assert_eq!(sink.writes, 0, "{status}");
    }
}

/// A declared length over the sink's limit is refused before any byte is
/// written.
#[test]
fn download_pack_refuses_a_declared_length_over_the_limit_before_any_write() {
    let mut server = mockito::Server::new();
    let _m = server
        .mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body(vec![7u8; 4096])
        .create();
    let t = build_transport(&server.url());
    let mut sink = Sink::new(4095);
    assert!(matches!(
        t.download_pack(&sample_key(), None, &mut sink),
        Err(TransportError::PayloadTooLarge(4096))
    ));
    assert_eq!(sink.begins, [Some(4096)]);
    assert_eq!(sink.writes, 0);
}

/// A `200` that declares a body over [`PACK_BODY_LIMIT`] is refused before
/// the sink begins, whatever the sink's own limit.
#[test]
fn download_pack_refuses_a_declared_length_over_the_body_limit_before_begin() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let answers = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut head = [0u8; 1024];
        let _ = std::io::Read::read(&mut stream, &mut head);
        let answer = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
            PACK_BODY_LIMIT + 1
        );
        // The client may close first; a failed write is fine.
        let _ = std::io::Write::write_all(&mut stream, answer.as_bytes());
        let _ = std::io::Write::write_all(&mut stream, &[7u8; 4096]);
    });
    let t = build_transport(&endpoint);
    let mut sink = Sink::new(u64::MAX);
    assert!(matches!(
        t.download_pack(&sample_key(), None, &mut sink),
        Err(TransportError::PayloadTooLarge(_))
    ));
    answers.join().unwrap();
    assert!(sink.begins.is_empty(), "{:?}", sink.begins);
    assert_eq!(sink.writes, 0);
}

/// A `200` whose body is cut part way is retried, and the retry begins the
/// sink again, so the sink ends with the whole body only.
#[test]
fn download_pack_cut_mid_body_begins_the_sink_again() {
    let bytes = pattern(600 * 1024);
    let mut server = mockito::Server::new();
    let half = bytes[..300 * 1024].to_vec();
    let cut = server
        .mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_chunked_body(move |w| {
            w.write_all(&half)?;
            Err(std::io::Error::other("cut"))
        })
        .expect(1)
        .create();
    let whole = server
        .mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body(bytes.clone())
        .expect(1)
        .create();
    let t = build_transport(&server.url());
    let mut sink = Sink::new(u64::MAX);
    t.download_pack(&sample_key(), None, &mut sink).unwrap();
    cut.assert();
    whole.assert();
    assert_eq!(sink.begins, [None, Some(bytes.len() as u64)]);
    assert_eq!(sink.bytes, bytes);
}

/// A store that drops every connection after the request headers ends the
/// upload as a connection failure after the retries. Each attempt reads
/// the body again from offset 0, and none hangs on the thread that reads
/// it.
#[test]
fn upload_pack_to_a_store_that_drops_the_connection_ends_after_the_retries() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let accepts = std::thread::spawn(move || {
        let mut connections = 0;
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let mut head = [0u8; 1024];
            let _ = std::io::Read::read(&mut stream, &mut head);
            drop(stream);
            connections += 1;
            if connections == 6 {
                return connections;
            }
        }
        connections
    });
    let t = build_transport(&endpoint);
    let body = Recorded::new(pattern(2 * 1024 * 1024));
    assert!(matches!(
        t.upload_pack(&body, &sample_key(), None),
        Err(TransportError::ConnectionFailed)
    ));
    assert_eq!(accepts.join().unwrap(), 6, "the attempt and 5 retries");
    assert_eq!(body.reads(), [0; 7], "the hash pass, then one per attempt");
}

/// A sink that failed on a local write ends the download with an error no
/// retry takes.
#[test]
fn download_pack_sink_failure_is_not_retried() {
    let mut server = mockito::Server::new();
    let m = server
        .mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body(vec![7u8; 4096])
        .expect(1)
        .create();
    let t = build_transport(&server.url());
    let mut sink = Sink::new(u64::MAX);
    sink.fail_writes = true;
    let err = t.download_pack(&sample_key(), None, &mut sink).unwrap_err();
    assert!(!kit_core::protocol::is_retryable(&err), "{err:?}");
    m.assert();
}

// -- packExists --------------------------------------------------------------

#[test]
fn pack_exists_true() {
    let mut server = mockito::Server::new();
    let _m = server
        .mock("HEAD", mockito::Matcher::Any)
        .with_status(200)
        .create();
    let t = build_transport(&server.url());
    assert!(t.pack_exists(&sample_key(), None).unwrap());
}

#[test]
fn pack_exists_false_404() {
    let mut server = mockito::Server::new();
    let _m = server
        .mock("HEAD", mockito::Matcher::Any)
        .with_status(404)
        .create();
    let t = build_transport(&server.url());
    assert!(!t.pack_exists(&sample_key(), None).unwrap());
}

#[test]
fn pack_exists_403_access_denied() {
    let mut server = mockito::Server::new();
    let _m = server
        .mock("HEAD", mockito::Matcher::Any)
        .with_status(403)
        .create();
    let t = build_transport(&server.url());
    assert!(matches!(
        t.pack_exists(&sample_key(), None),
        Err(TransportError::AccessDenied)
    ));
}

// -- writeRef / updateRef ----------------------------------------------------

#[test]
fn write_ref_any_200_ok() {
    let mut server = mockito::Server::new();
    let m = server
        .mock("PUT", "/bucket/refs/heads/main")
        .with_status(200)
        .create();
    let t = build_transport(&server.url());
    t.write_ref("refs/heads/main", &sample_hash()).unwrap();
    m.assert();
}

#[test]
fn write_ref_uses_url_prefix_namespace() {
    let mut server = mockito::Server::new();
    let m = server
        .mock("PUT", "/bucket/repo-a/refs/heads/main")
        .with_status(200)
        .create();
    let t = build_transport_with_prefix(&server.url(), "repo-a");
    t.write_ref("refs/heads/main", &sample_hash()).unwrap();
    m.assert();
}

#[test]
fn update_ref_missing_sends_if_none_match_star() {
    let mut server = mockito::Server::new();
    let m = server
        .mock("PUT", "/bucket/refs/heads/main")
        .match_header("if-none-match", "*")
        .with_status(201)
        .create();
    let t = build_transport(&server.url());
    t.update_ref(
        "refs/heads/main",
        RefWriteCondition::Missing,
        &sample_hash(),
    )
    .unwrap();
    m.assert();
}

#[test]
fn update_ref_match_sends_if_match_etag() {
    let mut server = mockito::Server::new();
    let m = server
        .mock("PUT", "/bucket/refs/heads/main")
        .match_header(
            "if-match",
            mockito::Matcher::Regex(r#"^"[0-9a-f]{32}"$"#.into()),
        )
        .with_status(200)
        .create();
    let t = build_transport(&server.url());
    t.update_ref(
        "refs/heads/main",
        RefWriteCondition::Match([0x77; 32]),
        &sample_hash(),
    )
    .unwrap();
    m.assert();
}

#[test]
fn update_ref_412_returns_ref_conflict_no_retry() {
    // If the transport incorrectly treated 412 as retryable, mockito
    // would panic on the unset second expectation. We assert on the
    // single-mock (default: exactly once) case.
    let mut server = mockito::Server::new();
    let m = server
        .mock("PUT", mockito::Matcher::Any)
        .with_status(412)
        .create();
    let t = build_transport(&server.url());
    assert!(matches!(
        t.update_ref(
            "refs/heads/main",
            RefWriteCondition::Missing,
            &sample_hash(),
        ),
        Err(TransportError::RefConflict)
    ));
    m.assert();
}

#[test]
fn update_ref_409_returns_ref_conflict() {
    let mut server = mockito::Server::new();
    let _m = server
        .mock("PUT", mockito::Matcher::Any)
        .with_status(409)
        .create();
    let t = build_transport(&server.url());
    assert!(matches!(
        t.update_ref(
            "refs/heads/main",
            RefWriteCondition::Missing,
            &sample_hash(),
        ),
        Err(TransportError::RefConflict)
    ));
}

#[test]
fn update_ref_invalid_name_rejected_before_network() {
    // No mocks installed — if the transport contacted the server we'd
    // see a panic on the unset expectation.
    let server = mockito::Server::new();
    let t = build_transport(&server.url());
    assert!(matches!(
        t.update_ref("/bad/leading/slash", RefWriteCondition::Any, &sample_hash()),
        Err(TransportError::InvalidRef(_))
    ));
}

// -- readRef ------------------------------------------------------------------

#[test]
fn read_ref_200_parses_wire_format() {
    let mut server = mockito::Server::new();
    let h = [0xEEu8; 32];
    let mut body = to_hex(&h).into_bytes();
    body.push(b'\n');
    let _m = server
        .mock("GET", "/bucket/refs/heads/main")
        .with_status(200)
        .with_body(body)
        .create();
    let t = build_transport(&server.url());
    let got = t.read_ref("refs/heads/main").unwrap().unwrap();
    assert_eq!(got, h);
}

#[test]
fn read_ref_uses_url_prefix_namespace() {
    let mut server = mockito::Server::new();
    let h = [0xEEu8; 32];
    let mut body = to_hex(&h).into_bytes();
    body.push(b'\n');
    let m = server
        .mock("GET", "/bucket/repo-a/refs/heads/main")
        .with_status(200)
        .with_body(body)
        .create();
    let t = build_transport_with_prefix(&server.url(), "repo-a");
    let got = t.read_ref("refs/heads/main").unwrap().unwrap();
    assert_eq!(got, h);
    m.assert();
}

#[test]
fn read_ref_404_returns_none() {
    let mut server = mockito::Server::new();
    let _m = server
        .mock("GET", mockito::Matcher::Any)
        .with_status(404)
        .create();
    let t = build_transport(&server.url());
    assert!(t.read_ref("refs/heads/missing").unwrap().is_none());
}

/// A missing ref's error document can be longer than a ref body: a store
/// names the key, the request and the host in it. Its body is not read.
#[test]
fn read_ref_404_with_a_long_error_document_returns_none() {
    let mut server = mockito::Server::new();
    let _m = server
        .mock("GET", "/bucket/refs/heads/main")
        .with_status(404)
        .with_body(format!(
            "<Error><Code>NoSuchKey</Code><Key>refs/heads/main</Key><HostId>{}</HostId></Error>",
            "a".repeat(1024)
        ))
        .create();
    let t = build_transport(&server.url());
    assert_eq!(t.read_ref("refs/heads/main").unwrap(), None);
}

#[test]
fn read_ref_invalid_body_returns_invalid_response() {
    let mut server = mockito::Server::new();
    let _m = server
        .mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body(b"not-a-hash")
        .create();
    let t = build_transport(&server.url());
    assert!(matches!(
        t.read_ref("refs/heads/main"),
        Err(TransportError::InvalidResponse)
    ));
}

/// SPEC-REFS §1: uppercase hex is forbidden on the wire and
/// readers MUST reject it. The tolerant parser used to accept it via
/// the general `from_hex`.
#[test]
fn read_ref_uppercase_hex_returns_invalid_response() {
    let mut server = mockito::Server::new();
    let h = [0xEEu8; 32];
    let mut body = to_hex(&h).to_uppercase().into_bytes();
    body.push(b'\n');
    let _m = server
        .mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body(body)
        .create();
    let t = build_transport(&server.url());
    assert!(matches!(
        t.read_ref("refs/heads/main"),
        Err(TransportError::InvalidResponse)
    ));
}

/// SPEC-REFS §1: the wire form is exactly 65 bytes — 64 lowercase
/// hex + `\n`. S3 stores ref bytes verbatim, so CRLF, extra whitespace,
/// or a missing terminal newline are corruption, not tolerated variants.
#[test]
fn read_ref_non_canonical_body_returns_invalid_response() {
    let h = [0xEEu8; 32];
    let hex = to_hex(&h);
    let malformed: [Vec<u8>; 3] = [
        format!("{hex}\r\n").into_bytes(), // CRLF
        format!("{hex}  \n").into_bytes(), // trailing spaces
        hex.clone().into_bytes(),          // missing newline
    ];
    for body in malformed {
        let mut server = mockito::Server::new();
        let _m = server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_body(body.clone())
            .create();
        let t = build_transport(&server.url());
        assert!(
            matches!(
                t.read_ref("refs/heads/main"),
                Err(TransportError::InvalidResponse)
            ),
            "body {body:?} must be rejected"
        );
    }
}

/// A ref body that exceeds `REF_BODY_LIMIT` (256 bytes) must surface a
/// non-retryable `PayloadTooLarge` (it was once a retryable 507), and the
/// transport must NOT retry it — exactly one GET is expected.
#[test]
fn read_ref_oversized_body_is_payload_too_large_and_not_retried() {
    let mut server = mockito::Server::new();
    let oversized = vec![b'a'; 4096];
    let m = server
        .mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body(oversized)
        .expect(1) // exactly one request — no retry storm
        .create();
    let t = build_transport(&server.url());
    assert!(matches!(
        t.read_ref("refs/heads/main"),
        Err(TransportError::PayloadTooLarge(_))
    ));
    m.assert();
}

// -- listRefs -----------------------------------------------------------------

#[test]
fn list_refs_200_parses_xml_and_sorts() {
    let mut server = mockito::Server::new();

    // ListObjectsV2 response: two keys under refs/heads/.
    let xml = br#"<ListBucketResult>
        <Contents><Key>refs/heads/alpha</Key></Contents>
        <Contents><Key>refs/heads/zebra</Key></Contents>
    </ListBucketResult>"#;
    let _m_list = server
        .mock(
            "GET",
            mockito::Matcher::Regex(r"/bucket\?list-type=2".into()),
        )
        .with_status(200)
        .with_body(xml)
        .create();

    // Each referenced key needs a body; mockito matches on path so we
    // install one mock per key.
    let h_alpha = [0x01u8; 32];
    let h_zebra = [0x02u8; 32];
    let mut body_alpha = to_hex(&h_alpha).into_bytes();
    body_alpha.push(b'\n');
    let mut body_zebra = to_hex(&h_zebra).into_bytes();
    body_zebra.push(b'\n');
    let _m_alpha = server
        .mock("GET", "/bucket/refs/heads/alpha")
        .with_status(200)
        .with_body(body_alpha)
        .create();
    let _m_zebra = server
        .mock("GET", "/bucket/refs/heads/zebra")
        .with_status(200)
        .with_body(body_zebra)
        .create();

    let t = build_transport(&server.url());
    let refs = t.list_refs("refs/heads/").unwrap();
    assert_eq!(refs.len(), 2);
    assert_eq!(refs[0].name, "alpha");
    assert_eq!(refs[1].name, "zebra");
    assert_eq!(refs[0].hash.unwrap(), h_alpha);
    assert_eq!(refs[1].hash.unwrap(), h_zebra);
}

/// SPEC-REFS §1: `list_refs` resolves each key with the same strict
/// parser as `read_ref`. A listed ref whose read returns 200 with a body
/// that is not a canonical 65-byte ref wire fails the whole listing, as
/// an error status does: dropping the ref would hand a fetch a listing
/// without that branch.
#[test]
fn list_refs_fails_on_a_non_canonical_ref_body() {
    let malformed: [Vec<u8>; 4] = [
        format!("{}\n", to_hex(&[0xABu8; 32]).to_uppercase()).into_bytes(),
        format!("{}\r\n", to_hex(&[0x03u8; 32])).into_bytes(),
        to_hex(&[0x04u8; 32]).into_bytes(),
        b"deadbeef\n".to_vec(),
    ];
    for body in malformed {
        let mut server = mockito::Server::new();
        let names = vec!["bad".to_owned(), "good".to_owned()];
        let _list = mock_listing(&mut server, &names);
        let _good = server
            .mock("GET", "/bucket/refs/heads/good")
            .with_status(200)
            .with_body(ref_body(&[0x01u8; 32]))
            .create();
        let _bad = server
            .mock("GET", "/bucket/refs/heads/bad")
            .with_status(200)
            .with_body(body.clone())
            .create();
        let t = build_transport(&server.url());
        let got = t.list_refs("refs/heads/");
        assert!(
            matches!(got, Err(TransportError::InvalidResponse)),
            "body {:?} must fail the listing, got {got:?}",
            String::from_utf8_lossy(&body)
        );
    }
}

#[test]
fn list_refs_uses_url_prefix_namespace_and_strips_it() {
    let mut server = mockito::Server::new();

    let xml = br#"<ListBucketResult>
        <Contents><Key>repo-a/refs/heads/alpha</Key></Contents>
        <Contents><Key>repo-a/refs/heads/zebra</Key></Contents>
        <Contents><Key>repo-b/refs/heads/ignored</Key></Contents>
    </ListBucketResult>"#;
    let m_list = server
        .mock("GET", "/bucket")
        // Query is canonically percent-encoded before signing;
        // `/` becomes `%2F`.
        .match_query(mockito::Matcher::Exact(
            "list-type=2&prefix=repo-a%2Frefs%2Fheads%2F".to_owned(),
        ))
        .with_status(200)
        .with_body(xml)
        .create();

    let h_alpha = [0x01u8; 32];
    let h_zebra = [0x02u8; 32];
    let mut body_alpha = to_hex(&h_alpha).into_bytes();
    body_alpha.push(b'\n');
    let mut body_zebra = to_hex(&h_zebra).into_bytes();
    body_zebra.push(b'\n');
    let m_alpha = server
        .mock("GET", "/bucket/repo-a/refs/heads/alpha")
        .with_status(200)
        .with_body(body_alpha)
        .create();
    let m_zebra = server
        .mock("GET", "/bucket/repo-a/refs/heads/zebra")
        .with_status(200)
        .with_body(body_zebra)
        .create();

    let t = build_transport_with_prefix(&server.url(), "repo-a");
    let refs = t.list_refs("refs/heads/").unwrap();
    assert_eq!(refs.len(), 2);
    assert_eq!(refs[0].name, "alpha");
    assert_eq!(refs[1].name, "zebra");
    assert_eq!(refs[0].hash.unwrap(), h_alpha);
    assert_eq!(refs[1].hash.unwrap(), h_zebra);
    m_list.assert();
    m_alpha.assert();
    m_zebra.assert();
}

#[test]
fn list_refs_403_access_denied() {
    let mut server = mockito::Server::new();
    let _m = server
        .mock(
            "GET",
            mockito::Matcher::Regex(r"/bucket\?list-type=2".into()),
        )
        .with_status(403)
        .create();
    let t = build_transport(&server.url());
    assert!(matches!(
        t.list_refs("refs/heads/"),
        Err(TransportError::AccessDenied)
    ));
}

// -- Retry / 429 --------------------------------------------------------------

#[test]
fn retry_429_then_200() {
    let mut server = mockito::Server::new();
    let _m429 = server
        .mock("GET", mockito::Matcher::Any)
        .with_status(429)
        .create();
    let _m200 = server
        .mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body(b"pack")
        .create();
    let t = build_transport(&server.url());
    let got = t.download_blob(&sample_key(), None, u64::MAX).unwrap();
    assert_eq!(got, b"pack");
}

#[test]
fn connect_reads_env_credentials() {
    // `connect` must parse a well-formed URL; empty env is fine at
    // construction, but `connect` rejects malformed URLs outright.
    let err = S3Transport::connect("kit+s3://").unwrap_err();
    match err {
        TransportError::InvalidRef(_) => {}
        other => panic!("expected InvalidRef, got {other:?}"),
    }
    // Valid URL builds successfully even with no env credentials — the
    // first signed request is what surfaces AccessDenied from the real
    // server.
    let ok = S3Transport::connect("kit+s3://host.example/my-bucket");
    assert!(ok.is_ok());
}

#[test]
fn with_parts_rejects_invalid_url_prefixes() {
    let server = mockito::Server::new();
    for prefix in [
        "/repo",
        "repo/",
        "repo//a",
        "repo/../a",
        "repo/./a",
        "repo\\a",
    ] {
        assert!(matches!(
            S3Transport::with_parts(
                server.url(),
                "bucket",
                Some(prefix.to_owned()),
                demo_creds()
            ),
            Err(TransportError::InvalidRef(_))
        ));
    }
}

#[test]
fn retry_order_calls_server_enough_times() {
    // Thread-safe counter so we can confirm the transport makes EXACTLY
    // (1 + N) attempts before giving up — 1 initial + N retries (N = 5
    // in the fast ladder we installed). The single GET that
    // `download_pack` issues is retried through the full ladder and its
    // terminal 502 propagates.
    static CALLS: AtomicU32 = AtomicU32::new(0);
    CALLS.store(0, Ordering::SeqCst);

    let mut server = mockito::Server::new();
    let m = server
        .mock("GET", mockito::Matcher::Any)
        .with_status(502)
        .expect(6)
        .with_body_from_request(|_| {
            CALLS.fetch_add(1, Ordering::SeqCst);
            b"err".to_vec()
        })
        .create();
    let t = build_transport(&server.url());
    match t.download_blob(&sample_key(), None, u64::MAX) {
        Err(TransportError::ServerError { status: 502 }) => {}
        other => panic!("expected the terminal 502 after retries, got {other:?}"),
    }
    m.assert();
    assert_eq!(
        CALLS.load(Ordering::SeqCst),
        6,
        "exhausted retry ladder must make exactly 1 + 5 attempts"
    );
}

/// Regression: a truncated ListObjectsV2 response (`IsTruncated=true`
/// with a `NextContinuationToken`) MUST be followed with a
/// `continuation-token` request, accumulating keys from every page.
/// Before the fix, only the first page's keys were returned, silently
/// truncating any ref list past the per-page cap.
#[test]
fn list_refs_paginates_on_continuation_token() {
    let mut server = mockito::Server::new();

    // Page 1: one key + IsTruncated=true + a continuation token.
    let page1 = br#"<ListBucketResult>
        <IsTruncated>true</IsTruncated>
        <Contents><Key>refs/heads/alpha</Key></Contents>
        <NextContinuationToken>TOKEN123</NextContinuationToken>
    </ListBucketResult>"#;
    // Page 2: the remaining key, not truncated.
    let page2 = br#"<ListBucketResult>
        <IsTruncated>false</IsTruncated>
        <Contents><Key>refs/heads/zebra</Key></Contents>
    </ListBucketResult>"#;

    // Page 1 request: no continuation-token in the query.
    let m_page1 = server
        .mock("GET", "/bucket")
        .match_query(mockito::Matcher::Exact(
            "list-type=2&prefix=refs%2Fheads%2F".to_owned(),
        ))
        .with_status(200)
        .with_body(page1)
        .create();
    // Page 2 request: carries continuation-token=TOKEN123 (canonically
    // sorted, so it sorts before list-type).
    let m_page2 = server
        .mock("GET", "/bucket")
        .match_query(mockito::Matcher::Exact(
            "continuation-token=TOKEN123&list-type=2&prefix=refs%2Fheads%2F".to_owned(),
        ))
        .with_status(200)
        .with_body(page2)
        .create();

    let h_alpha = [0x01u8; 32];
    let h_zebra = [0x02u8; 32];
    let mut body_alpha = to_hex(&h_alpha).into_bytes();
    body_alpha.push(b'\n');
    let mut body_zebra = to_hex(&h_zebra).into_bytes();
    body_zebra.push(b'\n');
    let _m_alpha = server
        .mock("GET", "/bucket/refs/heads/alpha")
        .with_status(200)
        .with_body(body_alpha)
        .create();
    let _m_zebra = server
        .mock("GET", "/bucket/refs/heads/zebra")
        .with_status(200)
        .with_body(body_zebra)
        .create();

    let t = build_transport(&server.url());
    let refs = t.list_refs("refs/heads/").unwrap();
    assert_eq!(refs.len(), 2, "both pages' refs must be returned");
    assert_eq!(refs[0].name, "alpha");
    assert_eq!(refs[1].name, "zebra");
    m_page1.assert();
    m_page2.assert();
}

/// Regression: `list_refs` with a prefix that has NO trailing slash
/// (e.g. `refs/heads`, which `validate_ref_prefix` accepts) must still
/// strip the prefix + separator and return suffix-only names, matching
/// the canonical memory/file transports. Before the fix the suffix kept
/// a leading '/' and the ref was silently dropped.
#[test]
fn list_refs_prefix_without_trailing_slash_strips_separator() {
    let mut server = mockito::Server::new();

    let xml = br#"<ListBucketResult>
        <Contents><Key>refs/heads/main</Key></Contents>
    </ListBucketResult>"#;
    // effective_list_prefix appends no trailing slash for "refs/heads".
    let _m_list = server
        .mock("GET", "/bucket")
        .match_query(mockito::Matcher::Exact(
            "list-type=2&prefix=refs%2Fheads".to_owned(),
        ))
        .with_status(200)
        .with_body(xml)
        .create();

    let h_main = [0x07u8; 32];
    let mut body_main = to_hex(&h_main).into_bytes();
    body_main.push(b'\n');
    let _m_main = server
        .mock("GET", "/bucket/refs/heads/main")
        .with_status(200)
        .with_body(body_main)
        .create();

    let t = build_transport(&server.url());
    let refs = t.list_refs("refs/heads").unwrap();
    assert_eq!(
        refs.len(),
        1,
        "ref must not be dropped for slash-less prefix"
    );
    assert_eq!(refs[0].name, "main");
    assert_eq!(refs[0].hash.unwrap(), h_main);
}

/// Regression (SPEC-REFS §4): `list_refs("refs/heads/feat")` must not
/// return "refs/heads/featx" stripped down to "x". S3's own
/// `ListObjectsV2` `prefix` query is a literal string prefix with no
/// path-component awareness, so the server can legitimately return both
/// keys for this query — the client-side suffix computation is the only
/// place the path-component boundary is enforced, and before the fix it
/// accepted the false match.
#[test]
fn list_refs_prefix_respects_path_component_boundary() {
    let mut server = mockito::Server::new();

    let xml = br#"<ListBucketResult>
        <Contents><Key>refs/heads/feat/x</Key></Contents>
        <Contents><Key>refs/heads/featx</Key></Contents>
    </ListBucketResult>"#;
    let _m_list = server
        .mock(
            "GET",
            mockito::Matcher::Regex(r"/bucket\?list-type=2".into()),
        )
        .with_status(200)
        .with_body(xml)
        .create();

    let h_x = [0x11u8; 32];
    let h_featx = [0x22u8; 32];
    let mut body_x = to_hex(&h_x).into_bytes();
    body_x.push(b'\n');
    let mut body_featx = to_hex(&h_featx).into_bytes();
    body_featx.push(b'\n');
    let _m_x = server
        .mock("GET", "/bucket/refs/heads/feat/x")
        .with_status(200)
        .with_body(body_x)
        .create();
    let _m_featx = server
        .mock("GET", "/bucket/refs/heads/featx")
        .with_status(200)
        .with_body(body_featx)
        .create();

    let t = build_transport(&server.url());
    let refs = t.list_refs("refs/heads/feat").unwrap();
    assert_eq!(refs.len(), 1, "featx must not match prefix feat");
    assert_eq!(refs[0].name, "x");
    assert_eq!(refs[0].hash.unwrap(), h_x);
}

/// A hostile endpoint that repeats its continuation token must end the
/// listing with an error after a bounded number of requests.
#[test]
fn list_refs_rejects_a_repeated_continuation_token() {
    let mut server = mockito::Server::new();
    let page = br#"<ListBucketResult>
        <IsTruncated>true</IsTruncated>
        <NextContinuationToken>SAME</NextContinuationToken>
    </ListBucketResult>"#;
    let m = server
        .mock("GET", "/bucket")
        .match_query(mockito::Matcher::Any)
        .with_status(200)
        .with_body(page)
        .expect_at_most(3)
        .create();

    let t = build_transport(&server.url());
    assert!(t.list_refs("refs/heads/").is_err());
    m.assert();
}

/// A redirect response is an error. The client must not replay a
/// request, or its body, at the redirect target.
#[test]
fn redirects_are_not_followed() {
    let mut server = mockito::Server::new();
    let target = format!("{}/evil", server.url());
    let _redirect = server
        .mock("GET", mockito::Matcher::Regex("^/bucket/packs/".into()))
        .with_status(307)
        .with_header("location", &target)
        .create();
    let evil = server
        .mock("GET", "/evil")
        .with_status(200)
        .with_body("x")
        .expect(0)
        .create();

    let t = build_transport(&server.url());
    assert!(matches!(
        t.download_blob(&sample_key(), None, u64::MAX),
        Err(TransportError::ServerError { status: 307 })
    ));
    evil.assert();
}

// -- list_refs: one ref read per listed key ------------------------------------

/// A ListObjectsV2 body naming `names` under `refs/heads/`.
fn listing_xml(names: &[String]) -> Vec<u8> {
    use std::fmt::Write as _;
    let mut xml = String::from("<ListBucketResult>");
    for n in names {
        let _ = write!(xml, "<Contents><Key>refs/heads/{n}</Key></Contents>");
    }
    xml.push_str("</ListBucketResult>");
    xml.into_bytes()
}

fn ref_body(h: &Hash) -> Vec<u8> {
    let mut body = to_hex(h).into_bytes();
    body.push(b'\n');
    body
}

fn mock_listing(server: &mut mockito::Server, names: &[String]) -> mockito::Mock {
    server
        .mock(
            "GET",
            mockito::Matcher::Regex(r"/bucket\?list-type=2".into()),
        )
        .with_status(200)
        .with_body(listing_xml(names))
        .expect(1)
        .create()
}

#[test]
fn list_refs_reads_each_listed_ref_once_and_keeps_the_order() {
    let mut server = mockito::Server::new();
    let names: Vec<String> = (0..40).map(|i| format!("b{i:02}")).collect();
    let list = mock_listing(&mut server, &names);
    let reads: Vec<_> = names
        .iter()
        .enumerate()
        .map(|(i, n)| {
            server
                .mock("GET", format!("/bucket/refs/heads/{n}").as_str())
                .with_status(200)
                .with_body(ref_body(&[u8::try_from(i).unwrap() + 1; 32]))
                .expect(1)
                .create()
        })
        .collect();
    let t = build_transport(&server.url());
    let refs = t.list_refs("refs/heads/").unwrap();
    let got: Vec<(String, Hash)> = refs
        .into_iter()
        .map(|r| (r.name, r.hash.unwrap()))
        .collect();
    let want: Vec<(String, Hash)> = names
        .iter()
        .enumerate()
        .map(|(i, n)| (n.clone(), [u8::try_from(i).unwrap() + 1; 32]))
        .collect();
    assert_eq!(got, want);
    list.assert();
    for m in reads {
        m.assert();
    }
}

#[test]
fn list_refs_fails_when_a_listed_ref_read_fails() {
    let mut server = mockito::Server::new();
    let names: Vec<String> = ["a", "b", "c"].iter().map(|s| (*s).to_owned()).collect();
    let _list = mock_listing(&mut server, &names);
    for n in ["a", "c"] {
        server
            .mock("GET", format!("/bucket/refs/heads/{n}").as_str())
            .with_status(200)
            .with_body(ref_body(&sample_hash()))
            .create();
    }
    let _broken = server
        .mock("GET", "/bucket/refs/heads/b")
        .with_status(500)
        .create();
    let t = build_transport(&server.url());
    assert!(
        matches!(
            t.list_refs("refs/heads/"),
            Err(TransportError::ServerError { status: 500 })
        ),
        "a failed ref read must fail the listing, not drop the ref"
    );
}

#[test]
fn list_refs_fails_when_a_listed_ref_read_is_denied() {
    let mut server = mockito::Server::new();
    let names = vec!["a".to_owned(), "b".to_owned()];
    let _list = mock_listing(&mut server, &names);
    let _a = server
        .mock("GET", "/bucket/refs/heads/a")
        .with_status(200)
        .with_body(ref_body(&sample_hash()))
        .create();
    let _b = server
        .mock("GET", "/bucket/refs/heads/b")
        .with_status(403)
        .create();
    let t = build_transport(&server.url());
    assert!(matches!(
        t.list_refs("refs/heads/"),
        Err(TransportError::AccessDenied)
    ));
}

/// A ref deleted between the listing and its read is absent, as in an
/// older listing (SPEC-TRANSPORT-CONNECT §7.9 allows a stale listing).
#[test]
fn list_refs_skips_a_ref_deleted_after_the_listing() {
    let mut server = mockito::Server::new();
    let names = vec!["a".to_owned(), "gone".to_owned()];
    let _list = mock_listing(&mut server, &names);
    let _a = server
        .mock("GET", "/bucket/refs/heads/a")
        .with_status(200)
        .with_body(ref_body(&sample_hash()))
        .create();
    let _gone = server
        .mock("GET", "/bucket/refs/heads/gone")
        .with_status(404)
        .create();
    let t = build_transport(&server.url());
    let refs = t.list_refs("refs/heads/").unwrap();
    assert_eq!(refs.len(), 1);
    assert_eq!(refs[0].name, "a");
}

// -- pack bodies and sinks ---------------------------------------------------

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| u8::try_from(i % 251).unwrap()).collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    kit_transport_s3::sigv4::sha256_hex(bytes)
}

/// A pack body that records the offset of every read it starts. It can
/// claim a length other than its bytes', and end early after its first
/// read.
struct Recorded {
    bytes: Vec<u8>,
    len: u64,
    cut_after_first: Option<usize>,
    reads: Mutex<Vec<u64>>,
}

impl Recorded {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            len: bytes.len() as u64,
            bytes,
            cut_after_first: None,
            reads: Mutex::new(Vec::new()),
        }
    }

    fn claiming(mut self, len: u64) -> Self {
        self.len = len;
        self
    }

    fn cut_after_first_read(mut self, at: usize) -> Self {
        self.cut_after_first = Some(at);
        self
    }

    fn reads(&self) -> Vec<u64> {
        self.reads.lock().unwrap().clone()
    }
}

impl PackBody for Recorded {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_from(&self, offset: u64) -> std::io::Result<Box<dyn std::io::Read + Send + '_>> {
        let mut reads = self.reads.lock().unwrap();
        reads.push(offset);
        let end = match self.cut_after_first {
            Some(at) if reads.len() > 1 => at,
            _ => self.bytes.len(),
        };
        let start = usize::try_from(offset).unwrap();
        Ok(Box::new(&self.bytes[start..end]))
    }
}

/// A sink that keeps what it is sent and records each call.
struct Sink {
    limit: u64,
    begins: Vec<Option<u64>>,
    writes: usize,
    bytes: Vec<u8>,
    fail_writes: bool,
    failed: Option<std::io::ErrorKind>,
}

impl Sink {
    fn new(limit: u64) -> Self {
        Self {
            limit,
            begins: Vec::new(),
            writes: 0,
            bytes: Vec::new(),
            fail_writes: false,
            failed: None,
        }
    }
}

impl PackSink for Sink {
    fn begin(&mut self, declared: Option<u64>) -> Result<(), TransportError> {
        self.begins.push(declared);
        if self.failed.is_some() {
            return Err(TransportError::ProtocolError);
        }
        self.bytes.clear();
        match declared {
            Some(len) if len > self.limit => Err(TransportError::PayloadTooLarge(
                usize::try_from(len).unwrap(),
            )),
            _ => Ok(()),
        }
    }

    fn write(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
        self.writes += 1;
        if self.fail_writes {
            self.failed = Some(std::io::ErrorKind::StorageFull);
            return Err(TransportError::ProtocolError);
        }
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    fn failed(&self) -> Option<std::io::ErrorKind> {
        self.failed
    }
}
