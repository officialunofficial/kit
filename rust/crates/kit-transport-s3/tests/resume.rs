#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers
//! An interrupted pack download continues with `Range`: only against an
//! exact `206` with the entity tag of the first answer, and every other
//! answer reads the pack again from its start. The pack is checked whole
//! against its key either way.

use std::time::Duration;

use kit_core::hash;
use kit_core::object::{Blob, Object};
use kit_core::pack::{PackError, PackSpool, PackWriter, pack_key};
use kit_core::protocol::{
    BackoffIterator, PACK_BODY_LIMIT, PackKey, PackSink, RestartReason, ResumeOutcome, Transport,
    TransportError, TransportResult,
};
use kit_test_util::range_server::{RangeServer, Request, Response, honest};
use kit_transport_s3::S3Transport;
use kit_transport_s3::sigv4::Credentials;

const ETAG: &str = "\"v1\"";

/// A pack of a few blobs that do not compress, and its key.
fn pack() -> (Vec<u8>, PackKey) {
    let mut writer = PackWriter::new();
    for seed in 0u8..6 {
        let data: Vec<u8> = (0u32..2000)
            .flat_map(|n| hash::hash(&[&n.to_le_bytes()[..], &[seed]].concat()))
            .collect();
        let object = Object::Blob(Blob { data });
        writer
            .push_raw(
                object.id().unwrap(),
                &kit_core::serialize::serialize(&object).unwrap(),
            )
            .unwrap();
    }
    let bytes = writer.finish().unwrap();
    let key = PackKey::from_hash(pack_key(&bytes));
    (bytes, key)
}

fn transport(endpoint: &str) -> S3Transport {
    let mut transport = S3Transport::with_parts(
        endpoint,
        "bucket",
        None,
        Credentials {
            access_key_id: "AKIA_TEST".into(),
            secret_access_key: "secret".into(),
            region: "us-east-1".into(),
        },
    )
    .unwrap();
    transport.set_clock(|| 1_711_300_000);
    transport.set_sleeper(|_| {});
    transport.set_backoff(|| BackoffIterator::with(Duration::ZERO, Duration::ZERO, 4));
    transport
}

/// A spool that keeps what the transport tells it about resuming.
struct Recording {
    spool: PackSpool,
    outcomes: Vec<ResumeOutcome>,
    begins: usize,
}

impl Recording {
    fn new() -> Self {
        let dir = std::env::temp_dir();
        Self {
            spool: PackSpool::create(&dir, PACK_BODY_LIMIT).unwrap(),
            outcomes: Vec::new(),
            begins: 0,
        }
    }
}

impl PackSink for Recording {
    fn begin(&mut self, declared: Option<u64>) -> TransportResult<()> {
        self.begins += 1;
        PackSink::begin(&mut self.spool, declared)
    }
    fn write(&mut self, bytes: &[u8]) -> TransportResult<()> {
        PackSink::write(&mut self.spool, bytes)
    }
    fn failed(&self) -> Option<std::io::ErrorKind> {
        self.spool.failed()
    }
    fn retained(&self) -> u64 {
        PackSink::retained(&self.spool)
    }
    fn resume(&mut self, total: u64, offset: u64) -> TransportResult<()> {
        PackSink::resume(&mut self.spool, total, offset)
    }
    fn note_resume(&mut self, outcome: ResumeOutcome) {
        self.outcomes.push(outcome);
    }
}

/// Download the pack from a server whose answer to request `n` is
/// `script(n, honest answer)`, and verify what arrived.
fn download(
    object: &[u8],
    key: &PackKey,
    script: impl Fn(usize, &Request, Response) -> Response + Send + Sync + 'static,
) -> (
    TransportResult<()>,
    Result<(), PackError>,
    Recording,
    Vec<Request>,
) {
    let object = object.to_vec();
    let server =
        RangeServer::start(move |n, request| script(n, request, honest(&object, ETAG, request)));
    let transport = transport(&server.endpoint());
    let mut sink = Recording::new();
    let downloaded = transport.download_pack(key, None, &mut sink);
    let spool = std::mem::replace(
        &mut sink.spool,
        PackSpool::create(&std::env::temp_dir(), 1).unwrap(),
    );
    let verified = spool.finish(key).map(drop);
    (downloaded, verified, sink, server.requests())
}

fn ranged(request: &Request) -> bool {
    request.header("range").is_some()
}

#[test]
fn an_interrupted_download_continues_where_it_stopped() {
    let (object, key) = pack();
    for cut in [1, 17, 4096, object.len() / 2, object.len() - 1] {
        let (downloaded, verified, sink, requests) =
            download(&object, &key, move |n, _, answer| {
                if n == 0 {
                    answer.cut_after(cut)
                } else {
                    answer
                }
            });
        downloaded.unwrap();
        verified.unwrap();
        assert_eq!(requests.len(), 2, "cut at {cut}");
        assert_eq!(requests[1].header("range"), Some(&*format!("bytes={cut}-")));
        assert_eq!(requests[1].header("if-match"), Some(ETAG));
        assert_eq!(
            sink.outcomes,
            [ResumeOutcome::Resumed { bytes: cut as u64 }],
            "cut at {cut}"
        );
        assert_eq!(sink.begins, 1, "the body begins once");
    }
}

#[test]
fn a_download_interrupted_twice_continues_twice() {
    let (object, key) = pack();
    let (first, second) = (1000, 5000);
    let (downloaded, verified, sink, requests) =
        download(&object, &key, move |n, _, answer| match n {
            0 => answer.cut_after(first),
            1 => answer.cut_after(second - first),
            _ => answer,
        });
    downloaded.unwrap();
    verified.unwrap();
    assert_eq!(requests.len(), 3);
    assert_eq!(
        requests[2].header("range"),
        Some(&*format!("bytes={second}-"))
    );
    assert_eq!(
        sink.outcomes,
        [
            ResumeOutcome::Resumed {
                bytes: first as u64
            },
            ResumeOutcome::Resumed {
                bytes: second as u64
            },
        ]
    );
}

/// A name, the reason it must give, and how it spoils the honest answer.
type Case = (
    &'static str,
    RestartReason,
    Box<dyn Fn(Response) -> Response + Send + Sync>,
);

#[test]
fn an_answer_that_is_not_the_rest_reads_the_pack_again() {
    let (object, key) = pack();
    let total = object.len();
    let cases: Vec<Case> = vec![
        (
            "range ignored",
            RestartReason::Status,
            Box::new(|answer| answer),
        ),
        (
            "weak tag",
            RestartReason::Validator,
            Box::new(|a| a.header("etag", "W/\"v1\"")),
        ),
        (
            "another tag",
            RestartReason::Validator,
            Box::new(|a| a.header("etag", "\"v2\"")),
        ),
        (
            "no tag",
            RestartReason::Validator,
            Box::new(|a| a.without("etag")),
        ),
        (
            "wrong start",
            RestartReason::Range,
            Box::new(move |a| {
                a.header("content-range", &format!("bytes 99-{}/{total}", total - 1))
            }),
        ),
        (
            "wrong end",
            RestartReason::Range,
            Box::new(move |a| {
                a.header("content-range", &format!("bytes 100-{}/{total}", total - 2))
            }),
        ),
        (
            "wrong total",
            RestartReason::Range,
            Box::new(move |a| {
                a.header(
                    "content-range",
                    &format!("bytes 100-{}/{}", total, total + 1),
                )
            }),
        ),
        (
            "no range",
            RestartReason::Range,
            Box::new(|a| a.without("content-range")),
        ),
        (
            "coded",
            RestartReason::Range,
            Box::new(|a| a.header("content-encoding", "gzip")),
        ),
        (
            "wrong length",
            RestartReason::Range,
            Box::new(|mut a| {
                a.declared = Some(a.body.len() + 1);
                a
            }),
        ),
    ];
    for (name, reason, tamper) in cases {
        let ignored = name == "range ignored";
        let object_for_script = object.clone();
        let (downloaded, verified, sink, requests) =
            download(&object, &key, move |n, _, answer| match n {
                0 => answer.cut_after(100),
                1 if ignored => Response::new(200, &object_for_script).header("etag", ETAG),
                1 => tamper(answer),
                _ => answer,
            });
        downloaded.unwrap_or_else(|error| panic!("{name}: {error:?}"));
        verified.unwrap_or_else(|error| panic!("{name}: {error:?}"));
        assert_eq!(
            sink.outcomes,
            [ResumeOutcome::Restarted { reason }],
            "{name}"
        );
        assert!(ranged(&requests[1]), "{name}");
        if ignored {
            assert_eq!(requests.len(), 2, "{name}: the full answer is taken");
        } else {
            assert_eq!(requests.len(), 3, "{name}");
            assert!(!ranged(&requests[2]), "{name}: the fallback is a full read");
        }
        assert_eq!(sink.begins, 2, "{name}: the body begins again");
    }
}

#[test]
fn a_refused_condition_or_range_reads_the_pack_again() {
    let (object, key) = pack();
    for (status, reason) in [(412, RestartReason::Validator), (416, RestartReason::Range)] {
        let (downloaded, verified, sink, requests) =
            download(&object, &key, move |n, _, answer| match n {
                0 => answer.cut_after(100),
                1 => Response::new(status, b""),
                _ => answer,
            });
        downloaded.unwrap();
        verified.unwrap();
        assert_eq!(requests.len(), 3, "{status}");
        assert!(!ranged(&requests[2]), "{status}");
        assert_eq!(
            sink.outcomes,
            [ResumeOutcome::Restarted { reason }],
            "{status}"
        );
    }
}

#[test]
fn without_a_strong_tag_on_the_first_answer_the_retry_is_a_full_read() {
    let (object, key) = pack();
    for tag in [None, Some("W/\"v1\"")] {
        let (downloaded, verified, sink, requests) =
            download(&object, &key, move |n, _, answer| {
                let answer = match tag {
                    Some(tag) => answer.header("etag", tag),
                    None => answer.without("etag"),
                };
                if n == 0 {
                    answer.cut_after(100)
                } else {
                    answer
                }
            });
        downloaded.unwrap();
        verified.unwrap();
        assert_eq!(requests.len(), 2, "{tag:?}");
        assert!(!ranged(&requests[1]), "{tag:?}");
        assert!(sink.outcomes.is_empty(), "{tag:?}");
        assert_eq!(sink.begins, 2, "{tag:?}");
    }
}

#[test]
fn a_prefix_that_is_not_the_pack_fails_the_whole_pack_check() {
    let (object, key) = pack();
    let mut damaged = object.clone();
    damaged[50] ^= 1;
    let (downloaded, verified, sink, _) = download(&object, &key, move |n, _, answer| {
        // The first answer's bytes are damaged, then cut; the rest is right.
        if n == 0 {
            let mut first = answer;
            first.body = damaged.clone();
            first.cut_after(100)
        } else {
            answer
        }
    });
    downloaded.unwrap();
    assert!(
        matches!(verified, Err(PackError::KeyMismatch)),
        "{verified:?}"
    );
    assert_eq!(sink.outcomes, [ResumeOutcome::Resumed { bytes: 100 }]);
}

#[test]
fn a_download_that_keeps_stopping_ends_in_an_error() {
    let (object, key) = pack();
    let (downloaded, verified, _, requests) =
        download(&object, &key, |_, _, answer| answer.cut_after(10));
    assert!(matches!(downloaded, Err(TransportError::ConnectionFailed)));
    assert!(verified.is_err());
    assert!(requests.len() <= 6, "the ladder bounds the attempts");
}
