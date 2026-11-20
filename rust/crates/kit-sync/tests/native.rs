//! Pack-location fetches over the native HTTP channel, against a one-shot
//! loopback HTTP stub.
#![cfg(feature = "connect-native")]
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use kit_sync::NativeHttp;

/// Fetch a location into memory, as kit-client's location sink would take it.
fn fetch(
    transport: &NativeHttp,
    url: &str,
    limit: u64,
    timeout: Option<std::time::Duration>,
) -> Result<Vec<u8>, String> {
    use kit_client::HttpTransport as _;
    use kit_sync::Executor as _;
    let mut sink = kit_core::protocol::MemorySink::new(limit);
    transport.block_on(transport.fetch_pack_location(url, limit, timeout, &mut sink))?;
    Ok(sink.into_bytes().unwrap())
}

/// Serve exactly one plain HTTP response and retain its request headers.
fn location_response(
    response: &'static [u8],
    body_delay: std::time::Duration,
) -> (String, std::thread::JoinHandle<String>) {
    use std::io::{Read as _, Write as _};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!(
        "http://{}/pack?signature=test",
        listener.local_addr().unwrap()
    );
    let thread = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            stream.read_exact(&mut byte).unwrap();
            request.push(byte[0]);
        }
        std::thread::sleep(body_delay);
        // A deadline may have already closed the receiving connection.
        let _ = stream.write_all(response);
        String::from_utf8(request).unwrap()
    });
    (url, thread)
}

#[test]
fn pack_location_fetch_never_sends_rpc_defaults_or_credentials() {
    use kit_client::HttpTransport as _;
    let (url, server) = location_response(
        b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\npack",
        std::time::Duration::ZERO,
    );
    let mut headers = http::HeaderMap::new();
    headers.insert("authorization", "Bearer secret".parse().unwrap());
    headers.insert("cookie", "session=secret".parse().unwrap());
    headers.insert("x-kit-signature", "secret".parse().unwrap());
    headers.insert("x-host-default", "secret".parse().unwrap());
    let transport = NativeHttp::new()
        .unwrap()
        .with_test_pack_location_http(true)
        .allow_private_pack_locations(true)
        .with_default_headers(headers);
    assert!(transport.supports_pack_locations());
    assert_eq!(fetch(&transport, &url, 4, None).unwrap(), b"pack");
    let request = server.join().unwrap().to_ascii_lowercase();
    assert!(request.starts_with("get /pack?signature=test http/1.1\r\n"));
    assert!(request.contains("accept-encoding: identity\r\n"));
    assert!(!request.contains("secret"));
    assert!(!request.contains("authorization:"));
    assert!(!request.contains("cookie:"));
    assert!(!request.contains("x-kit-"));
    assert!(!request.contains("x-host-default:"));
}

#[test]
fn pack_location_bodies_stream_into_the_sink_with_or_without_a_length() {
    let transport = NativeHttp::new()
        .unwrap()
        .with_test_pack_location_http(true)
        .allow_private_pack_locations(true);
    let (url, server) = location_response(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n2\r\npa\r\n2\r\nck\r\n0\r\n\r\n",
        std::time::Duration::ZERO,
    );
    assert_eq!(fetch(&transport, &url, 4, None).unwrap(), b"pack");
    server.join().unwrap();
    // A chunked body that runs past the limit is refused as it arrives.
    let (url, server) = location_response(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n3\r\npac\r\n2\r\nks\r\n0\r\n\r\n",
        std::time::Duration::ZERO,
    );
    assert!(fetch(&transport, &url, 4, None).is_err());
    server.join().unwrap();
}

#[test]
fn pack_location_fetch_refuses_redirects_encoding_and_oversize_bodies() {
    let transport = NativeHttp::new()
        .unwrap()
        .with_test_pack_location_http(true)
        .allow_private_pack_locations(true);
    for response in [
        &b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"[..],
        &b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 4\r\nConnection: close\r\n\r\npack"[..],
        &b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\npacks"[..],
    ] {
        let (url, server) = location_response(response, std::time::Duration::ZERO);
        assert!(
            fetch(&transport, &url, 4, None)
                .is_err()
        );
        server.join().unwrap();
    }
}

#[test]
fn pack_location_fetch_enforces_its_own_scheme_and_stall_bound() {
    let transport = NativeHttp::new()
        .unwrap()
        .allow_insecure_http(true)
        .with_test_pack_location_http(true)
        .allow_private_pack_locations(true)
        .with_metadata_timeout(std::time::Duration::from_secs(5))
        .with_transfer_timeout(std::time::Duration::from_millis(200));
    for url in [
        "http://example.invalid/pack",
        "ftp://127.0.0.1/pack",
        "https://user:secret@example.invalid/pack",
        "/relative/pack",
    ] {
        assert!(fetch(&transport, url, 4, None).is_err(), "{url}");
    }
    let (url, server) = location_response(
        b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\npack",
        std::time::Duration::from_millis(400),
    );
    let error = fetch(&transport, &url, 4, None).unwrap_err();
    assert_eq!(error, "pack location transfer stalled: no data for 200 ms");
    server.join().unwrap();
}

/// Serve one location response of `chunks` chunks of `chunk` bytes, with
/// `gap` before each chunk.
fn trickled_location(
    chunks: usize,
    chunk: usize,
    gap: std::time::Duration,
) -> (String, std::thread::JoinHandle<()>) {
    use std::io::{Read as _, Write as _};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/pack", listener.local_addr().unwrap());
    let thread = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            stream.read_exact(&mut byte).unwrap();
            request.push(byte[0]);
        }
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            chunks * chunk
        );
        stream.write_all(head.as_bytes()).unwrap();
        for _ in 0..chunks {
            std::thread::sleep(gap);
            // The client may have given up on a stalled body.
            if stream.write_all(&vec![7; chunk]).is_err() {
                return;
            }
        }
    });
    (url, thread)
}

#[test]
fn a_slow_location_body_that_keeps_moving_outlives_the_stall_bound() {
    let transport = NativeHttp::new()
        .unwrap()
        .with_test_pack_location_http(true)
        .allow_private_pack_locations(true)
        .with_transfer_timeout(std::time::Duration::from_secs(3));
    // Fourteen chunks 250 ms apart take 3.5 s in all, past the 3 s bound.
    let (url, server) = trickled_location(14, 1024, std::time::Duration::from_millis(250));
    let start = std::time::Instant::now();
    let body = fetch(&transport, &url, 14 * 1024, None).unwrap();
    assert_eq!(body, vec![7; 14 * 1024]);
    assert!(start.elapsed() >= std::time::Duration::from_millis(3500));
    server.join().unwrap();
}

#[test]
fn a_location_body_that_stops_fails_after_the_stall_bound() {
    let transport = NativeHttp::new()
        .unwrap()
        .with_test_pack_location_http(true)
        .allow_private_pack_locations(true)
        .with_transfer_timeout(std::time::Duration::from_millis(300));
    // The answer's head arrives, then nothing for 6 s.
    let (url, server) = trickled_location(1, 1024, std::time::Duration::from_secs(6));
    let start = std::time::Instant::now();
    let error = fetch(&transport, &url, 2 * 1024, None).unwrap_err();
    assert_eq!(error, "pack location transfer stalled: no data for 300 ms");
    assert!(start.elapsed() < std::time::Duration::from_secs(5));
    server.join().unwrap();
}

#[test]
fn pack_location_fetch_requires_explicit_test_opt_in_for_loopback_http() {
    use kit_client::HttpTransport as _;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}/pack", listener.local_addr().unwrap());
    let transport = NativeHttp::new().unwrap().allow_insecure_http(true);
    assert!(!transport.allows_test_pack_location_http());
    let error = fetch(&transport, &url, 4, None).unwrap_err();
    assert!(error.contains("HTTPS"), "{error}");
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    let transport = transport
        .with_test_pack_location_http(true)
        .allow_private_pack_locations(true);
    assert!(transport.allows_test_pack_location_http());
    let transport = transport.with_test_pack_location_http(false);
    assert!(!transport.allows_test_pack_location_http());
}

#[test]
fn pack_location_rejects_loopback_before_connecting() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let transport = NativeHttp::new()
        .unwrap()
        .with_transfer_timeout(std::time::Duration::from_millis(25));
    let url = format!("https://{}/pack", listener.local_addr().unwrap());
    assert!(fetch(&transport, &url, 4, None).is_err());
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn pack_location_fetch_honors_shorter_local_budget() {
    let transport = NativeHttp::new()
        .unwrap()
        .with_test_pack_location_http(true)
        .allow_private_pack_locations(true);
    let (url, server) = location_response(
        b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\npack",
        std::time::Duration::from_millis(300),
    );
    let start = std::time::Instant::now();
    let result = fetch(
        &transport,
        &url,
        4,
        Some(std::time::Duration::from_millis(40)),
    );
    assert!(start.elapsed() < std::time::Duration::from_millis(200));
    assert!(result.is_err());
    server.join().unwrap();
}

#[test]
fn pack_location_rejects_private_literals_before_dispatch() {
    let transport = NativeHttp::new()
        .unwrap()
        .with_transfer_timeout(std::time::Duration::from_millis(20));
    for host in [
        "127.0.0.1",
        "10.1.2.3",
        "169.254.1.1",
        "[::ffff:127.0.0.1]",
        "[::10.1.2.3]",
    ] {
        let url = format!("https://{host}/pack");
        let error = fetch(&transport, &url, 4, None).unwrap_err();
        assert!(error.contains("destination refused"), "{host}: {error}");
    }
}

mod resume {
    //! An interrupted location body continues with `Range` against an exact
    //! `206` with the first answer's strong entity tag. Any other answer
    //! reads the location again from its start, and a location that keeps
    //! stopping ends the fetch, so the client reads the pack from the server.

    use std::time::Duration;

    use kit_core::hash;
    use kit_core::object::{Blob, Object};
    use kit_core::pack::{PackError, PackSpool, PackWriter, pack_key};
    use kit_core::protocol::{
        PACK_BODY_LIMIT, PackKey, PackSink, RestartReason, ResumeOutcome, TransportResult,
    };
    use kit_sync::NativeHttp;
    use kit_test_util::range_server::{RangeServer, Request, Response, honest};

    const ETAG: &str = "\"v1\"";

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

    struct Recording {
        spool: Option<PackSpool>,
        outcomes: Vec<ResumeOutcome>,
        begins: usize,
    }

    impl Recording {
        fn spool(&mut self) -> &mut PackSpool {
            self.spool.as_mut().unwrap()
        }
    }

    impl PackSink for Recording {
        fn begin(&mut self, declared: Option<u64>) -> TransportResult<()> {
            self.begins += 1;
            PackSink::begin(self.spool(), declared)
        }
        fn write(&mut self, bytes: &[u8]) -> TransportResult<()> {
            PackSink::write(self.spool(), bytes)
        }
        fn failed(&self) -> Option<std::io::ErrorKind> {
            self.spool.as_ref().unwrap().failed()
        }
        fn retained(&self) -> u64 {
            PackSink::retained(self.spool.as_ref().unwrap())
        }
        fn resume(&mut self, total: u64, offset: u64) -> TransportResult<()> {
            PackSink::resume(self.spool(), total, offset)
        }
        fn note_resume(&mut self, outcome: ResumeOutcome) {
            self.outcomes.push(outcome);
        }
    }

    struct Fetched {
        fetched: Result<(), String>,
        verified: Result<(), PackError>,
        outcomes: Vec<ResumeOutcome>,
        begins: usize,
        requests: Vec<Request>,
    }

    fn fetch(
        transport: &NativeHttp,
        object: &[u8],
        key: &PackKey,
        timeout: Option<Duration>,
        script: impl Fn(usize, &Request, Response) -> Response + Send + Sync + 'static,
    ) -> Fetched {
        use kit_client::HttpTransport as _;
        use kit_sync::Executor as _;
        let object = object.to_vec();
        let server = RangeServer::start(move |n, request| {
            script(n, request, honest(&object, ETAG, request))
        });
        let mut sink = Recording {
            spool: Some(PackSpool::create(&std::env::temp_dir(), PACK_BODY_LIMIT).unwrap()),
            outcomes: Vec::new(),
            begins: 0,
        };
        let url = format!("{}/pack?signature=test", server.endpoint());
        let fetched = transport.block_on(transport.fetch_pack_location(
            &url,
            PACK_BODY_LIMIT,
            timeout,
            &mut sink,
        ));
        let verified = sink.spool.take().unwrap().finish(key).map(drop);
        Fetched {
            fetched,
            verified,
            outcomes: sink.outcomes,
            begins: sink.begins,
            requests: server.requests(),
        }
    }

    fn transport() -> NativeHttp {
        NativeHttp::new()
            .unwrap()
            .with_test_pack_location_http(true)
            .allow_private_pack_locations(true)
    }

    fn ranged(request: &Request) -> bool {
        request.header("range").is_some()
    }

    #[test]
    fn an_interrupted_location_continues_where_it_stopped() {
        let (object, key) = pack();
        for cut in [1, 17, 4096, object.len() / 2, object.len() - 1] {
            let got = fetch(&transport(), &object, &key, None, move |n, _, answer| {
                if n == 0 {
                    answer.cut_after(cut)
                } else {
                    answer
                }
            });
            got.fetched.unwrap();
            got.verified.unwrap();
            assert_eq!(got.requests.len(), 2, "cut at {cut}");
            assert_eq!(
                got.requests[1].header("range"),
                Some(&*format!("bytes={cut}-"))
            );
            assert_eq!(got.requests[1].header("if-match"), Some(ETAG));
            assert_eq!(
                got.outcomes,
                [ResumeOutcome::Resumed { bytes: cut as u64 }],
                "cut at {cut}"
            );
            assert_eq!(got.begins, 1, "the body begins once");
        }
    }

    #[test]
    fn a_stalled_location_continues_too() {
        let (object, key) = pack();
        let transport = transport().with_transfer_timeout(Duration::from_millis(400));
        let got = fetch(&transport, &object, &key, None, |n, _, answer| {
            if n == 0 {
                answer.cut_after(3000).hold_for(Duration::from_secs(3))
            } else {
                answer
            }
        });
        got.fetched.unwrap();
        got.verified.unwrap();
        assert_eq!(got.outcomes, [ResumeOutcome::Resumed { bytes: 3000 }]);
    }

    #[test]
    fn an_answer_that_is_not_the_rest_reads_the_location_again() {
        let (object, key) = pack();
        let total = object.len();
        let cases: Vec<(
            &str,
            RestartReason,
            Box<dyn Fn(Response) -> Response + Send + Sync>,
        )> = vec![
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
                "wrong length",
                RestartReason::Range,
                Box::new(|mut a| {
                    a.declared = Some(a.body.len() + 1);
                    a
                }),
            ),
            (
                "precondition failed",
                RestartReason::Validator,
                Box::new(|_| Response::new(412, b"")),
            ),
            (
                "range not satisfiable",
                RestartReason::Range,
                Box::new(|_| Response::new(416, b"")),
            ),
        ];
        for (name, reason, tamper) in cases {
            let got = fetch(
                &transport(),
                &object,
                &key,
                None,
                move |n, _, answer| match n {
                    0 => answer.cut_after(100),
                    1 => tamper(answer),
                    _ => answer,
                },
            );
            got.fetched
                .unwrap_or_else(|error| panic!("{name}: {error}"));
            got.verified
                .unwrap_or_else(|error| panic!("{name}: {error:?}"));
            assert_eq!(
                got.outcomes,
                [ResumeOutcome::Restarted { reason }],
                "{name}"
            );
            assert_eq!(got.requests.len(), 3, "{name}");
            assert!(
                ranged(&got.requests[1]) && !ranged(&got.requests[2]),
                "{name}"
            );
            assert_eq!(got.begins, 2, "{name}");
        }
    }

    #[test]
    fn a_server_that_ignores_range_has_its_full_answer_taken() {
        let (object, key) = pack();
        let full = object.clone();
        let got = fetch(
            &transport(),
            &object,
            &key,
            None,
            move |n, _, answer| match n {
                0 => answer.cut_after(100),
                1 => Response::new(200, &full).header("etag", ETAG),
                _ => answer,
            },
        );
        got.fetched.unwrap();
        got.verified.unwrap();
        assert_eq!(got.requests.len(), 2);
        assert_eq!(
            got.outcomes,
            [ResumeOutcome::Restarted {
                reason: RestartReason::Status
            }]
        );
        assert_eq!(got.begins, 2);
    }

    #[test]
    fn without_a_strong_tag_an_interrupted_location_is_not_retried() {
        let (object, key) = pack();
        for tag in [None, Some("W/\"v1\"")] {
            let got = fetch(&transport(), &object, &key, None, move |n, _, answer| {
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
            assert!(got.fetched.is_err(), "{tag:?}");
            assert_eq!(got.requests.len(), 1, "{tag:?}");
            assert!(got.outcomes.is_empty(), "{tag:?}");
        }
    }

    #[test]
    fn a_prefix_that_is_not_the_pack_fails_the_whole_pack_check() {
        let (object, key) = pack();
        let mut damaged = object.clone();
        damaged[50] ^= 1;
        let got = fetch(&transport(), &object, &key, None, move |n, _, answer| {
            if n == 0 {
                let mut first = answer;
                first.body = damaged.clone();
                first.cut_after(100)
            } else {
                answer
            }
        });
        got.fetched.unwrap();
        assert!(
            matches!(got.verified, Err(PackError::KeyMismatch)),
            "{:?}",
            got.verified
        );
    }

    #[test]
    fn a_location_that_keeps_stopping_ends_after_the_resumes_run_out() {
        let (object, key) = pack();
        let got = fetch(&transport(), &object, &key, None, |_, _, answer| {
            answer.cut_after(10)
        });
        assert!(got.fetched.is_err());
        // The first request and three resumes.
        assert_eq!(got.requests.len(), 4);
        assert_eq!(got.outcomes.len(), 3);
    }

    #[test]
    fn the_deadline_covers_every_resume() {
        let (object, key) = pack();
        let got = fetch(
            &transport(),
            &object,
            &key,
            Some(Duration::from_millis(300)),
            |_, _, answer| answer.cut_after(10).hold_for(Duration::from_millis(200)),
        );
        assert_eq!(got.fetched.unwrap_err(), "pack location deadline exceeded");
        assert!(got.requests.len() <= 3);
    }
}
