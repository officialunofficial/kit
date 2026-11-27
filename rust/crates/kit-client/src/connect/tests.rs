use super::*;

fn pending(value: Option<u32>, header: Option<&str>) -> RemoteError {
    let detail = crate::proto::PendingVerification {
        retry_after_ms: value,
        ..Default::default()
    }
    .encode_to_vec();
    let mut error = RemoteError {
        code: "unavailable".into(),
        message: String::new(),
        details: vec![Detail {
            type_url: "type.googleapis.com/kit.transport.v1.PendingVerification".into(),
            value: Some(STANDARD_NO_PAD.encode(detail)),
        }],
        status: 503,
        headers: HeaderMap::new(),
    };
    if let Some(header) = header {
        error.headers.insert("retry-after", header.parse().unwrap());
    }
    error
}

#[test]
fn only_typed_pending_honors_bounded_retry_hints() {
    for (value, header, milliseconds) in [
        (None, None, 1000),
        (Some(0), None, 1000),
        (Some(2000), Some("5"), 5000),
        (Some(u32::MAX), Some("999999999999999"), 60_000),
    ] {
        assert_eq!(
            pending_delay(&pending(value, header)),
            Some(Duration::from_millis(milliseconds))
        );
    }
    let mut error = pending(Some(2000), Some("5"));
    error.details[0].value = Some("invalid".into());
    assert_eq!(pending_delay(&error), None);
    error = pending(Some(2000), Some("5"));
    error.code = "permission_denied".into();
    assert_eq!(pending_delay(&error), None);
    error = pending(Some(2000), Some("5"));
    error.details.push(error.details[0].clone());
    assert_eq!(pending_delay(&error), None);
}

#[test]
fn streaming_end_errors_and_truncation_fail_closed() {
    for bytes in [
        b"\0".as_slice(),
        b"\0\0\0\0\x05abc",
        b"\x01\0\0\0\0",
        b"\0\0\0\0\0",
    ] {
        assert!(decode_stream(bytes).is_err());
    }
    let mut bytes = Vec::new();
    frame(&mut bytes, b"protobuf").unwrap();
    let end = br#"{"error":{"code":"failed_precondition","message":"ticket rejected"}}"#;
    bytes.push(2);
    bytes.extend_from_slice(&u32::try_from(end.len()).unwrap().to_be_bytes());
    bytes.extend_from_slice(end);
    assert!(
        matches!(decode_stream(&bytes), Err(Error::Remote(error)) if error.code == "failed_precondition")
    );
}

struct ScriptClock {
    now: std::cell::Cell<i64>,
    wake_at: std::cell::Cell<Option<i64>>,
    nonce: std::cell::Cell<u8>,
}
impl Clock for ScriptClock {
    fn now_ms(&self) -> i64 {
        self.now.get()
    }
    fn nonce(&self) -> Result<Hash, String> {
        let next = self.nonce.get() + 1;
        self.nonce.set(next);
        Ok([next; 32])
    }
    async fn wait(&self, duration: Duration) {
        self.now.set(
            self.wake_at
                .take()
                .unwrap_or_else(|| self.now.get() + i64::try_from(duration.as_millis()).unwrap()),
        );
    }
}
struct ScriptSigner;
impl Signer for ScriptSigner {
    fn public_key(&self) -> Hash {
        [1; 32]
    }
    async fn sign(&self, _: &Hash) -> Result<[u8; 64], String> {
        Ok([0; 64])
    }
}
enum Reply {
    Pending,
    ExpiredInTransit(i64),
    Unauthenticated,
    Committed,
    Lost,
}
struct ScriptTransport {
    replies: std::cell::RefCell<std::collections::VecDeque<Reply>>,
    requests: std::cell::RefCell<Vec<Request<Vec<u8>>>>,
}
impl HttpTransport for ScriptTransport {
    async fn send(&self, request: Request<Vec<u8>>, _: usize) -> Result<Response<Vec<u8>>, String> {
        let reply = self
            .replies
            .borrow_mut()
            .pop_front()
            .expect("script has a reply");
        if let Reply::ExpiredInTransit(server_now) = reply {
            let expiry: i64 = request.headers()["x-expires-at"]
                .to_str()
                .unwrap()
                .parse()
                .unwrap();
            assert!(
                expiry < server_now,
                "server clock or transit made this credential expire"
            );
        }
        self.requests.borrow_mut().push(request);
        let (status, content_type, bytes) = match reply {
            Reply::Pending => {
                let detail = crate::proto::PendingVerification {
                    retry_after_ms: Some(2000),
                    ..Default::default()
                }
                .encode_to_vec();
                let error = serde_json::json!({"code":"unavailable", "details":[{
                    "type":"kit.transport.v1.PendingVerification", "value":STANDARD_NO_PAD.encode(detail)
                }]});
                (503, "application/json", error.to_string().into_bytes())
            }
            Reply::ExpiredInTransit(_) | Reply::Unauthenticated => (
                401,
                "application/json",
                br#"{"code":"unauthenticated","message":"credential rejected"}"#.to_vec(),
            ),
            Reply::Committed => (
                200,
                "application/proto",
                crate::proto::AdvanceRefsResponse {
                    outcome: Some(crate::proto::AdvanceOutcome::Committed.into()),
                    ..Default::default()
                }
                .encode_to_vec(),
            ),
            Reply::Lost => return Err("response lost".into()),
        };
        Ok(Response::builder()
            .status(status)
            .header("content-type", content_type)
            .body(bytes)
            .unwrap())
    }
}
fn ready<F: std::future::Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    match future
        .as_mut()
        .poll(&mut std::task::Context::from_waker(std::task::Waker::noop()))
    {
        std::task::Poll::Ready(value) => value,
        std::task::Poll::Pending => panic!("scripted boundaries complete immediately"),
    }
}
fn script(
    replies: impl IntoIterator<Item = Reply>,
    wake_at: Option<i64>,
) -> (ScriptTransport, ScriptClock) {
    (
        ScriptTransport {
            replies: std::cell::RefCell::new(replies.into_iter().collect()),
            requests: std::cell::RefCell::new(Vec::new()),
        },
        ScriptClock {
            now: std::cell::Cell::new(0),
            wake_at: std::cell::Cell::new(wake_at),
            nonce: std::cell::Cell::new(0),
        },
    )
}
fn advance_script(
    transport: &ScriptTransport,
    clock: &ScriptClock,
) -> Result<crate::proto::AdvanceRefsResponse, Error> {
    let destination = Destination::new("https://vcs.example.org".into(), "default".into()).unwrap();
    let rpc = Rpc::signed(transport, &ScriptSigner, clock, &destination, 600_000);
    ready(crate::push::advance(
        &rpc,
        &crate::proto::AdvanceRefsRequest {
            head_ref: Some("refs/heads/main".into()),
            head_expectation: Some(crate::proto::RefExpectation::Missing.into()),
            head_new_id: Some(vec![7; 32]),
            packmap_ref: Some("refs/kit/packmap/main".into()),
            packmap_expectation: Some(crate::proto::RefExpectation::Missing.into()),
            packmap_new_id: Some(vec![8; 32]),
            ticket_ids: vec![vec![9; 32]],
            ..Default::default()
        },
    ))
}
#[test]
fn pending_renews_after_local_expiry_and_once_after_expiry_in_transit() {
    for (wake_at, replies, count) in [
        (300_001, vec![Reply::Pending, Reply::Committed], 2),
        (
            298_000,
            vec![
                Reply::Pending,
                Reply::ExpiredInTransit(301_000),
                Reply::Committed,
            ],
            3,
        ),
    ] {
        let (transport, clock) = script(replies, Some(wake_at));
        assert_eq!(
            advance_script(&transport, &clock)
                .unwrap()
                .outcome
                .unwrap()
                .as_known(),
            Some(crate::proto::AdvanceOutcome::Committed)
        );
        let requests = transport.requests.borrow();
        assert_eq!(requests.len(), count);
        assert!(
            requests
                .iter()
                .all(|request| request.body() == requests[0].body())
        );
        assert_ne!(
            requests[0].headers()["idempotency-key"],
            requests[count - 1].headers()["idempotency-key"]
        );
        if count == 3 {
            assert_eq!(
                requests[0].headers(),
                requests[1].headers(),
                "still locally valid poll preserves identity"
            );
        }
    }
}
#[test]
fn post_pending_authentication_recovery_is_bounded_and_never_hides_response_loss() {
    for (replies, count, authentication) in [
        (
            vec![
                Reply::Pending,
                Reply::ExpiredInTransit(301_000),
                Reply::Unauthenticated,
            ],
            3,
            true,
        ),
        (vec![Reply::Pending, Reply::Lost], 2, false),
        (vec![Reply::Unauthenticated], 1, true),
    ] {
        let (transport, clock) = script(replies, Some(298_000));
        let error = advance_script(&transport, &clock).unwrap_err();
        if authentication {
            assert!(matches!(error, Error::Remote(error) if error.code == "unauthenticated"));
        } else {
            assert!(matches!(error, Error::Transport(_)));
            let requests = transport.requests.borrow();
            assert_eq!(requests[0].headers(), requests[1].headers());
            assert_eq!(requests[0].body(), requests[1].body());
        }
        assert_eq!(transport.requests.borrow().len(), count);
    }
}

#[test]
fn frames_are_yielded_lazily_and_require_a_clean_end() {
    let mut bytes = Vec::new();
    for _ in 0..10_000 {
        frame(&mut bytes, &[]).unwrap();
    }
    let mut frames = Frames::new(&bytes);
    assert!(matches!(frames.next(), Some(Ok(f)) if f.is_empty()));
    assert!(matches!(frames.nth(9_998), Some(Ok(_))));
    assert!(matches!(frames.next(), Some(Err(_))), "no end frame");
    assert!(frames.next().is_none());
}

#[test]
fn destination_accepts_both_namespace_grammars_and_refuses_others() {
    let origin = || "https://vcs.example.org".to_owned();
    let ed = format!("ed25519-{}/repo", "ab".repeat(32));
    for repository in [
        ed.as_str(),
        "019c88c3-a904-7bd1-8a5d-3182a0c6978a/repo",
        "default",
    ] {
        assert!(Destination::new(origin(), repository.into()).is_ok());
    }
    for repository in ["Upper/repo", "root/repo", "ed25519-zz/repo", "ns/Repo"] {
        assert!(Destination::new(origin(), repository.into()).is_err());
    }
}

fn lag(code: &str, message: &str, type_urls: &[&str]) -> RemoteError {
    RemoteError {
        code: code.into(),
        message: message.into(),
        details: type_urls
            .iter()
            .map(|type_url| Detail {
                type_url: (*type_url).into(),
                value: None,
            })
            .collect(),
        status: 503,
        headers: HeaderMap::new(),
    }
}

#[test]
fn membership_lag_is_classified_by_the_typed_detail_alone() {
    for url in [
        "kit.transport.v1.MembershipNotVisible",
        "type.googleapis.com/kit.transport.v1.MembershipNotVisible",
    ] {
        // Whatever the message says, the detail decides.
        let error = lag("unavailable", "something else", &[url]);
        assert!(membership_lag(&error), "{url}");
        assert!(matches!(
            Error::Remote(Box::new(error)).typed(),
            Error::MembershipNotVisible
        ));
    }
}

fn withheld(code: &str, ref_name: &str) -> RemoteError {
    use base64::Engine as _;
    use buffa::Message as _;
    let value = base64::engine::general_purpose::STANDARD.encode(
        crate::proto::ContentWithheld {
            ref_name: Some(ref_name.into()),
            ..Default::default()
        }
        .encode_to_vec(),
    );
    RemoteError {
        code: code.into(),
        message: "never shown".into(),
        details: vec![Detail {
            type_url: "kit.transport.v1.ContentWithheld".into(),
            value: Some(value),
        }],
        status: 403,
        headers: HeaderMap::new(),
    }
}

#[test]
fn one_valid_withheld_detail_on_permission_denied_is_typed() {
    let error = Error::Remote(Box::new(withheld(
        "permission_denied",
        "refs/kit/packmap/main",
    )))
    .typed();
    assert!(matches!(
        &error,
        Error::ContentWithheld { ref_name } if ref_name == "refs/kit/packmap/main"
    ));
    assert_eq!(error.to_string(), "Part of this Kit is withheld.");
}

#[test]
fn every_other_withheld_shape_stays_the_raw_remote_error() {
    let raw =
        |error: RemoteError| matches!(Error::Remote(Box::new(error)).typed(), Error::Remote(_));
    // Another code.
    assert!(raw(withheld("not_found", "refs/heads/main")));
    assert!(raw(withheld("unavailable", "refs/heads/main")));
    // No detail, two details, a malformed value, an oversized ref name.
    let mut none = withheld("permission_denied", "refs/heads/main");
    none.details.clear();
    assert!(raw(none));
    let mut two = withheld("permission_denied", "refs/heads/main");
    two.details.push(two.details[0].clone());
    assert!(raw(two));
    let mut malformed = withheld("permission_denied", "refs/heads/main");
    malformed.details[0].value = Some("%%%".into());
    assert!(raw(malformed));
    assert!(raw(withheld("permission_denied", &"r".repeat(513))));
}

#[test]
fn membership_lag_needs_unavailable_and_a_matching_signal() {
    for error in [
        lag(
            "failed_precondition",
            "repository membership not yet visible",
            &["kit.transport.v1.MembershipNotVisible"],
        ),
        lag("unavailable", "repository membership not yet visible", &[]),
        lag("unavailable", "", &["kit.transport.v1.PendingVerification"]),
    ] {
        assert!(!membership_lag(&error), "{error:?}");
    }
}

/// A sink that keeps its bytes and says how many it can continue from.
#[derive(Default)]
struct Held {
    bytes: Vec<u8>,
    claims: u64,
    resumed: Option<(u64, u64)>,
    outcomes: Vec<ResumeOutcome>,
}

impl PackSink for Held {
    fn begin(&mut self, _: Option<u64>) -> TransportResult<()> {
        self.bytes.clear();
        Ok(())
    }
    fn write(&mut self, bytes: &[u8]) -> TransportResult<()> {
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }
    fn failed(&self) -> Option<std::io::ErrorKind> {
        None
    }
    fn retained(&self) -> u64 {
        self.claims
    }
    fn resume(&mut self, total: u64, offset: u64) -> TransportResult<()> {
        self.resumed = Some((total, offset));
        Ok(())
    }
    fn note_resume(&mut self, outcome: ResumeOutcome) {
        self.outcomes.push(outcome);
    }
}

/// A location sink over `held`, with 40 of its 100 bytes received.
fn partial(held: &mut Held) -> LocationSink<'_> {
    let mut sink = LocationSink::new(held, 100);
    sink.begin(Some(100)).unwrap();
    sink.write(&[1; 40]).unwrap();
    sink
}

#[test]
fn a_location_sink_continues_a_prefix_that_both_sinks_hold() {
    let mut held = Held {
        claims: 40,
        ..Held::default()
    };
    let mut sink = partial(&mut held);
    assert_eq!(sink.retained(), 40);
    sink.resume(100, 40).unwrap();
    sink.write(&[2; 60]).unwrap();
    assert!(sink.verified(&kit_core::hash::hash(
        &[[1; 40].as_slice(), &[2; 60]].concat()
    )));
    sink.note_resume(ResumeOutcome::Resumed { bytes: 40 });
    drop(sink);
    assert_eq!(held.resumed, Some((100, 40)));
    assert_eq!(held.outcomes, [ResumeOutcome::Resumed { bytes: 40 }]);
}

#[test]
fn a_location_sink_refuses_a_continuation_it_cannot_vouch_for() {
    // The inner sink holds a different prefix than was received.
    let mut held = Held {
        claims: 7,
        ..Held::default()
    };
    let mut sink = partial(&mut held);
    assert_eq!(sink.retained(), 0);
    assert!(sink.resume(100, 40).is_err());
    drop(sink);
    assert_eq!(held.resumed, None);

    // The inner sink keeps nothing.
    let mut held = Held::default();
    let mut sink = partial(&mut held);
    assert_eq!(sink.retained(), 0);
    assert!(sink.resume(100, 40).is_err());

    // A length or an offset that is not the received prefix.
    let mut held = Held {
        claims: 40,
        ..Held::default()
    };
    let mut sink = partial(&mut held);
    assert!(sink.resume(99, 40).is_err());
    assert!(sink.resume(100, 39).is_err());
    drop(sink);
    assert_eq!(held.resumed, None);

    // Nothing has been received.
    let mut held = Held {
        claims: 0,
        ..Held::default()
    };
    let mut sink = LocationSink::new(&mut held, 100);
    sink.begin(Some(100)).unwrap();
    assert!(sink.resume(100, 0).is_err());
}
