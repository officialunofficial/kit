//! Integration test for: per-verb-class client timeouts.
//!
//! `ConnectTransport` applies a short `UNARY_TIMEOUT` to cheap unary RPCs
//! (`ListRefs`/`ReadRef`/`UpdateRef`/`AdvanceRefs`/`PackExists`) and a stall
//! bound, `PACK_TRANSFER_TIMEOUT`, to the pack-transfer RPCs
//! (`UploadPack`/`DownloadPack`) — independently configurable via
//! `with_unary_timeout`/`with_pack_transfer_timeout`. A transfer that keeps
//! moving data runs past its stall bound; one that stops is retried on the
//! connection ladder and then fails with the stall's text.
//!
//! This drives a real (in-process) Connect server, per
//! SPEC-TRANSPORT-CONNECT's testing-decisions bar (mirrors
//! `tests/roundtrip.rs`'s "a real server, not a mock standing in for one").
//! Both the `ListRefs` and `DownloadPack` handlers are deliberately slow by
//! the same fixed delay; the test asserts a short `unary_timeout` fails the
//! `ListRefs` call fast while a
//! *longer* `pack_transfer_timeout` on the very same client instance lets
//! the equally-slow `DownloadPack` call succeed — proving the two timeout
//! classes are wired independently rather than sharing one client-wide
//! deadline.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use connectrpc::server::Server;
use connectrpc::{RequestContext, Response, Router, ServiceRequest, ServiceResult, ServiceStream};
use kit_core::protocol::{PackKey, Transport, TransportError};
use kit_transport_connect::{ConnectTransport, generated};

/// Deliberately slow `TransportService`: `list_refs` and `download_pack`
/// each sleep for `delay` before responding. `download_pack` then sends
/// `chunks` chunks of [`CHUNK`] bytes of `7`, `gap` apart, and counts its
/// calls. No other verb is exercised by this test; their bodies are trivial
/// stand-ins that satisfy the trait.
struct SlowService {
    delay: Duration,
    chunks: u64,
    gap: Duration,
    downloads: Arc<AtomicUsize>,
}

const CHUNK: u64 = 1024;

/// The pack a [`SlowService`] serves.
fn pack(chunks: u64) -> Vec<u8> {
    vec![7; usize::try_from(chunks * CHUNK).expect("test pack size")]
}

#[allow(refining_impl_trait)]
impl generated::TransportService for SlowService {
    async fn list_repos(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, generated::ListReposRequest>,
    ) -> ServiceResult<generated::ListReposResponse> {
        Err(connectrpc::ConnectError::unimplemented(
            "unused test method",
        ))
    }

    async fn get_receipt(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, generated::GetReceiptRequest>,
    ) -> ServiceResult<generated::GetReceiptResponse> {
        Err(connectrpc::ConnectError::unimplemented(
            "not implemented yet",
        ))
    }

    // Compile-only stubs for the additive trait methods.
    async fn get_server_info(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, generated::GetServerInfoRequest>,
    ) -> ServiceResult<generated::GetServerInfoResponse> {
        Err(connectrpc::ConnectError::unimplemented(
            "not implemented yet",
        ))
    }

    async fn begin_upload(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, generated::BeginUploadRequest>,
    ) -> ServiceResult<generated::BeginUploadResponse> {
        Err(connectrpc::ConnectError::unimplemented(
            "not implemented yet",
        ))
    }

    async fn upload_part(
        &self,
        _ctx: RequestContext,
        _requests: connectrpc::InboundStream<generated::UploadPartRequest>,
    ) -> ServiceResult<generated::UploadPartResponse> {
        Err(connectrpc::ConnectError::unimplemented(
            "not implemented yet",
        ))
    }

    async fn complete_upload(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, generated::CompleteUploadRequest>,
    ) -> ServiceResult<generated::CompleteUploadResponse> {
        Err(connectrpc::ConnectError::unimplemented(
            "not implemented yet",
        ))
    }

    async fn list_refs(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, generated::ListRefsRequest>,
    ) -> ServiceResult<generated::ListRefsResponse> {
        tokio::time::sleep(self.delay).await;
        Ok(Response::new(generated::ListRefsResponse::default()))
    }

    async fn read_ref(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, generated::ReadRefRequest>,
    ) -> ServiceResult<generated::ReadRefResponse> {
        Ok(Response::new(generated::ReadRefResponse::default()))
    }

    async fn update_ref(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, generated::UpdateRefRequest>,
    ) -> ServiceResult<generated::UpdateRefResponse> {
        Ok(Response::new(generated::UpdateRefResponse::default()))
    }

    async fn advance_refs(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, generated::AdvanceRefsRequest>,
    ) -> ServiceResult<generated::AdvanceRefsResponse> {
        Ok(Response::new(generated::AdvanceRefsResponse::default()))
    }

    async fn pack_exists(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, generated::PackExistsRequest>,
    ) -> ServiceResult<generated::PackExistsResponse> {
        Ok(Response::new(generated::PackExistsResponse::default()))
    }

    async fn upload_pack(
        &self,
        _ctx: RequestContext,
        _requests: connectrpc::InboundStream<generated::UploadPackRequest>,
    ) -> ServiceResult<generated::UploadPackResponse> {
        Ok(Response::new(generated::UploadPackResponse::default()))
    }

    async fn download_pack(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, generated::DownloadPackRequest>,
    ) -> ServiceResult<ServiceStream<generated::DownloadPackResponse>> {
        self.downloads.fetch_add(1, Ordering::SeqCst);
        tokio::time::sleep(self.delay).await;
        let msg = request.to_owned_message();
        let pack_id = msg.pack_id.unwrap_or_default();
        let (chunks, gap) = (self.chunks, self.gap);
        let header = generated::DownloadPackResponse {
            body: Some(
                generated::DownloadPackHeader {
                    total_bytes: Some(chunks * CHUNK),
                    ..Default::default()
                }
                .into(),
            ),
            ..Default::default()
        };
        let body = futures::stream::unfold(0, move |index| {
            let pack_id = pack_id.clone();
            async move {
                if index == chunks {
                    return None;
                }
                tokio::time::sleep(gap).await;
                let chunk = generated::DownloadPackResponse {
                    body: Some(
                        generated::PackChunk {
                            pack_id: Some(pack_id),
                            offset: Some(index * CHUNK),
                            data: Some(pack(1)),
                            last: Some(index + 1 == chunks),
                            ..Default::default()
                        }
                        .into(),
                    ),
                    ..Default::default()
                };
                Some((Ok(chunk), index + 1))
            }
        });
        Response::stream_ok(futures::StreamExt::chain(
            futures::stream::iter([Ok(header)]),
            body,
        ))
    }

    async fn get_authority_generation(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, generated::GetAuthorityGenerationRequest>,
    ) -> ServiceResult<generated::GetAuthorityGenerationResponse> {
        Err(connectrpc::ConnectError::unimplemented(
            "not implemented yet",
        ))
    }
    async fn set_authority_generation(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, generated::SetAuthorityGenerationRequest>,
    ) -> ServiceResult<generated::SetAuthorityGenerationResponse> {
        Err(connectrpc::ConnectError::unimplemented(
            "not implemented yet",
        ))
    }
    async fn get_grant_epoch(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, generated::GetGrantEpochRequest>,
    ) -> ServiceResult<generated::GetGrantEpochResponse> {
        Err(connectrpc::ConnectError::unimplemented(
            "not implemented yet",
        ))
    }

    async fn set_grant_epoch(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, generated::SetGrantEpochRequest>,
    ) -> ServiceResult<generated::SetGrantEpochResponse> {
        Err(connectrpc::ConnectError::unimplemented(
            "not implemented yet",
        ))
    }

    async fn set_repo_visibility(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, generated::SetRepoVisibilityRequest>,
    ) -> ServiceResult<generated::SetRepoVisibilityResponse> {
        Err(connectrpc::ConnectError::unimplemented(
            "not implemented yet",
        ))
    }

    async fn issue_object_url(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, generated::IssueObjectUrlRequest>,
    ) -> ServiceResult<generated::IssueObjectUrlResponse> {
        Err(connectrpc::ConnectError::unimplemented(
            "not implemented yet",
        ))
    }
}

/// Bind a real Connect server on an ephemeral loopback port that runs
/// `service`. Returns the port, a shutdown trigger, and the server thread's
/// join handle — mirrors `tests/roundtrip.rs::spawn_server`.
fn spawn_slow_server(
    service: SlowService,
) -> (
    u16,
    tokio::sync::oneshot::Sender<()>,
    std::thread::JoinHandle<()>,
) {
    let (addr_tx, addr_rx) = mpsc::channel();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

    let handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .expect("build server tokio runtime");
        rt.block_on(async move {
            let bound = Server::bind("127.0.0.1:0")
                .await
                .expect("bind ephemeral loopback port");
            let port = bound
                .local_addr()
                .expect("bound server has a local addr")
                .port();
            addr_tx.send(port).expect("send bound port to test thread");

            let service = Arc::new(service);
            let router = Router::new().add_service(service);

            bound
                .serve_with_graceful_shutdown(router, async {
                    let _ = shutdown_rx.await;
                })
                .await
                .expect("serve TransportService");
        });
    });

    let port = addr_rx.recv().expect("recv bound port");
    (port, shutdown_tx, handle)
}

#[test]
fn unary_timeout_fires_fast_while_pack_transfer_timeout_covers_the_same_delay() {
    // Both handlers sleep 300ms. A 50ms `unary_timeout` cannot cover that;
    // a 5s `pack_transfer_timeout` comfortably can — on the very same
    // client instance, proving the two classes don't share one deadline.
    let handler_delay = Duration::from_millis(300);
    let short_unary_timeout = Duration::from_millis(50);
    let ample_pack_transfer_timeout = Duration::from_secs(5);

    let (port, shutdown, handle) = spawn_slow_server(SlowService {
        delay: handler_delay,
        chunks: 1,
        gap: Duration::ZERO,
        downloads: Arc::default(),
    });
    let uri: http::Uri = format!("http://127.0.0.1:{port}")
        .parse()
        .expect("valid loopback URI");
    let client = ConnectTransport::connect_for_test(uri)
        .with_unary_timeout(short_unary_timeout)
        .with_pack_transfer_timeout(ample_pack_transfer_timeout);

    // -- cheap unary call: must fail, and fail fast ----------------------
    let start = Instant::now();
    let err = client
        .list_refs("")
        .expect_err("a ListRefs call slower than unary_timeout must fail");
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(2),
        "unary_timeout must fire well before the transfer bound \
         (and before the handler's own 300ms delay would have finished \
         naturally is irrelevant — 50ms must win): took {elapsed:?}"
    );
    assert!(
        !matches!(err, TransportError::PackNotFound),
        "expected a timeout-shaped error, got {err:?}"
    );

    // -- pack-transfer call: same slow handler, must still succeed ------
    let key = PackKey::new(kit_core::hash::hash(&pack(1)));
    let start = Instant::now();
    let bytes = client
        .download_blob(&key, None, u64::MAX)
        .expect("a DownloadPack call within pack_transfer_timeout must succeed");
    let elapsed = start.elapsed();
    assert_eq!(bytes, pack(1));
    assert!(
        elapsed >= handler_delay,
        "sanity check: the handler's delay must actually have been waited out, took {elapsed:?}"
    );
    assert!(
        elapsed < ample_pack_transfer_timeout,
        "must succeed comfortably inside the pack-transfer budget, took {elapsed:?}"
    );

    let _ = shutdown.send(());
    handle.join().expect("server thread joins cleanly");
}

fn two_retries() -> kit_core::protocol::BackoffIterator {
    kit_core::protocol::BackoffIterator::with(Duration::ZERO, Duration::ZERO, 2)
}

fn no_sleep(_: Duration) {}

#[test]
fn a_slow_download_that_keeps_moving_outlives_the_stall_bound() {
    // Fourteen chunks 250 ms apart take 3.5 s in all, past the 3 s bound.
    let downloads = Arc::new(AtomicUsize::new(0));
    let (port, shutdown, handle) = spawn_slow_server(SlowService {
        delay: Duration::ZERO,
        chunks: 14,
        gap: Duration::from_millis(250),
        downloads: Arc::clone(&downloads),
    });
    let uri: http::Uri = format!("http://127.0.0.1:{port}")
        .parse()
        .expect("valid loopback URI");
    let client = ConnectTransport::connect_for_test_with_retry(uri, two_retries, no_sleep)
        .with_pack_transfer_timeout(Duration::from_secs(3));
    let key = PackKey::new(kit_core::hash::hash(&pack(14)));
    let start = Instant::now();
    let bytes = client
        .download_blob(&key, None, u64::MAX)
        .expect("a download that keeps moving must not stall");
    assert_eq!(bytes, pack(14));
    assert!(start.elapsed() >= Duration::from_millis(3500));
    assert_eq!(downloads.load(Ordering::SeqCst), 1, "no attempt stalled");
    let _ = shutdown.send(());
    handle.join().expect("server thread joins cleanly");
}

#[test]
fn a_stalled_download_is_retried_then_fails_naming_the_stall() {
    // The header arrives, then nothing for 8 s on every attempt.
    let downloads = Arc::new(AtomicUsize::new(0));
    let (port, shutdown, handle) = spawn_slow_server(SlowService {
        delay: Duration::ZERO,
        chunks: 1,
        gap: Duration::from_secs(8),
        downloads: Arc::clone(&downloads),
    });
    let uri: http::Uri = format!("http://127.0.0.1:{port}")
        .parse()
        .expect("valid loopback URI");
    let client = ConnectTransport::connect_for_test_with_retry(uri, two_retries, no_sleep)
        .with_pack_transfer_timeout(Duration::from_millis(300));
    let key = PackKey::new(kit_core::hash::hash(&pack(1)));
    let start = Instant::now();
    let error = client
        .download_blob(&key, None, u64::MAX)
        .expect_err("a download that stops must fail");
    assert_eq!(
        error.to_string(),
        "remote error: transfer stalled: no data for 300 ms"
    );
    assert_eq!(
        downloads.load(Ordering::SeqCst),
        3,
        "the first attempt and two retries"
    );
    assert!(start.elapsed() < Duration::from_secs(6));
    let _ = shutdown.send(());
    handle.join().expect("server thread joins cleanly");
}

#[test]
fn a_stalled_download_through_a_source_fails_naming_the_stall() {
    // The source the sync commands use reports the stall, not a server
    // error, once the retries are spent.
    let downloads = Arc::new(AtomicUsize::new(0));
    let (port, shutdown, handle) = spawn_slow_server(SlowService {
        delay: Duration::ZERO,
        chunks: 1,
        gap: Duration::from_secs(8),
        downloads: Arc::clone(&downloads),
    });
    let uri: http::Uri = format!("http://127.0.0.1:{port}")
        .parse()
        .expect("valid loopback URI");
    let client = ConnectTransport::connect_for_test_with_retry(uri, two_retries, no_sleep)
        .with_pack_transfer_timeout(Duration::from_millis(300));
    let key = PackKey::new(kit_core::hash::hash(&pack(1)));
    let error = client
        .with_source(|source| source.download_blob(&key, "refs/heads/main"))
        .expect("the source opens")
        .expect_err("a download that stops must fail");
    assert!(
        error
            .to_string()
            .contains("transfer stalled: no data for 300 ms"),
        "{error}"
    );
    assert_eq!(
        downloads.load(Ordering::SeqCst),
        3,
        "the first attempt and two retries"
    );
    let _ = shutdown.send(());
    handle.join().expect("server thread joins cleanly");
}
