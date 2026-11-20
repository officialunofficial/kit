#![cfg_attr(not(test), deny(clippy::print_stdout, clippy::print_stderr))]
#![doc = include_str!("../README.md")]
//!
//! kit S3-compatible conditional-write transport.
//!
//! Implements the 7-verb [`Transport`] trait on top of a reqwest
//! blocking client with our own SigV4 signer (see [`sigv4`]). The store
//! must support `If-Match` and `If-None-Match` writes. A ref
//! compare-and-swap sends the MD5 of the expected ref body as
//! `If-Match`, so the store must return the body MD5 as the `ETag` of a
//! single `PUT`.
//!
//! URL shape: `kit+s3://<endpoint>/<bucket>[/prefix]` — credentials are
//! pulled from the `KIT_S3_ACCESS_KEY_ID` / `KIT_S3_SECRET_ACCESS_KEY`
//! environment at `connect` time, and the signing region from
//! `KIT_S3_REGION` (default `us-east-1`). An unset pair does not fail
//! construction; the first signed call surfaces
//! [`TransportError::AccessDenied`].
//!
//! Retry policy mirrors SPEC-TRANSPORT §7 via
//! [`kit_core::protocol::BackoffIterator`]: 5xx, HTTP 408 and 429 retry up to
//! 5 attempts; `412 Precondition Failed` NEVER retries so CAS writes
//! can't silently turn into duplicate PUTs.
//!
//! A pack streams both ways (SPEC-TRANSPORT §6.7). `upload_pack` hashes
//! the body once for the SigV4 payload hash, then sends it in one sized
//! `PUT`, reading it again from offset 0 on every attempt. That `PUT` runs
//! on reqwest's async client, so it can fail on a stall rather than on
//! total time. `download_pack`
//! writes only a `200` answer's body to the sink, as it arrives. Neither
//! holds the pack in memory. Every pack fits one `PUT`: S3 takes up to
//! 5 GiB, and a pack is at most [`PACK_BODY_LIMIT`].

// This crate contains zero `unsafe` — enforce that it stays that way.
#![forbid(unsafe_code)]
// Narrative-heavy module docs fight `doc_markdown`; the
// `duration_suboptimal_units` lint insists on `from_mins(1)` for our 60s
// HTTP timeout which obscures intent (we mean seconds, not minutes).
#![allow(clippy::doc_markdown, clippy::duration_suboptimal_units)]

pub mod sigv4;

use std::env;
use std::io::{self, Read as _};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use kit_core::hash::Hasher;
use kit_core::hash::{Hash, to_hex};
use kit_core::protocol::{
    BackoffIterator, PackKey, RepoCursor, Transport, TransportError, TransportResult, is_retryable,
};
use kit_core::refs::{
    Ref, RefWriteCondition, parse_lowercase_hash, validate_ref_name, validate_ref_prefix,
};
use md5::Md5;
mod tls;

use reqwest::Method;
use reqwest::blocking::{Client, RequestBuilder, Response};
use sha2::{Digest as _, Sha256};

use crate::sigv4::{Credentials, SignedRequest, sha256_hex, sign_request_with_payload_hash};

// Body-size cap for a pack download. Canonical value lives in kit-core.
use kit_core::protocol::{
    PACK_BODY_LIMIT, PackBody, PackSink, RestartReason, ResumeOutcome, Validator, saturating_usize,
};
use kit_core::ref_listing::{MAX_PAGES, RefListing};
/// Body-size cap for a ref body (64 hex + newline + slack).
const REF_BODY_LIMIT: usize = 256;
/// Cap for list XML / small responses (16 MiB).
const REF_LIST_BODY_LIMIT: usize = 16 * 1024 * 1024;

/// HTTP `PUT`-return body cap when we don't care about the response.
const SMALL_RESPONSE_LIMIT: usize = 4 * 1024;

/// Bytes of a pack read at a time: by the hash pass, by the thread that
/// feeds an upload, and from a download's response.
const PACK_IO_CHUNK: usize = 256 * 1024;

/// Chunks of [`PACK_IO_CHUNK`] the thread that reads a pack for an upload
/// may queue ahead of the request that sends them.
const PACK_FEED_DEPTH: usize = 2;

/// The client's timeout for one request, up to its response headers, and
/// for each read of a response body. A pack `PUT` fails once this long
/// passes with no byte of its body taken by the connection and no answer:
/// a bound on silence, not on total time, so a slow upload that keeps
/// moving finishes a pack of any size.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// Environment variable names for credentials.
pub const ENV_ACCESS_KEY: &str = "KIT_S3_ACCESS_KEY_ID";
pub const ENV_SECRET_KEY: &str = "KIT_S3_SECRET_ACCESS_KEY";
/// Environment variable name for the signing region.
pub const ENV_REGION: &str = "KIT_S3_REGION";
/// Signing region used when [`ENV_REGION`] is unset.
pub const DEFAULT_REGION: &str = "us-east-1";

// ---------------------------------------------------------------------------
// Connect / construction
// ---------------------------------------------------------------------------

/// Why the s3 transport refuses every ref delete.
pub const S3_DELETE_REFUSED: &str = "the s3 transport cannot delete a ref conditionally";

/// The transport implementation. Clone-safe — the underlying reqwest
/// client is cheap to share across threads.
pub struct S3Transport {
    endpoint: String,
    bucket: String,
    prefix: Option<String>,
    creds: Credentials,
    client: Client,
    /// Test-only clock override so unit tests are deterministic.
    clock: Clock,
    /// Test-only sleep override so retry tests don't block the suite.
    sleeper: Sleeper,
    /// Backoff ladder constructor — swapped in tests to tighten delays.
    backoff: fn() -> BackoffIterator,
    /// The client and runtime of pack `PUT`s.
    put: PackPut,
    /// How long a pack `PUT` may move nothing: [`REQUEST_TIMEOUT`], shorter
    /// in tests.
    stall: Duration,
}

impl std::fmt::Debug for S3Transport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3Transport")
            .field("endpoint", &self.endpoint)
            .field("bucket", &self.bucket)
            .field("prefix", &self.prefix)
            .field("region", &self.creds.region)
            .finish_non_exhaustive()
    }
}

type Clock = fn() -> i64;
type Sleeper = fn(Duration);

fn default_clock() -> i64 {
    // Pre-1970 wall clock collapses to `0`, which the signer accepts
    // (maps to 1970-01-01). `as i64` can only wrap past year 2262 — we
    // explicitly accept that far-future saturation.
    #[allow(clippy::cast_possible_wrap)]
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        Err(_) => 0,
    }
}

fn default_sleeper(d: Duration) {
    thread::sleep(d);
}

impl S3Transport {
    /// Parse a `kit+s3://<endpoint>/<bucket>[/prefix]` URL and build a
    /// transport. Credentials come from the environment (see
    /// [`ENV_ACCESS_KEY`] / [`ENV_SECRET_KEY`]); if either is unset the
    /// credentials default to empty strings and the first signed call
    /// returns [`TransportError::AccessDenied`].
    ///
    /// The endpoint is the host component in the URL; we rebuild it as
    /// `https://<host>` because the transport only speaks HTTPS.
    pub fn connect(url: &str) -> Result<Self, TransportError> {
        let parsed = parse_s3_url(url)?;
        let endpoint = format!("https://{}", parsed.host);
        let bucket = parsed.bucket;
        let prefix = parsed.prefix;
        let access_key_id = env::var(ENV_ACCESS_KEY).unwrap_or_default();
        let secret_access_key = env::var(ENV_SECRET_KEY).unwrap_or_default();
        let region = env::var(ENV_REGION).unwrap_or_else(|_| DEFAULT_REGION.into());

        let selected = env::var_os("KIT_SSL_CA_FILE");
        let roots = tls::certificates(selected.as_deref().map(std::path::Path::new))?;
        let client = Client::builder()
            .tls_certs_merge(roots.clone())
            .timeout(REQUEST_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| TransportError::ConnectionFailed)?;

        Ok(Self {
            endpoint,
            bucket,
            prefix,
            creds: Credentials {
                access_key_id,
                secret_access_key,
                region,
            },
            client,
            clock: default_clock,
            sleeper: default_sleeper,
            backoff: BackoffIterator::new,
            put: PackPut::with_roots(roots)?,
            stall: REQUEST_TIMEOUT,
        })
    }

    /// Construct a transport directly against an endpoint URL, for tests
    /// (mockito hands us a plain `http://127.0.0.1:PORT` base). The path
    /// component of `endpoint` MUST be empty — only scheme+host\[:port\].
    #[doc(hidden)]
    pub fn with_parts(
        endpoint: impl Into<String>,
        bucket: impl Into<String>,
        prefix: Option<String>,
        creds: Credentials,
    ) -> Result<Self, TransportError> {
        let selected = env::var_os("KIT_SSL_CA_FILE");
        let roots = tls::certificates(selected.as_deref().map(std::path::Path::new))?;
        let client = Client::builder()
            .tls_certs_merge(roots.clone())
            .timeout(REQUEST_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| TransportError::ConnectionFailed)?;
        Ok(Self {
            endpoint: endpoint.into(),
            bucket: bucket.into(),
            prefix: normalize_s3_prefix(prefix)?,
            creds,
            client,
            clock: default_clock,
            sleeper: default_sleeper,
            backoff: BackoffIterator::new,
            put: PackPut::with_roots(roots)?,
            stall: REQUEST_TIMEOUT,
        })
    }

    /// Test-only: expose the resolved credentials so integration tests
    /// outside this crate can assert that [`Self::connect`] actually
    /// read [`ENV_ACCESS_KEY`] / [`ENV_SECRET_KEY`] / [`ENV_REGION`],
    /// rather than merely asserting the constant names. Not exposed via
    /// `Debug` (deliberately, to avoid leaking secrets into logs).
    #[doc(hidden)]
    #[must_use]
    pub fn credentials_for_test(&self) -> (&str, &str, &str) {
        (
            &self.creds.access_key_id,
            &self.creds.secret_access_key,
            &self.creds.region,
        )
    }

    /// Test-only: install a fake clock. The clock returns Unix seconds.
    #[doc(hidden)]
    pub fn set_clock(&mut self, clock: Clock) {
        self.clock = clock;
    }

    /// Test-only: install a fake sleeper so backoff doesn't block the
    /// test suite.
    #[doc(hidden)]
    pub fn set_sleeper(&mut self, sleeper: Sleeper) {
        self.sleeper = sleeper;
    }

    /// Test-only: install a tighter backoff ladder.
    #[doc(hidden)]
    pub fn set_backoff(&mut self, backoff: fn() -> BackoffIterator) {
        self.backoff = backoff;
    }

    // -- Path / key builders --

    /// Build the S3 object key for a pack: `packs/<64-char hex digest>`.
    #[must_use]
    pub fn pack_object_key(digest: &Hash) -> String {
        format!("packs/{}", to_hex(digest))
    }

    /// Build the repository namespace key. Without a URL prefix this is
    /// the canonical repository-relative key; with a prefix it is
    /// `<prefix>/<canonical-key>`.
    fn effective_key(&self, key: &str) -> String {
        match self.prefix.as_deref() {
            Some(prefix) if key.is_empty() => format!("{prefix}/"),
            Some(prefix) => format!("{prefix}/{key}"),
            None => key.to_owned(),
        }
    }

    /// Build the S3 path `/<bucket>/<effective-key>` that the signer will
    /// sign and the client will request.
    fn build_path(&self, key: &str) -> String {
        if key.is_empty() {
            return format!("/{}", self.bucket);
        }
        format!("/{}/{}", self.bucket, self.effective_key(key))
    }

    /// Build a ListObjectsV2 prefix under the URL namespace. Listing is
    /// sent to bucket root (`key = ""`) and scoped only through this query.
    fn effective_list_prefix(&self, prefix: &str) -> String {
        match self.prefix.as_deref() {
            Some(namespace) if prefix.is_empty() => format!("{namespace}/"),
            Some(namespace) => format!("{namespace}/{prefix}"),
            None => prefix.to_owned(),
        }
    }

    fn strip_effective_prefix<'a>(&self, key: &'a str) -> Option<&'a str> {
        let Some(namespace) = self.prefix.as_deref() else {
            return Some(key);
        };
        key.strip_prefix(namespace)?.strip_prefix('/')
    }

    /// Build the canonical query string for `ListObjectsV2` scoped to a
    /// prefix. `prefix` MAY be empty to list every key.
    ///
    /// The query is URI-encoded and key-sorted via
    /// [`sigv4::canonical_query_string`] so the bytes signed match what
    /// real AWS S3 re-derives server-side (a raw `/` in the prefix would
    /// otherwise yield `403 SignatureDoesNotMatch`).
    #[must_use]
    pub fn build_list_query(prefix: &str) -> String {
        sigv4::canonical_query_string(&[("list-type", "2"), ("prefix", prefix)])
    }

    /// Build the canonical `ListObjectsV2` query string for the next page
    /// of a truncated listing, carrying the `continuation-token` returned
    /// by the previous page. Same encoding/sorting rules as
    /// [`Self::build_list_query`].
    #[must_use]
    pub fn build_list_query_continued(prefix: &str, continuation_token: &str) -> String {
        sigv4::canonical_query_string(&[
            ("continuation-token", continuation_token),
            ("list-type", "2"),
            ("prefix", prefix),
        ])
    }

    // -- HTTP core --

    /// Make a signed HTTP request with exponential-backoff retry on
    /// 5xx / 408 / 429 / connection failures. Other 4xx returns
    /// immediately.
    fn http_request(
        &self,
        method: &Method,
        key: &str,
        query: &str,
        payload: Option<&[u8]>,
        extra_headers: &[(&'static str, String)],
        body_limit: Option<usize>,
    ) -> TransportResult<HttpResponse> {
        self.retrying(|| {
            self.http_request_once(method, key, query, payload, extra_headers, body_limit)
                .map_err(AttemptError::from)
        })
    }

    /// Run `attempt` on the SPEC-TRANSPORT §7 ladder: again after a 5xx, a
    /// 408, 429 or a connection failure, until the ladder runs out. Any other
    /// error returns at once.
    fn retrying(
        &self,
        mut attempt: impl FnMut() -> Result<HttpResponse, AttemptError>,
    ) -> TransportResult<HttpResponse> {
        let mut iter = (self.backoff)();
        loop {
            match attempt() {
                Ok(resp) => {
                    let status = resp.status;
                    // Retry on 5xx / 429.
                    if (status == 408 || is_retryable(&TransportError::ServerError { status }))
                        && let Some(d) = iter.next()
                    {
                        (self.sleeper)(d);
                        continue;
                    }
                    return Ok(resp);
                }
                Err(error) => {
                    let retry = matches!(
                        error,
                        AttemptError::Stalled
                            | AttemptError::Retryable(_)
                            | AttemptError::Transport(TransportError::ConnectionFailed)
                    );
                    if retry && let Some(delay) = iter.next() {
                        (self.sleeper)(delay);
                        continue;
                    }
                    return Err(match error {
                        AttemptError::Stalled => TransportError::ConnectionFailed,
                        AttemptError::Retryable(error) | AttemptError::Transport(error) => error,
                    });
                }
            }
        }
    }

    /// A request for `key` signed over `payload_sha256`, the lowercase hex
    /// SHA-256 of the exact body the caller attaches.
    fn signed_request(
        &self,
        method: &Method,
        key: &str,
        query: &str,
        payload_sha256: &str,
        extra_headers: &[(&'static str, String)],
    ) -> RequestBuilder {
        let (url, headers) = self.signed_parts(method, key, query, payload_sha256, extra_headers);
        let mut builder = self.client.request(method.clone(), &url);
        for (name, value) in headers {
            builder = builder.header(name, value);
        }
        builder
    }

    /// The URL and headers of a request for `key` signed over
    /// `payload_sha256`.
    fn signed_parts(
        &self,
        method: &Method,
        key: &str,
        query: &str,
        payload_sha256: &str,
        extra_headers: &[(&'static str, String)],
    ) -> (String, Vec<(&'static str, String)>) {
        let path = self.build_path(key);
        let signed: SignedRequest = sign_request_with_payload_hash(
            &self.creds,
            method_to_str(method),
            &path,
            query,
            payload_sha256,
            &self.endpoint,
            (self.clock)(),
        );

        let url = if query.is_empty() {
            format!("{}{}", self.endpoint, path)
        } else {
            format!("{}{}?{}", self.endpoint, path, query)
        };

        let mut headers = vec![
            ("Authorization", signed.authorization),
            ("x-amz-date", signed.x_amz_date),
            ("x-amz-content-sha256", signed.x_amz_content_sha256),
        ];
        headers.extend(extra_headers.iter().cloned());
        (url, headers)
    }

    fn http_request_once(
        &self,
        method: &Method,
        key: &str,
        query: &str,
        payload: Option<&[u8]>,
        extra_headers: &[(&'static str, String)],
        body_limit: Option<usize>,
    ) -> TransportResult<HttpResponse> {
        let payload_bytes: &[u8] = payload.unwrap_or(&[]);
        let mut builder = self.signed_request(
            method,
            key,
            query,
            &sha256_hex(payload_bytes),
            extra_headers,
        );
        if let Some(bytes) = payload {
            builder = builder
                .header("Content-Length", bytes.len().to_string())
                .body(bytes.to_vec());
        }

        let resp = builder
            .send()
            .map_err(|_| TransportError::ConnectionFailed)?;
        extract_response(resp, body_limit, method == Method::HEAD)
    }

    /// `PUT` `pack` at `object_key` in one request whose body streams from
    /// `pack`. The request is signed over the SHA-256 of one pass over
    /// `pack.len()` bytes from offset 0, and every attempt sends those
    /// bytes, read again from offset 0. An attempt has no total time limit:
    /// it fails once [`REQUEST_TIMEOUT`] passes with no progress, and is
    /// retried like a lost connection.
    ///
    /// # Errors
    /// [`TransportError::ProtocolError`] when `pack` cannot be read or holds
    /// fewer bytes than its length, before or during a send: a local
    /// failure, never retried. [`TransportError::RemoteError`] naming the
    /// stall when the last attempt stalled. Otherwise as
    /// [`Self::http_request`].
    fn put_pack(&self, pack: &dyn PackBody, object_key: &str) -> TransportResult<HttpResponse> {
        let payload_sha256 = pack_sha256(pack)?;
        let stalled = std::cell::Cell::new(false);
        let result = self.retrying(|| {
            let (url, headers) =
                self.signed_parts(&Method::PUT, object_key, "", &payload_sha256, &[]);
            let sent = self.put.send(&url, headers, pack, self.stall);
            stalled.set(matches!(sent, Err(AttemptError::Stalled)));
            sent
        });
        match result {
            Err(TransportError::ConnectionFailed) if stalled.get() => {
                Err(TransportError::RemoteError(stall_text(self.stall)))
            }
            other => other,
        }
    }

    /// `GET` the pack at `object_key` into `sink`. Only a `200` answer's body,
    /// or the rest of it in a `206`, reaches the sink (see [`copy_to_sink`]).
    /// Any other answer's body is never read: the status alone maps to the
    /// error.
    ///
    /// A retried attempt continues the body when the sink holds a prefix of
    /// it ([`PackSink::retained`]) and the first answer gave a strong entity
    /// tag and a length: it asks for the rest with `Range` and `If-Match`,
    /// and takes the body only if the answer is exactly that rest
    /// ([`Validator::accepts`]). Any other answer to the request, a refusal
    /// to range included, reads the pack again from its start, and the sink
    /// begins again. The caller checks the whole pack against its key.
    fn get_pack(&self, object_key: &str, sink: &mut dyn PackSink) -> TransportResult<()> {
        let empty_sha256 = sha256_hex(&[]);
        let mut validator: Option<Validator> = None;
        let resp = self.retrying(|| {
            let mut resume = validator
                .clone()
                .zip(Some(sink.retained()).filter(|&n| n > 0));
            loop {
                let ranged = resume.as_ref().map(|(validator, offset)| {
                    vec![
                        ("Range", Validator::range(*offset)),
                        ("If-Match", validator.etag().to_owned()),
                    ]
                });
                let resp = self
                    .signed_request(
                        &Method::GET,
                        object_key,
                        "",
                        &empty_sha256,
                        ranged.as_deref().unwrap_or_default(),
                    )
                    .send()
                    .map_err(|_| TransportError::ConnectionFailed)?;
                let status = resp.status().as_u16();
                if let Some((held, offset)) = &resume {
                    match status {
                        206 => {
                            let accepted = held.accepts(
                                *offset,
                                status,
                                header(&resp, "etag"),
                                header(&resp, "content-range"),
                                resp.content_length(),
                            );
                            if let Err(reason) = accepted {
                                sink.note_resume(ResumeOutcome::Restarted { reason });
                                resume = None;
                                continue;
                            }
                            sink.note_resume(ResumeOutcome::Resumed { bytes: *offset });
                            copy_to_sink(resp, sink, Some((held.total(), *offset)))?;
                            return Ok(HttpResponse {
                                status: 200,
                                body: Vec::new(),
                            });
                        }
                        412 | 416 => {
                            let reason = if status == 412 {
                                RestartReason::Validator
                            } else {
                                RestartReason::Range
                            };
                            sink.note_resume(ResumeOutcome::Restarted { reason });
                            resume = None;
                            continue;
                        }
                        200 => sink.note_resume(ResumeOutcome::Restarted {
                            reason: RestartReason::Status,
                        }),
                        _ => {}
                    }
                }
                if status == 200 {
                    validator = Validator::new(header(&resp, "etag"), resp.content_length());
                    copy_to_sink(resp, sink, None)?;
                }
                return Ok(HttpResponse {
                    status,
                    body: Vec::new(),
                });
            }
        })?;
        match resp.status {
            200 => Ok(()),
            404 => Err(TransportError::PackNotFound),
            403 | 401 => Err(TransportError::AccessDenied),
            s => Err(TransportError::ServerError { status: s }),
        }
    }
}

/// The value of response header `name`, when it is text.
fn header<'a>(resp: &'a Response, name: &str) -> Option<&'a str> {
    resp.headers().get(name)?.to_str().ok()
}

/// The lowercase hex SHA-256 of `pack`'s `len()` bytes, read once from
/// offset 0.
///
/// # Errors
/// [`TransportError::ProtocolError`] when `pack` cannot be read or ends
/// early: a local failure, never retried.
fn pack_sha256(pack: &dyn PackBody) -> TransportResult<String> {
    let mut reader = pack
        .read_from(0)
        .map_err(|_| TransportError::ProtocolError)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; PACK_IO_CHUNK];
    let mut left = pack.len();
    while left > 0 {
        let want = saturating_usize(left).min(buf.len());
        reader
            .read_exact(&mut buf[..want])
            .map_err(|_| TransportError::ProtocolError)?;
        hasher.update(&buf[..want]);
        left -= want as u64;
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Pack `PUT`s run on reqwest's async client, each attempt on a runtime of
/// its own. The blocking client bounds a request that has a body only in
/// total, and cannot end one that stopped moving; here a watchdog can.
///
/// The client keeps no idle connection: a connection lives on the runtime
/// of its attempt, which is shut down when the attempt ends. That shutdown
/// drops the request body still held by the connection, which frees the
/// thread feeding it.
struct PackPut {
    client: reqwest::Client,
}

/// Why a pack `PUT` attempt failed.
enum AttemptError {
    /// No byte moved for the stall bound.
    Stalled,
    Transport(TransportError),
    Retryable(TransportError),
}

impl From<TransportError> for AttemptError {
    fn from(error: TransportError) -> Self {
        Self::Transport(error)
    }
}

impl PackPut {
    fn with_roots(roots: Vec<reqwest::Certificate>) -> Result<Self, TransportError> {
        let client = reqwest::Client::builder()
            .tls_certs_merge(roots)
            .redirect(reqwest::redirect::Policy::none())
            .pool_max_idle_per_host(0)
            .build()
            .map_err(|_| TransportError::ConnectionFailed)?;
        Ok(Self { client })
    }

    /// `PUT` `pack.len()` bytes read from `pack` at offset 0 to `url`, and
    /// read a success's body of at most [`SMALL_RESPONSE_LIMIT`] bytes.
    ///
    /// A scoped thread reads `pack` and hands its bytes over in chunks of
    /// [`PACK_IO_CHUNK`], at most [`PACK_FEED_DEPTH`] ahead, so the upload
    /// holds a few chunks, never the pack. Each chunk the connection takes,
    /// the answer's head and each chunk of the answer's body is progress;
    /// `stall` with none ends the attempt.
    ///
    /// # Errors
    /// [`TransportError::ProtocolError`] when `pack` cannot be read or ends
    /// early: a local failure, never retried. [`AttemptError::Stalled`] after
    /// `stall` with no progress. [`TransportError::ConnectionFailed`] for any
    /// other failure to send, a thread or runtime that cannot start
    /// included. A refused 4xx upload other than 408 or 429 returns
    /// [`TransportError::RemoteError`] with its status and S3 code.
    fn send(
        &self,
        url: &str,
        headers: Vec<(&'static str, String)>,
        pack: &dyn PackBody,
        stall: Duration,
    ) -> Result<HttpResponse, AttemptError> {
        let len = pack.len();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| TransportError::ConnectionFailed)?;
        thread::scope(|scope| {
            let (tx, rx) = tokio::sync::mpsc::channel(PACK_FEED_DEPTH);
            let feeder = thread::Builder::new()
                .spawn_scoped(scope, move || feed(pack, len, &tx))
                .map_err(|_| TransportError::ConnectionFailed)?;
            let progress = Arc::new(Progress::new());
            let ready = Arc::new(tokio::sync::Notify::new());
            let notified = Arc::clone(&ready).notified_owned();
            let wait = (stall / 2).min(Duration::from_secs(1));
            let mut request = self
                .client
                .put(url)
                .header(reqwest::header::CONTENT_LENGTH, len)
                .header(reqwest::header::EXPECT, "100-continue")
                .body(reqwest::Body::wrap(FedBody {
                    rx,
                    gate: Some(Box::pin(async move {
                        let _ = tokio::time::timeout(wait, notified).await;
                    })),
                    rest: bytes::Bytes::new(),
                    len,
                    progress: Arc::clone(&progress),
                }));
            for (name, value) in headers {
                request = request.header(name, value);
            }
            let mut request: http::Request<reqwest::Body> = request
                .build()
                .map_err(|_| TransportError::ProtocolError)?
                .try_into()
                .map_err(|_| TransportError::ProtocolError)?;
            hyper::ext::on_informational(&mut request, move |response| {
                if response.status() == http::StatusCode::CONTINUE {
                    ready.notify_one();
                }
            });
            let request =
                reqwest::Request::try_from(request).map_err(|_| TransportError::ProtocolError)?;
            let exchange = async {
                let mut response = self
                    .client
                    .execute(request)
                    .await
                    .map_err(|_| TransportError::ConnectionFailed)?;
                progress.mark();
                let status = response.status().as_u16();
                if (400..500).contains(&status) && !matches!(status, 408 | 429) {
                    return Err(client_error(&mut response, status, stall / 2).await);
                }
                let mut body = Vec::new();
                if (200..300).contains(&status) {
                    while let Some(chunk) = response
                        .chunk()
                        .await
                        .map_err(|_| TransportError::ConnectionFailed)?
                    {
                        progress.mark();
                        if body.len() + chunk.len() > SMALL_RESPONSE_LIMIT {
                            return Err(
                                TransportError::PayloadTooLarge(body.len() + chunk.len()).into()
                            );
                        }
                        body.extend_from_slice(&chunk);
                    }
                }
                Ok(HttpResponse { status, body })
            };
            let sent = runtime.block_on(watched(exchange, stall, &progress));
            // The connection task may still hold the body. Shutting the
            // runtime down drops it, and with it the body's receiver, which
            // ends the feeder's sends.
            runtime.shutdown_background();
            match feeder.join() {
                Ok(Ok(())) => match sent {
                    Some(result) => result,
                    None => Err(AttemptError::Stalled),
                },
                Ok(Err(_)) | Err(_) => Err(TransportError::ProtocolError.into()),
            }
        })
    }
}

/// Keep a refused upload's status even when its advisory body is cut short.
/// Only the bounded S3 code is reported; the body can contain credentials.
async fn client_error(
    response: &mut reqwest::Response,
    status: u16,
    timeout: Duration,
) -> AttemptError {
    let mut code = response
        .headers()
        .get("x-amz-error-code")
        .and_then(|value| value.to_str().ok())
        .and_then(s3_code);
    if code.is_none() {
        let mut body = Vec::new();
        let read = async {
            while let Ok(Some(chunk)) = response.chunk().await {
                if body.len() + chunk.len() > SMALL_RESPONSE_LIMIT {
                    break;
                }
                body.extend_from_slice(&chunk);
            }
        };
        let _ = tokio::time::timeout(timeout, read).await;
        code = std::str::from_utf8(&body)
            .ok()
            .and_then(|text| extract_element(text, "Code"))
            .and_then(|value| s3_code(&value));
    }
    let transient = matches!(
        code.as_deref(),
        Some("RequestTimeout" | "RequestTimeoutException" | "InternalError" | "SlowDown")
    );
    let error = TransportError::RemoteError(format!(
        "S3 HTTP {status}: {}",
        code.as_deref().unwrap_or("unknown error code")
    ));
    if transient {
        AttemptError::Retryable(error)
    } else {
        AttemptError::Transport(error)
    }
}

fn s3_code(value: &str) -> Option<String> {
    (!value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'))
    .then(|| value.to_owned())
}

/// The time a pack `PUT` last moved, as nanoseconds from its start.
struct Progress {
    start: tokio::time::Instant,
    last: AtomicU64,
}

impl Progress {
    fn new() -> Self {
        Self {
            start: tokio::time::Instant::now(),
            last: AtomicU64::new(0),
        }
    }

    fn mark(&self) {
        let elapsed = u64::try_from(self.start.elapsed().as_nanos()).unwrap_or(u64::MAX);
        self.last.fetch_max(elapsed, Ordering::Relaxed);
    }

    /// When the attempt stalls if nothing moves before then.
    fn stalls_at(&self, stall: Duration) -> tokio::time::Instant {
        let quiet_since = Duration::from_nanos(self.last.load(Ordering::Relaxed));
        self.start
            .checked_add(quiet_since.saturating_add(stall))
            .unwrap_or_else(|| self.start + Duration::from_hours(30 * 365 * 24))
    }
}

/// Run `future` until it finishes, or `None` once `stall` passes with no
/// [`Progress::mark`]. Each wake rechecks the last mark, so an upload that
/// keeps moving keeps going.
async fn watched<F: std::future::Future>(
    future: F,
    stall: Duration,
    progress: &Progress,
) -> Option<F::Output> {
    let mut future = std::pin::pin!(future);
    loop {
        let at = progress.stalls_at(stall);
        if let Ok(output) = tokio::time::timeout_at(at, future.as_mut()).await {
            return Some(output);
        }
        if tokio::time::Instant::now() >= progress.stalls_at(stall) {
            return None;
        }
    }
}

/// The failure text of a pack `PUT` that moved nothing for `stall`.
fn stall_text(stall: Duration) -> String {
    if stall.subsec_nanos() == 0 {
        format!("transfer stalled: no data for {} s", stall.as_secs())
    } else {
        format!("transfer stalled: no data for {} ms", stall.as_millis())
    }
}

/// Read `len` bytes of `pack` from offset 0 into `tx`, a chunk at a time.
/// It stops without error when the receiver is gone: the request ended,
/// whatever its outcome. A read failure, a short body included, goes to the
/// receiver too, so the request ends, and is returned.
fn feed(
    pack: &dyn PackBody,
    len: u64,
    tx: &tokio::sync::mpsc::Sender<io::Result<Vec<u8>>>,
) -> Result<(), io::ErrorKind> {
    let fail = |err: io::Error| {
        let kind = err.kind();
        let _ = tx.blocking_send(Err(err));
        Err(kind)
    };
    let mut reader = match pack.read_from(0) {
        Ok(reader) => reader,
        Err(err) => return fail(err),
    };
    let mut left = len;
    while left > 0 {
        let mut chunk = vec![0u8; saturating_usize(left).min(PACK_IO_CHUNK)];
        if let Err(err) = reader.read_exact(&mut chunk) {
            return fail(err);
        }
        left -= chunk.len() as u64;
        if tx.blocking_send(Ok(chunk)).is_err() {
            return Ok(());
        }
    }
    Ok(())
}

/// The most bytes of a pack `PUT`'s body handed to the connection at once.
/// The connection takes the next slice only once it has written the
/// previous ones, so each take is progress; a whole [`PACK_IO_CHUNK`] would
/// leave a slow link silent for longer between takes.
const PUT_SLICE: usize = 64 * 1024;

/// The body a pack `PUT` sends: the chunks [`feed`] queues, in order and in
/// slices of at most [`PUT_SLICE`], then its end once the feeder is done.
/// Handing a slice to the connection is progress.
struct FedBody {
    // Wait for 100 Continue or a bounded fallback before sending any bytes.
    gate: Option<std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + Sync>>>,
    rx: tokio::sync::mpsc::Receiver<io::Result<Vec<u8>>>,
    /// What is left of the chunk being sent.
    rest: bytes::Bytes,
    len: u64,
    progress: Arc<Progress>,
}

impl http_body::Body for FedBody {
    type Data = bytes::Bytes;
    type Error = io::Error;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        if let Some(gate) = self.gate.as_mut() {
            std::task::ready!(gate.as_mut().poll(cx));
            self.gate = None;
        }
        if self.rest.is_empty() {
            match std::task::ready!(self.rx.poll_recv(cx)) {
                Some(Ok(chunk)) => self.rest = bytes::Bytes::from(chunk),
                Some(Err(err)) => return std::task::Poll::Ready(Some(Err(err))),
                None => return std::task::Poll::Ready(None),
            }
        }
        let take = self.rest.len().min(PUT_SLICE);
        let slice = self.rest.split_to(take);
        self.progress.mark();
        std::task::Poll::Ready(Some(Ok(http_body::Frame::data(slice))))
    }

    fn size_hint(&self) -> http_body::SizeHint {
        http_body::SizeHint::with_exact(self.len)
    }
}

/// Write a `200` answer's body to `sink` as it arrives, a chunk at a time,
/// or with `resume` as `(total, offset)` the rest of a body from `offset`.
///
/// A body's `Content-Length`, when present, goes to [`PackSink::begin`]
/// before any byte is read, so a body over [`PACK_BODY_LIMIT`] or the sink's
/// limit is refused unread, and the sink refuses bytes past it. Without one,
/// the sink's limit and [`PACK_BODY_LIMIT`] bound the body. The rest of a
/// body goes to [`PackSink::resume`] instead, which keeps what the sink took.
///
/// # Errors
/// [`TransportError::PayloadTooLarge`] past a limit; the sink's error;
/// [`TransportError::ConnectionFailed`] when the body cannot be read.
fn copy_to_sink(
    mut resp: Response,
    sink: &mut dyn PackSink,
    resume: Option<(u64, u64)>,
) -> TransportResult<()> {
    let mut taken = if let Some((total, offset)) = resume {
        if total > PACK_BODY_LIMIT {
            return Err(TransportError::PayloadTooLarge(saturating_usize(total)));
        }
        sink.resume(total, offset)?;
        offset
    } else {
        let declared = resp.content_length();
        if let Some(len) = declared.filter(|&len| len > PACK_BODY_LIMIT) {
            return Err(TransportError::PayloadTooLarge(saturating_usize(len)));
        }
        sink.begin(declared)?;
        0
    };
    let mut buf = vec![0u8; PACK_IO_CHUNK];
    loop {
        let n = resp
            .read(&mut buf)
            .map_err(|_| TransportError::ConnectionFailed)?;
        if n == 0 {
            return Ok(());
        }
        taken += n as u64;
        if taken > PACK_BODY_LIMIT {
            return Err(TransportError::PayloadTooLarge(saturating_usize(taken)));
        }
        sink.write(&buf[..n])?;
    }
}

struct HttpResponse {
    status: u16,
    body: Vec<u8>,
}

/// The status of `resp`, and its body when it is a success. An error
/// answer's body is never read: callers map the status alone, and a store's
/// error document (S3 `NoSuchKey` names the key, request and host) may be
/// longer than the limit of the body a success would carry.
fn extract_response(
    resp: Response,
    body_limit: Option<usize>,
    is_head: bool,
) -> TransportResult<HttpResponse> {
    let status = resp.status().as_u16();
    let body = if is_head || !(200..300).contains(&status) {
        Vec::new()
    } else if let Some(limit) = body_limit {
        // Read at most `limit + 1` bytes. The extra byte shows that the
        // body is over the limit. The read stops there, so a hostile
        // server cannot make the client buffer more than the limit.
        let cap = u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1);
        let mut body = Vec::new();
        resp.take(cap)
            .read_to_end(&mut body)
            .map_err(|_| TransportError::ConnectionFailed)?;
        if body.len() > limit {
            // Non-retryable: fetching the same oversized object again
            // would exceed the limit again. A 507 status would be
            // retryable, so this error is a distinct kind.
            return Err(TransportError::PayloadTooLarge(body.len()));
        }
        body
    } else {
        // Body not needed (e.g. `HEAD` response already has no body, or
        // the status is retryable and the caller discards).
        Vec::new()
    };
    Ok(HttpResponse { status, body })
}

fn method_to_str(m: &Method) -> &'static str {
    match *m {
        Method::PUT => "PUT",
        Method::HEAD => "HEAD",
        Method::DELETE => "DELETE",
        Method::POST => "POST",
        // Default to "GET" for GET (and any unrecognised method) — the S3
        // transport only issues the five verbs above so any other value
        // here indicates a bug, but we prefer a safe default to a panic.
        _ => "GET",
    }
}

// ---------------------------------------------------------------------------
// URL parsing
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct ParsedS3Url {
    host: String,
    bucket: String,
    prefix: Option<String>,
}

/// Accept `kit+s3://<host>/<bucket>[/prefix]` and return host/bucket/prefix.
/// The host component stays intact so we can rebuild the HTTPS endpoint.
fn parse_s3_url(url: &str) -> Result<ParsedS3Url, TransportError> {
    let rest = url
        .strip_prefix("kit+s3://")
        .ok_or_else(|| TransportError::InvalidRef(format!("not a kit+s3 URL: {url}")))?;
    let Some((host, tail)) = rest.split_once('/') else {
        return Err(TransportError::InvalidRef(
            "kit+s3 URL missing bucket".into(),
        ));
    };
    if host.is_empty() {
        return Err(TransportError::InvalidRef("kit+s3 URL empty host".into()));
    }
    let (bucket, raw_prefix) = match tail.split_once('/') {
        Some((b, p)) if !p.is_empty() => (b, Some(p.to_owned())),
        Some((b, _)) => (b, None),
        None => (tail, None),
    };
    if bucket.is_empty() {
        return Err(TransportError::InvalidRef("kit+s3 URL empty bucket".into()));
    }
    Ok(ParsedS3Url {
        host: host.to_owned(),
        bucket: bucket.to_owned(),
        prefix: normalize_s3_prefix(raw_prefix)?,
    })
}

fn normalize_s3_prefix(prefix: Option<String>) -> Result<Option<String>, TransportError> {
    let Some(prefix) = prefix else {
        return Ok(None);
    };
    if prefix.is_empty()
        || prefix.starts_with('/')
        || prefix.ends_with('/')
        || prefix.contains("//")
        || prefix.contains('\\')
    {
        return Err(TransportError::InvalidRef(format!(
            "invalid S3 prefix: {prefix}"
        )));
    }
    for segment in prefix.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(TransportError::InvalidRef(format!(
                "invalid S3 prefix: {prefix}"
            )));
        }
        if !segment.bytes().all(is_safe_s3_prefix_byte) {
            return Err(TransportError::InvalidRef(format!(
                "invalid S3 prefix: {prefix}"
            )));
        }
    }
    Ok(Some(prefix))
}

fn is_safe_s3_prefix_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')
}

// ---------------------------------------------------------------------------
// MD5 of wire-format ref — ETag for CAS
// ---------------------------------------------------------------------------

/// Format a hash as the on-the-wire ref body: 64 hex chars + LF.
fn format_ref_wire(h: &Hash) -> Vec<u8> {
    let mut out = Vec::with_capacity(65);
    out.extend_from_slice(to_hex(h).as_bytes());
    out.push(b'\n');
    out
}

/// Wrap `value` in double quotes to produce the `"<md5>"` ETag the store returns.
fn quoted_md5(wire: &[u8]) -> String {
    let mut h = Md5::new();
    h.update(wire);
    let digest = h.finalize();
    format!("\"{}\"", hex::encode(digest))
}

// ---------------------------------------------------------------------------
// Transport impl
// ---------------------------------------------------------------------------

impl Transport for S3Transport {
    fn supports_attestations(&self) -> bool {
        true
    }
    fn write_attestmap(
        &self,
        condition: RefWriteCondition,
        tip: &Hash,
        _keys: &[PackKey],
    ) -> TransportResult<()> {
        if matches!(condition, RefWriteCondition::Any) {
            return Err(TransportError::ProtocolError);
        }
        self.update_ref(kit_core::refs::ATTESTMAP_REF, condition, tip)
    }

    /// The cursor of SPEC-TRANSPORT §6.8: a digest of the key, `ETag` and
    /// `LastModified` of every object under `refs/`, read from the listing
    /// alone. It costs one request per 1,000 refs and no ref read.
    fn repo_cursor(&self) -> TransportResult<Option<RepoCursor>> {
        let query_prefix = self.effective_list_prefix("refs/");
        let mut listing = RefListing::<String>::new(MAX_PAGES);
        let mut digest = Hasher::new();
        digest.update(CURSOR_DOMAIN);
        loop {
            if !listing.can_request() {
                return Err(invalid_listing());
            }
            let query = match listing.cursor() {
                "" => Self::build_list_query(&query_prefix),
                token => Self::build_list_query_continued(&query_prefix, token),
            };
            let resp = self.http_request(
                &Method::GET,
                "",
                &query,
                None,
                &[],
                Some(REF_LIST_BODY_LIMIT),
            )?;
            match resp.status {
                200 => {}
                403 | 401 => return Err(TransportError::AccessDenied),
                s => return Err(TransportError::ServerError { status: s }),
            }
            let Some(page) = parse_cursor_page(&resp.body) else {
                // An entry without an `ETag` or `LastModified` cannot vouch
                // for the ref it names.
                return Ok(None);
            };
            let keys = page.entries.iter().map(|e| e.key.clone()).collect();
            for entry in &page.entries {
                for field in [&entry.key, &entry.etag, &entry.last_modified] {
                    digest.update(&(field.len() as u64).to_le_bytes());
                    digest.update(field.as_bytes());
                }
            }
            if listing
                .push(keys, page.next_continuation_token, |key| key)
                .map_err(|_| invalid_listing())?
            {
                break;
            }
        }
        RepoCursor::new(&digest.finalize()).map(Some)
    }

    /// Streams the body: one pass hashes it for the SigV4 payload hash,
    /// then one sized `PUT` sends it, read again from offset 0 on every
    /// attempt. A body over [`PACK_BODY_LIMIT`] is refused before any read.
    fn upload_pack(
        &self,
        pack: &dyn PackBody,
        key: &PackKey,
        _head_ref: Option<&str>,
    ) -> TransportResult<()> {
        if pack.len() > PACK_BODY_LIMIT {
            return Err(TransportError::PayloadTooLarge(saturating_usize(
                pack.len(),
            )));
        }
        let resp = self.put_pack(pack, &Self::pack_object_key(key.as_bytes()))?;
        match resp.status {
            200 | 201 => Ok(()),
            403 | 401 => Err(TransportError::AccessDenied),
            s => Err(TransportError::ServerError { status: s }),
        }
    }

    /// Streams a `200` answer's body into `sink` as it arrives, its
    /// `Content-Length` declared first. No other answer's body reaches it.
    fn download_pack(
        &self,
        key: &PackKey,
        _ref_hint: Option<&str>,
        sink: &mut dyn PackSink,
    ) -> TransportResult<()> {
        self.get_pack(&Self::pack_object_key(key.as_bytes()), sink)
    }

    fn pack_exists(&self, key: &PackKey, _ref_hint: Option<&str>) -> TransportResult<bool> {
        let object_key = Self::pack_object_key(key.as_bytes());
        let resp = self.http_request(&Method::HEAD, &object_key, "", None, &[], None)?;
        match resp.status {
            200 => Ok(true),
            404 => Ok(false),
            403 | 401 => Err(TransportError::AccessDenied),
            s => Err(TransportError::ServerError { status: s }),
        }
    }

    /// Refused, with no request sent (SPEC-TRANSPORT §6.3). A conditional
    /// `DELETE` is not something every S3 store honours, and one that
    /// ignores `If-Match` would delete without the check. So this transport
    /// deletes nothing, and the default [`Transport::delete_refs`] refuses
    /// at its first step, before any write.
    fn delete_ref(&self, _name: &str, _expected: &Hash) -> TransportResult<()> {
        Err(TransportError::Unsupported(S3_DELETE_REFUSED))
    }

    fn update_ref(
        &self,
        name: &str,
        condition: RefWriteCondition,
        hash: &Hash,
    ) -> TransportResult<()> {
        if !validate_ref_name(name) {
            return Err(TransportError::InvalidRef(name.to_owned()));
        }
        let wire = format_ref_wire(hash);
        let mut extra: Vec<(&'static str, String)> = Vec::new();
        match condition {
            RefWriteCondition::Any => {}
            RefWriteCondition::Missing => {
                extra.push(("If-None-Match", "*".into()));
            }
            RefWriteCondition::Match(expected) => {
                let expected_wire = format_ref_wire(&expected);
                extra.push(("If-Match", quoted_md5(&expected_wire)));
            }
        }
        let resp = self.http_request(
            &Method::PUT,
            name,
            "",
            Some(&wire),
            &extra,
            Some(SMALL_RESPONSE_LIMIT),
        )?;
        match resp.status {
            200 | 201 => Ok(()),
            409 | 412 => Err(TransportError::RefConflict),
            403 | 401 => Err(TransportError::AccessDenied),
            s => Err(TransportError::ServerError { status: s }),
        }
    }

    fn read_ref(&self, name: &str) -> TransportResult<Option<Hash>> {
        if !validate_ref_name(name) {
            return Err(TransportError::InvalidRef(name.to_owned()));
        }
        let resp = self.http_request(&Method::GET, name, "", None, &[], Some(REF_BODY_LIMIT))?;
        match resp.status {
            200 => parse_ref_body(&resp.body).map(Some),
            404 => Ok(None),
            403 | 401 => Err(TransportError::AccessDenied),
            s => Err(TransportError::ServerError { status: s }),
        }
    }

    fn list_refs(&self, prefix: &str) -> TransportResult<Vec<Ref>> {
        if !validate_ref_prefix(prefix) {
            return Err(TransportError::InvalidRef(prefix.to_owned()));
        }
        let query_prefix = self.effective_list_prefix(prefix);

        // Trim a trailing '/' so suffix extraction below matches the
        // canonical memory/file transports: `list_refs("refs/heads")`
        // and `list_refs("refs/heads/")` both yield `"main"`, never
        // `"/main"` (which `validate_ref_name` would reject, silently
        // dropping the ref).
        let prefix_trimmed = prefix.trim_end_matches('/');

        // Paginate: ListObjectsV2 caps each page at 1000 keys and signals
        // more via IsTruncated + NextContinuationToken. Without this loop
        // a namespace with >1000 ref objects returns a silently truncated
        // ref list, corrupting fetch/sync decisions.
        // The shared accumulator bounds pages, retained bytes and cursor
        // size, and rejects unordered pages and a repeated token.
        let mut listing = RefListing::<String>::new(MAX_PAGES);
        loop {
            if !listing.can_request() {
                return Err(invalid_listing());
            }
            let query = match listing.cursor() {
                "" => Self::build_list_query(&query_prefix),
                token => Self::build_list_query_continued(&query_prefix, token),
            };
            let resp = self.http_request(
                &Method::GET,
                "",
                &query,
                None,
                &[],
                Some(REF_LIST_BODY_LIMIT),
            )?;
            match resp.status {
                200 => {}
                403 | 401 => return Err(TransportError::AccessDenied),
                s => return Err(TransportError::ServerError { status: s }),
            }
            let page = parse_list_page(&resp.body);
            if listing
                .push(page.keys, page.next_continuation_token, |key| key)
                .map_err(|_| invalid_listing())?
            {
                break;
            }
        }
        let keys = listing.finish().map_err(|_| invalid_listing())?;

        // Each candidate is a listed key that names a ref of this listing,
        // with its suffix-only name. S3's `ListObjectsV2` `prefix` query is
        // a literal string prefix with no path-component awareness, so a
        // request for ".../refs/heads/feat" can legitimately come back with
        // a key for ".../refs/heads/featx": this client-side check is the
        // only place that boundary is enforced (SPEC-REFS §4); it MUST NOT
        // accept a match that isn't followed by either a `/` or the end.
        let candidates: Vec<(&str, &str)> = keys
            .iter()
            .filter_map(|key| {
                let repo_key = self.strip_effective_prefix(key)?;
                if !validate_ref_name(repo_key) {
                    return None;
                }
                let suffix = if prefix_trimmed.is_empty() {
                    repo_key
                } else {
                    let after = repo_key.strip_prefix(prefix_trimmed)?;
                    match after.strip_prefix('/') {
                        Some(stripped) => stripped,
                        None if after.is_empty() => after,
                        None => return None,
                    }
                };
                validate_ref_name(suffix).then_some((repo_key, suffix))
            })
            .collect();

        // Resolve each key to its hash via a second GET, at most
        // MAX_PARALLEL_REF_READS at once. This is an inherent O(N) request
        // cost of the object-per-ref layout (the hash lives only in the
        // object body, so ListObjectsV2 cannot return it). A failed read
        // fails the listing, whether a transport error (post-retry), an
        // error status or a malformed body: silently dropping a ref would reintroduce the
        // short-listing bug that the pagination above exists to prevent.
        // Only a 404 skips the ref: it was deleted after the listing, as in
        // an older one. The first failure in key order is the one returned,
        // as a sequential walk would return it.
        let reads = read_bounded(&candidates, MAX_PARALLEL_REF_READS, |(repo_key, _)| {
            let resp =
                self.http_request(&Method::GET, repo_key, "", None, &[], Some(REF_BODY_LIMIT))?;
            match resp.status {
                // A 200 whose body is not a canonical ref wire is a corrupt
                // or foreign object; it fails the listing as `read_ref`
                // fails.
                200 => parse_ref_body(&resp.body).map(Some),
                404 => Ok(None),
                403 | 401 => Err(TransportError::AccessDenied),
                s => Err(TransportError::ServerError { status: s }),
            }
        });
        let mut out: Vec<Ref> = Vec::with_capacity(candidates.len());
        for ((_, suffix), read) in candidates.iter().zip(reads) {
            if let Some(h) = read? {
                out.push(Ref {
                    name: (*suffix).to_owned(),
                    hash: Some(h),
                });
            }
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }
}

/// The most ref reads [`Transport::list_refs`] keeps in flight at once.
const MAX_PARALLEL_REF_READS: usize = 16;

/// `read` applied to every item, by at most `limit` threads, each result in
/// the item's position. Once a read fails, no thread starts another; every
/// item before a failed one was started before it, so the first failure in
/// item order is the one a sequential walk would meet. Items never started
/// report [`TransportError::ConnectionFailed`] and sit after that failure.
fn read_bounded<T: Sync, R: Send>(
    items: &[T],
    limit: usize,
    read: impl Fn(&T) -> TransportResult<R> + Sync,
) -> Vec<TransportResult<R>> {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Mutex, PoisonError};
    let next = AtomicUsize::new(0);
    let failed = AtomicBool::new(false);
    let slots: Vec<Mutex<Option<TransportResult<R>>>> =
        items.iter().map(|_| Mutex::new(None)).collect();
    thread::scope(|scope| {
        for _ in 0..limit.min(items.len()) {
            scope.spawn(|| {
                while !failed.load(Ordering::Acquire) {
                    let i = next.fetch_add(1, Ordering::AcqRel);
                    let Some(item) = items.get(i) else { break };
                    let result = read(item);
                    if result.is_err() {
                        failed.store(true, Ordering::Release);
                    }
                    *slots[i].lock().unwrap_or_else(PoisonError::into_inner) = Some(result);
                }
            });
        }
    });
    slots
        .into_iter()
        .map(|slot| {
            slot.into_inner()
                .unwrap_or_else(PoisonError::into_inner)
                .unwrap_or(Err(TransportError::ConnectionFailed))
        })
        .collect()
}

fn parse_ref_body(body: &[u8]) -> TransportResult<Hash> {
    // SPEC-REFS §1: a ref value on the wire is exactly 64 lowercase hex
    // chars + a single '\n' — 65 bytes. S3 exposes ref bytes verbatim
    // (the byte-exact ETag/CAS contract in SPEC-REFS §5 depends on it),
    // so the tolerance SPEC-REFS grants local ref *files* does not apply:
    // uppercase hex, CRLF, extra whitespace, or any other length is a
    // corrupt or foreign object and must be rejected.
    let Some((&b'\n', hex)) = body.split_last() else {
        return Err(TransportError::InvalidResponse);
    };
    parse_lowercase_hash(hex).ok_or(TransportError::InvalidResponse)
}

/// One parsed page of a `ListObjectsV2` response: the keys it contained
/// plus the pagination cursor needed to fetch the next page.
struct ListPage {
    keys: Vec<String>,
    /// `Some(token)` when `<IsTruncated>true</IsTruncated>` and a
    /// `<NextContinuationToken>` is present — feed it back as the
    /// `continuation-token` query parameter to fetch the next page.
    next_continuation_token: Option<String>,
}

/// Domain-separation tag of the digest that [`Transport::repo_cursor`] returns.
const CURSOR_DOMAIN: &[u8] = b"kit-s3-repo-cursor-v1\0";

/// One `<Contents>` entry of a listing, as the cursor reads it.
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CursorEntry {
    pub key: String,
    pub etag: String,
    pub last_modified: String,
}

/// One page of a listing for the cursor.
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CursorPage {
    pub entries: Vec<CursorEntry>,
    pub next_continuation_token: Option<String>,
}

/// Parse a `ListObjectsV2` body for the cursor. `None` when the body is not
/// UTF-8 or any entry lacks its key, `ETag` or `LastModified`.
#[doc(hidden)]
#[must_use]
pub fn parse_cursor_page(xml: &[u8]) -> Option<CursorPage> {
    let s = std::str::from_utf8(xml).ok()?;
    let mut entries = Vec::new();
    let mut rest = s;
    while let Some(start) = rest.find("<Contents>") {
        let body = &rest[start + "<Contents>".len()..];
        let end = body.find("</Contents>")?;
        let block = &body[..end];
        entries.push(CursorEntry {
            key: extract_element(block, "Key")?,
            etag: extract_element(block, "ETag").filter(|v| !v.is_empty())?,
            last_modified: extract_element(block, "LastModified").filter(|v| !v.is_empty())?,
        });
        rest = &body[end + "</Contents>".len()..];
    }
    let ListPage {
        next_continuation_token,
        ..
    } = parse_list_page(xml);
    Some(CursorPage {
        entries,
        next_continuation_token,
    })
}

/// Extract every `<Key>...</Key>` value from a ListBucketResult body.
/// No XML validation, no entity decoding (S3 never URL-encodes keys in
/// the XML).
fn extract_keys(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cursor = 0usize;
    while cursor < s.len() {
        let Some(start) = s[cursor..].find("<Key>") else {
            break;
        };
        let abs_start = cursor + start + "<Key>".len();
        let Some(end) = s[abs_start..].find("</Key>") else {
            break;
        };
        let abs_end = abs_start + end;
        out.push(s[abs_start..abs_end].to_owned());
        cursor = abs_end + "</Key>".len();
    }
    out
}

/// Extract the text content of the first `<tag>...</tag>` element.
fn extract_element(s: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = s.find(&open)? + open.len();
    let end = s[start..].find(&close)? + start;
    Some(s[start..end].to_owned())
}

fn invalid_listing() -> TransportError {
    TransportError::RemoteError("invalid or excessive ref listing".into())
}

/// Parse a full `ListObjectsV2` XML body into keys + pagination cursor.
///
/// S3-compatible stores cap a single `ListObjectsV2` response at
/// 1000 keys and signal more pages via
/// `<IsTruncated>true</IsTruncated>` plus a `<NextContinuationToken>`.
/// Ignoring those would silently truncate the ref list — see
/// [`S3Transport::list_refs`], which loops on the returned token.
fn parse_list_page(xml: &[u8]) -> ListPage {
    let Ok(s) = std::str::from_utf8(xml) else {
        return ListPage {
            keys: Vec::new(),
            next_continuation_token: None,
        };
    };
    let keys = extract_keys(s);
    let truncated = extract_element(s, "IsTruncated").as_deref() == Some("true");
    let next_continuation_token = if truncated {
        // Only honor a non-empty token; an empty/missing one ends the
        // loop rather than re-requesting page 0 forever.
        extract_element(s, "NextContinuationToken").filter(|t| !t.is_empty())
    } else {
        None
    };
    ListPage {
        keys,
        next_continuation_token,
    }
}

// ---------------------------------------------------------------------------
// Sparse-checkout fetch. Feature-gated behind
// `sparse-checkout`.
//
// Wire contract additions (SPEC-TRANSPORT §6.6):
//
// - Object key: `sparse/<tree-hash-hex>/<filter-hash-hex>`. A server
//   that wants to offer sparse delivery pre-builds the manifest under
//   that key. Clients GET it; the response body IS the
//   `application/x-kit-sparse` envelope.
// - The `?sparse=<filter-hash-hex>` query is a no-op on S3 (the
//   content-addressed key already encodes it) — we accept it for URL
//   parity with the HTTP transport but ignore it.
// - 404 → no precomputed sparse for that (tree, filter) pair. Maps to
//   `PackNotFound` so retries are terminated.
// ---------------------------------------------------------------------------

#[cfg(feature = "sparse-checkout")]
mod sparse_fetch {
    use super::{
        Hash, Method, PACK_BODY_LIMIT, S3Transport, TransportError, TransportResult,
        saturating_usize, to_hex,
    };
    use kit_core::sparse::{
        SPARSE_WIRE_MAX_BYTES, VerifiedSparseTree, decode_sparse_response, hash_filter,
    };
    use std::path::PathBuf;

    impl S3Transport {
        /// Build the S3 object key for a sparse delivery:
        /// `sparse/v2/<tree-hex>/<filter-hex>`.
        #[must_use]
        pub fn sparse_object_key(tree_hash: &Hash, filter_hash: &Hash) -> String {
            format!("sparse/v2/{}/{}", to_hex(tree_hash), to_hex(filter_hash))
        }

        /// Fetch the precomputed sparse delivery for `(tree_hash,
        /// filter)`. The S3 transport does NOT compute manifests; it
        /// assumes a server has pre-built them under the canonical
        /// key.
        ///
        /// Authenticates the witness against the requested tree and filter,
        /// then returns the locally derived selection.
        ///
        /// # Errors
        ///
        /// - [`TransportError::PackNotFound`] — no precomputed sparse
        ///   for the addressed `(tree, filter)` pair.
        /// - [`TransportError::AccessDenied`] — credentials rejected.
        /// - [`TransportError::InvalidResponse`] — wire envelope
        ///   decode failed.
        /// - [`TransportError::PayloadTooLarge`] — response body
        ///   exceeded `SPARSE_WIRE_MAX_BYTES`.
        pub fn fetch_sparse_tree(
            &self,
            tree_hash: &Hash,
            filter: &[PathBuf],
        ) -> TransportResult<VerifiedSparseTree> {
            kit_core::sparse::validate_filter(filter)
                .map_err(|_| TransportError::InvalidResponse)?;
            let filter_hash = hash_filter(filter);
            let key = Self::sparse_object_key(tree_hash, &filter_hash);
            // Cap body size at the wire-format max — far smaller than
            // the pack-body limit. PACK_BODY_LIMIT is the
            // existing transport-side ceiling, used here for parity
            // when SPARSE_WIRE_MAX_BYTES would otherwise allow a
            // non-pack body larger than any pack we'd accept.
            let cap = SPARSE_WIRE_MAX_BYTES.min(saturating_usize(PACK_BODY_LIMIT));
            let resp = self.http_request_pub(&Method::GET, &key, "", None, &[], Some(cap))?;
            match resp.status_pub() {
                200 => {
                    let response = decode_sparse_response(resp.body_pub())
                        .map_err(|_| TransportError::InvalidResponse)?;
                    kit_core::sparse::verify_sparse(tree_hash, filter, &response)
                        .map_err(|_| TransportError::InvalidResponse)
                }
                404 => Err(TransportError::PackNotFound),
                403 | 401 => Err(TransportError::AccessDenied),
                s => Err(TransportError::ServerError { status: s }),
            }
        }
    }
}

// Crate-private bridge so the sparse-fetch module can poke through
// `http_request` without the transport file losing its tightly-scoped
// `pub(crate)` surface.
#[cfg(feature = "sparse-checkout")]
impl S3Transport {
    pub(crate) fn http_request_pub(
        &self,
        method: &Method,
        key: &str,
        query: &str,
        payload: Option<&[u8]>,
        extra_headers: &[(&'static str, String)],
        body_limit: Option<usize>,
    ) -> TransportResult<HttpResponse> {
        self.http_request(method, key, query, payload, extra_headers, body_limit)
    }
}

#[cfg(feature = "sparse-checkout")]
impl HttpResponse {
    pub(crate) fn status_pub(&self) -> u16 {
        self.status
    }
    pub(crate) fn body_pub(&self) -> &[u8] {
        &self.body
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #[test]
    fn read_bounded_keeps_order_and_stays_under_its_limit() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let items: Vec<usize> = (0..200).collect();
        let (now, peak) = (AtomicUsize::new(0), AtomicUsize::new(0));
        let out = read_bounded(&items, 16, |i| {
            let n = now.fetch_add(1, Ordering::SeqCst) + 1;
            peak.fetch_max(n, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(1));
            now.fetch_sub(1, Ordering::SeqCst);
            Ok(i * 2)
        });
        let out: Vec<usize> = out.into_iter().map(Result::unwrap).collect();
        assert_eq!(out, items.iter().map(|i| i * 2).collect::<Vec<_>>());
        let peak = peak.load(Ordering::SeqCst);
        assert!(peak <= 16, "{peak} reads in flight");
        assert!(peak > 1, "the reads ran in parallel");
    }

    #[test]
    fn read_bounded_returns_the_first_failure_in_item_order() {
        let items: Vec<usize> = (0..100).collect();
        let out = read_bounded(&items, 8, |&i| {
            if i == 30 || i == 31 {
                return Err(TransportError::ServerError {
                    status: u16::try_from(500 + i).unwrap(),
                });
            }
            std::thread::sleep(Duration::from_millis(1));
            Ok(i)
        });
        let first = out.into_iter().collect::<TransportResult<Vec<_>>>();
        assert!(matches!(
            first,
            Err(TransportError::ServerError { status: 530 })
        ));
        // A failure stops new reads: far fewer than all items ran.
        let started = std::sync::atomic::AtomicUsize::new(0);
        let _ = read_bounded(&items, 4, |&i| {
            started.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if i == 0 {
                Err(TransportError::ConnectionFailed)
            } else {
                Ok(())
            }
        });
        assert!(started.load(std::sync::atomic::Ordering::SeqCst) < items.len());
    }

    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn extract_response_stops_reading_a_hostile_body_at_the_limit() {
        const CHUNK: usize = 64 * 1024;
        const CHUNKS: usize = 4096; // 256 MiB if the client read it all
        let sent = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&sent);
        let mut server = mockito::Server::new();
        let _m = server
            .mock("GET", "/hostile")
            .with_status(200)
            .with_chunked_body(move |w| {
                let chunk = vec![0u8; CHUNK];
                for _ in 0..CHUNKS {
                    w.write_all(&chunk)?;
                    counter.fetch_add(CHUNK, Ordering::SeqCst);
                }
                Ok(())
            })
            .create();
        let resp = reqwest::blocking::get(format!("{}/hostile", server.url())).unwrap();
        let err = extract_response(resp, Some(1024), false).err().unwrap();
        assert!(matches!(err, TransportError::PayloadTooLarge(1025)));
        // The server blocks on a full socket buffer once the client stops
        // reading. It must not get close to the full body.
        assert!(sent.load(Ordering::SeqCst) < CHUNK * CHUNKS / 2);
    }

    #[test]
    fn extract_response_accepts_a_body_at_the_limit() {
        let mut server = mockito::Server::new();
        let _m = server
            .mock("GET", "/ok")
            .with_status(200)
            .with_body(vec![7u8; 1024])
            .create();
        let resp = reqwest::blocking::get(format!("{}/ok", server.url())).unwrap();
        let out = extract_response(resp, Some(1024), false).unwrap();
        assert_eq!(out.body.len(), 1024);
    }

    #[test]
    fn pack_object_key_shape() {
        let digest = [0xABu8; 32];
        let key = S3Transport::pack_object_key(&digest);
        assert!(key.starts_with("packs/"));
        assert_eq!(key.len(), "packs/".len() + 64);
    }

    #[test]
    fn list_query_format() {
        // `/` MUST be percent-encoded as `%2F` and keys sorted, so the
        // signed query matches what real AWS S3 re-derives server-side.
        assert_eq!(
            S3Transport::build_list_query("refs/heads/"),
            "list-type=2&prefix=refs%2Fheads%2F"
        );
        assert_eq!(S3Transport::build_list_query(""), "list-type=2&prefix=");
    }

    #[test]
    fn list_query_continued_format() {
        // Canonical sort puts `continuation-token` before `list-type`.
        assert_eq!(
            S3Transport::build_list_query_continued("refs/heads/", "TOKEN123"),
            "continuation-token=TOKEN123&list-type=2&prefix=refs%2Fheads%2F"
        );
    }

    #[test]
    fn list_page_reports_continuation_when_truncated() {
        let xml = br"<ListBucketResult>
            <IsTruncated>true</IsTruncated>
            <Contents><Key>refs/heads/a</Key></Contents>
            <NextContinuationToken>NEXT</NextContinuationToken>
        </ListBucketResult>";
        let page = parse_list_page(xml);
        assert_eq!(page.keys, vec!["refs/heads/a".to_owned()]);
        assert_eq!(page.next_continuation_token.as_deref(), Some("NEXT"));
    }

    #[test]
    fn list_page_no_continuation_when_not_truncated() {
        let xml = br"<ListBucketResult>
            <IsTruncated>false</IsTruncated>
            <Contents><Key>refs/heads/a</Key></Contents>
        </ListBucketResult>";
        let page = parse_list_page(xml);
        assert_eq!(page.keys, vec!["refs/heads/a".to_owned()]);
        assert!(page.next_continuation_token.is_none());
    }

    #[test]
    fn list_page_truncated_but_empty_token_terminates() {
        // Defensive: IsTruncated=true with a missing/empty token must
        // not loop forever.
        let xml = br"<ListBucketResult>
            <IsTruncated>true</IsTruncated>
            <Contents><Key>refs/heads/a</Key></Contents>
        </ListBucketResult>";
        let page = parse_list_page(xml);
        assert!(page.next_continuation_token.is_none());
    }

    #[test]
    fn url_parse_ok_no_prefix() {
        let p = parse_s3_url("kit+s3://s3.example.com/bucket").unwrap();
        assert_eq!(p.host, "s3.example.com");
        assert_eq!(p.bucket, "bucket");
        assert!(p.prefix.is_none());
    }

    #[test]
    fn url_parse_ok_with_prefix() {
        let p = parse_s3_url("kit+s3://host.example/bucket/project-a").unwrap();
        assert_eq!(p.prefix.as_deref(), Some("project-a"));
    }

    #[test]
    fn url_parse_ok_with_nested_safe_prefix() {
        let p = parse_s3_url("kit+s3://host.example/bucket/team_1/project.a-2").unwrap();
        assert_eq!(p.prefix.as_deref(), Some("team_1/project.a-2"));
    }

    #[test]
    fn url_parse_rejects_prefix_url_metacharacters() {
        for prefix in [
            "project?x=1",
            "project#frag",
            "project&x=1",
            "project x",
            "project%2Fother",
            "project+other",
        ] {
            let url = format!("kit+s3://host.example/bucket/{prefix}");
            assert!(
                matches!(parse_s3_url(&url), Err(TransportError::InvalidRef(_))),
                "prefix should be rejected: {prefix}"
            );
        }
    }

    #[test]
    fn url_parse_rejects_non_kit_scheme() {
        assert!(matches!(
            parse_s3_url("s3://bucket"),
            Err(TransportError::InvalidRef(_))
        ));
    }

    #[test]
    fn url_parse_rejects_empty_bucket() {
        assert!(matches!(
            parse_s3_url("kit+s3://host.example"),
            Err(TransportError::InvalidRef(_))
        ));
    }

    #[test]
    fn list_xml_extracts_keys() {
        let xml = "<ListBucketResult><Contents><Key>refs/heads/main</Key></Contents><Contents><Key>refs/tags/v1</Key></Contents></ListBucketResult>";
        assert_eq!(
            extract_keys(xml),
            vec!["refs/heads/main".to_owned(), "refs/tags/v1".to_owned()]
        );
    }

    #[test]
    fn list_xml_empty() {
        assert!(extract_keys("<ListBucketResult></ListBucketResult>").is_empty());
    }

    #[test]
    fn format_ref_wire_is_65_bytes() {
        let h = [0x11u8; 32];
        let w = format_ref_wire(&h);
        assert_eq!(w.len(), 65);
        assert_eq!(w[64], b'\n');
    }

    #[test]
    fn quoted_md5_has_surrounding_quotes() {
        let got = quoted_md5(b"hello");
        assert!(got.starts_with('"') && got.ends_with('"'));
        // 32 hex + 2 quotes.
        assert_eq!(got.len(), 34);
    }

    const CANONICAL_HEX: &[u8; 64] =
        b"0101010101010101010101010101010101010101010101010101010101010101";

    /// Positive: the canonical 65-byte wire body (64 lowercase hex +
    /// `\n`) parses.
    #[test]
    fn parse_ref_body_accepts_canonical_65_byte_body() {
        let mut body = CANONICAL_HEX.to_vec();
        body.push(b'\n');
        assert_eq!(body.len(), 65);
        let h = parse_ref_body(&body).unwrap();
        assert_eq!(h[0], 0x01);
    }

    #[test]
    fn parse_ref_body_rejects_short() {
        assert!(parse_ref_body(b"deadbeef").is_err());
    }

    /// SPEC-REFS §1: uppercase hex MUST be rejected on read.
    #[test]
    fn parse_ref_body_rejects_uppercase_hex() {
        let mut body = CANONICAL_HEX.to_vec();
        body[0] = b'A';
        body.push(b'\n');
        assert!(matches!(
            parse_ref_body(&body),
            Err(TransportError::InvalidResponse)
        ));
    }

    /// The terminal `\n` is part of the 65-byte wire form; a bare
    /// 64-hex body is malformed.
    #[test]
    fn parse_ref_body_rejects_missing_newline() {
        assert!(matches!(
            parse_ref_body(CANONICAL_HEX),
            Err(TransportError::InvalidResponse)
        ));
    }

    /// CRLF is not the wire form — S3 stores ref bytes verbatim, so the
    /// local-file `\r` tolerance does not apply here.
    #[test]
    fn parse_ref_body_rejects_crlf() {
        let mut body = CANONICAL_HEX.to_vec();
        body.extend_from_slice(b"\r\n");
        assert!(matches!(
            parse_ref_body(&body),
            Err(TransportError::InvalidResponse)
        ));
    }

    #[test]
    fn parse_ref_body_rejects_trailing_spaces() {
        let mut body = CANONICAL_HEX.to_vec();
        body.extend_from_slice(b"  \n");
        assert!(matches!(
            parse_ref_body(&body),
            Err(TransportError::InvalidResponse)
        ));

        // Space after the newline is equally malformed.
        let mut body = CANONICAL_HEX.to_vec();
        body.extend_from_slice(b"\n ");
        assert!(matches!(
            parse_ref_body(&body),
            Err(TransportError::InvalidResponse)
        ));
    }

    #[test]
    fn parse_ref_body_rejects_wrong_length() {
        // 63 hex chars + newline.
        let mut body = CANONICAL_HEX[..63].to_vec();
        body.push(b'\n');
        assert!(matches!(
            parse_ref_body(&body),
            Err(TransportError::InvalidResponse)
        ));

        // 65 hex chars + newline.
        let mut body = CANONICAL_HEX.to_vec();
        body.extend_from_slice(b"0\n");
        assert!(matches!(
            parse_ref_body(&body),
            Err(TransportError::InvalidResponse)
        ));

        // Doubled newline (66 bytes).
        let mut body = CANONICAL_HEX.to_vec();
        body.extend_from_slice(b"\n\n");
        assert!(matches!(
            parse_ref_body(&body),
            Err(TransportError::InvalidResponse)
        ));

        // Empty body.
        assert!(matches!(
            parse_ref_body(b""),
            Err(TransportError::InvalidResponse)
        ));
    }

    #[test]
    fn connect_rejects_bad_url() {
        assert!(S3Transport::connect("not-a-url").is_err());
    }

    /// A transport against `endpoint` whose pack `PUT`s stall after `stall`
    /// and retry twice, without sleeping.
    fn stalling_transport(endpoint: &str, stall: Duration) -> S3Transport {
        let mut t = S3Transport::with_parts(
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
        t.set_sleeper(|_| {});
        t.set_backoff(|| BackoffIterator::with(Duration::ZERO, Duration::ZERO, 2));
        t.stall = stall;
        t
    }

    /// A server that reads each request's head, then reads the first `paced`
    /// bytes of its body `step` bytes every `gap` (nothing, if `step` is
    /// zero) and the rest at once, then answers `200`. It counts the
    /// requests it took.
    fn pacing_server(step: usize, gap: Duration, paced: usize) -> (String, Arc<AtomicUsize>) {
        use std::io::{BufRead as _, BufReader, Write as _};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let taken = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&taken);
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { return };
                count.fetch_add(1, Ordering::SeqCst);
                thread::spawn(move || {
                    let mut reader = BufReader::new(stream);
                    let mut len = 0usize;
                    loop {
                        let mut line = String::new();
                        if reader.read_line(&mut line).unwrap_or(0) == 0 {
                            return;
                        }
                        let line = line.trim_end().to_ascii_lowercase();
                        if line.is_empty() {
                            break;
                        }
                        if let Some(value) = line.strip_prefix("content-length:") {
                            len = value.trim().parse().unwrap();
                        }
                    }
                    if step == 0 {
                        // Hold the connection, read nothing, answer nothing.
                        thread::sleep(Duration::from_secs(60));
                        return;
                    }
                    let mut chunk = vec![0u8; step];
                    let mut left = len;
                    while left > 0 {
                        let want = left.min(step);
                        if reader.read_exact(&mut chunk[..want]).is_err() {
                            return;
                        }
                        left -= want;
                        if len - left < paced {
                            thread::sleep(gap);
                        }
                    }
                    let _ = reader
                        .get_mut()
                        .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n");
                });
            }
        });
        (endpoint, taken)
    }

    #[test]
    fn early_client_error_is_not_retried_and_names_the_code() {
        use std::io::{BufRead as _, BufReader, Write as _};
        for status in [400, 403, 404] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let endpoint = format!("http://{}", listener.local_addr().unwrap());
            let server = thread::spawn(move || {
                let (stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut reader = BufReader::new(stream);
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" {
                        break;
                    }
                }
                assert!(reader.buffer().is_empty(), "body sent before Continue");
                if status == 400 {
                    let body = "<Error><Code>AccessDenied</Code></Error>";
                    write!(reader.get_mut(), "HTTP/1.1 {status} Error\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
                } else {
                    write!(reader.get_mut(), "HTTP/1.1 {status} Error\r\nx-amz-error-code: AccessDenied\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
                }
                // Close immediately, without reading the upload body.
            });
            let t = stalling_transport(&endpoint, Duration::from_secs(5));
            let error = t
                .upload_pack(
                    &kit_core::protocol::SliceBody(&vec![7; 16 << 20]),
                    &PackKey::new([0; 32]),
                    None,
                )
                .unwrap_err();
            server.join().unwrap();
            assert!(!is_retryable(&error), "{error:?}");
            assert!(error.to_string().contains("AccessDenied"), "{error}");
        }
    }

    #[test]
    fn transient_upload_statuses_are_retried() {
        use std::io::{BufRead as _, BufReader, Write as _};
        for (status, code) in [
            (408, ""),
            (429, ""),
            (500, ""),
            (503, ""),
            (400, "RequestTimeout"),
            (400, "RequestTimeoutException"),
            (400, "InternalError"),
            (400, "SlowDown"),
        ] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let endpoint = format!("http://{}", listener.local_addr().unwrap());
            listener.set_nonblocking(true).unwrap();
            let server = thread::spawn(move || {
                for attempt in 0..2 {
                    let start = std::time::Instant::now();
                    let stream = loop {
                        match listener.accept() {
                            Ok((stream, _)) => break stream,
                            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                                assert!(start.elapsed() < Duration::from_secs(10), "missing retry");
                                thread::sleep(Duration::from_millis(5));
                            }
                            Err(error) => panic!("accept: {error}"),
                        }
                    };
                    // Accepted sockets inherit nonblocking mode on macOS.
                    stream.set_nonblocking(false).unwrap();
                    stream
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    let mut reader = BufReader::new(stream);
                    let mut len = 0;
                    loop {
                        let mut line = String::new();
                        assert!(reader.read_line(&mut line).unwrap() > 0);
                        if line == "\r\n" {
                            break;
                        }
                        if let Some(value) =
                            line.to_ascii_lowercase().strip_prefix("content-length:")
                        {
                            len = value.trim().parse::<u64>().unwrap();
                        }
                    }
                    if attempt == 0 {
                        let body = format!("<Error><Code>{code}</Code></Error>");
                        write!(reader.get_mut(), "HTTP/1.1 {status} Error\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
                    } else {
                        reader
                            .get_mut()
                            .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
                            .unwrap();
                        assert_eq!(
                            std::io::copy(&mut reader.by_ref().take(len), &mut io::sink()).unwrap(),
                            len
                        );
                        reader.get_mut().write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
                    }
                }
            });
            let t = stalling_transport(&endpoint, Duration::from_secs(5));
            let result = t.upload_pack(
                &kit_core::protocol::SliceBody(&[7; 1024]),
                &PackKey::new([0; 32]),
                None,
            );
            server.join().unwrap();
            assert!(result.is_ok(), "{status} {code}: {result:?}");
        }
    }

    #[test]
    fn a_pack_put_that_keeps_moving_outlives_the_stall_bound() {
        // About 5 MiB/s for 32 MiB, 6.4 s in all, past the 4 s bound; the
        // rest is read at once, so the end of the upload is never quiet.
        let stall = Duration::from_secs(4);
        let (endpoint, taken) = pacing_server(256 * 1024, Duration::from_millis(50), 32 << 20);
        let t = stalling_transport(&endpoint, stall);
        let pack = vec![7u8; 40 * 1024 * 1024];
        let started = std::time::Instant::now();
        t.upload_pack(
            &kit_core::protocol::SliceBody(&pack),
            &PackKey::new([1; 32]),
            None,
        )
        .unwrap();
        assert!(
            started.elapsed() > stall,
            "the upload took {:?}, within one stall bound",
            started.elapsed()
        );
        assert_eq!(taken.load(Ordering::SeqCst), 1, "no attempt was retried");
    }

    #[test]
    fn a_pack_put_that_stops_is_retried_then_fails_naming_the_stall() {
        let (endpoint, taken) = pacing_server(0, Duration::ZERO, 0);
        let t = stalling_transport(&endpoint, Duration::from_millis(300));
        let pack = vec![7u8; 64 * 1024 * 1024];
        let started = std::time::Instant::now();
        let err = t
            .upload_pack(
                &kit_core::protocol::SliceBody(&pack),
                &PackKey::new([1; 32]),
                None,
            )
            .unwrap_err();
        match err {
            TransportError::RemoteError(text) => {
                assert_eq!(text, "transfer stalled: no data for 300 ms");
            }
            other => panic!("expected the stall, got {other:?}"),
        }
        assert_eq!(
            taken.load(Ordering::SeqCst),
            3,
            "one attempt and two retries"
        );
        assert!(started.elapsed() < Duration::from_secs(30));
    }
}
