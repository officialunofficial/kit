//! Cross-transport types: error taxonomy, the [`Transport`] trait, the
//! [`PackKey`] digest wrapper, and the retry/backoff helpers used by
//! every transport implementation (memory, file, HTTP, S3, SSH, enc).
//! [`retrying`] is the single shared driver of the SPEC-TRANSPORT §7
//! ladder — every transport's `retrying`/`with_retry` method is a thin
//! wrapper around it, so the backoff/classification policy lives in
//! exactly one place instead of being reimplemented per crate.
//!
//! The SSH wire format is defined in `kit-rpc`'s `ssh.proto` and
//! lives in `kit_rpc::kit::rpc::v1::ssh`; transport-ssh consumes
//! the schema directly. The hand-rolled `OP_HELLO` byte format that
//! used to live in this module has been retired.

// SPEC-TRANSPORT §7 calls out the exponential ladder in seconds
// (1, 2, 4, …, 300). Expressing those values with `Duration::from_secs`
// is deliberate — switching to `from_mins` loses the one-to-one match
// with the spec text.
#![allow(clippy::duration_suboptimal_units)]

use core::fmt;
use core::time::Duration;

use crate::hash::{FromHexError, Hash, to_hex};
use crate::refs::Ref;
pub use crate::refs::RefWriteCondition;

// ---------------------------------------------------------------------------
// Error taxonomy
// ---------------------------------------------------------------------------

/// Errors that any transport may surface across the [`Transport`]
/// boundary. Implementations MAY wrap transport-specific errors
/// internally but MUST map them to one of these variants before
/// returning.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TransportError {
    /// Verification is still pending. Scheduling belongs to the caller.
    #[error("remote error: verification pending, retry after {retry_after:?}")]
    PendingVerification { retry_after: Duration },
    /// Repository membership has not become visible yet.
    #[error("remote error: repository membership not yet visible")]
    MembershipNotVisible,
    /// A remote supplied a bounded delay hint, in milliseconds.
    #[error("remote error: retry after {ms} ms")]
    RetryAfter { ms: u64 },
    /// `download_pack` called on a digest the remote does not hold.
    #[error("pack not found on remote")]
    PackNotFound,
    /// Authentication or ACL failure (HTTP 401/403, SSH auth refusal,
    /// S3 `SignatureDoesNotMatch`, …).
    #[error("access denied by remote")]
    AccessDenied,
    /// A remote requires admission before this write may proceed.
    #[error("{0}")]
    AdmissionRequired(Box<AdmissionRequired>),
    /// User admission configuration or helper headers were rejected.
    #[error("admission configuration: {0}")]
    AdmissionConfiguration(String),
    /// Local HTTPS trust configuration could not be loaded or validated.
    #[error("HTTPS trust configuration: {0}")]
    TlsConfiguration(String),
    /// The configured admission helper failed.
    #[error("admission helper failed: {0}")]
    AdmissionHelperFailed(String),
    /// Catch-all remote-side failure carrying an advisory message. The
    /// message is for operators; programs MUST NOT pattern-match on its
    /// contents.
    #[error("remote error: {}", sanitize_remote_error_text(.0))]
    RemoteError(String),
    /// `update_ref` CAS precondition was not satisfied. Per
    /// SPEC-TRANSPORT §7, callers MUST treat this as
    /// "possibly-success on retry" for `.missing` / `.match` and
    /// confirm with `read_ref`.
    #[error("ref CAS precondition failed")]
    RefConflict,
    /// Caller passed a ref name failing SPEC-REFS §3.
    #[error("invalid ref name: {}", escape_terminal_text(.0, false))]
    InvalidRef(String),
    /// Network-level failure: DNS, TCP connect, TLS handshake, SSH
    /// subprocess spawn. Retryable (see [`is_retryable`]).
    #[error("connection to remote failed")]
    ConnectionFailed,
    /// Unexpected HTTP status or transport-protocol error. 5xx and 429
    /// are retryable; 4xx (except 401/403/404/409/412) is not.
    #[error("server error (status {status})")]
    ServerError {
        /// Numeric status code. HTTP uses its native codes; transports
        /// without a status integer use `0`.
        status: u16,
    },
    /// Server response did not match the wire contract (truncated
    /// frame, unknown opcode, bad JSON, …).
    #[error("invalid response from remote")]
    InvalidResponse,
    /// Generic protocol-level failure — malformed frame, unexpected
    /// opcode order, or failed handshake.
    #[error("protocol error")]
    ProtocolError,
    /// Payload exceeded a transport-specific cap.
    #[error("payload too large: {0} bytes")]
    PayloadTooLarge(usize),
    /// An insecure URL scheme (plain `http://`) was supplied for a
    /// non-loopback host. Plain HTTP is restricted to loopback addresses
    /// (`127.0.0.1`, `::1`, `localhost`) so production traffic is never
    /// transported in the clear.
    #[error("insecure scheme: plain http:// is allowed only for loopback hosts")]
    InsecureScheme,

    /// The transport cannot do this operation safely, so it refused it
    /// before it wrote anything. The text says which operation.
    #[error("{0}")]
    Unsupported(&'static str),
}

/// One opaque challenge advertised by the remote.
#[derive(Clone, PartialEq, Eq)]
pub struct AdmissionChallengeEntry {
    /// Lowercase scheme identifier.
    pub scheme: String,
    /// Opaque challenge value. Do not display or log it.
    pub value: String,
}

impl fmt::Debug for AdmissionChallengeEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdmissionChallengeEntry")
            .field("scheme", &self.scheme)
            .field("value_len", &self.value.len())
            .finish()
    }
}

/// A remote admission challenge and the bounded response headers needed by a helper.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AdmissionRequired {
    /// Challenges in server preference order.
    pub challenges: Vec<AdmissionChallengeEntry>,
    /// Untrusted server description, retained for the helper.
    pub description: String,
    /// Bounded `WWW-Authenticate` header values.
    pub www_authenticate: Vec<String>,
    /// Bounded `ADMISSION-REQUIRED` header values.
    pub admission_required: Vec<String>,
    /// Terminal admission state, if a helper already ran or hit its cap.
    pub reason: Option<&'static str>,
}

impl AdmissionRequired {
    /// Construct a remote challenge from already-bounded fields. The Connect
    /// client validates the bounds before calling this.
    #[must_use]
    pub fn new(
        challenges: Vec<AdmissionChallengeEntry>,
        description: String,
        www_authenticate: Vec<String>,
        admission_required: Vec<String>,
    ) -> Self {
        Self {
            challenges,
            description,
            www_authenticate,
            admission_required,
            reason: None,
        }
    }

    /// Add a safe terminal explanation without exposing challenge values.
    #[must_use]
    pub fn with_reason(mut self, reason: &'static str) -> Self {
        self.reason = Some(reason);
        self
    }
}

impl fmt::Debug for AdmissionRequired {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdmissionRequired")
            .field("challenges", &self.challenges)
            .field("description_len", &self.description.len())
            .field("www_authenticate_count", &self.www_authenticate.len())
            .field("admission_required_count", &self.admission_required.len())
            .field("reason", &self.reason)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for AdmissionRequired {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("admission required by remote: ")?;
        write_safe_remote_text(f, &self.description)?;
        if self.challenges.is_empty() {
            f.write_str(" (no challenges)")?;
        } else {
            f.write_str(" (schemes: ")?;
            for (i, challenge) in self.challenges.iter().enumerate() {
                if i != 0 {
                    f.write_str(", ")?;
                }
                write_safe_remote_text(f, &challenge.scheme)?;
            }
            f.write_str(")")?;
        }
        if let Some(reason) = self.reason {
            write!(f, ": {reason}")?;
        }
        Ok(())
    }
}

fn write_safe_remote_text(f: &mut fmt::Formatter<'_>, value: &str) -> fmt::Result {
    f.write_str(&escape_terminal_text(value, false))
}

/// Longest remote error text, in bytes, that a transport keeps.
pub const MAX_REMOTE_ERROR_TEXT: usize = 256;

/// Escape control and bidi-override characters so that `value` is safe
/// to print to a terminal.
///
/// Each C0, C1 and bidi control becomes `\u{hex}`. With `keep_layout`,
/// tab and newline pass through unchanged.
#[must_use]
pub fn escape_terminal_text(value: &str, keep_layout: bool) -> String {
    use fmt::Write as _;
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        let layout = keep_layout && matches!(c, '\t' | '\n');
        let hostile =
            c.is_control() || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}');
        if hostile && !layout {
            let _ = write!(out, "\\u{{{:x}}}", c as u32);
        } else {
            out.push(c);
        }
    }
    out
}

/// Escape remote error text and cut it to [`MAX_REMOTE_ERROR_TEXT`] bytes.
#[must_use]
pub fn sanitize_remote_error_text(value: &str) -> String {
    let mut end = value.len().min(MAX_REMOTE_ERROR_TEXT);
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    escape_terminal_text(&value[..end], false)
}

/// Result alias used throughout this module.
pub type TransportResult<T> = Result<T, TransportError>;

// ---------------------------------------------------------------------------
// PackKey — 32-byte digest wrapper
// ---------------------------------------------------------------------------

/// A 32-byte pack digest used as the content-address for an uploaded
/// pack. This is the same 32 bytes as [`Hash`](tyalias@Hash) but wrapped so pack
/// digests and object hashes do not silently cross purposes at API
/// boundaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PackKey(pub [u8; 32]);

impl PackKey {
    /// Build a [`PackKey`] from a raw 32-byte digest.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the underlying 32 bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lowercase 64-char hex.
    #[must_use]
    pub fn to_hex(&self) -> String {
        to_hex(&self.0)
    }

    /// Build a [`PackKey`] from a [`Hash`](tyalias@Hash) (alias for [`From`]).
    #[must_use]
    pub const fn from_hash(h: Hash) -> Self {
        Self(h)
    }

    /// Convert back to a plain [`Hash`](tyalias@Hash).
    #[must_use]
    pub const fn into_hash(self) -> Hash {
        self.0
    }

    /// Verify downloaded bytes against this independently requested address.
    /// Covers the entire byte sequence, including a pack's internal trailer.
    /// Also applies to auxiliary blobs: a lookup URL or a self-consistent
    /// manifest cannot authenticate the returned bytes on its own.
    ///
    /// # Errors
    /// Returns [`TransportError::InvalidResponse`] on a digest mismatch.
    pub fn verify_bytes(self, bytes: &[u8]) -> TransportResult<()> {
        if crate::hash::hash(bytes) != self.0 {
            return Err(TransportError::InvalidResponse);
        }
        Ok(())
    }
}

impl From<Hash> for PackKey {
    fn from(h: Hash) -> Self {
        Self(h)
    }
}

impl From<PackKey> for Hash {
    fn from(k: PackKey) -> Hash {
        k.0
    }
}

impl fmt::Display for PackKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// Parse a [`PackKey`] from a 64-char lowercase hex string.
///
/// Accepts uppercase too (matches the permissive [`crate::hash::from_hex`]
/// semantics); callers that require lowercase MUST validate the input
/// independently.
pub fn pack_key_from_hex(s: &str) -> Result<PackKey, FromHexError> {
    let h = crate::hash::from_hex(s)?;
    Ok(PackKey(h))
}

// ---------------------------------------------------------------------------
// Retry / backoff
// ---------------------------------------------------------------------------

/// Return `true` if a transport should retry after seeing `err`.
///
/// Retryable per SPEC-TRANSPORT §7:
/// - [`TransportError::ConnectionFailed`]
/// - [`TransportError::ServerError`] with a 5xx status OR HTTP 429.
///
/// Explicitly non-retryable:
/// - [`TransportError::PackNotFound`]
/// - [`TransportError::AccessDenied`]
/// - [`TransportError::AdmissionRequired`] — requires an explicit helper response
/// - [`TransportError::RefConflict`] (CAS retry is a caller-level policy)
/// - [`TransportError::InvalidRef`]
/// - [`TransportError::InvalidResponse`] / [`TransportError::ProtocolError`]
/// - [`TransportError::PayloadTooLarge`]
/// - [`TransportError::TlsConfiguration`] — local trust setup failed.
/// - [`TransportError::RemoteError`] — the remote chose not to be specific;
///   we do not guess.
/// - [`TransportError::ServerError`] with any 4xx status.
#[must_use]
pub fn is_retryable(err: &TransportError) -> bool {
    match err {
        TransportError::ConnectionFailed => true,
        TransportError::ServerError { status } => *status >= 500 || *status == 429,
        _ => false,
    }
}

/// Max attempts for the default backoff ladder.
///
/// SPEC-TRANSPORT §7: `attempt = 1; while attempt ≤ 5`.
pub const BACKOFF_MAX_ATTEMPTS: u32 = 5;

/// Initial sleep between attempts.
pub const BACKOFF_INITIAL: Duration = Duration::from_secs(1);

/// Upper bound on any individual sleep.
pub const BACKOFF_CAP: Duration = Duration::from_secs(300);

/// Per-pack body size ceiling enforced by every transport that ingests
/// pack bytes (HTTP `Content-Length`, S3 `GetObject`, SSH
/// `DownloadPackHeader.total_bytes`). On 64-bit targets, 4 GiB matches
/// the pack-format addressable range; pointer-width-limited targets cap
/// at their maximum addressable buffer size instead of failing to compile.
#[cfg(target_pointer_width = "64")]
pub const PACK_BODY_LIMIT: u64 = 4 * 1024 * 1024 * 1024;
#[cfg(not(target_pointer_width = "64"))]
pub const PACK_BODY_LIMIT: u64 = usize::MAX as u64;

/// The most bytes one pack may take on a remote that advertises `advertised`,
/// header and trailer included: the advertised limit, never above
/// [`PACK_BODY_LIMIT`]. Every fetch refuses a longer pack, so a writer seals
/// under this even when the remote advertises no limit.
#[must_use]
pub fn max_pack_bytes(advertised: Option<u64>) -> u64 {
    advertised.map_or(PACK_BODY_LIMIT, |limit| limit.min(PACK_BODY_LIMIT))
}

/// Exponential-backoff iterator used by all transports.
///
/// Yields `[1s, 2s, 4s, 8s, 16s]` (5 attempts) for the default ladder,
/// doubling each step and capping at 300s. This is the ladder mandated
/// by SPEC-TRANSPORT §7 for `ConnectionFailed`, 5xx, and HTTP 429.
///
/// The iterator is self-contained — it holds no reference to a clock,
/// so it can be constructed in tests and exhaustively enumerated.
#[derive(Debug, Clone)]
pub struct BackoffIterator {
    next_delay: Duration,
    attempts_remaining: u32,
    cap: Duration,
}

impl BackoffIterator {
    /// Default ladder: 5 attempts, starting at 1s, doubling, capped at 300s.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            next_delay: BACKOFF_INITIAL,
            attempts_remaining: BACKOFF_MAX_ATTEMPTS,
            cap: BACKOFF_CAP,
        }
    }

    /// Custom ladder for tests.
    #[must_use]
    pub const fn with(initial: Duration, cap: Duration, attempts: u32) -> Self {
        Self {
            next_delay: initial,
            attempts_remaining: attempts,
            cap,
        }
    }
}

impl Default for BackoffIterator {
    fn default() -> Self {
        Self::new()
    }
}

impl Iterator for BackoffIterator {
    type Item = Duration;

    fn next(&mut self) -> Option<Self::Item> {
        if self.attempts_remaining == 0 {
            return None;
        }
        self.attempts_remaining -= 1;
        let current = self.next_delay;
        let doubled = current.saturating_mul(2);
        self.next_delay = if doubled > self.cap {
            self.cap
        } else {
            doubled
        };
        Some(current)
    }
}

/// Transport-agnostic retry driver shared by every [`Transport`]
/// implementation, so the SPEC-TRANSPORT §7 ladder lives in exactly one
/// place instead of being reimplemented per crate.
///
/// `op` is re-invoked from scratch on every attempt — it MUST perform a
/// fresh, self-contained unit of work each call (a new HTTP request on
/// the existing connection pool, a freshly-reconnected SSH child, a
/// redialed encrypted session, …) rather than assuming any state left
/// over from a failed prior attempt is still valid. This matters most
/// for connection-oriented transports: a frame-level failure can leave
/// a stream mid-message-desynced, so `op` reconnecting before retrying
/// (rather than resuming on the same broken handle) is what makes the
/// retry safe, not just present.
///
/// `backoff` is a ladder *factory* (not a live iterator) so a fresh
/// ladder starts on every call to `retrying` — production uses
/// [`BackoffIterator::new`], tests inject a short/deterministic ladder.
/// `sleep` is the delay hook between attempts; production sleeps for
/// the full duration, tests typically inject a no-op or recorder.
///
/// Retries only the classes [`is_retryable`] accepts
/// (`ConnectionFailed`, `ServerError{5xx}`, `ServerError{429}`); every
/// other error returns immediately on the first attempt.
pub fn retrying<T>(
    mut op: impl FnMut() -> TransportResult<T>,
    backoff: fn() -> BackoffIterator,
    sleep: fn(Duration),
) -> TransportResult<T> {
    let mut ladder = backoff();
    loop {
        match op() {
            Ok(v) => return Ok(v),
            Err(err) => {
                if is_retryable(&err)
                    && let Some(delay) = ladder.next()
                {
                    sleep(delay);
                    continue;
                }
                return Err(err);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Pack bodies and sinks
// ---------------------------------------------------------------------------

/// The bytes of a sealed pack, readable from any offset as often as a
/// transport needs: once per attempt, per part, per hash pass. A push hands a
/// transport a pack spooled to disk ([`crate::pack::SpooledPack`]), so no
/// transport needs the whole pack in memory to send it.
pub trait PackBody: Send + Sync {
    /// Length of the pack in bytes.
    fn len(&self) -> u64;

    /// Whether the pack holds no bytes.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// A reader of the pack's bytes from `offset` to the end. Each call
    /// starts a reader of its own, so a retry reads the same bytes again.
    ///
    /// # Errors
    /// An I/O error, or `UnexpectedEof` for an offset past the end.
    fn read_from(&self, offset: u64) -> std::io::Result<Box<dyn std::io::Read + Send + '_>>;
}

/// A pack held in memory, for tests, small host pushes and blobs.
#[derive(Debug, Clone, Copy)]
pub struct SliceBody<'a>(pub &'a [u8]);

impl PackBody for SliceBody<'_> {
    fn len(&self) -> u64 {
        self.0.len() as u64
    }

    fn read_from(&self, offset: u64) -> std::io::Result<Box<dyn std::io::Read + Send + '_>> {
        let start = usize::try_from(offset)
            .ok()
            .filter(|&start| start <= self.0.len())
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::UnexpectedEof))?;
        Ok(Box::new(&self.0[start..]))
    }
}

/// All of `body`'s bytes in one buffer, for a transport that cannot yet send
/// a pack from a reader. It refuses a body over [`PACK_BODY_LIMIT`].
///
/// # Errors
/// [`TransportError::PayloadTooLarge`] over the limit, and
/// [`TransportError::ProtocolError`] when the body cannot be read: a local
/// failure, never retried.
pub fn read_body(body: &dyn PackBody) -> TransportResult<Vec<u8>> {
    let len = body.len();
    if len > PACK_BODY_LIMIT {
        return Err(TransportError::PayloadTooLarge(saturating_usize(len)));
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(saturating_usize(len))
        .map_err(|_| TransportError::PayloadTooLarge(saturating_usize(len)))?;
    let mut reader = body
        .read_from(0)
        .map_err(|_| TransportError::ProtocolError)?;
    std::io::Read::read_to_end(&mut std::io::Read::take(&mut reader, len), &mut bytes)
        .map_err(|_| TransportError::ProtocolError)?;
    if bytes.len() as u64 != len {
        return Err(TransportError::ProtocolError);
    }
    Ok(bytes)
}

/// `n` as a `usize`, or `usize::MAX` when it does not fit.
#[must_use]
pub fn saturating_usize(n: u64) -> usize {
    usize::try_from(n).unwrap_or(usize::MAX)
}

/// Where a downloaded pack goes. A transport calls [`Self::begin`] once per
/// attempt, then [`Self::write`] with the bytes as they arrive. The consumer
/// keeps the bytes and checks them: a sink takes a body, and nothing it
/// takes is trusted until the consumer verifies it.
pub trait PackSink: Send {
    /// Start a body, or start over after a failed attempt: bytes taken
    /// earlier are discarded. `declared` is the length the sender
    /// announced, if any.
    ///
    /// # Errors
    /// [`TransportError::PayloadTooLarge`] for a declared length over the
    /// sink's limit, before any byte. [`TransportError::ProtocolError`] once
    /// the sink has failed: a local error is never retried.
    fn begin(&mut self, declared: Option<u64>) -> TransportResult<()>;

    /// Append `bytes` to the body.
    ///
    /// # Errors
    /// [`TransportError::PayloadTooLarge`] for a byte past the declared
    /// length or the limit. After a local I/O error,
    /// [`TransportError::ProtocolError`], which no transport retries.
    fn write(&mut self, bytes: &[u8]) -> TransportResult<()>;

    /// The local I/O error that ended this sink, if any. A caller checks it
    /// before it retries, falls back or maps an error, and reports this
    /// error instead. It stays set: [`Self::begin`] never clears it.
    fn failed(&self) -> Option<std::io::ErrorKind>;
}

/// A sink that keeps a body of at most `limit` bytes in memory, for small
/// transfers such as packlist nodes.
#[derive(Debug)]
pub struct MemorySink {
    bytes: Vec<u8>,
    limit: u64,
    declared: Option<u64>,
    begun: bool,
}

impl MemorySink {
    /// A sink that takes at most `limit` bytes.
    #[must_use]
    pub fn new(limit: u64) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
            declared: None,
            begun: false,
        }
    }

    /// The body taken.
    ///
    /// # Errors
    /// [`TransportError::ProtocolError`] when no body was begun, and
    /// [`TransportError::InvalidResponse`] when it is shorter than declared.
    pub fn into_bytes(self) -> TransportResult<Vec<u8>> {
        if !self.begun {
            return Err(TransportError::ProtocolError);
        }
        if self
            .declared
            .is_some_and(|declared| declared != self.bytes.len() as u64)
        {
            return Err(TransportError::InvalidResponse);
        }
        Ok(self.bytes)
    }
}

impl PackSink for MemorySink {
    fn begin(&mut self, declared: Option<u64>) -> TransportResult<()> {
        self.begun = false;
        self.bytes.clear();
        if declared.is_some_and(|len| len > self.limit) {
            return Err(TransportError::PayloadTooLarge(saturating_usize(
                declared.unwrap_or(u64::MAX),
            )));
        }
        self.declared = declared;
        self.begun = true;
        Ok(())
    }

    fn write(&mut self, bytes: &[u8]) -> TransportResult<()> {
        if !self.begun {
            return Err(TransportError::ProtocolError);
        }
        let end = (self.bytes.len() as u64).saturating_add(bytes.len() as u64);
        if end > self.limit || self.declared.is_some_and(|declared| end > declared) {
            self.begun = false;
            return Err(TransportError::PayloadTooLarge(saturating_usize(end)));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    fn failed(&self) -> Option<std::io::ErrorKind> {
        None
    }
}

/// Write `bytes` to `sink` as one body of declared length, in reads of at
/// most [`crate::pack::SPOOL_BUFFER`] bytes. For a transport that holds a
/// pack in memory.
///
/// # Errors
/// The sink's error.
pub fn write_body(sink: &mut dyn PackSink, bytes: &[u8]) -> TransportResult<()> {
    sink.begin(Some(bytes.len() as u64))?;
    for piece in bytes.chunks(crate::pack::SPOOL_BUFFER) {
        sink.write(piece)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Transport trait
// ---------------------------------------------------------------------------

/// The kit transport vtable.
///
/// Every transport (memory, file, HTTP, S3, SSH) implements this trait.
/// Methods are synchronous and take `&self`; transports that need
/// interior mutability (e.g. connection pools) MUST use a `Mutex` /
/// `RwLock` internally. This keeps the trait object-safe.
///
/// All implementations MUST honour the retry policy in
/// SPEC-TRANSPORT §7 internally OR document that the caller is
/// responsible — the abstract trait takes no position. The
/// [`is_retryable`] and [`BackoffIterator`] helpers are provided for
/// implementations that embed the policy.
/// The repository a transport addresses, for remote error context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct RepositoryAddress<'a> {
    /// Repository identity as sent on the wire (STC §7.4).
    pub repository: &'a str,
    /// Origin (scheme and authority) of the remote.
    pub origin: &'a str,
}

impl<'a> RepositoryAddress<'a> {
    /// Build an address from a repository identity and a remote origin.
    #[must_use]
    pub const fn new(repository: &'a str, origin: &'a str) -> Self {
        Self { repository, origin }
    }
}

/// The most bytes a [`RepoCursor`] holds (SPEC-TRANSPORT §1.2).
pub const REPO_CURSOR_MAX_LEN: usize = 64;

/// An opaque token for the state of a repository's refs (SPEC-TRANSPORT
/// §1.2). Two cursors of one repository compare equal only when its refs are
/// unchanged between them. A cursor carries no order: compare it for
/// equality and nothing else.
#[derive(Clone, PartialEq, Eq)]
pub struct RepoCursor(Vec<u8>);

impl RepoCursor {
    /// Wrap `bytes`. An empty cursor or one over [`REPO_CURSOR_MAX_LEN`]
    /// bytes is [`TransportError::InvalidResponse`].
    pub fn new(bytes: &[u8]) -> TransportResult<Self> {
        if bytes.is_empty() || bytes.len() > REPO_CURSOR_MAX_LEN {
            return Err(TransportError::InvalidResponse);
        }
        Ok(Self(bytes.to_vec()))
    }

    /// The cursor bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for RepoCursor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RepoCursor({} bytes)", self.0.len())
    }
}

pub trait Transport: Send + Sync {
    /// Whether the remote supports the attestation log. Unknown sources refuse.
    fn supports_attestations(&self) -> bool { false }

    /// Publish the attestation log and consume its uploaded pack and node keys.
    fn write_attestmap(&self, condition: RefWriteCondition, tip: &Hash, keys: &[PackKey]) -> TransportResult<()> {
        let _ = (condition, tip, keys);
        Err(TransportError::ProtocolError)
    }

    /// Repository identity and origin used for remote error context, if available.
    /// Existing transports carry no addressing context by default.
    fn repository_address(&self) -> Option<RepositoryAddress<'_>> {
        None
    }

    /// The repository cursor (SPEC-TRANSPORT §1.2), or `None` when the
    /// transport does not offer one. Reading it reads no ref.
    fn repo_cursor(&self) -> TransportResult<Option<RepoCursor>> {
        Ok(None)
    }

    /// Upload a sealed pack. The key is BLAKE3 of the whole pack, computed
    /// by the caller before the first byte is sent; servers MAY dedupe on
    /// it. `head_ref` is the head the pack is for: transports with upload
    /// tickets authorize by it, and the others ignore it. A retry reads
    /// `pack` again from its start.
    fn upload_pack(
        &self,
        pack: &dyn PackBody,
        key: &PackKey,
        head_ref: Option<&str>,
    ) -> TransportResult<()>;

    /// Download a pack by its key into `sink`: [`PackSink::begin`] once per
    /// attempt, with the length when the remote declares one, then the
    /// bytes. The caller checks them against the key. `ref_hint` is a
    /// read-your-writes hint, ignored where it means nothing.
    ///
    /// Returns [`TransportError::PackNotFound`] if the remote does not hold
    /// this key. A transport never retries an attempt after
    /// [`PackSink::failed`] is set.
    fn download_pack(
        &self,
        key: &PackKey,
        ref_hint: Option<&str>,
        sink: &mut dyn PackSink,
    ) -> TransportResult<()>;

    /// HEAD-check a pack. Cheaper than [`Self::download_pack`] on network
    /// transports. `ref_hint` as for [`Self::download_pack`].
    fn pack_exists(&self, key: &PackKey, ref_hint: Option<&str>) -> TransportResult<bool>;

    /// Upload a content-addressed **auxiliary blob**: transfer metadata
    /// that is NOT a packfile, such as a packlist chain node. The key is
    /// BLAKE3 of `bytes`, exactly like a pack.
    ///
    /// Auxiliary blobs share the key-addressed store with packs, so the
    /// default uploads `bytes` as a pack. The distinct verb keeps the kind
    /// explicit at the call site.
    fn upload_blob(
        &self,
        bytes: &[u8],
        key: &PackKey,
        head_ref: Option<&str>,
    ) -> TransportResult<()> {
        self.upload_pack(&SliceBody(bytes), key, head_ref)
    }

    /// Download an auxiliary blob of at most `max` bytes. A longer blob is
    /// [`TransportError::PayloadTooLarge`], refused from its declared length
    /// before its body is read where the remote declares one. The default
    /// downloads it as a pack into a [`MemorySink`].
    fn download_blob(
        &self,
        key: &PackKey,
        ref_hint: Option<&str>,
        max: u64,
    ) -> TransportResult<Vec<u8>> {
        let mut sink = MemorySink::new(max);
        self.download_pack(key, ref_hint, &mut sink)?;
        sink.into_bytes()
    }

    /// Unconditional ref write — equivalent to
    /// `update_ref(name, RefWriteCondition::Any, hash)`.
    ///
    /// Default impl delegates to [`Self::update_ref`] so transports only
    /// implement one entry point.
    fn write_ref(&self, name: &str, hash: &Hash) -> TransportResult<()> {
        self.update_ref(name, RefWriteCondition::Any, hash)
    }

    /// CAS ref write. See [`RefWriteCondition`].
    ///
    /// On `.missing` / `.match` CAS failure, returns
    /// [`TransportError::RefConflict`]. Callers retrying after a
    /// timeout MUST follow up with [`Self::read_ref`] to confirm
    /// whether the first attempt actually landed (SPEC-TRANSPORT §7).
    fn update_ref(
        &self,
        name: &str,
        condition: RefWriteCondition,
        hash: &Hash,
    ) -> TransportResult<()>;

    /// Delete `name` if it holds `expected` (SPEC-TRANSPORT §1). A ref that
    /// is absent or holds another value is [`TransportError::RefConflict`],
    /// and nothing is deleted. No transport offers an unconditional delete;
    /// one that cannot condition a delete refuses every delete before it
    /// writes anything.
    fn delete_ref(&self, name: &str, expected: &Hash) -> TransportResult<()>;

    /// Delete a head ref, then its chain ref (`refs/kit/packmap/<b>` or
    /// `refs/kit/tagmap/<t>`), each under `Match` (SPEC-TRANSPORT §7.3).
    /// With `map_expected` `None` the head has no chain ref, and only the
    /// head is deleted.
    ///
    /// [`AdvanceOutcome::HeadConflict`] means the head did not hold
    /// `head_expected` and nothing was deleted. A transport that deletes both
    /// refs in one transaction reports a moved chain ref as
    /// [`AdvanceOutcome::PackmapConflict`], with nothing deleted.
    ///
    /// The default deletes the head and then the chain ref, one
    /// [`Self::delete_ref`] each. Once the head is gone the delete has
    /// happened, so a failed chain-ref delete, a lost CAS or any other
    /// error, still reports [`AdvanceOutcome::Committed`], as a crash
    /// between the two would. The chain ref it leaves behind is harmless: a
    /// fetch reads it as a stale listing, and the next push of that name
    /// appends to it.
    fn delete_refs(
        &self,
        head: &str,
        head_expected: &Hash,
        map: &str,
        map_expected: Option<&Hash>,
    ) -> TransportResult<AdvanceOutcome> {
        match self.delete_ref(head, head_expected) {
            Ok(()) => {}
            Err(TransportError::RefConflict) => return Ok(AdvanceOutcome::HeadConflict),
            Err(e) => return Err(e),
        }
        if let Some(expected) = map_expected {
            // The head is gone: a chain ref left behind is a leftover.
            let _ = self.delete_ref(map, expected);
        }
        Ok(AdvanceOutcome::Committed)
    }

    /// Read the current value of a ref, or `None` if it does not exist.
    fn read_ref(&self, name: &str) -> TransportResult<Option<Hash>>;

    /// List refs whose full name starts with `prefix`. Returned names
    /// have `prefix` stripped per SPEC-REFS §4. An empty prefix lists
    /// every ref.
    fn list_refs(&self, prefix: &str) -> TransportResult<Vec<Ref>>;

    /// How [`Self::list_refs`] answers: an ordered read that pages, by
    /// default. A transport whose listing comes in one bounded frame, or
    /// whose listing may lag a write, says so.
    fn ref_listing(&self) -> RefListing {
        RefListing::Ordered
    }

    /// Advance a branch by updating its **head ref and its packmap ref
    /// together**, each under its own CAS precondition.
    ///
    /// This exists so the delta-transfer invariant — "if `head_ref` resolves
    /// to T, the packmap reconstructs `closure(T)`" — can be upheld without a
    /// window where the two refs disagree. A transport backed by a
    /// transactional ref store SHOULD override this to apply both writes in
    /// ONE transaction: then a failed advance changes nothing, and the head
    /// is never observed past a packmap that can't yet reconstruct it.
    ///
    /// The default impl is the non-transactional approximation used by
    /// stores without multi-ref transactions: it writes the **packmap first**
    /// (durable before the head moves) then the head. A crash in between
    /// leaves the head at its prior value and the packmap a superset — still
    /// consistent for fetch while concurrent writes also preserve the chain.
    /// This ordering cannot protect against a concurrent reset. A
    /// transport that offers an atomic or serialized advance provides its
    /// own two-ref advance, and force pushes against it use the guarded
    /// force driver.
    /// The [`AdvanceOutcome`] distinguishes a packmap
    /// precondition failure (caller re-reads and retries the chain) from a
    /// head precondition failure (caller treats it as non-fast-forward),
    /// which a single `RefConflict` could not.
    fn advance_refs(
        &self,
        head_ref: &str,
        head_condition: RefWriteCondition,
        head_value: &Hash,
        packmap_ref: &str,
        packmap_condition: RefWriteCondition,
        packmap_value: &Hash,
    ) -> TransportResult<AdvanceOutcome> {
        match self.update_ref(packmap_ref, packmap_condition, packmap_value) {
            Ok(()) => {}
            Err(TransportError::RefConflict) => return Ok(AdvanceOutcome::PackmapConflict),
            Err(e) => return Err(e),
        }
        match self.update_ref(head_ref, head_condition, head_value) {
            Ok(()) => Ok(AdvanceOutcome::Committed),
            Err(TransportError::RefConflict) => Ok(AdvanceOutcome::HeadConflict),
            Err(e) => Err(e),
        }
    }

    /// Advance both refs while committing any upload tickets for `commit`.
    /// Other transports ignore the pack keys and use their existing advance.
    #[allow(clippy::too_many_arguments)]
    fn advance_refs_committing(
        &self,
        head_ref: &str,
        head_condition: RefWriteCondition,
        head_value: &Hash,
        packmap_ref: &str,
        packmap_condition: RefWriteCondition,
        packmap_value: &Hash,
        _commit: &[PackKey],
    ) -> TransportResult<CommitOutcome> {
        self.advance_refs(
            head_ref,
            head_condition,
            head_value,
            packmap_ref,
            packmap_condition,
            packmap_value,
        )
        .map(CommitOutcome::Advanced)
    }

    /// Limits the remote advertises to the push planner. `None` means the
    /// transport does not impose an additional limit.
    fn upload_limits(&self) -> UploadLimits {
        UploadLimits::default()
    }

    /// Head precondition for a force push using an atomic or serialized
    /// advance.
    ///
    /// The default keeps the unconditional force-write intent. Transports
    /// whose atomic endpoint cannot encode [`RefWriteCondition::Any`] must
    /// override this to match `observed_head` (or require a missing head).
    /// Push pairs this condition with a packmap precondition and retries a
    /// concurrent head change, so force pushes never use an ordered fallback.
    /// Only used when [`Self::supports_atomic_advance`] or
    /// [`Self::supports_serialized_advance`] returns `true`.
    fn atomic_force_head_condition(&self, _observed_head: Option<Hash>) -> RefWriteCondition {
        RefWriteCondition::Any
    }

    /// Whether [`Self::advance_refs`] commits the head + packmap advance as
    /// one indivisible transaction, rather than the default's ordered
    /// packmap-then-head writes.
    ///
    /// The default (non-transactional) `advance_refs` is safe for an
    /// **appending** packmap write if concurrent writers preserve that chain:
    /// per its doc comment, a crash or lost
    /// head-CAS race between the two writes leaves the packmap a strict
    /// superset of what the (unmoved) head needs — still reconstructable.
    /// A re-baseline, the node with `prev = None` that lists every pack of
    /// the chain it replaces, is a superset too. That safety argument does
    /// NOT extend to a packmap **reset**, a node with `prev = None` that
    /// drops packs of the chain it replaces: a reset is not a superset of
    /// the prior chain, so a
    /// packmap write that commits while the paired head write loses its CAS
    /// would strand the (still-unmoved) head pointing at a commit whose
    /// closure the reset packmap can no longer reconstruct.
    ///
    /// Callers MUST treat `false` (the default) as "never request a
    /// packmap reset against this transport", unless
    /// [`Self::supports_serialized_advance`] is `true` and the push is a
    /// verified fast-forward of the head it conditions on
    /// (SPEC-TRANSPORT §7.2). Override to
    /// `true` ONLY when [`Self::advance_refs`] is overridden with a
    /// genuinely transactional implementation (e.g. the HTTP transport's
    /// single-request `/refs/advance` endpoint). If that endpoint
    /// cannot encode an unconditional head write, also override
    /// [`Self::atomic_force_head_condition`] so force pushes stay atomic.
    fn supports_atomic_advance(&self) -> bool {
        false
    }

    /// Whether [`Self::advance_refs`] is serialized for writers: it checks
    /// both conditions before it writes either ref, a conflict changes
    /// nothing, and no other write to either ref interleaves with it.
    /// Readers may still see the packmap written before the head, and a
    /// crash between the two writes may leave the new packmap with the old
    /// head.
    ///
    /// Every atomic advance is serialized, so the default returns
    /// [`Self::supports_atomic_advance`]. A transport that overrides this
    /// to `true` without an atomic advance gets a packmap reset only for a
    /// push that is a verified fast-forward of the head it conditions on:
    /// the reset then also rebuilds that head's closure, so the state a
    /// reader or a crash can expose stays consistent. Force pushes against
    /// it use the guarded force driver, which never appends a pack whose
    /// planned bases a concurrent reset dropped.
    fn supports_serialized_advance(&self) -> bool {
        self.supports_atomic_advance()
    }

    /// Known atomic-advance capability. Discovery-based transports return
    /// `None` when discovery failed or was invalid: force pushes must refuse
    /// rather than assume concurrent writers cannot reset the packmap.
    fn atomic_advance_status(&self) -> Option<bool> {
        Some(self.supports_atomic_advance())
    }
}

/// Result of [`Transport::advance_refs`] — a two-ref branch advance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdvanceOutcome {
    /// Both refs were updated.
    Committed,
    /// The head precondition did not hold. An atomic transport leaves
    /// nothing changed. Callers re-read the head (SPEC-TRANSPORT §7): if it
    /// already holds their target, a retried write landed and the advance
    /// succeeded; otherwise the branch moved under them (non-fast-forward).
    HeadConflict,
    /// The packmap precondition did not hold (a concurrent pusher advanced
    /// the chain). Callers re-read the packmap and retry.
    PackmapConflict,
}

/// Result of an advance that can consume upload tickets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CommitOutcome {
    /// The advance reached the ordinary two-ref outcome.
    Advanced(AdvanceOutcome),
    /// A ticket was invalid, expired, incomplete, or was already consumed.
    TicketRejected,
    /// A delta base is not yet available to this repository.
    DeltaBaseUnavailable,
    /// The packlist names content not in this repository.
    PacklistNotInRepository,
}

/// How a remote's ref listing answers, which a tag push needs to know.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefListing {
    /// The listing reflects every write that completed before it, and it
    /// pages, so its size has no bound of its own.
    Ordered,
    /// As [`RefListing::Ordered`], but `kit serve` answers a listing in one
    /// frame of about 1 MiB. Its `kit+ssh` remotes and `kit+file` roots,
    /// which `kit serve` may serve, keep each listing within that frame.
    OneFrame,
    /// The listing may lag a completed write, as a Connect server's may. A
    /// strong `read_ref` is the authority.
    Eventual,
}

/// Server limits relevant to splitting a push into packs and advances.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct UploadLimits {
    /// Maximum accepted serialized pack bytes, if advertised.
    pub max_pack_bytes: Option<u64>,
    /// Most data packs one advance may carry, when the transport issues upload
    /// tickets. An advance names one ticket for its packmap node, so this is
    /// one fewer than the ticket allowance. `None` means no tickets.
    pub data_packs_per_advance: Option<usize>,
    /// First serialized pack size that requires a ticket, when known.
    /// A transport may stop requiring tickets after discovery fallback.
    pub ticket_threshold_bytes: Option<u64>,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read as _;

    #[test]
    fn a_repo_cursor_holds_its_bytes_within_the_bound_and_hides_them_in_debug() {
        for bytes in [&[][..], &[7; REPO_CURSOR_MAX_LEN + 1]] {
            assert!(matches!(
                RepoCursor::new(bytes),
                Err(TransportError::InvalidResponse)
            ));
        }
        for bytes in [vec![0], vec![1], vec![7; REPO_CURSOR_MAX_LEN]] {
            let cursor = RepoCursor::new(&bytes).unwrap();
            assert_eq!(cursor.as_bytes(), bytes);
            assert_eq!(
                format!("{cursor:?}"),
                format!("RepoCursor({} bytes)", bytes.len())
            );
        }
        assert_ne!(
            RepoCursor::new(&[0]).unwrap(),
            RepoCursor::new(&[1]).unwrap()
        );
    }

    #[test]
    fn remote_text_is_escaped_when_displayed() {
        let e = TransportError::RemoteError("\x1b[2Jx\u{202e}".into());
        assert_eq!(e.to_string(), "remote error: \\u{1b}[2Jx\\u{202e}");
        let e = TransportError::InvalidRef("a\x07b".into());
        assert_eq!(e.to_string(), "invalid ref name: a\\u{7}b");
    }

    #[test]
    fn remote_text_is_cut_when_displayed() {
        let e = TransportError::RemoteError("a".repeat(10 * MAX_REMOTE_ERROR_TEXT));
        assert_eq!(
            e.to_string(),
            format!("remote error: {}", "a".repeat(MAX_REMOTE_ERROR_TEXT))
        );
        // The cut falls inside a multi-byte character: it backs up.
        let e = TransportError::RemoteError("é".repeat(MAX_REMOTE_ERROR_TEXT));
        assert_eq!(
            e.to_string(),
            format!("remote error: {}", "é".repeat(MAX_REMOTE_ERROR_TEXT / 2))
        );
    }

    #[test]
    fn pack_key_hex_roundtrip() {
        let bytes = [0x42u8; 32];
        let pk = PackKey::new(bytes);
        let hex = pk.to_hex();
        assert_eq!(hex.len(), 64);
        let pk2 = pack_key_from_hex(&hex).unwrap();
        assert_eq!(pk, pk2);
    }

    #[test]
    fn is_retryable_matches_spec() {
        assert!(is_retryable(&TransportError::ConnectionFailed));
        assert!(is_retryable(&TransportError::ServerError { status: 500 }));
        assert!(is_retryable(&TransportError::ServerError { status: 503 }));
        assert!(is_retryable(&TransportError::ServerError { status: 429 }));
        assert!(!is_retryable(&TransportError::ServerError { status: 404 }));
        assert!(!is_retryable(&TransportError::ServerError { status: 401 }));
        assert!(!is_retryable(&TransportError::PackNotFound));
        assert!(!is_retryable(&TransportError::AccessDenied));
        assert!(!is_retryable(&TransportError::TlsConfiguration(
            "bad CA file".into()
        )));
        assert!(!is_retryable(&TransportError::RefConflict));
    }

    #[test]
    fn backoff_default_ladder_is_1_2_4_8_16() {
        let delays: Vec<Duration> = BackoffIterator::new().collect();
        assert_eq!(
            delays,
            vec![
                Duration::from_secs(1),
                Duration::from_secs(2),
                Duration::from_secs(4),
                Duration::from_secs(8),
                Duration::from_secs(16),
            ]
        );
    }

    #[test]
    fn backoff_caps_at_max() {
        let cap = Duration::from_secs(10);
        let delays: Vec<Duration> = BackoffIterator::with(Duration::from_secs(8), cap, 5).collect();
        // 8s, then cap (16s would exceed 10s cap; clamped to 10s)
        assert_eq!(delays[0], Duration::from_secs(8));
        for d in &delays[1..] {
            assert!(*d <= cap);
        }
    }

    // -----------------------------------------------------------------
    // Default verbs, bodies and sinks
    // -----------------------------------------------------------------

    /// The bytes, key and head ref of the last upload.
    type Upload = (Vec<u8>, PackKey, Option<String>);

    /// Minimal in-memory [`Transport`] that implements only the required
    /// verbs, so the defaults are under test.
    #[derive(Default)]
    struct RecordingTransport {
        uploaded: std::sync::Mutex<Option<Upload>>,
        stored: std::sync::Mutex<std::collections::HashMap<[u8; 32], Vec<u8>>>,
        atomic: bool,
        /// Every ref a delete removed, in order.
        deleted: std::sync::Mutex<Vec<String>>,
        /// A ref whose delete loses its CAS.
        conflict_on: Option<&'static str>,
        /// A ref whose delete fails with another error.
        fail_on: Option<&'static str>,
    }

    impl Transport for RecordingTransport {
        fn upload_pack(
            &self,
            pack: &dyn PackBody,
            key: &PackKey,
            head_ref: Option<&str>,
        ) -> TransportResult<()> {
            let bytes = read_body(pack)?;
            *self.uploaded.lock().unwrap() = Some((bytes.clone(), *key, head_ref.map(Into::into)));
            self.stored.lock().unwrap().insert(*key.as_bytes(), bytes);
            Ok(())
        }

        fn download_pack(
            &self,
            key: &PackKey,
            _ref_hint: Option<&str>,
            sink: &mut dyn PackSink,
        ) -> TransportResult<()> {
            let bytes = self
                .stored
                .lock()
                .unwrap()
                .get(key.as_bytes())
                .cloned()
                .ok_or(TransportError::PackNotFound)?;
            write_body(sink, &bytes)
        }

        fn pack_exists(&self, _key: &PackKey, _ref_hint: Option<&str>) -> TransportResult<bool> {
            unimplemented!("not exercised by these tests")
        }

        fn update_ref(
            &self,
            _name: &str,
            _condition: RefWriteCondition,
            _hash: &Hash,
        ) -> TransportResult<()> {
            unimplemented!("not exercised by these tests")
        }

        fn delete_ref(&self, name: &str, _expected: &Hash) -> TransportResult<()> {
            if self.conflict_on == Some(name) {
                return Err(TransportError::RefConflict);
            }
            if self.fail_on == Some(name) {
                return Err(TransportError::ConnectionFailed);
            }
            self.deleted.lock().unwrap().push(name.to_owned());
            Ok(())
        }

        fn read_ref(&self, _name: &str) -> TransportResult<Option<Hash>> {
            unimplemented!("not exercised by these tests")
        }

        fn list_refs(&self, _prefix: &str) -> TransportResult<Vec<Ref>> {
            unimplemented!("not exercised by these tests")
        }

        fn supports_atomic_advance(&self) -> bool {
            self.atomic
        }
    }

    const HEAD: &str = "refs/heads/main";
    const MAP: &str = "refs/kit/packmap/main";

    fn delete_pair(transport: &RecordingTransport, map: Option<&Hash>) -> AdvanceOutcome {
        transport.delete_refs(HEAD, &[1; 32], MAP, map).unwrap()
    }

    /// The default delete removes the head, then its chain ref.
    #[test]
    fn default_delete_removes_the_head_then_its_chain_ref() {
        let transport = RecordingTransport::default();
        assert_eq!(
            delete_pair(&transport, Some(&[2; 32])),
            AdvanceOutcome::Committed
        );
        assert_eq!(*transport.deleted.lock().unwrap(), [HEAD, MAP]);
    }

    /// A head without a chain ref is deleted alone.
    #[test]
    fn default_delete_of_a_head_without_a_chain_ref_deletes_the_head_only() {
        let transport = RecordingTransport::default();
        assert_eq!(delete_pair(&transport, None), AdvanceOutcome::Committed);
        assert_eq!(*transport.deleted.lock().unwrap(), [HEAD]);
    }

    /// A head that lost its CAS is a conflict, and the chain ref is never
    /// touched.
    #[test]
    fn default_delete_with_a_stale_head_deletes_nothing() {
        let transport = RecordingTransport {
            conflict_on: Some(HEAD),
            ..RecordingTransport::default()
        };
        assert_eq!(
            delete_pair(&transport, Some(&[2; 32])),
            AdvanceOutcome::HeadConflict
        );
        assert!(transport.deleted.lock().unwrap().is_empty());
    }

    /// Once the head is gone the delete has happened: a lost CAS or another
    /// failure on the chain ref leaves it behind and still reports success.
    #[test]
    fn default_delete_succeeds_once_the_head_is_gone() {
        for (conflict_on, fail_on) in [(Some(MAP), None), (None, Some(MAP))] {
            let transport = RecordingTransport {
                conflict_on,
                fail_on,
                ..RecordingTransport::default()
            };
            assert_eq!(
                delete_pair(&transport, Some(&[2; 32])),
                AdvanceOutcome::Committed
            );
            assert_eq!(*transport.deleted.lock().unwrap(), [HEAD]);
        }
    }

    /// A head delete that fails for another reason is surfaced, and the
    /// chain ref is never touched.
    #[test]
    fn default_delete_surfaces_a_failed_head_delete() {
        let transport = RecordingTransport {
            fail_on: Some(HEAD),
            ..RecordingTransport::default()
        };
        assert!(matches!(
            transport.delete_refs(HEAD, &[1; 32], MAP, Some(&[2; 32])),
            Err(TransportError::ConnectionFailed)
        ));
        assert!(transport.deleted.lock().unwrap().is_empty());
    }

    /// Every atomic advance is serialized; an ordered one is neither.
    #[test]
    fn serialized_advance_defaults_to_atomic_advance() {
        for atomic in [false, true] {
            let transport = RecordingTransport {
                atomic,
                ..RecordingTransport::default()
            };
            assert_eq!(transport.supports_serialized_advance(), atomic);
        }
    }

    #[test]
    fn a_blob_goes_up_as_a_pack_and_comes_back_within_its_bound() {
        let transport = RecordingTransport::default();
        let bytes = b"test pack";
        let key = PackKey::new(crate::hash::hash(bytes));
        transport
            .upload_blob(bytes, &key, Some("refs/heads/main"))
            .unwrap();
        let (sent, _, head_ref) = transport.uploaded.lock().unwrap().clone().unwrap();
        assert_eq!(sent, bytes);
        assert_eq!(head_ref.as_deref(), Some("refs/heads/main"));
        assert_eq!(
            transport
                .download_blob(&key, None, bytes.len() as u64)
                .unwrap(),
            bytes
        );
        assert!(matches!(
            transport.download_blob(&key, None, bytes.len() as u64 - 1),
            Err(TransportError::PayloadTooLarge(_))
        ));
        assert_eq!(transport.upload_limits(), UploadLimits::default());
    }

    #[test]
    fn atomic_force_head_condition_defaults_to_any() {
        let transport = RecordingTransport::default();
        assert_eq!(
            transport.atomic_force_head_condition(Some([1; 32])),
            RefWriteCondition::Any
        );
        assert_eq!(
            transport.atomic_force_head_condition(None),
            RefWriteCondition::Any
        );
    }

    #[test]
    fn a_slice_body_reads_from_any_offset_as_often_as_asked() {
        let body = SliceBody(b"0123456789");
        for _ in 0..2 {
            let mut tail = Vec::new();
            body.read_from(4).unwrap().read_to_end(&mut tail).unwrap();
            assert_eq!(tail, b"456789");
        }
        assert_eq!(read_body(&body).unwrap(), b"0123456789");
        assert!(body.read_from(11).is_err());
    }

    #[test]
    fn a_memory_sink_refuses_a_declared_length_over_its_limit_before_any_byte() {
        let mut sink = MemorySink::new(4);
        assert!(matches!(
            sink.begin(Some(5)),
            Err(TransportError::PayloadTooLarge(_))
        ));
        assert!(matches!(
            sink.write(b"a"),
            Err(TransportError::ProtocolError)
        ));
    }

    #[test]
    fn a_memory_sink_refuses_bytes_past_its_declared_length_or_its_limit() {
        let mut sink = MemorySink::new(4);
        sink.begin(Some(2)).unwrap();
        assert!(sink.write(b"abc").is_err());
        sink.begin(None).unwrap();
        sink.write(b"abcd").unwrap();
        assert!(sink.write(b"e").is_err());
    }

    #[test]
    fn a_memory_sink_starts_over_on_begin_and_checks_the_declared_length() {
        let mut sink = MemorySink::new(16);
        sink.begin(Some(3)).unwrap();
        sink.write(b"xy").unwrap();
        sink.begin(Some(3)).unwrap();
        sink.write(b"abc").unwrap();
        assert_eq!(sink.into_bytes().unwrap(), b"abc");
        let mut short = MemorySink::new(16);
        short.begin(Some(3)).unwrap();
        short.write(b"ab").unwrap();
        assert!(matches!(
            short.into_bytes(),
            Err(TransportError::InvalidResponse)
        ));
        assert!(MemorySink::new(16).into_bytes().is_err());
    }

    // -----------------------------------------------------------------
    // retrying() driver
    // -----------------------------------------------------------------

    fn test_backoff() -> BackoffIterator {
        BackoffIterator::with(Duration::from_millis(1), Duration::from_millis(1), 5)
    }

    fn no_sleep(_delay: Duration) {}

    #[test]
    fn retrying_succeeds_on_first_try_without_sleeping() {
        use core::sync::atomic::{AtomicUsize, Ordering};

        fn record_sleep(_delay: Duration) {
            SLEEPS.fetch_add(1, Ordering::SeqCst);
        }

        static CALLS: AtomicUsize = AtomicUsize::new(0);
        static SLEEPS: AtomicUsize = AtomicUsize::new(0);
        CALLS.store(0, Ordering::SeqCst);
        SLEEPS.store(0, Ordering::SeqCst);

        let result = retrying::<u32>(
            || {
                CALLS.fetch_add(1, Ordering::SeqCst);
                Ok(7)
            },
            test_backoff,
            record_sleep,
        );

        assert_eq!(result.unwrap(), 7);
        assert_eq!(CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(SLEEPS.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn retrying_recovers_after_transient_connection_failures() {
        use core::sync::atomic::{AtomicUsize, Ordering};
        static CALLS: AtomicUsize = AtomicUsize::new(0);
        CALLS.store(0, Ordering::SeqCst);

        let result = retrying::<u32>(
            || {
                let n = CALLS.fetch_add(1, Ordering::SeqCst);
                if n < 3 {
                    Err(TransportError::ConnectionFailed)
                } else {
                    Ok(42)
                }
            },
            test_backoff,
            no_sleep,
        );

        assert_eq!(result.unwrap(), 42);
        assert_eq!(CALLS.load(Ordering::SeqCst), 4);
    }

    #[test]
    fn retrying_gives_up_after_ladder_exhausts() {
        use core::sync::atomic::{AtomicUsize, Ordering};
        static CALLS: AtomicUsize = AtomicUsize::new(0);
        CALLS.store(0, Ordering::SeqCst);

        let result = retrying::<u32>(
            || {
                CALLS.fetch_add(1, Ordering::SeqCst);
                Err(TransportError::ConnectionFailed)
            },
            test_backoff,
            no_sleep,
        );

        assert!(matches!(result, Err(TransportError::ConnectionFailed)));
        // 5-attempt ladder => 1 initial + 5 retries = 6 total calls.
        assert_eq!(CALLS.load(Ordering::SeqCst), 6);
    }

    #[test]
    fn retrying_does_not_retry_non_retryable_errors() {
        use core::sync::atomic::{AtomicUsize, Ordering};
        static CALLS: AtomicUsize = AtomicUsize::new(0);
        CALLS.store(0, Ordering::SeqCst);

        let result = retrying::<u32>(
            || {
                CALLS.fetch_add(1, Ordering::SeqCst);
                Err(TransportError::PackNotFound)
            },
            test_backoff,
            no_sleep,
        );

        assert!(matches!(result, Err(TransportError::PackNotFound)));
        assert_eq!(CALLS.load(Ordering::SeqCst), 1);
    }
}
