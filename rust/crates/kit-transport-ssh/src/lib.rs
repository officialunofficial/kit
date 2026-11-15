#![cfg_attr(not(test), deny(clippy::print_stdout, clippy::print_stderr))]
#![doc = include_str!("../README.md")]
//!
//! kit SSH transport.
//!
//! Implements [`kit_core::protocol::Transport`] over a long-lived
//! system `ssh(1)` child process, exchanging the seven kit verbs as
//! length-prefixed protobuf [`SshFrame`] messages defined in
//! `kit-rpc/proto/kit/rpc/v1/ssh/ssh.proto` (buffa is the Rust runtime kit uses;
//! the wire is plain protobuf 3 / edition 2023).
//!
//! # Design choice: `std::process::Command`, NOT `russh`
//!
//! SSH-SECURITY.md §1 is explicit: kit does NOT implement its own SSH
//! client. It shells out to `ssh(1)` and delegates host-key
//! verification, agent handling, credential selection, and kex to the
//! user's installed OpenSSH. Same posture `git+ssh://` takes:
//!
//! - Our binary does not need to ship a crypto stack (no `russh`,
//!   `rustls`, `openssl`, `native-tls`).
//! - `ssh-agent`, `~/.ssh/config`, `ProxyCommand`, and every other
//!   knob the user already configured Just Work, with zero kit code.
//! - Host-key rotation / trust escalation stays on the OpenSSH side,
//!   where it belongs — see SSH-SECURITY.md §4 for the gaps we inherit
//!   from this choice.
//!
//! The Transport trait itself is synchronous (object-safe, `&self`,
//! `TransportResult<T>`), so wrapping `Command::spawn` + blocking
//! stdio is the shortest path to parity with the other transports.

#![forbid(unsafe_code)]
// `ref_option` flags `&Option<T>` arguments. Wire-frame fields are
// `Option<T>` (Edition 2023 explicit presence); passing references
// through helpers is the natural shape — the `Option<&T>` rewrite
// forces a borrow at every callsite.
#![allow(clippy::ref_option)]
#![allow(clippy::items_after_statements)]
#![allow(clippy::manual_let_else)]
// `cast_possible_truncation` fires on `total as usize` for pack-chunk
// offsets. Pack sizes are bounded well below usize::MAX on every
// supported platform.
#![allow(clippy::cast_possible_truncation)]

pub mod url;

use std::io;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use kit_core::hash::Hash;
use kit_core::protocol::{
    BackoffIterator, PackKey, RepoCursor, Transport, TransportError, TransportResult,
};
use kit_core::refs::{Ref, RefWriteCondition, validate_ref_name, validate_ref_prefix};
use kit_rpc::kit::rpc::v1::ssh::{
    DownloadPack, Hello, ListRefs, PackChunk, PackExists, ReadRef, ReadRepoCursor, SshFrame,
    UpdateRef, UploadPack, ssh_frame,
};
use kit_rpc::kit::rpc::v1::{ErrorCode, ProtocolVersion};
use kit_rpc::{
    CHUNK_DATA_MAX, FrameError, MAX_REF_NAME, body_name, cond_to_wire, list_response_refs,
    map_update_ref_error, read_frame, rpc_error_to_transport, unexpected_frame, write_frame,
};

pub use crate::url::{KIT_SSH_PREFIX, SshTarget, parse_kit_ssh_url, validate_ssh_path};

use kit_core::protocol::{PACK_BODY_LIMIT, PackBody, PackSink, saturating_usize};

/// Client identification string sent in the `Hello` frame. Inherited
/// from the workspace version, so a release bump propagates
/// automatically.
const CLIENT_ID: &str = concat!("kit ", env!("CARGO_PKG_VERSION"));

/// Default timeout for SSH handshake replies, verb responses, and child shutdown.
pub const DEFAULT_SSH_TIMEOUT: Duration = Duration::from_secs(30);

/// Optional SSH CLI knobs threaded from `.kit/config`. All fields default
/// to empty, which means "inherit the user's `ssh(1)` defaults". See
/// SPEC-TRANSPORT §4.3 for the canonical field list.
#[derive(Debug, Default, Clone)]
pub struct SshOptions {
    /// `-o StrictHostKeyChecking=<value>`. Empty → do not pass.
    pub strict_host_key_checking: String,
    /// `-o UserKnownHostsFile=<path>`. Empty → do not pass.
    pub user_known_hosts_file: String,
    /// `-i <file>`. Empty → do not pass. ssh(1) defaults to
    /// `~/.ssh/id_ed25519`, then `~/.ssh/id_rsa`, agent-first.
    pub identity_file: String,
}

/// Errors raised while bringing up the SSH child — before the first
/// [`Transport`] verb is ever called.
#[derive(Debug, thiserror::Error)]
pub enum SshInitError {
    /// The URL failed `parse_kit_ssh_url` / `validate_ssh_path`.
    #[error(transparent)]
    InvalidUrl(#[from] TransportError),
    /// Could not spawn `ssh`. Usually means the binary is not on
    /// `$PATH` or the fork/exec itself failed.
    #[error("failed to spawn ssh: {0}")]
    Spawn(#[from] io::Error),
    /// Hello handshake failed — wrong proto version, server-emitted
    /// Error frame, or unparseable reply.
    #[error("ssh hello handshake failed: {0}")]
    HandshakeFailed(String),
}

/// Transport over a spawned `ssh(1)` child process.
///
/// Construction spawns the child, sends the mandatory `Hello` frame,
/// and validates the server's reply. If any of those steps fail the
/// child is torn down before the constructor returns, so a successful
/// [`SshTransport::connect`] ALWAYS yields a handle whose first verb
/// call lands on a v1 kit server.
///
/// ## Retry / reconnect (SPEC-TRANSPORT §7)
///
/// Every verb is driven through [`kit_core::protocol::retrying`]. A
/// `ConnectionFailed` on the child pipe (broken stdin/stdout, a
/// desynced frame stream, a stalled handshake) marks the connection
/// `closed`; before each retry attempt the transport transparently
/// spawns a *new* `ssh` child from the same `target`/`options` and
/// redoes the `Hello` handshake, then re-issues the verb from scratch
/// against the fresh connection. This is required for correctness, not
/// just resilience — resuming a partially-written frame sequence on a
/// pipe that already desynced would corrupt every subsequent frame, so
/// the only safe retry is a full reconnect. `upload_pack` is
/// content-addressed and safe to resend in full on the new connection
/// (SPEC-TRANSPORT §7); a retried `update_ref` CAS write is not
/// idempotent and callers MUST disambiguate a `RefConflict` with
/// `read_ref` as usual.
#[derive(Debug)]
pub struct SshTransport {
    /// The child's stdio handles sit behind a `Mutex` so `&self`
    /// [`Transport`] methods can still mutate them. SSH is a single
    /// pipelined stream — concurrent verbs on one [`SshTransport`]
    /// serialise through this mutex.
    io: Mutex<ChildIo>,
    /// Remote target, retained so a dropped connection can be
    /// transparently re-dialed on retry.
    target: SshTarget,
    /// `.kit/config` SSH options, retained for the same reason.
    options: SshOptions,
    /// Retry-delay ladder factory. Production uses the spec ladder;
    /// tests inject a shorter ladder so retry assertions stay fast.
    backoff: fn() -> BackoffIterator,
    /// Sleep hook between retry attempts. Production sleeps for the
    /// full delay; tests inject a no-op.
    sleep: fn(Duration),
}

#[derive(Debug)]
struct ChildIo {
    child: Child,
    stdin_tx: Option<mpsc::SyncSender<WriteJob>>,
    stdout_rx: mpsc::Receiver<Result<SshFrame, FrameError>>,
    /// `true` once we've shut down the child pipe. Guards double-close
    /// from `Drop` + explicit `close`.
    closed: bool,
}

#[derive(Debug)]
struct WriteJob {
    frame: SshFrame,
    result_tx: mpsc::Sender<Result<(), FrameError>>,
}

impl SshTransport {
    /// Parse `url`, spawn `ssh`, and perform the `Hello` handshake.
    pub fn connect(url: &str) -> Result<Self, SshInitError> {
        let target = parse_kit_ssh_url(url)?;
        Self::connect_with_options(&target, &SshOptions::default())
    }

    /// Spawn `ssh` from a pre-parsed [`SshTarget`] with explicit
    /// `.kit/config` SSH options. Callers that already resolved
    /// config should use this entry point; `connect` is the
    /// convenience form.
    pub fn connect_with_options(
        target: &SshTarget,
        options: &SshOptions,
    ) -> Result<Self, SshInitError> {
        let io = spawn_and_handshake(target, options)?;
        Ok(Self {
            io: Mutex::new(io),
            target: target.clone(),
            options: options.clone(),
            backoff: BackoffIterator::new,
            sleep: thread::sleep,
        })
    }

    /// Test-only constructor with explicit retry hooks — lets unit/e2e
    /// tests use a short deterministic backoff ladder and a no-op sleep
    /// instead of the multi-second production ladder.
    #[doc(hidden)]
    pub fn connect_with_options_and_retry(
        target: &SshTarget,
        options: &SshOptions,
        backoff: fn() -> BackoffIterator,
        sleep: fn(Duration),
    ) -> Result<Self, SshInitError> {
        let io = spawn_and_handshake(target, options)?;
        Ok(Self {
            io: Mutex::new(io),
            target: target.clone(),
            options: options.clone(),
            backoff,
            sleep,
        })
    }

    /// Explicit shutdown — closes stdin and waits for the child.
    /// Equivalent to dropping the transport, but lets the caller
    /// observe any shutdown error. Safe to call multiple times.
    pub fn close(&mut self) -> io::Result<()> {
        match self.io.get_mut() {
            Ok(io) => shut_child(io),
            Err(_) => Err(io::Error::other("ssh transport mutex poisoned")),
        }
    }

    /// Ensure the child connection is live, respawning it from
    /// `self.target` / `self.options` if a prior failure marked it
    /// `closed`. Called at the top of every retry attempt so a
    /// `ConnectionFailed` from the previous attempt heals before the
    /// verb is re-issued.
    fn ensure_connected(&self) -> TransportResult<()> {
        let needs_reconnect = {
            let io = self
                .io
                .lock()
                .map_err(|_| TransportError::ConnectionFailed)?;
            io.closed
        };
        if !needs_reconnect {
            return Ok(());
        }
        let fresh = spawn_and_handshake(&self.target, &self.options)
            .map_err(|_| TransportError::ConnectionFailed)?;
        let mut io = self
            .io
            .lock()
            .map_err(|_| TransportError::ConnectionFailed)?;
        // Defensive: tear down whatever's left of the old child (already
        // marked closed, but a fresh `shut_child` call is a no-op if so).
        let _ = shut_child(&mut io);
        *io = fresh;
        Ok(())
    }

    /// Drive `attempt` through the SPEC-TRANSPORT §7 retry ladder,
    /// reconnecting before every attempt after the first if the prior
    /// one left the connection `closed`.
    fn with_retry<T>(
        &self,
        mut attempt: impl FnMut(&mut ChildIo) -> TransportResult<T>,
    ) -> TransportResult<T> {
        kit_core::protocol::retrying(
            || {
                self.ensure_connected()?;
                let mut io = self
                    .io
                    .lock()
                    .map_err(|_| TransportError::ConnectionFailed)?;
                attempt(&mut io)
            },
            self.backoff,
            self.sleep,
        )
    }
}

/// Spawn the `ssh` child, wire up its stdio pumps, and drive the
/// mandatory `Hello` handshake. Shared by [`SshTransport::connect_with_options`]
/// and [`SshTransport::ensure_connected`]'s reconnect path so the two
/// never drift.
fn spawn_and_handshake(target: &SshTarget, options: &SshOptions) -> Result<ChildIo, SshInitError> {
    validate_ssh_path(&target.path)?;
    let mut cmd = build_ssh_command(target, options);
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;
    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| SshInitError::HandshakeFailed("no child stdin".into()))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| SshInitError::HandshakeFailed("no child stdout".into()))?;
    let stdin_tx = spawn_stdin_writer(stdin);
    let stdout_rx = spawn_stdout_reader(stdout);
    let mut io = ChildIo {
        child,
        stdin_tx: Some(stdin_tx),
        stdout_rx,
        closed: false,
    };
    if let Err(e) = perform_client_handshake(&mut io) {
        // Tear down before returning so the caller never sees a
        // half-initialised connection.
        let _ = shut_child(&mut io);
        return Err(e);
    }
    Ok(io)
}

impl Drop for SshTransport {
    fn drop(&mut self) {
        match self.io.get_mut() {
            Ok(io) => {
                let _ = shut_child(io);
            }
            Err(poison) => {
                let io = poison.into_inner();
                let _ = shut_child(io);
            }
        }
    }
}

impl Transport for SshTransport {
    /// Ask the server for its repository cursor (SPEC-TRANSPORT §4.2.2). A
    /// server that predates the request answers `INVALID_REQUEST` and the
    /// transport offers none.
    fn repo_cursor(&self) -> TransportResult<Option<RepoCursor>> {
        self.with_retry(|io| {
            let req = SshFrame {
                body: Some(ssh_frame::Body::ReadRepoCursor(
                    Box::<ReadRepoCursor>::default(),
                )),
                ..Default::default()
            };
            write_child_frame_or_err(io, req)?;
            cursor_from_reply(read_child_frame_or_err(io)?.body)
        })
    }

    /// Streams the body: the header announces `pack.len()`, then each
    /// `PackChunk` carries up to `CHUNK_DATA_MAX` bytes read from `pack`.
    /// Every attempt, after a reconnect too, reads `pack` again from offset
    /// 0, so the server receives the same bytes and checks them against the
    /// key. A body over [`PACK_BODY_LIMIT`] is refused before any read and
    /// any frame.
    fn upload_pack(
        &self,
        pack: &dyn PackBody,
        key: &PackKey,
        _head_ref: Option<&str>,
    ) -> TransportResult<()> {
        let total = pack.len();
        if total > PACK_BODY_LIMIT {
            return Err(TransportError::PayloadTooLarge(saturating_usize(total)));
        }
        self.with_retry(|io| {
            // Opened before the header, so a body that cannot be opened
            // leaves the connection idle and usable.
            let mut body = pack
                .read_from(0)
                .map_err(|_| TransportError::ProtocolError)?;
            let header = SshFrame {
                body: Some(ssh_frame::Body::UploadPack(Box::new(
                    UploadPack::default()
                        .with_pack_id(key.as_bytes().to_vec())
                        .with_total_bytes(total),
                ))),
                ..Default::default()
            };
            write_child_frame_or_err(io, header)?;
            send_pack_chunks(&mut body, total, key, |chunk| {
                write_child_frame_or_err(io, chunk)
            })
            .map_err(|e| match e {
                // The server waits for chunks this upload will not
                // send: the connection cannot carry another verb.
                SendError::Local => {
                    abandon_child(io);
                    TransportError::ProtocolError
                }
                SendError::Wire(e) => e,
            })?;

            let resp = read_child_frame_or_err(io)?;
            match resp.body {
                Some(ssh_frame::Body::UploadPackResponse(_)) => Ok(()),
                Some(ssh_frame::Body::Error(e)) => Err(rpc_error_to_transport(*e, "ssh")),
                other => Err(unexpected_frame("ssh", "UploadPackResponse", other)),
            }
        })
    }

    /// Declares the header's length to `sink` before any chunk is read, then
    /// writes each chunk as it arrives. A retry, after a reconnect, begins
    /// the sink again; a sink that failed refuses that, so the transfer ends.
    fn download_pack(
        &self,
        key: &PackKey,
        _ref_hint: Option<&str>,
        sink: &mut dyn PackSink,
    ) -> TransportResult<()> {
        self.with_retry(|io| {
            let req = SshFrame {
                body: Some(ssh_frame::Body::DownloadPack(Box::new(
                    DownloadPack::default().with_pack_id(key.as_bytes().to_vec()),
                ))),
                ..Default::default()
            };
            write_child_frame_or_err(io, req)?;
            read_download_pack(|| read_child_frame_or_err(io), sink).map_err(|e| match e {
                ReplyError::Answered(e) => e,
                ReplyError::Cut(e) => {
                    abandon_child(io);
                    e
                }
            })
        })
    }

    fn pack_exists(&self, key: &PackKey, _ref_hint: Option<&str>) -> TransportResult<bool> {
        self.with_retry(|io| {
            let req = SshFrame {
                body: Some(ssh_frame::Body::PackExists(Box::new(
                    PackExists::default().with_pack_id(key.as_bytes().to_vec()),
                ))),
                ..Default::default()
            };
            write_child_frame_or_err(io, req)?;
            let resp = read_child_frame_or_err(io)?;
            match resp.body {
                Some(ssh_frame::Body::PackExistsResponse(r)) => Ok(r.exists.unwrap_or(false)),
                Some(ssh_frame::Body::Error(e)) => Err(rpc_error_to_transport(*e, "ssh")),
                other => Err(unexpected_frame("ssh", "PackExistsResponse", other)),
            }
        })
    }

    fn update_ref(
        &self,
        name: &str,
        condition: RefWriteCondition,
        hash: &Hash,
    ) -> TransportResult<()> {
        if !validate_ref_name(name) {
            return Err(TransportError::InvalidRef(name.into()));
        }
        if name.len() > MAX_REF_NAME {
            return Err(TransportError::InvalidRef("ref name too long".into()));
        }

        self.with_retry(|io| {
            // CAS intent = `expectation`. `expected_id` is meaningful only
            // for MATCH. See SPEC-TRANSPORT §4.2.1.
            let (expected_id, expectation) = cond_to_wire(condition);

            let req = SshFrame {
                body: Some(ssh_frame::Body::UpdateRef(Box::new(
                    UpdateRef::default()
                        .with_name(name)
                        .with_expected_id(expected_id)
                        .with_new_id(hash.to_vec())
                        .with_expectation(expectation),
                ))),
                ..Default::default()
            };
            write_child_frame_or_err(io, req)?;

            let resp = read_child_frame_or_err(io)?;
            match resp.body {
                Some(ssh_frame::Body::UpdateRefResponse(_)) => Ok(()),
                Some(ssh_frame::Body::Error(e)) => Err(map_update_ref_error(*e, condition, "ssh")),
                other => Err(unexpected_frame("ssh", "UpdateRefResponse", other)),
            }
        })
    }

    fn read_ref(&self, name: &str) -> TransportResult<Option<Hash>> {
        if !validate_ref_name(name) {
            return Err(TransportError::InvalidRef(name.into()));
        }
        if name.len() > MAX_REF_NAME {
            return Err(TransportError::InvalidRef("ref name too long".into()));
        }
        self.with_retry(|io| {
            let req = SshFrame {
                body: Some(ssh_frame::Body::ReadRef(Box::new(
                    ReadRef::default().with_name(name),
                ))),
                ..Default::default()
            };
            write_child_frame_or_err(io, req)?;
            let resp = read_child_frame_or_err(io)?;
            match resp.body {
                Some(ssh_frame::Body::ReadRefResponse(r)) => {
                    let oid = r.object_id.unwrap_or_default();
                    if oid.is_empty() {
                        Ok(None)
                    } else if oid.len() == 32 {
                        let mut h = [0u8; 32];
                        h.copy_from_slice(&oid);
                        Ok(Some(h))
                    } else {
                        Err(TransportError::InvalidResponse)
                    }
                }
                Some(ssh_frame::Body::Error(e)) => Err(rpc_error_to_transport(*e, "ssh")),
                other => Err(unexpected_frame("ssh", "ReadRefResponse", other)),
            }
        })
    }

    fn list_refs(&self, prefix: &str) -> TransportResult<Vec<Ref>> {
        if !prefix.is_empty() && !validate_ref_prefix(prefix) {
            return Err(TransportError::InvalidRef(prefix.into()));
        }
        if prefix.len() > MAX_REF_NAME {
            return Err(TransportError::InvalidRef("ref prefix too long".into()));
        }
        self.with_retry(|io| {
            let req = SshFrame {
                body: Some(ssh_frame::Body::ListRefs(Box::new(
                    ListRefs::default().with_prefix(prefix),
                ))),
                ..Default::default()
            };
            write_child_frame_or_err(io, req)?;
            let resp = read_child_frame_or_err(io)?;
            match resp.body {
                Some(ssh_frame::Body::ListRefsResponse(r)) => list_response_refs(prefix, r.refs),
                Some(ssh_frame::Body::Error(e)) => Err(rpc_error_to_transport(*e, "ssh")),
                other => Err(unexpected_frame("ssh", "ListRefsResponse", other)),
            }
        })
    }
}

// ---------------------------------------------------------------------------
// Helpers (transport-ssh-specific I/O wrappers; shared frame helpers
// live in `kit_rpc::helpers`)
// ---------------------------------------------------------------------------

/// The cursor in the reply to `ReadRepoCursor` (SPEC-TRANSPORT §4.2.2).
///
/// `INVALID_REQUEST` is how a server that predates the request answers any
/// frame it does not know (SPEC-RPC §2), so it means no cursor. Any other
/// error, any other frame, a field the reply should not hold and a cursor
/// that is empty or over [`kit_core::protocol::REPO_CURSOR_MAX_LEN`] bytes
/// are errors, never "no cursor".
///
/// # Errors
/// [`TransportError::InvalidResponse`] for a reply that holds an unknown
/// field or a cursor of the wrong length, the transport error of any other
/// server error, and [`TransportError::RemoteError`] for any other frame.
pub fn cursor_from_reply(body: Option<ssh_frame::Body>) -> TransportResult<Option<RepoCursor>> {
    match body {
        Some(ssh_frame::Body::ReadRepoCursorResponse(r)) => {
            if !r.__buffa_unknown_fields.is_empty() {
                return Err(TransportError::InvalidResponse);
            }
            r.cursor.as_deref().map(RepoCursor::new).transpose()
        }
        Some(ssh_frame::Body::Error(e))
            if e.code.is_some_and(|c| c == ErrorCode::InvalidRequest) =>
        {
            Ok(None)
        }
        Some(ssh_frame::Body::Error(e)) => Err(rpc_error_to_transport(*e, "ssh")),
        other => Err(unexpected_frame("ssh", "ReadRepoCursorResponse", other)),
    }
}

/// How a `DownloadPack` reply ended before its last chunk reached the sink.
#[derive(Debug)]
enum ReplyError {
    /// The server answered the request with an error frame: the reply is
    /// complete and the connection carries the next verb.
    Answered(TransportError),
    /// The reply stopped part way. Frames may still be in flight, so the
    /// connection is closed and the next verb reconnects.
    Cut(TransportError),
}

/// Read a `DownloadPack` reply from `next_frame` into `sink`.
///
/// The header's `total_bytes` goes to [`PackSink::begin`] before any chunk
/// is read, so a sink refuses a body over its limit before the first byte,
/// and a sink refuses bytes past the header's length. A header without one
/// declares none, and the sink's own limit bounds the body. Each chunk is written
/// as it arrives: one chunk is held at a time.
fn read_download_pack<F>(mut next_frame: F, sink: &mut dyn PackSink) -> Result<(), ReplyError>
where
    F: FnMut() -> TransportResult<SshFrame>,
{
    let header = next_frame().map_err(ReplyError::Cut)?;
    let declared = match header.body {
        Some(ssh_frame::Body::DownloadPackHeader(h)) => h.total_bytes,
        Some(ssh_frame::Body::Error(e)) => {
            return Err(ReplyError::Answered(rpc_error_to_transport(*e, "ssh")));
        }
        other => {
            return Err(ReplyError::Cut(unexpected_frame(
                "ssh",
                "DownloadPackHeader",
                other,
            )));
        }
    };
    if declared.is_some_and(|total| total > PACK_BODY_LIMIT) {
        return Err(ReplyError::Cut(TransportError::RemoteError(
            "server-advertised pack size exceeds client cap".into(),
        )));
    }
    sink.begin(declared).map_err(ReplyError::Cut)?;
    loop {
        let frame = next_frame().map_err(ReplyError::Cut)?;
        match frame.body {
            Some(ssh_frame::Body::PackChunk(c)) => {
                sink.write(&c.data.unwrap_or_default())
                    .map_err(ReplyError::Cut)?;
                if c.last.unwrap_or(false) {
                    return Ok(());
                }
            }
            Some(ssh_frame::Body::Error(e)) => {
                return Err(ReplyError::Cut(rpc_error_to_transport(*e, "ssh")));
            }
            other => {
                return Err(ReplyError::Cut(unexpected_frame("ssh", "PackChunk", other)));
            }
        }
    }
}

/// Close a connection whose reply was not read to its end.
fn abandon_child(io: &mut ChildIo) {
    io.closed = true;
    let _ = io.stdin_tx.take();
    terminate_child_now(&mut io.child);
}

/// How sending a pack's chunks stopped short.
#[derive(Debug)]
enum SendError {
    /// The pack could not be read, or held fewer bytes than its length: a
    /// local failure, never retried.
    Local,
    /// A frame could not be sent.
    Wire(TransportError),
}

/// Send the `total` bytes of `body`, a pack read from offset 0, as
/// `PackChunk` frames of at most [`CHUNK_DATA_MAX`] bytes through `send`,
/// the last one marked. An empty pack is one empty last chunk. One chunk is
/// held at a time.
fn send_pack_chunks(
    reader: &mut dyn io::Read,
    total: u64,
    key: &PackKey,
    mut send: impl FnMut(SshFrame) -> TransportResult<()>,
) -> Result<(), SendError> {
    let mut offset = 0u64;
    loop {
        let len = saturating_usize(total - offset).min(CHUNK_DATA_MAX);
        let mut data = vec![0u8; len];
        reader.read_exact(&mut data).map_err(|_| SendError::Local)?;
        let last = offset + len as u64 == total;
        let chunk = SshFrame {
            body: Some(ssh_frame::Body::PackChunk(Box::new(
                PackChunk::default()
                    .with_pack_id(key.as_bytes().to_vec())
                    .with_offset(offset)
                    .with_data(data)
                    .with_last(last),
            ))),
            ..Default::default()
        };
        send(chunk).map_err(SendError::Wire)?;
        if last {
            return Ok(());
        }
        offset += len as u64;
    }
}

#[cfg(test)]
fn read_frame_or_err<R: io::Read>(r: &mut R) -> TransportResult<SshFrame> {
    match read_frame::<_, SshFrame>(r) {
        Ok(f) => Ok(f),
        Err(e) => Err(frame_error_to_transport(&e)),
    }
}

fn spawn_stdin_writer(mut stdin: ChildStdin) -> mpsc::SyncSender<WriteJob> {
    let (tx, rx) = mpsc::sync_channel::<WriteJob>(1);
    thread::spawn(move || {
        for job in rx {
            let result = write_frame(&mut stdin, &job.frame);
            let should_stop = result.is_err();
            let _ = job.result_tx.send(result);
            if should_stop {
                break;
            }
        }
    });
    tx
}

fn write_child_frame_or_err(io: &mut ChildIo, frame: SshFrame) -> TransportResult<()> {
    let stdin_tx = io
        .stdin_tx
        .as_ref()
        .ok_or(TransportError::ConnectionFailed)?;
    let (result_tx, result_rx) = mpsc::channel();
    stdin_tx
        .send(WriteJob { frame, result_tx })
        .map_err(|_| TransportError::ConnectionFailed)?;

    if let Ok(Ok(())) = result_rx.recv_timeout(DEFAULT_SSH_TIMEOUT) {
        Ok(())
    } else {
        io.closed = true;
        let _ = io.stdin_tx.take();
        terminate_child_now(&mut io.child);
        Err(TransportError::ConnectionFailed)
    }
}

fn spawn_stdout_reader(
    mut stdout: std::process::ChildStdout,
) -> mpsc::Receiver<Result<SshFrame, FrameError>> {
    let (tx, rx) = mpsc::sync_channel(1);
    thread::spawn(move || {
        loop {
            let frame = read_frame::<_, SshFrame>(&mut stdout);
            let should_stop = frame.is_err();
            if tx.send(frame).is_err() || should_stop {
                break;
            }
        }
    });
    rx
}

#[derive(Debug)]
enum TimedFrameError {
    Timeout,
    Disconnected,
    Frame(FrameError),
}

fn recv_frame_with_timeout(
    rx: &mpsc::Receiver<Result<SshFrame, FrameError>>,
    timeout: Duration,
) -> Result<SshFrame, TimedFrameError> {
    match rx.recv_timeout(timeout) {
        Ok(Ok(frame)) => Ok(frame),
        Ok(Err(e)) => Err(TimedFrameError::Frame(e)),
        Err(mpsc::RecvTimeoutError::Timeout) => Err(TimedFrameError::Timeout),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(TimedFrameError::Disconnected),
    }
}

fn read_child_frame_or_err(io: &mut ChildIo) -> TransportResult<SshFrame> {
    match recv_frame_with_timeout(&io.stdout_rx, DEFAULT_SSH_TIMEOUT) {
        Ok(frame) => Ok(frame),
        Err(TimedFrameError::Timeout) => {
            io.closed = true;
            let _ = io.stdin_tx.take();
            terminate_child_now(&mut io.child);
            Err(TransportError::ConnectionFailed)
        }
        Err(TimedFrameError::Disconnected) => Err(TransportError::ConnectionFailed),
        Err(TimedFrameError::Frame(e)) => Err(frame_error_to_transport(&e)),
    }
}

fn frame_error_to_transport(e: &FrameError) -> TransportError {
    match *e {
        FrameError::LengthTruncated | FrameError::BodyTruncated { .. } => {
            TransportError::ConnectionFailed
        }
        FrameError::LengthTooLarge(n) => TransportError::PayloadTooLarge(n as usize),
        FrameError::DecodeFailed => TransportError::ProtocolError,
        FrameError::Io(_) => TransportError::ConnectionFailed,
    }
}

// ---------------------------------------------------------------------------
// Hello handshake + child teardown
// ---------------------------------------------------------------------------

fn perform_client_handshake(io: &mut ChildIo) -> Result<(), SshInitError> {
    let hello = SshFrame {
        body: Some(ssh_frame::Body::Hello(Box::new(
            Hello::default()
                .with_proto(ProtocolVersion::ProtocolVersion1)
                .with_client_id(CLIENT_ID),
        ))),
        ..Default::default()
    };
    write_child_frame_or_err(io, hello)
        .map_err(|e| SshInitError::HandshakeFailed(format!("send hello: {e:?}")))?;

    let resp = match recv_frame_with_timeout(&io.stdout_rx, DEFAULT_SSH_TIMEOUT) {
        Ok(frame) => frame,
        Err(TimedFrameError::Timeout) => {
            io.closed = true;
            let _ = io.stdin_tx.take();
            terminate_child_now(&mut io.child);
            return Err(SshInitError::HandshakeFailed(
                "read hello reply timed out".into(),
            ));
        }
        Err(TimedFrameError::Disconnected) => {
            return Err(SshInitError::HandshakeFailed(
                "read hello reply: child stdout closed".into(),
            ));
        }
        Err(TimedFrameError::Frame(e)) => {
            return Err(SshInitError::HandshakeFailed(format!(
                "read hello reply: {e}"
            )));
        }
    };
    match resp.body {
        Some(ssh_frame::Body::HelloResponse(h)) => {
            let proto = h.proto.unwrap_or_default();
            if proto != ProtocolVersion::ProtocolVersion1 {
                return Err(SshInitError::HandshakeFailed(format!(
                    "server proto_version {} != expected 1",
                    proto.to_i32()
                )));
            }
            Ok(())
        }
        Some(ssh_frame::Body::Error(e)) => Err(SshInitError::HandshakeFailed(format!(
            "server error: {}",
            kit_core::protocol::sanitize_remote_error_text(&e.message.unwrap_or_default())
        ))),
        other => Err(SshInitError::HandshakeFailed(format!(
            "unexpected hello reply: {}",
            body_name(&other)
        ))),
    }
}

#[allow(clippy::unnecessary_wraps)]
fn shut_child(io: &mut ChildIo) -> io::Result<()> {
    if io.closed {
        return Ok(());
    }
    io.closed = true;
    // Dropping stdin closes the pipe; `kit serve` treats EOF as a clean
    // shutdown, and this avoids blocking forever on a best-effort Close write.
    let _ = io.stdin_tx.take();
    wait_child_timeout(&mut io.child, DEFAULT_SSH_TIMEOUT)?;
    Ok(())
}

fn wait_child_timeout(child: &mut Child, timeout: Duration) -> io::Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        if child.try_wait()?.is_some() {
            return Ok(());
        }
        let now = Instant::now();
        if now >= deadline {
            terminate_child_now(child);
            return Ok(());
        }
        thread::sleep(core::cmp::min(
            Duration::from_millis(10),
            deadline.saturating_duration_since(now),
        ));
    }
}

fn terminate_child_now(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

// ---------------------------------------------------------------------------
// argv construction
// ---------------------------------------------------------------------------

/// Environment override for the SSH client program. Defaults to `ssh`.
/// Set `KIT_SSH_PROGRAM` to point at a wrapper script — used by the
/// hermetic SSH e2e tests to record argv and exec the local `kit serve`
/// without a real network hop. In production this is unset and the
/// system `ssh(1)` is spawned.
const SSH_PROGRAM_ENV: &str = "KIT_SSH_PROGRAM";

fn build_ssh_command(target: &SshTarget, options: &SshOptions) -> Command {
    let program = std::env::var(SSH_PROGRAM_ENV).unwrap_or_else(|_| "ssh".to_string());
    let mut cmd = Command::new(program);
    if let Some(port) = target.port {
        cmd.arg("-p").arg(port.to_string());
    }
    if !options.strict_host_key_checking.is_empty() {
        cmd.arg("-o").arg(format!(
            "StrictHostKeyChecking={}",
            options.strict_host_key_checking
        ));
    }
    if !options.user_known_hosts_file.is_empty() {
        cmd.arg("-o").arg(format!(
            "UserKnownHostsFile={}",
            options.user_known_hosts_file
        ));
    }
    if !options.identity_file.is_empty() {
        cmd.arg("-i").arg(&options.identity_file);
    }
    // BatchMode + accept-new match the defaults GitHub's CLI assumes
    // for git+ssh. kit defers to whatever the user configured, but if
    // they haven't set either knob we should not block on an
    // interactive password prompt.
    if options.strict_host_key_checking.is_empty() {
        cmd.arg("-o").arg("StrictHostKeyChecking=accept-new");
    }
    cmd.arg("-o").arg("BatchMode=yes");
    cmd.arg("-o")
        .arg(format!("ConnectTimeout={}", DEFAULT_SSH_TIMEOUT.as_secs()));

    // `--` ends the option list, so no URL field can act as an ssh option.
    cmd.arg("--");
    cmd.arg(format!("{}@{}", target.user, target.host));
    // The path is already restricted to `[A-Za-z0-9._-/]` by
    // `validate_ssh_path`, so handing it to the remote shell as a
    // separate argv token is safe. Three tokens (kit / serve / path)
    // so sshd invokes `kit serve <path>` without an intervening
    // `sh -c` that broke the handshake on some sshd configurations.
    cmd.arg("kit").arg("serve").arg(&target.path);
    cmd
}

#[cfg(test)]
mod tests {
    // These smoke tests cover the helper functions. The public surface
    // is exercised against `kit serve` in the kit-bin tests.
    use super::*;
    use kit_core::protocol::MemorySink;
    use kit_rpc::kit::common::v1::{RefEntry, RefExpectation};
    use kit_rpc::kit::rpc::v1::ssh::DownloadPackHeader;
    use kit_rpc::kit::rpc::v1::{Error as RpcError, ErrorCode};

    /// `--` sits right before the destination, so a hostile user or
    /// host field stays an operand even when it looks like an option.
    #[test]
    fn ssh_command_puts_double_dash_before_destination() {
        for (user, host) in [("-oProxyCommand=x", "h"), ("u", "-J"), ("alice", "host")] {
            let target = SshTarget {
                user: user.into(),
                host: host.into(),
                port: Some(2222),
                path: "/repo".into(),
            };
            let cmd = build_ssh_command(&target, &SshOptions::default());
            let args: Vec<String> = cmd
                .get_args()
                .map(|a| a.to_string_lossy().into_owned())
                .collect();
            let dest = format!("{user}@{host}");
            let at = args.iter().position(|a| *a == dest).unwrap();
            assert_eq!(args[at - 1], "--");
            assert_eq!(args.iter().filter(|a| *a == "--").count(), 1);
            assert_eq!(args[at + 1..], ["kit", "serve", "/repo"]);
        }
    }

    /// A CAS mismatch — `InvalidRequest` with the current id in
    /// `details` under a precondition write — maps to `RefConflict`.
    /// (The mapping now lives in `kit_rpc::map_update_ref_error`,
    /// shared with the enc transport; these tests pin the SSH client's
    /// contract against it.)
    #[test]
    fn update_ref_error_maps_cas_mismatch_to_conflict() {
        let e = RpcError::default()
            .with_code(ErrorCode::InvalidRequest)
            .with_message("ref changed")
            .with_details(vec![0xABu8; 32]);
        assert!(matches!(
            map_update_ref_error(e, RefWriteCondition::Missing, "ssh"),
            TransportError::RefConflict
        ));
    }

    /// A genuine invalid-request (no `details` payload) under a
    /// precondition write must NOT be masked as `RefConflict` — it
    /// surfaces its real message via `rpc_error_to_transport`.
    #[test]
    fn update_ref_error_does_not_mask_plain_invalid_request() {
        let e = RpcError::default()
            .with_code(ErrorCode::InvalidRequest)
            .with_message("malformed ref name");
        match map_update_ref_error(e, RefWriteCondition::Match([0u8; 32]), "ssh") {
            TransportError::RemoteError(msg) => assert_eq!(msg, "malformed ref name"),
            other => panic!("expected RemoteError, got {other:?}"),
        }
    }

    /// Under `Any` (no CAS precondition) even a detail-bearing
    /// `InvalidRequest` is not a conflict.
    #[test]
    fn update_ref_error_any_condition_never_conflict() {
        let e = RpcError::default()
            .with_code(ErrorCode::InvalidRequest)
            .with_message("bad")
            .with_details(vec![0xABu8; 32]);
        assert!(!matches!(
            map_update_ref_error(e, RefWriteCondition::Any, "ssh"),
            TransportError::RefConflict
        ));
    }

    #[test]
    fn ref_entry_to_ref_validates_oid_length() {
        let bad = RefEntry::default()
            .with_name("refs/heads/main")
            .with_object_id(vec![0u8; 16]);
        assert!(matches!(
            kit_rpc::ref_entry_to_ref(bad),
            Err(TransportError::InvalidResponse)
        ));
    }

    #[test]
    fn ref_entry_to_ref_validates_name() {
        // Empty ref names are rejected by `validate_ref_name`.
        let bad = RefEntry::default()
            .with_name(String::new())
            .with_object_id(vec![0u8; 32]);
        assert!(matches!(
            kit_rpc::ref_entry_to_ref(bad),
            Err(TransportError::InvalidRef(_))
        ));
    }

    fn header_frame(total: u64) -> SshFrame {
        SshFrame {
            body: Some(ssh_frame::Body::DownloadPackHeader(Box::new(
                DownloadPackHeader::default().with_total_bytes(total),
            ))),
            ..Default::default()
        }
    }

    fn chunk_frame(offset: u64, data: &[u8], last: bool) -> SshFrame {
        SshFrame {
            body: Some(ssh_frame::Body::PackChunk(Box::new(
                PackChunk::default()
                    .with_pack_id(vec![0u8; 32])
                    .with_offset(offset)
                    .with_data(data.to_vec())
                    .with_last(last),
            ))),
            ..Default::default()
        }
    }

    /// Feed `frames` to [`read_download_pack`], counting the frames it reads.
    fn read_reply(frames: &[SshFrame], sink: &mut dyn PackSink) -> (Result<(), ReplyError>, usize) {
        let mut buf = Vec::new();
        for frame in frames {
            write_frame(&mut buf, frame).unwrap();
        }
        let mut cursor = std::io::Cursor::new(buf);
        let mut reads = 0;
        let result = read_download_pack(
            || {
                reads += 1;
                read_frame_or_err(&mut cursor)
            },
            sink,
        );
        (result, reads)
    }

    /// A header of `u64::MAX` is refused before any chunk is read.
    #[test]
    fn download_pack_refuses_an_oversize_header_before_any_chunk() {
        let mut sink = MemorySink::new(u64::MAX);
        let (result, reads) = read_reply(&[header_frame(u64::MAX)], &mut sink);
        match result {
            Err(ReplyError::Cut(TransportError::RemoteError(msg))) => {
                assert!(msg.contains("exceeds client cap"), "{msg}");
            }
            other => panic!("expected a cut reply, got {other:?}"),
        }
        assert_eq!(reads, 1);
    }

    /// The sink sees the header's length before any chunk: a 64 MiB node
    /// is refused at the node bound with only the header read.
    #[test]
    fn download_pack_declares_the_header_length_before_any_chunk() {
        let mut sink = MemorySink::new(kit_core::transfer::MAX_PACKLIST_NODE_BYTES);
        let frames = vec![header_frame(64 << 20), chunk_frame(0, &[0; 16], false)];
        let (result, reads) = read_reply(&frames, &mut sink);
        assert!(
            matches!(
                result,
                Err(ReplyError::Cut(TransportError::PayloadTooLarge(_)))
            ),
            "{result:?}"
        );
        assert_eq!(reads, 1, "no chunk is read once the sink refuses");
    }

    /// A pack over several chunks reaches the sink byte for byte.
    #[test]
    fn download_pack_writes_every_chunk_to_the_sink() {
        const CHUNK: usize = 37;
        let payload: Vec<u8> = (0..(CHUNK * 5 + 11) as u32)
            .map(|i| (i % 251) as u8)
            .collect();
        let mut frames = vec![header_frame(payload.len() as u64)];
        for (i, part) in payload.chunks(CHUNK).enumerate() {
            let last = (i + 1) * CHUNK >= payload.len();
            frames.push(chunk_frame((i * CHUNK) as u64, part, last));
        }
        let mut sink = MemorySink::new(u64::MAX);
        let (result, reads) = read_reply(&frames, &mut sink);
        result.unwrap();
        assert_eq!(reads, 7);
        assert_eq!(sink.into_bytes().unwrap(), payload);
    }

    /// A header without a length declares none: the sink's limit bounds the
    /// body.
    #[test]
    fn download_pack_header_without_a_length_declares_none() {
        let header = SshFrame {
            body: Some(ssh_frame::Body::DownloadPackHeader(Box::default())),
            ..Default::default()
        };
        let frames = [header.clone(), chunk_frame(0, &[1, 2, 3], true)];
        let mut sink = MemorySink::new(3);
        let (result, _) = read_reply(&frames, &mut sink);
        result.unwrap();
        assert_eq!(sink.into_bytes().unwrap(), [1, 2, 3]);

        let frames = [header, chunk_frame(0, &[1, 2, 3, 4], true)];
        let mut sink = MemorySink::new(3);
        let (result, _) = read_reply(&frames, &mut sink);
        assert!(
            matches!(
                result,
                Err(ReplyError::Cut(TransportError::PayloadTooLarge(_)))
            ),
            "{result:?}"
        );
    }

    /// A server that sends more than its header promised is cut off at the
    /// first byte past it.
    #[test]
    fn download_pack_refuses_bytes_past_the_header_length() {
        let frames = vec![header_frame(2), chunk_frame(0, &[1, 2, 3, 4], true)];
        let mut sink = MemorySink::new(u64::MAX);
        let (result, _) = read_reply(&frames, &mut sink);
        assert!(
            matches!(
                result,
                Err(ReplyError::Cut(TransportError::PayloadTooLarge(_)))
            ),
            "{result:?}"
        );
    }

    /// An error frame in place of the header answers the request; the
    /// connection stays usable.
    #[test]
    fn download_pack_error_reply_is_answered() {
        let error = SshFrame {
            body: Some(ssh_frame::Body::Error(Box::new(
                RpcError::default().with_code(ErrorCode::KeyNotFound),
            ))),
            ..Default::default()
        };
        let mut sink = MemorySink::new(u64::MAX);
        let (result, _) = read_reply(&[error], &mut sink);
        assert!(matches!(result, Err(ReplyError::Answered(_))), "{result:?}");
    }

    /// A sink that failed on a local write ends the reply with an error no
    /// retry takes.
    #[test]
    fn download_pack_sink_failure_is_not_retried() {
        let mut sink = FullDisk(None);
        let frames = vec![header_frame(4), chunk_frame(0, &[1, 2, 3, 4], true)];
        let (result, _) = read_reply(&frames, &mut sink);
        let Err(ReplyError::Cut(error)) = result else {
            panic!("expected a cut reply, got {result:?}");
        };
        assert!(!kit_core::protocol::is_retryable(&error), "{error:?}");
        assert_eq!(sink.failed(), Some(io::ErrorKind::StorageFull));
    }

    /// The chunk frames `send_pack_chunks` sends for `pack`.
    fn sent_chunks(pack: &dyn PackBody) -> (Result<(), SendError>, Vec<PackChunk>) {
        let mut chunks = Vec::new();
        let mut body = pack.read_from(0).unwrap();
        let result = send_pack_chunks(&mut body, pack.len(), &PackKey::new([7; 32]), |frame| {
            match frame.body {
                Some(ssh_frame::Body::PackChunk(c)) => chunks.push(*c),
                other => panic!("expected a chunk, got {other:?}"),
            }
            Ok(())
        });
        (result, chunks)
    }

    /// A pack goes out in order, in chunks of at most `CHUNK_DATA_MAX`
    /// bytes, with only the last one marked.
    #[test]
    fn upload_sends_the_body_in_marked_chunks() {
        let bytes: Vec<u8> = (0..2 * CHUNK_DATA_MAX + 5)
            .map(|i| (i % 251) as u8)
            .collect();
        let (result, chunks) = sent_chunks(&kit_core::protocol::SliceBody(&bytes));
        result.unwrap();
        let offsets: Vec<u64> = chunks.iter().map(|c| c.offset.unwrap()).collect();
        assert_eq!(
            offsets,
            [0, CHUNK_DATA_MAX as u64, 2 * CHUNK_DATA_MAX as u64]
        );
        let lasts: Vec<bool> = chunks.iter().map(|c| c.last.unwrap()).collect();
        assert_eq!(lasts, [false, false, true]);
        let sent: Vec<u8> = chunks.into_iter().flat_map(|c| c.data.unwrap()).collect();
        assert_eq!(sent, bytes);
    }

    /// An empty pack is one empty last chunk.
    #[test]
    fn upload_of_an_empty_pack_sends_one_last_chunk() {
        let (result, chunks) = sent_chunks(&kit_core::protocol::SliceBody(&[]));
        result.unwrap();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].last, Some(true));
        assert!(chunks[0].data.as_deref().unwrap_or_default().is_empty());
    }

    /// A body shorter than its length stops the upload as a local error,
    /// never with a last chunk.
    #[test]
    fn upload_of_a_short_body_is_a_local_error() {
        struct Short<'a>(&'a [u8]);
        impl PackBody for Short<'_> {
            fn len(&self) -> u64 {
                self.0.len() as u64 + 1
            }
            fn read_from(&self, offset: u64) -> io::Result<Box<dyn io::Read + Send + '_>> {
                Ok(Box::new(&self.0[usize::try_from(offset).unwrap()..]))
            }
        }
        let bytes = vec![1u8; CHUNK_DATA_MAX + 10];
        let (result, chunks) = sent_chunks(&Short(&bytes));
        assert!(matches!(result, Err(SendError::Local)), "{result:?}");
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].last, Some(false));
    }

    /// A sink whose first write fails like a full disk.
    struct FullDisk(Option<io::ErrorKind>);

    impl PackSink for FullDisk {
        fn begin(&mut self, _: Option<u64>) -> TransportResult<()> {
            match self.0 {
                Some(_) => Err(TransportError::ProtocolError),
                None => Ok(()),
            }
        }
        fn write(&mut self, _: &[u8]) -> TransportResult<()> {
            self.0 = Some(io::ErrorKind::StorageFull);
            Err(TransportError::ProtocolError)
        }
        fn failed(&self) -> Option<io::ErrorKind> {
            self.0
        }
    }

    #[test]
    fn recv_frame_with_timeout_reports_stalled_reader() {
        let (_tx, rx) = mpsc::channel();
        let started = Instant::now();
        let result = recv_frame_with_timeout(&rx, Duration::from_millis(10));

        assert!(matches!(result, Err(TimedFrameError::Timeout)));
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    // Spawns a real external `sleep 5` child process —
    // quarantined to the serial `--ignored` CI lane
    // (cloudbuild/ci.yaml) instead of paying real subprocess
    // spawn/kill overhead on every `cargo test`.
    #[ignore = "spawns a real external subprocess; run via the serial --ignored CI lane"]
    fn wait_child_timeout_kills_stalled_child() {
        let mut child = Command::new("sleep")
            .arg("5")
            .spawn()
            .expect("spawn sleep child");
        let started = Instant::now();

        wait_child_timeout(&mut child, Duration::from_millis(20)).expect("bounded wait");

        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(child.try_wait().expect("poll child").is_some());
    }

    #[test]
    fn ssh_command_sets_connect_timeout() {
        let target = SshTarget {
            user: "git".into(),
            host: "example.com".into(),
            port: None,
            path: "repo".into(),
        };
        let cmd = build_ssh_command(&target, &SshOptions::default());
        let args: Vec<String> = cmd
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();

        assert!(args.contains(&format!("ConnectTimeout={}", DEFAULT_SSH_TIMEOUT.as_secs())));
    }

    /// Build an `UpdateRef` body via `cond_to_wire` so this test
    /// exercises the same encoding path as `Transport::update_ref`.
    fn encode_update_ref(condition: RefWriteCondition) -> UpdateRef {
        let new_hash = [0xABu8; 32];
        let (expected_id, expectation) = cond_to_wire(condition);
        UpdateRef {
            name: Some("refs/heads/main".into()),
            expected_id: Some(expected_id),
            new_id: Some(new_hash.to_vec()),
            expectation: Some(expectation.into()),
            ..Default::default()
        }
    }

    /// The three CAS variants MUST produce three distinct
    /// `cond_to_wire` encodings. Before the `expectation` field
    /// landed, `Any` and `Missing` collapsed to the same bytes — this
    /// pins that they no longer do.
    #[test]
    fn cond_to_wire_variants_produce_distinct_encodings() {
        use buffa::Message;

        let any = encode_update_ref(RefWriteCondition::Any).encode_to_vec();
        let missing = encode_update_ref(RefWriteCondition::Missing).encode_to_vec();
        let m = encode_update_ref(RefWriteCondition::Match([0xCDu8; 32])).encode_to_vec();

        assert_ne!(any, missing, "Any and Missing must differ on the wire");
        assert_ne!(any, m, "Any and Match must differ on the wire");
        assert_ne!(missing, m, "Missing and Match must differ on the wire");

        // Hex-print the three encodings so a failing CI run leaves
        // the wire bytes in the log for forensic review.
        eprintln!("UpdateRef[Any]     = {}", hex_encode(&any));
        eprintln!("UpdateRef[Missing] = {}", hex_encode(&missing));
        eprintln!("UpdateRef[Match]   = {}", hex_encode(&m));
    }

    /// After encoding and decoding round-trips, each variant
    /// surfaces its declared `expectation` value. Catches a future
    /// codegen change that drops the field by mistake.
    #[test]
    fn update_ref_expectation_round_trips() {
        use buffa::Message;

        for (cond, want) in [
            (RefWriteCondition::Any, RefExpectation::Any),
            (RefWriteCondition::Missing, RefExpectation::Missing),
            (
                RefWriteCondition::Match([0xCDu8; 32]),
                RefExpectation::Match,
            ),
        ] {
            let bytes = encode_update_ref(cond).encode_to_vec();
            let decoded = UpdateRef::decode(&mut &bytes[..]).expect("decode UpdateRef");
            assert_eq!(
                decoded.expectation,
                Some(want.into()),
                "expectation field did not round-trip for {cond:?}"
            );
        }
    }

    /// A frame missing `expectation` decodes as UNSPECIFIED — a real
    /// wire state that a conforming server MUST reject (see
    /// SPEC-TRANSPORT §4.2.1). This test pins the decode side; the
    /// server-side rejection lives in `kit-bin/src/commands/serve.rs`.
    #[test]
    fn update_ref_without_expectation_decodes_as_unspecified() {
        use buffa::Message;

        let req = UpdateRef {
            name: Some("refs/heads/main".into()),
            expected_id: Some(Vec::new()),
            new_id: Some(vec![0xABu8; 32]),
            // `expectation` left as None → zero-default on the wire.
            ..Default::default()
        };
        let bytes = req.encode_to_vec();
        let decoded = UpdateRef::decode(&mut &bytes[..]).expect("decode UpdateRef");
        assert_eq!(
            decoded.expectation.unwrap_or_default(),
            RefExpectation::Unspecified,
            "missing expectation field MUST decode as UNSPECIFIED"
        );
    }

    fn hex_encode(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    fn cursor_reply(cursor: Option<Vec<u8>>) -> ssh_frame::Body {
        let r = kit_rpc::kit::rpc::v1::ssh::ReadRepoCursorResponse {
            cursor,
            ..Default::default()
        };
        ssh_frame::Body::ReadRepoCursorResponse(Box::new(r))
    }

    fn error_reply(code: ErrorCode) -> ssh_frame::Body {
        let e = kit_rpc::kit::rpc::v1::Error::default()
            .with_code(code)
            .with_message("empty frame");
        ssh_frame::Body::Error(Box::new(e))
    }

    #[test]
    fn cursor_reply_holds_a_cursor_or_none() {
        for len in [1, 16, 32, 64] {
            let got = cursor_from_reply(Some(cursor_reply(Some(vec![7; len])))).unwrap();
            assert_eq!(got.unwrap().as_bytes(), &vec![7; len][..]);
        }
        assert_eq!(cursor_from_reply(Some(cursor_reply(None))).unwrap(), None);
    }

    #[test]
    fn cursor_reply_rejects_a_cursor_of_the_wrong_length() {
        for len in [0, 65, 1000] {
            assert!(matches!(
                cursor_from_reply(Some(cursor_reply(Some(vec![7; len])))),
                Err(TransportError::InvalidResponse)
            ));
        }
    }

    #[test]
    fn cursor_reply_rejects_a_field_it_does_not_define() {
        // Field 2 after a valid cursor: a trailing field, not "a cursor".
        let bytes = [0x0a, 0x01, 0x07, 0x12, 0x01, 0x00];
        let r = <kit_rpc::kit::rpc::v1::ssh::ReadRepoCursorResponse as buffa::Message>::decode_from_slice(
            &bytes,
        )
        .unwrap();
        assert!(matches!(
            cursor_from_reply(Some(ssh_frame::Body::ReadRepoCursorResponse(Box::new(r)))),
            Err(TransportError::InvalidResponse)
        ));
    }

    #[test]
    fn cursor_reply_of_a_server_that_predates_the_request_is_none() {
        // SPEC-RPC section 2: such a server answers a body it does not know
        // with INVALID_REQUEST. Any other error and any other frame is an
        // error, never "no cursor".
        assert_eq!(
            cursor_from_reply(Some(error_reply(ErrorCode::InvalidRequest))).unwrap(),
            None
        );
        for code in [ErrorCode::Internal, ErrorCode::KeyNotFound] {
            assert!(cursor_from_reply(Some(error_reply(code))).is_err());
        }
        for body in [
            None,
            Some(ssh_frame::Body::UpdateRefResponse(Box::default())),
            Some(ssh_frame::Body::ListRefsResponse(Box::default())),
        ] {
            assert!(matches!(
                cursor_from_reply(body),
                Err(TransportError::RemoteError(_))
            ));
        }
    }

    #[test]
    fn body_name_covers_every_oneof_variant() {
        // Every `ssh_frame::Body` oneof variant, pinned to its exact
        // `body_name` string. If the proto adds a variant and
        // `body_name` isn't updated, the new arm falls through to
        // `"(empty body)"` — exhaustively listing all 19 variants here
        // (plus `None`) means a forgotten arm shows up as a wrong
        // string on an EXISTING case only if it collides; the real
        // guard is that adding a variant to the match in `body_name`
        // without a corresponding line here is caught by nothing, so
        // this list must be kept in sync with `ssh_frame::Body`
        // (mirrors the exhaustive `match` in `body_name` itself).
        use ssh_frame::Body;
        assert_eq!(body_name(&None), "(empty body)");
        assert_eq!(body_name(&Some(Body::Hello(Box::default()))), "hello");
        assert_eq!(
            body_name(&Some(Body::HelloResponse(Box::default()))),
            "hello_response"
        );
        assert_eq!(body_name(&Some(Body::Error(Box::default()))), "error");
        assert_eq!(body_name(&Some(Body::Close(Box::default()))), "close");
        assert_eq!(
            body_name(&Some(Body::ListRefs(Box::default()))),
            "list_refs"
        );
        assert_eq!(
            body_name(&Some(Body::ListRefsResponse(Box::default()))),
            "list_refs_response"
        );
        assert_eq!(body_name(&Some(Body::ReadRef(Box::default()))), "read_ref");
        assert_eq!(
            body_name(&Some(Body::ReadRefResponse(Box::default()))),
            "read_ref_response"
        );
        assert_eq!(
            body_name(&Some(Body::UpdateRef(Box::default()))),
            "update_ref"
        );
        assert_eq!(
            body_name(&Some(Body::UpdateRefResponse(Box::default()))),
            "update_ref_response"
        );
        assert_eq!(
            body_name(&Some(Body::ReadRepoCursor(Box::default()))),
            "read_repo_cursor"
        );
        assert_eq!(
            body_name(&Some(Body::ReadRepoCursorResponse(Box::default()))),
            "read_repo_cursor_response"
        );
        assert_eq!(
            body_name(&Some(Body::PackExists(Box::default()))),
            "pack_exists"
        );
        assert_eq!(
            body_name(&Some(Body::PackExistsResponse(Box::default()))),
            "pack_exists_response"
        );
        assert_eq!(
            body_name(&Some(Body::UploadPack(Box::default()))),
            "upload_pack"
        );
        assert_eq!(
            body_name(&Some(Body::UploadPackResponse(Box::default()))),
            "upload_pack_response"
        );
        assert_eq!(
            body_name(&Some(Body::DownloadPack(Box::default()))),
            "download_pack"
        );
        assert_eq!(
            body_name(&Some(Body::DownloadPackHeader(Box::default()))),
            "download_pack_header"
        );
        assert_eq!(
            body_name(&Some(Body::PackChunk(Box::default()))),
            "pack_chunk"
        );
    }

    // --- build_ssh_command argv wiring ----------------------

    /// Collect the argv tokens of a built `Command` as owned strings so
    /// tests can assert on the spawned `ssh(1)` command line.
    fn argv_tokens(cmd: &Command) -> Vec<String> {
        cmd.get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    }

    /// Assert that `tokens` contains the consecutive pair
    /// `[flag, value]` (e.g. `-o`, `StrictHostKeyChecking=yes`).
    fn contains_pair(tokens: &[String], flag: &str, value: &str) -> bool {
        tokens.windows(2).any(|w| w[0] == flag && w[1] == value)
    }

    fn target() -> SshTarget {
        SshTarget {
            user: "alice".to_string(),
            host: "host.example.com".to_string(),
            port: None,
            path: "/repos/project".to_string(),
        }
    }

    /// A fully-populated `SshOptions` must surface as the documented
    /// `-o StrictHostKeyChecking=… -o UserKnownHostsFile=… -i …` flags
    /// (SSH-SECURITY.md §3). This is the consumer half of —
    /// it already worked, but the test pins the exact flag form so the
    /// producer wiring has a contract to satisfy.
    #[test]
    fn build_ssh_command_wires_populated_options() {
        let opts = SshOptions {
            strict_host_key_checking: "yes".to_string(),
            user_known_hosts_file: "/path/to/project.known_hosts".to_string(),
            identity_file: "/path/to/id_ed25519".to_string(),
        };
        let cmd = build_ssh_command(&target(), &opts);
        let tokens = argv_tokens(&cmd);
        assert!(
            contains_pair(&tokens, "-o", "StrictHostKeyChecking=yes"),
            "missing StrictHostKeyChecking flag: {tokens:?}"
        );
        assert!(
            contains_pair(
                &tokens,
                "-o",
                "UserKnownHostsFile=/path/to/project.known_hosts"
            ),
            "missing UserKnownHostsFile flag: {tokens:?}"
        );
        assert!(
            contains_pair(&tokens, "-i", "/path/to/id_ed25519"),
            "missing identity flag: {tokens:?}"
        );
    }

    /// Default options must emit NONE of the trust-pinning flags — the
    /// user's `ssh(1)` defaults are inherited. (A baseline
    /// `StrictHostKeyChecking=accept-new` IS added, but never the
    /// caller-supplied `yes`, and no `UserKnownHostsFile`/`-i`.)
    #[test]
    fn build_ssh_command_omits_flags_for_default_options() {
        let cmd = build_ssh_command(&target(), &SshOptions::default());
        let tokens = argv_tokens(&cmd);
        assert!(
            !tokens.iter().any(|t| t.starts_with("UserKnownHostsFile=")),
            "default options must not set UserKnownHostsFile: {tokens:?}"
        );
        assert!(
            !tokens.contains(&"-i".to_string()),
            "default options must not pass -i: {tokens:?}"
        );
        // No explicit StrictHostKeyChecking=<caller value>; only the
        // built-in accept-new baseline is permitted.
        assert!(
            !tokens.iter().any(|t| t == "StrictHostKeyChecking=yes"),
            "default options must not pin StrictHostKeyChecking=yes: {tokens:?}"
        );
    }
}
