//! The session driver: `Hello`, then the verb loop under the per-connection
//! budgets (SPEC-TRANSPORT §4.2, SPEC-RPC §4).

use mkit_rpc::kit::rpc::v1::ssh::{HelloResponse, SshFrame, ssh_frame};
use mkit_rpc::kit::rpc::v1::{ErrorCode, ProtocolVersion};

use crate::budget::Budget;
use crate::repo::Repo;
use crate::verbs::Verbs;

/// Why a frame could not be read or written.
#[derive(Debug)]
#[non_exhaustive]
pub enum FrameIoError {
    /// The peer closed the stream cleanly, between frames.
    Eof,
    /// The read deadline of the source passed.
    Timeout,
    /// A frame that is too long, truncated or undecodable.
    Malformed,
    /// Any other I/O failure.
    Io,
}

impl From<mkit_rpc::FrameError> for FrameIoError {
    /// A truncated length prefix is a clean end of stream. An I/O failure is
    /// [`Self::Io`]. Anything else is [`Self::Malformed`].
    fn from(err: mkit_rpc::FrameError) -> Self {
        match err {
            mkit_rpc::FrameError::LengthTruncated => Self::Eof,
            mkit_rpc::FrameError::Io(_) => Self::Io,
            _ => Self::Malformed,
        }
    }
}

/// Where a session reads its frames.
pub trait FrameSource {
    /// The next frame. A source with a read deadline returns
    /// [`FrameIoError::Timeout`] when the deadline passes.
    ///
    /// # Errors
    /// [`FrameIoError`] for a stream that ended, timed out or broke.
    fn next_frame(&mut self) -> Result<SshFrame, FrameIoError>;
}

/// Where a session writes its frames.
pub trait FrameSink {
    /// Write one frame and flush it.
    ///
    /// # Errors
    /// [`FrameIoError`] when the frame could not be written.
    fn send(&mut self, frame: &SshFrame) -> Result<(), FrameIoError>;
}

/// The settings of a session.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SessionConfig {
    /// `HelloResponse.server_id`.
    pub server_id: String,
    /// End cleanly right after a successful handshake, before any verb. Only
    /// a test sets it.
    pub stop_after_hello: bool,
}

impl SessionConfig {
    /// A session that answers `Hello` with `server_id`.
    #[must_use]
    pub fn new(server_id: impl Into<String>) -> Self {
        Self {
            server_id: server_id.into(),
            stop_after_hello: false,
        }
    }
}

/// How a session ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEnd {
    /// The client sent `Close` or closed the stream between frames, or
    /// `stop_after_hello` was set.
    Clean,
    /// A failed handshake, an unreadable frame or an exceeded budget. The
    /// error frame, if any, went out first.
    ProtocolError,
    /// The source timed out.
    Timeout,
    /// The sink failed while the server answered a verb.
    IoError,
}

/// A verb stopped the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stop {
    /// The sink failed.
    Io,
    /// The source timed out inside an upload.
    Timeout,
}

impl From<FrameIoError> for Stop {
    fn from(_: FrameIoError) -> Self {
        Self::Io
    }
}

/// Send an `Error{code, message}` frame with empty `details`.
pub(crate) fn emit_error<K: FrameSink>(
    sink: &mut K,
    code: ErrorCode,
    message: &str,
) -> Result<(), Stop> {
    let frame = mkit_rpc::ssh_error_frame(code, message);
    sink.send(&frame).map_err(Stop::from)
}

/// Send a frame that holds `body`.
pub(crate) fn send_body<K: FrameSink>(sink: &mut K, body: ssh_frame::Body) -> Result<(), Stop> {
    let frame = SshFrame {
        body: Some(body),
        ..Default::default()
    };
    sink.send(&frame).map_err(Stop::from)
}

/// The application handshake (SPEC-RPC §4). The first frame must be a
/// protocol-1 `Hello`. The answer is a `HelloResponse` with `server_id`.
///
/// # Errors
/// [`SessionEnd::Timeout`] when the source times out. Otherwise
/// [`SessionEnd::ProtocolError`]: after an error frame for a first frame
/// that is not `Hello` or that names another protocol version, and without
/// a frame for an unreadable first frame or a failed `HelloResponse` write.
fn handshake<S: FrameSource, K: FrameSink>(
    src: &mut S,
    sink: &mut K,
    server_id: &str,
) -> Result<(), SessionEnd> {
    let frame = match src.next_frame() {
        Ok(frame) => frame,
        Err(FrameIoError::Timeout) => return Err(SessionEnd::Timeout),
        Err(_) => return Err(SessionEnd::ProtocolError),
    };
    let Some(ssh_frame::Body::Hello(hello)) = frame.body else {
        let _ = emit_error(sink, ErrorCode::InvalidRequest, "first frame must be Hello");
        return Err(SessionEnd::ProtocolError);
    };
    let proto = hello.proto.unwrap_or_default();
    if proto != ProtocolVersion::ProtocolVersion1 {
        let message = format!("unsupported proto_version {}", proto.to_i32());
        let _ = emit_error(sink, ErrorCode::InvalidRequest, &message);
        return Err(SessionEnd::ProtocolError);
    }
    let resp = ssh_frame::Body::HelloResponse(Box::new(HelloResponse {
        proto: Some(ProtocolVersion::ProtocolVersion1.into()),
        server_id: Some(server_id.to_owned()),
        ..Default::default()
    }));
    send_body(sink, resp).map_err(|_| SessionEnd::ProtocolError)
}

/// Serve one ssh-frame session on `repo`: the handshake, then one verb per
/// top-level frame until `Close`, a clean end of stream, a protocol error or
/// a failure.
///
/// `key` is the Ed25519 public key that the transport asserts for the
/// session, or `None`. It is never read from a frame. Only
/// [`WritePolicy`](crate::WritePolicy) uses it, to decide who may write.
pub fn serve_session<S: FrameSource, K: FrameSink>(
    repo: &Repo,
    key: Option<[u8; 32]>,
    src: &mut S,
    sink: &mut K,
    cfg: &SessionConfig,
) -> SessionEnd {
    if let Err(end) = handshake(src, sink, &cfg.server_id) {
        return end;
    }
    if cfg.stop_after_hello {
        return SessionEnd::Clean;
    }
    let mut verbs = Verbs::new(repo, key);
    let mut budget = Budget::default();
    loop {
        let frame = match src.next_frame() {
            Ok(frame) => frame,
            Err(FrameIoError::Eof) => return SessionEnd::Clean,
            Err(FrameIoError::Timeout) => return SessionEnd::Timeout,
            Err(_) => {
                let _ = emit_error(sink, ErrorCode::InvalidRequest, "frame parse error");
                return SessionEnd::ProtocolError;
            }
        };
        if let Err(message) = budget.charge(&frame) {
            let _ = emit_error(sink, ErrorCode::InvalidRequest, message);
            return SessionEnd::ProtocolError;
        }
        let body = match frame.body {
            Some(ssh_frame::Body::Close(_)) => return SessionEnd::Clean,
            body => body,
        };
        match verbs.dispatch(body, src, sink) {
            Ok(()) => {}
            Err(Stop::Io) => return SessionEnd::IoError,
            Err(Stop::Timeout) => return SessionEnd::Timeout,
        }
    }
}
