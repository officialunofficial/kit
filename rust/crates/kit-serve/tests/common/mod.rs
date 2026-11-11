//! Shared harness for the session tests: scripted frame sources and sinks,
//! frame builders and a repository in a temp directory.
// The frame builders return `Option<Body>`, so a script can also hold the empty
// frame (`None`). Each test file uses a subset of the helpers.
#![allow(
    dead_code,
    unreachable_pub,
    clippy::unwrap_used,
    clippy::unnecessary_wraps
)]

use std::collections::VecDeque;
use std::path::{Path, PathBuf};

use kit_core::hash::{Hash, hash};
use kit_rpc::kit::common::v1::RefExpectation;
use kit_rpc::kit::rpc::v1::ssh::{
    DownloadPack, Hello, ListRefs, PackChunk, PackExists, ReadRef, ReadRepoCursor, SshFrame,
    UpdateRef, UploadPack, ssh_frame,
};
use kit_rpc::kit::rpc::v1::{Error as RpcError, ErrorCode, ProtocolVersion};
use kit_serve::{
    FrameIoError, FrameSink, FrameSource, Repo, SessionConfig, SessionEnd, WritePolicy,
    serve_session,
};

pub type Body = ssh_frame::Body;

/// The `server_id` that the captured golden sessions carry.
pub const SERVER_ID: &str = "kit serve/0.4.2";

/// A scripted frame source. Once the script runs out it reports a clean end
/// of stream.
pub struct VecSource(pub VecDeque<Result<SshFrame, FrameIoError>>);

impl FrameSource for VecSource {
    fn next_frame(&mut self) -> Result<SshFrame, FrameIoError> {
        self.0.pop_front().unwrap_or(Err(FrameIoError::Eof))
    }
}

/// Collects frames. It fails every send once `fail_after` frames are in. It
/// runs `after_send` after each frame it keeps.
#[derive(Default)]
pub struct VecSink {
    pub frames: Vec<SshFrame>,
    pub fail_after: Option<usize>,
    pub after_send: Option<Box<dyn FnMut(usize)>>,
}

impl FrameSink for VecSink {
    fn send(&mut self, frame: &SshFrame) -> Result<(), FrameIoError> {
        if self.fail_after.is_some_and(|n| self.frames.len() >= n) {
            return Err(FrameIoError::Io);
        }
        self.frames.push(frame.clone());
        if let Some(hook) = &mut self.after_send {
            hook(self.frames.len());
        }
        Ok(())
    }
}

pub fn frame(body: Option<Body>) -> SshFrame {
    SshFrame {
        body,
        ..Default::default()
    }
}

pub fn hello() -> Option<Body> {
    let hello = Hello::default().with_proto(ProtocolVersion::ProtocolVersion1);
    Some(Body::Hello(Box::new(hello)))
}

/// A source: `Hello`, then `bodies`.
pub fn script(bodies: impl IntoIterator<Item = Option<Body>>) -> VecSource {
    let frames = core::iter::once(hello()).chain(bodies);
    VecSource(frames.map(|b| Ok(frame(b))).collect())
}

/// A repository in a temp directory.
pub struct Fixture {
    pub td: tempfile::TempDir,
    pub repo: Repo,
}

impl Fixture {
    pub fn new() -> Self {
        Self::with_policy(WritePolicy::Open)
    }

    pub fn with_policy(policy: WritePolicy) -> Self {
        let td = tempfile::tempdir().unwrap();
        let repo = Repo::open(td.path(), policy).unwrap();
        Self { td, repo }
    }

    pub fn root(&self) -> &Path {
        self.td.path()
    }

    /// Run a session: `Hello`, then `bodies`. Returns how it ended and every
    /// frame after the `HelloResponse`, which it checks.
    pub fn run(
        &self,
        bodies: impl IntoIterator<Item = Option<Body>>,
    ) -> (SessionEnd, Vec<SshFrame>) {
        self.run_as(None, bodies)
    }

    /// [`Self::run`] as the session that the transport asserted `key` for.
    pub fn run_as(
        &self,
        key: Option<[u8; 32]>,
        bodies: impl IntoIterator<Item = Option<Body>>,
    ) -> (SessionEnd, Vec<SshFrame>) {
        let mut sink = VecSink::default();
        let end = serve_session(
            &self.repo,
            key,
            &mut script(bodies),
            &mut sink,
            &SessionConfig::new(SERVER_ID),
        );
        let mut frames = sink.frames.into_iter();
        let first = frames.next().expect("a HelloResponse");
        let Some(Body::HelloResponse(resp)) = first.body else {
            panic!("expected HelloResponse, got {:?}", first.body);
        };
        assert_eq!(resp.server_id.as_deref(), Some(SERVER_ID));
        (end, frames.collect())
    }

    /// Run `src` against `sink` as an anonymous session.
    pub fn serve(
        &self,
        src: &mut VecSource,
        sink: &mut VecSink,
        cfg: &SessionConfig,
    ) -> SessionEnd {
        serve_session(&self.repo, None, src, sink, cfg)
    }

    /// Seed the repository through the session itself: `refs` with `ANY`
    /// and the packs, each in one chunk.
    pub fn seed(&self, refs: &[(&str, Hash)], packs: &[&[u8]]) {
        let mut bodies = Vec::new();
        for (name, id) in refs {
            bodies.push(update(name, id, Some(RefExpectation::Any), None));
        }
        for pack in packs {
            let id = hash(pack);
            bodies.push(upload_header(&id, Some(pack.len() as u64)));
            bodies.push(chunk(&id, Some(0), pack, true));
        }
        let (end, frames) = self.run(bodies);
        assert_eq!(end, SessionEnd::Clean);
        let ok = |f: &SshFrame| {
            matches!(
                f.body,
                Some(Body::UpdateRefResponse(_) | Body::UploadPackResponse(_))
            )
        };
        assert!(frames.iter().all(ok), "seeding failed: {frames:?}");
    }

    pub fn pack_present(&self, id: Hash) -> bool {
        self.root()
            .join("packs")
            .join(kit_core::hash::to_hex(&id))
            .is_file()
    }

    /// Every file under the root, relative to it, sorted.
    pub fn files(&self) -> Vec<PathBuf> {
        fn walk(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    walk(root, &path, out);
                } else {
                    out.push(path.strip_prefix(root).unwrap().to_owned());
                }
            }
        }
        let mut out = Vec::new();
        walk(self.root(), self.root(), &mut out);
        out.sort();
        out
    }
}

/// The frame's error, which it must be.
#[track_caller]
pub fn error(f: &SshFrame) -> &RpcError {
    match &f.body {
        Some(Body::Error(e)) => e,
        other => panic!("expected an Error frame, got {other:?}"),
    }
}

/// Assert `f` is `Error{code, message}` with empty `details`.
#[track_caller]
pub fn assert_error(f: &SshFrame, code: ErrorCode, message: &str) {
    let e = error(f);
    assert!(e.code.is_some_and(|c| c == code), "code of {e:?}");
    assert_eq!(e.message.as_deref(), Some(message));
    assert_eq!(e.details.as_deref().map_or(0, <[u8]>::len), 0);
}

pub fn upload_header(id: &[u8], total: Option<u64>) -> Option<Body> {
    Some(Body::UploadPack(Box::new(UploadPack {
        pack_id: Some(id.to_vec()),
        total_bytes: total,
        ..Default::default()
    })))
}

pub fn chunk(id: &[u8], offset: Option<u64>, data: &[u8], last: bool) -> Option<Body> {
    Some(Body::PackChunk(Box::new(PackChunk {
        pack_id: Some(id.to_vec()),
        offset,
        data: Some(data.to_vec()),
        last: Some(last),
        ..Default::default()
    })))
}

pub fn update(
    name: &str,
    new: &[u8],
    expectation: Option<RefExpectation>,
    expected: Option<&[u8]>,
) -> Option<Body> {
    let mut req = UpdateRef::default()
        .with_name(name)
        .with_new_id(new.to_vec());
    if let Some(e) = expectation {
        req = req.with_expectation(e);
    }
    if let Some(e) = expected {
        req = req.with_expected_id(e.to_vec());
    }
    Some(Body::UpdateRef(Box::new(req)))
}

pub fn read_ref(name: &str) -> Option<Body> {
    Some(Body::ReadRef(Box::new(ReadRef::default().with_name(name))))
}

pub fn list_refs(prefix: Option<&str>) -> Option<Body> {
    let mut req = ListRefs::default();
    if let Some(p) = prefix {
        req = req.with_prefix(p);
    }
    Some(Body::ListRefs(Box::new(req)))
}

pub fn read_repo_cursor() -> Option<Body> {
    Some(Body::ReadRepoCursor(Box::<ReadRepoCursor>::default()))
}

pub fn exists(id: &[u8]) -> Option<Body> {
    let req = PackExists::default().with_pack_id(id.to_vec());
    Some(Body::PackExists(Box::new(req)))
}

pub fn download(id: Option<&[u8]>) -> Option<Body> {
    let mut req = DownloadPack::default();
    if let Some(id) = id {
        req = req.with_pack_id(id.to_vec());
    }
    Some(Body::DownloadPack(Box::new(req)))
}

pub fn close() -> Option<Body> {
    Some(Body::Close(Box::default()))
}

pub fn pack_bytes(len: usize, seed: u8) -> Vec<u8> {
    #[allow(clippy::cast_possible_truncation)]
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

pub fn valid_pack() -> (Vec<u8>, Hash) {
    let bytes = b"valid pack bytes".to_vec();
    let id = hash(&bytes);
    (bytes, id)
}

/// The cursor of a `ReadRepoCursorResponse`, or `None` when the reply holds
/// none.
#[track_caller]
pub fn reply_cursor(f: &SshFrame) -> Option<Vec<u8>> {
    match &f.body {
        Some(Body::ReadRepoCursorResponse(r)) => r.cursor.clone(),
        other => panic!("expected ReadRepoCursorResponse, got {other:?}"),
    }
}

/// Set the modification time of the directory `dir` and of every directory
/// below it to `when`.
pub fn stamp_dirs(dir: &Path, when: std::time::SystemTime) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            stamp_dirs(&path, when);
        }
    }
    std::fs::File::open(dir)
        .unwrap()
        .set_modified(when)
        .unwrap();
}

/// The names of a `ListRefsResponse`.
#[track_caller]
pub fn listed_names(f: &SshFrame) -> Vec<String> {
    match &f.body {
        Some(Body::ListRefsResponse(r)) => r.refs.iter().map(|e| e.name.clone().unwrap()).collect(),
        other => panic!("expected ListRefsResponse, got {other:?}"),
    }
}

/// The pack that a `DownloadPack` reply carries, after it checks the
/// framing: a header with the length, then contiguous chunks that repeat
/// `id`, of which only the final one is `last`.
#[track_caller]
pub fn downloaded(frames: &[SshFrame], id: &[u8]) -> Vec<u8> {
    let Some(Body::DownloadPackHeader(h)) = &frames[0].body else {
        panic!("expected DownloadPackHeader, got {:?}", frames[0].body);
    };
    let total = h.total_bytes.unwrap();
    let mut out = Vec::new();
    for (i, f) in frames[1..].iter().enumerate() {
        let Some(Body::PackChunk(c)) = &f.body else {
            panic!("expected PackChunk, got {:?}", f.body);
        };
        assert_eq!(c.pack_id.as_deref(), Some(id));
        assert_eq!(c.offset, Some(out.len() as u64));
        out.extend_from_slice(c.data.as_deref().unwrap());
        if c.last == Some(true) {
            assert_eq!(out.len() as u64, total);
            assert_eq!(i + 2, frames.len(), "nothing after the last chunk");
            return out;
        }
    }
    panic!("no last chunk");
}
