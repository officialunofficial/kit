//! A loopback Connect server for pack streaming tests, backed by a file
//! remote, and a loopback HTTP host for its pack locations.
//!
//! Neither holds a pack in memory: uploads stream into files, parts are
//! written at their offsets, and downloads and locations stream from the
//! file remote. A test that counts the process's heap therefore counts the
//! client's. Modes make the server misbehave on purpose: a location with
//! the wrong bytes or length, a streamed answer to a location offer, a pack
//! sent as one oversized frame, a part that fails once.
#![allow(dead_code)] // each test binary uses part of the fixture

use std::collections::HashMap;
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, mpsc};

use connectrpc::server::Server;
use connectrpc::{
    ConnectError, ErrorCode, RequestContext, Response, Router, ServiceRequest, ServiceResult,
    ServiceStream,
};
use futures::StreamExt as _;
use generated::__buffa::oneof::begin_upload_response::Result as BeginResult;
use generated::__buffa::oneof::upload_pack_request::Body as UploadBody;
use generated::__buffa::oneof::upload_part_request::Msg as PartBody;
use kit_core::hash::{Hash, Hasher};
use kit_core::protocol::{
    AdvanceOutcome, PackBody, PackKey, PackSink, RefWriteCondition, Transport, TransportError,
    TransportResult,
};
use kit_transport_connect::generated;
use kit_transport_file::FileTransport;

/// The chunk size the reference server sends.
pub const CHUNK: usize = 800 * 1024;
/// The part size the server's tickets carry.
pub const PART_SIZE: u64 = 8 << 20;

/// How the server answers a `DownloadPack` that accepts a location.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Location {
    /// Locations are not advertised.
    Off,
    /// A location whose host serves the pack.
    Honest,
    /// The host serves the pack with its first byte changed.
    WrongKey,
    /// The host serves one byte less, declared.
    Short,
    /// The host serves one byte more, declared.
    Long,
    /// The host serves one byte less, with no declared length.
    ShortUnsized,
    /// The host serves one byte more, with no declared length.
    LongUnsized,
    /// Locations are advertised, but the server streams instead.
    Stream,
}

/// What the server counts.
#[derive(Clone, Debug, Default)]
pub struct Counts {
    /// Each `DownloadPack`'s key, and whether it accepted a location.
    pub downloads: Vec<(Hash, bool)>,
    /// The key of each location fetch.
    pub location_gets: Vec<Hash>,
    pub upload_packs: usize,
    pub begins: usize,
    /// Each `UploadPart`'s index, in order.
    pub parts: Vec<u32>,
    pub completes: usize,
}

struct Ticket {
    pack: Hash,
    bytes: u64,
    head: String,
    file: PathBuf,
    expires: i64,
}

struct Modes {
    location: Location,
    one_frame: bool,
    threshold: u64,
    fail_part_once: Option<u32>,
}

struct Shared {
    remote: FileTransport,
    dir: PathBuf,
    location_port: u16,
    modes: Mutex<Modes>,
    counts: Mutex<Counts>,
    tickets: Mutex<HashMap<Hash, Ticket>>,
    next: Mutex<u64>,
}

/// The server, its location host, and the file remote behind both.
pub struct PackServer {
    pub port: u16,
    shared: Arc<Shared>,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Counts {
    /// The `DownloadPack` calls for `key`: whether each accepted a location.
    pub fn downloads_of(&self, key: &Hash) -> Vec<bool> {
        self.downloads
            .iter()
            .filter(|(pack, _)| pack == key)
            .map(|(_, accept)| *accept)
            .collect()
    }

    /// The location fetches of `key`.
    pub fn location_gets_of(&self, key: &Hash) -> usize {
        self.location_gets
            .iter()
            .filter(|pack| *pack == key)
            .count()
    }
}

impl PackServer {
    /// Serve the file remote at `dir/remote`, keeping upload files in `dir`.
    pub fn start(dir: &Path) -> Self {
        std::fs::create_dir_all(dir).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let location_port = listener.local_addr().unwrap().port();
        let shared = Arc::new(Shared {
            remote: FileTransport::new(dir.join("remote")),
            dir: dir.to_owned(),
            location_port,
            modes: Mutex::new(Modes {
                location: Location::Off,
                one_frame: false,
                threshold: 0,
                fail_part_once: None,
            }),
            counts: Mutex::new(Counts::default()),
            tickets: Mutex::new(HashMap::new()),
            next: Mutex::new(0),
        });
        let host = Arc::clone(&shared);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { return };
                let host = Arc::clone(&host);
                std::thread::spawn(move || serve_location(&host, stream));
            }
        });
        let service = Arc::new(Service(Arc::clone(&shared)));
        let (port_tx, port_rx) = mpsc::channel();
        let (shutdown, stopped) = tokio::sync::oneshot::channel();
        let thread = std::thread::spawn(move || {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap()
                .block_on(async move {
                    let bound = Server::bind("127.0.0.1:0").await.unwrap();
                    port_tx.send(bound.local_addr().unwrap().port()).unwrap();
                    bound
                        .serve_with_graceful_shutdown(Router::new().add_service(service), async {
                            let _ = stopped.await;
                        })
                        .await
                        .unwrap();
                });
        });
        Self {
            port: port_rx.recv().unwrap(),
            shared,
            shutdown: Some(shutdown),
            thread: Some(thread),
        }
    }

    pub fn origin(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    /// The file remote, for seeding and checking.
    pub fn remote(&self) -> &FileTransport {
        &self.shared.remote
    }

    pub fn set_location(&self, location: Location) {
        self.shared.modes.lock().unwrap().location = location;
    }

    /// Send each pack as one chunk, in one frame.
    pub fn set_one_frame(&self, one_frame: bool) {
        self.shared.modes.lock().unwrap().one_frame = one_frame;
    }

    /// Packs below `bytes` upload without a ticket.
    pub fn set_ticket_threshold(&self, bytes: u64) {
        self.shared.modes.lock().unwrap().threshold = bytes;
    }

    /// Fail the next `UploadPart` of part `index`, once, as a refusal.
    pub fn fail_part_once(&self, index: u32) {
        self.shared.modes.lock().unwrap().fail_part_once = Some(index);
    }

    pub fn counts(&self) -> Counts {
        self.shared.counts.lock().unwrap().clone()
    }

    pub fn reset_counts(&self) {
        *self.shared.counts.lock().unwrap() = Counts::default();
    }
}

impl Drop for PackServer {
    fn drop(&mut self) {
        let _ = self.shutdown.take().unwrap().send(());
        let result = self.thread.take().unwrap().join();
        if !std::thread::panicking() {
            result.unwrap();
        }
    }
}

/// A file on disk as a pack body; each reader opens the file again.
pub struct FileBody {
    pub path: PathBuf,
    pub len: u64,
}

impl PackBody for FileBody {
    fn len(&self) -> u64 {
        self.len
    }
    fn read_from(&self, offset: u64) -> std::io::Result<Box<dyn std::io::Read + Send + '_>> {
        if offset > self.len {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        let mut file = std::fs::File::open(&self.path)?;
        file.seek(SeekFrom::Start(offset))?;
        Ok(Box::new(file.take(self.len - offset)))
    }
}

fn to_connect_error(error: TransportError) -> ConnectError {
    match error {
        TransportError::PackNotFound => ConnectError::not_found("pack not found"),
        TransportError::RefConflict => ConnectError::failed_precondition("ref CAS conflict"),
        TransportError::InvalidRef(message) => ConnectError::invalid_argument(message),
        error => ConnectError::new(ErrorCode::Internal, error.to_string()),
    }
}

fn to_hash(bytes: Option<Vec<u8>>) -> Result<Hash, ConnectError> {
    bytes
        .and_then(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok())
        .ok_or_else(|| ConnectError::invalid_argument("digest must be 32 bytes"))
}

fn condition(
    expectation: Option<buffa::EnumValue<generated::RefExpectation>>,
    expected: Option<Vec<u8>>,
) -> Result<RefWriteCondition, ConnectError> {
    match expectation.and_then(|value| value.as_known()) {
        Some(generated::RefExpectation::Any) => Ok(RefWriteCondition::Any),
        Some(generated::RefExpectation::Missing) => Ok(RefWriteCondition::Missing),
        Some(generated::RefExpectation::Match) => Ok(RefWriteCondition::Match(to_hash(expected)?)),
        _ => Err(ConnectError::invalid_argument("ref expectation")),
    }
}

fn now_ms() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

fn internal(error: impl std::fmt::Display) -> ConnectError {
    ConnectError::new(ErrorCode::Internal, error.to_string())
}

/// Hash a file's bytes, one read at a time.
fn hash_file(path: &Path) -> std::io::Result<Hash> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Hasher::new();
    let mut buf = vec![0; 1 << 20];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            return Ok(hasher.finalize());
        }
        hasher.update(&buf[..n]);
    }
}

/// Sends a download as `DownloadPack` messages over a bounded channel.
struct ChannelSink {
    key: Hash,
    sender: tokio::sync::mpsc::Sender<Result<generated::DownloadPackResponse, ConnectError>>,
    sent: u64,
    total: u64,
    one_frame: Option<Vec<u8>>,
}

impl ChannelSink {
    fn send(&self, message: generated::DownloadPackResponse) -> TransportResult<()> {
        self.sender
            .blocking_send(Ok(message))
            .map_err(|_| TransportError::ConnectionFailed)
    }
    fn chunk(&mut self, data: &[u8]) -> TransportResult<()> {
        let end = self.sent + data.len() as u64;
        let message = generated::DownloadPackResponse {
            body: Some(
                generated::PackChunk {
                    pack_id: Some(self.key.to_vec()),
                    offset: Some(self.sent),
                    data: Some(data.to_vec()),
                    last: Some(end == self.total),
                    ..Default::default()
                }
                .into(),
            ),
            ..Default::default()
        };
        self.sent = end;
        self.send(message)
    }
}

impl PackSink for ChannelSink {
    fn begin(&mut self, declared: Option<u64>) -> TransportResult<()> {
        self.total = declared.ok_or(TransportError::ProtocolError)?;
        self.send(generated::DownloadPackResponse {
            body: Some(
                generated::DownloadPackHeader {
                    total_bytes: Some(self.total),
                    ..Default::default()
                }
                .into(),
            ),
            ..Default::default()
        })?;
        if self.total == 0 {
            self.chunk(&[])?;
        }
        Ok(())
    }
    fn write(&mut self, bytes: &[u8]) -> TransportResult<()> {
        if let Some(whole) = &mut self.one_frame {
            whole.extend_from_slice(bytes);
            if whole.len() as u64 == self.total {
                let whole = std::mem::take(whole);
                self.chunk(&whole)?;
            }
            return Ok(());
        }
        for piece in bytes.chunks(CHUNK) {
            self.chunk(piece)?;
        }
        Ok(())
    }
    fn failed(&self) -> Option<std::io::ErrorKind> {
        None
    }
}

/// Writes a location body to a socket, misbehaving as `mode` says.
struct SocketSink {
    stream: TcpStream,
    mode: Location,
    started: bool,
}

impl PackSink for SocketSink {
    fn begin(&mut self, declared: Option<u64>) -> TransportResult<()> {
        let len = declared.ok_or(TransportError::ProtocolError)?;
        let length = match self.mode {
            Location::Short => format!("Content-Length: {}\r\n", len - 1),
            Location::Long => format!("Content-Length: {}\r\n", len + 1),
            Location::ShortUnsized | Location::LongUnsized => String::new(),
            _ => format!("Content-Length: {len}\r\n"),
        };
        write!(
            self.stream,
            "HTTP/1.1 200 OK\r\n{length}Connection: close\r\n\r\n"
        )
        .map_err(|_| TransportError::ConnectionFailed)
    }
    fn write(&mut self, bytes: &[u8]) -> TransportResult<()> {
        let mut bytes = bytes.to_vec();
        if !self.started && self.mode == Location::WrongKey {
            bytes[0] ^= 1;
        }
        if !self.started && matches!(self.mode, Location::Short | Location::ShortUnsized) {
            bytes.remove(0);
        }
        if !self.started && matches!(self.mode, Location::Long | Location::LongUnsized) {
            bytes.insert(0, 0);
        }
        self.started = true;
        self.stream
            .write_all(&bytes)
            .map_err(|_| TransportError::ConnectionFailed)
    }
    fn failed(&self) -> Option<std::io::ErrorKind> {
        None
    }
}

fn serve_location(shared: &Shared, mut stream: TcpStream) {
    let mut request = Vec::new();
    let mut byte = [0];
    while !request.ends_with(b"\r\n\r\n") {
        if stream.read_exact(&mut byte).is_err() {
            return;
        }
        request.push(byte[0]);
    }
    let line = String::from_utf8_lossy(&request);
    let Some(hex) = line
        .split_whitespace()
        .nth(1)
        .and_then(|path| path.strip_prefix('/'))
    else {
        return;
    };
    let Ok(key) = kit_core::hash::from_hex(hex) else {
        return;
    };
    shared.counts.lock().unwrap().location_gets.push(key);
    let mode = shared.modes.lock().unwrap().location;
    let mut sink = SocketSink {
        stream,
        mode,
        started: false,
    };
    // A client that stopped reading closes the socket; that is not an error here.
    let _ = shared
        .remote
        .download_pack(&PackKey::new(key), None, &mut sink);
}

struct Service(Arc<Shared>);

#[allow(refining_impl_trait)]
impl generated::TransportService for Service {
    async fn list_repos(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, generated::ListReposRequest>,
    ) -> ServiceResult<generated::ListReposResponse> {
        Err(ConnectError::unimplemented("unused"))
    }

    async fn get_receipt(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, generated::GetReceiptRequest>,
    ) -> ServiceResult<generated::GetReceiptResponse> {
        Err(ConnectError::unimplemented("unused"))
    }

    async fn get_server_info(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, generated::GetServerInfoRequest>,
    ) -> ServiceResult<generated::GetServerInfoResponse> {
        let modes = self.0.modes.lock().unwrap();
        let locations = modes.location != Location::Off;
        Ok(Response::new(generated::GetServerInfoResponse {
            protocol: Some("kit.transport.v1".into()),
            spec_version: Some(2),
            max_pack_bytes: Some(4 << 30),
            part_size: Some(PART_SIZE),
            max_parts: Some(512),
            max_list_refs_page_size: Some(1000),
            begin_upload_threshold_bytes: Some(modes.threshold),
            atomic_advance: Some(true),
            supports_pack_locations: Some(locations),
            max_pack_location_lifetime_ms: locations.then_some(60_000),
            ..Default::default()
        }))
    }

    async fn list_refs(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, generated::ListRefsRequest>,
    ) -> ServiceResult<generated::ListRefsResponse> {
        let prefix = request.to_owned_message().prefix.unwrap_or_default();
        let refs = self.0.remote.list_refs(&prefix).map_err(to_connect_error)?;
        Ok(Response::new(generated::ListRefsResponse {
            refs: refs
                .into_iter()
                .map(|entry| generated::RefEntry {
                    name: Some(entry.name),
                    object_id: Some(entry.hash.unwrap_or_default().to_vec()),
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        }))
    }

    async fn read_ref(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, generated::ReadRefRequest>,
    ) -> ServiceResult<generated::ReadRefResponse> {
        let name = request.to_owned_message().name.unwrap_or_default();
        let current = self.0.remote.read_ref(&name).map_err(to_connect_error)?;
        Ok(Response::new(generated::ReadRefResponse {
            exists: Some(current.is_some()),
            object_id: current.map(|id| id.to_vec()),
            ..Default::default()
        }))
    }

    async fn update_ref(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, generated::UpdateRefRequest>,
    ) -> ServiceResult<generated::UpdateRefResponse> {
        let message = request.to_owned_message();
        let name = message.name.unwrap_or_default();
        let condition = condition(message.expectation, message.expected_id)?;
        self.0
            .remote
            .update_ref(&name, condition, &to_hash(message.new_id)?)
            .map_err(to_connect_error)?;
        Ok(Response::new(generated::UpdateRefResponse::default()))
    }

    async fn advance_refs(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, generated::AdvanceRefsRequest>,
    ) -> ServiceResult<generated::AdvanceRefsResponse> {
        let message = request.to_owned_message();
        let outcome = self
            .0
            .remote
            .advance_refs(
                &message.head_ref.unwrap_or_default(),
                condition(message.head_expectation, message.head_expected_id)?,
                &to_hash(message.head_new_id)?,
                &message.packmap_ref.unwrap_or_default(),
                condition(message.packmap_expectation, message.packmap_expected_id)?,
                &to_hash(message.packmap_new_id)?,
            )
            .map_err(to_connect_error)?;
        Ok(Response::new(generated::AdvanceRefsResponse {
            outcome: Some(
                match outcome {
                    AdvanceOutcome::Committed => generated::AdvanceOutcome::Committed,
                    AdvanceOutcome::HeadConflict => generated::AdvanceOutcome::HeadConflict,
                    AdvanceOutcome::PackmapConflict => generated::AdvanceOutcome::PackmapConflict,
                }
                .into(),
            ),
            ..Default::default()
        }))
    }

    async fn pack_exists(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, generated::PackExistsRequest>,
    ) -> ServiceResult<generated::PackExistsResponse> {
        let key = PackKey::new(to_hash(request.to_owned_message().pack_id)?);
        let exists = self
            .0
            .remote
            .pack_exists(&key, None)
            .map_err(to_connect_error)?;
        Ok(Response::new(generated::PackExistsResponse {
            exists: Some(exists),
            ..Default::default()
        }))
    }

    async fn download_pack(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, generated::DownloadPackRequest>,
    ) -> ServiceResult<ServiceStream<generated::DownloadPackResponse>> {
        let message = request.to_owned_message();
        let pack = to_hash(message.pack_id)?;
        let key = PackKey::new(pack);
        if !self
            .0
            .remote
            .pack_exists(&key, None)
            .map_err(to_connect_error)?
        {
            return Err(ConnectError::not_found("pack not found"));
        }
        let accept = message.accept_location == Some(true);
        let (location, one_frame) = {
            let modes = self.0.modes.lock().unwrap();
            (modes.location, modes.one_frame)
        };
        self.0.counts.lock().unwrap().downloads.push((pack, accept));
        if accept && !matches!(location, Location::Off | Location::Stream) {
            let size = std::fs::metadata(self.0.remote_path(&pack))
                .map_err(internal)?
                .len();
            let answer = generated::DownloadPackResponse {
                body: Some(
                    generated::DownloadPackLocation {
                        url: Some(format!(
                            "http://127.0.0.1:{}/{}",
                            self.0.location_port,
                            kit_core::hash::to_hex(&pack)
                        )),
                        expires_at_ms: Some(now_ms() + 30_000),
                        total_bytes: Some(size),
                        ..Default::default()
                    }
                    .into(),
                ),
                ..Default::default()
            };
            return Response::stream_ok(futures::stream::iter([Ok(answer)]));
        }
        let (sender, receiver) = tokio::sync::mpsc::channel(2);
        let shared = Arc::clone(&self.0);
        std::thread::spawn(move || {
            let mut sink = ChannelSink {
                key: pack,
                sender: sender.clone(),
                sent: 0,
                total: 0,
                one_frame: one_frame.then(Vec::new),
            };
            if let Err(error) = shared.remote.download_pack(&key, None, &mut sink) {
                let _ = sender.blocking_send(Err(to_connect_error(error)));
            }
        });
        Response::stream_ok(futures::stream::unfold(receiver, |mut receiver| async {
            receiver.recv().await.map(|message| (message, receiver))
        }))
    }

    async fn upload_pack(
        &self,
        _ctx: RequestContext,
        mut requests: connectrpc::InboundStream<generated::UploadPackRequest>,
    ) -> ServiceResult<generated::UploadPackResponse> {
        self.0.counts.lock().unwrap().upload_packs += 1;
        let first = requests
            .next()
            .await
            .ok_or_else(|| ConnectError::invalid_argument("empty stream"))??;
        let Some(UploadBody::Header(header)) = first.to_owned_message().body else {
            return Err(ConnectError::invalid_argument("header first"));
        };
        let pack = to_hash(header.pack_id)?;
        let path = self.0.upload_path();
        let mut file = std::fs::File::create(&path).map_err(internal)?;
        let mut hasher = Hasher::new();
        let mut received = 0_u64;
        loop {
            let message = requests
                .next()
                .await
                .ok_or_else(|| ConnectError::invalid_argument("no last chunk"))??;
            let Some(UploadBody::Chunk(chunk)) = message.to_owned_message().body else {
                return Err(ConnectError::invalid_argument("chunk expected"));
            };
            if chunk.offset != Some(received) || chunk.pack_id.as_deref() != Some(&pack[..]) {
                return Err(ConnectError::invalid_argument("chunk order"));
            }
            let data = chunk.data.unwrap_or_default();
            hasher.update(&data);
            file.write_all(&data).map_err(internal)?;
            received += data.len() as u64;
            if chunk.last == Some(true) {
                break;
            }
        }
        drop(file);
        if received != header.total_bytes.unwrap_or(0) || hasher.finalize() != pack {
            return Err(ConnectError::invalid_argument("pack commitment"));
        }
        self.0.store(&path, received, pack)?;
        Ok(Response::new(generated::UploadPackResponse::default()))
    }

    async fn begin_upload(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, generated::BeginUploadRequest>,
    ) -> ServiceResult<generated::BeginUploadResponse> {
        self.0.counts.lock().unwrap().begins += 1;
        let message = request.to_owned_message();
        let pack = to_hash(message.pack_id)?;
        let bytes = message.bytes.unwrap_or(0);
        let head = message.r#ref.unwrap_or_default();
        if self
            .0
            .remote
            .pack_exists(&PackKey::new(pack), None)
            .map_err(to_connect_error)?
        {
            return Ok(Response::new(generated::BeginUploadResponse {
                result: Some(BeginResult::AlreadyPresent(Box::default())),
                ..Default::default()
            }));
        }
        let mut tickets = self.0.tickets.lock().unwrap();
        // An open ticket for the same pack is handed out again, so stored
        // part receipts stay valid across a restart.
        let open = tickets
            .iter()
            .find(|(_, ticket)| ticket.pack == pack && ticket.head == head)
            .map(|(id, ticket)| (*id, ticket.expires));
        let (id, expires) = match open {
            Some(open) => open,
            None => {
                let file = self.0.upload_path();
                let created = std::fs::File::create(&file).map_err(internal)?;
                created.set_len(bytes).map_err(internal)?;
                let id = kit_core::hash::hash(file.to_string_lossy().as_bytes());
                let expires = now_ms() + 3_600_000;
                tickets.insert(
                    id,
                    Ticket {
                        pack,
                        bytes,
                        head,
                        file,
                        expires,
                    },
                );
                (id, expires)
            }
        };
        Ok(Response::new(generated::BeginUploadResponse {
            result: Some(BeginResult::Ticket(Box::new(generated::UploadTicket {
                id: Some(id.to_vec()),
                part_size: Some(PART_SIZE),
                expires_unix_ms: Some(expires),
                token: Some(id.to_vec()),
                ..Default::default()
            }))),
            ..Default::default()
        }))
    }

    async fn upload_part(
        &self,
        _ctx: RequestContext,
        mut requests: connectrpc::InboundStream<generated::UploadPartRequest>,
    ) -> ServiceResult<generated::UploadPartResponse> {
        let first = requests
            .next()
            .await
            .ok_or_else(|| ConnectError::invalid_argument("empty stream"))??;
        let Some(PartBody::Header(header)) = first.to_owned_message().msg else {
            return Err(ConnectError::invalid_argument("header first"));
        };
        let index = header.index.unwrap_or(0);
        self.0.counts.lock().unwrap().parts.push(index);
        let id = to_hash(header.ticket_token)?;
        let path = self
            .0
            .tickets
            .lock()
            .unwrap()
            .get(&id)
            .map(|ticket| ticket.file.clone())
            .ok_or_else(|| ConnectError::failed_precondition("unknown ticket"))?;
        let fail = {
            let mut modes = self.0.modes.lock().unwrap();
            let fail = modes.fail_part_once == Some(index);
            if fail {
                modes.fail_part_once = None;
            }
            fail
        };
        if fail {
            // Read the whole part first, so the client sees the refusal
            // rather than a reset stream.
            while let Some(message) = requests.next().await {
                message?;
            }
            return Err(ConnectError::permission_denied("injected part failure"));
        }
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .map_err(internal)?;
        file.seek(SeekFrom::Start(u64::from(index) * PART_SIZE))
            .map_err(internal)?;
        while let Some(message) = requests.next().await {
            if let Some(PartBody::Chunk(data)) = message?.to_owned_message().msg {
                file.write_all(&data).map_err(internal)?;
            }
        }
        Ok(Response::new(generated::UploadPartResponse {
            receipt: Some([&id[..4], &index.to_le_bytes()[..]].concat()),
            ..Default::default()
        }))
    }

    async fn complete_upload(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, generated::CompleteUploadRequest>,
    ) -> ServiceResult<generated::CompleteUploadResponse> {
        self.0.counts.lock().unwrap().completes += 1;
        let message = request.to_owned_message();
        let id = to_hash(message.ticket_token)?;
        let ticket = self
            .0
            .tickets
            .lock()
            .unwrap()
            .remove(&id)
            .ok_or_else(|| ConnectError::failed_precondition("unknown ticket"))?;
        let parts = ticket.bytes.div_ceil(PART_SIZE);
        if message.receipts.len() as u64 != parts {
            return Err(ConnectError::invalid_argument("receipt count"));
        }
        if hash_file(&ticket.file).map_err(internal)? != ticket.pack {
            return Err(ConnectError::invalid_argument("pack commitment"));
        }
        self.0.store(&ticket.file, ticket.bytes, ticket.pack)?;
        Ok(Response::new(generated::CompleteUploadResponse::default()))
    }

    async fn get_authority_generation(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, generated::GetAuthorityGenerationRequest>,
    ) -> ServiceResult<generated::GetAuthorityGenerationResponse> {
        Err(ConnectError::unimplemented("unused"))
    }

    async fn set_authority_generation(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, generated::SetAuthorityGenerationRequest>,
    ) -> ServiceResult<generated::SetAuthorityGenerationResponse> {
        Err(ConnectError::unimplemented("unused"))
    }

    async fn get_grant_epoch(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, generated::GetGrantEpochRequest>,
    ) -> ServiceResult<generated::GetGrantEpochResponse> {
        Err(ConnectError::unimplemented("unused"))
    }

    async fn set_grant_epoch(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, generated::SetGrantEpochRequest>,
    ) -> ServiceResult<generated::SetGrantEpochResponse> {
        Err(ConnectError::unimplemented("unused"))
    }

    async fn set_repo_visibility(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, generated::SetRepoVisibilityRequest>,
    ) -> ServiceResult<generated::SetRepoVisibilityResponse> {
        Err(ConnectError::unimplemented("unused"))
    }

    async fn issue_object_url(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, generated::IssueObjectUrlRequest>,
    ) -> ServiceResult<generated::IssueObjectUrlResponse> {
        Err(ConnectError::unimplemented("unused"))
    }
}

impl Shared {
    /// A fresh file for an upload.
    fn upload_path(&self) -> PathBuf {
        let mut next = self.next.lock().unwrap();
        *next += 1;
        self.dir.join(format!("upload-{next}"))
    }

    /// Store an uploaded file in the remote, then remove it.
    fn store(&self, path: &Path, len: u64, pack: Hash) -> Result<(), ConnectError> {
        let body = FileBody {
            path: path.to_owned(),
            len,
        };
        self.remote
            .upload_pack(&body, &PackKey::new(pack), None)
            .map_err(to_connect_error)?;
        std::fs::remove_file(path).map_err(internal)
    }

    /// Where the file remote keeps a pack.
    fn remote_path(&self, pack: &Hash) -> PathBuf {
        self.dir
            .join("remote")
            .join("packs")
            .join(kit_core::hash::to_hex(pack))
    }
}
