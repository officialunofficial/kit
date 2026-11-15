//! Packs stream through a Connect remote in bounded frames, both ways.
//!
//! A loopback Connect server over a file remote, with a loopback host for
//! its pack locations, checks the client's side: the frame and node bounds,
//! the location fallback, a full disk on each download path, and the three
//! upload paths, ticketless, single-part and multipart with resume.
//!
//! A full disk is injected with `kit_core::fault`, which fails every write
//! of a kind in the process, so the tests here run one at a time.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

#[path = "support/pack_server.rs"]
mod pack_server;
#[path = "support/streaming.rs"]
mod streaming;

use std::io::{ErrorKind, Read};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use kit_client::MemoryPartReceiptStore;
use kit_core::fault::{self, Site};
use kit_core::hash::{self, Hash};
use kit_core::layout::RepoLayout;
use kit_core::protocol::{PackBody, PackKey, Transport};
use kit_core::refs::{self, RefWriteCondition};
use kit_sync::{
    ClientSource, NoopObserver, RemoteSource, SourceError, SyncError, SyncOptions, WriteRecovery,
    fetch,
};
use pack_server::{Location, PART_SIZE, PackServer};
use streaming::{Dalek, MIB, client, http, noise, seed, spool_entries, target};

/// The tests share the injected failures, so each one holds this while it
/// runs.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A host that would retry every failure twice, and counts each time it
/// is asked.
#[derive(Default)]
struct RetryAll(AtomicUsize);

impl WriteRecovery for RetryAll {
    fn recover(&self, _: &str, _: &SourceError, attempt: u32) -> Result<bool, SourceError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(attempt < 3)
    }
}

/// Fetch `origin` from `server` into `work`, with `retry` as the host.
fn fetch_from(server: &PackServer, work: &Path, retry: &RetryAll) -> Result<(), SyncError> {
    let http = http();
    let signer = Dalek::new();
    let client = client(&http, &signer, &server.origin());
    let source = ClientSource::new(&client, &http).with_write_recovery(retry);
    fetch(
        work,
        &source,
        "origin",
        &SyncOptions::default(),
        &NoopObserver,
    )
    .map(drop)
}

fn fetched_main(work: &Path) -> Option<Hash> {
    refs::read_remote_ref(&RepoLayout::single(work), "origin", "main").unwrap()
}

/// A pack sent as one frame over 4 MiB is refused from the frame's
/// envelope; the same pack in the usual chunks fetches.
#[test]
fn a_download_frame_over_4_mib_is_refused() {
    let _guard = serial();
    let dir = tempfile::tempdir().unwrap();
    let server = PackServer::start(dir.path());
    let seeded = seed(server.remote(), 6 * MIB);
    assert!(seeded.pack_len > kit_client::DOWNLOAD_FRAME_MAX as u64);

    server.set_one_frame(true);
    let work = target(dir.path(), "refused");
    match fetch_from(&server, &work, &RetryAll::default()) {
        Err(SyncError::Source(SourceError::InvalidResponse)) => {}
        other => panic!("expected the frame to be refused, got {other:?}"),
    }
    assert_eq!(spool_entries(&work), 0);

    server.set_one_frame(false);
    let work = target(dir.path(), "chunked");
    fetch_from(&server, &work, &RetryAll::default()).unwrap();
    assert_eq!(fetched_main(&work), Some(seeded.tip));
}

/// A location whose body has the wrong bytes, or the wrong length, falls
/// back to the RPC, which streams the pack; the fetch verifies it. An
/// honest location is used without the RPC.
#[test]
fn a_location_with_the_wrong_key_or_length_falls_back_to_the_rpc() {
    let _guard = serial();
    let dir = tempfile::tempdir().unwrap();
    let server = PackServer::start(dir.path());
    let seeded = seed(server.remote(), 4 * MIB);

    for mode in [
        Location::WrongKey,
        Location::Short,
        Location::Long,
        Location::ShortUnsized,
        Location::LongUnsized,
        Location::Honest,
    ] {
        server.set_location(mode);
        server.reset_counts();
        let work = target(dir.path(), &format!("{mode:?}"));
        fetch_from(&server, &work, &RetryAll::default()).unwrap();
        assert_eq!(fetched_main(&work), Some(seeded.tip), "{mode:?}");
        let counts = server.counts();
        assert_eq!(counts.location_gets_of(&seeded.pack), 1, "{mode:?}");
        let expected = if mode == Location::Honest {
            vec![true]
        } else {
            vec![true, false]
        };
        assert_eq!(counts.downloads_of(&seeded.pack), expected, "{mode:?}");
        assert_eq!(spool_entries(&work), 0, "{mode:?}");
    }
}

/// A full disk under the fetch's spool ends it as `SyncError::Io` on each
/// download path: a location, a streamed answer to the location offer, and
/// the stream without an offer. The client neither falls back nor retries,
/// and the host is never asked to. The fetch after it, with room, works.
#[test]
fn a_full_disk_ends_each_download_path_as_an_io_error_without_fallback_or_retry() {
    let _guard = serial();
    let dir = tempfile::tempdir().unwrap();
    let server = PackServer::start(dir.path());
    let seeded = seed(server.remote(), 4 * MIB);

    for (mode, offered, location_gets) in [
        (Location::Honest, true, 1),
        (Location::Stream, true, 0),
        (Location::Off, false, 0),
    ] {
        server.set_location(mode);
        server.reset_counts();
        let work = target(dir.path(), &format!("{mode:?}"));
        let retry = RetryAll::default();
        let failed = {
            let _full = fault::fail_writes(Site::Spool);
            fetch_from(&server, &work, &retry)
        };
        match failed {
            Err(SyncError::Io(error)) => {
                assert_eq!(error.kind(), ErrorKind::StorageFull, "{mode:?}: {error}");
            }
            other => panic!("{mode:?}: expected SyncError::Io, got {other:?}"),
        }
        let counts = server.counts();
        assert_eq!(
            counts.downloads_of(&seeded.pack),
            vec![offered],
            "{mode:?}: one attempt, no fallback"
        );
        assert_eq!(
            counts.location_gets_of(&seeded.pack),
            location_gets,
            "{mode:?}"
        );
        assert_eq!(retry.0.load(Ordering::SeqCst), 0, "{mode:?}: no retry");
        assert_eq!(spool_entries(&work), 0, "{mode:?}");
        assert_eq!(fetched_main(&work), None, "{mode:?}");

        fetch_from(&server, &work, &RetryAll::default()).unwrap();
        assert_eq!(fetched_main(&work), Some(seeded.tip), "{mode:?}");
    }
}

/// A packmap node over 1 MiB is refused from its declared length, on the
/// stream and on the location path, before any byte of it is read.
#[test]
fn a_connect_node_over_1_mib_is_refused() {
    let _guard = serial();
    let dir = tempfile::tempdir().unwrap();
    let server = PackServer::start(dir.path());
    let node = vec![0u8; 2 * MIB];
    let node_key = hash::hash(&node);
    server
        .remote()
        .upload_blob(&node, &PackKey::new(node_key), None)
        .unwrap();
    drop(node);
    for name in ["refs/kit/packmap/main", "refs/heads/main"] {
        server
            .remote()
            .update_ref(name, RefWriteCondition::Missing, &node_key)
            .unwrap();
    }

    for mode in [Location::Off, Location::Honest] {
        server.set_location(mode);
        server.reset_counts();
        let work = target(dir.path(), &format!("{mode:?}"));
        match fetch_from(&server, &work, &RetryAll::default()) {
            Err(SyncError::PackChainInvalid {
                source: Some(SourceError::InvalidResponse),
                ..
            }) => {}
            other => panic!("{mode:?}: expected the node to be refused, got {other:?}"),
        }
        assert_eq!(
            server.counts().location_gets_of(&node_key),
            0,
            "{mode:?}: the location is refused from its declared size"
        );
    }
}

/// A pack body in memory that records each read: where it started and how
/// many bytes it returned.
struct CountingBody {
    bytes: Vec<u8>,
    reads: Mutex<Vec<(u64, u64)>>,
}

impl CountingBody {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            reads: Mutex::new(Vec::new()),
        }
    }

    fn key(&self) -> PackKey {
        PackKey::new(hash::hash(&self.bytes))
    }

    fn take_reads(&self) -> Vec<(u64, u64)> {
        std::mem::take(&mut self.reads.lock().unwrap())
    }
}

struct CountingReader<'a> {
    body: &'a CountingBody,
    read: usize,
    rest: &'a [u8],
}

impl Read for CountingReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.rest.read(buf)?;
        self.body.reads.lock().unwrap()[self.read].1 += n as u64;
        Ok(n)
    }
}

impl PackBody for CountingBody {
    fn len(&self) -> u64 {
        self.bytes.len() as u64
    }
    fn read_from(&self, offset: u64) -> std::io::Result<Box<dyn Read + Send + '_>> {
        let rest = self
            .bytes
            .get(usize::try_from(offset).unwrap()..)
            .ok_or(ErrorKind::UnexpectedEof)?;
        let mut reads = self.reads.lock().unwrap();
        reads.push((offset, 0));
        Ok(Box::new(CountingReader {
            body: self,
            read: reads.len() - 1,
            rest,
        }))
    }
}

/// Upload `body` for `main` through a fresh source that keeps its part
/// receipts in `receipts`.
fn upload(
    server: &PackServer,
    body: &CountingBody,
    receipts: &Arc<MemoryPartReceiptStore>,
) -> Result<(), SourceError> {
    let http = http();
    let signer = Dalek::new();
    let client = client(&http, &signer, &server.origin());
    let source = ClientSource::new(&client, &http).with_receipt_store(receipts.clone());
    source.upload_pack(body, &body.key(), "refs/heads/main")
}

/// A multipart upload that fails at its second part resumes, from a new
/// source, with the stored receipt of the first: it sends the missing
/// parts and reads only those, twice each, once for the commitment and
/// once to send.
#[test]
fn a_multipart_upload_resumes_from_stored_receipts_and_reads_only_missing_parts() {
    let _guard = serial();
    let dir = tempfile::tempdir().unwrap();
    let server = PackServer::start(dir.path());
    let len = 2 * PART_SIZE + 12_345;
    let body = CountingBody::new(noise(usize::try_from(len).unwrap(), 3));
    let receipts = Arc::new(MemoryPartReceiptStore::default());

    server.fail_part_once(1);
    upload(&server, &body, &receipts).unwrap_err();
    assert_eq!(server.counts().parts, vec![0, 1]);
    assert!(!server.remote().pack_exists(&body.key(), None).unwrap());

    server.reset_counts();
    body.take_reads();
    upload(&server, &body, &receipts).unwrap();
    let counts = server.counts();
    assert_eq!(counts.parts, vec![1, 2], "only the missing parts are sent");
    assert_eq!((counts.begins, counts.completes), (1, 1));
    let reads = body.take_reads();
    let offsets: Vec<u64> = reads.iter().map(|(offset, _)| *offset).collect();
    assert_eq!(
        offsets,
        vec![PART_SIZE, PART_SIZE, 2 * PART_SIZE, 2 * PART_SIZE],
        "each missing part is read twice, and no other"
    );
    assert_eq!(
        reads.iter().map(|(_, n)| n).sum::<u64>(),
        2 * (len - PART_SIZE)
    );
    assert_eq!(
        server
            .remote()
            .download_blob(&body.key(), None, u64::MAX)
            .unwrap(),
        body.bytes
    );
}

/// A pack under the ticket threshold uploads with no ticket, and one that
/// fits a part uploads on its ticket in one call. Each reads the body once.
#[test]
fn the_ticketless_and_single_part_paths_upload_with_one_read() {
    let _guard = serial();
    let dir = tempfile::tempdir().unwrap();
    let server = PackServer::start(dir.path());
    let receipts = Arc::new(MemoryPartReceiptStore::default());

    for (threshold, begins, seed) in [(64 << 20, 0, 1), (0, 1, 2)] {
        server.set_ticket_threshold(threshold);
        server.reset_counts();
        let body = CountingBody::new(noise(5 * MIB + 7, seed));
        upload(&server, &body, &receipts).unwrap();
        let counts = server.counts();
        assert_eq!(
            (counts.begins, counts.upload_packs, counts.parts.len()),
            (begins, 1, 0),
            "threshold {threshold}"
        );
        assert_eq!(
            body.take_reads(),
            vec![(0, body.len())],
            "threshold {threshold}"
        );
        assert_eq!(
            server
                .remote()
                .download_blob(&body.key(), None, u64::MAX)
                .unwrap(),
            body.bytes
        );
    }
}

/// The `Transport` adapter streams an unhinted download into the caller's
/// sink, and refuses a blob longer than the caller's bound as
/// `PayloadTooLarge`, from its declared length.
#[test]
fn the_transport_adapter_streams_unhinted_downloads_and_refuses_a_long_blob() {
    let _guard = serial();
    let dir = tempfile::tempdir().unwrap();
    let server = PackServer::start(dir.path());
    let seeded = seed(server.remote(), 2 * MIB);
    let transport =
        kit_transport_connect::ConnectTransport::connect_for_test(server.origin().parse().unwrap());
    let key = PackKey::new(seeded.pack);

    let mut sink = kit_core::protocol::MemorySink::new(seeded.pack_len);
    transport.download_pack(&key, None, &mut sink).unwrap();
    assert_eq!(
        kit_core::pack::pack_key(&sink.into_bytes().unwrap()),
        seeded.pack
    );
    assert_eq!(
        transport
            .download_blob(&key, None, seeded.pack_len)
            .unwrap()
            .len() as u64,
        seeded.pack_len
    );
    server.reset_counts();
    match transport.download_blob(&key, None, seeded.pack_len - 1) {
        Err(kit_core::protocol::TransportError::PayloadTooLarge(len)) => {
            assert_eq!(len as u64, seeded.pack_len);
        }
        other => panic!("expected PayloadTooLarge, got {other:?}"),
    }
}
