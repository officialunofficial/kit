//! Downloading and applying the packs of a chain.
//!
//! Fetch authenticates one wire spool at a time, decodes into an unnamed
//! object spool, and checks signatures before it accepts those objects.
//! An accepted pack can contribute to several publication windows. A window
//! can also hold objects from other accepted packs. Fetch records a wire pack
//! after the window that finishes it is durable.
//! The caller holds the prune guard until the ref names the objects.
//! Downloads and window publication run outside the worktree lock.

use kit_core::protocol::{PackSink, ResumeOutcome, TransportResult};
use std::path::Path;
use std::time::{Duration, Instant};

/// Borrowed sink adapter. No allocation or lock on a write; callbacks occur at
/// most ten times a second, plus attempt boundaries and the final count.
struct ProgressSink<'a> {
    spool: &'a mut PackSpool,
    observer: Option<&'a (dyn Observer<SyncEvent> + Sync)>,
    bytes: u64,
    total: Option<u64>,
    last: Instant,
    /// How the transport answered each request to continue the body.
    resumes: Vec<ResumeOutcome>,
}

impl PackSink for ProgressSink<'_> {
    fn begin(&mut self, declared: Option<u64>) -> TransportResult<()> {
        PackSink::begin(self.spool, declared)?;
        self.bytes = 0;
        self.total = declared;
        self.last = Instant::now();
        self.emit();
        Ok(())
    }

    fn write(&mut self, bytes: &[u8]) -> TransportResult<()> {
        PackSink::write(self.spool, bytes)?;
        self.bytes = self.bytes.saturating_add(bytes.len() as u64);
        if self.last.elapsed() >= Duration::from_millis(100) {
            self.last = Instant::now();
            self.emit();
        }
        Ok(())
    }

    fn failed(&self) -> Option<std::io::ErrorKind> {
        self.spool.failed()
    }

    fn retained(&self) -> u64 {
        PackSink::retained(self.spool)
    }

    fn resume(&mut self, total: u64, offset: u64) -> TransportResult<()> {
        PackSink::resume(self.spool, total, offset)?;
        self.bytes = offset;
        self.total = Some(total);
        self.last = Instant::now();
        self.emit();
        Ok(())
    }

    fn note_resume(&mut self, outcome: ResumeOutcome) {
        self.resumes.push(outcome);
    }
}

impl ProgressSink<'_> {
    fn emit(&self) {
        if let Some(observer) = self.observer {
            observer.event(&SyncEvent::DownloadProgress {
                bytes: self.bytes,
                bytes_total: self.total,
            });
        }
    }
}

use kit_core::hash::Hash;
use kit_core::pack::{
    FetchDecodeBudget, ObjectSpool, PackError, PackReader, PackSpool, RetainedPacks, VerifiedPack,
};
use kit_core::protocol::{PACK_BODY_LIMIT, PackKey};
use kit_core::store::{ObjectStore, PruneGuard};

use crate::SourceError;
use crate::applied_packs::AppliedPacks;
use crate::error::SyncError;
use crate::fetch::DownloadSavings;
use crate::observer::{Observer, SyncEvent};
use crate::packmap::chain_label;
use crate::publication::{PendingView, Publication};
use crate::source::RemoteSource;
use crate::verify::verify_new_object_signatures;

/// What applying a chain did: the packs it downloaded and applied, the packs
/// it skipped because the record already holds them, and the objects the
/// applied packs wrote. It is filled in as the chain applies, so a caller
/// reads how far a failed chain got.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct ChainApplied {
    pub(crate) packs: usize,
    pub(crate) skipped: usize,
    pub(crate) objects: usize,
    pub(crate) savings: DownloadSavings,
}

/// A local I/O error on the spool in `dir`, named by that directory.
pub(crate) fn spool_error(dir: &Path, kind: std::io::ErrorKind, detail: &str) -> SyncError {
    SyncError::Io(std::io::Error::new(
        kind,
        format!("pack spool in {}: {detail}", dir.display()),
    ))
}

/// Where a verified pack came from.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Origin {
    Remote,
    /// The disk: kept after a failed apply, and verified again.
    Kept,
}

/// The verified pack `key`: one kept after a failed apply, when there is
/// one, or else a download into a spool in `store`'s spool directory,
/// checking its length, its key and its trailer as it arrives. Only a pack
/// that passes all three comes back, as a [`VerifiedPack`]; the spool of any
/// other is closed and, being unnamed, leaves nothing on disk.
///
/// A local disk error on the spool (out of space, say) is
/// [`SyncError::Io`] whatever the transport made of it: it is checked
/// before the transport's error is mapped, and no transport retries it.
///
/// What a resumed download or a kept pack saved goes to `savings` and the
/// observer.
fn verified_pack(
    store: &ObjectStore,
    source: &dyn RemoteSource,
    head_ref: &str,
    key: &PackKey,
    observer: &dyn Observer<SyncEvent>,
    savings: &mut DownloadSavings,
) -> Result<(VerifiedPack, Origin), SyncError> {
    let dir = store.spool_dir();
    if let Some(pack) = RetainedPacks::new(&dir).take(key) {
        savings.bytes_reused += pack.len();
        observer.event(&SyncEvent::PackReused { bytes: pack.len() });
        return Ok((pack, Origin::Kept));
    }
    let mut spool = PackSpool::create(&dir, PACK_BODY_LIMIT).map_err(|error| match error {
        PackError::Io(io) => spool_error(&dir, io.kind(), &io.to_string()),
        error => error.into(),
    })?;
    let mut sink = ProgressSink {
        spool: &mut spool,
        observer: observer.concurrent(),
        bytes: 0,
        total: None,
        last: Instant::now(),
        resumes: Vec::new(),
    };
    observer.event(&SyncEvent::DownloadProgress {
        bytes: 0,
        bytes_total: None,
    });
    let downloaded = source.download_pack(key, head_ref, &mut sink);
    observer.event(&SyncEvent::DownloadProgress {
        bytes: sink.bytes,
        bytes_total: sink.total,
    });
    for outcome in std::mem::take(&mut sink.resumes) {
        match outcome {
            ResumeOutcome::Resumed { bytes } => {
                savings.bytes_resumed += bytes;
                observer.event(&SyncEvent::DownloadResumed { bytes });
            }
            ResumeOutcome::Restarted { reason } => {
                savings.resumes_restarted += 1;
                observer.event(&SyncEvent::DownloadRestarted {
                    reason: reason.as_str(),
                });
            }
            _ => {}
        }
    }
    if let Some(kind) = spool.failed() {
        return Err(spool_error(&dir, kind, "write failed"));
    }
    match downloaded {
        Ok(()) => {}
        Err(error) if error.is_not_found() => {
            return Err(SyncError::AdvertisedPackMissing {
                branch: chain_label(head_ref).to_owned(),
                pack: key.to_hex(),
                source: error,
            });
        }
        Err(error) => return Err(error.into()),
    }
    let pack = spool.finish(key).map_err(|error| match error {
        // Bytes that are not the requested pack, whole or in part, are an
        // invalid response, as a digest mismatch always was.
        PackError::KeyMismatch | PackError::UnexpectedEof | PackError::PackfileTooShort => {
            SourceError::InvalidResponse.into()
        }
        PackError::Io(io) => spool_error(&dir, io.kind(), &io.to_string()),
        error => error.into(),
    })?;
    Ok((pack, Origin::Remote))
}

/// Download and apply every pack of `chain`, the chain of `head_ref`, oldest
/// first, into `store`,
/// recording each in `applied` as soon as its objects are committed and its
/// signatures checked. A pack already recorded is skipped. `done` counts the
/// work as it goes, including on failure.
///
/// The caller MUST hold a [`kit_core::store::PruneGuard`] across this call and
/// through the ref publish that makes the written objects reachable.
///
/// One pack is spooled at a time, and the ids of one pack's signed objects are
/// held: the full history's ids are never accumulated. The record holds a pack
/// only after its digest, unpack and signature checks succeed, so a failed or
/// killed fetch leaves the record naming only packs whose objects are in the
/// store.
#[allow(clippy::too_many_arguments)]
pub(crate) fn apply_pack_chain(
    store: &ObjectStore,
    source: &dyn RemoteSource,
    observer: &dyn Observer<SyncEvent>,
    remote: &str,
    head_ref: &str,
    chain: &[Hash],
    applied: &mut AppliedPacks,
    require_signed: bool,
    done: &mut ChainApplied,
    guard: &PruneGuard,
    decoded: &mut FetchDecodeBudget,
    validate: impl FnOnce(&PendingView<'_>) -> Result<(), SyncError>,
) -> Result<(), SyncError> {
    let retained = RetainedPacks::new(&store.spool_dir());
    let mut unsettled = Vec::new();
    let result = apply_chain(
        store,
        source,
        observer,
        remote,
        head_ref,
        chain,
        applied,
        require_signed,
        done,
        guard,
        decoded,
        &retained,
        &mut unsettled,
        validate,
    );
    settle(&mut unsettled, applied, &retained);
    if result.is_err() {
        // These packs verified and then did not reach the store, or reached
        // a window that did not land. Keep them for a retry. A pack that came
        // from the disk is still there.
        for held in &unsettled {
            if let (Origin::Remote, Some(pack)) = (held.origin, &held.pack) {
                let _ = retained.keep(&held.key, pack);
            }
        }
    }
    result
}

/// A verified pack that no window has made durable yet.
///
/// Only the newest few keep their pack open: more would hold a file each
/// until a window lands, and a retry cannot use more than the cache holds.
struct Unsettled {
    key: PackKey,
    pack: Option<VerifiedPack>,
    origin: Origin,
}

/// Close all but the newest [`RetainedPacks::LIMIT`] packs of `unsettled`.
fn release_older(unsettled: &mut [Unsettled]) {
    let older = unsettled.len().saturating_sub(RetainedPacks::LIMIT);
    for held in &mut unsettled[..older] {
        held.pack = None;
    }
}

/// Drop the packs `applied` records: their objects are in the store. A kept
/// pack that served leaves the disk.
fn settle(unsettled: &mut Vec<Unsettled>, applied: &AppliedPacks, retained: &RetainedPacks) {
    unsettled.retain(|held| {
        let recorded = applied.contains(&held.key);
        if recorded && held.origin == Origin::Kept {
            retained.discard(&held.key);
        }
        !recorded
    });
}

/// [`apply_pack_chain`]'s work. It leaves in `unsettled` every verified pack
/// whose objects may not be in the store.
#[allow(clippy::too_many_arguments)]
fn apply_chain(
    store: &ObjectStore,
    source: &dyn RemoteSource,
    observer: &dyn Observer<SyncEvent>,
    remote: &str,
    head_ref: &str,
    chain: &[Hash],
    applied: &mut AppliedPacks,
    require_signed: bool,
    done: &mut ChainApplied,
    guard: &PruneGuard,
    decoded: &mut FetchDecodeBudget,
    retained: &RetainedPacks,
    unsettled: &mut Vec<Unsettled>,
    validate: impl FnOnce(&PendingView<'_>) -> Result<(), SyncError>,
) -> Result<(), SyncError> {
    let mut publication = Publication::new(store, guard)?;
    let mut failure = None;
    for &pk in chain {
        if observer.cancelled() {
            failure = Some(SyncError::Interrupted);
            break;
        }
        let key = PackKey::from_hash(pk);
        if applied.contains(&key) || publication.completed(&key) {
            if applied.contains(&key) {
                // Applied meanwhile, so a copy kept for it is of no use.
                retained.discard(&key);
            }
            done.skipped += 1;
            continue;
        }
        let (pack, origin) =
            match verified_pack(store, source, head_ref, &key, observer, &mut done.savings) {
                Ok(found) => found,
                Err(error) => {
                    failure = Some(error);
                    break;
                }
            };
        unsettled.push(Unsettled {
            key,
            pack: Some(pack),
            origin,
        });
        let held = unsettled.last().expect("pushed a pack");
        let pack = held.pack.as_ref().expect("the newest pack is open");
        let staged = decode_pack(store, pack, &publication, require_signed, decoded);
        let (spool, unpacked) = match staged {
            Ok(decoded) => decoded,
            Err(error) => {
                failure = Some(error);
                break;
            }
        };
        let accepted = publication
            .accept(&spool, key, observer, remote, applied)
            .and_then(|()| publication.finish_if_done(observer, remote, applied));
        if let Err(error) = accepted {
            // The seal in flight still finishes, so its window is recorded.
            let _ = publication.finish(observer, remote, applied);
            return Err(error.into());
        }
        settle(unsettled, applied, retained);
        release_older(unsettled);
        if unpacked > 0 {
            observer.event(&SyncEvent::ObjectsUnpacked { count: unpacked });
        }
        done.objects += unpacked;
        done.packs += 1;
    }
    if let Some(error) = failure {
        // Keep the accepted prefix when a later download is interrupted or
        // refused. The failed pack never entered the publication window.
        publication.seal(observer, remote, applied)?;
        return Err(error);
    }
    // Every accepted pack must be in the store before the walk.
    publication.finish(observer, remote, applied)?;
    let checked = publication
        .view()
        .map_err(SyncError::from)
        .and_then(|view| validate(&view));
    publication.seal(observer, remote, applied)?;
    checked
}

fn decode_pack(
    store: &ObjectStore,
    pack: &VerifiedPack,
    publication: &Publication<'_>,
    require_signed: bool,
    decoded: &mut FetchDecodeBudget,
) -> Result<(ObjectSpool, usize), SyncError> {
    let spool = publication.decode_spool().map_err(|e| {
        let dir = store.spool_dir();
        spool_error(&dir, e.kind(), &e.to_string())
    })?;
    let report = PackReader::stage_verified(pack, store, &publication.pending(), &spool, decoded)?;
    verify_new_object_signatures(
        &PendingView::new(store, Some(&spool)),
        &report.signed,
        require_signed,
    )?;
    Ok((spool, (report.raw_count + report.delta_count) as usize))
}

#[cfg(test)]
fn apply_pack(
    store: &ObjectStore,
    observer: &dyn Observer<SyncEvent>,
    remote: &str,
    key: &PackKey,
    pack: &VerifiedPack,
    applied: &mut AppliedPacks,
    require_signed: bool,
) -> Result<usize, SyncError> {
    let guard = store.prune_guard()?;
    let mut publication = Publication::new(store, &guard)?;
    let (spool, unpacked) = decode_pack(
        store,
        pack,
        &publication,
        require_signed,
        &mut FetchDecodeBudget::new(),
    )?;
    publication.accept(&spool, *key, observer, remote, applied)?;
    publication.seal(observer, remote, applied)?;
    if unpacked > 0 {
        observer.event(&SyncEvent::ObjectsUnpacked { count: unpacked });
    }
    Ok(unpacked)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observer::NoopObserver;
    use crate::packmap::download_packlist_node;
    use crate::source::TransportSource;
    use kit_core::hash;
    use kit_core::layout::RepoLayout;
    use kit_core::object::Object;
    use kit_core::pack;
    use kit_core::protocol::{PackSink, SliceBody, Transport as _};
    use kit_core::transfer;
    use kit_transport_memory::MemoryTransport;

    #[test]
    fn download_events_are_throttled_and_retry_lengths_reset() {
        #[derive(Default)]
        struct Recorder(std::sync::Mutex<Vec<SyncEvent>>);
        impl Observer<SyncEvent> for Recorder {
            fn event(&self, event: &SyncEvent) {
                self.0.lock().unwrap().push(event.clone());
            }
            fn concurrent(&self) -> Option<&(dyn Observer<SyncEvent> + Sync)> {
                Some(self)
            }
        }
        let recorder = Recorder::default();
        let dir = tempfile::tempdir().unwrap();
        let mut spool = PackSpool::create(dir.path(), 1024).unwrap();
        let mut sink = ProgressSink {
            spool: &mut spool,
            observer: recorder.concurrent(),
            bytes: 0,
            total: None,
            last: Instant::now(),
            resumes: Vec::new(),
        };
        sink.begin(Some(128)).unwrap();
        sink.write(&[0; 64]).unwrap();
        assert_eq!(recorder.0.lock().unwrap().len(), 1);
        sink.last = Instant::now()
            .checked_sub(Duration::from_millis(101))
            .unwrap();
        sink.write(&[0; 64]).unwrap();
        assert_eq!(
            recorder.0.lock().unwrap().last(),
            Some(&SyncEvent::DownloadProgress {
                bytes: 128,
                bytes_total: Some(128)
            })
        );
        sink.begin(None).unwrap();
        assert_eq!(
            recorder.0.lock().unwrap().last(),
            Some(&SyncEvent::DownloadProgress {
                bytes: 0,
                bytes_total: None
            })
        );
    }

    fn h(seed: &str) -> Hash {
        hash::hash(seed.as_bytes())
    }

    /// A fresh store and an empty record in a temporary directory.
    fn store_and_record() -> (tempfile::TempDir, RepoLayout, ObjectStore, AppliedPacks) {
        let td = tempfile::tempdir().unwrap();
        std::fs::create_dir(td.path().join("repo")).unwrap();
        let layout = RepoLayout::single(td.path().join("repo"));
        let store = ObjectStore::init(&layout).unwrap();
        let applied = AppliedPacks::load(&layout, "origin").unwrap();
        (td, layout, store, applied)
    }

    fn blob(data: &[u8]) -> Object {
        Object::Blob(kit_core::object::Blob {
            data: data.to_vec(),
        })
    }

    /// A pack of `blobs`, uploaded to `tx`, and its key.
    fn upload_blob_pack(tx: &MemoryTransport, blobs: &[&[u8]]) -> Hash {
        let mut writer = pack::PackWriter::new();
        for data in blobs {
            let blob = blob(data);
            writer
                .push_raw(
                    blob.id().unwrap(),
                    &kit_core::serialize::serialize(&blob).unwrap(),
                )
                .unwrap();
        }
        let bytes = writer.finish().unwrap();
        let key = pack::pack_key(&bytes);
        tx.upload_pack(&SliceBody(&bytes), &PackKey::from_hash(key), None)
            .unwrap();
        key
    }

    fn apply(
        store: &ObjectStore,
        source: &dyn RemoteSource,
        chain: &[Hash],
        applied: &mut AppliedPacks,
        done: &mut ChainApplied,
    ) -> Result<(), SyncError> {
        apply_pack_chain(
            store,
            source,
            &NoopObserver,
            "origin",
            "refs/heads/main",
            chain,
            applied,
            false,
            done,
            &store.prune_guard()?,
            &mut FetchDecodeBudget::new(),
            |_| Ok(()),
        )
    }

    #[test]
    fn requested_pack_identity_rejects_valid_substitute_before_unpack() {
        use kit_core::pack::PackWriter;

        let objects = [blob(b"first"), blob(b"second")];
        let mut a = PackWriter::new();
        let mut b = PackWriter::new();
        for object in &objects {
            a.push_raw(
                object.id().unwrap(),
                &kit_core::serialize::serialize(object).unwrap(),
            )
            .unwrap();
        }
        for object in objects.iter().rev() {
            b.push_raw(
                object.id().unwrap(),
                &kit_core::serialize::serialize(object).unwrap(),
            )
            .unwrap();
        }
        let a = a.finish().unwrap();
        let b = b.finish().unwrap();
        let key = pack::pack_key(&a);
        assert_ne!(key, pack::pack_key(&b));
        let tx = MemoryTransport::new();
        tx.upload_pack(&SliceBody(&b), &PackKey::from_hash(key), None)
            .unwrap();
        let (_td, _layout, store, mut applied) = store_and_record();

        assert!(matches!(
            apply(
                &store,
                &TransportSource::new(&tx),
                &[key],
                &mut applied,
                &mut ChainApplied::default()
            ),
            Err(SyncError::Source(crate::SourceError::InvalidResponse))
        ));
        assert!(!applied.contains(&PackKey::from_hash(key)));
        for object in &objects {
            assert!(!store.contains(&object.id().unwrap()));
        }
    }

    #[test]
    fn requested_packlist_identity_rejects_substitute() {
        let tx = MemoryTransport::new();
        let a = transfer::encode_packlist(None, &[h("pack-a")]).unwrap();
        let b = transfer::encode_packlist(None, &[h("pack-b")]).unwrap();
        let key = hash::hash(&a);
        tx.upload_blob(&b, &PackKey::from_hash(key), None).unwrap();
        assert!(matches!(
            download_packlist_node(&TransportSource::new(&tx), key, "refs/heads/main"),
            Err(SyncError::Source(crate::SourceError::InvalidResponse))
        ));
    }

    #[test]
    fn apply_pack_chain_records_each_pack_and_skips_applied_keys() {
        let tx = MemoryTransport::new();
        let a = upload_blob_pack(&tx, &[b"first"]);
        let b = upload_blob_pack(&tx, &[b"second"]);
        let c = upload_blob_pack(&tx, &[b"third"]);
        let (_td, layout, store, mut applied) = store_and_record();
        store.try_activate_local_packs().unwrap();
        let source = TransportSource::new(&tx);
        // The second listing of `a` arrives before its window seals.
        let chain = [a, a, b, c];
        let mut done = ChainApplied::default();
        apply(&store, &source, &chain, &mut applied, &mut done).unwrap();

        assert_eq!((done.packs, done.skipped, done.objects), (3, 1, 3));
        for key in [a, b, c] {
            assert!(applied.contains(&PackKey::from_hash(key)));
        }
        for data in [&b"first"[..], b"second", b"third"] {
            assert!(store.contains(&blob(data).id().unwrap()));
        }
        // The lines are on disk already, without a persist.
        let reloaded = AppliedPacks::load(&layout, "origin").unwrap();
        for key in [a, b, c] {
            assert!(reloaded.contains(&PackKey::from_hash(key)));
        }
    }

    #[test]
    fn a_failed_pack_leaves_the_earlier_packs_recorded_and_itself_not() {
        let tx = MemoryTransport::new();
        let a = upload_blob_pack(&tx, &[b"first"]);
        let b = upload_blob_pack(&tx, &[b"second"]);
        let missing = h("not uploaded");
        let (_td, layout, store, mut applied) = store_and_record();
        let mut done = ChainApplied::default();
        let error = apply(
            &store,
            &TransportSource::new(&tx),
            &[a, b, missing],
            &mut applied,
            &mut done,
        )
        .unwrap_err();
        assert!(matches!(error, SyncError::AdvertisedPackMissing { .. }));
        assert_eq!(done.packs, 2);
        let reloaded = AppliedPacks::load(&layout, "origin").unwrap();
        assert!(reloaded.contains(&PackKey::from_hash(a)));
        assert!(reloaded.contains(&PackKey::from_hash(b)));
        assert!(!reloaded.contains(&PackKey::from_hash(missing)));
    }

    #[test]
    fn a_chain_of_honest_packs_needs_nothing_but_their_own_length_in_the_fetch_budget() {
        // Two packs, each holding one compressible 4 MiB blob, which the pack
        // stores compressed and the reader counts as 4 MiB decoded. Each
        // pack's length brings more than that to a budget that starts empty.
        let tx = MemoryTransport::new();
        let (first, second) = (vec![b'a'; 4 << 20], vec![b'b'; 4 << 20]);
        let a = upload_blob_pack(&tx, &[&first]);
        let b = upload_blob_pack(&tx, &[&second]);
        let (_td, _layout, store, mut applied) = store_and_record();
        store.try_activate_local_packs().unwrap();
        let mut done = ChainApplied::default();
        apply_pack_chain(
            &store,
            &TransportSource::new(&tx),
            &NoopObserver,
            "origin",
            "refs/heads/main",
            &[a, b],
            &mut applied,
            false,
            &mut done,
            &store.prune_guard().unwrap(),
            &mut FetchDecodeBudget::with_limit(0),
            |_| Ok(()),
        )
        .unwrap();
        assert_eq!(done.packs, 2);
    }

    #[test]
    fn an_interrupted_final_check_keeps_the_accepted_window() {
        let tx = MemoryTransport::new();
        let key = upload_blob_pack(&tx, &[b"kept"]);
        let (_td, layout, store, mut applied) = store_and_record();
        store.try_activate_local_packs().unwrap();
        let result = apply_pack_chain(
            &store,
            &TransportSource::new(&tx),
            &NoopObserver,
            "origin",
            "refs/heads/main",
            &[key],
            &mut applied,
            true,
            &mut ChainApplied::default(),
            &store.prune_guard().unwrap(),
            &mut FetchDecodeBudget::new(),
            |view| {
                assert!(view.contains(&blob(b"kept").id().unwrap()));
                assert!(!store.contains(&blob(b"kept").id().unwrap()));
                Err(SyncError::Interrupted)
            },
        );
        assert!(matches!(result, Err(SyncError::Interrupted)));
        assert!(store.contains(&blob(b"kept").id().unwrap()));
        assert!(
            AppliedPacks::load(&layout, "origin")
                .unwrap()
                .contains(&PackKey::from_hash(key))
        );
    }

    /// A source whose every pack is `len` zero bytes, declared up front.
    struct ZeroPacks {
        len: u64,
    }

    impl RemoteSource for ZeroPacks {
        fn list_branches(&self) -> Result<Vec<kit_core::refs::Ref>, crate::SourceError> {
            Ok(Vec::new())
        }
        fn list_refs(&self, _: &str) -> Result<Vec<kit_core::refs::Ref>, crate::SourceError> {
            Ok(Vec::new())
        }
        fn read_ref(&self, _: &str) -> Result<Option<Hash>, crate::SourceError> {
            Ok(None)
        }
        fn download_blob(&self, _: &PackKey, _: &str) -> Result<Vec<u8>, crate::SourceError> {
            Err(crate::SourceError::ProtocolError)
        }
        fn download_pack(
            &self,
            _: &PackKey,
            _: &str,
            sink: &mut dyn PackSink,
        ) -> Result<(), crate::SourceError> {
            sink.begin(Some(self.len))?;
            let zeros = vec![0u8; 1 << 20];
            let mut left = self.len;
            while left > 0 {
                let n = left.min(zeros.len() as u64);
                sink.write(&zeros[..usize::try_from(n).unwrap()])?;
                left -= n;
            }
            Ok(())
        }
    }

    fn download_zero_pack(len: u64) -> Result<VerifiedPack, SyncError> {
        let (_td, _layout, store, _applied) = store_and_record();
        verified_pack(
            &store,
            &ZeroPacks { len },
            "refs/heads/main",
            &PackKey::from_hash(h("zero pack")),
            &NoopObserver,
            &mut DownloadSavings::default(),
        )
        .map(|(pack, _)| pack)
    }

    #[test]
    fn a_pack_above_the_body_limit_is_refused_before_any_byte() {
        let error = download_zero_pack(PACK_BODY_LIMIT + 1).unwrap_err();
        assert!(
            matches!(
                error,
                SyncError::Source(crate::SourceError::PayloadTooLarge(_))
            ),
            "{error:?}"
        );
    }

    /// A pack of exactly the limit is within it, so only its digest, not its
    /// size, can refuse it. It spools 4 GiB.
    #[test]
    #[ignore = "spools 4 GiB"]
    fn a_pack_of_exactly_the_body_limit_is_checked_against_its_key() {
        let error = download_zero_pack(PACK_BODY_LIMIT).unwrap_err();
        // The size is within the limit, so what refuses it is its digest.
        assert!(
            matches!(
                error,
                SyncError::Source(crate::SourceError::InvalidResponse)
            ),
            "{error:?}"
        );
    }

    /// Records the events of a fetch.
    #[derive(Default)]
    struct Events(std::sync::Mutex<Vec<SyncEvent>>);

    impl Observer<SyncEvent> for Events {
        fn event(&self, event: &SyncEvent) {
            self.0.lock().unwrap().push(event.clone());
        }
    }

    /// The signature check after an unpack reads the commits the pack stored
    /// and none of its blobs.
    #[test]
    fn the_signature_check_of_a_pack_of_large_blobs_reads_no_blob() {
        let (_td, _layout, store, mut applied) = store_and_record();
        let kp = kit_core::sign::KeyPair::generate().unwrap();
        let mut writer = pack::PackWriter::new();
        let mut blobs = Vec::new();
        for i in 0..4u8 {
            let blob = blob(&vec![i; 4 << 20]);
            let bytes = kit_core::serialize::serialize(&blob).unwrap();
            blobs.push(blob.id().unwrap());
            writer.push_raw(blob.id().unwrap(), &bytes).unwrap();
        }
        let mut commits = Vec::new();
        for i in 0..3u64 {
            let mut commit = kit_core::object::Commit::new_unannotated(
                blobs[0],
                Vec::new(),
                kit_core::object::Identity::ed25519(kp.public.0),
                kp.public.0,
                format!("large blobs #{i}").into_bytes(),
                1_700_000_000 + i,
                [0u8; 64],
            );
            commit.signature = kit_core::sign::sign_commit(&commit, &kp).unwrap().0;
            let commit = Object::Commit(commit);
            let bytes = kit_core::serialize::serialize(&commit).unwrap();
            commits.push(commit.id().unwrap());
            writer.push_raw(commit.id().unwrap(), &bytes).unwrap();
        }
        let bytes = writer.finish().unwrap();
        let key = PackKey::from_hash(pack::pack_key(&bytes));
        let mut spool = PackSpool::create(&store.spool_dir(), PACK_BODY_LIMIT).unwrap();
        kit_core::protocol::write_body(&mut spool, &bytes).unwrap();
        let verified = spool.finish(&key).unwrap();

        let unpacked = apply_pack(
            &store,
            &NoopObserver,
            "origin",
            &key,
            &verified,
            &mut applied,
            true,
        )
        .unwrap();

        assert_eq!(unpacked, 7);
        assert_eq!(crate::verify::test_counts::reads_of(&blobs), 0);
        assert_eq!(crate::verify::test_counts::reads_of(&commits), 3);
    }

    #[test]
    fn an_empty_pack_reports_no_unpacked_objects_and_a_full_one_reports_its_count() {
        let (_td, _layout, store, mut applied) = store_and_record();
        for (blobs, expected) in [(Vec::new(), None), (vec![&b"one"[..], b"two"], Some(2))] {
            let mut writer = pack::PackWriter::new();
            for data in &blobs {
                let blob = blob(data);
                writer
                    .push_raw(
                        blob.id().unwrap(),
                        &kit_core::serialize::serialize(&blob).unwrap(),
                    )
                    .unwrap();
            }
            let bytes = writer.finish().unwrap();
            let key = PackKey::from_hash(pack::pack_key(&bytes));
            let mut spool = PackSpool::create(&store.spool_dir(), PACK_BODY_LIMIT).unwrap();
            kit_core::protocol::write_body(&mut spool, &bytes).unwrap();
            let verified = spool.finish(&key).unwrap();
            let events = Events::default();
            let unpacked = apply_pack(
                &store,
                &events,
                "origin",
                &key,
                &verified,
                &mut applied,
                false,
            )
            .unwrap();
            assert_eq!(unpacked, expected.unwrap_or(0));
            let counts: Vec<usize> = events
                .0
                .lock()
                .unwrap()
                .iter()
                .filter_map(|event| match event {
                    SyncEvent::ObjectsUnpacked { count } => Some(*count),
                    _ => None,
                })
                .collect();
            assert_eq!(counts, expected.into_iter().collect::<Vec<_>>());
        }
    }

    /// A source that delivers a pack in two parts, as a transport that
    /// resumes does, and says how: it asks the sink what it holds, continues
    /// or begins again, and reports the outcome.
    struct Interrupted {
        bytes: Vec<u8>,
        cut: usize,
        restart: Option<kit_core::protocol::RestartReason>,
    }

    impl RemoteSource for Interrupted {
        fn list_branches(&self) -> Result<Vec<kit_core::refs::Ref>, crate::SourceError> {
            Ok(Vec::new())
        }
        fn list_refs(&self, _: &str) -> Result<Vec<kit_core::refs::Ref>, crate::SourceError> {
            Ok(Vec::new())
        }
        fn read_ref(&self, _: &str) -> Result<Option<Hash>, crate::SourceError> {
            Ok(None)
        }
        fn download_blob(&self, _: &PackKey, _: &str) -> Result<Vec<u8>, crate::SourceError> {
            Err(crate::SourceError::ProtocolError)
        }
        fn download_pack(
            &self,
            _: &PackKey,
            _: &str,
            sink: &mut dyn PackSink,
        ) -> Result<(), crate::SourceError> {
            use kit_core::protocol::ResumeOutcome;
            let total = self.bytes.len() as u64;
            sink.begin(Some(total))?;
            sink.write(&self.bytes[..self.cut])?;
            assert_eq!(sink.retained(), self.cut as u64);
            match self.restart {
                None => {
                    sink.resume(total, self.cut as u64)?;
                    sink.note_resume(ResumeOutcome::Resumed {
                        bytes: self.cut as u64,
                    });
                    sink.write(&self.bytes[self.cut..])?;
                }
                Some(reason) => {
                    sink.note_resume(ResumeOutcome::Restarted { reason });
                    sink.begin(Some(total))?;
                    sink.write(&self.bytes)?;
                }
            }
            Ok(())
        }
    }

    fn two_blob_pack() -> (Vec<u8>, PackKey) {
        let mut writer = pack::PackWriter::new();
        for data in [&b"first"[..], b"second"] {
            let blob = blob(data);
            writer
                .push_raw(
                    blob.id().unwrap(),
                    &kit_core::serialize::serialize(&blob).unwrap(),
                )
                .unwrap();
        }
        let bytes = writer.finish().unwrap();
        let key = PackKey::from_hash(pack::pack_key(&bytes));
        (bytes, key)
    }

    #[test]
    fn a_resumed_download_counts_the_bytes_it_did_not_fetch_again() {
        let (_td, _layout, store, _applied) = store_and_record();
        let (bytes, key) = two_blob_pack();
        let source = Interrupted {
            bytes,
            cut: 30,
            restart: None,
        };
        let events = Events::default();
        let mut savings = DownloadSavings::default();

        let (pack, origin) = verified_pack(
            &store,
            &source,
            "refs/heads/main",
            &key,
            &events,
            &mut savings,
        )
        .unwrap();

        assert!(origin == Origin::Remote);
        assert_eq!(pack.len(), source.bytes.len() as u64);
        assert_eq!(savings.bytes_resumed, 30);
        assert_eq!(savings.resumes_restarted, 0);
        assert_eq!(savings.bytes_reused, 0);
        let events = events.0.lock().unwrap();
        assert!(events.contains(&SyncEvent::DownloadResumed { bytes: 30 }));
        // The progress shows the whole pack after the resume.
        assert!(events.contains(&SyncEvent::DownloadProgress {
            bytes: source.bytes.len() as u64,
            bytes_total: Some(source.bytes.len() as u64)
        }));
    }

    #[test]
    fn a_restarted_download_is_counted_with_its_reason() {
        use kit_core::protocol::RestartReason;
        let (_td, _layout, store, _applied) = store_and_record();
        let (bytes, key) = two_blob_pack();
        for (reason, name) in [
            (RestartReason::Status, "status"),
            (RestartReason::Validator, "validator"),
            (RestartReason::Range, "range"),
        ] {
            let source = Interrupted {
                bytes: bytes.clone(),
                cut: 30,
                restart: Some(reason),
            };
            let events = Events::default();
            let mut savings = DownloadSavings::default();
            verified_pack(
                &store,
                &source,
                "refs/heads/main",
                &key,
                &events,
                &mut savings,
            )
            .unwrap();
            assert_eq!(savings.bytes_resumed, 0);
            assert_eq!(savings.resumes_restarted, 1);
            assert!(
                events
                    .0
                    .lock()
                    .unwrap()
                    .contains(&SyncEvent::DownloadRestarted { reason: name })
            );
        }
    }

    #[test]
    fn a_resumed_body_that_is_not_the_pack_is_an_invalid_response() {
        let (_td, _layout, store, _applied) = store_and_record();
        let (mut bytes, key) = two_blob_pack();
        let wrong = bytes.len() / 2;
        bytes[wrong] ^= 1;
        let source = Interrupted {
            bytes,
            cut: 30,
            restart: None,
        };
        let error = verified_pack(
            &store,
            &source,
            "refs/heads/main",
            &key,
            &NoopObserver,
            &mut DownloadSavings::default(),
        )
        .map(drop)
        .unwrap_err();
        assert!(matches!(
            error,
            SyncError::Source(crate::SourceError::InvalidResponse)
        ));
    }

    #[test]
    fn a_kept_pack_comes_from_disk_and_is_counted() {
        let (_td, _layout, store, _applied) = store_and_record();
        let (bytes, key) = two_blob_pack();
        let mut spool = PackSpool::create(&store.spool_dir(), PACK_BODY_LIMIT).unwrap();
        kit_core::protocol::write_body(&mut spool, &bytes).unwrap();
        let kept = spool.finish(&key).unwrap();
        RetainedPacks::new(&store.spool_dir())
            .keep(&key, &kept)
            .unwrap();
        let events = Events::default();
        let mut savings = DownloadSavings::default();

        // A source that fails the test if it is asked for the pack.
        let (pack, origin) = verified_pack(
            &store,
            &ZeroPacks { len: u64::MAX },
            "refs/heads/main",
            &key,
            &events,
            &mut savings,
        )
        .unwrap();

        assert!(origin == Origin::Kept);
        assert_eq!(pack.len(), bytes.len() as u64);
        assert_eq!(savings.bytes_reused, bytes.len() as u64);
        assert_eq!(
            *events.0.lock().unwrap(),
            [SyncEvent::PackReused {
                bytes: bytes.len() as u64
            }]
        );
    }

    fn unsettled_pack(store: &ObjectStore, origin: Origin) -> Unsettled {
        let (bytes, key) = two_blob_pack();
        let mut spool = PackSpool::create(&store.spool_dir(), PACK_BODY_LIMIT).unwrap();
        kit_core::protocol::write_body(&mut spool, &bytes).unwrap();
        Unsettled {
            key,
            pack: Some(spool.finish(&key).unwrap()),
            origin,
        }
    }

    #[test]
    fn only_the_newest_unsettled_packs_stay_open() {
        let (_td, _layout, store, _applied) = store_and_record();
        let mut unsettled: Vec<Unsettled> = (0..RetainedPacks::LIMIT + 3)
            .map(|_| unsettled_pack(&store, Origin::Remote))
            .collect();
        release_older(&mut unsettled);
        let open: Vec<bool> = unsettled.iter().map(|held| held.pack.is_some()).collect();
        let mut expected = vec![false; 3];
        expected.extend(vec![true; RetainedPacks::LIMIT]);
        assert_eq!(open, expected);
        // Releasing again, or with few packs, changes nothing.
        release_older(&mut unsettled);
        assert_eq!(
            unsettled.iter().filter(|held| held.pack.is_some()).count(),
            RetainedPacks::LIMIT
        );
        unsettled.truncate(2);
        release_older(&mut unsettled);
        assert_eq!(
            unsettled.iter().filter(|held| held.pack.is_some()).count(),
            0
        );
    }

    #[test]
    fn settling_drops_recorded_packs_and_removes_a_kept_one_from_disk() {
        let (_td, _layout, store, mut applied) = store_and_record();
        let retained = RetainedPacks::new(&store.spool_dir());
        let mut remote = unsettled_pack(&store, Origin::Remote);
        remote.key = PackKey::from_hash(hash::hash(b"another pack"));
        let kept = unsettled_pack(&store, Origin::Kept);
        let kept_key = kept.key;
        retained
            .keep(&kept_key, kept.pack.as_ref().unwrap())
            .unwrap();
        applied.record_applied(&kept_key).unwrap();
        let mut unsettled = vec![remote, kept];

        // Only the kept pack is recorded: it leaves the list and the disk.
        settle(&mut unsettled, &applied, &retained);

        assert_eq!(unsettled.len(), 1);
        assert!(unsettled[0].origin == Origin::Remote);
        assert!(retained.take(&kept_key).is_none(), "the kept copy is gone");
    }

    /// A blob of 200 kB that no other of the chain equals.
    fn large_blob(n: u16) -> Vec<u8> {
        let mut data = vec![0x5a; 200_000];
        data[..2].copy_from_slice(&n.to_le_bytes());
        data
    }

    /// Two wire packs of 40 MB: the second fills the first window, which
    /// seals in the background, and leaves its tail in the next window.
    fn two_large_packs(tx: &MemoryTransport) -> ([Hash; 2], Vec<Vec<u8>>) {
        let blobs: Vec<_> = (0..400).map(large_blob).collect();
        let keys = [0, 1].map(|n| {
            let refs: Vec<&[u8]> = blobs[n * 200..(n + 1) * 200]
                .iter()
                .map(Vec::as_slice)
                .collect();
            upload_blob_pack(tx, &refs)
        });
        (keys, blobs)
    }

    #[test]
    fn the_closure_walk_runs_after_the_window_in_flight_is_in_the_store() {
        let tx = MemoryTransport::new();
        let (keys, blobs) = two_large_packs(&tx);
        let (_td, layout, store, mut applied) = store_and_record();
        store.try_activate_local_packs().unwrap();
        let first = blob(&blobs[0]).id().unwrap();
        let last = blob(&blobs[399]).id().unwrap();
        apply_pack_chain(
            &store,
            &TransportSource::new(&tx),
            &NoopObserver,
            "origin",
            "refs/heads/main",
            &keys,
            &mut applied,
            false,
            &mut ChainApplied::default(),
            &store.prune_guard().unwrap(),
            &mut FetchDecodeBudget::new(),
            |view| {
                // The first window is sealed and recorded, the second is open.
                assert!(store.contains(&first));
                assert!(view.contains(&first));
                assert!(view.contains(&last));
                assert!(!store.contains(&last));
                Ok(())
            },
        )
        .unwrap();
        let reloaded = AppliedPacks::load(&layout, "origin").unwrap();
        for key in keys {
            assert!(reloaded.contains(&PackKey::from_hash(key)));
        }
        for data in &blobs {
            assert!(store.contains(&blob(data).id().unwrap()));
        }
    }

    #[test]
    fn a_failure_after_a_window_began_sealing_keeps_both_windows() {
        let tx = MemoryTransport::new();
        let (keys, blobs) = two_large_packs(&tx);
        let (_td, layout, store, mut applied) = store_and_record();
        store.try_activate_local_packs().unwrap();
        let error = apply(
            &store,
            &TransportSource::new(&tx),
            &[keys[0], keys[1], h("not uploaded")],
            &mut applied,
            &mut ChainApplied::default(),
        )
        .unwrap_err();
        assert!(matches!(error, SyncError::AdvertisedPackMissing { .. }));
        let reloaded = AppliedPacks::load(&layout, "origin").unwrap();
        for key in keys {
            assert!(reloaded.contains(&PackKey::from_hash(key)));
        }
        for data in &blobs {
            assert!(store.contains(&blob(data).id().unwrap()));
        }
    }
}
