//! Downloading and applying the packs of a chain.
//!
//! Each pack is downloaded into an unnamed spool file in the store's spool
//! directory (`.kit/tmp/`), checked against its length, key and trailer as it
//! arrives, unpacked from that file into the object store by window,
//! signature-checked and recorded as applied, then dropped, in chain order.
//! No repository lock is held, and memory does not grow with the pack: a
//! chain of any size needs one spool on disk and one window in memory,
//! unless the transport itself buffers the body. The
//! caller holds a [`kit_core::store::PruneGuard`] for the whole fetch: the
//! objects of a pack applied here are unreferenced until the fetch publishes
//! its ref, and the guard keeps gc from deleting them.

use kit_core::protocol::{PackSink, TransportResult};
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
use kit_core::pack::{PackError, PackReader, PackSpool, VerifiedPack};
use kit_core::protocol::{PACK_BODY_LIMIT, PackKey};
use kit_core::store::ObjectStore;

use crate::SourceError;
use crate::applied_packs::AppliedPacks;
use crate::error::SyncError;
use crate::observer::{Observer, SyncEvent};
use crate::packmap::chain_label;
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
}

/// A local I/O error on the spool in `dir`, named by that directory.
pub(crate) fn spool_error(dir: &Path, kind: std::io::ErrorKind, detail: &str) -> SyncError {
    SyncError::Io(std::io::Error::new(
        kind,
        format!("pack spool in {}: {detail}", dir.display()),
    ))
}

/// Download one pack into a spool in `store`'s spool directory, checking its
/// length, its key and its trailer as it arrives. Only a pack that passes all
/// three comes back, as a [`VerifiedPack`]; the spool of any other is closed
/// and, being unnamed, leaves nothing on disk.
///
/// A local disk error on the spool (out of space, say) is
/// [`SyncError::Io`] whatever the transport made of it: it is checked
/// before the transport's error is mapped, and no transport retries it.
fn download_verified_pack(
    store: &ObjectStore,
    source: &dyn RemoteSource,
    head_ref: &str,
    key: &PackKey,
    observer: &dyn Observer<SyncEvent>,
) -> Result<VerifiedPack, SyncError> {
    let dir = store.spool_dir();
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
    spool.finish(key).map_err(|error| match error {
        // Bytes that are not the requested pack, whole or in part, are an
        // invalid response, as a digest mismatch always was.
        PackError::KeyMismatch | PackError::UnexpectedEof | PackError::PackfileTooShort => {
            SourceError::InvalidResponse.into()
        }
        PackError::Io(io) => spool_error(&dir, io.kind(), &io.to_string()),
        error => error.into(),
    })
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
) -> Result<(), SyncError> {
    for &pk in chain {
        if observer.cancelled() {
            return Err(SyncError::Interrupted);
        }
        let key = PackKey::from_hash(pk);
        if applied.contains(&key) {
            done.skipped += 1;
            continue;
        }
        let pack = download_verified_pack(store, source, head_ref, &key, observer)?;
        done.objects += apply_pack(
            store,
            observer,
            remote,
            &key,
            &pack,
            applied,
            require_signed,
        )?;
        done.packs += 1;
    }
    Ok(())
}

/// Unpack `pack`, already checked against `key`, check the signatures of the
/// commits, remixes and tags it stored, and record it as applied. Returns the
/// objects it wrote. A record that cannot be appended is reported and does
/// not fail the fetch: the objects landed, and the record is a cache.
fn apply_pack(
    store: &ObjectStore,
    observer: &dyn Observer<SyncEvent>,
    remote: &str,
    key: &PackKey,
    pack: &VerifiedPack,
    applied: &mut AppliedPacks,
    require_signed: bool,
) -> Result<usize, SyncError> {
    let report = PackReader::read_verified(pack, store)?;
    let unpacked = (report.raw_count + report.delta_count) as usize;
    if unpacked > 0 {
        observer.event(&SyncEvent::ObjectsUnpacked { count: unpacked });
    }
    verify_new_object_signatures(store, &report.signed, require_signed)?;
    if let Err(e) = applied.record_applied(key) {
        observer.event(&SyncEvent::AppliedPacksPersistFailed {
            remote: remote.to_owned(),
            error: e.to_string(),
        });
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
        let source = TransportSource::new(&tx);
        // `a` repeats, so its second turn is skipped as applied.
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
        download_verified_pack(
            &store,
            &ZeroPacks { len },
            "refs/heads/main",
            &PackKey::from_hash(h("zero pack")),
            &NoopObserver,
        )
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
}
