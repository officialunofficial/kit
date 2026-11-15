//! Downloading and applying the packs of a chain.
//!
//! Each pack is downloaded, checked against its key, unpacked into the object
//! store, signature-checked and recorded as applied, then dropped, in chain
//! order. Nothing is staged on disk and no repository lock is held, so a
//! chain of any size needs one pack of memory. The caller holds a
//! [`kit_core::store::PruneGuard`] for the whole fetch: the objects of a pack
//! applied here are unreferenced until the fetch publishes its ref, and the
//! guard keeps gc from deleting them.

use kit_core::hash::Hash;
use kit_core::pack::PackReader;
use kit_core::protocol::PackKey;
use kit_core::store::ObjectStore;

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

/// Download one pack and check its size and its bytes against `key`.
fn download_checked_pack(
    source: &dyn RemoteSource,
    head_ref: &str,
    key: &PackKey,
) -> Result<Vec<u8>, SyncError> {
    let pack = match source.download_pack_via_ref(key, head_ref) {
        Ok(b) => b,
        Err(error) if error.is_not_found() => {
            return Err(SyncError::AdvertisedPackMissing {
                branch: chain_label(head_ref).to_owned(),
                pack: key.to_hex(),
                source: error,
            });
        }
        Err(e) => return Err(e.into()),
    };
    if pack.len() as u64 > kit_core::protocol::PACK_BODY_LIMIT {
        return Err(crate::SourceError::PayloadTooLarge(pack.len()).into());
    }
    key.verify_bytes(&pack).map_err(crate::SourceError::from)?;
    Ok(pack)
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
/// One pack is held in memory at a time, and so are the ids of one pack's
/// stored objects: the full history's ids are never accumulated. The record
/// holds a pack only after its digest, unpack and signature checks succeed, so
/// a failed or killed fetch leaves the record naming only packs whose objects
/// are in the store.
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
        let pack = download_checked_pack(source, head_ref, &key)?;
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
/// objects it stored, and record it as applied. Returns the objects it wrote.
/// A record that cannot be appended is reported and does not fail the fetch:
/// the objects landed, and the record is a cache.
fn apply_pack(
    store: &ObjectStore,
    observer: &dyn Observer<SyncEvent>,
    remote: &str,
    key: &PackKey,
    pack: &[u8],
    applied: &mut AppliedPacks,
    require_signed: bool,
) -> Result<usize, SyncError> {
    let report = PackReader::read(pack, store)?;
    let unpacked = (report.raw_count + report.delta_count) as usize;
    if unpacked > 0 {
        observer.event(&SyncEvent::ObjectsUnpacked { count: unpacked });
    }
    verify_new_object_signatures(store, &report.stored, require_signed)?;
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
    use kit_core::protocol::Transport as _;
    use kit_core::transfer;
    use kit_transport_memory::MemoryTransport;

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
        tx.upload_pack(&bytes, &PackKey::from_hash(key)).unwrap();
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
        tx.upload_pack(&b, &PackKey::from_hash(key)).unwrap();
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
        tx.upload_blob(&b, &PackKey::from_hash(key)).unwrap();
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

    /// A source whose every pack is `len` zero bytes.
    struct ZeroPacks {
        len: usize,
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
        fn download_blob_via_ref(
            &self,
            _: &PackKey,
            _: &str,
        ) -> Result<Vec<u8>, crate::SourceError> {
            Err(crate::SourceError::ProtocolError)
        }
        fn download_pack_via_ref(
            &self,
            _: &PackKey,
            _: &str,
        ) -> Result<Vec<u8>, crate::SourceError> {
            Ok(vec![0; self.len])
        }
    }

    fn download_zero_pack(len: usize) -> Result<Vec<u8>, SyncError> {
        download_checked_pack(
            &ZeroPacks { len },
            "refs/heads/main",
            &PackKey::from_hash(h("zero pack")),
        )
    }

    fn body_limit() -> usize {
        kit_core::protocol::PACK_BODY_LIMIT_USIZE
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn a_pack_above_the_body_limit_is_refused_before_it_is_hashed() {
        let len = body_limit() + 1;
        let error = download_zero_pack(len).unwrap_err();
        assert!(
            matches!(
                error,
                SyncError::Source(crate::SourceError::PayloadTooLarge(n)) if n == len
            ),
            "{error:?}"
        );
    }

    /// A pack of exactly the limit is within it, so only its digest, not its
    /// size, can refuse it. Hashing it reads 4 GiB.
    #[test]
    #[ignore = "reads a 4 GiB buffer"]
    fn a_pack_of_exactly_the_body_limit_is_checked_against_its_key() {
        let error = download_zero_pack(body_limit()).unwrap_err();
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
            let events = Events::default();
            let unpacked =
                apply_pack(&store, &events, "origin", &key, &bytes, &mut applied, false).unwrap();
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
