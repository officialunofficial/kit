#![allow(clippy::unwrap_used)]
include!("support/attestation_fetch.rs");

#[test]
fn memory_clone_fetch_pull_keep_attestations_outside_objects() {
    attestation_fetch::roundtrip(&kit_transport_memory::MemoryTransport::new());
}
#[test]
fn file_clone_fetch_pull_keep_attestations_outside_objects() {
    let dir = tempfile::tempdir().unwrap();
    attestation_fetch::roundtrip(&kit_transport_file::FileTransport::new(dir.path()));
}

#[test]
fn snapshot_precedes_listing_and_a_late_ci_envelope_waits_for_its_code() {
    use kit_core::{
        hash::Hash,
        protocol::{PackKey, PackSink},
        refs::Ref,
    };
    use kit_sync::{RemoteSource, SourceError};
    use std::cell::Cell;
    struct Racing<'a> {
        tx: &'a kit_transport_memory::MemoryTransport,
        raced: Cell<bool>,
        late: Cell<Option<Hash>>,
    }
    impl RemoteSource for Racing<'_> {
        fn supports_attestations(&self) -> bool {
            true
        }
        fn list_branches(&self) -> Result<Vec<Ref>, SourceError> {
            let listing = kit_sync::TransportSource::new(self.tx).list_branches()?;
            if !self.raced.replace(true) {
                let (tip, _) = attestation_fetch::code(self.tx);
                self.late.set(Some(tip));
                let env = attestation_fetch::envelope(tip);
                attestation_fetch::append(
                    self.tx,
                    &kit_attest::pack::build(&[&env], 4096).unwrap(),
                );
            }
            Ok(listing)
        }
        fn list_refs(&self, prefix: &str) -> Result<Vec<Ref>, SourceError> {
            kit_sync::TransportSource::new(self.tx).list_refs(prefix)
        }
        fn read_ref(&self, name: &str) -> Result<Option<Hash>, SourceError> {
            kit_sync::TransportSource::new(self.tx).read_ref(name)
        }
        fn download_blob(&self, key: &PackKey, name: &str) -> Result<Vec<u8>, SourceError> {
            kit_sync::TransportSource::new(self.tx).download_blob(key, name)
        }
        fn download_pack(
            &self,
            key: &PackKey,
            name: &str,
            sink: &mut dyn PackSink,
        ) -> Result<(), SourceError> {
            kit_sync::TransportSource::new(self.tx).download_pack(key, name, sink)
        }
    }
    let tx = kit_transport_memory::MemoryTransport::new();
    attestation_fetch::code(&tx);
    let source = Racing {
        tx: &tx,
        raced: Cell::new(false),
        late: Cell::new(None),
    };
    let temp = tempfile::tempdir().unwrap();
    let remote = kit_sync::CloneRemote {
        name: "origin".into(),
        url: "kit+memory://test".into(),
        kind: "memory".into(),
    };
    kit_sync::init_clone_dir(temp.path(), &remote).unwrap();
    let options = kit_sync::SyncOptions::default();
    let report = kit_sync::fetch(
        temp.path(),
        &source,
        "origin",
        &options,
        &kit_sync::NoopObserver,
    )
    .unwrap();
    assert_eq!(report.attestations_dropped, 0);
    assert_eq!(report.attestations_stored, 0);
    let report = kit_sync::fetch(
        temp.path(),
        &source,
        "origin",
        &options,
        &kit_sync::NoopObserver,
    )
    .unwrap();
    assert_eq!(report.attestations_stored, 1);
    assert_eq!(report.attestations_dropped, 0);
}

#[test]
fn off_switch_never_reads_a_hostile_attestation_log_and_reenable_fetches_it() {
    use kit_core::{
        protocol::Transport,
        refs::{ATTESTMAP_REF, RefWriteCondition},
    };
    let tx = kit_transport_memory::MemoryTransport::new();
    let (tip, _) = attestation_fetch::code(&tx);
    let envelope = attestation_fetch::envelope(tip);
    attestation_fetch::append(&tx, &kit_attest::pack::build(&[&envelope], 4096).unwrap());
    let temp = tempfile::tempdir().unwrap();
    let remote = kit_sync::CloneRemote {
        name: "origin".into(),
        url: "kit+memory://test".into(),
        kind: "memory".into(),
    };
    kit_sync::init_clone_dir(temp.path(), &remote).unwrap();
    let source = kit_sync::TransportSource::new(&tx);
    let head = tx.read_ref(ATTESTMAP_REF).unwrap().unwrap();
    tx.update_ref(ATTESTMAP_REF, RefWriteCondition::Any, &[255; 32])
        .unwrap();
    let mut options = kit_sync::SyncOptions::default();
    options.attestations = false;
    let report = kit_sync::fetch(
        temp.path(),
        &source,
        "origin",
        &options,
        &kit_sync::NoopObserver,
    )
    .unwrap();
    assert!(report.attestation_warnings.is_empty());
    tx.update_ref(ATTESTMAP_REF, RefWriteCondition::Any, &head)
        .unwrap();
    options.attestations = true;
    let report = kit_sync::fetch(
        temp.path(),
        &source,
        "origin",
        &options,
        &kit_sync::NoopObserver,
    )
    .unwrap();
    assert_eq!(report.attestations_stored, 1);
}

#[test]
fn decoded_budget_defers_without_recording_a_complete_cursor_and_resumes() {
    use kit_core::{hash::hash, layout::RepoLayout};
    let tx = kit_transport_memory::MemoryTransport::new();
    let (tip, tree) = attestation_fetch::code(&tx);
    let first = attestation_fetch::envelope(tip);
    let second = attestation_fetch::envelope(tree);
    for env in [&first, &second] {
        attestation_fetch::append(&tx, &kit_attest::pack::build(&[env], 4096).unwrap());
    }
    let temp = tempfile::tempdir().unwrap();
    let remote = kit_sync::CloneRemote {
        name: "origin".into(),
        url: "kit+memory://test".into(),
        kind: "memory".into(),
    };
    kit_sync::init_clone_dir(temp.path(), &remote).unwrap();
    let source = kit_sync::TransportSource::new(&tx);
    let mut options = kit_sync::SyncOptions::default();
    options.attestation_decode_bytes = (first.len().max(second.len()) + 10) as u64;
    let report = kit_sync::fetch(
        temp.path(),
        &source,
        "origin",
        &options,
        &kit_sync::NoopObserver,
    )
    .unwrap();
    assert_eq!(report.attestations_stored, 1);
    assert_eq!(report.attestations_rejected, 0);
    assert_eq!(report.attestation_warnings.len(), 1);
    let layout = RepoLayout::single(temp.path());
    let path = kit_sync::attestation_records::path(&layout, &source, "origin", "", false);
    let record = kit_sync::attestation_records::Record::decode(
        &std::fs::read(path).unwrap(),
        kit_sync::attestation_records::RecordKind::Fetch,
    )
    .unwrap();
    assert!(record.head.is_none());
    assert_eq!(record.ids.len(), 1);
    let report = kit_sync::fetch(
        temp.path(),
        &source,
        "origin",
        &options,
        &kit_sync::NoopObserver,
    )
    .unwrap();
    assert_eq!(report.attestations_stored, 1);
    assert!(report.attestation_warnings.is_empty());
    assert!(kit_sync::attestation_records::fetched_path(&layout, &hash(&second)).exists());
}

struct ShortOnce<'a> {
    tx: &'a kit_transport_memory::MemoryTransport,
    pack: kit_core::hash::Hash,
    pending: std::cell::Cell<bool>,
    supported: std::cell::Cell<bool>,
}
impl kit_sync::RemoteSource for ShortOnce<'_> {
    fn supports_attestations(&self) -> bool {
        self.supported.get()
    }
    fn repo_cursor(&self) -> Result<Option<kit_core::protocol::RepoCursor>, kit_sync::SourceError> {
        kit_sync::RemoteSource::repo_cursor(&kit_sync::TransportSource::new(self.tx))
    }
    fn list_branches(&self) -> Result<Vec<kit_core::refs::Ref>, kit_sync::SourceError> {
        kit_sync::RemoteSource::list_branches(&kit_sync::TransportSource::new(self.tx))
    }
    fn list_refs(&self, prefix: &str) -> Result<Vec<kit_core::refs::Ref>, kit_sync::SourceError> {
        kit_sync::RemoteSource::list_refs(&kit_sync::TransportSource::new(self.tx), prefix)
    }
    fn read_ref(&self, name: &str) -> Result<Option<kit_core::hash::Hash>, kit_sync::SourceError> {
        kit_sync::RemoteSource::read_ref(&kit_sync::TransportSource::new(self.tx), name)
    }
    fn download_blob(
        &self,
        key: &kit_core::protocol::PackKey,
        name: &str,
    ) -> Result<Vec<u8>, kit_sync::SourceError> {
        kit_sync::RemoteSource::download_blob(&kit_sync::TransportSource::new(self.tx), key, name)
    }
    fn download_pack(
        &self,
        key: &kit_core::protocol::PackKey,
        name: &str,
        sink: &mut dyn kit_core::protocol::PackSink,
    ) -> Result<(), kit_sync::SourceError> {
        if key.into_hash() == self.pack && self.pending.replace(false) {
            use kit_core::protocol::Transport;
            let bytes = self.tx.download_blob(key, Some(name), 4096)?;
            sink.begin(Some(bytes.len() as u64))?;
            sink.write(&bytes[..bytes.len() - 1])?;
            return Ok(());
        }
        kit_sync::RemoteSource::download_pack(
            &kit_sync::TransportSource::new(self.tx),
            key,
            name,
            sink,
        )
    }
}
fn descriptor() -> kit_sync::CloneRemote {
    kit_sync::CloneRemote {
        name: "origin".into(),
        url: "kit+memory://test".into(),
        kind: "memory".into(),
    }
}

#[test]
fn short_transfer_warns_then_retries_instead_of_rejecting_the_pack() {
    let tx = kit_transport_memory::MemoryTransport::new();
    let (tip, _) = attestation_fetch::code(&tx);
    let env = attestation_fetch::envelope(tip);
    let bytes = kit_attest::pack::build(&[&env], 4096).unwrap();
    attestation_fetch::append(&tx, &bytes);
    let temp = tempfile::tempdir().unwrap();
    kit_sync::init_clone_dir(temp.path(), &descriptor()).unwrap();
    let source = ShortOnce {
        tx: &tx,
        pack: kit_core::hash::hash(&bytes),
        pending: std::cell::Cell::new(true),
        supported: std::cell::Cell::new(true),
    };
    let options = kit_sync::SyncOptions::default();
    let report = kit_sync::fetch(
        temp.path(),
        &source,
        "origin",
        &options,
        &kit_sync::NoopObserver,
    )
    .unwrap();
    assert_eq!(report.attestations_rejected, 0);
    assert_eq!(report.attestation_warnings.len(), 1);
    let report = kit_sync::fetch(
        temp.path(),
        &source,
        "origin",
        &options,
        &kit_sync::NoopObserver,
    )
    .unwrap();
    assert_eq!(report.attestations_stored, 1);
    assert!(report.attestation_warnings.is_empty());
}

#[test]
fn unsupported_cursor_is_reusable_but_capability_change_fetches_attestations() {
    let tx = kit_transport_memory::MemoryTransport::new();
    let (tip, _) = attestation_fetch::code(&tx);
    let env = attestation_fetch::envelope(tip);
    attestation_fetch::append(&tx, &kit_attest::pack::build(&[&env], 4096).unwrap());
    let temp = tempfile::tempdir().unwrap();
    kit_sync::init_clone_dir(temp.path(), &descriptor()).unwrap();
    let source = ShortOnce {
        tx: &tx,
        pack: [0; 32],
        pending: std::cell::Cell::new(false),
        supported: std::cell::Cell::new(false),
    };
    let options = kit_sync::SyncOptions::default();
    assert_eq!(
        kit_sync::fetch(
            temp.path(),
            &source,
            "origin",
            &options,
            &kit_sync::NoopObserver
        )
        .unwrap()
        .attestation_warnings
        .len(),
        1
    );
    assert!(
        kit_sync::fetch(
            temp.path(),
            &source,
            "origin",
            &options,
            &kit_sync::NoopObserver
        )
        .unwrap()
        .remote_unchanged
    );
    source.supported.set(true);
    assert_eq!(
        kit_sync::fetch(
            temp.path(),
            &source,
            "origin",
            &options,
            &kit_sync::NoopObserver
        )
        .unwrap()
        .attestations_stored,
        1
    );
}

#[test]
fn fetching_an_existing_local_envelope_keeps_its_local_authorship() {
    let tx = kit_transport_memory::MemoryTransport::new();
    let (tip, _) = attestation_fetch::code(&tx);
    let env = attestation_fetch::envelope(tip);
    attestation_fetch::append(&tx, &kit_attest::pack::build(&[&env], 4096).unwrap());
    let temp = tempfile::tempdir().unwrap();
    let layout = kit_sync::init_clone_dir(temp.path(), &descriptor()).unwrap();
    let (id, _) = kit_attest::store::save(&layout, &tip, &env).unwrap();
    let source = kit_sync::TransportSource::new(&tx);
    kit_sync::fetch(
        temp.path(),
        &source,
        "origin",
        &kit_sync::SyncOptions::default(),
        &kit_sync::NoopObserver,
    )
    .unwrap();
    assert!(!kit_sync::attestation_records::fetched_path(&layout, &id).exists());
}

#[test]
fn oversized_node_is_cached_without_discarding_processed_packs() {
    use kit_core::{
        protocol::{PackKey, Transport},
        refs::{ATTESTMAP_REF, RefWriteCondition},
    };
    use kit_sync::attestation_records::{Record, RecordKind};
    let tx = kit_transport_memory::MemoryTransport::new();
    let (tip, _) = attestation_fetch::code(&tx);
    let env = attestation_fetch::envelope(tip);
    attestation_fetch::append(&tx, &kit_attest::pack::build(&[&env], 4096).unwrap());
    let temp = tempfile::tempdir().unwrap();
    let layout = kit_sync::init_clone_dir(temp.path(), &descriptor()).unwrap();
    let source = kit_sync::TransportSource::new(&tx);
    let options = kit_sync::SyncOptions::default();
    kit_sync::fetch(
        temp.path(),
        &source,
        "origin",
        &options,
        &kit_sync::NoopObserver,
    )
    .unwrap();
    let path = kit_sync::attestation_records::path(&layout, &source, "origin", "", false);
    let before = std::fs::read(&path).unwrap();
    let bytes = vec![0; usize::try_from(kit_sync::attestation_records::NODE_BOUND).unwrap() + 1];
    let key = kit_core::hash::hash(&bytes);
    tx.upload_blob(&bytes, &PackKey::from_hash(key), None)
        .unwrap();
    tx.update_ref(ATTESTMAP_REF, RefWriteCondition::Any, &key)
        .unwrap();
    let report = kit_sync::fetch(
        temp.path(),
        &source,
        "origin",
        &options,
        &kit_sync::NoopObserver,
    )
    .unwrap();
    assert_eq!(report.attestation_warnings.len(), 1);
    let before = Record::decode(&before, RecordKind::Fetch).unwrap();
    let after = Record::decode(&std::fs::read(path).unwrap(), RecordKind::Fetch).unwrap();
    assert_eq!(after.head, Some(key));
    assert_eq!(after.ids, before.ids);
    let again = kit_sync::fetch(
        temp.path(),
        &source,
        "origin",
        &options,
        &kit_sync::NoopObserver,
    )
    .unwrap();
    assert!(again.remote_unchanged);
    assert!(again.attestation_warnings.is_empty());
}

#[test]
fn clone_resumes_after_fetch_stores_envelopes_before_checkout() {
    let tx = kit_transport_memory::MemoryTransport::new();
    let (tip, _) = attestation_fetch::code(&tx);
    let env = attestation_fetch::envelope(tip);
    attestation_fetch::append(&tx, &kit_attest::pack::build(&[&env], 4096).unwrap());
    let temp = tempfile::tempdir().unwrap();
    let remote = descriptor();
    kit_sync::init_clone_dir(temp.path(), &remote).unwrap();
    let source = kit_sync::TransportSource::new(&tx);
    let mut options = kit_sync::SyncOptions::default();
    options.remote_url.clone_from(&remote.url);
    kit_sync::fetch(
        temp.path(),
        &source,
        "origin",
        &options,
        &kit_sync::NoopObserver,
    )
    .unwrap();
    let report = kit_sync::clone(
        temp.path(),
        &source,
        &remote,
        &options,
        &kit_sync::NoopObserver,
    )
    .unwrap();
    assert_eq!(
        kit_core::refs::resolve_head(&kit_core::layout::RepoLayout::single(temp.path())).unwrap(),
        Some(tip)
    );
    assert!(report.pull.fetch.attestation_warnings.is_empty());
}

#[test]
fn missing_pack_is_rejected_without_blocking_newer_envelopes_or_cursor() {
    use kit_core::{
        protocol::{PackKey, Transport},
        refs::{ATTESTMAP_REF, RefWriteCondition},
    };
    let tx = kit_transport_memory::MemoryTransport::new();
    let (tip, _) = attestation_fetch::code(&tx);
    let env = attestation_fetch::envelope(tip);
    let node = kit_core::transfer::encode_packlist(None, &[[123; 32]]).unwrap();
    let key = kit_core::hash::hash(&node);
    tx.upload_blob(&node, &PackKey::from_hash(key), None)
        .unwrap();
    tx.update_ref(ATTESTMAP_REF, RefWriteCondition::Any, &key)
        .unwrap();
    attestation_fetch::append(&tx, &kit_attest::pack::build(&[&env], 4096).unwrap());
    let temp = tempfile::tempdir().unwrap();
    kit_sync::init_clone_dir(temp.path(), &descriptor()).unwrap();
    let source = kit_sync::TransportSource::new(&tx);
    let options = kit_sync::SyncOptions::default();
    let report = kit_sync::fetch(
        temp.path(),
        &source,
        "origin",
        &options,
        &kit_sync::NoopObserver,
    )
    .unwrap();
    assert_eq!(report.attestations_stored, 1);
    assert_eq!(report.attestations_rejected, 1);
    assert!(
        kit_sync::fetch(
            temp.path(),
            &source,
            "origin",
            &options,
            &kit_sync::NoopObserver
        )
        .unwrap()
        .remote_unchanged
    );
}

/// A source that reports an interrupt once the attestation phase has
/// downloaded its first pack, as a Ctrl-C there.
struct InterruptAfterPack<'a> {
    inner: kit_sync::TransportSource<'a>,
    packs: std::collections::BTreeSet<kit_core::hash::Hash>,
    cancelled: std::cell::Cell<bool>,
}
impl kit_sync::RemoteSource for InterruptAfterPack<'_> {
    fn supports_attestations(&self) -> bool {
        true
    }
    fn list_branches(&self) -> Result<Vec<kit_core::refs::Ref>, kit_sync::SourceError> {
        self.inner.list_branches()
    }
    fn list_refs(&self, prefix: &str) -> Result<Vec<kit_core::refs::Ref>, kit_sync::SourceError> {
        self.inner.list_refs(prefix)
    }
    fn read_ref(&self, name: &str) -> Result<Option<kit_core::hash::Hash>, kit_sync::SourceError> {
        self.inner.read_ref(name)
    }
    fn download_blob(
        &self,
        key: &kit_core::protocol::PackKey,
        name: &str,
    ) -> Result<Vec<u8>, kit_sync::SourceError> {
        self.inner.download_blob(key, name)
    }
    fn download_pack(
        &self,
        key: &kit_core::protocol::PackKey,
        name: &str,
        sink: &mut dyn kit_core::protocol::PackSink,
    ) -> Result<(), kit_sync::SourceError> {
        if self.packs.contains(&key.into_hash()) {
            self.cancelled.set(true);
        }
        self.inner.download_pack(key, name, sink)
    }
}
impl kit_sync::Observer<kit_sync::SyncEvent> for InterruptAfterPack<'_> {
    fn cancelled(&self) -> bool {
        self.cancelled.get()
    }
}

/// An interrupt in the attestation phase ends the fetch as interrupted, not
/// as a success with a warning, and the next fetch stores the envelopes.
#[test]
fn an_interrupt_in_the_attestation_phase_ends_the_fetch_as_interrupted() {
    let tx = kit_transport_memory::MemoryTransport::new();
    let (tip, _) = attestation_fetch::code(&tx);
    let first = kit_attest::pack::build(&[&attestation_fetch::envelope(tip)], 4096).unwrap();
    attestation_fetch::append(&tx, &first);
    let mut second = kit_attest::envelope::decode(&attestation_fetch::envelope(tip)).unwrap();
    second.payload = String::from_utf8(second.payload)
        .unwrap()
        .replace("example.com/test/v1", "example.com/second/v1")
        .into_bytes();
    let second = kit_attest::pack::build(&[second.encode().unwrap().as_bytes()], 4096).unwrap();
    attestation_fetch::append(&tx, &second);
    let temp = tempfile::tempdir().unwrap();
    kit_sync::init_clone_dir(temp.path(), &descriptor()).unwrap();
    let source = InterruptAfterPack {
        inner: kit_sync::TransportSource::new(&tx),
        packs: [kit_core::hash::hash(&first), kit_core::hash::hash(&second)]
            .into_iter()
            .collect(),
        cancelled: std::cell::Cell::new(false),
    };
    let result = kit_sync::fetch(
        temp.path(),
        &source,
        "origin",
        &kit_sync::SyncOptions::default(),
        &source,
    );
    assert!(source.cancelled.get());
    assert!(
        matches!(result, Err(kit_sync::SyncError::Interrupted)),
        "{result:?}"
    );
    kit_sync::fetch(
        temp.path(),
        &kit_sync::TransportSource::new(&tx),
        "origin",
        &kit_sync::SyncOptions::default(),
        &kit_sync::NoopObserver,
    )
    .unwrap();
    let layout = kit_core::layout::RepoLayout::single(temp.path());
    assert_eq!(kit_attest::store::list(&layout, &tip).unwrap().len(), 2);
}
