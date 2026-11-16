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
    for env in [&first, &second] { attestation_fetch::append(&tx, &kit_attest::pack::build(&[env], 4096).unwrap()); }
    let temp = tempfile::tempdir().unwrap();
    let remote = kit_sync::CloneRemote { name: "origin".into(), url: "kit+memory://test".into(), kind: "memory".into() };
    kit_sync::init_clone_dir(temp.path(), &remote).unwrap();
    let source = kit_sync::TransportSource::new(&tx);
    let mut options = kit_sync::SyncOptions::default();
    options.attestation_decode_bytes = (first.len().max(second.len()) + 10) as u64;
    let report = kit_sync::fetch(temp.path(), &source, "origin", &options, &kit_sync::NoopObserver).unwrap();
    assert_eq!(report.attestations_stored, 1);
    assert_eq!(report.attestations_rejected, 0);
    assert_eq!(report.attestation_warnings.len(), 1);
    let layout = RepoLayout::single(temp.path());
    let path = kit_sync::attestation_records::path(&layout, &source, "origin", "", false);
    let record = kit_sync::attestation_records::Record::decode(&std::fs::read(path).unwrap(), kit_sync::attestation_records::RecordKind::Fetch).unwrap();
    assert!(record.head.is_none()); assert_eq!(record.ids.len(), 1);
    let report = kit_sync::fetch(temp.path(), &source, "origin", &options, &kit_sync::NoopObserver).unwrap();
    assert_eq!(report.attestations_stored, 1);
    assert!(report.attestation_warnings.is_empty());
    assert!(kit_sync::attestation_records::fetched_path(&layout, &hash(&second)).exists());
}
