#![allow(clippy::unwrap_used)]
include!("support/attestation_fetch.rs");
use kit_core::{
    hash::{self, Hash},
    layout::RepoLayout,
    protocol::{PackKey, Transport},
    refs::{self, ATTESTMAP_REF, RefWriteCondition},
};
use kit_sync::{
    CloneRemote, NoopObserver, PushLease, PushOptions, PushTarget, SyncOptions, TransportSource,
};

fn local(tx: &dyn Transport, predicate: &str) -> (tempfile::TempDir, Hash) {
    let temp = tempfile::tempdir().unwrap();
    let desc = CloneRemote {
        name: "origin".into(),
        url: "kit+memory://push".into(),
        kind: "memory".into(),
    };
    kit_sync::clone(
        temp.path(),
        &TransportSource::new(tx),
        &desc,
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();
    let layout = RepoLayout::single(temp.path());
    let tip = refs::read_ref(&layout, "main").unwrap().unwrap();
    let mut env = kit_attest::envelope::decode(&attestation_fetch::envelope(tip)).unwrap();
    env.payload = String::from_utf8(env.payload)
        .unwrap()
        .replace("example.com/test/v1", predicate)
        .into_bytes();
    kit_attest::store::save(&layout, &tip, env.encode().unwrap().as_bytes()).unwrap();
    (temp, tip)
}
fn options() -> PushOptions<'static> {
    let mut opts = PushOptions::default();
    opts.target = PushTarget::Branch {
        local: "main".into(),
        remote: "main".into(),
        lease: PushLease::FastForward,
    };
    opts.remote_name = "origin";
    opts.attestations = true;
    opts
}
struct UpdateOnly;
impl kit_sync::push::StepAuthority for UpdateOnly {
    fn can_compact_attestations(&self) -> bool { false }
    fn authorize(&self, _: &str, _: RefWriteCondition, _: bool) -> Result<(), String> {
        Ok(())
    }
}
#[test]
fn compaction_replaces_4097_listed_packs_only_with_force_permission() {
    let tx = kit_transport_memory::MemoryTransport::new();
    let (tip, _) = attestation_fetch::code(&tx);
    let old = kit_attest::pack::build(&[&attestation_fetch::envelope(tip)], 4096).unwrap();
    let key = hash::hash(&old);
    tx.upload_blob(&old, &PackKey::new(key), None).unwrap();
    let node = kit_core::transfer::encode_packlist(None, &vec![key; 4096]).unwrap();
    let head = hash::hash(&node);
    tx.upload_blob(&node, &PackKey::new(head), None).unwrap();
    tx.update_ref(ATTESTMAP_REF, RefWriteCondition::Missing, &head)
        .unwrap();
    let (dir, _) = local(&tx, "example.com/new/v1");
    let mut opts = options();
    opts.control.authority = Some(&UpdateOnly);
    let result = kit_sync::push(dir.path(), &TransportSource::new(&tx), &opts).unwrap();
    assert_eq!(result.steps, 0);
    assert_eq!(result.attestations_pushed, 0);
    assert!(
        result
            .attestation_warnings
            .iter()
            .any(|s| s.contains("requires the f"))
    );
    assert_eq!(tx.read_ref(ATTESTMAP_REF).unwrap(), Some(head));
    opts.control.authority = None;
    let result = kit_sync::push(dir.path(), &TransportSource::new(&tx), &opts).unwrap();
    assert_eq!(result.attestations_pushed, 1);
    let next = tx.read_ref(ATTESTMAP_REF).unwrap().unwrap();
    let bytes = tx
        .download_blob(&PackKey::new(next), None, 1 << 20)
        .unwrap();
    let baseline = kit_core::transfer::decode_packlist(&bytes).unwrap();
    assert!(baseline.prev.is_none());
    assert_eq!(baseline.packs.len(), 1);
}
#[test]
fn simultaneous_attesters_both_survive_cas() {
    let tx = kit_transport_memory::MemoryTransport::new();
    attestation_fetch::code(&tx);
    let (a, _) = local(&tx, "example.com/a/v1");
    let (b, _) = local(&tx, "example.com/b/v1");
    let barrier = std::sync::Barrier::new(2);
    let source = TransportSource::new(&tx);
    std::thread::scope(|scope| {
        let source = &source;
        let barrier = &barrier;
        let a = scope.spawn(|| {
            let gated = Gated { source, barrier, first: std::cell::Cell::new(true), limits: kit_core::protocol::UploadLimits::default() };
            kit_sync::push(a.path(), &gated, &options()).unwrap()
        });
        let b = scope.spawn(|| {
            let gated = Gated { source, barrier, first: std::cell::Cell::new(true), limits: kit_core::protocol::UploadLimits::default() };
            kit_sync::push(b.path(), &gated, &options()).unwrap()
        });
        assert_eq!(a.join().unwrap().attestations_pushed, 1);
        assert_eq!(b.join().unwrap().attestations_pushed, 1);
    });
    let dir = tempfile::tempdir().unwrap();
    let desc = CloneRemote {
        name: "origin".into(),
        url: "kit+memory://push".into(),
        kind: "memory".into(),
    };
    let cloned = kit_sync::clone(
        dir.path(),
        &TransportSource::new(&tx),
        &desc,
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();
    assert_eq!(cloned.pull.fetch.attestations_stored, 2);
}
#[test]
fn failed_attestation_log_does_not_fail_the_code_push() {
    let tx = kit_transport_memory::MemoryTransport::new();
    attestation_fetch::code(&tx);
    let (dir, _) = local(&tx, "example.com/local/v1");
    tx.update_ref(ATTESTMAP_REF, RefWriteCondition::Any, &[2; 32])
        .unwrap();
    let result = kit_sync::push(dir.path(), &TransportSource::new(&tx), &options()).unwrap();
    assert_eq!(result.attestations_pushed, 0);
    assert!(!result.attestation_warnings.is_empty());
}

// Both writers observe the same head before either can publish.
struct Gated<'a> {
    source: &'a TransportSource<'a>,
    barrier: &'a std::sync::Barrier,
    first: std::cell::Cell<bool>,
    limits: kit_core::protocol::UploadLimits,
}
impl kit_sync::RemoteSource for Gated<'_> {
    fn upload_limits(&self) -> kit_core::protocol::UploadLimits { self.limits }
    fn supports_push(&self) -> bool { true }
    fn supports_attestations(&self) -> bool { true }
    fn list_branches(&self) -> Result<Vec<refs::Ref>, kit_sync::SourceError> { self.source.list_branches() }
    fn list_refs(&self, prefix: &str) -> Result<Vec<refs::Ref>, kit_sync::SourceError> { self.source.list_refs(prefix) }
    fn read_ref(&self, name: &str) -> Result<Option<Hash>, kit_sync::SourceError> {
        let result = self.source.read_ref(name);
        if name == ATTESTMAP_REF && self.first.replace(false) { self.barrier.wait(); }
        result
    }
    fn download_blob(&self, key: &PackKey, hint: &str) -> Result<Vec<u8>, kit_sync::SourceError> { self.source.download_blob(key, hint) }
    fn download_pack(&self, key: &PackKey, hint: &str, sink: &mut dyn kit_core::protocol::PackSink) -> Result<(), kit_sync::SourceError> { self.source.download_pack(key, hint, sink) }
    fn upload_pack(&self, body: &dyn kit_core::protocol::PackBody, key: &PackKey, hint: &str) -> Result<(), kit_sync::SourceError> { self.source.upload_pack(body, key, hint) }
    fn upload_blob(&self, bytes: &[u8], key: &PackKey, hint: &str) -> Result<(), kit_sync::SourceError> { self.source.upload_blob(bytes, key, hint) }
    fn write_attestmap(&self, condition: RefWriteCondition, tip: &Hash, keys: &[PackKey]) -> Result<(), kit_sync::SourceError> { if let Some(budget) = self.limits.data_packs_per_advance { assert!(keys.len() <= budget + 1); }
        self.source.write_attestmap(condition, tip, keys) }
}

#[test]
fn compaction_splits_existing_packs_under_smaller_upload_and_ticket_caps() {
    let tx = kit_transport_memory::MemoryTransport::new();
    let (tip, _) = attestation_fetch::code(&tx);
    let envelopes: Vec<_> = (0..8).map(|n| {
        let mut env = kit_attest::envelope::decode(&attestation_fetch::envelope(tip)).unwrap();
        env.payload = String::from_utf8(env.payload).unwrap().replace("example.com/test/v1", &format!("example.com/old{n}/v1")).into_bytes();
        env.encode().unwrap().into_bytes()
    }).collect();
    let old = kit_attest::pack::build(&envelopes.iter().map(Vec::as_slice).collect::<Vec<_>>(), 1<<20).unwrap();
    let key = hash::hash(&old);
    tx.upload_blob(&old, &PackKey::new(key), None).unwrap();
    let node = kit_core::transfer::encode_packlist(None, &vec![key;4096]).unwrap();
    let id = hash::hash(&node);
    tx.upload_blob(&node, &PackKey::new(id), None).unwrap();
    tx.update_ref(ATTESTMAP_REF, RefWriteCondition::Missing, &id).unwrap();
    let (dir, _) = local(&tx, "example.com/new/v1");
    let source = TransportSource::new(&tx);
    let gated = Gated { source: &source, barrier: &std::sync::Barrier::new(1), first: std::cell::Cell::new(false),
        limits: kit_core::protocol::UploadLimits { max_pack_bytes: Some(1024), data_packs_per_advance: Some(1), ..Default::default() } };
    let report = kit_sync::push(dir.path(), &gated, &options()).unwrap();
    assert_eq!(report.attestations_pushed, 1);
    assert!(report.attestation_warnings.iter().all(|w| w.contains("permanent")), "{:?}", report.attestation_warnings);
    let id = tx.read_ref(ATTESTMAP_REF).unwrap().unwrap();
    let bytes = tx.download_blob(&PackKey::new(id), None, 1<<20).unwrap();
    let node = kit_core::transfer::decode_packlist(&bytes).unwrap();
    assert!(node.prev.is_none());
    assert_eq!(node.packs.len(), 9);
}

#[test]
fn invalid_local_and_remote_envelopes_do_not_block_valid_publication() {
    let tx = kit_transport_memory::MemoryTransport::new();
    attestation_fetch::code(&tx);
    let (dir, tip) = local(&tx, "example.com/good/v1");
    let layout = RepoLayout::single(dir.path());
    kit_attest::store::save(&layout, &tip, b"invalid").unwrap();
    let bad = b"invalid pack";
    let key = hash::hash(bad);
    tx.upload_blob(bad, &PackKey::new(key), None).unwrap();
    let node = kit_core::transfer::encode_packlist(None, &vec![key;4096]).unwrap();
    let id = hash::hash(&node);
    tx.upload_blob(&node, &PackKey::new(id), None).unwrap();
    tx.update_ref(ATTESTMAP_REF, RefWriteCondition::Missing, &id).unwrap();
    let report = kit_sync::push(dir.path(), &TransportSource::new(&tx), &options()).unwrap();
    assert_eq!(report.attestations_pushed, 1);
    assert!(report.attestation_warnings.iter().any(|w| w.contains("invalid local")));
    assert!(report.attestation_warnings.iter().any(|w| w.contains("invalid attestation pack")));
}

#[test]
fn depth_64_rebaseline_preserves_oldest_first_pack_order_under_update_permission() {
    let tx = kit_transport_memory::MemoryTransport::new();
    let (tip, _) = attestation_fetch::code(&tx);
    let env = attestation_fetch::envelope(tip);
    let pack = kit_attest::pack::build(&[&env], 4096).unwrap();
    let key = hash::hash(&pack);
    for _ in 0..64 { attestation_fetch::append(&tx, &pack); }
    let (dir, _) = local(&tx, "example.com/new/v1");
    let mut opts = options();
    opts.control.authority = Some(&UpdateOnly);
    let report = kit_sync::push(dir.path(), &TransportSource::new(&tx), &opts).unwrap();
    assert_eq!(report.attestations_pushed, 1);
    let id = tx.read_ref(ATTESTMAP_REF).unwrap().unwrap();
    let bytes = tx.download_blob(&PackKey::new(id), None, 1<<20).unwrap();
    let node = kit_core::transfer::decode_packlist(&bytes).unwrap();
    assert!(node.prev.is_none());
    assert_eq!(&node.packs[..64], &vec![key;64]);
    assert_eq!(node.packs.len(), 65);
}
