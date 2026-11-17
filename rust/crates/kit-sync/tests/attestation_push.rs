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
    std::thread::scope(|scope| {
        let a = scope
            .spawn(|| kit_sync::push(a.path(), &TransportSource::new(&tx), &options()).unwrap());
        let b = scope
            .spawn(|| kit_sync::push(b.path(), &TransportSource::new(&tx), &options()).unwrap());
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
