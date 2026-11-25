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
    attestation_records::WALK_LIMIT,
};

fn clone(tx: &dyn Transport) -> (tempfile::TempDir, Hash) {
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
    let tip = refs::read_ref(&RepoLayout::single(temp.path()), "main")
        .unwrap()
        .unwrap();
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
fn variant(tip: Hash, predicate: &str, extra: serde_json::Value) -> Vec<u8> {
    let mut env = kit_attest::envelope::decode(&attestation_fetch::envelope(tip)).unwrap();
    let mut statement: serde_json::Value = serde_json::from_slice(&env.payload).unwrap();
    statement["predicateType"] = predicate.into();
    statement["predicate"] = extra;
    env.payload = serde_json::to_vec(&statement).unwrap();
    env.encode().unwrap().into_bytes()
}

// Export writes "local" for local and helper mirrors. Push publishes it.
#[test]
fn sanitized_local_mirror_has_no_warning() {
    let tx = kit_transport_memory::MemoryTransport::new();
    attestation_fetch::code(&tx);
    let (dir, tip) = clone(&tx);
    let layout = RepoLayout::single(dir.path());
    let env = variant(
        tip,
        "https://kit.storage/spec/predicate/git-bridge/v1",
        serde_json::json!({"gitCommit": "00", "mirror": "local", "refName": "refs/heads/main", "schemaVersion": 1, "specVersion": 1}),
    );
    kit_attest::store::save(&layout, &tip, &env).unwrap();
    let report = kit_sync::push(dir.path(), &TransportSource::new(&tx), &options()).unwrap();
    eprintln!("warnings: {:?}", report.attestation_warnings);
    assert_eq!(report.attestations_pushed, 1);
    assert!(
        !report
            .attestation_warnings
            .iter()
            .any(|w| w.contains("git-bridge")),
        "spurious leak warning for the sanitized placeholder"
    );
}

// A force-capable writer must compact a log above 4,096 packs. Here the log
// lists exactly WALK_LIMIT packs (two distinct valid packs, repeated).
#[test]
fn compaction_recovers_at_reader_limit() {
    let tx = kit_transport_memory::MemoryTransport::new();
    let (tip, _) = attestation_fetch::code(&tx);
    let keys: Vec<Hash> = ["a", "b"]
        .iter()
        .map(|n| {
            let env = variant(
                tip,
                &format!("https://example.com/{n}/v1"),
                serde_json::json!({}),
            );
            let pack = kit_attest::pack::build(&[&env], 1 << 20).unwrap();
            let key = hash::hash(&pack);
            tx.upload_blob(&pack, &PackKey::new(key), None).unwrap();
            key
        })
        .collect();
    let mut prior = None;
    let mut left = WALK_LIMIT;
    let mut n = 0usize;
    while left > 0 {
        let count = left.min(4096);
        let listing: Vec<Hash> = (0..count).map(|i| keys[(n + i) % 2]).collect();
        n += count;
        let node = kit_core::transfer::encode_packlist(prior, &listing).unwrap();
        let id = hash::hash(&node);
        tx.upload_blob(&node, &PackKey::new(id), None).unwrap();
        prior = Some(id);
        left -= count;
    }
    tx.update_ref(ATTESTMAP_REF, RefWriteCondition::Missing, &prior.unwrap())
        .unwrap();
    let (dir, tip) = clone(&tx);
    // One new locally made envelope to publish.
    let layout = RepoLayout::single(dir.path());
    let env = variant(tip, "https://example.com/local/v1", serde_json::json!({}));
    kit_attest::store::save(&layout, &tip, &env).unwrap();
    // No authority: file/ssh/S3 writers are treated as holding f.
    let report = kit_sync::push(dir.path(), &TransportSource::new(&tx), &options()).unwrap();
    eprintln!(
        "pushed={} warnings={:?}",
        report.attestations_pushed, report.attestation_warnings
    );
    let head = tx.read_ref(ATTESTMAP_REF).unwrap().unwrap();
    let node = kit_core::transfer::decode_packlist(
        &tx.download_blob(&PackKey::new(head), None, 1 << 20)
            .unwrap(),
    )
    .unwrap();
    assert!(
        node.prev.is_none() && head != prior.unwrap(),
        "log was not compacted; still listing {WALK_LIMIT} packs"
    );
}

// One valid Zstandard frame with a single raw last block. This creates the
// same compressed-entry wire format without requiring an encoder feature.
fn compressed_envelope(envelope: &[u8]) -> Vec<u8> {
    let raw =
        kit_core::serialize::serialize(&kit_core::object::Object::Blob(kit_core::object::Blob {
            data: envelope.to_vec(),
        }))
        .unwrap();
    let len = u32::try_from(raw.len()).unwrap();
    let mut frame = vec![0x28, 0xb5, 0x2f, 0xfd, 0xa0];
    frame.extend(len.to_le_bytes());
    frame.extend_from_slice(&((len << 3) | 1).to_le_bytes()[..3]);
    frame.extend(&raw);
    let mut pack = b"KIT\0".to_vec();
    pack.extend(2u32.to_le_bytes());
    pack.extend(1u32.to_le_bytes());
    pack.push(3);
    pack.extend(u32::try_from(frame.len() + 4).unwrap().to_le_bytes());
    pack.extend(len.to_le_bytes());
    pack.extend(frame);
    let trailer = hash::hash(&pack);
    pack.extend(trailer);
    pack
}

#[test]
fn compressed_attestations_are_never_recorded_as_invalid() {
    let tx = kit_transport_memory::MemoryTransport::new();
    let (tip, _) = attestation_fetch::code(&tx);
    let pack = compressed_envelope(&attestation_fetch::envelope(tip));
    attestation_fetch::append(&tx, &pack);
    let dir = tempfile::tempdir().unwrap();
    let descriptor = CloneRemote {
        name: "origin".into(),
        url: "kit+memory://compression".into(),
        kind: "memory".into(),
    };
    kit_sync::init_clone_dir(dir.path(), &descriptor).unwrap();
    for _ in 0..2 {
        let report = kit_sync::fetch(
            dir.path(),
            &TransportSource::new(&tx),
            "origin",
            &SyncOptions::default(),
            &NoopObserver,
        )
        .unwrap();
        assert_eq!(report.attestations_rejected, 0);
        if compression_supported() {
            assert!(report.attestation_warnings.is_empty());
        } else {
            assert!(
                report
                    .attestation_warnings
                    .iter()
                    .any(|w| w.contains("pack-zstd"))
            );
        }
    }
}

#[test]
fn compaction_without_compression_support_preserves_the_log() {
    if compression_supported() {
        return;
    }
    let tx = kit_transport_memory::MemoryTransport::new();
    let (tip, _) = attestation_fetch::code(&tx);
    let (dir, _) = clone(&tx);
    let pack = compressed_envelope(&attestation_fetch::envelope(tip));
    let key = hash::hash(&pack);
    tx.upload_blob(&pack, &PackKey::new(key), None).unwrap();
    let node = kit_core::transfer::encode_packlist(None, &vec![key; 4096]).unwrap();
    let prior = hash::hash(&node);
    tx.upload_blob(&node, &PackKey::new(prior), None).unwrap();
    tx.update_ref(ATTESTMAP_REF, RefWriteCondition::Missing, &prior)
        .unwrap();
    let env = variant(tip, "https://example.com/local/v1", serde_json::json!({}));
    kit_attest::store::save(&RepoLayout::single(dir.path()), &tip, &env).unwrap();
    let report = kit_sync::push(dir.path(), &TransportSource::new(&tx), &options()).unwrap();
    assert_eq!(report.attestations_pushed, 0);
    assert!(
        report
            .attestation_warnings
            .iter()
            .any(|w| w.contains("pack-zstd"))
    );
    assert_eq!(tx.read_ref(ATTESTMAP_REF).unwrap(), Some(prior));
}

fn compression_supported() -> bool {
    let envelope = include_bytes!("../../../tests/golden/attest/envelope_basic.json");
    let pack = compressed_envelope(envelope);
    let result = kit_attest::pack::read(
        &mut std::io::Cursor::new(&pack),
        pack.len() as u64,
        1 << 20,
        hash::hash(&pack),
        &mut kit_attest::pack::DecodeBudget::default(),
        |_, _, _| {},
    );
    match result {
        Ok(()) => true,
        Err(kit_attest::pack::PackError::Pack(
            kit_core::pack::PackError::CompressionUnavailable,
        )) => false,
        Err(error) => panic!("unexpected compressed fixture error: {error}"),
    }
}
