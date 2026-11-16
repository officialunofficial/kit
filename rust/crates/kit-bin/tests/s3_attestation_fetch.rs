//! Read the same attestation log through signed S3 requests and pack sinks.
#![cfg(feature = "s3")]
#![allow(clippy::unwrap_used)]
include!("../../kit-sync/tests/support/attestation_fetch.rs");

#[test]
#[allow(clippy::too_many_lines)] // One transport round trip and its HTTP fixture.
fn s3_clone_fetch_pull_validate_attestations_and_resume_after_rejection() {
    use std::fmt::Write as _;
    use kit_core::{
        hash::{Hash, to_hex},
        protocol::{PackKey, Transport},
        refs::ATTESTMAP_REF,
    };
    let memory = kit_transport_memory::MemoryTransport::new();
    let (tip, _) = attestation_fetch::code(&memory);
    let env = attestation_fetch::envelope(tip);
    let absent = attestation_fetch::envelope([99; 32]);
    let bytes = kit_attest::pack::build(&[&env, &absent], 4096).unwrap();
    attestation_fetch::append(&memory, &bytes);
    // A valid code pack is hostile in the attestation namespace: its entries
    // are trees and commits, rather than plain envelope blobs.
    let code_head = memory.read_ref("refs/kit/packmap/main").unwrap().unwrap();
    let code_node = memory
        .download_blob(&PackKey::from_hash(code_head), None, 4096)
        .unwrap();
    let code_pack = kit_core::transfer::decode_packlist(&code_node)
        .unwrap()
        .packs[0];
    let code_bytes = memory
        .download_blob(&PackKey::from_hash(code_pack), None, 4096)
        .unwrap();
    attestation_fetch::append(&memory, &code_bytes);
    let mut server = mockito::Server::new();
    let mut mocks = vec![];
    let refs = memory.list_refs("refs/").unwrap();
    let mut xml = String::from("<ListBucketResult>");
    let mut pending = Vec::<Hash>::new();
    for reference in refs {
        let full = format!("refs/{}", reference.name);
        write!(xml, "<Contents><Key>{full}</Key></Contents>").unwrap();
        let value = reference.hash.unwrap();
        mocks.push(
            server
                .mock("GET", format!("/bucket/{full}").as_str())
                .with_status(200)
                .with_body(format!("{}\n", to_hex(&value)))
                .create(),
        );
        if full.starts_with("refs/kit/") {
            pending.push(value);
        }
    }
    xml.push_str("</ListBucketResult>");
    mocks.push(
        server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"/bucket\?list-type=2".into()),
            )
            .with_status(200)
            .with_body(xml)
            .create(),
    );
    let mut seen = std::collections::BTreeSet::new();
    while let Some(key) = pending.pop() {
        if !seen.insert(key) {
            continue;
        }
        let bytes = memory
            .download_blob(&PackKey::from_hash(key), None, 1 << 20)
            .unwrap();
        if let Ok(node) = kit_core::transfer::decode_packlist(&bytes) {
            pending.extend(node.prev);
            pending.extend(node.packs);
        }
        mocks.push(
            server
                .mock("GET", format!("/bucket/packs/{}", to_hex(&key)).as_str())
                .with_status(200)
                .with_body(bytes)
                .create(),
        );
    }
    let tx = kit_transport_s3::S3Transport::with_parts(
        server.url(),
        "bucket",
        None,
        kit_transport_s3::sigv4::Credentials {
            access_key_id: "test".into(),
            secret_access_key: "test".into(),
            region: "us-east-1".into(),
        },
    )
    .unwrap();
    let source = kit_sync::TransportSource::new(&tx);
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path().join("clone");
    let descriptor = kit_sync::CloneRemote {
        name: "origin".into(),
        url: "kit+s3://test/bucket".into(),
        kind: "s3".into(),
    };
    let mut options = kit_sync::SyncOptions::default();
    options.remote_url.clone_from(&descriptor.url);
    let report = kit_sync::clone(
        &dir,
        &source,
        &descriptor,
        &options,
        &kit_sync::NoopObserver,
    )
    .unwrap();
    assert_eq!(report.pull.fetch.attestations_stored, 1);
    assert_eq!(report.pull.fetch.attestations_dropped, 1);
    assert_eq!(report.pull.fetch.attestations_rejected, 1);
    assert_eq!(report.pull.fetch.attestation_warnings.len(), 1);
    assert_eq!(
        kit_sync::fetch(&dir, &source, "origin", &options, &kit_sync::NoopObserver)
            .unwrap()
            .attestations_rejected,
        0
    );
    assert_eq!(
        kit_sync::pull(&dir, &source, "origin", &options, &kit_sync::NoopObserver)
            .unwrap()
            .fetch
            .attestations_stored,
        0
    );
    let layout = kit_core::layout::RepoLayout::single(&dir);
    assert!(
        kit_sync::attestation_records::fetched_path(&layout, &kit_core::hash::hash(&env)).exists()
    );
    assert!(tx.read_ref(ATTESTMAP_REF).unwrap().is_some());
}
