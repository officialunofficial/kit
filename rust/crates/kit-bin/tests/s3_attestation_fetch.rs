//! Read the same attestation log through signed S3 requests and pack sinks.
#![cfg(feature = "s3")]
#![allow(clippy::unwrap_used)]
include!("../../kit-sync/tests/support/attestation_fetch.rs");

#[test]
#[allow(clippy::too_many_lines)] // One transport round trip and its HTTP fixture.
fn s3_clone_fetch_pull_validate_attestations_and_resume_after_rejection() {
    use kit_core::{
        hash::{Hash, to_hex},
        protocol::{PackKey, Transport},
        refs::ATTESTMAP_REF,
    };
    use std::fmt::Write as _;
    let memory = std::sync::Arc::new(kit_transport_memory::MemoryTransport::new());
    let (tip, _) = attestation_fetch::code(&*memory);
    let env = attestation_fetch::envelope(tip);
    let absent = attestation_fetch::envelope([99; 32]);
    let bytes = kit_attest::pack::build(&[&env, &absent], 4096).unwrap();
    attestation_fetch::append(&*memory, &bytes);
    attestation_fetch::append(&*memory, &attestation_fetch::hostile_claim());
    let mut server = mockito::Server::new();
    let mut mocks = vec![];
    let refs = memory.list_refs("refs/").unwrap();
    let mut xml = String::from("<ListBucketResult>");
    let mut pending = Vec::<Hash>::new();
    for reference in refs {
        let full = format!("refs/{}", reference.name);
        write!(xml, "<Contents><Key>{full}</Key></Contents>").unwrap();
        let value = reference.hash.unwrap();
        let data = std::sync::Arc::clone(&memory);
        let ref_name = full.clone();
        mocks.push(
            server
                .mock("GET", format!("/bucket/{full}").as_str())
                .with_status(200)
                .with_body_from_request(move |_| {
                    format!("{}\n", to_hex(&data.read_ref(&ref_name).unwrap().unwrap()))
                        .into_bytes()
                })
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
    let data = std::sync::Arc::clone(&memory);
    mocks.push(
        server
            .mock(
                "PUT",
                mockito::Matcher::Regex("/bucket/(packs/|refs/kit/attestmap)".into()),
            )
            .with_status(200)
            .with_body_from_request(move |request| {
                let path = request.path().strip_prefix("/bucket/").unwrap();
                let bytes = request.body().unwrap();
                if let Some(hex) = path.strip_prefix("packs/") {
                    let key = kit_core::refs::parse_lowercase_hash(hex.as_bytes()).unwrap();
                    data.upload_blob(bytes, &PackKey::new(key), Some(ATTESTMAP_REF))
                        .unwrap();
                } else {
                    let key =
                        kit_core::refs::parse_lowercase_hash(bytes.strip_suffix(b"\n").unwrap())
                            .unwrap();
                    data.update_ref(path, kit_core::refs::RefWriteCondition::Any, &key)
                        .unwrap();
                }
                Vec::new()
            })
            .create(),
    );
    let data = std::sync::Arc::clone(&memory);
    mocks.push(
        server
            .mock(
                "GET",
                mockito::Matcher::Regex("/bucket/packs/[a-f0-9]+".into()),
            )
            .with_status(200)
            .with_body_from_request(move |request| {
                let hex = request.path().strip_prefix("/bucket/packs/").unwrap();
                let key = kit_core::refs::parse_lowercase_hash(hex.as_bytes()).unwrap();
                data.download_blob(&PackKey::new(key), Some(ATTESTMAP_REF), 1 << 20)
                    .unwrap()
            })
            .create(),
    );
    mocks.push(
        server
            .mock(
                "HEAD",
                mockito::Matcher::Regex("/bucket/packs/[a-f0-9]+".into()),
            )
            .with_status(404)
            .create(),
    );
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
    assert!(report.pull.fetch.attestation_warnings[0].contains("decoded cap"));
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
    attestation_fetch::push_up_to_date(&tx, &dir, &layout, tip);
    assert!(tx.read_ref(ATTESTMAP_REF).unwrap().is_some());
}
