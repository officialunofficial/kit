//! Capability-gated fetches through both native Connect adapters.
#![allow(clippy::unwrap_used)]
include!("../../kit-sync/tests/support/attestation_fetch.rs");

use buffa::Message;
use kit_client::proto;
use kit_core::{
    hash::Hash,
    protocol::{PackKey, Transport},
    refs::ATTESTMAP_REF,
};
use std::sync::{Arc, Mutex};

struct Fixture {
    _mocks: Vec<mockito::Mock>,
    server: mockito::ServerGuard,
    calls: Arc<Mutex<Vec<String>>>,
    tip: Hash,
}
fn frame(body: &mut Vec<u8>, message: &impl Message) {
    let bytes = message.encode_to_vec();
    body.push(0);
    body.extend(u32::try_from(bytes.len()).unwrap().to_be_bytes());
    body.extend(bytes);
}
#[allow(clippy::too_many_lines)] // Discovery and three read endpoints share one fixture.
fn fixture(advertised: bool) -> Fixture {
    let memory = Arc::new(kit_transport_memory::MemoryTransport::new());
    let (tip, _) = attestation_fetch::code(&*memory);
    let envelope = attestation_fetch::envelope(tip);
    attestation_fetch::append(
        &*memory,
        &kit_attest::pack::build(&[&envelope], 4096).unwrap(),
    );
    let mut server = mockito::Server::new();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let info = proto::GetServerInfoResponse {
        protocol: Some("kit.transport.v1".into()),
        spec_version: Some(2),
        max_pack_bytes: Some(32 << 20),
        part_size: Some(8 << 20),
        max_parts: Some(1),
        max_list_refs_page_size: Some(100),
        supports_attestations: Some(advertised),
        ..Default::default()
    };
    let info_mock = server
        .mock("POST", "/kit.transport.v1.TransportService/GetServerInfo")
        .with_status(200)
        .with_header("content-type", "application/proto")
        .with_body(info.encode_to_vec())
        .create();
    let data = Arc::clone(&memory);
    let log = Arc::clone(&calls);
    let read_mock = server
        .mock("POST", "/kit.transport.v1.TransportService/ReadRef")
        .with_status(200)
        .with_header("content-type", "application/proto")
        .with_body_from_request(move |request| {
            let request =
                proto::ReadRefRequest::decode_from_slice(request.body().unwrap()).unwrap();
            let name = request.name.unwrap();
            log.lock().unwrap().push(format!("read:{name}"));
            let id = data.read_ref(&name).unwrap();
            proto::ReadRefResponse {
                exists: Some(id.is_some()),
                object_id: id.map(|id| id.to_vec()),
                ..Default::default()
            }
            .encode_to_vec()
        })
        .create();
    let data = Arc::clone(&memory);
    let log = Arc::clone(&calls);
    let list_mock = server
        .mock("POST", "/kit.transport.v1.TransportService/ListRefs")
        .with_status(200)
        .with_header("content-type", "application/proto")
        .with_body_from_request(move |request| {
            let request =
                proto::ListRefsRequest::decode_from_slice(request.body().unwrap()).unwrap();
            let prefix = request.prefix.unwrap_or_default();
            log.lock().unwrap().push(format!("list:{prefix}"));
            proto::ListRefsResponse {
                refs: data
                    .list_refs(&prefix)
                    .unwrap()
                    .into_iter()
                    .map(|reference| proto::RefEntry {
                        name: Some(reference.name),
                        object_id: reference.hash.map(|id| id.to_vec()),
                        ..Default::default()
                    })
                    .collect(),
                ..Default::default()
            }
            .encode_to_vec()
        })
        .create();
    let data = Arc::clone(&memory);
    let download_mock = server
        .mock("POST", "/kit.transport.v1.TransportService/DownloadPack")
        .with_status(200)
        .with_header("content-type", "application/connect+proto")
        .with_body_from_request(move |request| {
            let wire = request.body().unwrap();
            let request = proto::DownloadPackRequest::decode_from_slice(&wire[5..]).unwrap();
            let key: Hash = request.pack_id.unwrap().try_into().unwrap();
            let bytes = data
                .download_blob(&PackKey::from_hash(key), None, 1 << 20)
                .unwrap();
            let mut body = Vec::new();
            frame(
                &mut body,
                &proto::DownloadPackResponse {
                    body: Some(
                        proto::DownloadPackHeader {
                            total_bytes: Some(bytes.len() as u64),
                            ..Default::default()
                        }
                        .into(),
                    ),
                    ..Default::default()
                },
            );
            frame(
                &mut body,
                &proto::DownloadPackResponse {
                    body: Some(
                        proto::PackChunk {
                            pack_id: Some(key.to_vec()),
                            offset: Some(0),
                            data: Some(bytes),
                            last: Some(true),
                            ..Default::default()
                        }
                        .into(),
                    ),
                    ..Default::default()
                },
            );
            body.push(2);
            body.extend(2u32.to_be_bytes());
            body.extend(b"{}");
            body
        })
        .create();
    Fixture {
        server,
        _mocks: vec![info_mock, read_mock, list_mock, download_mock],
        calls,
        tip,
    }
}
fn check(advertised: bool) {
    for client_backend in [false, true] {
        let fixture = fixture(advertised);
        let temp = tempfile::tempdir().unwrap();
        let url = format!("kit+{}/default", fixture.server.url());
        let descriptor = kit_sync::CloneRemote {
            name: "origin".into(),
            url: url.clone(),
            kind: "http".into(),
        };
        let layout = kit_sync::init_clone_dir(temp.path(), &descriptor).unwrap();
        let mut options = kit_sync::SyncOptions::default();
        options.remote_url.clone_from(&url);
        let run = |source: &dyn kit_sync::RemoteSource| {
            assert_eq!(source.supports_attestations(), advertised);
            kit_sync::fetch(
                temp.path(),
                source,
                "origin",
                &options,
                &kit_sync::NoopObserver,
            )
            .unwrap()
        };
        let report = if client_backend {
            let http = kit_sync::NativeHttp::new().unwrap();
            let client = kit_client::Client::anonymous(
                &http,
                kit_client::Destination::new(fixture.server.url(), "default".into()).unwrap(),
            );
            run(&kit_sync::ClientSource::new(&client, &http))
        } else {
            let tx = kit_transport_connect::ConnectTransport::connect(&url).unwrap();
            run(&kit_sync::TransportSource::new(&tx))
        };
        assert_eq!(report.branches_fetched, 1);
        assert_eq!(
            kit_core::refs::read_remote_ref(&layout, "origin", "main").unwrap(),
            Some(fixture.tip)
        );
        let calls = fixture.calls.lock().unwrap();
        let snapshot = calls
            .iter()
            .position(|call| call == &format!("read:{ATTESTMAP_REF}"));
        if advertised {
            assert_eq!(report.attestations_stored, 1);
            assert!(report.attestation_warnings.is_empty());
            let listing = calls
                .iter()
                .position(|call| call == "list:refs/heads/")
                .unwrap();
            assert!(snapshot.unwrap() < listing);
            assert_eq!(
                kit_attest::store::list(&layout, &fixture.tip)
                    .unwrap()
                    .len(),
                1
            );
        } else {
            assert_eq!(report.attestations_stored, 0);
            assert_eq!(report.attestation_warnings.len(), 1);
            assert!(snapshot.is_none());
            assert!(
                kit_attest::store::list(&layout, &fixture.tip)
                    .unwrap()
                    .is_empty()
            );
        }
    }
}
#[test]
fn connect_without_attestation_capability_warns_once_and_still_fetches_code() {
    check(false);
}
#[test]
fn connect_with_attestation_capability_fetches_the_snapshot_before_code_listing() {
    check(true);
}
