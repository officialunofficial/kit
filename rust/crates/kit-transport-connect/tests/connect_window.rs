//! A shallow window over Connect (SPEC-SHALLOW §8.2): the client follows
//! `GetServerInfo`, streams the packs of a `DownloadWindow` reply into the
//! store and checks the window before anything is named.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

#[path = "support/pack_server.rs"]
mod pack_server;

use kit_core::hash::Hash;
use kit_core::layout::RepoLayout;
use kit_core::object::{Blob, Commit, EntryMode, Identity, Object, Tree, TreeEntry};
use kit_core::protocol::{SHALLOW_UNSUPPORTED, Transport, TransportError, WindowRequest};
use kit_core::serialize;
use kit_core::shallow::{self, ReceivedError};
use kit_core::store::ObjectStore;
use kit_sync::{WindowFetchError, receive_window};
use kit_transport_connect::ConnectTransport;
use pack_server::{CannedWindow, PackServer};

fn put(store: &ObjectStore, object: &Object) -> Hash {
    store.write(&serialize::serialize(object).unwrap()).unwrap()
}

/// A line of `n` commits, each with its own one-file tree.
fn line(store: &ObjectStore, n: usize) -> Vec<Hash> {
    let mut commits: Vec<Hash> = Vec::new();
    for i in 0..n {
        let blob = put(
            store,
            &Object::Blob(Blob {
                data: format!("{i}\n").into_bytes(),
            }),
        );
        let tree = put(
            store,
            &Object::Tree(Tree {
                entries: vec![TreeEntry {
                    name: b"f".to_vec(),
                    mode: EntryMode::Blob,
                    object_hash: blob,
                }],
            }),
        );
        commits.push(put(
            store,
            &Object::Commit(Commit {
                tree_hash: tree,
                parents: commits.last().copied().into_iter().collect(),
                author: Identity::ed25519([0; 32]),
                signer: [0; 32],
                message: format!("c{i}").into_bytes(),
                timestamp: i as u64,
                message_hash: [0; 32],
                content_digest: [0; 32],
                signature: [0; 64],
            }),
        ));
    }
    commits
}

/// The honest reply to the window of `tip` at `depth`.
fn canned(store: &ObjectStore, tip: Hash, depth: u32) -> CannedWindow {
    let window = shallow::window_in(store, &[(tip, depth)]).unwrap();
    let packs = shallow::window_packs(store, &window, &[])
        .unwrap()
        .into_iter()
        .map(|(key, bytes)| (*key.as_bytes(), bytes))
        .collect();
    (packs, window.boundary.iter().copied().collect())
}

fn empty_store(dir: &std::path::Path) -> ObjectStore {
    ObjectStore::init(&RepoLayout::single(dir)).unwrap()
}

#[test]
fn a_window_arrives_over_connect_and_is_checked() {
    let dir = tempfile::tempdir().unwrap();
    let full = empty_store(&dir.path().join("full"));
    let c = line(&full, 5);
    let server = PackServer::start(&dir.path().join("server"));
    server.set_window(canned(&full, c[4], 2));
    let transport = ConnectTransport::connect_for_test(server.origin().parse().unwrap());
    assert!(transport.supports_download_window());

    let store = empty_store(&dir.path().join("client"));
    let request = WindowRequest {
        tips: vec![c[4]],
        depth: 2,
        have: vec![],
    };
    let window = receive_window(&transport, &store, &request).unwrap();
    assert_eq!(window.commits, [c[3], c[4]].into_iter().collect());
    assert_eq!(window.boundary.iter().copied().collect::<Vec<_>>(), [c[3]]);
    assert!(store.read(&c[2]).is_err(), "nothing beyond the window");
}

#[test]
fn a_boundary_the_packs_do_not_bear_out_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let full = empty_store(&dir.path().join("full"));
    let c = line(&full, 4);
    let server = PackServer::start(&dir.path().join("server"));
    let (packs, mut boundary) = canned(&full, c[3], 2);
    boundary.push(c[0]);
    server.set_window((packs, boundary));
    let transport = ConnectTransport::connect_for_test(server.origin().parse().unwrap());

    let store = empty_store(&dir.path().join("client"));
    let request = WindowRequest {
        tips: vec![c[3]],
        depth: 2,
        have: vec![],
    };
    assert!(matches!(
        receive_window(&transport, &store, &request),
        Err(WindowFetchError::Received(ReceivedError::BoundaryMismatch))
    ));
}

#[test]
fn a_server_that_does_not_advertise_windows_is_not_asked() {
    let dir = tempfile::tempdir().unwrap();
    let server = PackServer::start(&dir.path().join("server"));
    let transport = ConnectTransport::connect_for_test(server.origin().parse().unwrap());
    assert!(!transport.supports_download_window());
    let store = empty_store(&dir.path().join("client"));
    let request = WindowRequest {
        tips: vec![[1; 32]],
        depth: 1,
        have: vec![],
    };
    match receive_window(&transport, &store, &request) {
        Err(WindowFetchError::Transport(TransportError::Unsupported(message))) => {
            assert_eq!(message, SHALLOW_UNSUPPORTED);
        }
        other => panic!("expected the shallow refusal, got {other:?}"),
    }
}
