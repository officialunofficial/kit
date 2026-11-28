//! The client side of a shallow fetch: receiving a window and refusing a
//! response that does not make the window it claims (SPEC-SHALLOW §8.2).
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::collections::BTreeSet;

use kit_core::hash::Hash;
use kit_core::layout::RepoLayout;
use kit_core::object::{Blob, Commit, EntryMode, Identity, Object, Tree, TreeEntry};
use kit_core::pack::PackWriter;
use kit_core::protocol::{
    PackBody, PackKey, PackSink, RefWriteCondition, SHALLOW_UNSUPPORTED, Transport, TransportError,
    TransportResult, WindowRequest, WindowSink,
};
use kit_core::refs::Ref;
use kit_core::serialize;
use kit_core::shallow::{self, ReceivedError};
use kit_core::store::ObjectStore;
use kit_sync::{WindowFetchError, receive_window};
use tempfile::TempDir;

fn store() -> (TempDir, ObjectStore) {
    let d = TempDir::new().unwrap();
    let s = ObjectStore::init(&RepoLayout::single(d.path())).unwrap();
    (d, s)
}

fn put(store: &ObjectStore, object: &Object) -> Hash {
    store.write(&serialize::serialize(object).unwrap()).unwrap()
}

/// A line of `n` commits, each with one file of its own content. Oldest
/// first.
fn line(store: &ObjectStore, n: usize) -> Vec<Hash> {
    let mut out: Vec<Hash> = Vec::new();
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
        out.push(put(
            store,
            &Object::Commit(Commit {
                tree_hash: tree,
                parents: out.last().copied().into_iter().collect(),
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
    out
}

fn tree_of(store: &ObjectStore, commit: &Hash) -> Hash {
    match store.read_object(commit).unwrap() {
        Object::Commit(c) => c.tree_hash,
        _ => unreachable!(),
    }
}

/// How the test server answers.
#[derive(Clone, Copy)]
enum Answer {
    Honest,
    /// Lists one more commit in the boundary than the window has.
    ExtraBoundary(Hash),
    /// Leaves one object out of the packs.
    Drop(Hash),
}

/// A remote that builds windows from an object store, as a server that
/// builds packs does.
struct WindowServer {
    store: ObjectStore,
    answer: Answer,
}

impl Transport for WindowServer {
    fn supports_download_window(&self) -> bool {
        true
    }

    fn download_window(
        &self,
        request: &WindowRequest,
        sink: &mut dyn WindowSink,
    ) -> TransportResult<Vec<Hash>> {
        request.validate()?;
        let tips: Vec<(Hash, u32)> = request.tips.iter().map(|t| (*t, request.depth)).collect();
        let window = shallow::window_in(&self.store, &tips).unwrap();
        let mut objects = shallow::window_objects(&self.store, &window, &request.have).unwrap();
        if let Answer::Drop(id) = self.answer {
            objects.remove(&id);
        }
        let mut writer = PackWriter::new_raw_only();
        for id in &objects {
            writer.push_raw(*id, &self.store.read(id).unwrap()).unwrap();
        }
        let (pack, id) = writer.finish_with_key().unwrap();
        let key = PackKey::from_hash(id);
        sink.begin_pack(&key, pack.len() as u64)?;
        for chunk in pack.chunks(1000) {
            sink.write(chunk)?;
        }
        sink.end_pack()?;
        let mut boundary: Vec<Hash> = window.boundary.iter().copied().collect();
        if let Answer::ExtraBoundary(id) = self.answer {
            boundary.push(id);
        }
        Ok(boundary)
    }

    fn upload_pack(&self, _: &dyn PackBody, _: &PackKey, _: Option<&str>) -> TransportResult<()> {
        Err(TransportError::ProtocolError)
    }
    fn download_pack(
        &self,
        _: &PackKey,
        _: Option<&str>,
        _: &mut dyn PackSink,
    ) -> TransportResult<()> {
        Err(TransportError::ProtocolError)
    }
    fn pack_exists(&self, _: &PackKey, _: Option<&str>) -> TransportResult<bool> {
        Ok(false)
    }
    fn update_ref(&self, _: &str, _: RefWriteCondition, _: &Hash) -> TransportResult<()> {
        Err(TransportError::ProtocolError)
    }
    fn delete_ref(&self, _: &str, _: &Hash) -> TransportResult<()> {
        Err(TransportError::ProtocolError)
    }
    fn read_ref(&self, _: &str) -> TransportResult<Option<Hash>> {
        Ok(None)
    }
    fn list_refs(&self, _: &str) -> TransportResult<Vec<Ref>> {
        Ok(vec![])
    }
}

fn server(
    n: usize,
    answer: impl FnOnce(&ObjectStore, &[Hash]) -> Answer,
) -> (TempDir, WindowServer, Vec<Hash>) {
    let (d, s) = store();
    let c = line(&s, n);
    let answer = answer(&s, &c);
    (d, WindowServer { store: s, answer }, c)
}

fn request(tip: Hash, depth: u32) -> WindowRequest {
    WindowRequest {
        tips: vec![tip],
        depth,
        have: vec![],
    }
}

#[test]
fn an_honest_window_is_received_and_checked() {
    let (_sd, remote, c) = server(5, |_, _| Answer::Honest);
    let (_cd, local) = store();
    let window = receive_window(&remote, &local, &request(c[4], 2)).unwrap();
    assert_eq!(window.commits, BTreeSet::from([c[3], c[4]]));
    assert_eq!(window.boundary, shallow::Boundary::new([c[3]]));
    for commit in &window.commits {
        assert!(local.read_object(commit).is_ok());
        assert!(local.read_object(&tree_of(&local, commit)).is_ok());
    }
    assert!(
        local.read_object(&c[2]).is_err(),
        "nothing beyond the boundary"
    );
}

#[test]
fn a_boundary_list_that_differs_is_refused() {
    let (_sd, remote, c) = server(5, |_, c| Answer::ExtraBoundary(c[4]));
    let (_cd, local) = store();
    let err = receive_window(&remote, &local, &request(c[4], 2)).unwrap_err();
    assert!(
        matches!(
            err,
            WindowFetchError::Received(ReceivedError::BoundaryMismatch)
        ),
        "{err}"
    );
}

#[test]
fn a_pack_that_misses_part_of_a_closure_is_refused() {
    let (_sd, remote, c) = server(5, |s, c| Answer::Drop(tree_of(s, &c[3])));
    let (_cd, local) = store();
    let err = receive_window(&remote, &local, &request(c[4], 2)).unwrap_err();
    assert!(
        matches!(
            err,
            WindowFetchError::Received(ReceivedError::Incomplete(_))
        ),
        "{err}"
    );
}

#[test]
fn a_held_commit_is_not_sent_again() {
    let (_sd, remote, c) = server(5, |_, _| Answer::Honest);
    let (_cd, local) = store();
    receive_window(&remote, &local, &request(c[3], 1)).unwrap();
    let deeper = WindowRequest {
        tips: vec![c[4]],
        depth: 3,
        have: vec![c[3]],
    };
    let window = receive_window(&remote, &local, &deeper).unwrap();
    assert_eq!(window.commits, BTreeSet::from([c[2], c[3], c[4]]));
}

#[test]
fn storage_that_only_holds_packs_cannot_serve_a_window() {
    let (_cd, local) = store();
    let memory = kit_transport_memory::MemoryTransport::default();
    let err = receive_window(&memory, &local, &request([1; 32], 1)).unwrap_err();
    assert!(
        matches!(&err, WindowFetchError::Transport(TransportError::Unsupported(m)) if *m == SHALLOW_UNSUPPORTED),
        "{err}"
    );
    assert_eq!(err.to_string(), SHALLOW_UNSUPPORTED);
}

#[test]
fn a_request_outside_the_limits_is_refused_before_it_is_sent() {
    let (_sd, remote, c) = server(2, |_, _| Answer::Honest);
    let (_cd, local) = store();
    for bad in [
        request(c[1], 0),
        request(c[1], shallow::MAX_DEPTH + 1),
        WindowRequest {
            tips: vec![],
            depth: 1,
            have: vec![],
        },
        WindowRequest {
            tips: vec![c[1]; 1_001],
            depth: 1,
            have: vec![],
        },
        WindowRequest {
            tips: vec![c[1]],
            depth: 1,
            have: vec![c[0]; 1_001],
        },
    ] {
        let err = receive_window(&remote, &local, &bad).unwrap_err();
        assert!(
            matches!(
                err,
                WindowFetchError::Transport(TransportError::Unsupported(_))
            ),
            "{err}"
        );
    }
}
