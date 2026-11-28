//! `DownloadWindow` over the ssh session (SPEC-SHALLOW §8): the server
//! advertises it, answers with packs and a boundary that a client accepts,
//! and refuses a request it cannot serve with one error frame.
#![allow(clippy::unwrap_used, clippy::unnecessary_wraps)] // unwrap is the assertion; a frame body is an Option

mod common;

use common::*;
use kit_core::hash::{Hash, hash};
use kit_core::layout::RepoLayout;
use kit_core::object::{Blob, Commit, EntryMode, Identity, Object, Tree, TreeEntry};
use kit_core::pack::{PackReader, PackSpool, PackWriter};
use kit_core::protocol::PackKey;
use kit_core::serialize;
use kit_core::shallow;
use kit_core::store::ObjectStore;
use kit_rpc::kit::rpc::v1::ErrorCode;
use kit_rpc::kit::rpc::v1::ssh::{DownloadWindow, SshFrame};
use kit_serve::{SessionConfig, SessionEnd};

fn put(store: &ObjectStore, object: &Object) -> Hash {
    store.write(&serialize::serialize(object).unwrap()).unwrap()
}

/// A line of `n` commits, each pushed as its own raw pack.
fn seeded(fx: &Fixture, n: usize) -> Vec<Hash> {
    let work = tempfile::tempdir().unwrap();
    let store = ObjectStore::init(&RepoLayout::single(work.path())).unwrap();
    let mut commits: Vec<Hash> = Vec::new();
    let mut packs = Vec::new();
    for i in 0..n {
        let blob = put(
            &store,
            &Object::Blob(Blob {
                data: format!("{i}\n").into_bytes(),
            }),
        );
        let tree = put(
            &store,
            &Object::Tree(Tree {
                entries: vec![TreeEntry {
                    name: b"f".to_vec(),
                    mode: EntryMode::Blob,
                    object_hash: blob,
                }],
            }),
        );
        let commit = put(
            &store,
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
        );
        let mut writer = PackWriter::new_raw_only();
        for id in [blob, tree, commit] {
            writer.push_raw(id, &store.read(&id).unwrap()).unwrap();
        }
        packs.push(writer.finish().unwrap());
        commits.push(commit);
    }
    let refs: Vec<&[u8]> = packs.iter().map(Vec::as_slice).collect();
    fx.seed(&[], &refs);
    commits
}

fn request(tips: &[Hash], depth: u32, have: &[Hash]) -> Option<Body> {
    Some(Body::DownloadWindow(Box::new(DownloadWindow {
        tips: tips.iter().map(|h| h.to_vec()).collect(),
        depth: Some(depth),
        have: have.iter().map(|h| h.to_vec()).collect(),
        ..Default::default()
    })))
}

/// Read a window reply into `store` as a client does, and return the
/// boundary the server listed.
fn receive(frames: &[SshFrame], store: &ObjectStore) -> Vec<Hash> {
    let mut frames = frames.iter();
    loop {
        match &frames.next().unwrap().body {
            Some(Body::DownloadWindowPack(header)) => {
                let id = header.pack_id.clone().unwrap();
                let total = header.total_bytes.unwrap();
                let mut bytes = Vec::new();
                loop {
                    let Some(Body::PackChunk(c)) = &frames.next().unwrap().body else {
                        panic!("a pack's chunks follow its header");
                    };
                    assert_eq!(c.pack_id.as_deref(), Some(id.as_slice()));
                    assert_eq!(c.offset, Some(bytes.len() as u64));
                    bytes.extend_from_slice(c.data.as_deref().unwrap());
                    if c.last.unwrap() {
                        break;
                    }
                }
                assert_eq!(bytes.len() as u64, total);
                let key = PackKey::from_hash(<Hash>::try_from(id.as_slice()).unwrap());
                assert_eq!(hash(&bytes), *key.as_bytes(), "a pack's id is its digest");
                let mut spool = PackSpool::create(&store.spool_dir(), total).unwrap();
                spool.begin(Some(total)).unwrap();
                spool.write(&bytes).unwrap();
                PackReader::read_verified(&spool.finish(&key).unwrap(), store).unwrap();
            }
            Some(Body::DownloadWindowBoundary(b)) => {
                assert!(frames.next().is_none(), "the boundary ends the reply");
                return b
                    .commits
                    .iter()
                    .map(|id| <Hash>::try_from(id.as_slice()).unwrap())
                    .collect();
            }
            other => panic!("unexpected frame {other:?}"),
        }
    }
}

#[test]
fn the_server_advertises_windows() {
    let fx = Fixture::new();
    let mut sink = VecSink::default();
    let end = fx.serve(&mut script([]), &mut sink, &SessionConfig::new(SERVER_ID));
    assert_eq!(end, SessionEnd::Clean);
    let Some(Body::HelloResponse(resp)) = &sink.frames[0].body else {
        panic!("expected HelloResponse");
    };
    assert_eq!(resp.download_window, Some(true));
}

#[test]
fn a_window_reply_is_what_the_client_checks_for() {
    let fx = Fixture::new();
    let c = seeded(&fx, 5);
    let (end, frames) = fx.run([request(&[c[4]], 2, &[])]);
    assert_eq!(end, SessionEnd::Clean);

    let work = tempfile::tempdir().unwrap();
    let store = ObjectStore::init(&RepoLayout::single(work.path())).unwrap();
    let listed = receive(&frames, &store);
    assert_eq!(listed, vec![c[3]]);
    let window = shallow::check_received(&store, &[c[4]], 2, &listed).unwrap();
    assert_eq!(window.commits, [c[3], c[4]].into_iter().collect());
    assert!(store.read(&c[2]).is_err(), "nothing beyond the window");
}

#[test]
fn a_held_commit_is_not_sent_again() {
    let fx = Fixture::new();
    let c = seeded(&fx, 3);
    let (_, all) = fx.run([request(&[c[2]], 3, &[])]);
    let (_, less) = fx.run([request(&[c[2]], 3, &[c[1]])]);
    let bytes = |frames: &[SshFrame]| -> usize {
        frames
            .iter()
            .filter_map(|f| match &f.body {
                Some(Body::PackChunk(c)) => c.data.as_ref().map(Vec::len),
                _ => None,
            })
            .sum()
    };
    assert!(bytes(&less) < bytes(&all));
}

#[test]
fn a_window_the_server_cannot_serve_is_one_error_frame() {
    let fx = Fixture::new();
    let c = seeded(&fx, 2);
    let cases = [
        (
            request(&[[9; 32]], 1, &[]),
            ErrorCode::KeyNotFound,
            "window commit not found",
        ),
        (
            request(&[c[1]], 0, &[]),
            ErrorCode::InvalidRequest,
            "a window depth is from 1 to 2147483647",
        ),
        (
            request(&[], 1, &[]),
            ErrorCode::InvalidRequest,
            "a window request names from 1 to 1,000 tips",
        ),
        (
            Some(Body::DownloadWindow(Box::new(DownloadWindow {
                tips: vec![vec![1; 31]],
                depth: Some(1),
                ..Default::default()
            }))),
            ErrorCode::InvalidRequest,
            "a window commit id is 32 bytes",
        ),
    ];
    for (body, code, message) in cases {
        let (end, frames) = fx.run([body, read_ref("refs/heads/main")]);
        assert_eq!(end, SessionEnd::Clean);
        assert_eq!(frames.len(), 2, "{message}: {frames:?}");
        assert_error(&frames[0], code, message);
        assert!(
            matches!(frames[1].body, Some(Body::ReadRefResponse(_))),
            "the session carries on"
        );
    }
}
