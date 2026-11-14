//! Push a branch to a transport and read the remote back.
#![cfg(all(
    feature = "sync",
    feature = "transport-connect",
    feature = "transport-file"
))]
#![allow(clippy::unwrap_used)] // unwrap is the assertion in tests

use kit_core::hash::Hash;
use kit_core::layout::RepoLayout;
use kit_core::object::{Commit, Identity, Object, Tree};
use kit_core::protocol::Transport as _;
use kit_core::refs::RefWriteCondition;
use kit_core::serialize;
use kit_core::store::ObjectStore;
use libkit::transfer::{Error, push_branch, push_branch_with_depth};
use libkit::transport::file::FileTransport;

fn commit(store: &ObjectStore, parents: Vec<Hash>, message: &[u8]) -> Hash {
    let tree = store
        .write(&serialize::serialize(&Object::Tree(Tree { entries: vec![] })).unwrap())
        .unwrap();
    let commit = Commit::new_unannotated(
        tree,
        parents,
        Identity::ed25519([1; 32]),
        [1; 32],
        message.to_vec(),
        0,
        [0; 64],
    );
    store
        .write(&serialize::serialize(&Object::Commit(commit)).unwrap())
        .unwrap()
}

fn store() -> (tempfile::TempDir, ObjectStore) {
    let dir = tempfile::tempdir().unwrap();
    let store = ObjectStore::init(&RepoLayout::single(dir.path())).unwrap();
    (dir, store)
}

#[test]
fn push_branch_with_depth_moves_the_branch_and_refuses_a_stale_condition() {
    let (_dir, store) = store();
    let first = commit(&store, vec![], b"first");
    let second = commit(&store, vec![first], b"second");
    let third = commit(&store, vec![second], b"third");
    let remote_dir = tempfile::tempdir().unwrap();
    let remote = FileTransport::new(remote_dir.path());

    push_branch_with_depth(
        &remote,
        &store,
        "main",
        first,
        RefWriteCondition::Missing,
        2,
    )
    .unwrap();
    assert_eq!(remote.read_ref("refs/heads/main").unwrap(), Some(first));

    push_branch_with_depth(
        &remote,
        &store,
        "main",
        second,
        RefWriteCondition::Match(first),
        2,
    )
    .unwrap();
    assert_eq!(remote.read_ref("refs/heads/main").unwrap(), Some(second));

    // The condition names a head the remote no longer has: the push fails
    // and the head stays.
    let stale = push_branch_with_depth(
        &remote,
        &store,
        "main",
        third,
        RefWriteCondition::Match(first),
        2,
    );
    assert!(
        matches!(&stale, Err(Error::NonFastForwardPush { branch }) if branch == "main"),
        "{stale:?}"
    );
    assert_eq!(remote.read_ref("refs/heads/main").unwrap(), Some(second));

    // The default depth pushes the same way.
    push_branch(
        &remote,
        &store,
        "main",
        third,
        RefWriteCondition::Match(second),
    )
    .unwrap();
    assert_eq!(remote.read_ref("refs/heads/main").unwrap(), Some(third));
}
