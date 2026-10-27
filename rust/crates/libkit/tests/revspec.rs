//! Revision resolution, branch moves and locks through an open `Repo`.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in tests

use kit_core::layout::RepoLayout;
use kit_core::object::{Commit, Identity, Object};
use kit_core::observer::NoopObserver;
use kit_core::refs::{self, RefWriteCondition};
use kit_core::serialize;
use kit_core::store::ObjectStore;
use libkit::{Environment, Repo, head, lock, revspec};

fn commit(store: &ObjectStore, parents: Vec<[u8; 32]>, seed: u8) -> [u8; 32] {
    let commit = Commit::new_unannotated(
        [seed; 32],
        parents,
        Identity::ed25519([seed; 32]),
        [seed; 32],
        vec![seed],
        u64::from(seed),
        [0; 64],
    );
    store
        .write(&serialize::serialize(&Object::Commit(commit)).unwrap())
        .unwrap()
}

#[test]
fn a_repo_resolves_revisions_moves_head_and_locks_by_its_own_layout() {
    let dir = tempfile::tempdir().unwrap();
    let layout = RepoLayout::single(dir.path());
    let store = ObjectStore::init(&layout).unwrap();
    refs::init(&layout).unwrap();
    let root = commit(&store, vec![], 1);
    let tip = commit(&store, vec![root], 2);
    refs::write_ref(&layout, "main", &root).unwrap();

    let repo = Repo::open(dir.path(), &Environment::new(dir.path())).unwrap();
    assert_eq!(
        revspec::resolve_revision(repo.store(), repo.layout(), "HEAD").unwrap(),
        root
    );

    let guard = lock::acquire_worktree(repo.layout(), &NoopObserver).unwrap();
    head::advance(repo.layout(), &tip, RefWriteCondition::Match(root)).unwrap();
    drop(guard);

    assert_eq!(
        revspec::resolve_revision(repo.store(), repo.layout(), "HEAD").unwrap(),
        tip
    );
    assert_eq!(
        revspec::resolve_revision(repo.store(), repo.layout(), "main~1").unwrap(),
        root
    );
}
