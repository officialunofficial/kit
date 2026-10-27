//! A repository on disk, a key, and helpers that the operation tests share.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in tests
#![allow(dead_code)] // each test file uses part of the helpers

use std::fs;
use std::path::PathBuf;

use kit_core::hash::Hash;
use kit_core::index::{self, EntryStatus, IndexEntry};
use kit_core::layout::RepoLayout;
use kit_core::object::{Blob, Commit, EntryMode, Identity, Object, Tree, TreeEntry};
use kit_core::refs;
use kit_core::serialize;
use kit_core::sign::{self, KeyPair};
use kit_core::store::ObjectStore;
use kit_core::worktree;
use libkit::signing::{Error, Signer, Signing};
use libkit::sync::worktree::restore_worktree_and_index;

pub(crate) struct Fixture {
    pub(crate) dir: tempfile::TempDir,
    pub(crate) layout: RepoLayout,
    pub(crate) store: ObjectStore,
}

/// An empty repository whose `HEAD` names `main`.
pub(crate) fn init() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let layout = RepoLayout::single(dir.path());
    let store = ObjectStore::init(&layout).unwrap();
    refs::init(&layout).unwrap();
    refs::write_head_branch(&layout, "main").unwrap();
    Fixture { dir, layout, store }
}

impl Fixture {
    pub(crate) fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    pub(crate) fn read(&self, name: &str) -> String {
        fs::read_to_string(self.path(name)).unwrap()
    }

    pub(crate) fn write(&self, name: &str, text: &str) {
        fs::write(self.path(name), text).unwrap();
    }

    /// A commit with these files and no signature.
    pub(crate) fn commit(
        &self,
        files: &[(&str, &str)],
        parents: &[Hash],
        message: &str,
        time: u64,
    ) -> Hash {
        let entries: Vec<TreeEntry> = files
            .iter()
            .map(|(name, text)| TreeEntry {
                name: name.as_bytes().to_vec(),
                mode: EntryMode::Blob,
                object_hash: self
                    .store
                    .write(
                        &serialize::serialize(&Object::Blob(Blob {
                            data: text.as_bytes().to_vec(),
                        }))
                        .unwrap(),
                    )
                    .unwrap(),
            })
            .collect();
        let tree = self
            .store
            .write(&serialize::serialize(&Object::Tree(Tree { entries })).unwrap())
            .unwrap();
        let commit = Commit::new_unannotated(
            tree,
            parents.to_vec(),
            Identity::ed25519([9; 32]),
            [9; 32],
            message.as_bytes().to_vec(),
            time,
            [0; 64],
        );
        self.store
            .write(&serialize::serialize(&Object::Commit(commit)).unwrap())
            .unwrap()
    }

    /// Point `branch` at `commit`, check it out, and put its files in the tree.
    pub(crate) fn checkout(&self, branch: &str, commit: Hash) {
        refs::write_ref(&self.layout, branch, &commit).unwrap();
        refs::write_head_branch(&self.layout, branch).unwrap();
        let Object::Commit(c) = self.store.read_object(&commit).unwrap() else {
            panic!("not a commit");
        };
        restore_worktree_and_index(&self.layout, &self.store, c.tree_hash).unwrap();
    }

    /// Stage the current content of a file, as `kit add` does.
    pub(crate) fn stage(&self, name: &str) {
        let data = fs::read(self.path(name)).unwrap();
        let object_hash = worktree::store_file_object(&self.store, &data).unwrap();
        let mut idx = index::read_index(&self.layout).unwrap();
        idx.upsert_entry(IndexEntry {
            path: name.to_owned(),
            status: EntryStatus::Blob,
            object_hash,
            mtime_ns: 0,
            size: 0,
            ino: 0,
            ctime_ns: 0,
        });
        index::write_index(&self.layout, &idx).unwrap();
    }

    pub(crate) fn commit_object(&self, h: Hash) -> Commit {
        match self.store.read_object(&h).unwrap() {
            Object::Commit(c) => c,
            other => panic!("not a commit: {other:?}"),
        }
    }

    /// The files of a commit, as `(name, text)` pairs in tree order.
    pub(crate) fn files_of(&self, h: Hash) -> Vec<(String, String)> {
        let Object::Tree(tree) = self
            .store
            .read_object(&self.commit_object(h).tree_hash)
            .unwrap()
        else {
            panic!("not a tree");
        };
        tree.entries
            .iter()
            .map(|e| {
                let Object::Blob(b) = self.store.read_object(&e.object_hash).unwrap() else {
                    panic!("not a blob");
                };
                (
                    String::from_utf8(e.name.clone()).unwrap(),
                    String::from_utf8(b.data).unwrap(),
                )
            })
            .collect()
    }
}

/// Signs with a fixed key.
pub(crate) struct TestSigning;

struct TestSigner(KeyPair);

impl Signing for TestSigning {
    fn open(&self, _layout: &RepoLayout) -> Result<Box<dyn Signer>, Error> {
        Ok(Box::new(TestSigner(KeyPair::from_seed([7; 32]))))
    }
}

impl Signer for TestSigner {
    fn public_key(&self) -> Result<[u8; 32], Error> {
        Ok(self.0.public.0)
    }

    fn author(&self) -> Result<Identity, Error> {
        Ok(Identity::ed25519(self.0.public.0))
    }

    fn sign_commit(&mut self, commit: &Commit) -> Result<[u8; 64], Error> {
        Ok(sign::sign_commit(commit, &self.0).unwrap().0)
    }
}
