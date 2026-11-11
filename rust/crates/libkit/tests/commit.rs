//! Make a signed commit from the index.
#![cfg(feature = "sync")]
#![allow(clippy::unwrap_used)] // unwrap is the assertion in tests

use std::fs;
use std::io;
use std::path::PathBuf;

use kit_core::hash::Hash;
use kit_core::index::{self, Index};
use kit_core::layout::RepoLayout;
use kit_core::object::{Commit, Identity, Object, Tree};
use kit_core::ops::conflict_state::{self, ConflictRecord, MergeState};
use kit_core::ops::recovery;
use kit_core::refs;
use kit_core::serialize;
use kit_core::sign::KeyPair;
use kit_core::store::ObjectStore;
use libkit::add::{self, Choice, HunkChooser, PatchHunk};
use libkit::commit::{self, Created, Error, Pending, Request};
use libkit::repo::StoreConfig;
use libkit::signer::Signer;
use libkit::{Environment, NoopObserver};

struct NoChooser;

impl HunkChooser for NoChooser {
    fn choose(&mut self, path: &str, _hunks: &[PatchHunk]) -> io::Result<Choice> {
        panic!("the chooser must not run for {path}");
    }
}

struct Fixture {
    _dir: tempfile::TempDir,
    root: PathBuf,
    layout: RepoLayout,
    store: ObjectStore,
    signer: Signer,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let layout = RepoLayout::single(&root);
        let store = ObjectStore::init(&layout).unwrap();
        refs::init(&layout).unwrap();
        refs::write_head_branch(&layout, "main").unwrap();
        Self {
            _dir: dir,
            root,
            layout,
            store,
            signer: Signer::File(KeyPair::from_seed([9; 32])),
        }
    }

    /// Write `content` to `path` and stage the whole tree.
    fn stage(&self, path: &str, content: &str) {
        let full = self.root.join(path);
        fs::create_dir_all(full.parent().unwrap()).unwrap();
        fs::write(full, content).unwrap();
        let environment = Environment::default();
        add::stage(
            &self.layout,
            &StoreConfig {
                environment: &environment,
                observer: &NoopObserver,
            },
            &self.root,
            &add::Request {
                all: false,
                update: false,
                patch: false,
                force: false,
                dry_run: false,
                paths: &[".".to_owned()],
            },
            &mut NoChooser,
            &NoopObserver,
            &NoopObserver,
        )
        .unwrap();
    }

    fn public(&self) -> [u8; 32] {
        self.signer.public_key().unwrap()
    }

    fn make(&mut self, message: &str, all: bool, pending: &Pending) -> Result<Created, Error> {
        self.make_gated(message, all, pending, &|_| Ok(()))
    }

    fn make_gated(
        &mut self,
        message: &str,
        all: bool,
        pending: &Pending,
        gate: &dyn Fn(&[ConflictRecord]) -> Result<(), String>,
    ) -> Result<Created, Error> {
        let public = self.public();
        commit::create(
            &self.layout,
            &self.store,
            pending,
            &Request {
                message,
                author: Identity::ed25519(public),
                signer_public: public,
                all,
            },
            &mut self.signer,
            gate,
            &NoopObserver,
        )
    }

    fn begin(&self, amend: bool) -> Result<Pending, Error> {
        commit::begin(&self.layout, &self.store, amend)
    }

    fn commit(&mut self, message: &str) -> Created {
        let pending = self.begin(false).unwrap();
        self.make(message, false, &pending).unwrap()
    }

    fn read(&self, hash: &Hash) -> Commit {
        match self.store.read_object(hash).unwrap() {
            Object::Commit(c) => c,
            other => panic!("not a commit: {other:?}"),
        }
    }

    fn head(&self) -> Option<Hash> {
        refs::resolve_head(&self.layout).unwrap()
    }

    /// A commit that no ref names, with an empty tree.
    fn loose_commit(&self, message: &str, parents: Vec<Hash>) -> Hash {
        let tree = Object::Tree(Tree {
            entries: Vec::new(),
        });
        let tree_hash = self
            .store
            .write(&serialize::serialize(&tree).unwrap())
            .unwrap();
        let commit = Object::Commit(Commit::new_unannotated(
            tree_hash,
            parents,
            Identity::ed25519([2; 32]),
            [2; 32],
            message.as_bytes().to_vec(),
            0,
            [0; 64],
        ));
        self.store
            .write(&serialize::serialize(&commit).unwrap())
            .unwrap()
    }
}

#[test]
fn the_first_commit_is_a_signed_root_on_the_branch() {
    let mut f = Fixture::new();
    f.stage("a.txt", "one\n");
    let created = f.commit("first");
    assert!(created.is_root());
    assert!(!created.is_merge());
    assert_eq!(created.branch.as_deref(), Some("main"));
    assert_eq!(created.base_tree, None);
    assert_eq!(f.head(), Some(created.commit));

    let stored = f.read(&created.commit);
    assert_eq!(stored.message, b"first");
    assert_eq!(stored.tree_hash, created.tree);
    assert_eq!(stored.signer, f.public());
    assert_ne!(stored.signature, [0; 64], "the commit is signed");
    // The index follows the new tree.
    let idx = index::read_index(&f.layout).unwrap();
    assert!(idx.find_entry("a.txt").is_some());
}

#[test]
fn a_second_commit_builds_on_head_and_shows_its_change_against_it() {
    let mut f = Fixture::new();
    f.stage("a.txt", "one\n");
    let first = f.commit("first");
    f.stage("a.txt", "two\n");
    let second = f.commit("second");
    assert_eq!(second.parents, vec![first.commit]);
    assert_eq!(second.base_tree, Some(first.tree));
    assert_ne!(second.tree, first.tree);
    assert_eq!(f.head(), Some(second.commit));
}

#[test]
fn an_empty_index_is_refused() {
    let mut f = Fixture::new();
    index::write_index(&f.layout, &Index::new()).unwrap();
    let pending = f.begin(false).unwrap();
    let error = f.make("m", false, &pending).unwrap_err();
    assert!(matches!(error, Error::NothingStaged), "{error:?}");
    assert_eq!(
        error.to_string(),
        "nothing staged: index is empty; run `kit add <path>` (or `kit add .`) before commit"
    );
    assert_eq!(f.head(), None);
}

#[test]
fn all_stages_the_changes_of_tracked_files_first() {
    let mut f = Fixture::new();
    f.stage("a.txt", "one\n");
    let first = f.commit("first");
    fs::write(f.root.join("a.txt"), "two\n").unwrap();
    let pending = f.begin(false).unwrap();
    let second = f.make("second", true, &pending).unwrap();
    assert_ne!(second.tree, first.tree);
    assert_eq!(f.head(), Some(second.commit));
}

#[test]
fn a_plain_commit_has_no_default_message() {
    let f = Fixture::new();
    assert_eq!(f.begin(false).unwrap().default_message(), None);
}

#[test]
fn an_amend_replaces_head_and_keeps_its_parents_and_message() {
    let mut f = Fixture::new();
    f.stage("a.txt", "one\n");
    let first = f.commit("first");
    f.stage("a.txt", "two\n");
    let second = f.commit("second");

    f.stage("a.txt", "three\n");
    let pending = f.begin(true).unwrap();
    assert_eq!(pending.default_message().as_deref(), Some("second"));
    let amended = f.make("second, amended", false, &pending).unwrap();
    assert_eq!(amended.parents, vec![first.commit]);
    assert_eq!(f.head(), Some(amended.commit));
    assert_ne!(amended.commit, second.commit);

    // The replaced commit stays recoverable.
    let log = recovery::read_all(&f.layout).unwrap();
    assert_eq!(log.len(), 1, "{log:?}");
    assert_eq!(log[0].op, "amend");
    assert_eq!(log[0].superseded, second.commit);
    assert_eq!(log[0].branch, "main");
}

#[test]
fn an_amend_needs_a_commit_to_replace() {
    let f = Fixture::new();
    let error = f.begin(true).unwrap_err();
    assert!(matches!(error, Error::NothingToAmend), "{error:?}");
    assert_eq!(
        error.to_string(),
        "nothing to amend: HEAD has no commit yet"
    );
}

#[test]
fn an_amend_stops_when_head_moved_while_the_message_was_composed() {
    let mut f = Fixture::new();
    f.stage("a.txt", "one\n");
    f.commit("first");
    let pending = f.begin(true).unwrap();

    f.stage("a.txt", "two\n");
    let concurrent = f.commit("concurrent");
    f.stage("a.txt", "three\n");
    let error = f.make("amended", false, &pending).unwrap_err();
    assert!(matches!(error, Error::HeadMoved), "{error:?}");
    assert_eq!(f.head(), Some(concurrent.commit), "the branch is untouched");
}

fn start_merge(f: &Fixture, other: Hash) -> MergeState {
    let state = MergeState {
        merge_head: other,
        orig_head: f.head().unwrap(),
        message: b"Merge branch 'other'".to_vec(),
    };
    conflict_state::write_merge_state(&f.layout, &state, &[]).unwrap();
    state
}

#[test]
fn a_commit_that_concludes_a_merge_has_two_parents_and_clears_the_merge() {
    let mut f = Fixture::new();
    f.stage("a.txt", "one\n");
    let first = f.commit("first");
    let other = f.loose_commit("other", vec![]);
    start_merge(&f, other);
    f.stage("b.txt", "merged\n");

    let pending = f.begin(false).unwrap();
    assert_eq!(
        pending.default_message().as_deref(),
        Some("Merge branch 'other'")
    );
    let merged = f.make("Merge branch 'other'", false, &pending).unwrap();
    assert!(merged.is_merge());
    assert_eq!(merged.parents, vec![first.commit, other]);
    assert_eq!(
        merged.base_tree,
        Some(merged.tree),
        "a merge shows no change"
    );
    assert!(!conflict_state::is_merge_in_progress(&f.layout));
    assert_eq!(f.head(), Some(merged.commit));
}

#[test]
fn an_amend_is_refused_while_a_merge_is_in_progress() {
    let mut f = Fixture::new();
    f.stage("a.txt", "one\n");
    f.commit("first");
    let other = f.loose_commit("other", vec![]);
    start_merge(&f, other);
    let error = f.begin(true).unwrap_err();
    assert!(matches!(error, Error::AmendDuringMerge), "{error:?}");
}

#[test]
fn a_merge_that_ended_while_the_message_was_composed_stops_the_commit() {
    let mut f = Fixture::new();
    f.stage("a.txt", "one\n");
    f.commit("first");
    let other = f.loose_commit("other", vec![]);
    start_merge(&f, other);
    let pending = f.begin(false).unwrap();

    conflict_state::clear_merge_state(&f.layout).unwrap();
    f.stage("a.txt", "two\n");
    let error = f.make("m", false, &pending).unwrap_err();
    assert!(matches!(error, Error::MergeChanged), "{error:?}");
}

#[test]
fn the_gate_decides_whether_a_merge_may_conclude() {
    let mut f = Fixture::new();
    f.stage("a.txt", "one\n");
    let first = f.commit("first");
    let other = f.loose_commit("other", vec![]);
    start_merge(&f, other);
    f.stage("b.txt", "merged\n");
    let pending = f.begin(false).unwrap();

    let refuse = |_: &[ConflictRecord]| Err("conflict markers remain".to_owned());
    let error = f.make_gated("m", false, &pending, &refuse).unwrap_err();
    assert!(
        matches!(error, Error::Unresolved(ref t) if t == "conflict markers remain"),
        "{error:?}"
    );
    assert_eq!(error.to_string(), "conflict markers remain");
    assert_eq!(f.head(), Some(first.commit));
    assert!(conflict_state::is_merge_in_progress(&f.layout));
}

#[test]
fn a_plain_commit_does_not_run_the_gate() {
    let mut f = Fixture::new();
    f.stage("a.txt", "one\n");
    let pending = f.begin(false).unwrap();
    let refuse = |_: &[ConflictRecord]| Err("never".to_owned());
    f.make_gated("m", false, &pending, &refuse).unwrap();
}
