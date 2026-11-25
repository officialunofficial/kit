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
use kit_core::ops::merge::ConflictKind;
use kit_core::ops::pull_state::PullState;
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
                allow_empty: false,
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

/// The index file as a test sees a rewrite of it: the bytes, and the inode,
/// which a temporary file and a rename change.
#[cfg(unix)]
fn index_file(f: &Fixture) -> (Vec<u8>, u64) {
    use std::os::unix::fs::MetadataExt as _;
    let path = f.layout.index_file();
    (fs::read(&path).unwrap(), fs::metadata(path).unwrap().ino())
}

#[cfg(unix)]
#[test]
fn a_plain_commit_leaves_the_index_file_alone() {
    let mut f = Fixture::new();
    f.stage("a.txt", "one\n");
    f.commit("first");
    f.stage("b.txt", "two\n");
    f.stage("a.txt", "three\n");
    let staged = index_file(&f);

    let second = f.commit("second");
    assert_eq!(index_file(&f), staged, "the index already holds the tree");
    let idx = index::read_index(&f.layout).unwrap();
    let paths: Vec<_> = idx.entries.iter().map(|e| e.path.as_str()).collect();
    assert_eq!(paths.len(), 2, "{paths:?}");
    assert!(idx.find_entry("a.txt").is_some() && idx.find_entry("b.txt").is_some());
    assert_eq!(f.head(), Some(second.commit));
}

#[cfg(unix)]
#[test]
fn a_commit_of_a_staged_removal_rebuilds_the_index_without_it() {
    let mut f = Fixture::new();
    f.stage("a.txt", "one\n");
    f.stage("b.txt", "two\n");
    f.commit("first");
    let mut idx = index::read_index(&f.layout).unwrap();
    let removed = idx.find_entry("b.txt").unwrap();
    idx.entries[removed].status = index::EntryStatus::Removed;
    idx.entries[removed].object_hash = kit_core::hash::ZERO;
    index::write_index(&f.layout, &idx).unwrap();
    let staged = index_file(&f);

    f.commit("drop b");
    assert_ne!(index_file(&f), staged, "the tombstone is dropped");
    let idx = index::read_index(&f.layout).unwrap();
    assert!(idx.find_entry("b.txt").is_none(), "{:?}", idx.entries);
    assert!(idx.find_entry("a.txt").is_some());
}

#[cfg(unix)]
#[test]
fn an_amend_rebuilds_the_index_from_its_tree() {
    let mut f = Fixture::new();
    f.stage("a.txt", "one\n");
    f.commit("first");
    f.stage("a.txt", "two\n");
    let staged = index_file(&f);

    let pending = f.begin(true).unwrap();
    f.make("amended", false, &pending).unwrap();
    assert_ne!(
        index_file(&f).1,
        staged.1,
        "an amend writes the index again"
    );
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
    #[cfg(unix)]
    let staged = index_file(&f);

    let pending = f.begin(false).unwrap();
    assert_eq!(
        pending.default_message().as_deref(),
        Some("Merge branch 'other'")
    );
    let merged = f.make("Merge branch 'other'", false, &pending).unwrap();
    #[cfg(unix)]
    assert_ne!(index_file(&f).1, staged.1, "a merge writes the index again");
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
fn a_merge_state_over_its_own_merge_commit_is_no_merge() {
    let mut f = Fixture::new();
    f.stage("a.txt", "one\n");
    f.commit("first");
    let other = f.loose_commit("other", vec![]);
    let state = start_merge(&f, other);
    f.stage("b.txt", "merged\n");
    let pending = f.begin(false).unwrap();
    let merged = f.make("Merge branch 'other'", false, &pending).unwrap();
    // A stop after the branch moved and before the state was cleared.
    conflict_state::write_merge_state(&f.layout, &state, &[]).unwrap();
    assert!(conflict_state::is_merge_in_progress(&f.layout));

    // The state has no message to offer, and an amend is no amend of a merge.
    let pending = f.begin(false).unwrap();
    assert_eq!(pending.default_message(), None);
    assert!(f.begin(true).is_ok());
    f.stage("c.txt", "later\n");
    let later = f.make("later", false, &pending).unwrap();
    assert_eq!(
        later.parents,
        vec![merged.commit],
        "no sibling of the merge"
    );
    assert_eq!(f.head(), Some(later.commit));
    assert_eq!(f.read(&later.commit).parents, vec![merged.commit]);
    assert!(!conflict_state::is_merge_in_progress(&f.layout));
}

#[test]
fn an_amend_over_a_merge_state_that_a_stop_left_replaces_the_merge_commit() {
    let mut f = Fixture::new();
    f.stage("a.txt", "one\n");
    f.commit("first");
    let other = f.loose_commit("other", vec![]);
    let state = start_merge(&f, other);
    f.stage("b.txt", "merged\n");
    let pending = f.begin(false).unwrap();
    let merged = f.make("Merge branch 'other'", false, &pending).unwrap();
    conflict_state::write_merge_state(&f.layout, &state, &[]).unwrap();

    let pending = f.begin(true).unwrap();
    let amended = f.make("amended", false, &pending).unwrap();
    assert_eq!(
        amended.parents, merged.parents,
        "the merge keeps both parents"
    );
    assert!(!conflict_state::is_merge_in_progress(&f.layout));
}

#[test]
fn a_merge_state_over_another_head_is_still_a_merge() {
    let mut f = Fixture::new();
    f.stage("a.txt", "one\n");
    let first = f.commit("first");
    let other = f.loose_commit("other", vec![]);
    start_merge(&f, other);
    // A commit with the same parents in another order is not the merge.
    let reversed = f.loose_commit("reversed", vec![other, first.commit]);
    refs::write_ref(&f.layout, "main", &reversed).unwrap();

    let pending = f.begin(false).unwrap();
    assert_eq!(
        pending.default_message().as_deref(),
        Some("Merge branch 'other'")
    );
    assert!(matches!(f.begin(true), Err(Error::AmendDuringMerge)));
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

/// A repository whose pull stopped partway: `HEAD` is at the pulled commit,
/// which changed `a.txt` and `c.txt`, and the index holds both files from
/// before the pull.
struct StoppedPull {
    fixture: Fixture,
    first: Created,
    pulled: Created,
}

impl StoppedPull {
    fn new() -> Self {
        let mut fixture = Fixture::new();
        fixture.stage("a.txt", "one\n");
        fixture.stage("c.txt", "one\n");
        let first = fixture.commit("first");
        fixture.stage("a.txt", "two\n");
        fixture.stage("c.txt", "two\n");
        let pulled = fixture.commit("pulled");
        fixture.stage("a.txt", "one\n");
        fixture.stage("c.txt", "one\n");
        Self {
            fixture,
            first,
            pulled,
        }
    }

    /// Record the pull, as it does before it moves the branch.
    fn record(&self) {
        record_pull(&self.fixture, self.pulled.commit, self.first.tree);
    }
}

fn record_pull(fixture: &Fixture, target: Hash, before_tree: Hash) {
    fs::create_dir_all(fixture.layout.worktree_state_dir()).unwrap();
    let state = PullState {
        target,
        before_tree,
    };
    fs::write(fixture.layout.pull_head_file(), state.encode()).unwrap();
}

#[test]
fn a_commit_is_refused_while_an_interrupted_pull_has_not_finished() {
    let mut s = StoppedPull::new();
    let pending = s.fixture.begin(false).unwrap();
    s.record();
    assert!(matches!(
        s.fixture.begin(false),
        Err(Error::PullUnfinished(target)) if target == s.pulled.commit
    ));
    assert!(matches!(
        s.fixture.begin(true),
        Err(Error::PullUnfinished(_))
    ));
    // A caller that read its state before the pull stopped meets the same
    // refusal when it commits.
    assert!(matches!(
        s.fixture
            .make("would revert the pulled change", false, &pending),
        Err(Error::PullUnfinished(_))
    ));
    assert_eq!(s.fixture.head(), Some(s.pulled.commit));
}

#[test]
fn commit_all_is_refused_before_it_stages_a_half_restored_tree() {
    let mut s = StoppedPull::new();
    let pending = s.fixture.begin(false).unwrap();
    s.record();
    // The files of the pulled commit are on disk for some paths.
    fs::write(s.fixture.root.join("a.txt"), "two\n").unwrap();
    assert!(matches!(
        s.fixture.make("would record a mixture", true, &pending),
        Err(Error::PullUnfinished(_))
    ));
    let staged = index::read_index(&s.fixture.layout).unwrap();
    assert_eq!(staged.entries.len(), 2);
    assert_eq!(s.fixture.head(), Some(s.pulled.commit));
}

#[test]
fn staging_other_files_does_not_hide_an_interrupted_pull() {
    let s = StoppedPull::new();
    s.record();
    // A new file, then every file of a half-restored worktree.
    s.fixture.stage("new.txt", "work\n");
    assert!(matches!(
        s.fixture.begin(false),
        Err(Error::PullUnfinished(_))
    ));
    fs::write(s.fixture.root.join("a.txt"), "two\n").unwrap();
    s.fixture.stage("new.txt", "work\n");
    assert!(matches!(
        s.fixture.begin(false),
        Err(Error::PullUnfinished(_))
    ));
}

#[test]
fn a_commit_goes_on_once_the_index_holds_the_pulled_files() {
    let mut s = StoppedPull::new();
    s.record();
    // The restore reached the index, which it writes last, and stopped before
    // it removed the record. Staged work on top is the user's.
    s.fixture.stage("a.txt", "two\n");
    s.fixture.stage("c.txt", "two\n");
    s.fixture.stage("b.txt", "work\n");
    let pending = s.fixture.begin(false).unwrap();
    let created = s.fixture.make("work", false, &pending).unwrap();
    assert_eq!(
        s.fixture.read(&created.commit).parents,
        vec![s.pulled.commit]
    );
}

#[test]
fn a_commit_goes_on_when_the_pull_has_not_moved_head() {
    let mut s = StoppedPull::new();
    s.record();
    // `HEAD` is at the commit before the pull, as it is when the pull stopped
    // before it moved the branch.
    refs::write_ref(&s.fixture.layout, "main", &s.first.commit).unwrap();
    s.fixture.stage("b.txt", "work\n");
    let pending = s.fixture.begin(false).unwrap();
    s.fixture.make("work", false, &pending).unwrap();
}

#[test]
fn a_clone_stopped_in_its_restore_refuses_a_commit() {
    let mut f = Fixture::new();
    let empty = Object::Tree(Tree {
        entries: Vec::new(),
    });
    let before_tree = f
        .store
        .write(&serialize::serialize(&empty).unwrap())
        .unwrap();
    f.stage("a.txt", "one\n");
    let cloned = f.commit("cloned");
    // The index of a clone is written last, so it does not exist yet.
    fs::remove_file(f.layout.index_file()).unwrap();
    record_pull(&f, cloned.commit, before_tree);
    assert!(matches!(
        f.begin(false),
        Err(Error::PullUnfinished(target)) if target == cloned.commit
    ));
}

#[test]
fn a_malformed_pull_record_stops_a_commit() {
    let s = StoppedPull::new();
    fs::create_dir_all(s.fixture.layout.worktree_state_dir()).unwrap();
    fs::write(s.fixture.layout.pull_head_file(), b"short").unwrap();
    assert!(matches!(
        s.fixture.begin(false),
        Err(Error::ReadPullState(_))
    ));
}

#[test]
fn a_pull_that_only_added_a_file_is_unfinished_while_the_index_lacks_it() {
    let mut f = Fixture::new();
    f.stage("a.txt", "one\n");
    let first = f.commit("first");
    f.stage("dir/new.txt", "added\n");
    let pulled = f.commit("pulled");
    // The index of the stopped restore lacks the added file.
    let mut staged = index::read_index(&f.layout).unwrap();
    staged.remove_path("dir/new.txt").unwrap();
    index::write_index(&f.layout, &staged).unwrap();
    record_pull(&f, pulled.commit, first.tree);
    assert!(matches!(f.begin(false), Err(Error::PullUnfinished(_))));
}

#[cfg(unix)]
#[test]
fn a_pull_that_only_changed_a_mode_is_unfinished_while_the_index_holds_the_old_mode() {
    use std::os::unix::fs::PermissionsExt;

    let mut f = Fixture::new();
    f.stage("run.sh", "echo\n");
    let first = f.commit("first");
    let path = f.root.join("run.sh");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    f.stage("other.txt", "x\n");
    let pulled = f.commit("pulled");
    assert_ne!(pulled.tree, first.tree);
    // The index of the stopped restore holds the file without its mode.
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    f.stage("other.txt", "x\n");
    record_pull(&f, pulled.commit, first.tree);
    assert!(matches!(f.begin(false), Err(Error::PullUnfinished(_))));
    // A finished restore holds the mode again.
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    f.stage("other.txt", "x\n");
    f.begin(false).unwrap();
}

#[test]
fn a_merge_whose_conflict_list_is_missing_is_not_committed() {
    let mut f = Fixture::new();
    f.stage("a.txt", "one\n");
    f.commit("first");
    let other = f.loose_commit("other", vec![]);
    let state = MergeState {
        merge_head: other,
        orig_head: f.head().unwrap(),
        message: b"Merge branch 'other'".to_vec(),
    };
    let conflicts = [ConflictRecord {
        path: "a.txt".into(),
        kind: ConflictKind::ModifyModify,
        base_hash: None,
        ours_hash: None,
        theirs_hash: None,
    }];
    conflict_state::write_merge_state(&f.layout, &state, &conflicts).unwrap();
    fs::remove_file(f.layout.conflicts_file()).unwrap();
    f.stage("b.txt", "merged\n");
    let before = f.head();

    let pending = f.begin(false).unwrap();
    let error = f.make("Merge branch 'other'", false, &pending).unwrap_err();
    assert!(matches!(error, Error::MergeStateIncomplete), "{error:?}");
    assert_eq!(f.head(), before, "the branch is untouched");
}
