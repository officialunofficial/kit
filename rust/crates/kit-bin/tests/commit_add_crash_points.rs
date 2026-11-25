//! Crash points of `add`, `commit`, an amend and a merge commit.
//!
//! These commands share device flushes (SPEC-OBJECTS §10.1, "Shared flush
//! points"). The binary of this test build copies the repository after each
//! full flush (see `kit_core::durable::flush_file`), so each copy is the
//! repository as a power loss right after that flush leaves it, at its
//! worst: what was renamed since the flush may be gone, and nothing before it
//! is. The test checks every copy:
//!
//! - the repository is whole and readable, and `kit status` accepts it;
//! - the ref and the index are the old or the new value, never another;
//! - ordering: a ref, an index or a recovery-log line that appears after a
//!   flush names only objects that were visible at the flush before, and a
//!   recovery-log line is there before the ref it protects moves;
//! - a merge's state is cleared only after the merge commit is durable;
//! - a merge, cherry-pick or revert whose state outlives the commit that
//!   concludes it keeps that commit, and one whose stop left no conflict list
//!   can be aborted.
//!
//! The device operations are those of the real binary. The hook is a
//! test-only environment variable, so each case runs in its own process.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;

use common::{Repo, check_exit, check_invariants, kit, kit_env};
use kit_core::hash::{Hash, ZERO, to_hex};
use kit_core::index::read_index;
use kit_core::layout::RepoLayout;
use kit_core::object::Object;
use kit_core::ops::reachable_objects;
use kit_core::refs;
use kit_core::store::ObjectStore;

fn copy_tree(src: &Path, dest: &Path) {
    fs::create_dir_all(dest).unwrap();
    // The key directory must keep its mode, or a command that signs refuses.
    fs::set_permissions(dest, fs::metadata(src).unwrap().permissions()).unwrap();
    for entry in fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let to = dest.join(entry.file_name());
        let kind = entry.file_type().unwrap();
        if kind.is_dir() {
            copy_tree(&entry.path(), &to);
        } else if kind.is_file() {
            fs::copy(entry.path(), &to).unwrap();
        }
    }
}

/// The repository before `args` ran, after each of its full flushes, and after
/// it returned, with the output of the command.
fn snapshots(repo: &Repo, scratch: &Path, args: &[&str]) -> (Output, Vec<PathBuf>) {
    let before = scratch.join("before");
    copy_tree(repo.path(), &before);
    let snaps = scratch.join("flushes");
    fs::create_dir_all(&snaps).unwrap();
    let out = kit_env(
        repo.path(),
        repo.xdg(),
        args,
        &[
            ("KIT_FLUSH_SNAPSHOT_SRC", repo.path().to_str().unwrap()),
            ("KIT_FLUSH_SNAPSHOT_DEST", snaps.to_str().unwrap()),
        ],
    );
    let mut points = vec![before];
    let flushes = fs::read_dir(&snaps).unwrap().count();
    for n in 1..=flushes {
        points.push(snaps.join(n.to_string()));
    }
    let after = scratch.join("after");
    copy_tree(repo.path(), &after);
    points.push(after);
    (out, points)
}

/// The repository before `args` ran, after each of its full flushes, and after
/// it returned.
fn crash_points(repo: &Repo, scratch: &Path, args: &[&str]) -> Vec<PathBuf> {
    let (out, points) = snapshots(repo, scratch, args);
    assert!(
        out.status.success(),
        "kit {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    points
}

/// The repository at one crash point. What a command may change is read once,
/// before any command runs on the copy: `kit status` refreshes the index.
struct State {
    layout: RepoLayout,
    tip: Option<Hash>,
    index: Vec<u8>,
    log: String,
    merging: bool,
}

impl State {
    fn at(root: &Path) -> Self {
        let layout = RepoLayout::single(root);
        Self {
            tip: refs::read_ref(&layout, "main").unwrap(),
            index: fs::read(root.join(".kit/index")).unwrap_or_default(),
            log: fs::read_to_string(root.join(".kit/recovery-log")).unwrap_or_default(),
            merging: OPERATION_MARKERS
                .iter()
                .any(|marker| root.join(".kit").join(marker).exists()),
            layout,
        }
    }

    fn tip(&self) -> Option<Hash> {
        self.tip
    }

    fn index(&self) -> &[u8] {
        &self.index
    }

    fn log(&self) -> &str {
        &self.log
    }

    fn merging(&self) -> bool {
        self.merging
    }

    fn store(&self) -> ObjectStore {
        ObjectStore::open(&self.layout).unwrap()
    }
}

/// What a pointer that changed between two crash points names must have been
/// visible at the earlier one.
fn check_order(prev: &State, cur: &State, label: &str) {
    let prev_store = prev.store();
    let cur_store = cur.store();
    if cur.tip() != prev.tip()
        && let Some(tip) = cur.tip()
    {
        for h in reachable_objects(&cur_store, &tip).unwrap() {
            assert!(
                prev_store.contains(&h),
                "[{label}] the ref names {} before a flush made it durable",
                to_hex(&h)
            );
        }
    }
    if cur.index != prev.index {
        for entry in read_index(&cur.layout).unwrap().entries {
            if entry.object_hash != ZERO {
                assert!(
                    prev_store.contains(&entry.object_hash),
                    "[{label}] the index names {} before a flush made it durable",
                    to_hex(&entry.object_hash)
                );
            }
        }
    }
}

/// Every crash point is whole, readable and accepted by the next command.
fn check_each(points: &[PathBuf], xdg: &Path, label: &str) -> Vec<State> {
    let mut states = Vec::new();
    for (n, point) in points.iter().enumerate() {
        let label = format!("{label}, point {n}");
        let state = State::at(point);
        if let Some(prev) = states.last() {
            check_order(prev, &state, &label);
        }
        check_invariants(point, &label).unwrap_or_else(|e| panic!("{e}"));
        // The next command runs on a copy, so the point stays as it was.
        let copy = tempfile::tempdir().unwrap();
        copy_tree(point, copy.path());
        let out = kit(copy.path(), xdg, &["status"]);
        check_exit(&out, &label).unwrap_or_else(|e| panic!("{e}"));
        assert!(
            out.status.success(),
            "[{label}] status: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        states.push(state);
    }
    states
}

fn base_repo() -> Repo {
    let repo = Repo::new();
    for dir in ["a", "dir/sub"] {
        for file in 0..3 {
            repo.write(
                &format!("{dir}/f{file}.txt"),
                format!("{dir} {file}\n").as_bytes(),
            );
        }
    }
    repo.ok(&["add", "."]);
    repo.ok(&["commit", "-m", "base"]);
    repo
}

/// The count of full flushes on the Apple file systems that the pins in
/// `flush_counts` are made for. Elsewhere only the checks of every point run.
#[cfg(all(target_os = "macos", not(feature = "history-mmr")))]
fn assert_points(points: &[PathBuf], flushes: usize) {
    assert_eq!(points.len(), flushes + 2, "full flushes of the command");
}

#[cfg(not(all(target_os = "macos", not(feature = "history-mmr"))))]
fn assert_points(points: &[PathBuf], _flushes: usize) {
    assert!(points.len() >= 2);
}

#[test]
fn every_crash_point_of_add_is_the_old_index_or_the_new_one() {
    let repo = base_repo();
    repo.write("a/f0.txt", b"edited\n");
    repo.write("a/new.txt", b"new file\n");
    let scratch = tempfile::tempdir().unwrap();
    let points = crash_points(&repo, scratch.path(), &["add", "a/f0.txt", "a/new.txt"]);
    assert_points(&points, 3);
    let states = check_each(&points, repo.xdg(), "add");

    let (old, new) = (
        states[0].index().to_vec(),
        states.last().unwrap().index().to_vec(),
    );
    assert_ne!(old, new, "the add changed the index");
    for state in &states {
        let index = state.index();
        assert!(index == old || index == new, "the index is old or new");
        assert_eq!(state.tip(), states[0].tip(), "an add moves no ref");
    }
}

#[test]
fn every_crash_point_of_commit_is_the_old_ref_or_the_new_one() {
    let repo = base_repo();
    repo.write("a/f0.txt", b"edited\n");
    repo.ok(&["add", "a/f0.txt"]);
    let scratch = tempfile::tempdir().unwrap();
    let points = crash_points(&repo, scratch.path(), &["commit", "-m", "edit"]);
    assert_points(&points, 3);
    let states = check_each(&points, repo.xdg(), "commit");

    let (old, new) = (states[0].tip(), states.last().unwrap().tip());
    assert_ne!(old, new, "the commit moved the ref");
    for state in &states {
        let tip = state.tip();
        assert!(tip == old || tip == new, "the ref is old or new");
        assert_eq!(
            state.index(),
            states[0].index(),
            "a plain commit keeps the index"
        );
    }
    // The ref is renamed only after the flush that made the objects' names
    // durable, so no point before that has the new ref.
    #[cfg(all(target_os = "macos", not(feature = "history-mmr")))]
    {
        assert_eq!(states[1].tip(), old);
        assert_eq!(states[2].tip(), old);
        assert_eq!(states[3].tip(), new);
    }
}

#[test]
fn every_crash_point_of_an_amend_keeps_the_replaced_commit_recoverable() {
    let repo = base_repo();
    repo.write("a/f0.txt", b"edited\n");
    repo.ok(&["add", "a/f0.txt"]);
    let scratch = tempfile::tempdir().unwrap();
    let points = crash_points(
        &repo,
        scratch.path(),
        &["commit", "--amend", "-m", "amended"],
    );
    assert_points(&points, 3);
    let states = check_each(&points, repo.xdg(), "amend");

    let (old, new) = (
        states[0].tip().unwrap(),
        states.last().unwrap().tip().unwrap(),
    );
    assert_ne!(old, new, "the amend moved the ref");
    for (n, state) in states.iter().enumerate() {
        let tip = state.tip().unwrap();
        assert!(tip == old || tip == new, "the ref is old or new");
        if tip == new {
            // The log line is durable at the flush before the ref renames.
            assert!(
                states[n - 1].log().contains(&to_hex(&old)),
                "point {n}: the ref moved before its recovery entry was durable"
            );
        }
    }
}

#[test]
fn every_crash_point_of_a_merge_commit_clears_the_merge_after_the_ref_is_durable() {
    let repo = base_repo();
    repo.ok(&["branch", "side"]);
    repo.write("a/f0.txt", b"main\n");
    repo.ok(&["add", "a/f0.txt"]);
    repo.ok(&["commit", "-m", "main"]);
    repo.ok(&["checkout", "side"]);
    repo.write("side.txt", b"side\n");
    repo.ok(&["add", "side.txt"]);
    repo.ok(&["commit", "-m", "side"]);
    repo.ok(&["checkout", "main"]);
    repo.ok(&["merge", "--no-commit", "side"]);
    let scratch = tempfile::tempdir().unwrap();
    let points = crash_points(&repo, scratch.path(), &["commit", "-m", "merged"]);
    assert_points(&points, 4);
    let states = check_each(&points, repo.xdg(), "merge");

    let (old, new) = (states[0].tip(), states.last().unwrap().tip());
    assert_ne!(old, new, "the merge commit moved the ref");
    assert!(states[0].merging(), "the merge was in progress");
    assert!(!states.last().unwrap().merging(), "the merge was concluded");
    for (n, state) in states.iter().enumerate() {
        let tip = state.tip();
        assert!(tip == old || tip == new, "the ref is old or new");
        if !state.merging() {
            // The merge state is gone only over a durable merge commit.
            assert_eq!(
                tip, new,
                "point {n}: the merge state is gone, the ref is not new"
            );
            assert_eq!(
                states[n - 1].tip(),
                new,
                "point {n}: the merge state went before the ref was durable"
            );
        }
    }
}

#[test]
fn every_crash_point_of_a_cherry_pick_commit_clears_the_state_after_the_ref_is_durable() {
    let repo = base_repo();
    repo.ok(&["branch", "side"]);
    repo.write("a/f0.txt", b"main\n");
    repo.ok(&["add", "a/f0.txt"]);
    repo.ok(&["commit", "-m", "main"]);
    repo.ok(&["checkout", "side"]);
    repo.write("a/f0.txt", b"side\n");
    repo.ok(&["add", "a/f0.txt"]);
    repo.ok(&["commit", "-m", "side"]);
    let picked = to_hex(
        &refs::read_ref(&RepoLayout::single(repo.path()), "side")
            .unwrap()
            .unwrap(),
    );
    repo.ok(&["checkout", "main"]);
    // The pick conflicts and stops; the resolution is staged and committed.
    let stopped = kit(repo.path(), repo.xdg(), &["cherry-pick", &picked]);
    assert!(!stopped.status.success(), "the pick conflicts");
    repo.write("a/f0.txt", b"resolved\n");
    repo.ok(&["add", "a/f0.txt"]);
    let scratch = tempfile::tempdir().unwrap();
    let points = crash_points(&repo, scratch.path(), &["commit", "-m", "picked"]);
    assert_points(&points, 4);
    let states = check_each(&points, repo.xdg(), "cherry-pick");

    let (old, new) = (states[0].tip(), states.last().unwrap().tip());
    assert_ne!(old, new, "the commit moved the ref");
    assert!(states[0].merging(), "the pick was in progress");
    assert!(!states.last().unwrap().merging(), "the pick was concluded");
    for (n, state) in states.iter().enumerate() {
        let tip = state.tip();
        assert!(tip == old || tip == new, "the ref is old or new");
        if !state.merging() {
            assert_eq!(
                tip, new,
                "point {n}: the pick state is gone, the ref is not new"
            );
            assert_eq!(
                states[n - 1].tip(),
                new,
                "point {n}: the pick state went before the ref was durable"
            );
        }
    }
}

/// The files that mark and describe a merge, a cherry-pick or a revert in
/// progress. The markers come first.
const OPERATION_MARKERS: [&str; 3] = ["MERGE_HEAD", "CHERRY_PICK_HEAD", "REVERT_HEAD"];
const OPERATION_FILES: [&str; 9] = [
    "MERGE_HEAD",
    "CHERRY_PICK_HEAD",
    "REVERT_HEAD",
    "MERGE_MSG",
    "CHERRY_PICK_MSG",
    "REVERT_MSG",
    "ORIG_HEAD",
    "kit-conflicts",
    "KIT_OP_RESULT",
];

/// The repository after a command that concluded an operation, with the state
/// of the operation back: a stop after the branch moved and before the state
/// was cleared. `before` is the repository as it was when the operation was
/// still in progress.
fn stale_state(before: &Path, after: &Path, scratch: &Path) -> PathBuf {
    let stale = scratch.join("stale");
    copy_tree(after, &stale);
    for name in OPERATION_FILES {
        let from = before.join(".kit").join(name);
        if from.is_file() {
            fs::copy(from, stale.join(".kit").join(name)).unwrap();
        }
    }
    stale
}

/// `kit <args>` on a copy of `point`, which stays as it was. The copy and its
/// output come back.
fn run_on_copy(point: &Path, xdg: &Path, args: &[&str]) -> (tempfile::TempDir, Output) {
    let copy = copy_of(point);
    let out = kit(copy.path(), xdg, args);
    (copy, out)
}

/// A copy of a crash point that a command can sign in. The copy of a flush
/// does not keep the mode of the key directory.
fn copy_of(point: &Path) -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    let copy = tempfile::tempdir().unwrap();
    copy_tree(point, copy.path());
    fs::set_permissions(
        copy.path().join(".kit/keys"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    copy
}

fn tip_of(root: &Path) -> Option<Hash> {
    State::at(root).tip()
}

/// The points of a command that concludes an operation where the state of the
/// operation is still there over the commit that concludes it: the crash
/// points that the command passes, and the one that a stop right before the
/// clear leaves.
fn stale_points(points: &[PathBuf], scratch: &Path, new: Hash) -> Vec<PathBuf> {
    let mut stale: Vec<PathBuf> = points[1..]
        .iter()
        .filter(|point| {
            let state = State::at(point);
            state.merging() && state.tip() == Some(new)
        })
        .cloned()
        .collect();
    stale.push(stale_state(&points[0], points.last().unwrap(), scratch));
    stale
}

fn no_operation(root: &Path, label: &str) {
    for name in OPERATION_FILES {
        assert!(
            !root.join(".kit").join(name).exists(),
            "[{label}] {name} is left"
        );
    }
}

/// `main` and `side` change the same file. `op` stops on the conflict, and
/// the arguments start it.
fn conflicting(op: &str) -> (Repo, Vec<String>) {
    let repo = base_repo();
    if op == "revert" {
        repo.write("a/f0.txt", b"changed\n");
        repo.ok(&["add", "a/f0.txt"]);
        repo.ok(&["commit", "-m", "change"]);
        repo.write("a/f0.txt", b"later\n");
        repo.ok(&["add", "a/f0.txt"]);
        repo.ok(&["commit", "-m", "later"]);
        return (repo, vec![op.into(), "HEAD~1".into()]);
    }
    repo.ok(&["branch", "side"]);
    repo.write("a/f0.txt", b"main\n");
    repo.ok(&["add", "a/f0.txt"]);
    repo.ok(&["commit", "-m", "main"]);
    repo.ok(&["checkout", "side"]);
    repo.write("a/f0.txt", b"side\n");
    repo.ok(&["add", "a/f0.txt"]);
    repo.ok(&["commit", "-m", "side"]);
    repo.ok(&["checkout", "main"]);
    let target = if op == "merge" {
        "side".to_owned()
    } else {
        to_hex(
            &refs::read_ref(&RepoLayout::single(repo.path()), "side")
                .unwrap()
                .unwrap(),
        )
    };
    (repo, vec![op.into(), target])
}

fn resolve(repo: &Repo) {
    repo.write("a/f0.txt", b"resolved\n");
    repo.ok(&["add", "a/f0.txt"]);
}

/// The parents of the commit that `tip` names.
fn parents_of(root: &Path, tip: Hash) -> Vec<Hash> {
    let store = ObjectStore::open(&RepoLayout::single(root)).unwrap();
    match store.read_object(&tip).unwrap() {
        Object::Commit(c) => c.parents,
        other => panic!("not a commit: {other:?}"),
    }
}

/// `op --abort` and `op --continue` on the repository that a stop after the
/// commit of `op --continue` left: they keep the commit.
fn a_stop_after_the_commit_of(op: &str) {
    let (repo, args) = conflicting(op);
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    assert!(!repo.run(&args).status.success(), "{op} conflicts");
    resolve(&repo);
    let scratch = tempfile::tempdir().unwrap();
    let points = crash_points(&repo, scratch.path(), &[op, "--continue"]);
    let (old, new) = (
        State::at(&points[0]).tip().unwrap(),
        tip_of(points.last().unwrap()).unwrap(),
    );
    assert_ne!(old, new, "{op}: the continue moved the ref");
    for (n, point) in stale_points(&points, scratch.path(), new)
        .iter()
        .enumerate()
    {
        for action in ["--abort", "--continue"] {
            let label = format!("{op} {action}, stale point {n}");
            let (copy, out) = run_on_copy(point, repo.xdg(), &[op, action]);
            check_exit(&out, &label).unwrap_or_else(|e| panic!("{e}"));
            assert!(
                out.status.success(),
                "[{label}] {}",
                String::from_utf8_lossy(&out.stderr)
            );
            assert_eq!(
                tip_of(copy.path()),
                Some(new),
                "[{label}] the commit is kept"
            );
            no_operation(copy.path(), &label);
            check_invariants(copy.path(), &label).unwrap_or_else(|e| panic!("{e}"));
        }
    }
}

#[test]
fn a_cherry_pick_stopped_after_its_commit_keeps_the_commit() {
    a_stop_after_the_commit_of("cherry-pick");
}

#[test]
fn a_revert_stopped_after_its_commit_keeps_the_commit() {
    a_stop_after_the_commit_of("revert");
}

#[test]
fn a_commit_over_a_merge_that_a_stop_left_the_state_of_is_not_a_sibling() {
    let repo = base_repo();
    repo.ok(&["branch", "side"]);
    repo.write("a/f0.txt", b"main\n");
    repo.ok(&["add", "a/f0.txt"]);
    repo.ok(&["commit", "-m", "main"]);
    repo.ok(&["checkout", "side"]);
    repo.write("side.txt", b"side\n");
    repo.ok(&["add", "side.txt"]);
    repo.ok(&["commit", "-m", "side"]);
    repo.ok(&["checkout", "main"]);
    repo.ok(&["merge", "--no-commit", "side"]);
    let scratch = tempfile::tempdir().unwrap();
    let points = crash_points(&repo, scratch.path(), &["commit", "-m", "merged"]);
    let new = tip_of(points.last().unwrap()).unwrap();
    assert_eq!(parents_of(points.last().unwrap(), new).len(), 2);
    for (n, point) in stale_points(&points, scratch.path(), new)
        .iter()
        .enumerate()
    {
        let label = format!("commit over a merge, stale point {n}");
        let copy = copy_of(point);
        // A change staged after the stop is a commit of its own.
        fs::write(copy.path().join("later.txt"), b"later\n").unwrap();
        for args in [vec!["add", "later.txt"], vec!["commit", "-m", "later"]] {
            let out = kit(copy.path(), repo.xdg(), &args);
            assert!(
                out.status.success(),
                "[{label}] {args:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        let tip = tip_of(copy.path()).unwrap();
        assert_eq!(parents_of(copy.path(), tip), vec![new], "[{label}]");
        no_operation(copy.path(), &label);
        check_invariants(copy.path(), &label).unwrap_or_else(|e| panic!("{e}"));

        // A commit of what is staged already never drops the merge commit.
        let (copy, out) = run_on_copy(point, repo.xdg(), &["commit", "-m", "again"]);
        check_exit(&out, &label).unwrap_or_else(|e| panic!("{e}"));
        let tip = tip_of(copy.path()).unwrap();
        let store = ObjectStore::open(&RepoLayout::single(copy.path())).unwrap();
        assert!(
            reachable_objects(&store, &tip).unwrap().contains(&new),
            "[{label}] the merge commit is not under the branch"
        );
        no_operation(copy.path(), &label);
    }
}

#[test]
fn a_merge_stopped_after_its_commit_keeps_the_commit() {
    let (repo, args) = conflicting("merge");
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    assert!(!repo.run(&args).status.success(), "the merge conflicts");
    resolve(&repo);
    let scratch = tempfile::tempdir().unwrap();
    let points = crash_points(&repo, scratch.path(), &["merge", "--continue"]);
    let new = tip_of(points.last().unwrap()).unwrap();
    for (n, point) in stale_points(&points, scratch.path(), new)
        .iter()
        .enumerate()
    {
        for action in ["--abort", "--continue"] {
            let label = format!("merge {action}, stale point {n}");
            let (copy, out) = run_on_copy(point, repo.xdg(), &["merge", action]);
            check_exit(&out, &label).unwrap_or_else(|e| panic!("{e}"));
            assert!(
                out.status.success(),
                "[{label}] {}",
                String::from_utf8_lossy(&out.stderr)
            );
            assert_eq!(
                tip_of(copy.path()),
                Some(new),
                "[{label}] the commit is kept"
            );
            no_operation(copy.path(), &label);
        }
    }
}

/// The abort of an operation that a stop left without its conflict list
/// restores the branch and the files, or refuses and names the way out. The
/// way out drops the operation and restores the files.
fn a_stop_before_the_conflict_list_of(op: &str) {
    let (repo, args) = conflicting(op);
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let scratch = tempfile::tempdir().unwrap();
    let (out, mut points) = snapshots(&repo, scratch.path(), &args);
    assert!(!out.status.success(), "{op} conflicts");
    // The markers are written and the list is not.
    let unlisted = scratch.path().join("unlisted");
    copy_tree(points.last().unwrap(), &unlisted);
    fs::remove_file(unlisted.join(".kit/kit-conflicts")).unwrap();
    points.push(unlisted);
    let old = State::at(&points[0]).tip();
    let original = fs::read(points[0].join("a/f0.txt")).unwrap();
    let mut refused = 0;
    for (n, point) in points.iter().enumerate() {
        if !State::at(point).merging() {
            continue;
        }
        let label = format!("{op} --abort, point {n}");
        let (copy, out) = run_on_copy(point, repo.xdg(), &[op, "--abort"]);
        check_exit(&out, &label).unwrap_or_else(|e| panic!("{e}"));
        let way_out = if out.status.success() {
            copy
        } else {
            refused += 1;
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert!(
                stderr.contains("kit reset --hard -f"),
                "[{label}] the refusal names no way out: {stderr}"
            );
            // The refusal changed nothing.
            assert_eq!(tip_of(copy.path()), old, "[{label}]");
            let (copy, out) = run_on_copy(point, repo.xdg(), &["reset", "--hard", "-f"]);
            assert!(
                out.status.success(),
                "[{label}] the way out: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            copy
        };
        assert_eq!(tip_of(way_out.path()), old, "[{label}] the branch is back");
        assert_eq!(
            fs::read(way_out.path().join("a/f0.txt")).unwrap(),
            original,
            "[{label}] the file is back"
        );
        no_operation(way_out.path(), &label);
    }
    // Some point has markers and no list, and the abort refuses it.
    assert!(refused > 0, "{op}: no point is refused");
}

#[test]
fn a_merge_stopped_before_its_conflict_list_is_aborted_or_names_the_way_out() {
    a_stop_before_the_conflict_list_of("merge");
}

#[test]
fn a_cherry_pick_stopped_before_its_conflict_list_is_aborted_or_names_the_way_out() {
    a_stop_before_the_conflict_list_of("cherry-pick");
}

#[test]
fn a_revert_stopped_before_its_conflict_list_is_aborted_or_names_the_way_out() {
    a_stop_before_the_conflict_list_of("revert");
}

/// A paused pick or revert whose `HEAD` moved to another child of the commit
/// before it is still live: its resolution is not in that commit. Continuing
/// commits the resolution on top of it, and never reports a commit that was
/// not made.
fn a_live_operation_on_a_moved_head(op: &str) {
    let (repo, args) = conflicting(op);
    repo.ok(&["branch", "moved"]);
    repo.ok(&["checkout", "moved"]);
    repo.write("y.txt", b"y\n");
    repo.ok(&["add", "y.txt"]);
    repo.ok(&["commit", "-m", "y"]);
    let moved = tip_of_branch(repo.path(), "moved");
    repo.ok(&["checkout", "main"]);
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    assert!(!repo.run(&args).status.success(), "{op} conflicts");
    repo.ok(&["reset", "--soft", &to_hex(&moved)]);
    resolve(&repo);

    let out = repo.run(&[op, "--continue"]);
    assert!(
        out.status.success(),
        "{op} --continue: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let tip = tip_of(repo.path()).unwrap();
    assert_ne!(tip, moved, "{op} --continue made no commit");
    assert_eq!(parents_of(repo.path(), tip), vec![moved]);
    assert_eq!(
        fs::read(repo.path().join("a/f0.txt")).unwrap(),
        b"resolved\n"
    );
    no_operation(repo.path(), op);
}

fn tip_of_branch(root: &Path, branch: &str) -> Hash {
    refs::read_ref(&RepoLayout::single(root), branch)
        .unwrap()
        .unwrap()
}

#[test]
fn a_cherry_pick_on_a_moved_head_is_still_live() {
    a_live_operation_on_a_moved_head("cherry-pick");
}

#[test]
fn a_revert_on_a_moved_head_is_still_live() {
    a_live_operation_on_a_moved_head("revert");
}

/// A paused pick whose `HEAD` moved to a child of the commit before it that
/// has the same tree: the index holds that tree, but the conflict markers are
/// still in the file. Continuing refuses.
fn a_live_pick_on_a_moved_head_with_markers() {
    let op = "cherry-pick";
    let (repo, args) = conflicting(op);
    repo.ok(&["branch", "same"]);
    repo.ok(&["checkout", "same"]);
    repo.ok(&["commit", "-m", "same tree"]);
    let same = tip_of_branch(repo.path(), "same");
    repo.ok(&["checkout", "main"]);
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    assert!(!repo.run(&args).status.success(), "{op} conflicts");
    repo.ok(&["reset", "--soft", &to_hex(&same)]);

    let out = repo.run(&[op, "--continue"]);
    assert!(!out.status.success(), "{op} --continue: {out:?}");
    assert_eq!(tip_of(repo.path()), Some(same), "{op}: no commit was made");
    assert!(
        repo.path().join(".kit/CHERRY_PICK_HEAD").exists(),
        "{op}: the state is still there"
    );
}

#[test]
fn a_cherry_pick_on_a_moved_head_with_markers_is_still_live() {
    a_live_pick_on_a_moved_head_with_markers();
}
