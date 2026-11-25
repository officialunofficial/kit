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
//! - a merge's state is cleared only after the merge commit is durable.
//!
//! The device operations are those of the real binary. The hook is a
//! test-only environment variable, so each case runs in its own process.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

mod common;

use std::fs;
use std::path::{Path, PathBuf};

use common::{Repo, check_exit, check_invariants, kit, kit_env};
use kit_core::hash::{Hash, ZERO, to_hex};
use kit_core::index::read_index;
use kit_core::layout::RepoLayout;
use kit_core::ops::reachable_objects;
use kit_core::refs;
use kit_core::store::ObjectStore;

fn copy_tree(src: &Path, dest: &Path) {
    fs::create_dir_all(dest).unwrap();
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
/// it returned.
fn crash_points(repo: &Repo, scratch: &Path, args: &[&str]) -> Vec<PathBuf> {
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
    assert!(
        out.status.success(),
        "kit {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let mut points = vec![before];
    let flushes = fs::read_dir(&snaps).unwrap().count();
    for n in 1..=flushes {
        points.push(snaps.join(n.to_string()));
    }
    let after = scratch.join("after");
    copy_tree(repo.path(), &after);
    points.push(after);
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
            merging: root.join(".kit/MERGE_HEAD").exists()
                || root.join(".kit/CHERRY_PICK_HEAD").exists(),
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
