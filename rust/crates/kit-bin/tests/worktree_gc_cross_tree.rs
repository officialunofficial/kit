//! Cross-worktree gc correctness and the lock split.
//!
//! Root collection unions HEAD + index + `ORIG_HEAD` + in-progress-op
//! state across EVERY worktree, and gc's "shared lock spanning trees"
//! is the union of all per-tree worktree locks, taken in deterministic
//! order. The ~5s lock-timeout test lives in the serial `#[ignore]`
//! lane per the test-suite policy.

#![allow(clippy::unwrap_used)] // unwrap is the assertion in tests

mod common;

use std::path::PathBuf;
use std::process::Output;

use common::{Repo, kit};

fn wt_add(repo: &Repo, extra: &[&str], name: &str) -> (tempfile::TempDir, PathBuf, Output) {
    let host = tempfile::tempdir().expect("worktree host dir");
    let tree = host.path().join(name);
    let target_arg = tree.to_string_lossy().into_owned();
    let mut argv = vec!["worktree", "add", &target_arg];
    argv.extend_from_slice(extra);
    let out = repo.run(&argv);
    (host, tree, out)
}

#[test]
fn gc_keeps_sibling_in_progress_merge_state() {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"base\n", "seed");
    repo.ok(&["branch", "feature"]);
    let (_host, tree, out) = wt_add(&repo, &["feature"], "wt1");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Diverge: main edits a.txt, the linked tree edits it differently
    // and merges main's branch — conflict, leaving MERGE_HEAD +
    // conflict sidecar in the LINKED tree's state dir.
    repo.write("a.txt", b"ours-main\n");
    repo.ok(&["add", "a.txt"]);
    repo.ok(&["commit", "-m", "main change"]);

    std::fs::write(tree.join("a.txt"), b"theirs-linked\n").unwrap();
    let out = kit(&tree, repo.xdg(), &["add", "a.txt"]);
    assert!(out.status.success());
    let out = kit(&tree, repo.xdg(), &["commit", "-m", "linked change"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let merge = kit(&tree, repo.xdg(), &["merge", "main"]);
    assert!(
        !merge.status.success(),
        "merge should conflict: {}",
        String::from_utf8_lossy(&merge.stdout)
    );
    assert!(
        repo.kit_dir().join("worktrees/wt1/MERGE_HEAD").is_file(),
        "conflict state must live in the sibling's state dir"
    );

    // gc from the MAIN tree with zero grace: the sibling's op state
    // (MERGE_HEAD commit, ORIG_HEAD, conflict base/ours/theirs blobs)
    // must all stay live.
    repo.ok(&["gc", "--grace-secs", "0"]);

    // The sibling can still resolve and conclude the merge.
    std::fs::write(tree.join("a.txt"), b"resolved\n").unwrap();
    let out = kit(&tree, repo.xdg(), &["add", "a.txt"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let out = kit(&tree, repo.xdg(), &["merge", "--continue"]);
    assert!(
        out.status.success(),
        "merge --continue after cross-tree gc: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    common::check_invariants(repo.path(), "after gc + sibling merge").unwrap();
}

fn exists_in(repo: &Repo, hex: &str) -> bool {
    repo.run(&["cat", hex]).status.success()
}

/// A blob nothing references, stored by `kit hash`. Returns its id.
fn orphan_blob(repo: &Repo, name: &str, body: &[u8]) -> String {
    repo.write(name, body);
    let out = repo.ok(&["hash", name]);
    std::fs::remove_file(repo.path().join(name)).unwrap();
    String::from_utf8(out.stdout).unwrap().trim().to_owned()
}

/// What a linked tree alone reaches survives gc: a commit only its detached
/// HEAD names and a blob only its index names. Garbage goes.
#[test]
fn gc_keeps_what_only_a_linked_trees_head_and_index_reach() {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"one\n", "seed");
    let (_host, tree, out) = wt_add(&repo, &["HEAD"], "detached");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // A commit on the linked tree's detached HEAD: no branch names it.
    std::fs::write(tree.join("head.txt"), b"head only\n").unwrap();
    assert!(
        kit(&tree, repo.xdg(), &["add", "head.txt"])
            .status
            .success()
    );
    let out = kit(&tree, repo.xdg(), &["commit", "-m", "linked head"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let head = std::fs::read_to_string(repo.kit_dir().join("worktrees/detached/HEAD"))
        .unwrap()
        .trim()
        .to_owned();
    assert_eq!(head.len(), 64, "a detached HEAD holds a commit id: {head}");

    // A blob staged in the linked tree and committed nowhere.
    std::fs::write(tree.join("staged.txt"), b"index only\n").unwrap();
    assert!(
        kit(&tree, repo.xdg(), &["add", "staged.txt"])
            .status
            .success()
    );
    let staged = String::from_utf8(kit(&tree, repo.xdg(), &["hash", "staged.txt"]).stdout)
        .unwrap()
        .trim()
        .to_owned();

    let garbage = orphan_blob(&repo, "garbage.bin", b"reachable from nothing\n");
    assert!(exists_in(&repo, &head) && exists_in(&repo, &staged) && exists_in(&repo, &garbage));

    repo.ok(&["gc", "--grace-secs", "0"]);

    assert!(exists_in(&repo, &head), "the linked HEAD's commit survives");
    assert!(
        exists_in(&repo, &staged),
        "the linked index's blob survives"
    );
    assert!(
        !exists_in(&repo, &garbage),
        "unreachable garbage is collected"
    );
    common::check_invariants(repo.path(), "after gc with a linked tree").unwrap();
}

/// A linked tree whose state cannot be read stops gc before it removes
/// anything, and the message names that tree.
#[test]
fn gc_refuses_and_names_a_linked_tree_it_cannot_read() {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"one\n", "seed");
    let (_host, tree, out) = wt_add(&repo, &[], "broken");
    assert!(out.status.success());
    let garbage = orphan_blob(&repo, "garbage.bin", b"kept while gc refuses\n");

    std::fs::write(
        repo.kit_dir().join("worktrees/broken/index"),
        b"not an index",
    )
    .unwrap();
    let out = repo.run(&["gc", "--grace-secs", "0"]);

    assert!(!out.status.success(), "gc must refuse");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(&tree.display().to_string()),
        "the message names the tree: {stderr}"
    );
    assert!(exists_in(&repo, &garbage), "nothing was removed");
}

#[test]
fn destructive_commands_in_linked_tree_stay_tree_local() {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"one\n", "seed");
    let (_host, tree, out) = wt_add(&repo, &[], "topic");
    assert!(out.status.success());

    // Dirty BOTH trees, then reset --hard / clean only in the linked one.
    repo.write("a.txt", b"main-dirty\n");
    repo.write("untracked-main.txt", b"keep\n");
    std::fs::write(tree.join("a.txt"), b"linked-dirty\n").unwrap();
    std::fs::write(tree.join("junk.txt"), b"drop\n").unwrap();

    let out = kit(&tree, repo.xdg(), &["reset", "--hard", "-f", "HEAD"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let out = kit(&tree, repo.xdg(), &["clean", "-f"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Linked tree is pristine again...
    assert_eq!(std::fs::read(tree.join("a.txt")).unwrap(), b"one\n");
    assert!(!tree.join("junk.txt").exists());
    // ...while the main tree's local state is untouched.
    assert_eq!(
        std::fs::read(repo.path().join("a.txt")).unwrap(),
        b"main-dirty\n"
    );
    assert!(repo.path().join("untracked-main.txt").exists());
}

/// gc must block (and then time out) while a SIBLING tree's worktree
/// lock is held — the cross-tree half of the lock split. ~5s of
/// deliberate lock-timeout spinning, so this runs in the serial
/// `--run-ignored` CI lane, not the default suite.
#[test]
#[ignore = "deliberate ~5s lock-timeout; serial CI lane"]
fn gc_blocks_on_a_sibling_worktree_lock() {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"one\n", "seed");
    let (_host, _tree, out) = wt_add(&repo, &[], "topic");
    assert!(out.status.success());

    // Hold the SIBLING's worktree lock the way a concurrent kit
    // process would: take the kernel lock on its sentinel. A sentinel
    // file alone does not count as held.
    let sibling_state = repo.kit_dir().join("worktrees/topic");
    let held = kit_core::repo_lock::acquire_default(&sibling_state, "worktree.lock")
        .expect("acquire sibling worktree lock");

    let out = repo.run(&["gc", "--grace-secs", "0"]);
    assert!(
        !out.status.success(),
        "gc must not run while a sibling tree is mid-mutation"
    );
    assert_eq!(out.status.code(), Some(75), "TEMPFAIL on lock contention");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("lock"),
        "diagnostic must name the lock: {stderr}"
    );

    // Release and retry: gc proceeds.
    drop(held);
    repo.ok(&["gc", "--grace-secs", "0"]);
}
