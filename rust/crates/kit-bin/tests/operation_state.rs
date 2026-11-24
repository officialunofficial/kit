//! A merge, cherry-pick or revert in progress: `status` names it, a hard
//! reset ends it, and an abort works when the result tree is gone.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::fs;
use std::path::Path;
use std::process::Command;

fn run_in(cwd: &Path, args: &[&str]) -> std::process::Output {
    let xdg = tempfile::tempdir().expect("xdg tempdir");
    let out = Command::new(env!("CARGO_BIN_EXE_kit"))
        .args(args)
        .current_dir(cwd)
        .env("XDG_CONFIG_HOME", xdg.path())
        .output()
        .expect("spawn kit");
    drop(xdg);
    out
}

fn ok(cwd: &Path, args: &[&str]) {
    let out = run_in(cwd, args);
    assert!(out.status.success(), "kit {args:?}: {out:?}");
}

fn write(root: &Path, name: &str, content: &str) {
    fs::write(root.join(name), content).unwrap();
}

fn commit_all(root: &Path, message: &str) {
    ok(root, &["add", "."]);
    ok(root, &["commit", "-m", message]);
}

fn parents_of_head(root: &Path) -> usize {
    let out = run_in(root, &["cat-file", "-p", "HEAD"]);
    assert!(out.status.success(), "{out:?}");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| l.starts_with("parent "))
        .count()
}

fn status_text(root: &Path) -> String {
    let out = run_in(root, &["status"]);
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// `main` and `side` both change `a.txt`; `side` also adds `t.txt`. `main`
/// is checked out.
fn diverged_repo(clean_add: bool) -> tempfile::TempDir {
    let td = tempfile::tempdir().unwrap();
    let root = td.path();
    ok(root, &["init"]);
    ok(root, &["keygen"]);
    write(root, "a.txt", "base\n");
    commit_all(root, "base");
    ok(root, &["branch", "side"]);
    ok(root, &["checkout", "side"]);
    write(root, "a.txt", "side\n");
    if clean_add {
        write(root, "t.txt", "added by side\n");
    }
    commit_all(root, "side");
    ok(root, &["checkout", "main"]);
    write(root, "a.txt", "main\n");
    commit_all(root, "main");
    td
}

#[test]
fn a_hard_reset_ends_a_merge_so_the_next_commit_has_one_parent() {
    let td = diverged_repo(true);
    let root = td.path();
    assert!(!run_in(root, &["merge", "side"]).status.success());
    assert!(root.join(".kit/MERGE_HEAD").exists());

    ok(root, &["reset", "--hard", "-f"]);
    for name in [
        "MERGE_HEAD",
        "MERGE_MSG",
        "ORIG_HEAD",
        "KIT_OP_RESULT",
        "kit-conflicts",
    ] {
        assert!(!root.join(".kit").join(name).exists(), "{name} is left");
    }

    write(root, "u.txt", "unrelated\n");
    commit_all(root, "unrelated");
    assert_eq!(
        parents_of_head(root),
        1,
        "the discarded merge is not recorded"
    );
    assert!(!root.join("t.txt").exists());
}

#[test]
fn a_hard_reset_ends_a_cherry_pick() {
    let td = diverged_repo(true);
    let root = td.path();
    assert!(!run_in(root, &["cherry-pick", "side"]).status.success());
    assert!(root.join(".kit/CHERRY_PICK_HEAD").exists());

    ok(root, &["reset", "--hard", "-f"]);
    assert!(!root.join(".kit/CHERRY_PICK_HEAD").exists());
    assert!(!status_text(root).contains("in progress"));
}

#[test]
fn status_names_an_operation_in_progress() {
    let td = diverged_repo(false);
    let root = td.path();
    assert!(!status_text(root).contains("in progress"));
    assert!(!run_in(root, &["merge", "side"]).status.success());
    let text = status_text(root);
    assert!(text.contains("A merge is in progress"), "{text}");
    assert!(text.contains("kit merge --abort"), "{text}");
}

#[test]
fn a_merge_is_aborted_when_its_result_tree_is_missing() {
    let td = diverged_repo(false);
    let root = td.path();
    assert!(!run_in(root, &["merge", "side"]).status.success());
    // A tree that the store does not hold.
    fs::write(
        root.join(".kit/KIT_OP_RESULT"),
        format!("{}\n", "ab".repeat(32)),
    )
    .unwrap();

    let out = run_in(root, &["merge", "--abort"]);
    assert!(out.status.success(), "{out:?}");
    assert!(!root.join(".kit/MERGE_HEAD").exists());
    assert_eq!(fs::read_to_string(root.join("a.txt")).unwrap(), "main\n");
}

#[test]
fn a_continue_refuses_an_operation_whose_conflict_list_is_missing() {
    for (op, marker) in [
        ("merge", "MERGE_HEAD"),
        ("cherry-pick", "CHERRY_PICK_HEAD"),
        ("revert", "REVERT_HEAD"),
    ] {
        let td = diverged_repo(false);
        let root = td.path();
        let target = if op == "revert" { "HEAD~1" } else { "side" };
        assert!(!run_in(root, &[op, target]).status.success(), "{op}");
        assert!(root.join(".kit").join(marker).exists(), "{op}");
        fs::remove_file(root.join(".kit/kit-conflicts")).unwrap();
        // The file still holds conflict markers.
        let before = run_in(root, &["rev-parse", "HEAD"]).stdout;

        let out = run_in(root, &[op, "--continue"]);
        assert!(!out.status.success(), "{op} --continue: {out:?}");
        assert_eq!(run_in(root, &["rev-parse", "HEAD"]).stdout, before, "{op}");
        assert!(root.join(".kit").join(marker).exists(), "{op}");
    }
}
