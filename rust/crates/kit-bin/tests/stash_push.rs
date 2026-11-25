//! `kit stash push` is another name for `kit stash save`.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

fn run_in(cwd: &Path, args: &[&str]) -> Output {
    let xdg = tempfile::tempdir().expect("xdg tempdir");
    Command::new(env!("CARGO_BIN_EXE_kit"))
        .args(args)
        .current_dir(cwd)
        .env("XDG_CONFIG_HOME", xdg.path())
        .output()
        .expect("spawn kit")
}

fn ok(cwd: &Path, args: &[&str]) -> Output {
    let out = run_in(cwd, args);
    assert!(out.status.success(), "{args:?} failed: {out:?}");
    out
}

fn repo() -> tempfile::TempDir {
    let repo = tempfile::tempdir().unwrap();
    ok(repo.path(), &["init"]);
    ok(repo.path(), &["keygen"]);
    fs::write(repo.path().join("a.txt"), b"one\n").unwrap();
    ok(repo.path(), &["add", "a.txt"]);
    ok(repo.path(), &["commit", "-m", "c1"]);
    repo
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn push_with_a_message_saves_and_pop_restores() {
    let repo = repo();
    fs::write(repo.path().join("a.txt"), b"two\n").unwrap();
    ok(repo.path(), &["stash", "push", "-m", "wip"]);
    assert_eq!(fs::read(repo.path().join("a.txt")).unwrap(), b"one\n");
    assert!(stdout(&ok(repo.path(), &["stash", "list"])).contains("On main: wip"));
    ok(repo.path(), &["stash", "pop"]);
    assert_eq!(fs::read(repo.path().join("a.txt")).unwrap(), b"two\n");
}

#[test]
fn push_without_a_message_records_the_automatic_message() {
    let repo = repo();
    fs::write(repo.path().join("a.txt"), b"two\n").unwrap();
    ok(repo.path(), &["stash", "push"]);
    assert!(stdout(&ok(repo.path(), &["stash", "list"])).contains("WIP on main: "));
}

#[test]
fn push_and_save_record_the_same_message() {
    let a = repo();
    let b = repo();
    for (dir, verb) in [(&a, "push"), (&b, "save")] {
        fs::write(dir.path().join("a.txt"), b"two\n").unwrap();
        ok(dir.path(), &["stash", verb, "-m", "m"]);
    }
    let la = stdout(&ok(a.path(), &["stash", "list"]));
    let lb = stdout(&ok(b.path(), &["stash", "list"]));
    assert_eq!(la, lb);
}

#[test]
fn push_rejects_an_unknown_flag() {
    let repo = repo();
    fs::write(repo.path().join("a.txt"), b"two\n").unwrap();
    assert!(
        !run_in(repo.path(), &["stash", "push", "--bogus"])
            .status
            .success()
    );
    assert_eq!(fs::read(repo.path().join("a.txt")).unwrap(), b"two\n");
    assert!(stdout(&ok(repo.path(), &["stash", "list"])).is_empty());
}

#[test]
fn include_untracked_refuses_collisions_before_restoring_tracked_changes() {
    for flag in ["-u", "--include-untracked"] {
        let r = repo();
        let p = r.path();
        fs::write(p.join("a.txt"), b"edited").unwrap();
        fs::write(p.join("new.txt"), b"saved").unwrap();
        ok(p, &["stash", "push", flag]);
        assert!(!p.join("new.txt").exists());
        fs::write(p.join("new.txt"), b"saved").unwrap();
        for verb in ["apply", "pop"] {
            assert!(!run_in(p, &["stash", verb]).status.success());
            assert_eq!(fs::read(p.join("a.txt")).unwrap(), b"one\n");
            assert_eq!(fs::read(p.join("new.txt")).unwrap(), b"saved");
        }
        fs::remove_file(p.join("new.txt")).unwrap();
        ok(p, &["stash", "pop"]);
        assert_eq!(fs::read(p.join("new.txt")).unwrap(), b"saved");
        assert_eq!(fs::read(p.join("a.txt")).unwrap(), b"edited");
    }
}

#[test]
fn include_untracked_uses_nested_ignore_reincludes_and_keeps_ignored_files() {
    for flag in ["-u", "--include-untracked"] {
        let r = repo();
        let p = r.path();
        fs::create_dir(p.join("nested")).unwrap();
        fs::write(p.join(".gitignore"), b"*.log\n").unwrap();
        fs::write(p.join("nested/.gitignore"), b"!keep.log\n").unwrap();
        ok(p, &["add", ".gitignore", "nested/.gitignore"]);
        ok(p, &["commit", "-m", "ignore rules"]);
        fs::write(p.join("nested/keep.log"), b"saved").unwrap();
        fs::write(p.join("nested/skip.log"), b"ignored").unwrap();
        ok(p, &["stash", "push", flag]);
        assert!(!p.join("nested/keep.log").exists());
        assert_eq!(fs::read(p.join("nested/skip.log")).unwrap(), b"ignored");
        fs::write(p.join("nested/skip.log"), b"still local").unwrap();
        ok(p, &["stash", "pop"]);
        assert_eq!(fs::read(p.join("nested/keep.log")).unwrap(), b"saved");
        assert_eq!(fs::read(p.join("nested/skip.log")).unwrap(), b"still local");
    }
}

#[test]
fn path_stash_keeps_unmatched_worktree_and_index() {
    let r = repo();
    let p = r.path();
    fs::write(p.join("b.txt"), b"base").unwrap();
    ok(p, &["add", "b.txt"]);
    ok(p, &["commit", "-m", "second"]);
    fs::write(p.join("b.txt"), b"staged").unwrap();
    ok(p, &["add", "b.txt"]);
    fs::write(p.join("a.txt"), b"saved").unwrap();
    ok(p, &["stash", "push", "--", "a.txt"]);
    assert_eq!(fs::read(p.join("a.txt")).unwrap(), b"one\n");
    assert_eq!(fs::read(p.join("b.txt")).unwrap(), b"staged");
    ok(p, &["stash", "pop"]);
    assert_eq!(fs::read(p.join("a.txt")).unwrap(), b"saved");
    assert_eq!(fs::read(p.join("b.txt")).unwrap(), b"staged");
}

#[test]
fn selected_stash_preserves_same_basename_and_restores_deletions() {
    let r = repo();
    let p = r.path();
    fs::create_dir(p.join("sub")).unwrap();
    fs::write(p.join("sub/a.txt"), b"nested").unwrap();
    ok(p, &["add", "."]);
    ok(p, &["commit", "-m", "nested"]);
    fs::write(p.join("sub/a.txt"), b"keep").unwrap();
    fs::remove_file(p.join("a.txt")).unwrap();
    ok(p, &["stash", "push", "a.txt"]);
    assert_eq!(fs::read(p.join("sub/a.txt")).unwrap(), b"keep");
    assert!(p.join("a.txt").exists());
    ok(p, &["stash", "pop", "--index"]);
    assert!(!p.join("a.txt").exists());
    assert_eq!(fs::read(p.join("sub/a.txt")).unwrap(), b"keep");
}

#[test]
fn selected_untracked_stash_matches_git_worktree_results() {
    let k = repo();
    let g = tempfile::tempdir().unwrap();
    let git = |args: &[&str]| {
        let o = Command::new("git")
            .current_dir(g.path())
            .args(args)
            .output()
            .unwrap();
        assert!(o.status.success(), "git {args:?}: {o:?}");
    };
    git(&["init", "-b", "main"]);
    fs::write(g.path().join("a.txt"), b"one\n").unwrap();
    git(&["add", "."]);
    git(&[
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.com",
        "-c",
        "commit.gpgsign=false",
        "commit",
        "-m",
        "base",
    ]);
    for root in [k.path(), g.path()] {
        fs::write(root.join("a.txt"), b"edited").unwrap();
        fs::write(root.join("new.txt"), b"untracked").unwrap();
        fs::write(root.join("keep.txt"), b"keep").unwrap();
    }
    ok(k.path(), &["stash", "push", "-u", "--", "a.txt", "new.txt"]);
    git(&["stash", "push", "-u", "--", "a.txt", "new.txt"]);
    for root in [k.path(), g.path()] {
        assert!(!root.join("new.txt").exists());
        assert_eq!(fs::read(root.join("a.txt")).unwrap(), b"one\n");
        assert_eq!(fs::read(root.join("keep.txt")).unwrap(), b"keep");
    }
    ok(k.path(), &["stash", "pop"]);
    git(&["stash", "pop"]);
    for file in ["a.txt", "new.txt", "keep.txt"] {
        assert_eq!(
            fs::read(k.path().join(file)).unwrap(),
            fs::read(g.path().join(file)).unwrap()
        );
    }
}

#[test]
fn deletion_stash_refuses_a_new_untracked_file_after_head_drops_it() {
    let r = repo();
    let p = r.path();
    fs::remove_file(p.join("a.txt")).unwrap();
    ok(p, &["stash", "push"]);
    ok(p, &["rm", "a.txt"]);
    ok(p, &["commit", "-m", "drop"]);
    fs::write(p.join("a.txt"), b"precious").unwrap();
    for verb in ["apply", "pop"] {
        assert!(!run_in(p, &["stash", verb]).status.success());
        assert_eq!(fs::read(p.join("a.txt")).unwrap(), b"precious");
    }
}

#[test]
fn selected_stash_seeds_an_empty_index_and_root_path_resets_everything() {
    let r = repo();
    let p = r.path();
    fs::write(p.join("b.txt"), b"keep").unwrap();
    ok(p, &["add", "."]);
    ok(p, &["commit", "-m", "two"]);
    ok(p, &["stash", "push"]);
    ok(p, &["stash", "drop"]);
    fs::write(p.join("a.txt"), b"edit").unwrap();
    ok(p, &["stash", "push", "a.txt"]);
    let files = stdout(&ok(p, &["ls-files"]));
    assert!(files.contains("b.txt"), "{files}");
    ok(p, &["stash", "pop"]);
    ok(p, &["stash", "push", "--", "."]);
    assert_eq!(fs::read(p.join("a.txt")).unwrap(), b"one\n");
    assert!(!run_in(p, &["stash", "push", "missing"]).status.success());
}

#[test]
fn index_restore_refuses_conflicts_when_saved_worktree_equals_head() {
    let r = repo();
    let p = r.path();
    fs::write(p.join("a.txt"), b"staged").unwrap();
    ok(p, &["add", "a.txt"]);
    fs::write(p.join("a.txt"), b"one\n").unwrap();
    ok(p, &["stash", "push", "a.txt"]);
    fs::write(p.join("a.txt"), b"precious").unwrap();
    ok(p, &["add", "a.txt"]);
    assert!(!run_in(p, &["stash", "pop", "--index"]).status.success());
    assert_eq!(fs::read(p.join("a.txt")).unwrap(), b"precious");
}

#[test]
fn nested_changes_and_untracked_files_round_trip_through_apply_and_pop() {
    for verb in ["apply", "pop"] {
        for selected in [false, true] {
            let r = repo();
            let p = r.path();
            fs::create_dir(p.join("sub")).unwrap();
            fs::write(p.join("sub/tracked"), b"base").unwrap();
            ok(p, &["add", "."]);
            ok(p, &["commit", "-m", "nested"]);
            fs::write(p.join("sub/tracked"), b"edit").unwrap();
            fs::write(p.join("sub/untracked"), b"new").unwrap();
            if selected {
                ok(p, &["stash", "push", "-u", "sub/tracked", "sub/untracked"]);
            } else {
                ok(p, &["stash", "push", "-u"]);
            }
            assert_eq!(fs::read(p.join("sub/tracked")).unwrap(), b"base");
            assert!(!p.join("sub/untracked").exists());
            ok(p, &["stash", verb]);
            assert_eq!(fs::read(p.join("sub/tracked")).unwrap(), b"edit");
            assert_eq!(fs::read(p.join("sub/untracked")).unwrap(), b"new");
        }
    }
}
