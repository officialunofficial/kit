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
fn push_rejects_an_unknown_flag_and_a_pathspec() {
    let repo = repo();
    fs::write(repo.path().join("a.txt"), b"two\n").unwrap();
    for args in [
        &["stash", "push", "--bogus"][..],
        &["stash", "push", "a.txt"][..],
    ] {
        assert!(!run_in(repo.path(), args).status.success(), "{args:?}");
    }
    assert_eq!(fs::read(repo.path().join("a.txt")).unwrap(), b"two\n");
    assert!(stdout(&ok(repo.path(), &["stash", "list"])).is_empty());
}

#[test]
fn include_untracked_refuses_collisions_before_restoring_tracked_changes() {
    for flag in ["-u", "--include-untracked"] {
        let r = repo(); let p = r.path();
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

