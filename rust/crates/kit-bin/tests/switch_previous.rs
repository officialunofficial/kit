//! Previous HEAD selection.
#![allow(clippy::unwrap_used)]
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
fn previous_head_toggles_branches_and_detached_commits() {
    let r = repo();
    let p = r.path();
    assert!(!run_in(p, &["switch", "-"]).status.success());
    ok(p, &["switch", "-c", "other"]);
    ok(p, &["switch", "-"]);
    assert!(String::from_utf8_lossy(&ok(p, &["symbolic-ref", "HEAD"]).stdout).contains("main"));
    ok(p, &["checkout", "@{-1}"]);
    let hash = stdout(&ok(p, &["rev-parse", "HEAD"]));
    ok(p, &["checkout", hash.trim()]);
    ok(p, &["switch", "main"]);
    ok(p, &["switch", "-"]);
    assert!(!run_in(p, &["symbolic-ref", "HEAD"]).status.success());
    assert!(!run_in(p, &["switch", "@{-2}"]).status.success());
}

#[test]
fn previous_head_is_local_state_and_does_not_block_verification() {
    let r = repo();
    let p = r.path();
    ok(p, &["switch", "-c", "other"]);
    let old = fs::read(p.join(".kit/PREVIOUS_HEAD")).unwrap();
    ok(p, &["switch", "other"]);
    assert_eq!(fs::read(p.join(".kit/PREVIOUS_HEAD")).unwrap(), old);
    ok(p, &["verify", "HEAD"]);
    let id = stdout(&ok(p, &["rev-parse", "HEAD"]));
    ok(p, &["closure", "verify", id.trim()]);
    ok(p, &["gc"]);
    fs::write(p.join(".kit/PREVIOUS_HEAD"), b"malformed").unwrap();
    let out = run_in(p, &["switch", "-"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("no previous branch"));
}

#[test]
fn detached_previous_head_ignores_a_branch_named_for_its_commit() {
    let r = repo();
    let p = r.path();
    let first = stdout(&ok(p, &["rev-parse", "HEAD"]));
    let first = first.trim();
    fs::write(p.join("a.txt"), b"two\n").unwrap();
    ok(p, &["add", "a.txt"]);
    ok(p, &["commit", "-m", "second"]);
    ok(p, &["branch", first]);
    ok(p, &["checkout", "HEAD~1"]);
    ok(p, &["switch", "main"]);
    ok(p, &["switch", "-"]);
    assert!(!run_in(p, &["symbolic-ref", "HEAD"]).status.success());
    assert_eq!(stdout(&ok(p, &["rev-parse", "HEAD"])).trim(), first);
    assert_eq!(fs::read(p.join("a.txt")).unwrap(), b"one\n");
}

#[test]
fn previous_branch_named_for_a_commit_resolves_the_branch_tip() {
    let r = repo();
    let p = r.path();
    let first = stdout(&ok(p, &["rev-parse", "HEAD"]));
    let first = first.trim();
    fs::write(p.join("a.txt"), b"two\n").unwrap();
    ok(p, &["add", "a.txt"]);
    ok(p, &["commit", "-m", "second"]);
    let second = stdout(&ok(p, &["rev-parse", "HEAD"]));
    ok(p, &["switch", "-c", first]);
    ok(p, &["switch", "main"]);
    ok(p, &["switch", "-"]);
    assert!(stdout(&ok(p, &["symbolic-ref", "HEAD"])).contains(first));
    assert_eq!(fs::read(p.join("a.txt")).unwrap(), b"two\n");
    assert_eq!(stdout(&ok(p, &["rev-parse", "HEAD"])).trim(), second.trim());
    ok(p, &["switch", "main"]);
    ok(p, &["switch", "-c", "from-previous", "-"]);
    assert_eq!(stdout(&ok(p, &["rev-parse", "HEAD"])).trim(), second.trim());
}
