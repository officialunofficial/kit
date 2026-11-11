//! `kit branch -r` and `kit branch -a` list the remote-tracking branches.
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

fn ok(cwd: &Path, args: &[&str]) -> String {
    let out = run_in(cwd, args);
    assert!(out.status.success(), "{args:?} failed: {out:?}");
    String::from_utf8(out.stdout).unwrap()
}

/// A repo on `main` with a local branch `topic`, that pushed both to
/// `origin` and `main` to `upstream`.
fn repo() -> (tempfile::TempDir, [tempfile::TempDir; 2]) {
    let repo = tempfile::tempdir().unwrap();
    ok(repo.path(), &["init"]);
    ok(repo.path(), &["keygen"]);
    fs::write(repo.path().join("a.txt"), b"one").unwrap();
    ok(repo.path(), &["add", "a.txt"]);
    ok(repo.path(), &["commit", "-m", "first commit"]);
    ok(repo.path(), &["branch", "topic"]);
    let remotes = [tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap()];
    for (name, dir) in ["origin", "upstream"].iter().zip(&remotes) {
        let url = format!("kit+file://{}", dir.path().display());
        ok(repo.path(), &["remote", "add", name, &url]);
    }
    ok(repo.path(), &["push", "origin", "main:main"]);
    ok(repo.path(), &["push", "origin", "topic:topic"]);
    ok(repo.path(), &["push", "upstream", "main:main"]);
    (repo, remotes)
}

#[test]
fn dash_r_lists_the_tracking_branches_of_every_remote() {
    let (repo, _remotes) = repo();
    assert_eq!(
        ok(repo.path(), &["branch", "-r"]),
        "  origin/main\n  origin/topic\n  upstream/main\n"
    );
}

#[test]
fn dash_a_lists_local_then_remote_branches() {
    let (repo, _remotes) = repo();
    assert_eq!(
        ok(repo.path(), &["branch", "-a"]),
        "* main\n  topic\n  remotes/origin/main\n  remotes/origin/topic\n  remotes/upstream/main\n"
    );
    // A plain listing stays local.
    assert_eq!(ok(repo.path(), &["branch"]), "* main\n  topic\n");
}

#[test]
fn patterns_and_verbose_apply_to_remote_branches() {
    let (repo, _remotes) = repo();
    assert_eq!(
        ok(repo.path(), &["branch", "-r", "origin/*"]),
        "  origin/main\n  origin/topic\n"
    );
    let verbose = ok(repo.path(), &["branch", "-r", "-v", "upstream/*"]);
    assert!(
        verbose.starts_with("  upstream/main ") && verbose.ends_with(" first commit\n"),
        "verbose: {verbose}"
    );
}

#[test]
fn json_marks_remote_branches_and_never_the_current_one() {
    let (repo, _remotes) = repo();
    // A local branch that is named like a tracking branch stays unmarked
    // in the remote rows.
    ok(repo.path(), &["branch", "origin/main"]);
    ok(repo.path(), &["switch", "origin/main"]);
    let out = ok(
        repo.path(),
        &["branch", "-r", "--format=json", "origin/main"],
    );
    assert!(
        out.contains("\"name\":\"origin/main\",\"current\":false,\"remote\":true"),
        "json: {out}"
    );
    let text = ok(repo.path(), &["branch", "-r", "origin/main"]);
    assert_eq!(text, "  origin/main\n");
}

#[test]
fn dash_r_and_dash_a_conflict_and_do_not_mix_with_delete() {
    let (repo, _remotes) = repo();
    for args in [
        &["branch", "-r", "-a"][..],
        &["branch", "-r", "-d", "topic"],
        &["branch", "-a", "-m", "topic", "x"],
    ] {
        let out = run_in(repo.path(), args);
        assert!(!out.status.success(), "{args:?} must fail: {out:?}");
    }
    assert_eq!(ok(repo.path(), &["branch"]), "* main\n  topic\n");
}
