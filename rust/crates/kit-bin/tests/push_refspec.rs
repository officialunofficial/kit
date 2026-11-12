//! `kit push <remote> <src>:<dst>`: branch refspecs over a `kit+file://`
//! remote. The push runs the same path as a plain push, so the lease and the
//! non-fast-forward check apply. Wildcards, a leading `+`, a delete and refs
//! outside `refs/heads/` are rejected before the remote is contacted.
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

fn ok(cwd: &Path, args: &[&str]) {
    let out = run_in(cwd, args);
    assert!(out.status.success(), "{args:?} failed: {out:?}");
}

fn commit(repo: &Path, content: &[u8], message: &str) {
    fs::write(repo.join("a.txt"), content).unwrap();
    ok(repo, &["add", "a.txt"]);
    ok(repo, &["commit", "-m", message]);
}

/// A repo with one commit and a remote `origin` that points at an empty
/// directory.
fn repo_and_remote() -> (tempfile::TempDir, tempfile::TempDir) {
    let repo = tempfile::tempdir().unwrap();
    ok(repo.path(), &["init"]);
    ok(repo.path(), &["keygen"]);
    commit(repo.path(), b"one", "c1");
    let remote = tempfile::tempdir().unwrap();
    let url = format!("kit+file://{}", remote.path().display());
    ok(repo.path(), &["remote", "add", "origin", &url]);
    (repo, remote)
}

fn read_ref(path: &Path) -> Option<String> {
    fs::read_to_string(path).ok().map(|s| s.trim().to_owned())
}

fn local_branch(repo: &Path, name: &str) -> String {
    read_ref(&repo.join(".kit/refs/heads").join(name)).unwrap()
}

fn remote_branch(remote: &Path, name: &str) -> Option<String> {
    read_ref(&remote.join("refs/heads").join(name))
}

fn tracking(repo: &Path, name: &str) -> Option<String> {
    read_ref(&repo.join(".kit/refs/remotes/origin").join(name))
}

#[test]
fn refspec_pushes_a_branch_under_another_name() {
    let (repo, remote) = repo_and_remote();
    ok(repo.path(), &["push", "origin", "main:release"]);
    let tip = local_branch(repo.path(), "main");
    assert_eq!(remote_branch(remote.path(), "release"), Some(tip.clone()));
    assert_eq!(remote_branch(remote.path(), "main"), None);
    assert_eq!(tracking(repo.path(), "release"), Some(tip));
    // A refspec push records no upstream without -u.
    let out = run_in(repo.path(), &["push"]);
    assert!(!out.status.success(), "no upstream expected: {out:?}");
}

#[test]
fn refspec_accepts_full_heads_refs_and_a_branch_that_is_not_current() {
    let (repo, remote) = repo_and_remote();
    ok(repo.path(), &["branch", "topic"]);
    ok(
        repo.path(),
        &["push", "origin", "refs/heads/topic:refs/heads/topic2"],
    );
    assert_eq!(
        remote_branch(remote.path(), "topic2"),
        Some(local_branch(repo.path(), "topic"))
    );
}

#[test]
fn refspec_with_set_upstream_records_the_upstream() {
    let (repo, remote) = repo_and_remote();
    ok(repo.path(), &["push", "-u", "origin", "main:release"]);
    commit(repo.path(), b"two", "c2");
    ok(repo.path(), &["push"]);
    assert_eq!(
        remote_branch(remote.path(), "release"),
        Some(local_branch(repo.path(), "main"))
    );
}

#[test]
fn refspec_push_rejects_a_non_fast_forward() {
    let (repo, remote) = repo_and_remote();
    ok(repo.path(), &["push", "origin", "main:release"]);
    // The remote moves on its own: the lease no longer holds.
    let other = "0".repeat(64);
    fs::write(
        remote.path().join("refs/heads/release"),
        format!("{other}\n"),
    )
    .unwrap();
    commit(repo.path(), b"two", "c2");
    let out = run_in(repo.path(), &["push", "origin", "main:release"]);
    assert!(!out.status.success(), "must be rejected: {out:?}");
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("non-fast-forward"), "stderr: {stderr}");
    assert_eq!(remote_branch(remote.path(), "release"), Some(other));
    ok(repo.path(), &["push", "--force", "origin", "main:release"]);
    assert_eq!(
        remote_branch(remote.path(), "release"),
        Some(local_branch(repo.path(), "main"))
    );
}

#[test]
fn refspec_dry_run_contacts_nothing() {
    let (repo, remote) = repo_and_remote();
    let out = run_in(
        repo.path(),
        &["push", "--dry-run", "origin", "main:release"],
    );
    assert!(out.status.success(), "{out:?}");
    assert!(
        String::from_utf8(out.stderr)
            .unwrap()
            .contains("main -> origin:release")
    );
    assert_eq!(remote_branch(remote.path(), "release"), None);
}

#[test]
fn unsupported_refspecs_are_rejected_before_any_push() {
    let (repo, remote) = repo_and_remote();
    let long = format!("main:{}", "a".repeat(600));
    let cases: [(&str, &str); 11] = [
        ("refs/heads/*:refs/heads/*", "wildcards"),
        ("main:release*", "wildcards"),
        ("+main:main", "leading '+'"),
        (":release", "deleting a remote ref"),
        ("main", "expected <src>:<dst>"),
        ("main:", "not a valid branch name"),
        ("main:a:b", "not a valid branch name"),
        ("main:refs/tags/v1", "only refs/heads/"),
        ("refs/tags/v1:refs/tags/v1", "only refs/heads/"),
        ("main:refs/remotes/origin/x", "only refs/heads/"),
        (&long, "branch name is too long"),
    ];
    for (spec, reason) in cases {
        let out = run_in(repo.path(), &["push", "origin", spec]);
        assert!(!out.status.success(), "{spec:?} must fail: {out:?}");
        let stderr = String::from_utf8(out.stderr).unwrap();
        assert!(stderr.contains(reason), "{spec:?}: {stderr}");
    }
    let out = run_in(repo.path(), &["push", "origin", "nosuch:release"]);
    assert!(!out.status.success());
    assert!(
        String::from_utf8(out.stderr)
            .unwrap()
            .contains("does not match any local branch")
    );
    let out = run_in(repo.path(), &["push", "--all", "origin", "main:main"]);
    assert!(!out.status.success(), "--all with a refspec: {out:?}");
    assert_eq!(fs::read_dir(remote.path()).unwrap().count(), 0);
}
