//! `kit fetch --prune` over a `kit+file://` remote: it deletes the
//! remote-tracking refs of branches the remote lost, and nothing else.
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

/// A repo that pushed `main` and `topic` to `origin`, and a local tag `v1`.
fn pushed_repo() -> (tempfile::TempDir, tempfile::TempDir) {
    let repo = tempfile::tempdir().unwrap();
    ok(repo.path(), &["init"]);
    ok(repo.path(), &["keygen"]);
    fs::write(repo.path().join("a.txt"), b"one").unwrap();
    ok(repo.path(), &["add", "a.txt"]);
    ok(repo.path(), &["commit", "-m", "c1"]);
    ok(repo.path(), &["branch", "topic"]);
    ok(repo.path(), &["tag", "v1"]);
    let remote = tempfile::tempdir().unwrap();
    let url = format!("kit+file://{}", remote.path().display());
    ok(repo.path(), &["remote", "add", "origin", &url]);
    ok(repo.path(), &["push", "origin", "main:main"]);
    ok(repo.path(), &["push", "origin", "topic:topic"]);
    (repo, remote)
}

fn lose_remote_topic(remote: &Path) {
    fs::remove_file(remote.join("refs/heads/topic")).unwrap();
    fs::remove_file(remote.join("refs/kit/packmap/topic")).unwrap();
}

fn tracking(repo: &Path, name: &str) -> bool {
    repo.join(".kit/refs/remotes/origin").join(name).is_file()
}

#[test]
fn prune_deletes_the_tracking_ref_of_a_lost_branch_only() {
    let (repo, remote) = pushed_repo();
    assert!(tracking(repo.path(), "topic"));
    lose_remote_topic(remote.path());

    ok(repo.path(), &["fetch", "origin"]);
    assert!(
        tracking(repo.path(), "topic"),
        "a fetch without --prune keeps it"
    );

    let out = ok(repo.path(), &["fetch", "--prune", "origin"]);
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("[deleted]") && stderr.contains("origin/topic"),
        "stderr: {stderr}"
    );
    assert!(!tracking(repo.path(), "topic"));
    assert!(tracking(repo.path(), "main"));
    assert!(repo.path().join(".kit/refs/heads/topic").is_file());
    assert!(repo.path().join(".kit/refs/tags/v1").is_file());
}

#[test]
fn prune_json_names_the_pruned_refs() {
    let (repo, remote) = pushed_repo();
    lose_remote_topic(remote.path());
    let out = ok(
        repo.path(),
        &["fetch", "--prune", "--format=json", "origin"],
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.contains("\"pruned\":[\"topic\"]"),
        "stdout: {stdout}"
    );
}

#[test]
fn prune_with_nothing_lost_changes_nothing() {
    let (repo, _remote) = pushed_repo();
    let out = ok(repo.path(), &["fetch", "-p", "origin"]);
    assert!(out.stderr.is_empty(), "stderr: {:?}", out.stderr);
    assert!(tracking(repo.path(), "topic"));
    assert!(tracking(repo.path(), "main"));
}

#[test]
fn prune_reports_maintenance_and_honors_the_repo_switch() {
    let (publisher, remote) = pushed_repo();
    let clone = tempfile::tempdir().unwrap();
    let url = format!("kit+file://{}", remote.path().display());
    ok(
        publisher.path(),
        &["clone", &url, clone.path().to_str().unwrap()],
    );
    let stamp = clone.path().join(".kit/gc-auto");
    assert!(stamp.is_file());
    let leftover = clone
        .path()
        .join(".kit/objects/pack/.11111111111111111111111111111111.tmp.pack");
    fs::write(&leftover, b"old stage").unwrap();
    fs::File::open(&leftover)
        .unwrap()
        .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1))
        .unwrap();

    lose_remote_topic(remote.path());
    ok(clone.path(), &["config", "--local", "gc.auto", "false"]);
    let disabled = ok(clone.path(), &["fetch", "-p", "--format=json"]);
    assert!(
        !String::from_utf8(disabled.stdout)
            .unwrap()
            .contains("\"maintenance\"")
    );
    assert!(leftover.exists());

    ok(clone.path(), &["config", "--local", "gc.auto", "true"]);
    fs::write(publisher.path().join("a.txt"), b"two").unwrap();
    ok(publisher.path(), &["add", "a.txt"]);
    ok(publisher.path(), &["commit", "-m", "c2"]);
    ok(publisher.path(), &["push", "origin", "main:main"]);
    let swept = ok(clone.path(), &["fetch", "-q", "--format=json"]);
    let report: serde_json::Value = serde_json::from_slice(&swept.stdout).unwrap();
    assert_eq!(report["maintenance"]["leftovers_removed"], 1);
    assert_eq!(report["maintenance"]["bytes_reclaimed"], 9);
    assert_eq!(report["maintenance"]["collection"], "not_due");
    assert!(
        !String::from_utf8(swept.stderr)
            .unwrap()
            .contains("maintenance:")
    );
    assert!(!leftover.exists());
}
