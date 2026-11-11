//! `kit rebase --onto <newbase> <upstream> [<branch>]` replays the commits of
//! `<upstream>..<branch>` onto `<newbase>`. `--continue`, `--skip` and
//! `--abort` finish or undo it.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

struct Repo {
    _dir: tempfile::TempDir,
    _xdg: tempfile::TempDir,
    path: PathBuf,
    xdg: PathBuf,
}

fn run(repo: &Repo, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_kit"))
        .args(args)
        .current_dir(&repo.path)
        .env("XDG_CONFIG_HOME", &repo.xdg)
        .output()
        .expect("spawn kit")
}

fn ok(repo: &Repo, args: &[&str]) -> String {
    let out = run(repo, args);
    assert!(out.status.success(), "{args:?} failed: {out:?}");
    String::from_utf8(out.stdout).unwrap()
}

fn commit(repo: &Repo, file: &str, body: &str, message: &str) {
    fs::write(repo.path.join(file), body).unwrap();
    ok(repo, &["add", file]);
    ok(repo, &["commit", "-m", message]);
}

fn rev(repo: &Repo, spec: &str) -> String {
    ok(repo, &["rev-parse", spec]).trim().to_owned()
}

fn subjects(repo: &Repo, range: &str) -> Vec<String> {
    ok(repo, &["log", "--oneline", range])
        .lines()
        .filter_map(|line| line.split_once(' '))
        .map(|(_, subject)| subject.to_owned())
        .collect()
}

/// `main` is `c0 <- m1`. `feature` is `c0 <- f1`. `topic` is
/// `f1 <- t1 <- t2`. `shared.txt` changes on `main` and in `t1`, so the replay
/// of `t1` onto `main` conflicts. `topic` is checked out.
fn repo() -> Repo {
    let dir = tempfile::tempdir().unwrap();
    let xdg = tempfile::tempdir().unwrap();
    let repo = Repo {
        path: dir.path().to_owned(),
        xdg: xdg.path().to_owned(),
        _dir: dir,
        _xdg: xdg,
    };
    ok(&repo, &["init"]);
    ok(&repo, &["keygen"]);
    commit(&repo, "shared.txt", "base\n", "c0");
    ok(&repo, &["branch", "feature"]);
    commit(&repo, "m.txt", "m\n", "m0");
    commit(&repo, "shared.txt", "main\n", "m1");
    ok(&repo, &["checkout", "feature"]);
    commit(&repo, "f.txt", "f\n", "f1");
    ok(&repo, &["branch", "topic"]);
    ok(&repo, &["checkout", "topic"]);
    commit(&repo, "shared.txt", "topic\n", "t1");
    commit(&repo, "t2.txt", "2\n", "t2");
    repo
}

/// `main` and `topic` that touch different files, so a replay is clean.
fn clean_repo() -> Repo {
    let repo = repo();
    ok(&repo, &["checkout", "main"]);
    ok(&repo, &["reset", "--hard", "HEAD~2"]);
    commit(&repo, "m.txt", "m\n", "m1");
    ok(&repo, &["checkout", "topic"]);
    ok(&repo, &["reset", "--hard", "HEAD~2"]);
    commit(&repo, "t1.txt", "1\n", "t1");
    commit(&repo, "t2.txt", "2\n", "t2");
    repo
}

fn assert_verifies(repo: &Repo, spec: &str) {
    let out = run(repo, &["verify", spec]);
    assert!(out.status.success(), "verify {spec}: {out:?}");
}

#[test]
fn onto_replays_only_the_commits_after_the_upstream() {
    let repo = clean_repo();
    let old = rev(&repo, "topic");
    let out = run(&repo, &["rebase", "--onto", "main", "feature"]);
    assert!(out.status.success(), "{out:?}");

    assert_ne!(rev(&repo, "topic"), old);
    assert_eq!(subjects(&repo, "topic"), ["t2", "t1", "m1", "c0"]);
    assert!(
        !repo.path.join("f.txt").exists(),
        "f1 stays behind the upstream"
    );
    for file in ["m.txt", "t1.txt", "t2.txt"] {
        assert!(repo.path.join(file).exists(), "{file}");
    }
    assert_verifies(&repo, "topic");
    assert_verifies(&repo, "topic~1");
    assert!(!repo.path.join(".kit/rebase-apply").exists());
}

#[test]
fn onto_with_a_branch_argument_rebases_that_branch() {
    let repo = clean_repo();
    let old = rev(&repo, "topic");
    ok(&repo, &["checkout", "main"]);
    let out = run(&repo, &["rebase", "--onto", "main", "feature", "topic"]);
    assert!(out.status.success(), "{out:?}");

    assert_eq!(subjects(&repo, "topic"), ["t2", "t1", "m1", "c0"]);
    assert_ne!(rev(&repo, "topic"), old);
    assert_eq!(rev(&repo, "HEAD"), rev(&repo, "topic"));
    assert_verifies(&repo, "HEAD");
}

#[test]
fn onto_conflict_then_continue_finishes_the_rebase() {
    let repo = repo();
    let old = rev(&repo, "topic");
    let out = run(&repo, &["rebase", "--onto", "main", "feature"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("Merge conflict in shared.txt"), "{stderr}");
    assert!(stderr.contains("kit rebase --continue"), "{stderr}");
    assert!(repo.path.join(".kit/rebase-apply").exists());

    fs::write(repo.path.join("shared.txt"), "resolved\n").unwrap();
    ok(&repo, &["add", "shared.txt"]);
    ok(&repo, &["rebase", "--continue"]);

    assert_eq!(subjects(&repo, "topic"), ["t2", "t1", "m1", "m0", "c0"]);
    assert_ne!(rev(&repo, "topic"), old);
    assert_eq!(
        fs::read_to_string(repo.path.join("shared.txt")).unwrap(),
        "resolved\n"
    );
    assert!(!repo.path.join("f.txt").exists());
    assert_verifies(&repo, "topic");
    assert_verifies(&repo, "topic~1");
    assert!(!repo.path.join(".kit/rebase-apply").exists());
}

#[test]
fn onto_conflict_then_abort_restores_the_branch() {
    let repo = repo();
    let old = rev(&repo, "topic");
    let out = run(&repo, &["rebase", "--onto", "main", "feature"]);
    assert!(!out.status.success());

    ok(&repo, &["rebase", "--abort"]);
    assert_eq!(rev(&repo, "topic"), old);
    assert_eq!(rev(&repo, "HEAD"), old);
    assert_eq!(
        fs::read_to_string(repo.path.join("shared.txt")).unwrap(),
        "topic\n"
    );
    assert!(!repo.path.join(".kit/rebase-apply").exists());
}

#[test]
fn onto_conflict_then_skip_drops_the_conflicting_commit() {
    let repo = repo();
    let out = run(&repo, &["rebase", "--onto", "main", "feature"]);
    assert!(!out.status.success());

    ok(&repo, &["rebase", "--skip"]);
    assert_eq!(subjects(&repo, "topic"), ["t2", "m1", "m0", "c0"]);
    assert_verifies(&repo, "topic");
}

#[test]
fn onto_rejects_a_missing_upstream_and_a_third_revision() {
    let repo = clean_repo();
    for args in [
        &["rebase", "--onto", "main"][..],
        &["rebase", "--onto", "main", "feature", "topic", "main"],
        &["rebase", "main", "topic"],
    ] {
        let out = run(&repo, args);
        assert_eq!(out.status.code(), Some(64), "{args:?}: {out:?}");
    }
}

#[test]
fn onto_conflicts_with_the_resume_flags() {
    let repo = clean_repo();
    for flag in ["--continue", "--abort", "--skip"] {
        let out = run(&repo, &["rebase", "--onto", "main", flag]);
        assert_eq!(out.status.code(), Some(64), "{flag}: {out:?}");
    }
}

#[test]
fn onto_with_an_unknown_revision_changes_nothing() {
    let repo = clean_repo();
    let old = rev(&repo, "topic");
    for args in [
        &["rebase", "--onto", "nope", "feature"][..],
        &["rebase", "--onto", "main", "nope"],
        &["rebase", "--onto", "main", "feature", "nope"],
    ] {
        let out = run(&repo, args);
        assert!(!out.status.success(), "{args:?}: {out:?}");
        let stderr = String::from_utf8(out.stderr).unwrap();
        assert!(stderr.contains("nope"), "{args:?}: {stderr}");
    }
    assert_eq!(rev(&repo, "topic"), old);
    assert!(!repo.path.join(".kit/rebase-apply").exists());
}
