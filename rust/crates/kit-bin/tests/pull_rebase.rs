//! `kit pull --rebase` and `kit pull --no-ff` over a `kit+file://` remote.
//! `--rebase` fetches, then replays the current branch onto the fetched branch
//! through the rebase machinery. `--no-ff` fetches, then merges the fetched
//! branch and always writes a merge commit.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct Fixture {
    /// Keeps the temporary directories alive. `dirs[1]` is the remote.
    dirs: Vec<tempfile::TempDir>,
    /// The repository that pushes.
    upstream: PathBuf,
    /// The clone that pulls.
    local: PathBuf,
    xdg: PathBuf,
}

fn run_in(fixture: &Fixture, cwd: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_kit"))
        .args(args)
        .current_dir(cwd)
        .env("XDG_CONFIG_HOME", &fixture.xdg)
        .output()
        .expect("spawn kit")
}

fn ok_in(fixture: &Fixture, cwd: &Path, args: &[&str]) -> String {
    let out = run_in(fixture, cwd, args);
    assert!(out.status.success(), "{args:?} failed: {out:?}");
    String::from_utf8(out.stdout).unwrap()
}

fn commit_in(fixture: &Fixture, cwd: &Path, file: &str, body: &str, message: &str) {
    fs::write(cwd.join(file), body).unwrap();
    ok_in(fixture, cwd, &["add", file]);
    ok_in(fixture, cwd, &["commit", "-m", message]);
}

fn rev(fixture: &Fixture, cwd: &Path, spec: &str) -> String {
    ok_in(fixture, cwd, &["rev-parse", spec]).trim().to_owned()
}

fn subjects(fixture: &Fixture) -> Vec<String> {
    ok_in(fixture, &fixture.local, &["log", "--oneline"])
        .lines()
        .filter_map(|line| line.split_once(' '))
        .map(|(_, subject)| subject.to_owned())
        .collect()
}

fn assert_verifies(fixture: &Fixture, spec: &str) {
    let out = run_in(fixture, &fixture.local, &["verify", spec]);
    assert!(out.status.success(), "verify {spec}: {out:?}");
}

fn rebase_state(fixture: &Fixture) -> bool {
    fixture.local.join(".kit/rebase-apply").exists()
}

/// `upstream` pushed `c0`, which sets `shared.txt`. `local` is a clone of it.
fn fixture() -> Fixture {
    let upstream = tempfile::tempdir().unwrap();
    let remote = tempfile::tempdir().unwrap();
    let parent = tempfile::tempdir().unwrap();
    let xdg = tempfile::tempdir().unwrap();
    let fixture = Fixture {
        upstream: upstream.path().to_owned(),
        local: parent.path().join("local"),
        xdg: xdg.path().to_owned(),
        dirs: vec![upstream, remote, parent, xdg],
    };
    let url = format!("kit+file://{}", fixture.dirs[1].path().display());
    ok_in(&fixture, &fixture.upstream, &["init"]);
    ok_in(&fixture, &fixture.upstream, &["keygen"]);
    commit_in(&fixture, &fixture.upstream, "shared.txt", "base\n", "c0");
    ok_in(
        &fixture,
        &fixture.upstream,
        &["remote", "add", "origin", &url],
    );
    ok_in(
        &fixture,
        &fixture.upstream,
        &["push", "origin", "main:main"],
    );
    ok_in(
        &fixture,
        fixture.local.parent().unwrap(),
        &["clone", &url, fixture.local.to_str().unwrap()],
    );
    ok_in(&fixture, &fixture.local, &["keygen"]);
    fixture
}

fn push_upstream(fixture: &Fixture, file: &str, body: &str, message: &str) {
    commit_in(fixture, &fixture.upstream, file, body, message);
    ok_in(fixture, &fixture.upstream, &["push", "origin", "main:main"]);
}

fn commit_local(fixture: &Fixture, file: &str, body: &str, message: &str) {
    commit_in(fixture, &fixture.local, file, body, message);
}

#[test]
fn pull_rebase_replays_local_commits_onto_the_fetched_branch() {
    let fixture = fixture();
    push_upstream(&fixture, "u.txt", "u\n", "u1");
    commit_local(&fixture, "l1.txt", "1\n", "l1");
    commit_local(&fixture, "l2.txt", "2\n", "l2");
    let old = rev(&fixture, &fixture.local, "HEAD");

    ok_in(&fixture, &fixture.local, &["pull", "--rebase"]);

    assert_eq!(subjects(&fixture), ["l2", "l1", "u1", "c0"]);
    assert_ne!(rev(&fixture, &fixture.local, "HEAD"), old);
    for file in ["u.txt", "l1.txt", "l2.txt"] {
        assert!(fixture.local.join(file).exists(), "{file}");
    }
    assert_verifies(&fixture, "HEAD");
    assert_verifies(&fixture, "HEAD~1");
    assert!(!rebase_state(&fixture));
}

#[test]
fn pull_rebase_moves_a_branch_that_has_no_local_commits_forward() {
    let fixture = fixture();
    push_upstream(&fixture, "u.txt", "u\n", "u1");
    ok_in(&fixture, &fixture.local, &["pull", "--rebase"]);
    assert_eq!(subjects(&fixture), ["u1", "c0"]);
    assert_eq!(
        rev(&fixture, &fixture.local, "HEAD"),
        rev(&fixture, &fixture.upstream, "HEAD")
    );
}

#[test]
fn pull_rebase_changes_nothing_when_the_branch_holds_the_fetched_tip() {
    let fixture = fixture();
    commit_local(&fixture, "l1.txt", "1\n", "l1");
    let old = rev(&fixture, &fixture.local, "HEAD");

    let out = run_in(&fixture, &fixture.local, &["pull", "--rebase"]);
    assert!(out.status.success(), "{out:?}");
    assert!(
        String::from_utf8(out.stderr)
            .unwrap()
            .contains("is up to date")
    );
    assert_eq!(rev(&fixture, &fixture.local, "HEAD"), old);
    assert!(!rebase_state(&fixture));
}

/// The upstream and the local branch both change `shared.txt`, so the replay
/// of `l1` conflicts. `l2` adds a file.
fn conflicting() -> Fixture {
    let fixture = fixture();
    push_upstream(&fixture, "shared.txt", "upstream\n", "u1");
    commit_local(&fixture, "shared.txt", "local\n", "l1");
    commit_local(&fixture, "l2.txt", "2\n", "l2");
    fixture
}

#[test]
fn pull_rebase_conflict_pauses_with_the_rebase_instructions_then_continue_finishes() {
    let fixture = conflicting();
    let out = run_in(&fixture, &fixture.local, &["pull", "--rebase"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("Merge conflict in shared.txt"), "{stderr}");
    assert!(stderr.contains("kit rebase --continue"), "{stderr}");
    assert!(rebase_state(&fixture));

    fs::write(fixture.local.join("shared.txt"), "resolved\n").unwrap();
    ok_in(&fixture, &fixture.local, &["add", "shared.txt"]);
    ok_in(&fixture, &fixture.local, &["rebase", "--continue"]);

    assert_eq!(subjects(&fixture), ["l2", "l1", "u1", "c0"]);
    assert_eq!(
        fs::read_to_string(fixture.local.join("shared.txt")).unwrap(),
        "resolved\n"
    );
    assert_verifies(&fixture, "HEAD");
    assert_verifies(&fixture, "HEAD~1");
    assert!(!rebase_state(&fixture));
}

#[test]
fn pull_rebase_conflict_then_abort_restores_the_branch() {
    let fixture = conflicting();
    let old = rev(&fixture, &fixture.local, "HEAD");
    let out = run_in(&fixture, &fixture.local, &["pull", "--rebase"]);
    assert!(!out.status.success());

    ok_in(&fixture, &fixture.local, &["rebase", "--abort"]);
    assert_eq!(rev(&fixture, &fixture.local, "HEAD"), old);
    assert_eq!(
        fs::read_to_string(fixture.local.join("shared.txt")).unwrap(),
        "local\n"
    );
    assert!(!rebase_state(&fixture));
}

#[test]
fn pull_rebase_conflict_then_skip_drops_the_conflicting_commit() {
    let fixture = conflicting();
    let out = run_in(&fixture, &fixture.local, &["pull", "--rebase"]);
    assert!(!out.status.success());

    ok_in(&fixture, &fixture.local, &["rebase", "--skip"]);
    assert_eq!(subjects(&fixture), ["l2", "u1", "c0"]);
    assert_verifies(&fixture, "HEAD");
}

#[test]
fn pull_rebase_does_not_combine_with_all_or_no_ff() {
    let fixture = fixture();
    for args in [
        &["pull", "--rebase", "--all"][..],
        &["pull", "--rebase", "--no-ff"],
    ] {
        let out = run_in(&fixture, &fixture.local, args);
        assert_eq!(out.status.code(), Some(64), "{args:?}: {out:?}");
    }
}

#[test]
fn pull_rebase_from_an_unknown_remote_changes_nothing() {
    let fixture = fixture();
    commit_local(&fixture, "l1.txt", "1\n", "l1");
    let old = rev(&fixture, &fixture.local, "HEAD");
    let out = run_in(&fixture, &fixture.local, &["pull", "--rebase", "nope"]);
    assert!(!out.status.success());
    assert!(String::from_utf8(out.stderr).unwrap().contains("nope"));
    assert_eq!(rev(&fixture, &fixture.local, "HEAD"), old);
    assert!(!rebase_state(&fixture));
}

#[test]
fn pull_rebase_refuses_a_detached_head() {
    let fixture = fixture();
    let head = rev(&fixture, &fixture.local, "HEAD");
    ok_in(&fixture, &fixture.local, &["checkout", &head]);
    let out = run_in(&fixture, &fixture.local, &["pull", "--rebase"]);
    assert_eq!(out.status.code(), Some(64), "{out:?}");
    assert!(!rebase_state(&fixture));
}

fn parents(fixture: &Fixture, spec: &str) -> Vec<String> {
    let rev = format!("{spec}^");
    [rev.clone() + "1", rev + "2"]
        .iter()
        .filter_map(|p| {
            let out = run_in(fixture, &fixture.local, &["rev-parse", p]);
            out.status
                .success()
                .then(|| String::from_utf8(out.stdout).unwrap().trim().to_owned())
        })
        .collect()
}

#[test]
fn pull_no_ff_writes_a_merge_commit_where_a_fast_forward_is_possible() {
    let fixture = fixture();
    push_upstream(&fixture, "u.txt", "u\n", "u1");
    let old = rev(&fixture, &fixture.local, "HEAD");

    let out = run_in(&fixture, &fixture.local, &["pull", "--no-ff"]);
    assert!(out.status.success(), "{out:?}");

    let head = rev(&fixture, &fixture.local, "HEAD");
    assert_ne!(head, old);
    assert_eq!(
        parents(&fixture, "HEAD"),
        [old, rev(&fixture, &fixture.upstream, "HEAD")]
    );
    assert!(fixture.local.join("u.txt").exists());
    assert_eq!(
        subjects(&fixture)[0],
        "Merge remote-tracking branch 'default/main'"
    );
    assert_verifies(&fixture, "HEAD");
}

#[test]
fn pull_no_ff_merges_diverged_branches() {
    let fixture = fixture();
    push_upstream(&fixture, "u.txt", "u\n", "u1");
    commit_local(&fixture, "l1.txt", "1\n", "l1");

    ok_in(&fixture, &fixture.local, &["pull", "--no-ff"]);

    assert_eq!(parents(&fixture, "HEAD").len(), 2);
    for file in ["u.txt", "l1.txt"] {
        assert!(fixture.local.join(file).exists(), "{file}");
    }
    assert_verifies(&fixture, "HEAD");
}

#[test]
fn pull_no_ff_changes_nothing_when_the_branch_holds_the_fetched_tip() {
    let fixture = fixture();
    commit_local(&fixture, "l1.txt", "1\n", "l1");
    let old = rev(&fixture, &fixture.local, "HEAD");

    let out = run_in(&fixture, &fixture.local, &["pull", "--no-ff"]);
    assert!(out.status.success(), "{out:?}");
    assert!(
        String::from_utf8(out.stderr)
            .unwrap()
            .contains("Already up to date.")
    );
    assert_eq!(rev(&fixture, &fixture.local, "HEAD"), old);
}

#[test]
fn pull_no_ff_conflict_pauses_the_merge_then_continue_finishes() {
    let fixture = fixture();
    push_upstream(&fixture, "shared.txt", "upstream\n", "u1");
    commit_local(&fixture, "shared.txt", "local\n", "l1");

    let out = run_in(&fixture, &fixture.local, &["pull", "--no-ff"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("Merge conflict in shared.txt"), "{stderr}");

    fs::write(fixture.local.join("shared.txt"), "resolved\n").unwrap();
    ok_in(&fixture, &fixture.local, &["add", "shared.txt"]);
    ok_in(&fixture, &fixture.local, &["merge", "--continue"]);
    assert_eq!(parents(&fixture, "HEAD").len(), 2);
    assert_verifies(&fixture, "HEAD");
}

#[test]
fn pull_no_ff_does_not_combine_with_all() {
    let fixture = fixture();
    let out = run_in(&fixture, &fixture.local, &["pull", "--no-ff", "--all"]);
    assert_eq!(out.status.code(), Some(64), "{out:?}");
}

#[test]
fn pull_no_ff_refuses_a_detached_head() {
    let fixture = fixture();
    let head = rev(&fixture, &fixture.local, "HEAD");
    ok_in(&fixture, &fixture.local, &["checkout", &head]);
    let out = run_in(&fixture, &fixture.local, &["pull", "--no-ff"]);
    assert_eq!(out.status.code(), Some(64), "{out:?}");
}
