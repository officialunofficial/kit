//! `kit pull` when the local branch holds the fetched tip already, or has
//! diverged from it, over a `kit+file://` remote. A branch that is equal to the
//! fetched tip or ahead of it is up to date, as in git; a diverged one is
//! refused.
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

fn head(fixture: &Fixture) -> String {
    ok_in(fixture, &fixture.local, &["rev-parse", "HEAD"])
        .trim()
        .to_owned()
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

fn assert_already_up_to_date(out: &Output) {
    assert!(out.status.success(), "{out:?}");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("Already up to date."),
        "{out:?}"
    );
}

#[test]
fn pull_when_the_branch_is_ahead_is_up_to_date_and_changes_nothing() {
    let fixture = fixture();
    commit_in(&fixture, &fixture.local, "l1.txt", "1\n", "l1");
    fs::write(fixture.local.join("untracked.txt"), "keep\n").unwrap();
    let before = head(&fixture);

    let out = run_in(&fixture, &fixture.local, &["pull"]);

    assert_already_up_to_date(&out);
    assert_eq!(head(&fixture), before);
    assert_eq!(fs::read(fixture.local.join("l1.txt")).unwrap(), b"1\n");
    assert_eq!(
        fs::read(fixture.local.join("untracked.txt")).unwrap(),
        b"keep\n"
    );
    // A second pull says the same.
    assert_already_up_to_date(&run_in(&fixture, &fixture.local, &["pull"]));
    assert_eq!(head(&fixture), before);
}

#[test]
fn pull_json_when_the_branch_is_ahead_reports_up_to_date() {
    let fixture = fixture();
    commit_in(&fixture, &fixture.local, "l1.txt", "1\n", "l1");
    let before = head(&fixture);

    let out = run_in(&fixture, &fixture.local, &["pull", "--format=json"]);

    assert!(out.status.success(), "{out:?}");
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("\"up_to_date\":true"), "{stdout}");
    assert!(stdout.contains(&before), "{stdout}");
}

#[test]
fn pull_when_the_branch_equals_the_remote_is_up_to_date() {
    let fixture = fixture();
    assert_already_up_to_date(&run_in(&fixture, &fixture.local, &["pull"]));
}

#[test]
fn pull_when_the_branch_is_behind_still_fast_forwards() {
    let fixture = fixture();
    commit_in(&fixture, &fixture.upstream, "u.txt", "u\n", "u1");
    ok_in(
        &fixture,
        &fixture.upstream,
        &["push", "origin", "main:main"],
    );

    ok_in(&fixture, &fixture.local, &["pull"]);

    assert_eq!(fs::read(fixture.local.join("u.txt")).unwrap(), b"u\n");
}

#[test]
fn pull_when_the_branch_has_diverged_is_refused_and_changes_nothing() {
    let fixture = fixture();
    commit_in(&fixture, &fixture.upstream, "u.txt", "u\n", "u1");
    ok_in(
        &fixture,
        &fixture.upstream,
        &["push", "origin", "main:main"],
    );
    commit_in(&fixture, &fixture.local, "l1.txt", "1\n", "l1");
    let before = head(&fixture);

    let out = run_in(&fixture, &fixture.local, &["pull"]);

    assert!(!out.status.success(), "{out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("would not fast-forward"), "{stderr}");
    assert!(!stderr.contains("Already up to date."), "{stderr}");
    assert_eq!(head(&fixture), before);
    assert!(!fixture.local.join("u.txt").exists());
}
