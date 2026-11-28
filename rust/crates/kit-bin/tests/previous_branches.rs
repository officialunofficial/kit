//! `@{-N}` names the N-th previous HEAD of this worktree, for N up to 16.
//!
//! Invariants:
//! - Sequence: after switching through b1..bk, `@{-N}` names b(k-N).
//! - Bounded: the record never holds more than 16 entries, and a torn last
//!   line is ignored.
//! - Per worktree: a switch in one tree never changes another's `@{-N}`.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

use proptest::prelude::*;

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

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

/// A repo on `main` with one commit and branches `b0`..`b{n-1}`, each with
/// a commit of its own so every branch names a distinct commit.
fn repo(n: usize) -> tempfile::TempDir {
    let repo = tempfile::tempdir().unwrap();
    let r = repo.path();
    ok(r, &["init"]);
    ok(r, &["keygen"]);
    fs::write(r.join("f.txt"), b"main\n").unwrap();
    ok(r, &["add", "f.txt"]);
    ok(r, &["commit", "-m", "main"]);
    for i in 0..n {
        let name = format!("b{i}");
        ok(r, &["switch", "-c", &name, "main"]);
        fs::write(r.join("f.txt"), format!("{name}\n")).unwrap();
        ok(r, &["commit", "-am", &name]);
    }
    ok(r, &["switch", "main"]);
    // Start each test with no record of the setup switches.
    for f in ["HEAD_HISTORY", "PREVIOUS_HEAD"] {
        let _ = fs::remove_file(r.join(".kit").join(f));
    }
    repo
}

fn rev(r: &Path, spec: &str) -> String {
    stdout(&ok(r, &["rev-parse", spec]))
}

fn current(r: &Path) -> String {
    stdout(&ok(r, &["branch", "--show-current"]))
}

#[test]
fn at_minus_n_names_earlier_branches() {
    let repo = repo(4);
    let r = repo.path();
    for b in ["b0", "b1", "b2", "b3"] {
        ok(r, &["switch", b]);
    }
    assert_eq!(rev(r, "@{-1}"), rev(r, "b2"));
    assert_eq!(rev(r, "@{-2}"), rev(r, "b1"));
    assert_eq!(rev(r, "@{-3}"), rev(r, "b0"));
    assert_eq!(rev(r, "@{-4}"), rev(r, "main"));
    // Suffix steps follow the base.
    assert_eq!(rev(r, "@{-2}~1"), rev(r, "main"));
    ok(r, &["switch", "@{-2}"]);
    assert_eq!(current(r), "b1");
    // The record is now main, b0, b1, b2, b3, so @{-2} is b2.
    ok(r, &["checkout", "@{-2}"]);
    assert_eq!(current(r), "b2");
}

#[test]
fn at_minus_n_beyond_the_record_is_an_error() {
    let repo = repo(2);
    let r = repo.path();
    ok(r, &["switch", "b0"]);
    ok(r, &["switch", "b1"]);
    let out = run_in(r, &["rev-parse", "--verify", "-q", "@{-4}"]);
    assert!(!out.status.success(), "{out:?}");
    let out = run_in(r, &["switch", "@{-4}"]);
    assert!(!out.status.success(), "{out:?}");
    assert_eq!(current(r), "b1");
}

#[test]
fn the_record_keeps_sixteen_entries() {
    let repo = repo(18);
    let r = repo.path();
    for i in 0..18 {
        ok(r, &["switch", &format!("b{i}")]);
    }
    // Now on b17; @{-16} is b1, and @{-17} has been dropped.
    assert_eq!(rev(r, "@{-16}"), rev(r, "b1"));
    let out = run_in(r, &["rev-parse", "@{-17}"]);
    assert!(!out.status.success(), "{out:?}");
    let text = fs::read_to_string(r.join(".kit/HEAD_HISTORY")).unwrap();
    assert_eq!(text.lines().count(), 16, "{text}");
}

#[test]
fn a_torn_last_line_is_ignored() {
    let repo = repo(2);
    let r = repo.path();
    ok(r, &["switch", "b0"]);
    ok(r, &["switch", "b1"]);
    let path = r.join(".kit/HEAD_HISTORY");
    let mut text = fs::read_to_string(&path).unwrap();
    text.push_str("ref: refs/heads/tor");
    fs::write(&path, text).unwrap();
    assert_eq!(rev(r, "@{-1}"), rev(r, "b0"));
    assert_eq!(rev(r, "@{-2}"), rev(r, "main"));
}

#[test]
fn a_damaged_line_is_an_error_not_a_guess() {
    let repo = repo(2);
    let r = repo.path();
    ok(r, &["switch", "b0"]);
    ok(r, &["switch", "b1"]);
    fs::write(r.join(".kit/HEAD_HISTORY"), "junk\nref: refs/heads/b0\n").unwrap();
    let out = run_in(r, &["rev-parse", "@{-2}"]);
    assert!(!out.status.success(), "{out:?}");
}

#[test]
fn a_repository_with_only_the_old_file_still_has_at_minus_one() {
    let repo = repo(2);
    let r = repo.path();
    ok(r, &["switch", "b0"]);
    ok(r, &["switch", "b1"]);
    fs::remove_file(r.join(".kit/HEAD_HISTORY")).unwrap();
    assert_eq!(rev(r, "@{-1}"), rev(r, "b0"));
    assert!(!run_in(r, &["rev-parse", "@{-2}"]).status.success());
    // The next switch starts the record from the old file.
    ok(r, &["switch", "-"]);
    assert_eq!(current(r), "b0");
    assert_eq!(rev(r, "@{-1}"), rev(r, "b1"));
    assert_eq!(rev(r, "@{-2}"), rev(r, "b0"));
}

#[test]
fn a_record_that_an_older_kit_left_behind_is_not_trusted() {
    let repo = repo(3);
    let r = repo.path();
    ok(r, &["switch", "b0"]);
    ok(r, &["switch", "b1"]);
    // An older kit switched b1 -> b2 and wrote only PREVIOUS_HEAD.
    ok(r, &["switch", "b2"]);
    let history = r.join(".kit/HEAD_HISTORY");
    let text = fs::read_to_string(&history).unwrap();
    let stale: Vec<&str> = text.lines().collect();
    fs::write(
        &history,
        format!("{}\n", stale[..stale.len() - 1].join("\n")),
    )
    .unwrap();
    fs::write(r.join(".kit/PREVIOUS_HEAD"), "ref: refs/heads/b1\n").unwrap();
    assert_eq!(rev(r, "@{-1}"), rev(r, "b1"));
    assert!(!run_in(r, &["rev-parse", "@{-2}"]).status.success());
}

#[test]
fn a_detached_head_is_recorded_by_commit() {
    let repo = repo(1);
    let r = repo.path();
    let main = rev(r, "main");
    ok(r, &["checkout", &main]);
    ok(r, &["switch", "b0"]);
    assert_eq!(rev(r, "@{-1}"), main);
    ok(r, &["switch", "@{-1}"]);
    assert_eq!(current(r), "");
    assert_eq!(rev(r, "HEAD"), main);
}

#[test]
fn each_worktree_has_its_own_record() {
    let repo = repo(3);
    let r = repo.path();
    ok(r, &["switch", "b0"]);
    let other = tempfile::tempdir().unwrap();
    let linked = other.path().join("linked");
    ok(r, &["worktree", "add", linked.to_str().unwrap(), "b1"]);
    ok(&linked, &["switch", "b2"]);
    ok(&linked, &["switch", "-c", "x", "b2"]);
    assert_eq!(rev(&linked, "@{-1}"), rev(r, "b2"));
    assert_eq!(rev(r, "@{-1}"), rev(r, "main"));
    assert!(!run_in(r, &["rev-parse", "@{-2}"]).status.success());
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 8, ..ProptestConfig::default() })]

    #[test]
    fn at_minus_n_follows_the_switch_sequence(
        steps in prop::collection::vec(0usize..4, 1..20),
    ) {
        let repo = repo(4);
        let r = repo.path();
        let mut seen = vec!["main".to_owned()];
        for s in steps {
            let b = format!("b{s}");
            if seen.last() == Some(&b) {
                continue;
            }
            ok(r, &["switch", &b]);
            seen.push(b);
        }
        let k = seen.len() - 1;
        for n in 1..=k.min(16) {
            let want = rev(r, &seen[k - n]);
            prop_assert_eq!(rev(r, &format!("@{{-{n}}}")), want, "@{{-{}}} after {:?}", n, seen);
        }
        if k < 16 {
            let past = format!("@{{-{}}}", k + 1);
            prop_assert!(!run_in(r, &["rev-parse", &past]).status.success());
        }
    }
}
