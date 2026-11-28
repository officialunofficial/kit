//! `kit stash push -a` saves ignored files too, and `kit stash branch`
//! starts a branch at the commit a stash was made on.
//!
//! Invariants:
//! - Round trip: `push -a` then `pop` gives back every file byte for byte,
//!   ignored files included, and `push -a` leaves no ignored file behind.
//! - Branch base: the new branch's tip is the stash's base commit.
//! - Drop on success only: `stash branch` drops the entry only after the
//!   apply succeeds; a refusal keeps it.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::collections::BTreeMap;
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

fn write(root: &Path, rel: &str, data: &[u8]) {
    let p = root.join(rel);
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, data).unwrap();
}

fn read(root: &Path, rel: &str) -> Vec<u8> {
    fs::read(root.join(rel)).unwrap()
}

/// A repo whose HEAD tracks `a.txt` and a `.kitignore` of `*.log` and
/// `build/`.
fn repo() -> tempfile::TempDir {
    let repo = tempfile::tempdir().unwrap();
    let r = repo.path();
    ok(r, &["init"]);
    ok(r, &["keygen"]);
    write(r, "a.txt", b"one\n");
    write(r, ".kitignore", b"*.log\nbuild/\n");
    ok(r, &["add", "a.txt", ".kitignore"]);
    ok(r, &["commit", "-m", "c1"]);
    repo
}

fn stash_messages(r: &Path) -> Vec<String> {
    stdout(&ok(r, &["stash", "list"]))
        .lines()
        .map(str::to_owned)
        .collect()
}

fn rev(r: &Path, spec: &str) -> String {
    stdout(&ok(r, &["rev-parse", spec]))
}

#[test]
fn an_ignored_build_file_survives_push_all_and_pop() {
    let repo = repo();
    let r = repo.path();
    write(r, "a.txt", b"two\n");
    write(r, "build/out.bin", b"\x00artifact\xff");
    write(r, "debug.log", b"log line\n");
    write(r, "new.txt", b"untracked\n");
    ok(r, &["stash", "push", "-a"]);
    assert_eq!(read(r, "a.txt"), b"one\n");
    assert!(!r.join("build").exists(), "push -a leaves build/ behind");
    assert!(
        !r.join("debug.log").exists(),
        "push -a leaves debug.log behind"
    );
    assert!(!r.join("new.txt").exists());
    ok(r, &["stash", "pop"]);
    assert_eq!(read(r, "a.txt"), b"two\n");
    assert_eq!(read(r, "build/out.bin"), b"\x00artifact\xff");
    assert_eq!(read(r, "debug.log"), b"log line\n");
    assert_eq!(read(r, "new.txt"), b"untracked\n");
    assert!(stash_messages(r).is_empty());
}

#[test]
fn the_long_form_and_the_implicit_save_take_all_too() {
    let repo = repo();
    let r = repo.path();
    write(r, "x.log", b"one\n");
    ok(r, &["stash", "--all"]);
    assert!(!r.join("x.log").exists());
    ok(r, &["stash", "pop"]);
    assert_eq!(read(r, "x.log"), b"one\n");
}

#[test]
fn plain_push_still_leaves_ignored_files_alone() {
    let repo = repo();
    let r = repo.path();
    write(r, "a.txt", b"two\n");
    write(r, "x.log", b"kept\n");
    ok(r, &["stash", "push"]);
    assert_eq!(read(r, "x.log"), b"kept\n");
}

#[test]
fn push_all_never_saves_the_repository_directory() {
    let repo = repo();
    let r = repo.path();
    write(r, "x.log", b"one\n");
    ok(r, &["stash", "push", "-a"]);
    let show = stdout(&ok(r, &["stash", "show"]));
    assert!(show.contains("x.log"), "{show}");
    assert!(!show.contains(".kit/"), "{show}");
    assert!(r.join(".kit").is_dir());
    ok(r, &["status"]);
}

#[test]
fn push_all_with_paths_is_refused() {
    let repo = repo();
    let r = repo.path();
    write(r, "x.log", b"one\n");
    let out = run_in(r, &["stash", "push", "-a", "--", "x.log"]);
    assert_eq!(out.status.code(), Some(64), "{out:?}");
    assert_eq!(read(r, "x.log"), b"one\n");
    assert!(stash_messages(r).is_empty());
}

#[test]
fn stash_branch_starts_at_the_stash_base_and_drops_the_entry() {
    let repo = repo();
    let r = repo.path();
    let c1 = rev(r, "HEAD");
    write(r, "a.txt", b"two\n");
    ok(r, &["add", "a.txt"]);
    write(r, "u.txt", b"untracked\n");
    ok(r, &["stash", "-m", "old work"]);
    // Move on so the old stash no longer applies on the branch tip.
    write(r, "a.txt", b"three\n");
    ok(r, &["commit", "-am", "c2"]);
    write(r, "b.txt", b"newer\n");
    ok(r, &["stash", "-m", "new work"]);
    assert_eq!(stash_messages(r).len(), 2);

    ok(r, &["stash", "branch", "fix", "stash@{1}"]);
    assert_eq!(stdout(&ok(r, &["branch", "--show-current"])), "fix");
    assert_eq!(rev(r, "fix"), c1);
    assert_eq!(read(r, "a.txt"), b"two\n");
    assert_eq!(read(r, "u.txt"), b"untracked\n");
    assert!(!r.join("b.txt").exists());
    // `stash branch` restores the staged state too.
    let staged = stdout(&ok(r, &["diff", "--cached", "--name-only"]));
    assert_eq!(staged, "a.txt");
    let left = stash_messages(r);
    assert_eq!(left.len(), 1, "{left:?}");
    assert!(left[0].contains("new work"), "{left:?}");
}

#[test]
fn stash_branch_defaults_to_the_newest_entry() {
    let repo = repo();
    let r = repo.path();
    let c1 = rev(r, "HEAD");
    write(r, "a.txt", b"two\n");
    ok(r, &["stash"]);
    ok(r, &["stash", "branch", "topic"]);
    assert_eq!(stdout(&ok(r, &["branch", "--show-current"])), "topic");
    assert_eq!(rev(r, "topic"), c1);
    assert_eq!(read(r, "a.txt"), b"two\n");
    assert!(stash_messages(r).is_empty());
}

#[test]
fn stash_branch_refuses_an_existing_branch_and_keeps_the_entry() {
    let repo = repo();
    let r = repo.path();
    ok(r, &["branch", "taken"]);
    write(r, "a.txt", b"two\n");
    ok(r, &["stash"]);
    let before = rev(r, "taken");
    let out = run_in(r, &["stash", "branch", "taken"]);
    assert!(!out.status.success(), "{out:?}");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("already exists"), "{err}");
    assert_eq!(rev(r, "taken"), before);
    assert_eq!(stash_messages(r).len(), 1);
    assert_eq!(read(r, "a.txt"), b"one\n");
}

#[test]
fn stash_branch_refuses_a_bad_name_or_entry_and_keeps_the_stash() {
    let repo = repo();
    let r = repo.path();
    write(r, "a.txt", b"two\n");
    ok(r, &["stash"]);
    let bad = run_in(r, &["stash", "branch", "a b"]);
    assert_eq!(bad.status.code(), Some(64), "{bad:?}");
    let missing = run_in(r, &["stash", "branch", "x", "stash@{5}"]);
    assert!(!missing.status.success(), "{missing:?}");
    assert_eq!(
        run_in(r, &["rev-parse", "--verify", "-q", "x"])
            .status
            .code(),
        Some(1)
    );
    assert_eq!(stash_messages(r).len(), 1);
}

#[test]
fn a_failed_apply_keeps_the_entry() {
    let repo = repo();
    let r = repo.path();
    write(r, "new.txt", b"stashed\n");
    ok(r, &["stash"]);
    // An untracked file in the way makes the apply refuse.
    write(r, "new.txt", b"in the way\n");
    let out = run_in(r, &["stash", "branch", "fix"]);
    assert!(!out.status.success(), "{out:?}");
    assert_eq!(read(r, "new.txt"), b"in the way\n");
    assert_eq!(stash_messages(r).len(), 1);
}

#[test]
fn stash_branch_on_an_unborn_stash_is_refused() {
    let repo = tempfile::tempdir().unwrap();
    let r = repo.path();
    ok(r, &["init"]);
    ok(r, &["keygen"]);
    write(r, "a.txt", b"one\n");
    ok(r, &["stash"]);
    let out = run_in(r, &["stash", "branch", "fix"]);
    assert!(!out.status.success(), "{out:?}");
    assert_eq!(stash_messages(r).len(), 1);
}

/// A file name in one of three places: tracked, plain untracked, or
/// matched by the ignore rules.
fn file_name() -> impl Strategy<Value = String> {
    (0u8..3, "[a-z]{1,6}").prop_map(|(kind, stem)| match kind {
        0 => format!("src/{stem}.txt"),
        1 => format!("{stem}.log"),
        _ => format!("build/{stem}.o"),
    })
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 12, ..ProptestConfig::default() })]

    #[test]
    fn push_all_then_pop_restores_every_file(
        files in prop::collection::btree_map(
            file_name(),
            prop::collection::vec(any::<u8>(), 0..64),
            1..8,
        ),
    ) {
        let repo = repo();
        let r = repo.path();
        for (name, data) in &files {
            write(r, name, data);
        }
        let before = snapshot(r);
        ok(r, &["stash", "push", "-a"]);
        let mid = snapshot(r);
        prop_assert_eq!(mid.keys().cloned().collect::<Vec<_>>(), vec![
            ".kitignore".to_owned(),
            "a.txt".to_owned(),
        ]);
        ok(r, &["stash", "pop"]);
        prop_assert_eq!(snapshot(r), before);
    }
}

/// Every file under `root` outside `.kit/`, by relative path.
fn snapshot(root: &Path) -> BTreeMap<String, Vec<u8>> {
    fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
        for entry in fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let rel = path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            if rel == ".kit" {
                continue;
            }
            if entry.file_type().unwrap().is_dir() {
                walk(root, &path, out);
            } else {
                out.insert(rel, fs::read(&path).unwrap());
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}
