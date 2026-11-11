//! `kit stash` never removes a path that the ignore rules match, and a pop
//! never sweeps one. A path is removed only when the stash holds it.
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

fn write(root: &Path, rel: &str, data: &[u8]) {
    let p = root.join(rel);
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, data).unwrap();
}

fn read(root: &Path, rel: &str) -> Vec<u8> {
    fs::read(root.join(rel)).unwrap()
}

/// A repo whose HEAD tracks `a.txt` and a committed `.kitignore` of `*.log`.
fn repo() -> tempfile::TempDir {
    let repo = tempfile::tempdir().unwrap();
    let r = repo.path();
    ok(r, &["init"]);
    ok(r, &["keygen"]);
    write(r, "a.txt", b"one\n");
    write(r, ".kitignore", b"*.log\nblocked/\ncache\n");
    ok(r, &["add", "a.txt", ".kitignore"]);
    ok(r, &["commit", "-m", "c1"]);
    repo
}

fn stash_count(r: &Path) -> usize {
    String::from_utf8_lossy(&ok(r, &["stash", "list"]).stdout)
        .lines()
        .count()
}

#[test]
fn ignored_files_survive_save_and_pop_and_other_files_round_trip() {
    let repo = repo();
    let r = repo.path();
    write(r, "a.txt", b"two\n");
    write(r, "new/u.txt", b"untracked\n");
    write(r, "i.log", b"ignored\n");
    write(r, "build/x.log", b"ignored deep\n");
    write(r, "build/y.txt", b"plain\n");
    ok(r, &["stash"]);
    assert_eq!(read(r, "a.txt"), b"one\n");
    assert!(!r.join("new").exists());
    assert!(!r.join("build/y.txt").exists());
    assert_eq!(read(r, "i.log"), b"ignored\n");
    assert_eq!(read(r, "build/x.log"), b"ignored deep\n");
    ok(r, &["stash", "pop"]);
    assert_eq!(read(r, "a.txt"), b"two\n");
    assert_eq!(read(r, "new/u.txt"), b"untracked\n");
    assert_eq!(read(r, "build/y.txt"), b"plain\n");
    assert_eq!(read(r, "i.log"), b"ignored\n");
    assert_eq!(read(r, "build/x.log"), b"ignored deep\n");
}

#[test]
fn an_ignored_file_in_a_directory_the_head_lacks_keeps_its_directory() {
    let repo = repo();
    let r = repo.path();
    write(r, "a.txt", b"two\n");
    write(r, "cache/only.log", b"keep\n");
    ok(r, &["stash"]);
    assert_eq!(read(r, "cache/only.log"), b"keep\n");
    ok(r, &["stash", "pop"]);
    assert_eq!(read(r, "a.txt"), b"two\n");
    assert_eq!(read(r, "cache/only.log"), b"keep\n");
}

#[test]
fn a_tracked_file_that_matches_an_ignore_rule_is_stashed_and_restored() {
    let repo = repo();
    let r = repo.path();
    write(r, "t.log", b"v1\n");
    ok(r, &["add", "-f", "t.log"]);
    ok(r, &["commit", "-m", "track t.log"]);
    write(r, "t.log", b"v2\n");
    write(r, "staged.log", b"new\n");
    ok(r, &["add", "-f", "staged.log"]);
    ok(r, &["stash"]);
    assert_eq!(read(r, "t.log"), b"v1\n");
    assert!(
        !r.join("staged.log").exists(),
        "a staged file leaves the worktree even when it matches a rule"
    );
    ok(r, &["stash", "pop"]);
    assert_eq!(read(r, "t.log"), b"v2\n");
    assert_eq!(read(r, "staged.log"), b"new\n");
}

#[test]
fn an_ignored_file_where_head_needs_a_path_refuses_the_save() {
    let repo = repo();
    let r = repo.path();
    write(r, "x.log", b"tracked\n");
    ok(r, &["add", "-f", "x.log"]);
    ok(r, &["commit", "-m", "track x.log"]);
    // Drop x.log from the index only. The ignored copy stays on disk, and
    // HEAD still needs the path.
    ok(r, &["rm", "--cached", "x.log"]);
    write(r, "x.log", b"my ignored copy\n");
    write(r, "a.txt", b"two\n");
    let out = run_in(r, &["stash"]);
    assert!(!out.status.success(), "{out:?}");
    assert_eq!(read(r, "x.log"), b"my ignored copy\n");
    assert_eq!(read(r, "a.txt"), b"two\n");
    assert_eq!(stash_count(r), 0);
}

#[test]
fn a_pop_that_needs_a_path_held_by_an_ignored_file_refuses_and_keeps_the_stash() {
    let repo = repo();
    let r = repo.path();
    // `blocked/` ignores a directory only, so a file of that name is stashed.
    write(r, "blocked", b"untracked file\n");
    ok(r, &["stash"]);
    write(r, "blocked/z.txt", b"ignored dir content\n");
    let out = run_in(r, &["stash", "pop"]);
    assert!(!out.status.success(), "{out:?}");
    assert_eq!(read(r, "blocked/z.txt"), b"ignored dir content\n");
    assert_eq!(stash_count(r), 1);
}

#[test]
fn an_untracked_kitignore_decides_at_save_time() {
    let repo = tempfile::tempdir().unwrap();
    let r = repo.path();
    ok(r, &["init"]);
    ok(r, &["keygen"]);
    write(r, "a.txt", b"one\n");
    ok(r, &["add", "a.txt"]);
    ok(r, &["commit", "-m", "c1"]);
    write(r, ".kitignore", b"*.log\n");
    write(r, "i.log", b"ignored\n");
    write(r, "a.txt", b"two\n");
    ok(r, &["stash"]);
    assert_eq!(read(r, "i.log"), b"ignored\n");
    assert_eq!(read(r, "a.txt"), b"one\n");
    // The stash holds the untracked .kitignore, so it left the worktree.
    assert!(!r.join(".kitignore").exists());
    let shown = String::from_utf8_lossy(&ok(r, &["stash", "show"]).stdout).into_owned();
    assert!(shown.contains(".kitignore"), "{shown}");
    assert!(!shown.contains("i.log"), "{shown}");
}

#[cfg(unix)]
#[test]
fn an_untracked_symlink_is_stashed_as_a_link_and_a_linked_ignored_dir_is_not_followed() {
    let repo = repo();
    let r = repo.path();
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("precious"), b"outside\n").unwrap();
    std::os::unix::fs::symlink("a.txt", r.join("link")).unwrap();
    std::os::unix::fs::symlink(outside.path(), r.join("cache")).unwrap();
    ok(r, &["stash"]);
    assert!(fs::symlink_metadata(r.join("link")).is_err());
    assert!(fs::symlink_metadata(r.join("cache")).unwrap().is_symlink());
    assert_eq!(
        fs::read(outside.path().join("precious")).unwrap(),
        b"outside\n"
    );
    ok(r, &["stash", "pop"]);
    assert_eq!(fs::read_link(r.join("link")).unwrap(), Path::new("a.txt"));
    assert_eq!(
        fs::read(outside.path().join("precious")).unwrap(),
        b"outside\n"
    );
}
