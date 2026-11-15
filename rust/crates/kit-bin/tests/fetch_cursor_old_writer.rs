//! A writer that predates the stripe counts changes a ref on a served
//! `kit+file://` root: it takes the repo lock, writes the ref file by a
//! temporary file and a rename, and bumps no count (SPEC-REFS §5.1.2). A
//! fetch that recorded the root's cursor must still see the change.
//!
//! The marker `bmt-v2` already makes kit 0.7.x refuse such a root, so this
//! is a second line of defence. The old writer is simulated by what it does
//! on disk.
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, SystemTime};

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

fn commit(repo: &Path, file: &str, body: &[u8], message: &str) {
    fs::write(repo.join(file), body).unwrap();
    ok(repo, &["add", file]);
    ok(repo, &["commit", "-m", message]);
}

/// The remote's file for `name` (`refs/heads/main`, a packmap, ...).
fn remote_ref(remote: &Path, name: &str) -> PathBuf {
    remote.join(name)
}

/// A write as kit 0.7.x makes it: the repo lock exclusive, a temporary
/// file and a rename, no stripe count. `from` is the ref whose value and
/// packmap the new ref takes, so that every object it needs is there.
fn old_writer_copies(remote: &Path, from: &str, to: &str) {
    let lock = fs::File::options()
        .create(true)
        .append(true)
        .open(remote.join(".kit/refs/.lock"))
        .unwrap();
    lock.lock().unwrap();
    for prefix in ["refs/heads", "refs/kit/packmap"] {
        let source = remote_ref(remote, &format!("{prefix}/{from}"));
        let dest = remote_ref(remote, &format!("{prefix}/{to}"));
        let bytes = fs::read(&source).unwrap();
        let tmp = dest.with_extension("tmp-old-writer");
        fs::write(&tmp, bytes).unwrap();
        fs::rename(&tmp, &dest).unwrap();
    }
    lock.unlock().unwrap();
}

/// Set the modification time of every directory under `<root>/refs` a
/// minute into the past, so the root offers a cursor again. The change time
/// of a directory cannot be set, and the cursor covers it.
fn settle_ref_dirs(root: &Path) {
    let when = SystemTime::now() - Duration::from_secs(60);
    let mut dirs = vec![root.join("refs")];
    while let Some(dir) = dirs.pop() {
        for entry in fs::read_dir(&dir).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                dirs.push(entry.path());
            }
        }
        fs::File::open(&dir).unwrap().set_modified(when).unwrap();
    }
}

fn tracking(repo: &Path, name: &str) -> Option<String> {
    fs::read_to_string(repo.join(".kit/refs/remotes/origin").join(name))
        .ok()
        .map(|s| s.trim().to_owned())
}

/// The fetch cursor records under `.kit`.
fn cursor_records(dir: &Path) -> usize {
    let mut found = 0;
    let Ok(entries) = fs::read_dir(dir) else {
        return 0;
    };
    for entry in entries {
        let entry = entry.unwrap();
        let path = entry.path();
        if entry.file_type().unwrap().is_dir() {
            if path.file_name().is_some_and(|n| n == ".cursors") {
                found += fs::read_dir(&path).unwrap().count();
            } else {
                found += cursor_records(&path);
            }
        }
    }
    found
}

#[test]
fn a_fetch_sees_a_ref_an_uncounted_writer_changed() {
    let repo = tempfile::tempdir().unwrap();
    let repo = repo.path();
    ok(repo, &["init"]);
    ok(repo, &["keygen"]);
    commit(repo, "a.txt", b"one", "c1");
    let remote = tempfile::tempdir().unwrap();
    let url = format!("kit+file://{}", remote.path().display());
    ok(repo, &["remote", "add", "origin", &url]);
    ok(repo, &["push", "origin", "main:main"]);
    let first = tracking(repo, "main").unwrap();

    // A second commit goes to its own branch, so the remote holds its
    // objects and a packmap that reaches them.
    commit(repo, "a.txt", b"two", "c2");
    ok(repo, &["push", "origin", "main:ahead"]);
    let ahead = tracking(repo, "ahead").unwrap();
    assert_ne!(first, ahead);

    // Fetch once the root has settled so the fetch records its cursor, and
    // again to rely on that record.
    settle_ref_dirs(remote.path());
    ok(repo, &["fetch", "origin"]);
    assert!(
        cursor_records(&repo.join(".kit")) > 0,
        "the fetch recorded the cursor of a settled root"
    );
    ok(repo, &["fetch", "origin"]);

    // The old writer creates a branch and then moves an existing one.
    old_writer_copies(remote.path(), "ahead", "late");
    settle_ref_dirs(remote.path());
    ok(repo, &["fetch", "origin"]);
    assert_eq!(
        tracking(repo, "late"),
        Some(ahead.clone()),
        "a created ref was skipped"
    );
    // Create a branch at the first commit by the same means, let a fetch
    // record it, then move it forward.
    old_writer_copies(remote.path(), "main", "late-main");
    settle_ref_dirs(remote.path());
    ok(repo, &["fetch", "origin"]);
    let before = tracking(repo, "late-main").unwrap();
    old_writer_copies(remote.path(), "ahead", "late-main");
    settle_ref_dirs(remote.path());
    ok(repo, &["fetch", "origin"]);
    let after = tracking(repo, "late-main").unwrap();
    assert_ne!(before, after, "an overwritten ref was skipped");
    assert_eq!(after, ahead);
}
