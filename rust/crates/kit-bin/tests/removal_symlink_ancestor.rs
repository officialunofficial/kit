//! `kit reset --hard` must not follow a symlink that the restore just put
//! in place of a tracked directory when it deletes the paths the target
//! drops. The current commit tracks `d/<name>`; the target replaces `d`
//! with a symlink. Deleting `d/<name>` afterwards must not reach through
//! the new link (into `.kit/`, or into a sibling the target still tracks).
#![cfg(unix)]
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;
use std::process::Output;

fn run_in(cwd: &Path, xdg: &Path, args: &[&str]) -> Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_kit"))
        .args(args)
        .current_dir(cwd)
        .env("XDG_CONFIG_HOME", xdg)
        .output()
        .expect("spawn kit")
}

fn ok(cwd: &Path, xdg: &Path, args: &[&str]) -> String {
    let out = run_in(cwd, xdg, args);
    assert!(out.status.success(), "kit {args:?} failed: {out:?}");
    String::from_utf8(out.stdout).unwrap().trim().to_owned()
}

fn commit_all(root: &Path, xdg: &Path, msg: &str) -> String {
    ok(root, xdg, &["add", "."]);
    ok(root, xdg, &["commit", "-m", msg]);
    ok(root, xdg, &["rev-parse", "HEAD"])
}

#[test]
fn reset_hard_does_not_delete_repository_files_through_a_new_symlink() {
    let td = tempfile::tempdir().unwrap();
    let xdg = tempfile::tempdir().unwrap();
    let (root, x) = (td.path(), xdg.path());
    ok(root, x, &["init"]);
    ok(root, x, &["keygen"]);
    let sentinels = [
        ".kit/HEAD",
        ".kit/format",
        ".kit/index",
        ".kit/keys/default.key",
    ];

    // Target commit: `d` is a symlink to `.kit`.
    fs::write(root.join("base.txt"), b"base\n").unwrap();
    symlink(".kit", root.join("d")).unwrap();
    let target = commit_all(root, x, "target");

    // Current commit: `d/` is a directory holding files named like the
    // repository's own files.
    fs::remove_file(root.join("d")).unwrap();
    fs::create_dir_all(root.join("d/keys")).unwrap();
    for name in ["HEAD", "format", "index", "keys/default.key"] {
        fs::write(root.join("d").join(name), b"decoy\n").unwrap();
    }
    commit_all(root, x, "current");
    for s in sentinels {
        assert!(root.join(s).exists(), "{s} missing before reset");
    }

    let out = run_in(root, x, &["reset", "--hard", &target]);

    let gone: Vec<&str> = sentinels
        .into_iter()
        .filter(|s| !root.join(s).exists())
        .collect();
    assert!(
        gone.is_empty(),
        "reset --hard deleted {gone:?} through the symlink d -> .kit: {out:?}"
    );
    assert!(out.status.success(), "reset --hard failed: {out:?}");
    assert!(
        fs::symlink_metadata(root.join("d"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[test]
fn reset_hard_does_not_delete_a_tracked_sibling_through_a_new_symlink() {
    let td = tempfile::tempdir().unwrap();
    let xdg = tempfile::tempdir().unwrap();
    let (root, x) = (td.path(), xdg.path());
    ok(root, x, &["init"]);
    ok(root, x, &["keygen"]);

    // Target commit: `sub/x` is tracked and `d` is a symlink to `sub`.
    fs::create_dir(root.join("sub")).unwrap();
    fs::write(root.join("sub/x"), b"keep\n").unwrap();
    symlink("sub", root.join("d")).unwrap();
    let target = commit_all(root, x, "target");

    // Current commit: `d/x` is a tracked file of its own; `sub/x` unchanged.
    fs::remove_file(root.join("d")).unwrap();
    fs::create_dir(root.join("d")).unwrap();
    fs::write(root.join("d/x"), b"dropped\n").unwrap();
    commit_all(root, x, "current");

    let out = run_in(root, x, &["reset", "--hard", &target]);
    assert!(out.status.success(), "reset --hard failed: {out:?}");
    assert_eq!(
        fs::read(root.join("sub/x")).ok().as_deref(),
        Some(&b"keep\n"[..]),
        "reset --hard deleted sub/x, which the target tracks, through d -> sub"
    );
    // The worktree matches the target: nothing left to commit.
    let status = ok(root, x, &["status", "--porcelain"]);
    assert!(status.is_empty(), "worktree differs from target: {status}");
}

/// Set up a repository whose current commit tracks `d/<name>` for the given
/// names, then replace `d` on disk with a symlink to `.kit`.
fn repo_with_tracked_dir_replaced_by_link(
    names: &[&str],
) -> (tempfile::TempDir, tempfile::TempDir) {
    let td = tempfile::tempdir().unwrap();
    let xdg = tempfile::tempdir().unwrap();
    let (root, x) = (td.path(), xdg.path());
    ok(root, x, &["init"]);
    ok(root, x, &["keygen"]);
    for name in names {
        let path = root.join("d").join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, b"decoy\n").unwrap();
    }
    commit_all(root, x, "current");
    (td, xdg)
}

#[test]
fn rm_does_not_delete_repository_files_through_a_symlinked_directory() {
    let (td, xdg) = repo_with_tracked_dir_replaced_by_link(&["HEAD"]);
    let (root, x) = (td.path(), xdg.path());
    fs::remove_dir_all(root.join("d")).unwrap();
    symlink(".kit", root.join("d")).unwrap();

    run_in(root, x, &["rm", "--force", "d/HEAD"]);

    assert!(
        root.join(".kit/HEAD").exists(),
        "rm deleted .kit/HEAD through d -> .kit"
    );
}

#[test]
fn checkout_does_not_prune_directories_through_a_symlinked_parent() {
    let (td, xdg) = repo_with_tracked_dir_replaced_by_link(&["refs/spare/x"]);
    let (root, x) = (td.path(), xdg.path());
    let current = ok(root, x, &["rev-parse", "HEAD"]);

    // Target commit: `d` is a symlink to `.kit`.
    fs::remove_dir_all(root.join("d")).unwrap();
    symlink(".kit", root.join("d")).unwrap();
    let target = commit_all(root, x, "target");
    ok(root, x, &["checkout", &current]);
    fs::create_dir_all(root.join(".kit/refs/spare")).unwrap();

    let out = run_in(root, x, &["checkout", &target]);

    assert!(out.status.success(), "checkout failed: {out:?}");
    assert!(
        root.join(".kit/refs/spare").is_dir(),
        "checkout pruned .kit/refs/spare through d -> .kit"
    );
}

#[test]
fn reset_hard_still_removes_a_dropped_file_in_a_real_directory() {
    let td = tempfile::tempdir().unwrap();
    let xdg = tempfile::tempdir().unwrap();
    let (root, x) = (td.path(), xdg.path());
    ok(root, x, &["init"]);
    ok(root, x, &["keygen"]);
    fs::write(root.join("keep.txt"), b"keep\n").unwrap();
    let target = commit_all(root, x, "target");
    fs::create_dir_all(root.join("a/b")).unwrap();
    fs::write(root.join("a/b/gone.txt"), b"gone\n").unwrap();
    commit_all(root, x, "current");

    ok(root, x, &["reset", "--hard", &target]);

    assert!(!root.join("a/b/gone.txt").exists());
    assert!(root.join("keep.txt").exists());
}

#[test]
fn checkout_still_removes_a_dropped_file_and_prunes_its_empty_directories() {
    let td = tempfile::tempdir().unwrap();
    let xdg = tempfile::tempdir().unwrap();
    let (root, x) = (td.path(), xdg.path());
    ok(root, x, &["init"]);
    ok(root, x, &["keygen"]);
    fs::write(root.join("keep.txt"), b"keep\n").unwrap();
    let target = commit_all(root, x, "target");
    fs::create_dir_all(root.join("a/b")).unwrap();
    fs::write(root.join("a/b/gone.txt"), b"gone\n").unwrap();
    commit_all(root, x, "current");

    ok(root, x, &["checkout", &target]);

    assert!(
        !root.join("a").exists(),
        "empty directories were not pruned"
    );
    assert!(root.join("keep.txt").exists());
}

#[test]
fn rm_still_removes_a_tracked_file_in_a_real_directory() {
    let td = tempfile::tempdir().unwrap();
    let xdg = tempfile::tempdir().unwrap();
    let (root, x) = (td.path(), xdg.path());
    ok(root, x, &["init"]);
    ok(root, x, &["keygen"]);
    fs::create_dir_all(root.join("a/b")).unwrap();
    fs::write(root.join("a/b/f.txt"), b"f\n").unwrap();
    commit_all(root, x, "current");

    ok(root, x, &["rm", "a/b/f.txt"]);

    assert!(
        !root.join("a").exists(),
        "file and empty directories remain"
    );
}
