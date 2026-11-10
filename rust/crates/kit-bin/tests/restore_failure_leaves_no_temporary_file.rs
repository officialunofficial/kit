//! A checkout or a stash pop that cannot write a file must not leave its
//! temporary file in the worktree, where `kit status` lists it and
//! `kit add` stages it.
#![cfg(unix)]
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

/// Larger than the file size limit below and smaller than the chunking
/// threshold, so the restore writes the file as one plain blob.
const BIG_FILE_BYTES: usize = 900 * 1024;

/// The file size limit in blocks of the shell's `ulimit -f`. It is 128 KiB
/// for 512-byte blocks and 256 KiB for 1024-byte blocks. Both are under
/// `BIG_FILE_BYTES`.
const FILE_SIZE_LIMIT_BLOCKS: u32 = 256;

fn kit_bin() -> &'static str {
    env!("CARGO_BIN_EXE_kit")
}

fn run_in(cwd: &Path, xdg: &Path, args: &[&str]) -> Output {
    Command::new(kit_bin())
        .args(args)
        .current_dir(cwd)
        .env("XDG_CONFIG_HOME", xdg)
        .output()
        .expect("spawn kit")
}

/// Run `kit args` with a file size limit. A write past the limit fails with
/// an I/O error instead of killing the process.
fn run_with_file_size_limit(cwd: &Path, xdg: &Path, args: &[&str]) -> Output {
    Command::new("sh")
        .arg("-c")
        .arg(format!(
            "trap '' XFSZ; ulimit -f {FILE_SIZE_LIMIT_BLOCKS}; exec \"$0\" \"$@\""
        ))
        .arg(kit_bin())
        .args(args)
        .current_dir(cwd)
        .env("XDG_CONFIG_HOME", xdg)
        .output()
        .expect("spawn sh")
}

fn ok(out: &Output) {
    assert!(out.status.success(), "command failed: {out:?}");
}

fn big_file(seed: u8) -> Vec<u8> {
    (0..BIG_FILE_BYTES)
        .map(|i| u8::try_from(i % 251).unwrap().wrapping_add(seed))
        .collect()
}

fn assert_failed_write_left_no_temporary_file(out: &Output, root: &Path) {
    assert!(!out.status.success(), "the write should fail: {out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("big.bin"), "stderr: {stderr}");
    let leftovers: Vec<_> = fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| name.starts_with(".kit-restore-tmp."))
        .collect();
    assert!(leftovers.is_empty(), "temporary files left: {leftovers:?}");
}

/// A repository with a keyed `main` that tracks `a.txt`.
fn repo_with_big_file() -> (tempfile::TempDir, tempfile::TempDir) {
    let td = tempfile::tempdir().unwrap();
    let xdg = tempfile::tempdir().unwrap();
    let (root, x) = (td.path(), xdg.path());
    ok(&run_in(root, x, &["init"]));
    ok(&run_in(root, x, &["keygen"]));
    fs::write(root.join("a.txt"), b"alpha\n").unwrap();
    ok(&run_in(root, x, &["add", "."]));
    ok(&run_in(root, x, &["commit", "-m", "initial"]));
    (td, xdg)
}

#[test]
fn checkout_that_cannot_write_a_file_leaves_no_temporary_file() {
    let (td, xdg) = repo_with_big_file();
    let (root, x) = (td.path(), xdg.path());
    ok(&run_in(root, x, &["branch", "feature"]));
    ok(&run_in(root, x, &["checkout", "feature"]));
    fs::write(root.join("big.bin"), big_file(0)).unwrap();
    ok(&run_in(root, x, &["add", "."]));
    ok(&run_in(root, x, &["commit", "-m", "add big file"]));
    ok(&run_in(root, x, &["checkout", "main"]));
    assert!(!root.join("big.bin").exists());

    let out = run_with_file_size_limit(root, x, &["checkout", "feature"]);

    assert_failed_write_left_no_temporary_file(&out, root);
}

#[test]
fn stash_pop_that_cannot_write_a_file_leaves_no_temporary_file() {
    let (td, xdg) = repo_with_big_file();
    let (root, x) = (td.path(), xdg.path());
    fs::write(root.join("big.bin"), big_file(0)).unwrap();
    ok(&run_in(root, x, &["add", "."]));
    ok(&run_in(root, x, &["commit", "-m", "add big file"]));
    fs::write(root.join("big.bin"), big_file(1)).unwrap();
    ok(&run_in(root, x, &["stash"]));
    assert_eq!(fs::read(root.join("big.bin")).unwrap(), big_file(0));

    let out = run_with_file_size_limit(root, x, &["stash", "pop"]);

    assert_failed_write_left_no_temporary_file(&out, root);
}
