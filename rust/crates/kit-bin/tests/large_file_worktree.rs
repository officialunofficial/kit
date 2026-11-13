//! A worktree file above 1 GiB, up to the chunked bound, goes through `add`,
//! `status`, `diff --stat` and `stash` without a size refusal.
//!
//! The file is sparse, so it costs little disk until `stash` writes it back.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::fs;
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;
use std::process::{Command, Output};

const GIB: u64 = 1 << 30;

fn kit(cwd: &Path, xdg: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_kit"))
        .args(args)
        .current_dir(cwd)
        .env("XDG_CONFIG_HOME", xdg)
        .output()
        .expect("spawn kit")
}

fn ok(cwd: &Path, xdg: &Path, args: &[&str]) -> Output {
    let out = kit(cwd, xdg, args);
    assert!(
        out.status.success(),
        "kit {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

#[test]
fn a_two_gib_file_adds_reports_changes_and_stashes() {
    let td = tempfile::tempdir().unwrap();
    let xdg = tempfile::tempdir().unwrap();
    let (root, x) = (td.path(), xdg.path());
    ok(root, x, &["init"]);
    ok(root, x, &["keygen"]);

    let big = root.join("big.bin");
    let file = fs::File::create(&big).unwrap();
    file.set_len(2 * GIB).unwrap();
    drop(file);

    ok(root, x, &["add", "big.bin"]);
    ok(root, x, &["commit", "-m", "big"]);
    let status = ok(root, x, &["status", "--porcelain"]);
    assert!(status.stdout.is_empty(), "a clean file reports nothing");

    let mut handle = fs::OpenOptions::new().write(true).open(&big).unwrap();
    handle.seek(SeekFrom::Start(GIB + 5)).unwrap();
    handle.write_all(b"changed").unwrap();
    drop(handle);

    let status = ok(root, x, &["status", "--porcelain"]);
    assert!(
        String::from_utf8_lossy(&status.stdout).contains("big.bin"),
        "status reports the changed file"
    );
    let stat = ok(root, x, &["diff", "--stat"]);
    assert!(
        String::from_utf8_lossy(&stat.stdout).contains("big.bin"),
        "diff --stat reports the changed file: {}",
        String::from_utf8_lossy(&stat.stdout)
    );

    ok(root, x, &["stash"]);
    assert_eq!(fs::metadata(&big).unwrap().len(), 2 * GIB);
    let status = ok(root, x, &["status", "--porcelain"]);
    assert!(
        status.stdout.is_empty(),
        "stash restores the committed file"
    );
}
