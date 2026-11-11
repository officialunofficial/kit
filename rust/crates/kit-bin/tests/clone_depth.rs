//! `kit clone --depth N` is rejected: a clone holds the full history.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::process::Command;

#[test]
fn clone_depth_is_rejected_with_the_reason() {
    let dest = tempfile::tempdir().unwrap();
    let xdg = tempfile::tempdir().unwrap();
    let target = dest.path().join("clone1");
    let out = Command::new(env!("CARGO_BIN_EXE_kit"))
        .args(["clone", "--depth", "1", "kit+file:///nonexistent"])
        .arg(&target)
        .current_dir(dest.path())
        .env("XDG_CONFIG_HOME", xdg.path())
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(64), "usage error: {out:?}");
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("--depth is not supported")
            && stderr.contains("every commit verifies with its ancestors"),
        "stderr: {stderr}"
    );
    assert!(!target.exists(), "no clone directory is created");
}
