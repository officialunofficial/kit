//! `remote add` / `clone` URL + name control-char validation.
//!
//! A URL (or remote name) containing a newline would inject extra
//! `key = value` lines into `.kit/config` via `config::write`, which
//! emits values raw. Both commands must reject control characters before
//! persisting. Driven end-to-end through the real binary.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

fn kit_bin() -> &'static str {
    env!("CARGO_BIN_EXE_kit")
}

fn run_in(cwd: &Path, args: &[&str]) -> Output {
    let xdg = tempfile::tempdir().expect("xdg tempdir");
    let out = Command::new(kit_bin())
        .args(args)
        .current_dir(cwd)
        .env("XDG_CONFIG_HOME", xdg.path())
        .output()
        .expect("spawn kit");
    drop(xdg);
    out
}

fn init_repo() -> tempfile::TempDir {
    let td = tempfile::tempdir().unwrap();
    assert!(run_in(td.path(), &["init"]).status.success());
    td
}

#[test]
fn remote_add_rejects_newline_in_url() {
    let td = init_repo();
    // A URL with an embedded newline + a forbidden key would, before the
    // fix, be written verbatim into `.kit/config`.
    let evil = "kit+https://example.com/p\nuser.identity = ed25519:deadbeef";
    let out = run_in(td.path(), &["remote", "add", evil]);
    assert!(
        !out.status.success(),
        "remote add must reject a URL with control characters"
    );
    // The config must not have been written with the injected line.
    let cfg = fs::read_to_string(td.path().join(".kit/config")).unwrap_or_default();
    assert!(
        !cfg.contains("user.identity"),
        "injected key leaked into config: {cfg}"
    );
}

#[test]
fn remote_add_rejects_newline_in_name() {
    let td = init_repo();
    let out = run_in(
        td.path(),
        &["remote", "add", "bad\nname", "kit+https://example.com/p"],
    );
    assert!(
        !out.status.success(),
        "remote add must reject a remote name with control characters"
    );
}

#[test]
fn clone_rejects_newline_in_url() {
    let parent = tempfile::tempdir().unwrap();
    let evil = "kit+https://example.com/p\nuser.identity = ed25519:deadbeef";
    let out = run_in(parent.path(), &["clone", evil, "dest"]);
    assert!(
        !out.status.success(),
        "clone must reject a URL with control characters"
    );
    // If a destination was created, its config must not carry the
    // injected line.
    let cfg = fs::read_to_string(parent.path().join("dest/.kit/config")).unwrap_or_default();
    assert!(
        !cfg.contains("user.identity"),
        "injected key leaked into clone config: {cfg}"
    );
}

#[test]
fn remote_add_accepts_clean_url() {
    let td = init_repo();
    let out = run_in(
        td.path(),
        &["remote", "add", "kit+https://example.com/project"],
    );
    assert!(
        out.status.success(),
        "a clean URL must still be accepted: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}
