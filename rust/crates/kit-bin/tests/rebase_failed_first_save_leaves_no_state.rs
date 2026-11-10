//! A rebase whose first state save fails must leave no `rebase-apply`
//! directory behind. An empty one blocks `kit rebase --abort` and every new
//! rebase.
#![cfg(unix)]
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

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

/// Run `kit args` with a file size limit of zero. A write fails with an I/O
/// error instead of killing the process.
fn run_without_file_space(cwd: &Path, xdg: &Path, args: &[&str]) -> Output {
    Command::new("sh")
        .arg("-c")
        .arg("trap '' XFSZ; ulimit -f 0; exec \"$0\" \"$@\"")
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

fn commit_file(root: &Path, xdg: &Path, name: &str) {
    fs::write(root.join(name), format!("{name}\n")).unwrap();
    ok(&run_in(root, xdg, &["add", name]));
    ok(&run_in(root, xdg, &["commit", "-m", name]));
}

/// A repository on `feature`, which has one commit that `main` lacks.
fn diverged_repo() -> (tempfile::TempDir, tempfile::TempDir) {
    let td = tempfile::tempdir().unwrap();
    let xdg = tempfile::tempdir().unwrap();
    let (root, x) = (td.path(), xdg.path());
    ok(&run_in(root, x, &["init"]));
    ok(&run_in(root, x, &["keygen"]));
    commit_file(root, x, "base.txt");
    ok(&run_in(root, x, &["branch", "feature"]));
    commit_file(root, x, "main.txt");
    ok(&run_in(root, x, &["checkout", "feature"]));
    commit_file(root, x, "feature.txt");
    (td, xdg)
}

#[test]
fn a_rebase_that_cannot_save_its_state_leaves_no_state_directory() {
    let (td, xdg) = diverged_repo();
    let (root, x) = (td.path(), xdg.path());

    let out = run_without_file_space(root, x, &["rebase", "main"]);

    assert!(!out.status.success(), "the save should fail: {out:?}");
    assert!(
        !root.join(".kit/rebase-apply").exists(),
        "state directory left behind"
    );
    ok(&run_in(root, x, &["rebase", "main"]));
}
