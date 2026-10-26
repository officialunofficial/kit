//! `kit cat` maps repository open failures to the documented exit codes.

mod common;

use common::kit;

const HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[test]
fn outside_a_repository_exits_with_the_general_error_code() {
    let dir = tempfile::tempdir().expect("tempdir");
    let xdg = tempfile::tempdir().expect("xdg");
    let out = kit(dir.path(), xdg.path(), &["cat", HASH]);
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("not a kit repo"), "{stderr}");
}

#[test]
fn a_broken_worktree_pointer_exits_with_the_data_error_code() {
    let dir = tempfile::tempdir().expect("tempdir");
    let xdg = tempfile::tempdir().expect("xdg");
    std::fs::write(dir.path().join(".kit"), b"gitdir: /somewhere\n").expect("write pointer");
    let out = kit(dir.path(), xdg.path(), &["cat", HASH]);
    assert_eq!(out.status.code(), Some(65));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("worktree discovery"), "{stderr}");
}
