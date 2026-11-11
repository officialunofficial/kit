//! `kit checkout -- <path>...`: restore paths through `kit restore`.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

mod common;

use std::process::Output;

use common::Repo;

fn read(repo: &Repo, rel: &str) -> String {
    std::fs::read_to_string(repo.path().join(rel)).unwrap()
}

fn text(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn branch(repo: &Repo) -> String {
    text(&repo.ok(&["rev-parse", "--abbrev-ref", "HEAD"]))
}

/// `f.txt` and `dir/g.txt`, committed in three commits: `f.txt` is `v1`, then
/// `dir/g.txt` is added, then `f.txt` is `v2`.
fn two_commits() -> Repo {
    let repo = Repo::new();
    repo.write("dir/g.txt", b"g1\n");
    repo.commit_file("f.txt", b"v1\n", "first");
    repo.ok(&["add", "dir/g.txt"]);
    repo.ok(&["commit", "-m", "second file"]);
    repo.commit_file("f.txt", b"v2\n", "second");
    repo
}

#[test]
fn a_deleted_file_comes_back_from_the_index() {
    let repo = two_commits();
    std::fs::remove_file(repo.path().join("f.txt")).unwrap();
    repo.ok(&["checkout", "--", "f.txt"]);
    assert_eq!(read(&repo, "f.txt"), "v2\n");
}

#[test]
fn an_edited_file_is_refused_as_restore_refuses_it() {
    let repo = two_commits();
    repo.write("f.txt", b"edited\n");
    let restore = repo.run(&["restore", "f.txt"]);
    let checkout = repo.run(&["checkout", "--", "f.txt"]);
    assert!(!checkout.status.success());
    assert_eq!(checkout.status.code(), restore.status.code());
    assert_eq!(checkout.stderr, restore.stderr);
    assert_eq!(read(&repo, "f.txt"), "edited\n");
}

#[test]
fn force_restores_an_edited_file_from_the_index() {
    let repo = two_commits();
    repo.write("f.txt", b"staged\n");
    repo.ok(&["add", "f.txt"]);
    repo.write("f.txt", b"edited\n");
    repo.ok(&["checkout", "-f", "--", "f.txt"]);
    assert_eq!(read(&repo, "f.txt"), "staged\n");
    repo.write("f.txt", b"edited again\n");
    repo.ok(&["checkout", "--force", "--", "f.txt"]);
    assert_eq!(read(&repo, "f.txt"), "staged\n");
}

#[test]
fn a_directory_and_several_paths_work() {
    let repo = two_commits();
    std::fs::remove_file(repo.path().join("f.txt")).unwrap();
    std::fs::remove_file(repo.path().join("dir/g.txt")).unwrap();
    repo.ok(&["checkout", "--", "dir", "f.txt"]);
    assert_eq!(read(&repo, "dir/g.txt"), "g1\n");
    assert_eq!(read(&repo, "f.txt"), "v2\n");
}

#[test]
fn a_path_that_starts_with_a_dash_is_a_path_after_the_separator() {
    let repo = two_commits();
    let out = repo.run(&["checkout", "--", "-nope"]);
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(stderr.contains("did not match"), "{stderr}");
}

#[test]
fn a_missing_path_changes_nothing() {
    let repo = two_commits();
    let out = repo.run(&["checkout", "--", "missing.txt"]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(read(&repo, "f.txt"), "v2\n");
    assert_eq!(text(&repo.ok(&["status", "--porcelain"])), "");
}

#[test]
fn other_forms_before_the_separator_are_usage_errors() {
    let repo = two_commits();
    for args in [
        vec!["checkout", "--"],
        vec!["checkout", "-b", "new", "--", "f.txt"],
        vec!["checkout", "main", "--", "f.txt"],
        vec!["checkout", "-f", "-f", "--", "f.txt"],
        vec!["checkout", "--sparse", "x", "--", "f.txt"],
    ] {
        let out = repo.run(&args);
        assert_eq!(out.status.code(), Some(64), "{args:?}");
        assert!(out.stdout.is_empty(), "{args:?}");
    }
    assert_eq!(branch(&repo), "main\n");
}

#[test]
fn a_branch_checkout_still_works() {
    let repo = two_commits();
    repo.ok(&["branch", "other"]);
    repo.ok(&["checkout", "other"]);
    assert_eq!(branch(&repo), "other\n");
}
