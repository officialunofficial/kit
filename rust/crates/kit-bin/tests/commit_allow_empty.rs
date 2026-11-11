//! `kit commit --allow-empty`: a commit whose tree equals its parent's, and a
//! first commit with nothing staged.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

mod common;

use common::Repo;

fn text(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

fn tree_of(repo: &Repo, rev: &str) -> String {
    text(&repo.ok(&["ls-tree", rev]))
}

#[test]
fn an_unchanged_tree_commits_with_the_flag() {
    let repo = Repo::new();
    repo.commit_file("f.txt", b"v1\n", "first");
    let before = text(&repo.ok(&["rev-parse", "HEAD"]));
    repo.ok(&["commit", "--allow-empty", "-m", "again"]);
    let after = text(&repo.ok(&["rev-parse", "HEAD"]));
    assert_ne!(before, after);
    assert_eq!(text(&repo.ok(&["rev-parse", "HEAD~1"])), before);
    assert_eq!(tree_of(&repo, "HEAD"), tree_of(&repo, "HEAD~1"));
}

#[test]
fn an_unchanged_tree_commits_without_the_flag_as_before() {
    let repo = Repo::new();
    repo.commit_file("f.txt", b"v1\n", "first");
    repo.ok(&["commit", "-m", "again"]);
    assert_eq!(tree_of(&repo, "HEAD"), tree_of(&repo, "HEAD~1"));
}

#[test]
fn a_first_commit_with_nothing_staged_needs_the_flag() {
    let repo = Repo::new();
    let refused = repo.run(&["commit", "-m", "root"]);
    assert!(!refused.status.success());
    assert!(!repo.run(&["rev-parse", "HEAD"]).status.success());

    repo.ok(&["commit", "--allow-empty", "-m", "root"]);
    repo.ok(&["rev-parse", "HEAD"]);
    repo.commit_file("f.txt", b"v1\n", "next");
    assert_eq!(text(&repo.ok(&["ls-tree", "HEAD~1"])), "");
}
