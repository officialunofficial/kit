//! `kit log --all`: the walk starts at `HEAD`, every local branch, every
//! remote-tracking ref and every tag.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

mod common;

use common::Repo;

fn stdout(repo: &Repo, args: &[&str]) -> String {
    String::from_utf8(repo.ok(args).stdout).unwrap()
}

/// Subjects of `log --oneline` with the given extra arguments, newest first.
fn subjects(repo: &Repo, args: &[&str]) -> Vec<String> {
    let mut all = vec!["log", "--oneline"];
    all.extend_from_slice(args);
    stdout(repo, &all)
        .lines()
        .map(|l| l.split_once(' ').unwrap().1.to_owned())
        .collect()
}

/// `main` holds `base` and `on main`. `topic` holds `on topic`. The tag `v1`
/// names `tagged`. `origin/gone` holds `remote only`. A detached HEAD holds
/// `detached`. Only `base` and `on topic` are reachable from the detached
/// HEAD.
fn scattered() -> (Repo, Repo) {
    let repo = Repo::new();
    let remote = Repo::new();
    repo.commit_file("a.txt", b"base\n", "base");
    let url = format!("kit+file://{}", remote.path().display());
    repo.ok(&["remote", "add", "origin", &url]);

    repo.ok(&["checkout", "-b", "topic"]);
    repo.commit_file("t.txt", b"topic\n", "on topic");
    repo.ok(&["checkout", "-b", "gone"]);
    repo.commit_file("r.txt", b"remote\n", "remote only");
    repo.ok(&["push", "origin", "gone:gone"]);
    repo.ok(&["checkout", "topic"]);
    repo.ok(&["branch", "-D", "gone"]);

    repo.ok(&["checkout", "-b", "tagged"]);
    repo.commit_file("g.txt", b"tag\n", "tagged");
    repo.ok(&["tag", "v1"]);
    repo.ok(&["checkout", "topic"]);
    repo.ok(&["branch", "-D", "tagged"]);

    repo.ok(&["checkout", "main"]);
    repo.commit_file("m.txt", b"main\n", "on main");
    let topic = stdout(&repo, &["rev-parse", "topic"]);
    repo.ok(&["checkout", topic.trim()]);
    repo.commit_file("d.txt", b"detached\n", "detached");
    (repo, remote)
}

#[test]
fn all_walks_from_every_kind_of_ref_and_head() {
    let (repo, _remote) = scattered();
    let all = subjects(&repo, &["--all"]);
    for expected in [
        "base",
        "on main",
        "on topic",
        "tagged",
        "remote only",
        "detached",
    ] {
        assert!(all.iter().any(|s| s == expected), "{expected}: {all:?}");
    }
    // Each commit shows once.
    assert_eq!(all.len(), 6, "{all:?}");
    // Without --all only the history of HEAD shows.
    assert_eq!(subjects(&repo, &[]), ["detached", "on topic", "base"]);
}

#[test]
fn all_shows_a_parent_after_its_children() {
    let (repo, _remote) = scattered();
    let all = subjects(&repo, &["--all"]);
    let at = |s: &str| all.iter().position(|x| x == s).unwrap();
    assert!(at("detached") < at("on topic"));
    assert!(at("on topic") < at("base"));
    assert!(at("remote only") < at("on topic"));
    assert!(at("tagged") < at("on topic"));
    assert!(at("on main") < at("base"));
    assert_eq!(all.last().unwrap(), "base");
}

#[test]
fn all_applies_a_limit_and_a_filter_after_the_walk() {
    let (repo, _remote) = scattered();
    assert_eq!(subjects(&repo, &["--all", "-n", "2"]).len(), 2);
    assert_eq!(
        subjects(&repo, &["--all", "--grep", "remote"]),
        ["remote only"]
    );
}

#[test]
fn all_works_in_the_default_and_json_formats() {
    let (repo, _remote) = scattered();
    let default = stdout(&repo, &["log", "--all"]);
    assert_eq!(default.matches("commit ").count(), 6);
    let json = stdout(&repo, &["log", "--all", "--format=json"]);
    assert_eq!(json.lines().count(), 6);
}

#[test]
fn all_with_a_revision_or_a_range_is_a_usage_error() {
    let (repo, _remote) = scattered();
    for extra in ["main", "topic..main", "topic...main"] {
        let out = repo.run(&["log", "--all", extra]);
        assert_eq!(out.status.code(), Some(64), "{extra}");
        assert!(out.stdout.is_empty(), "{extra}");
    }
}

#[test]
fn all_in_a_repository_without_a_commit_prints_nothing() {
    let repo = Repo::new();
    let out = repo.ok(&["log", "--all"]);
    assert!(out.stdout.is_empty());
}

#[test]
fn all_follows_an_annotated_tag_to_its_commit() {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"a\n", "first");
    repo.ok(&["checkout", "-b", "work"]);
    repo.commit_file("b.txt", b"b\n", "second");
    repo.ok(&["tag", "-a", "v2", "-m", "release"]);
    repo.ok(&["checkout", "main"]);
    repo.ok(&["branch", "-D", "work"]);
    assert_eq!(subjects(&repo, &["--all"]), ["second", "first"]);
}
