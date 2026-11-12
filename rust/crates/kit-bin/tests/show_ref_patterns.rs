//! `kit show-ref <pattern>...`: keep the refs that a pattern names.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

mod common;

use std::process::Output;

use common::Repo;

fn names(out: &Output) -> Vec<String> {
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|l| l.split_once(' ').unwrap().1.to_string())
        .collect()
}

/// Branches `main`, `domain` and `feature/main`, and the tag `v1`.
fn repo() -> Repo {
    let repo = Repo::new();
    repo.commit_file("f.txt", b"one\n", "first");
    repo.ok(&["branch", "domain"]);
    repo.ok(&["branch", "feature/main"]);
    repo.ok(&["tag", "v1"]);
    repo
}

#[test]
fn a_pattern_matches_the_full_name_or_trailing_components() {
    let repo = repo();
    assert_eq!(
        names(&repo.ok(&["show-ref", "refs/heads/main"])),
        ["refs/heads/main"]
    );
    assert_eq!(
        names(&repo.ok(&["show-ref", "heads/main"])),
        ["refs/heads/main"]
    );
    // `main` is a trailing component of two refs, and `domain` is not a match.
    assert_eq!(
        names(&repo.ok(&["show-ref", "main"])),
        ["refs/heads/feature/main", "refs/heads/main"]
    );
    assert_eq!(names(&repo.ok(&["show-ref", "v1"])), ["refs/tags/v1"]);
}

#[test]
fn a_partial_component_does_not_match() {
    let repo = repo();
    for pattern in ["ain", "omain", "refs/heads/mai", "heads", "refs/heads/"] {
        let out = repo.run(&["show-ref", pattern]);
        assert_eq!(out.status.code(), Some(1), "{pattern}");
        assert!(out.stdout.is_empty(), "{pattern}");
    }
}

#[test]
fn several_patterns_give_the_union_in_ref_order() {
    let repo = repo();
    assert_eq!(
        names(&repo.ok(&["show-ref", "v1", "domain"])),
        ["refs/heads/domain", "refs/tags/v1"]
    );
}

#[test]
fn a_pattern_combines_with_heads_and_tags() {
    let repo = repo();
    assert_eq!(
        names(&repo.ok(&["show-ref", "--heads", "domain", "v1"])),
        ["refs/heads/domain"]
    );
    let out = repo.run(&["show-ref", "--tags", "domain"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
}

#[test]
fn no_pattern_lists_every_ref() {
    let repo = repo();
    assert_eq!(
        names(&repo.ok(&["show-ref"])),
        [
            "refs/heads/domain",
            "refs/heads/feature/main",
            "refs/heads/main",
            "refs/tags/v1"
        ]
    );
}

#[test]
fn an_empty_pattern_is_a_usage_error() {
    let repo = repo();
    let out = repo.run(&["show-ref", ""]);
    assert_eq!(out.status.code(), Some(64));
    assert!(out.stdout.is_empty());
}
