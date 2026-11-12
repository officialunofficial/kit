//! `kit rev-list --max-count` and ranges: the commit selection of `kit log`
//! with the output of `rev-list`.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

mod common;

use std::process::Output;

use common::Repo;

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn ids(out: &Output) -> Vec<String> {
    text(&out.stdout).lines().map(str::to_string).collect()
}

/// Five commits, `c1` to `c5`, on `main`.
fn five_commits() -> Repo {
    let repo = Repo::new();
    for n in 1..=5 {
        repo.commit_file("f.txt", format!("{n}\n").as_bytes(), &format!("c{n}"));
    }
    repo
}

fn full(repo: &Repo) -> Vec<String> {
    ids(&repo.ok(&["rev-list", "HEAD"]))
}

#[test]
fn max_count_keeps_the_newest_commits() {
    let repo = five_commits();
    let all = full(&repo);
    assert_eq!(all.len(), 5);
    for (flags, n) in [
        (vec!["-n", "1"], 1),
        (vec!["-n", "3"], 3),
        (vec!["-n3"], 3),
        (vec!["--max-count=3"], 3),
        (vec!["--max-count", "3"], 3),
        (vec!["-n", "5"], 5),
    ] {
        let mut args = vec!["rev-list"];
        args.extend(&flags);
        args.push("HEAD");
        assert_eq!(ids(&repo.ok(&args)), all[..n], "{flags:?}");
    }
}

#[test]
fn max_count_of_zero_lists_nothing() {
    let repo = five_commits();
    for flags in [["-n", "0"], ["--max-count", "0"]] {
        let out = repo.ok(&["rev-list", flags[0], flags[1], "HEAD"]);
        assert!(out.stdout.is_empty(), "{flags:?}");
        let out = repo.ok(&["rev-list", "--count", flags[0], flags[1], "HEAD"]);
        assert_eq!(text(&out.stdout), "0\n", "{flags:?}");
    }
}

#[test]
fn max_count_above_the_history_lists_everything() {
    let repo = five_commits();
    let all = full(&repo);
    assert_eq!(ids(&repo.ok(&["rev-list", "-n", "6", "HEAD"])), all);
    assert_eq!(
        ids(&repo.ok(&["rev-list", "--max-count=1000000", "HEAD"])),
        all
    );
    let max = usize::MAX.to_string();
    assert_eq!(ids(&repo.ok(&["rev-list", "-n", &max, "HEAD"])), all);
}

#[test]
fn count_counts_what_the_limit_leaves() {
    let repo = five_commits();
    let out = repo.ok(&["rev-list", "--count", "-n", "2", "HEAD"]);
    assert_eq!(text(&out.stdout), "2\n");
    let out = repo.ok(&["rev-list", "--count", "HEAD"]);
    assert_eq!(text(&out.stdout), "5\n");
}

#[test]
fn a_root_commit_lists_itself() {
    let repo = Repo::new();
    repo.commit_file("f.txt", b"1\n", "only");
    assert_eq!(ids(&repo.ok(&["rev-list", "-n", "1", "HEAD"])).len(), 1);
}

#[test]
fn a_range_lists_the_commits_after_its_start() {
    let repo = five_commits();
    let all = full(&repo);
    assert_eq!(ids(&repo.ok(&["rev-list", "HEAD~3..HEAD"])), all[..3]);
    assert_eq!(ids(&repo.ok(&["rev-list", "HEAD~3.."])), all[..3]);
    assert_eq!(ids(&repo.ok(&["rev-list", "HEAD~3..HEAD~1"])), all[1..3]);
    assert!(
        ids(&repo.ok(&["rev-list", "HEAD..HEAD"])).is_empty(),
        "an empty range lists nothing"
    );
    assert_eq!(
        text(&repo.ok(&["rev-list", "--count", "HEAD~2..HEAD"]).stdout),
        "2\n"
    );
}

#[test]
fn a_range_takes_a_limit() {
    let repo = five_commits();
    let all = full(&repo);
    assert_eq!(
        ids(&repo.ok(&["rev-list", "-n", "2", "HEAD~4..HEAD"])),
        all[..2]
    );
}

#[test]
fn a_range_matches_the_history_of_log() {
    let repo = five_commits();
    let log = repo.ok(&["log", "--format=json", "HEAD~3..HEAD"]);
    let from_log: Vec<String> = text(&log.stdout)
        .lines()
        .map(|l| l.split("\"hash\":\"").nth(1).unwrap()[..64].to_string())
        .collect();
    assert_eq!(ids(&repo.ok(&["rev-list", "HEAD~3..HEAD"])), from_log);
}

#[test]
fn a_symmetric_range_lists_both_sides_without_the_base() {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"base\n", "base");
    repo.ok(&["branch", "feature"]);
    repo.ok(&["checkout", "feature"]);
    repo.commit_file("b.txt", b"feat\n", "feat");
    repo.ok(&["checkout", "main"]);
    repo.commit_file("c.txt", b"main\n", "main2");
    let sym = ids(&repo.ok(&["rev-list", "main...feature"]));
    assert_eq!(sym.len(), 2);
    let one = ids(&repo.ok(&["rev-list", "main..feature"]));
    assert_eq!(one.len(), 1);
    assert!(sym.contains(&one[0]));
    assert_eq!(
        ids(&repo.ok(&["rev-list", "-n", "1", "main...feature"])).len(),
        1
    );
}

#[test]
fn a_range_over_a_merge_lists_the_merged_side() {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"base\n", "base");
    repo.ok(&["branch", "feature"]);
    repo.ok(&["checkout", "feature"]);
    repo.commit_file("b.txt", b"feat\n", "feat");
    repo.ok(&["checkout", "main"]);
    repo.commit_file("c.txt", b"main\n", "main2");
    repo.ok(&["merge", "-m", "join", "feature"]);
    // base, feat, main2, join.
    assert_eq!(ids(&repo.ok(&["rev-list", "HEAD"])).len(), 4);
    // The merge and the commit of each side after the base.
    assert_eq!(ids(&repo.ok(&["rev-list", "HEAD~2..HEAD"])).len(), 3);
    assert_eq!(ids(&repo.ok(&["rev-list", "HEAD~1..HEAD"])).len(), 2);
    assert_eq!(ids(&repo.ok(&["rev-list", "-n", "3", "HEAD"])).len(), 3);
}

#[test]
fn a_bad_count_is_an_error() {
    let repo = five_commits();
    // The code of `log -n abc` for a value that is not a number. A value that
    // starts with `-` reads as a flag, a usage error.
    assert_eq!(repo.run(&["log", "-n", "abc"]).status.code(), Some(65));
    for value in [
        "abc",
        "-1",
        "1.5",
        "",
        "0x1",
        "+",
        "99999999999999999999999",
    ] {
        for args in [
            vec!["rev-list", "-n", value, "HEAD"],
            vec!["rev-list", "--max-count", value, "HEAD"],
        ] {
            let out = repo.run(&args);
            let expected = if value == "-1" { 64 } else { 65 };
            assert_eq!(out.status.code(), Some(expected), "{args:?}");
            assert!(out.stdout.is_empty(), "{args:?}");
            assert!(!out.stderr.is_empty(), "{args:?}");
        }
    }
    let out = repo.run(&["rev-list", "--max-count=-1", "HEAD"]);
    assert_eq!(out.status.code(), Some(65));
    let out = repo.run(&["rev-list", "-n", "HEAD"]);
    assert!(!out.status.success());
}

#[test]
fn a_bad_revision_or_range_is_an_error() {
    let repo = five_commits();
    for spec in [
        "",
        "nope",
        "nope..HEAD",
        "HEAD..nope",
        "nope...HEAD",
        "HEAD~9",
    ] {
        let out = repo.run(&["rev-list", spec]);
        assert_eq!(out.status.code(), Some(1), "{spec:?}");
        assert!(out.stdout.is_empty(), "{spec:?}");
        assert!(!out.stderr.is_empty(), "{spec:?}");
    }
}

#[test]
fn a_repository_without_commits_is_an_error() {
    let repo = Repo::new();
    for spec in ["HEAD", "HEAD..HEAD"] {
        let out = repo.run(&["rev-list", spec]);
        assert_eq!(out.status.code(), Some(1), "{spec}");
        assert!(out.stdout.is_empty());
    }
}

#[test]
fn a_missing_commit_is_an_error_not_a_short_list() {
    let repo = five_commits();
    let all = full(&repo);
    let id = &all[3];
    let object = repo.kit_dir().join("objects").join(&id[..2]).join(&id[2..]);
    std::fs::remove_file(object).unwrap();
    let out = repo.run(&["rev-list", "HEAD"]);
    assert_eq!(out.status.code(), Some(65));
    assert!(out.stdout.is_empty());
    // The limit stops the walk before the damaged commit.
    let out = repo.ok(&["rev-list", "-n", "3", "HEAD"]);
    assert_eq!(ids(&out), all[..3]);
}
