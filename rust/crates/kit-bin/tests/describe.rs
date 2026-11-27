//! `kit describe`: name a commit after the nearest tag that reaches it, as
//! `<tag>-<n>-k<short id>`.
//!
//! Fixed cases pin the choice of tag, the options and the exit codes. A
//! differential case checks the tag and the count against real
//! `git describe` when it is on `PATH`.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

mod common;

use std::path::Path;
use std::process::{Command, Output};

use common::Repo;

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn rev(repo: &Repo, spec: &str) -> String {
    stdout(&repo.ok(&["rev-parse", spec])).trim().to_owned()
}

fn describe(repo: &Repo, args: &[&str]) -> String {
    let mut all = vec!["describe"];
    all.extend_from_slice(args);
    stdout(&repo.ok(&all)).trim_end().to_owned()
}

/// `c1` (tag `v1`), `c2`, `c3` (tag `v2`), `c4`, `c5`; both tags annotated.
fn linear() -> Repo {
    let repo = Repo::new();
    for i in 1..=5 {
        repo.commit_file("f.txt", format!("{i}\n").as_bytes(), &format!("c{i}"));
        if i == 1 {
            repo.ok(&["tag", "-a", "v1", "-m", "one"]);
        }
        if i == 3 {
            repo.ok(&["tag", "-a", "v2", "-m", "two"]);
        }
    }
    repo
}

fn short(repo: &Repo, spec: &str) -> String {
    rev(repo, spec)[..7].to_owned()
}

#[test]
fn the_nearest_annotated_tag_names_the_commit() {
    let repo = linear();
    assert_eq!(
        describe(&repo, &[]),
        format!("v2-2-k{}", short(&repo, "HEAD"))
    );
    assert_eq!(
        describe(&repo, &["HEAD~1"]),
        format!("v2-1-k{}", short(&repo, "HEAD~1"))
    );
}

#[test]
fn an_exact_match_prints_the_tag_alone_unless_long() {
    let repo = linear();
    assert_eq!(describe(&repo, &["HEAD~2"]), "v2");
    assert_eq!(
        describe(&repo, &["--long", "HEAD~2"]),
        format!("v2-0-k{}", short(&repo, "HEAD~2"))
    );
}

#[test]
fn abbrev_sets_the_id_length_and_zero_drops_the_suffix() {
    let repo = linear();
    let full = rev(&repo, "HEAD");
    assert_eq!(
        describe(&repo, &["--abbrev=12"]),
        format!("v2-2-k{}", &full[..12])
    );
    assert_eq!(describe(&repo, &["--abbrev=0"]), "v2");
}

#[test]
fn a_lightweight_tag_counts_only_with_tags() {
    let repo = linear();
    repo.ok(&["tag", "light", "HEAD~1"]);
    assert_eq!(
        describe(&repo, &[]),
        format!("v2-2-k{}", short(&repo, "HEAD"))
    );
    assert_eq!(
        describe(&repo, &["--tags"]),
        format!("light-1-k{}", short(&repo, "HEAD"))
    );
}

#[test]
fn match_and_exclude_filter_the_tags() {
    let repo = linear();
    let head = short(&repo, "HEAD");
    assert_eq!(
        describe(&repo, &["--match", "v1*"]),
        format!("v1-4-k{head}")
    );
    assert_eq!(
        describe(&repo, &["--exclude", "v2"]),
        format!("v1-4-k{head}")
    );
    assert_eq!(
        describe(&repo, &["--match", "v*", "--exclude", "v1"]),
        format!("v2-2-k{head}")
    );
}

#[test]
fn a_tag_that_does_not_reach_the_commit_is_not_chosen() {
    let repo = linear();
    // `v2` is newer and nearer by count, but not an ancestor of `HEAD~3`.
    assert_eq!(
        describe(&repo, &["HEAD~3"]),
        format!("v1-1-k{}", short(&repo, "HEAD~3"))
    );
}

#[test]
fn always_falls_back_to_the_short_id() {
    let repo = Repo::new();
    repo.commit_file("f.txt", b"1\n", "c1");
    let out = repo.run(&["describe"]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(stderr(&out).contains("no names found"), "{}", stderr(&out));
    assert_eq!(describe(&repo, &["--always"]), short(&repo, "HEAD"));
}

#[test]
fn dirty_marks_a_changed_worktree() {
    let repo = linear();
    let head = short(&repo, "HEAD");
    assert_eq!(describe(&repo, &["--dirty"]), format!("v2-2-k{head}"));
    // An untracked file does not make the tree dirty, as in git.
    repo.write("untracked.txt", b"x\n");
    assert_eq!(describe(&repo, &["--dirty"]), format!("v2-2-k{head}"));
    repo.write("f.txt", b"changed\n");
    assert_eq!(describe(&repo, &["--dirty"]), format!("v2-2-k{head}-dirty"));
    assert_eq!(
        describe(&repo, &["--dirty=+wip"]),
        format!("v2-2-k{head}+wip")
    );
    repo.ok(&["add", "f.txt"]);
    assert_eq!(describe(&repo, &["--dirty"]), format!("v2-2-k{head}-dirty"));
}

#[test]
fn usage_errors_exit_64() {
    let repo = linear();
    for args in [
        &["--dirty", "HEAD"][..],
        &["no-such-rev"],
        &["HEAD", "HEAD~1"],
        &["--abbrev=x"],
    ] {
        let mut all = vec!["describe"];
        all.extend_from_slice(args);
        let out = repo.run(&all);
        assert_eq!(out.status.code(), Some(64), "{args:?}: {}", stderr(&out));
    }
}

fn git_available() -> bool {
    Command::new("git")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

fn git(dir: &Path, home: &Path, args: &[&str]) -> Output {
    let out = Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("HOME", home)
        .env("GIT_CONFIG_GLOBAL", home.join("absent"))
        .env("GIT_CONFIG_SYSTEM", home.join("absent-system"))
        .env("GIT_AUTHOR_NAME", "parity")
        .env("GIT_AUTHOR_EMAIL", "parity@example.com")
        .env("GIT_COMMITTER_NAME", "parity")
        .env("GIT_COMMITTER_EMAIL", "parity@example.com")
        .output()
        .unwrap();
    assert!(out.status.success(), "git {args:?}: {}", stderr(&out));
    out
}

/// One step of a script that both tools run.
enum Step {
    Commit(&'static str, &'static str),
    Tag(&'static str),
    Branch(&'static str),
    Switch(&'static str),
    Merge(&'static str),
}

/// A linear part with two tags, then a side branch tagged at its second
/// commit and a main line tagged at its first, merged.
const SCRIPT: &[Step] = &[
    Step::Commit("a.txt", "1"),
    Step::Tag("v1"),
    Step::Commit("a.txt", "2"),
    Step::Commit("a.txt", "3"),
    Step::Tag("v2"),
    Step::Commit("a.txt", "4"),
    Step::Branch("side"),
    Step::Switch("side"),
    Step::Commit("s.txt", "1"),
    Step::Commit("s.txt", "2"),
    Step::Tag("side-v"),
    Step::Switch("main"),
    Step::Commit("m.txt", "1"),
    Step::Tag("main-v"),
    Step::Commit("m.txt", "2"),
    Step::Commit("m.txt", "3"),
    Step::Merge("side"),
];

/// The `<tag>-<n>` part of a long name, or the name of an exact match.
fn tag_and_count(name: &str) -> String {
    match name.trim_end().rsplit_once('-') {
        Some((head, id)) if id.len() > 1 && matches!(id.as_bytes()[0], b'g' | b'k') => {
            head.to_owned()
        }
        _ => name.trim_end().to_owned(),
    }
}

#[test]
fn tag_and_count_match_git_describe() {
    if !git_available() {
        return;
    }
    let home = tempfile::tempdir().unwrap();
    let g = tempfile::tempdir().unwrap();
    let gdir = g.path();
    git(gdir, home.path(), &["init", "-q", "-b", "main"]);
    let repo = Repo::new();
    let mut tagged = false;
    let mut n = 0;
    for step in SCRIPT {
        match *step {
            Step::Commit(rel, body) => {
                n += 1;
                let msg = format!("c{n}");
                repo.commit_file(rel, body.as_bytes(), &msg);
                std::fs::write(gdir.join(rel), body).unwrap();
                git(gdir, home.path(), &["add", rel]);
                git(gdir, home.path(), &["commit", "-q", "-m", &msg]);
            }
            Step::Tag(name) => {
                repo.ok(&["tag", "-a", name, "-m", name]);
                git(gdir, home.path(), &["tag", "-a", name, "-m", name]);
                tagged = true;
            }
            Step::Branch(name) => {
                repo.ok(&["branch", name]);
                git(gdir, home.path(), &["branch", name]);
            }
            Step::Switch(name) => {
                repo.ok(&["switch", name]);
                git(gdir, home.path(), &["switch", "-q", name]);
            }
            Step::Merge(name) => {
                repo.ok(&["merge", name, "-m", "merge"]);
                git(
                    gdir,
                    home.path(),
                    &["merge", "-q", "--no-ff", name, "-m", "merge"],
                );
            }
        }
        if !tagged {
            continue;
        }
        for args in [
            &["describe"][..],
            &["describe", "--long"],
            &["describe", "--match", "v*"],
        ] {
            let ours = tag_and_count(&stdout(&repo.ok(args)));
            let theirs = tag_and_count(&stdout(&git(gdir, home.path(), args)));
            assert_eq!(ours, theirs, "after commit {n}: {args:?}");
        }
    }
    assert!(tagged);
}
