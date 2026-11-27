//! `kit range-diff`: show how each commit of a series changed between two
//! versions of it, for review of a rewritten branch.
//!
//! Fixed cases pin the pairing, the `=`, `!`, `<` and `>` lines, the three
//! ways to name the ranges and the usage errors. A differential case
//! compares the pairing with real `git range-diff`.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

mod common;

use std::path::Path;
use std::process::{Command, Output, Stdio};

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

fn range_diff(repo: &Repo, args: &[&str]) -> String {
    let mut all = vec!["range-diff"];
    all.extend_from_slice(args);
    stdout(&repo.ok(&all))
}

/// The pair lines of the output with the ids dropped:
/// `<old n> <status> <new n> <subject>`.
fn pairs(text: &str) -> Vec<String> {
    text.lines()
        .filter(|l| !l.starts_with(' ') && !l.is_empty())
        .map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            format!("{} {} {} {}", f[0], f[2], f[3], f[5..].join(" "))
        })
        .collect()
}

/// A base, an old series `one`, `two`, `three` on it, and a new series on a
/// later base, where `two` changes one line of eight and the others keep
/// theirs. One line of eight is a small enough change that the commits
/// pair rather than show as a drop and an add.
/// Returns the repo and the id of the old base.
const B_OLD: &[u8] = b"b1\nb2\nb3\nb4\nb5\nb6\nb7\nb8\n";
const B_NEW: &[u8] = b"b1\nb2\nb3\nB4 changed\nb5\nb6\nb7\nb8\n";

fn rewritten() -> (Repo, String) {
    let repo = Repo::new();
    repo.commit_file("base.txt", b"base\n", "base");
    let base = rev(&repo, "HEAD");
    repo.ok(&["branch", "old"]);
    repo.ok(&["switch", "old"]);
    repo.commit_file("a.txt", b"a\n", "one");
    repo.commit_file("b.txt", B_OLD, "two");
    repo.commit_file("c.txt", b"c\n", "three");
    repo.ok(&["switch", "main"]);
    repo.commit_file("z.txt", b"z\n", "unrelated");
    repo.ok(&["branch", "new"]);
    repo.ok(&["switch", "new"]);
    repo.commit_file("a.txt", b"a\n", "one");
    repo.commit_file("b.txt", B_NEW, "two");
    repo.commit_file("c.txt", b"c\n", "three");
    (repo, base)
}

#[test]
fn an_identical_range_marks_every_commit_equal() {
    let (repo, base) = rewritten();
    let range = format!("{base}..old");
    assert_eq!(
        pairs(&range_diff(&repo, &[&range, &range])),
        ["1: = 1: one", "2: = 2: two", "3: = 3: three"]
    );
}

#[test]
fn a_changed_commit_shows_bang_and_its_interdiff() {
    let (repo, base) = rewritten();
    let out = range_diff(&repo, &[&format!("{base}..old"), "main..new"]);
    assert_eq!(pairs(&out), ["1: = 1: one", "2: ! 2: two", "3: = 3: three"]);
    // The header names both ids, abbreviated, and the interdiff follows the
    // changed pair, indented four spaces.
    let old2 = rev(&repo, "old~1");
    let new2 = rev(&repo, "new~1");
    assert!(
        out.contains(&format!("2:  {} ! 2:  {} two\n", &old2[..7], &new2[..7])),
        "{out}"
    );
    assert!(out.contains("    -+b4\n"), "{out}");
    assert!(out.contains("    ++B4 changed\n"), "{out}");
}

#[test]
fn dropped_and_added_commits_show_lt_and_gt() {
    let repo = Repo::new();
    repo.commit_file("base.txt", b"base\n", "base");
    let base = rev(&repo, "HEAD");
    repo.ok(&["branch", "old"]);
    repo.ok(&["branch", "new"]);
    repo.ok(&["switch", "old"]);
    repo.commit_file("a.txt", b"a\n", "one");
    repo.commit_file("d.txt", b"dropped line\nanother\n", "dropped");
    repo.ok(&["switch", "new"]);
    repo.commit_file("a.txt", b"a\n", "one");
    repo.commit_file("n.txt", b"something new\nand more\n", "added");
    let out = range_diff(&repo, &[&format!("{base}..old"), &format!("{base}..new")]);
    assert_eq!(
        pairs(&out),
        ["1: = 1: one", "2: < -: dropped", "-: > 2: added"]
    );
    assert!(out.contains("-:  ------- > 2:  "), "{out}");
}

#[test]
fn the_three_ways_to_name_the_ranges_agree() {
    let (repo, base) = rewritten();
    let two = range_diff(&repo, &[&format!("{base}..old"), &format!("{base}..new")]);
    let dots = range_diff(&repo, &["old...new"]);
    let three = range_diff(&repo, &[&base, "old", "new"]);
    assert_eq!(dots, two);
    assert_eq!(three, two);
}

#[test]
fn swapping_the_ranges_swaps_the_sides() {
    let repo = Repo::new();
    repo.commit_file("base.txt", b"base\n", "base");
    let base = rev(&repo, "HEAD");
    repo.ok(&["branch", "old"]);
    repo.ok(&["branch", "new"]);
    repo.ok(&["switch", "old"]);
    repo.commit_file("a.txt", b"a\n", "one");
    repo.commit_file("d.txt", b"dropped line\nanother\n", "dropped");
    repo.ok(&["switch", "new"]);
    repo.commit_file("a.txt", b"a\n", "one");
    let (a, b) = (format!("{base}..old"), format!("{base}..new"));
    assert_eq!(
        pairs(&range_diff(&repo, &[&a, &b])),
        ["1: = 1: one", "2: < -: dropped"]
    );
    assert_eq!(
        pairs(&range_diff(&repo, &[&b, &a])),
        ["1: = 1: one", "-: > 2: dropped"]
    );
}

#[test]
fn usage_errors_exit_64() {
    let (repo, base) = rewritten();
    let range = format!("{base}..old");
    for args in [
        &["range-diff"][..],
        &["range-diff", "old"],
        &["range-diff", &range, "new"],
        &["range-diff", "--creation-factor=x", &range, &range],
        &["range-diff", "a", "b", "c", "d"],
    ] {
        let out = repo.run(args);
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
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(out.status.success(), "git {args:?}: {}", stderr(&out));
    out
}

/// One step of a script that both tools run.
enum Step {
    Commit(&'static str, &'static str, &'static str),
    Branch(&'static str),
    Switch(&'static str),
}

/// An old series of five commits, and a new one that reorders two, drops
/// one, rewrites one and adds one.
const SCRIPT: &[Step] = &[
    Step::Commit("base.txt", "base\n", "base"),
    Step::Branch("old"),
    Step::Branch("new"),
    Step::Switch("old"),
    Step::Commit("a.txt", "1\n2\n3\n", "add a"),
    Step::Commit("b.txt", "x\ny\n", "add b"),
    Step::Commit("c.txt", "c1\nc2\nc3\nc4\n", "add c"),
    Step::Commit("a.txt", "1\n2\n3\n4\n", "grow a"),
    Step::Commit("d.txt", "only old\nhere\n", "add d"),
    Step::Switch("new"),
    Step::Commit("b.txt", "x\ny\n", "add b"),
    Step::Commit("a.txt", "1\n2\n3\n", "add a"),
    Step::Commit("c.txt", "c1\nc2\nC3\nc4\n", "add c"),
    Step::Commit("a.txt", "1\n2\n3\n4\n", "grow a"),
    Step::Commit("e.txt", "brand new\nfile\nhere\n", "add e"),
];

#[test]
fn pairing_matches_git_range_diff() {
    if !git_available() {
        return;
    }
    let home = tempfile::tempdir().unwrap();
    let g = tempfile::tempdir().unwrap();
    let gdir = g.path();
    git(gdir, home.path(), &["init", "-q", "-b", "main"]);
    let repo = Repo::new();
    for step in SCRIPT {
        match *step {
            Step::Commit(rel, body, msg) => {
                repo.commit_file(rel, body.as_bytes(), msg);
                std::fs::write(gdir.join(rel), body).unwrap();
                git(gdir, home.path(), &["add", rel]);
                git(gdir, home.path(), &["commit", "-q", "-m", msg]);
            }
            Step::Branch(name) => {
                repo.ok(&["branch", name]);
                git(gdir, home.path(), &["branch", name]);
            }
            Step::Switch(name) => {
                repo.ok(&["switch", name]);
                git(gdir, home.path(), &["switch", "-q", name]);
            }
        }
    }
    for args in [
        &["range-diff", "main..old", "main..new"][..],
        &["range-diff", "main..new", "main..old"],
        &[
            "range-diff",
            "--creation-factor=100",
            "main..old",
            "main..new",
        ],
        &["range-diff", "main..old", "main..old"],
    ] {
        let ours = pairs(&stdout(&repo.ok(args)));
        let theirs = pairs(&stdout(&git(
            gdir,
            home.path(),
            &[&args[..1], &["--no-color"], &args[1..]].concat(),
        )));
        assert_eq!(ours, theirs, "{args:?}");
    }
}
