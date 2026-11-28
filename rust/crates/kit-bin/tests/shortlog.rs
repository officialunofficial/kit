//! `kit shortlog`: group commits by author, for release notes and
//! contributor counts.
//!
//! Fixed cases pin the groups, the sort orders, `-s`, `-e`, JSON, path
//! limiting and reading `kit log` output from standard input. A
//! differential case compares the groups with real `git shortlog`, and a
//! property test checks that the groups partition the commits that
//! `rev-list` counts.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

mod common;

use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use common::Repo;
use proptest::prelude::*;

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn shortlog(repo: &Repo, args: &[&str]) -> String {
    let mut all = vec!["shortlog"];
    all.extend_from_slice(args);
    stdout(&repo.ok(&all))
}

/// Commit a change to `rel` as `author`.
fn commit_as(repo: &Repo, author: &str, rel: &str, body: &str, msg: &str) {
    repo.write(rel, body.as_bytes());
    repo.ok(&["add", rel]);
    repo.ok(&["commit", "-m", msg, "--author", &format!("opaque:{author}")]);
}

/// Alice makes three commits, Bob two, interleaved; `b.txt` changes only in
/// Bob's second commit.
fn two_authors() -> Repo {
    let repo = Repo::new();
    commit_as(&repo, "Alice <a@example.com>", "a.txt", "1\n", "a one");
    commit_as(&repo, "Bob <b@example.com>", "a.txt", "2\n", "b one");
    commit_as(&repo, "Alice <a@example.com>", "a.txt", "3\n", "a two");
    commit_as(&repo, "Bob <b@example.com>", "b.txt", "x\n", "b two");
    commit_as(&repo, "Alice <a@example.com>", "a.txt", "4\n", "a three");
    repo
}

#[test]
fn groups_list_each_authors_subjects_oldest_first() {
    let repo = two_authors();
    assert_eq!(
        shortlog(&repo, &["HEAD"]),
        "Alice (3):\n      a one\n      a two\n      a three\n\n\
         Bob (2):\n      b one\n      b two\n\n"
    );
}

#[test]
fn summary_and_numbered_sort_by_count_then_name() {
    let repo = two_authors();
    commit_as(&repo, "Carol <c@example.com>", "c.txt", "1\n", "c one");
    commit_as(&repo, "Carol <c@example.com>", "c.txt", "2\n", "c two");
    assert_eq!(
        shortlog(&repo, &["-s", "HEAD"]),
        "     3\tAlice\n     2\tBob\n     2\tCarol\n"
    );
    commit_as(&repo, "Carol <c@example.com>", "c.txt", "3\n", "c three");
    commit_as(&repo, "Carol <c@example.com>", "c.txt", "4\n", "c four");
    assert_eq!(
        shortlog(&repo, &["-sn", "HEAD"]),
        "     4\tCarol\n     3\tAlice\n     2\tBob\n"
    );
}

#[test]
fn email_shows_the_whole_identity() {
    let repo = two_authors();
    assert_eq!(
        shortlog(&repo, &["-se", "HEAD"]),
        "     3\tAlice <a@example.com>\n     2\tBob <b@example.com>\n"
    );
}

#[test]
fn a_key_author_shows_its_key_id_with_email() {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"1\n", "signed");
    let out = shortlog(&repo, &["-se", "HEAD"]);
    let line = out.trim_end();
    let (count, name) = line.split_once('\t').unwrap();
    assert_eq!(count.trim(), "1");
    assert!(name.contains(" <ed25519:"), "{out}");
}

#[test]
fn a_range_and_paths_limit_the_commits() {
    let repo = two_authors();
    assert_eq!(
        shortlog(&repo, &["-s", "HEAD~2..HEAD"]),
        "     1\tAlice\n     1\tBob\n"
    );
    assert_eq!(
        shortlog(&repo, &["-s", "HEAD", "--", "b.txt"]),
        "     1\tBob\n"
    );
    assert_eq!(
        shortlog(&repo, &["HEAD", "--", "b.txt"]),
        "Bob (1):\n      b two\n\n"
    );
}

#[test]
fn json_prints_one_object_per_group() {
    let repo = two_authors();
    let out = shortlog(&repo, &["-n", "--format=json", "HEAD"]);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 2, "{out}");
    assert!(lines[0].starts_with("{\"author\":\"Alice\""), "{out}");
    assert!(lines[0].contains("\"count\":3"), "{out}");
    assert!(
        lines[0].contains("\"subjects\":[\"a one\",\"a two\",\"a three\"]"),
        "{out}"
    );
    assert!(lines[1].contains("\"author\":\"Bob\""), "{out}");
}

#[test]
fn log_output_on_standard_input_is_read() {
    let repo = two_authors();
    let log = stdout(&repo.ok(&["log"]));
    let mut child = Command::new(env!("CARGO_BIN_EXE_kit"))
        .args(["shortlog", "-s"])
        .current_dir(repo.path())
        .env("XDG_CONFIG_HOME", repo.xdg())
        .env("HOME", repo.xdg())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(log.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "     3\tAlice\n     2\tBob\n");
}

#[test]
fn bad_arguments_exit_as_kit_log_does() {
    let repo = two_authors();
    // A bad format and an unknown revision exit as they do for `kit log`.
    for args in [&["--format=xml", "HEAD"][..], &["no-such-rev"]] {
        let ours = repo.run(&[&["shortlog"][..], args].concat());
        let log = repo.run(&[&["log"][..], args].concat());
        assert!(!ours.status.success(), "{args:?}");
        assert_eq!(
            ours.status.code(),
            log.status.code(),
            "{args:?}: {}",
            stderr(&ours)
        );
    }
}

fn git_available() -> bool {
    Command::new("git")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

fn git(dir: &Path, home: &Path, args: &[&str], name: &str) -> Output {
    let out = Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("HOME", home)
        .env("GIT_CONFIG_GLOBAL", home.join("absent"))
        .env("GIT_CONFIG_SYSTEM", home.join("absent-system"))
        .env("GIT_AUTHOR_NAME", name)
        .env(
            "GIT_AUTHOR_EMAIL",
            format!("{}@example.com", name.to_lowercase()),
        )
        .env("GIT_COMMITTER_NAME", "parity")
        .env("GIT_COMMITTER_EMAIL", "parity@example.com")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(out.status.success(), "git {args:?}: {}", stderr(&out));
    out
}

#[test]
fn groups_match_git_shortlog() {
    if !git_available() {
        return;
    }
    let home = tempfile::tempdir().unwrap();
    let g = tempfile::tempdir().unwrap();
    let gdir = g.path();
    git(gdir, home.path(), &["init", "-q", "-b", "main"], "x");
    let repo = Repo::new();
    // Counts 4, 2 and 1, so no tie depends on the sort git's libc uses.
    let script = [
        ("Ann", "a.txt"),
        ("Ben", "b.txt"),
        ("Ann", "a.txt"),
        ("Cid", "a.txt"),
        ("Ann", "b.txt"),
        ("Ben", "a.txt"),
        ("Ann", "a.txt"),
    ];
    for (i, (name, rel)) in script.iter().enumerate() {
        let body = format!("{i}\n");
        let msg = format!("change {i}");
        commit_as(
            &repo,
            &format!("{name} <{}@example.com>", name.to_lowercase()),
            rel,
            &body,
            &msg,
        );
        std::fs::write(gdir.join(rel), &body).unwrap();
        git(gdir, home.path(), &["add", rel], name);
        git(gdir, home.path(), &["commit", "-q", "-m", &msg], name);
    }
    for args in [
        &["shortlog", "HEAD"][..],
        &["shortlog", "-s", "HEAD"],
        &["shortlog", "-sn", "HEAD"],
        &["shortlog", "-se", "HEAD"],
        &["shortlog", "HEAD~3..HEAD"],
        &["shortlog", "-sn", "HEAD", "--", "b.txt"],
    ] {
        let ours = stdout(&repo.ok(args));
        let theirs = stdout(&git(gdir, home.path(), args, "x"));
        assert_eq!(ours, theirs, "{args:?}");
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 8, ..ProptestConfig::default() })]

    /// The counts add up to the `rev-list` count, and every commit is in
    /// exactly one group.
    #[test]
    fn groups_partition_the_commits(authors in proptest::collection::vec(0usize..3, 1..8)) {
        let names = ["Ann <a@x>", "Ben <b@x>", "Cid <c@x>"];
        let repo = Repo::new();
        for (i, a) in authors.iter().enumerate() {
            commit_as(&repo, names[*a], "f.txt", &format!("{i}\n"), &format!("s{i}"));
        }
        let total = stdout(&repo.ok(&["rev-list", "--count", "HEAD"]));
        let out = shortlog(&repo, &["HEAD"]);
        let mut subjects: Vec<String> = out
            .lines()
            .filter_map(|l| l.strip_prefix("      ").map(str::to_owned))
            .collect();
        let counts: usize = out
            .lines()
            .filter_map(|l| l.rsplit_once(" (").and_then(|(_, n)| n.strip_suffix("):")))
            .map(|n| n.parse::<usize>().unwrap())
            .sum();
        prop_assert_eq!(counts, total.trim().parse::<usize>().unwrap());
        subjects.sort();
        let mut want: Vec<String> = (0..authors.len()).map(|i| format!("s{i}")).collect();
        want.sort();
        prop_assert_eq!(subjects, want);
    }
}
