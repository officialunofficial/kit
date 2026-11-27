//! `kit log [<rev>] [--] <path>...` and `kit log --follow <file>`: limit the
//! history to the commits that change the paths.
//!
//! The fixed cases pin the CLI surface and git's default history
//! simplification at merges. A differential case checks the subjects
//! against real `git` when it is on `PATH`. A property test drives random
//! linear histories through the binary and checks the output against a
//! model of which paths each commit changed.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

mod common;

use std::collections::BTreeMap;
use std::path::Path;
use std::process::{Command, Output};

use common::Repo;
use proptest::prelude::*;

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// The `--oneline` titles, newest first.
fn subjects(repo: &Repo, extra: &[&str]) -> Vec<String> {
    let mut args = vec!["log", "--oneline"];
    args.extend_from_slice(extra);
    titles(&stdout(&repo.ok(&args)))
}

fn titles(text: &str) -> Vec<String> {
    text.lines()
        .map(|l| l.split_once(' ').map_or("", |(_, t)| t).to_owned())
        .collect()
}

fn remove(repo: &Repo, rel: &str, msg: &str) {
    repo.ok(&["rm", rel]);
    repo.ok(&["commit", "-m", msg]);
}

/// `a.txt` and `dir/x.txt` change in turns, then `a.txt` is deleted and
/// added again.
fn linear() -> Repo {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"1\n", "add a");
    repo.commit_file("dir/x.txt", b"1\n", "add x");
    repo.commit_file("a.txt", b"2\n", "edit a");
    repo.commit_file("dir/y.txt", b"1\n", "add y");
    remove(&repo, "a.txt", "remove a");
    repo.commit_file("a.txt", b"3\n", "re-add a");
    repo
}

#[test]
fn a_file_path_keeps_the_commits_that_change_it() {
    let repo = linear();
    assert_eq!(
        subjects(&repo, &["--", "a.txt"]),
        ["re-add a", "remove a", "edit a", "add a"]
    );
}

#[test]
fn a_directory_path_keeps_the_commits_below_it() {
    let repo = linear();
    assert_eq!(subjects(&repo, &["--", "dir"]), ["add y", "add x"]);
    assert_eq!(subjects(&repo, &["--", "dir/"]), ["add y", "add x"]);
}

#[test]
fn several_paths_keep_the_union_in_walk_order() {
    let repo = linear();
    assert_eq!(
        subjects(&repo, &["--", "dir/y.txt", "a.txt"]),
        ["re-add a", "remove a", "add y", "edit a", "add a"]
    );
}

#[test]
fn a_path_without_a_separator_works_when_it_exists() {
    let repo = linear();
    assert_eq!(subjects(&repo, &["dir"]), ["add y", "add x"]);
    assert_eq!(subjects(&repo, &["HEAD~2", "dir"]), ["add y", "add x"]);
}

#[test]
fn a_path_is_relative_to_the_current_directory() {
    let repo = linear();
    let out = common::kit(
        &repo.path().join("dir"),
        repo.xdg(),
        &["log", "--oneline", "--", "x.txt"],
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(titles(&stdout(&out)), ["add x"]);
}

#[test]
fn a_dot_at_the_top_names_the_whole_tree() {
    let repo = linear();
    repo.ok(&["commit", "--allow-empty", "-m", "empty"]);
    let all = subjects(&repo, &[]);
    let dot = subjects(&repo, &["--", "."]);
    assert_eq!(dot.first().map(String::as_str), Some("re-add a"));
    assert_eq!(dot.len() + 1, all.len(), "only the empty commit drops out");
}

#[test]
fn a_path_that_never_existed_prints_nothing_after_a_separator() {
    let repo = linear();
    let out = repo.ok(&["log", "--oneline", "--", "nope.txt"]);
    assert!(stdout(&out).is_empty());
}

#[test]
fn a_missing_path_without_a_separator_is_an_error() {
    let repo = linear();
    let out = repo.run(&["log", "--oneline", "HEAD", "nope.txt"]);
    assert!(!out.status.success());
    assert!(stdout(&out).is_empty());
}

#[test]
fn an_argument_that_is_a_revision_and_a_file_is_ambiguous() {
    let repo = linear();
    repo.commit_file("main", b"file named like the branch\n", "add main file");
    let out = repo.run(&["log", "--oneline", "main"]);
    assert_eq!(
        out.status.code(),
        Some(64),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("ambiguous"));
    // `--` settles it either way.
    assert_eq!(subjects(&repo, &["--", "main"]), ["add main file"]);
    assert_eq!(subjects(&repo, &["main", "--"]).len(), 7);
}

#[test]
fn a_glob_is_a_usage_error() {
    let repo = linear();
    for spec in ["*.txt", "dir/?.txt", "[a].txt", ":(top)a.txt"] {
        let out = repo.run(&["log", "--", spec]);
        assert_eq!(out.status.code(), Some(64), "{spec}");
    }
}

#[test]
fn a_path_combines_with_the_other_options() {
    let repo = linear();
    assert_eq!(
        subjects(&repo, &["-n", "2", "--", "a.txt"]),
        ["re-add a", "remove a"]
    );
    assert_eq!(
        subjects(&repo, &["--grep", "edit", "--", "a.txt"]),
        ["edit a"]
    );
    assert_eq!(
        subjects(&repo, &["HEAD~3..", "--", "a.txt"]),
        ["re-add a", "remove a"]
    );
    let json = stdout(&repo.ok(&["log", "--format=json", "--", "dir"]));
    assert_eq!(json.lines().count(), 2);
    assert!(json.lines().all(|l| l.starts_with("{\"hash\":")));
}

#[test]
fn a_patch_shows_only_the_files_at_the_paths() {
    let repo = Repo::new();
    repo.write("a.txt", b"1\n");
    repo.write("b.txt", b"1\n");
    repo.ok(&["add", "a.txt", "b.txt"]);
    repo.ok(&["commit", "-m", "both"]);
    let patch = stdout(&repo.ok(&["log", "-p", "--", "a.txt"]));
    assert!(patch.contains("a.txt"));
    assert!(!patch.contains("b.txt"), "{patch}");
    let stat = stdout(&repo.ok(&["log", "--stat", "--", "b.txt"]));
    assert!(stat.contains("b.txt"));
    assert!(!stat.contains("a.txt"), "{stat}");
}

/// `main` edits `a.txt`, `feature` edits `b.txt`, then `main` merges
/// `feature` with no conflict.
fn merged() -> Repo {
    let repo = Repo::new();
    repo.write("a.txt", b"base\n");
    repo.write("b.txt", b"base\n");
    repo.ok(&["add", "a.txt", "b.txt"]);
    repo.ok(&["commit", "-m", "base"]);
    repo.ok(&["branch", "feature"]);
    repo.ok(&["checkout", "feature"]);
    repo.commit_file("b.txt", b"feature\n", "feature edits b");
    repo.ok(&["checkout", "main"]);
    repo.commit_file("a.txt", b"main\n", "main edits a");
    repo.ok(&["merge", "-m", "merge feature", "feature"]);
    repo
}

#[test]
fn a_merge_that_matches_a_parent_is_hidden_and_followed_through_it() {
    let repo = merged();
    assert_eq!(subjects(&repo, &["--", "a.txt"]), ["main edits a", "base"]);
    assert_eq!(
        subjects(&repo, &["--", "b.txt"]),
        ["feature edits b", "base"]
    );
    assert_eq!(
        subjects(&repo, &["--first-parent", "--", "b.txt"]),
        ["merge feature", "base"]
    );
}

#[test]
fn a_merge_that_matches_no_parent_shows() {
    let repo = merged();
    assert_eq!(
        subjects(&repo, &["--", "a.txt", "b.txt"]),
        ["merge feature", "main edits a", "feature edits b", "base"]
    );
}

#[test]
fn follow_continues_under_the_old_name_of_a_renamed_file() {
    let repo = Repo::new();
    repo.commit_file("old.txt", b"one\ntwo\n", "add old");
    repo.commit_file("old.txt", b"one\ntwo\nthree\n", "edit old");
    repo.commit_file("other.txt", b"x\n", "unrelated");
    repo.ok(&["mv", "old.txt", "new.txt"]);
    repo.ok(&["commit", "-m", "rename"]);
    repo.commit_file("new.txt", b"one\ntwo\nthree\nfour\n", "edit new");
    assert_eq!(subjects(&repo, &["--", "new.txt"]), ["edit new", "rename"]);
    assert_eq!(
        subjects(&repo, &["--follow", "--", "new.txt"]),
        ["edit new", "rename", "edit old", "add old"]
    );
    let patch = stdout(&repo.ok(&["log", "-p", "--follow", "--", "new.txt"]));
    assert!(
        patch.contains("old.txt"),
        "the older commits show the old name"
    );
    assert!(!patch.contains("other.txt"), "{patch}");
}

#[test]
fn follow_needs_exactly_one_path() {
    let repo = linear();
    for args in [
        vec!["log", "--follow"],
        vec!["log", "--follow", "--", "a.txt", "dir"],
    ] {
        let out = repo.run(&args);
        assert_eq!(out.status.code(), Some(64), "{args:?}");
    }
}

// ---------------------------------------------------------------------------
// Differential check against git.
// ---------------------------------------------------------------------------

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
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

/// One step of a script that both tools run.
enum Step {
    Write(&'static str, &'static str),
    Remove(&'static str),
    Commit(&'static str),
    Branch(&'static str),
    Checkout(&'static str),
    Merge(&'static str, &'static str),
}

const SCRIPT: &[Step] = &[
    Step::Write("a.txt", "1\n"),
    Step::Write("d/x.txt", "1\n"),
    Step::Commit("base"),
    Step::Branch("topic"),
    Step::Checkout("topic"),
    Step::Write("d/x.txt", "topic\n"),
    Step::Commit("topic edits x"),
    Step::Write("b.txt", "topic\n"),
    Step::Commit("topic adds b"),
    Step::Checkout("main"),
    Step::Write("a.txt", "2\n"),
    Step::Commit("main edits a"),
    Step::Merge("topic", "merge topic"),
    Step::Remove("a.txt"),
    Step::Commit("main removes a"),
    Step::Write("d/y.txt", "1\n"),
    Step::Commit("main adds y"),
];

#[test]
fn path_limited_subjects_match_git() {
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
            Step::Write(rel, body) => {
                repo.write(rel, body.as_bytes());
                std::fs::create_dir_all(gdir.join(rel).parent().unwrap()).unwrap();
                std::fs::write(gdir.join(rel), body).unwrap();
                repo.ok(&["add", rel]);
                git(gdir, home.path(), &["add", rel]);
            }
            Step::Remove(rel) => {
                repo.ok(&["rm", rel]);
                git(gdir, home.path(), &["rm", "-q", rel]);
            }
            Step::Commit(msg) => {
                repo.ok(&["commit", "-m", msg]);
                git(gdir, home.path(), &["commit", "-q", "-m", msg]);
            }
            Step::Branch(name) => {
                repo.ok(&["branch", name]);
                git(gdir, home.path(), &["branch", name]);
            }
            Step::Checkout(name) => {
                repo.ok(&["checkout", name]);
                git(gdir, home.path(), &["checkout", "-q", name]);
            }
            Step::Merge(name, msg) => {
                repo.ok(&["merge", "-m", msg, name]);
                git(
                    gdir,
                    home.path(),
                    &["merge", "-q", "--no-ff", "-m", msg, name],
                );
            }
        }
    }
    for paths in [
        &["a.txt"][..],
        &["b.txt"],
        &["d"],
        &["d/x.txt"],
        &["d/y.txt"],
        &["a.txt", "b.txt"],
        &["a.txt", "d"],
        &["."],
    ] {
        let mut kit_args = vec!["--"];
        kit_args.extend_from_slice(paths);
        let mut git_args = vec!["log", "--format=%s", "--"];
        git_args.extend_from_slice(paths);
        let expected: Vec<String> = stdout(&git(gdir, home.path(), &git_args))
            .lines()
            .map(str::to_owned)
            .collect();
        assert_eq!(subjects(&repo, &kit_args), expected, "paths {paths:?}");
        let mut first = vec!["--first-parent", "--"];
        first.extend_from_slice(paths);
        let mut git_first = vec!["log", "--first-parent", "--format=%s", "--"];
        git_first.extend_from_slice(paths);
        let expected: Vec<String> = stdout(&git(gdir, home.path(), &git_first))
            .lines()
            .map(str::to_owned)
            .collect();
        assert_eq!(
            subjects(&repo, &first),
            expected,
            "--first-parent {paths:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Property: random linear histories against a model.
// ---------------------------------------------------------------------------

const FILES: [&str; 4] = ["a", "b", "d/x", "d/y"];
const SPECS: [&str; 6] = ["a", "b", "d", "d/x", "d/y", "."];

/// One commit of a generated history: for each file, keep, write or delete.
#[derive(Debug, Clone, Copy)]
enum Edit {
    Keep,
    Write,
    Delete,
}

fn edit() -> impl Strategy<Value = Edit> {
    prop_oneof![Just(Edit::Keep), Just(Edit::Write), Just(Edit::Delete)]
}

fn covers(spec: &str, file: &str) -> bool {
    spec == "." || file == spec || file.starts_with(&format!("{spec}/"))
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: std::env::var("PROPTEST_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(12),
        ..ProptestConfig::default()
    })]

    /// Soundness and completeness on linear history: `log -- P` lists
    /// exactly the commits that change a file under P, newest first. Two
    /// paths give the union, and every result is a subsequence of `log`.
    #[test]
    fn path_limited_log_matches_the_model(
        history in prop::collection::vec(prop::array::uniform4(edit()), 1..6),
        pick in (0..SPECS.len(), 0..SPECS.len()),
    ) {
        let repo = Repo::new();
        let mut present: BTreeMap<&str, bool> = FILES.iter().map(|f| (*f, false)).collect();
        // For each commit, newest last: its title and the files it changed.
        let mut changed: Vec<(String, Vec<&str>)> = Vec::new();
        for (n, edits) in history.iter().enumerate() {
            let title = format!("c{n}");
            let mut touched = Vec::new();
            for (file, edit) in FILES.iter().zip(edits) {
                match edit {
                    Edit::Keep => {}
                    Edit::Write => {
                        repo.write(file, format!("{title}\n").as_bytes());
                        repo.ok(&["add", file]);
                        present.insert(file, true);
                        touched.push(*file);
                    }
                    Edit::Delete if present[file] => {
                        repo.ok(&["rm", file]);
                        present.insert(file, false);
                        touched.push(*file);
                    }
                    Edit::Delete => {}
                }
            }
            repo.ok(&["commit", "--allow-empty", "-m", &title]);
            changed.push((title, touched));
        }
        let all = subjects(&repo, &[]);
        let expect = |specs: &[&str]| -> Vec<String> {
            changed
                .iter()
                .rev()
                .filter(|(_, files)| files.iter().any(|f| specs.iter().any(|s| covers(s, f))))
                .map(|(t, _)| t.clone())
                .collect()
        };
        let (p, q) = (SPECS[pick.0], SPECS[pick.1]);
        let one = subjects(&repo, &["--", p]);
        prop_assert_eq!(&one, &expect(&[p]));
        let both = subjects(&repo, &["--", p, q]);
        prop_assert_eq!(&both, &expect(&[p, q]));
        // Subset: each result keeps the order of the full log.
        let mut rest = all.iter();
        for title in &both {
            prop_assert!(rest.any(|t| t == title), "{} out of order", title);
        }
    }
}
