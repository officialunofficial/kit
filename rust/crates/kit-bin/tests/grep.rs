//! `kit grep`: search the tracked files of the worktree, the index
//! (`--cached`) or a revision for lines that match a pattern.
//!
//! Fixed cases pin the sources, the output shapes and the exit codes. A
//! differential case checks the output against real `git grep` when it is
//! on `PATH`. A property test checks `-F` against a naive line scan, and
//! that the exit code is 0 exactly when something is printed.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

mod common;

use std::path::Path;
use std::process::{Command, Output};

use common::Repo;
use proptest::prelude::*;

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// Run `kit grep` and return the exit code and standard output.
fn grep(repo: &Repo, args: &[&str]) -> (Option<i32>, String) {
    let mut all = vec!["grep"];
    all.extend_from_slice(args);
    let out = repo.run(&all);
    (out.status.code(), stdout(&out))
}

/// `a.txt`, `dir/b.txt` and `dir/sub/c.txt` are committed.
fn fixture() -> Repo {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"alpha\nFoo bar\nfoobar\nbaz\n", "a");
    repo.commit_file("dir/b.txt", b"foo\nqux foo quux\n", "b");
    repo.commit_file("dir/sub/c.txt", b"nothing here\n", "c");
    repo
}

#[test]
fn the_worktree_search_prints_path_and_line() {
    let repo = fixture();
    let (code, out) = grep(&repo, &["foo"]);
    assert_eq!(code, Some(0));
    assert_eq!(out, "a.txt:foobar\ndir/b.txt:foo\ndir/b.txt:qux foo quux\n");
}

#[test]
fn line_numbers_follow_the_path() {
    let repo = fixture();
    let (_, out) = grep(&repo, &["-n", "foo"]);
    assert_eq!(
        out,
        "a.txt:3:foobar\ndir/b.txt:1:foo\ndir/b.txt:2:qux foo quux\n"
    );
}

#[test]
fn no_match_exits_one_with_no_output() {
    let repo = fixture();
    assert_eq!(grep(&repo, &["absent"]), (Some(1), String::new()));
}

#[test]
fn quiet_prints_nothing_and_keeps_the_exit_code() {
    let repo = fixture();
    assert_eq!(grep(&repo, &["-q", "foo"]), (Some(0), String::new()));
    assert_eq!(grep(&repo, &["-q", "absent"]), (Some(1), String::new()));
}

#[test]
fn ignore_case_word_invert_files_and_count() {
    let repo = fixture();
    assert_eq!(grep(&repo, &["-i", "^foo "]).1, "a.txt:Foo bar\n");
    assert_eq!(
        grep(&repo, &["-w", "foo"]).1,
        "dir/b.txt:foo\ndir/b.txt:qux foo quux\n"
    );
    assert_eq!(
        grep(&repo, &["-v", "a"]).1,
        "dir/b.txt:foo\ndir/sub/c.txt:nothing here\n"
    );
    assert_eq!(grep(&repo, &["-l", "foo"]).1, "a.txt\ndir/b.txt\n");
    assert_eq!(grep(&repo, &["-c", "foo"]).1, "a.txt:1\ndir/b.txt:2\n");
}

#[test]
fn fixed_strings_and_several_patterns() {
    let repo = Repo::new();
    repo.commit_file("r.txt", b"a.c\nabc\n(x)\n", "r");
    assert_eq!(grep(&repo, &["a.c"]).1, "r.txt:a.c\nr.txt:abc\n");
    assert_eq!(grep(&repo, &["-F", "a.c"]).1, "r.txt:a.c\n");
    assert_eq!(grep(&repo, &["-F", "(x)"]).1, "r.txt:(x)\n");
    assert_eq!(
        grep(&repo, &["-e", "abc", "-e", "x"]).1,
        "r.txt:abc\nr.txt:(x)\n"
    );
    // `-G` is accepted and reads the pattern as `-E` does.
    assert_eq!(grep(&repo, &["-G", "a.c"]).1, "r.txt:a.c\nr.txt:abc\n");
}

#[test]
fn paths_limit_the_search() {
    let repo = fixture();
    assert_eq!(
        grep(&repo, &["foo", "--", "dir"]).1,
        "dir/b.txt:foo\ndir/b.txt:qux foo quux\n"
    );
    assert_eq!(grep(&repo, &["foo", "a.txt"]).1, "a.txt:foobar\n");
    assert_eq!(
        grep(&repo, &["here", "--", "dir/sub/"]).1,
        "dir/sub/c.txt:nothing here\n"
    );
}

#[test]
fn an_untracked_file_is_never_searched() {
    let repo = fixture();
    repo.write("untracked.txt", b"foo\n");
    let (_, out) = grep(&repo, &["-l", "foo"]);
    assert_eq!(out, "a.txt\ndir/b.txt\n");
}

#[test]
fn the_worktree_search_reads_unstaged_edits() {
    let repo = fixture();
    repo.write("dir/sub/c.txt", b"foo now\n");
    assert_eq!(
        grep(&repo, &["-l", "foo"]).1,
        "a.txt\ndir/b.txt\ndir/sub/c.txt\n"
    );
}

#[test]
fn cached_sees_a_staged_edit_the_worktree_reverted() {
    let repo = fixture();
    repo.write("dir/sub/c.txt", b"staged needle\n");
    repo.ok(&["add", "dir/sub/c.txt"]);
    repo.write("dir/sub/c.txt", b"nothing here\n");
    assert_eq!(grep(&repo, &["needle"]), (Some(1), String::new()));
    assert_eq!(
        grep(&repo, &["--cached", "needle"]).1,
        "dir/sub/c.txt:staged needle\n"
    );
}

#[test]
fn a_revision_is_searched_with_its_name_as_prefix() {
    let repo = fixture();
    repo.commit_file("a.txt", b"changed\n", "change a");
    assert_eq!(grep(&repo, &["foobar"]), (Some(1), String::new()));
    assert_eq!(
        grep(&repo, &["-n", "foobar", "HEAD~1"]).1,
        "HEAD~1:a.txt:3:foobar\n"
    );
    assert_eq!(
        grep(&repo, &["-l", "foo", "HEAD~1", "HEAD"]).1,
        "HEAD~1:a.txt\nHEAD~1:dir/b.txt\nHEAD:dir/b.txt\n"
    );
    assert_eq!(
        grep(&repo, &["-c", "foo", "HEAD", "--", "dir"]).1,
        "HEAD:dir/b.txt:2\n"
    );
}

#[test]
fn a_revision_search_reads_neither_the_worktree_nor_the_index() {
    let repo = fixture();
    // Staged and unstaged edits, and an unreadable index entry would all
    // change the answer if the search looked at them.
    repo.write("a.txt", b"needle\n");
    repo.ok(&["add", "a.txt"]);
    repo.write("dir/b.txt", b"needle\n");
    assert_eq!(grep(&repo, &["needle", "HEAD"]), (Some(1), String::new()));
    std::fs::remove_file(repo.kit_dir().join("index")).unwrap();
    assert_eq!(
        grep(&repo, &["-c", "foo", "HEAD"]).1,
        "HEAD:a.txt:1\nHEAD:dir/b.txt:2\n"
    );
}

#[test]
fn a_binary_file_reports_that_it_matches() {
    let repo = Repo::new();
    repo.commit_file("b.bin", b"head\0needle\n", "bin");
    repo.commit_file("t.txt", b"needle\n", "text");
    let (code, out) = grep(&repo, &["needle"]);
    assert_eq!(code, Some(0));
    assert_eq!(out, "Binary file b.bin matches\nt.txt:needle\n");
    assert_eq!(grep(&repo, &["-l", "needle"]).1, "b.bin\nt.txt\n");
}

/// A file above the chunking threshold, every line of which matches. A
/// search that split lines at chunk boundaries would miscount.
#[test]
fn a_chunked_file_matches_across_chunk_boundaries() {
    let repo = Repo::new();
    let mut body = Vec::new();
    let mut lines = 0usize;
    while body.len() < 3 << 20 {
        body.extend_from_slice(
            format!("needle {lines:08} {}\n", "x".repeat(lines % 97)).as_bytes(),
        );
        lines += 1;
    }
    repo.commit_file("big.txt", &body, "big");
    let count = format!("big.txt:{lines}\n");
    assert_eq!(grep(&repo, &["-c", "^needle [0-9]{8} x*$"]).1, count);
    assert_eq!(
        grep(&repo, &["-c", "--cached", "^needle [0-9]{8} x*$"]).1,
        count
    );
    assert_eq!(
        grep(&repo, &["-c", "^needle [0-9]{8} x*$", "HEAD"]).1,
        format!("HEAD:{count}")
    );
}

#[test]
fn usage_errors_exit_64() {
    let repo = fixture();
    for args in [
        &[][..],
        &["--cached", "foo", "HEAD"],
        &["("],
        &["-F", "-E", "x"],
        &["foo", "no-such-path-or-rev"],
    ] {
        let mut all = vec!["grep"];
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
    Command::new("git")
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
        .unwrap()
}

const FILES: &[(&str, &str)] = &[
    ("a.txt", "alpha\nFoo bar\nfoobar\nbaz\n"),
    ("dir/b.txt", "foo\nqux foo quux\nFOO\n"),
    ("dir/sub/c.txt", "nothing here\nfood\n"),
    ("z.txt", "foo-bar foo_bar\n"),
];

#[test]
fn output_matches_git_grep() {
    if !git_available() {
        return;
    }
    let home = tempfile::tempdir().unwrap();
    let g = tempfile::tempdir().unwrap();
    let gdir = g.path();
    git(gdir, home.path(), &["init", "-q", "-b", "main"]);
    let repo = Repo::new();
    for (rel, body) in FILES {
        repo.write(rel, body.as_bytes());
        std::fs::create_dir_all(gdir.join(rel).parent().unwrap()).unwrap();
        std::fs::write(gdir.join(rel), body).unwrap();
        repo.ok(&["add", rel]);
        git(gdir, home.path(), &["add", rel]);
    }
    repo.ok(&["commit", "-m", "files"]);
    git(gdir, home.path(), &["commit", "-q", "-m", "files"]);
    for args in [
        &["-n", "foo"][..],
        &["-i", "foo"],
        &["-w", "foo"],
        &["-v", "foo"],
        &["-l", "foo"],
        &["-c", "foo"],
        &["-c", "-v", "o"],
        &["-n", "-i", "-w", "foo"],
        &["-F", "-n", "foo-bar"],
        &["-e", "alpha", "-e", "^food$"],
        &["-n", "foo", "HEAD"],
        &["-n", "--cached", "o", "--", "dir"],
        &["absent"],
    ] {
        let mut all = vec!["grep"];
        all.extend_from_slice(args);
        let theirs = git(gdir, home.path(), &all);
        let ours = repo.run(&all);
        assert_eq!(ours.status.code(), theirs.status.code(), "{args:?}");
        assert_eq!(stdout(&ours), stdout(&theirs), "{args:?}");
    }
}

/// The lines of `body` that hold `needle`, as `kit grep -F -n` prints them.
fn naive(path: &str, body: &str, needle: &str) -> String {
    body.lines()
        .enumerate()
        .filter(|(_, l)| l.contains(needle))
        .map(|(i, l)| format!("{path}:{}:{l}\n", i + 1))
        .collect()
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 16, ..ProptestConfig::default() })]

    #[test]
    fn fixed_strings_match_a_naive_scan(
        files in proptest::collection::btree_map(
            "[a-c]{1,3}",
            proptest::collection::vec("[ab.*( ]{0,6}", 0..6),
            1..4,
        ),
        needle in "[ab.*(]{1,2}",
    ) {
        let repo = Repo::new();
        let mut expected = String::new();
        for (name, lines) in &files {
            let rel = format!("{name}.txt");
            let body: String = lines.iter().map(|l| format!("{l}\n")).collect();
            repo.write(&rel, body.as_bytes());
            repo.ok(&["add", &rel]);
            expected.push_str(&naive(&rel, &body, &needle));
        }
        repo.ok(&["commit", "-m", "files"]);
        let (code, out) = grep(&repo, &["-F", "-n", "-e", &needle]);
        prop_assert_eq!(&out, &expected);
        prop_assert_eq!(code, Some(if out.is_empty() { 1 } else { 0 }));
    }
}
