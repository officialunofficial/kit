//! `-X ours` / `-X theirs` on merge, cherry-pick, revert, rebase and pull,
//! and `-s ours` on merge.
//!
//! Each command meets the same conflict: both sides change line 3 of a
//! ten-line file, and each side also changes a line of its own far from
//! line 3. With a strategy option the conflicting line takes the chosen
//! side, the other changes still merge, and the command finishes without
//! stopping. A differential case runs the merge through `git` when it is
//! on `PATH`.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

mod common;

use std::fmt::Write as _;
use std::path::Path;
use std::process::{Command, Output};

use common::Repo;

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// Lines `1` to `10`, with the given lines replaced.
fn file(changes: &[(usize, &str)]) -> String {
    (1..=10).fold(String::new(), |mut s, n| {
        match changes.iter().find(|(line, _)| *line == n) {
            Some((_, text)) => {
                let _ = writeln!(s, "{text}");
            }
            None => {
                let _ = writeln!(s, "{n}");
            }
        }
        s
    })
}

fn read(repo: &Repo, rel: &str) -> String {
    std::fs::read_to_string(repo.path().join(rel)).unwrap()
}

fn rev(repo: &Repo, spec: &str) -> String {
    stdout(&repo.ok(&["rev-parse", spec])).trim().to_owned()
}

/// `main` changes line 3 to `main` and line 8 to `main 8`. `topic`, made
/// from the base, changes line 3 to `topic` and line 10 to `topic 10`.
/// `HEAD` is `main`.
fn diverged() -> Repo {
    let repo = Repo::new();
    repo.commit_file("f.txt", file(&[]).as_bytes(), "base");
    repo.ok(&["branch", "topic"]);
    repo.commit_file(
        "f.txt",
        file(&[(3, "main"), (8, "main 8")]).as_bytes(),
        "main edits",
    );
    repo.ok(&["switch", "topic"]);
    repo.commit_file(
        "f.txt",
        file(&[(3, "topic"), (10, "topic 10")]).as_bytes(),
        "topic edits",
    );
    repo.ok(&["switch", "main"]);
    repo
}

fn merged_with(winner: &str) -> String {
    file(&[(3, winner), (8, "main 8"), (10, "topic 10")])
}

#[test]
fn without_an_option_the_merge_stops_on_the_conflict() {
    let repo = diverged();
    let out = repo.run(&["merge", "topic"]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
}

#[test]
fn merge_x_ours_keeps_our_line_and_their_other_change() {
    let repo = diverged();
    repo.ok(&["merge", "-X", "ours", "topic"]);
    assert_eq!(read(&repo, "f.txt"), merged_with("main"));
    assert_eq!(stdout(&repo.ok(&["status", "--porcelain"])), "");
    assert_eq!(rev(&repo, "HEAD^2"), rev(&repo, "topic"));
}

#[test]
fn merge_x_theirs_takes_their_line_and_keeps_our_other_change() {
    let repo = diverged();
    repo.ok(&["merge", "--strategy-option=theirs", "topic"]);
    assert_eq!(read(&repo, "f.txt"), merged_with("topic"));
}

#[test]
fn merge_x_ours_attached_form_works() {
    let repo = diverged();
    repo.ok(&["merge", "-Xours", "topic"]);
    assert_eq!(read(&repo, "f.txt"), merged_with("main"));
}

#[test]
fn a_clean_merge_is_the_same_with_any_option() {
    let mut trees = Vec::new();
    for option in [None, Some("ours"), Some("theirs")] {
        let repo = Repo::new();
        repo.commit_file("f.txt", file(&[]).as_bytes(), "base");
        repo.ok(&["branch", "topic"]);
        repo.commit_file("f.txt", file(&[(2, "main")]).as_bytes(), "main edits");
        repo.ok(&["switch", "topic"]);
        repo.commit_file("f.txt", file(&[(9, "topic")]).as_bytes(), "topic edits");
        repo.ok(&["switch", "main"]);
        let mut args = vec!["merge"];
        if let Some(o) = option {
            args.extend(["-X", o]);
        }
        args.push("topic");
        repo.ok(&args);
        trees.push(read(&repo, "f.txt"));
    }
    assert_eq!(trees[0], file(&[(2, "main"), (9, "topic")]));
    assert_eq!(trees[0], trees[1]);
    assert_eq!(trees[0], trees[2]);
}

#[test]
fn merge_s_ours_records_our_tree_with_both_parents() {
    let repo = diverged();
    let before = stdout(&repo.ok(&["ls-tree", "-r", "HEAD"]));
    repo.ok(&["merge", "-s", "ours", "topic"]);
    assert_eq!(stdout(&repo.ok(&["ls-tree", "-r", "HEAD"])), before);
    assert_eq!(read(&repo, "f.txt"), file(&[(3, "main"), (8, "main 8")]));
    assert_eq!(rev(&repo, "HEAD^2"), rev(&repo, "topic"));
}

#[test]
fn merge_s_ours_never_fast_forwards() {
    let repo = Repo::new();
    repo.commit_file("f.txt", file(&[]).as_bytes(), "base");
    let base = rev(&repo, "HEAD");
    repo.ok(&["branch", "topic"]);
    repo.ok(&["switch", "topic"]);
    repo.commit_file("f.txt", file(&[(3, "topic")]).as_bytes(), "topic edits");
    repo.ok(&["switch", "main"]);
    repo.ok(&["merge", "-s", "ours", "topic"]);
    assert_eq!(read(&repo, "f.txt"), file(&[]));
    assert_eq!(rev(&repo, "HEAD^1"), base);
    assert_eq!(rev(&repo, "HEAD^2"), rev(&repo, "topic"));
}

#[test]
fn merge_s_with_the_default_strategy_names_is_a_normal_merge() {
    for name in ["ort", "recursive"] {
        let repo = diverged();
        repo.ok(&["merge", "-s", name, "-X", "theirs", "topic"]);
        assert_eq!(read(&repo, "f.txt"), merged_with("topic"), "{name}");
    }
}

#[test]
fn an_unknown_option_or_strategy_is_a_usage_error() {
    let repo = diverged();
    for args in [
        &["merge", "-X", "patience", "topic"][..],
        &["merge", "-X", "", "topic"][..],
        &["merge", "-s", "octopus", "topic"][..],
        &["merge", "-s", "ours", "-X", "theirs", "topic"][..],
        &["cherry-pick", "-X", "subtree", "topic"][..],
        &["revert", "-X", "renormalize", "HEAD"][..],
        &["rebase", "-X", "nope", "topic"][..],
    ] {
        let out = repo.run(args);
        assert_eq!(out.status.code(), Some(64), "{args:?}: {}", stderr(&out));
    }
    assert_eq!(read(&repo, "f.txt"), file(&[(3, "main"), (8, "main 8")]));
}

#[test]
fn cherry_pick_x_theirs_takes_the_picked_line() {
    let repo = diverged();
    let topic = rev(&repo, "topic");
    repo.ok(&["cherry-pick", "-X", "theirs", &topic]);
    assert_eq!(read(&repo, "f.txt"), merged_with("topic"));
}

#[test]
fn cherry_pick_x_ours_keeps_our_line() {
    let repo = diverged();
    let topic = rev(&repo, "topic");
    repo.ok(&["cherry-pick", "-X", "ours", &topic]);
    assert_eq!(read(&repo, "f.txt"), merged_with("main"));
}

/// `main` sets line 3 to `first`, then to `second` with line 9 `nine`.
/// Reverting the first commit conflicts on line 3.
fn revert_fixture() -> (Repo, String) {
    let repo = Repo::new();
    repo.commit_file("f.txt", file(&[]).as_bytes(), "base");
    repo.commit_file(
        "f.txt",
        file(&[(3, "first"), (6, "six")]).as_bytes(),
        "first",
    );
    let first = rev(&repo, "HEAD");
    repo.commit_file(
        "f.txt",
        file(&[(3, "second"), (6, "six"), (9, "nine")]).as_bytes(),
        "second",
    );
    (repo, first)
}

#[test]
fn revert_x_ours_keeps_the_current_line() {
    let (repo, first) = revert_fixture();
    repo.ok(&["revert", "-X", "ours", &first]);
    assert_eq!(read(&repo, "f.txt"), file(&[(3, "second"), (9, "nine")]));
}

#[test]
fn revert_x_theirs_restores_the_old_line() {
    let (repo, first) = revert_fixture();
    repo.ok(&["revert", "-X", "theirs", &first]);
    assert_eq!(read(&repo, "f.txt"), file(&[(9, "nine")]));
}

#[test]
fn rebase_x_ours_favors_the_upstream_side() {
    // In a rebase, `ours` is the branch being rebased onto, as in git.
    let repo = diverged();
    repo.ok(&["switch", "topic"]);
    repo.ok(&["rebase", "-X", "ours", "main"]);
    assert_eq!(read(&repo, "f.txt"), merged_with("main"));
    assert_eq!(rev(&repo, "HEAD^"), rev(&repo, "main"));
}

#[test]
fn rebase_x_theirs_favors_the_replayed_commit() {
    let repo = diverged();
    repo.ok(&["switch", "topic"]);
    repo.ok(&["rebase", "-X", "theirs", "main"]);
    assert_eq!(read(&repo, "f.txt"), merged_with("topic"));
}

#[test]
fn rebase_keeps_the_option_across_a_pause() {
    // The first replayed commit stops on a modify/delete conflict. After the
    // resolution, the second one still uses `-X theirs`.
    let repo = Repo::new();
    repo.commit_file("f.txt", file(&[]).as_bytes(), "base");
    repo.commit_file("g.txt", b"g\n", "add g");
    repo.ok(&["branch", "topic"]);
    repo.ok(&["rm", "g.txt"]);
    repo.ok(&["commit", "-m", "main removes g"]);
    repo.commit_file("f.txt", file(&[(3, "main")]).as_bytes(), "main edits");
    repo.ok(&["switch", "topic"]);
    repo.commit_file("g.txt", b"g changed\n", "topic edits g");
    repo.commit_file("f.txt", file(&[(3, "topic")]).as_bytes(), "topic edits f");
    let out = repo.run(&["rebase", "-X", "theirs", "main"]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    repo.ok(&["add", "g.txt"]);
    repo.ok(&["rebase", "--continue"]);
    assert_eq!(read(&repo, "f.txt"), file(&[(3, "topic")]));
}

#[test]
fn a_modify_delete_conflict_still_stops() {
    let repo = Repo::new();
    repo.commit_file("f.txt", file(&[]).as_bytes(), "base");
    repo.ok(&["branch", "topic"]);
    repo.ok(&["rm", "f.txt"]);
    repo.ok(&["commit", "-m", "main removes f"]);
    repo.ok(&["switch", "topic"]);
    repo.commit_file("f.txt", file(&[(3, "topic")]).as_bytes(), "topic edits");
    repo.ok(&["switch", "main"]);
    for option in ["ours", "theirs"] {
        let out = repo.run(&["merge", "-X", option, "topic"]);
        assert_eq!(out.status.code(), Some(1), "{option}: {}", stderr(&out));
        repo.ok(&["merge", "--abort"]);
    }
}

#[test]
fn pull_x_theirs_takes_the_remote_line() {
    let upstream = Repo::new();
    let bare = tempfile::tempdir().unwrap();
    let url = format!("kit+file://{}", bare.path().display());
    upstream.commit_file("f.txt", file(&[]).as_bytes(), "base");
    upstream.ok(&["remote", "add", &url]);
    upstream.ok(&["push"]);
    let local = Repo::new();
    local.ok(&["remote", "add", &url]);
    local.ok(&["pull"]);
    upstream.commit_file(
        "f.txt",
        file(&[(3, "remote"), (10, "remote 10")]).as_bytes(),
        "remote",
    );
    upstream.ok(&["push"]);
    local.commit_file(
        "f.txt",
        file(&[(3, "local"), (8, "local 8")]).as_bytes(),
        "local",
    );
    local.ok(&["pull", "--no-ff", "-X", "theirs"]);
    assert_eq!(
        read(&local, "f.txt"),
        file(&[(3, "remote"), (8, "local 8"), (10, "remote 10")])
    );
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

#[test]
fn merge_results_match_git() {
    if !git_available() {
        eprintln!("SKIP: git not on PATH");
        return;
    }
    for option in ["ours", "theirs"] {
        let repo = diverged();
        repo.ok(&["merge", "-X", option, "topic"]);

        let home = tempfile::tempdir().unwrap();
        let g = tempfile::tempdir().unwrap();
        let (dir, home) = (g.path(), home.path());
        git(dir, home, &["init", "-q", "-b", "main"]);
        std::fs::write(dir.join("f.txt"), file(&[])).unwrap();
        git(dir, home, &["add", "."]);
        git(dir, home, &["commit", "-qm", "base"]);
        git(dir, home, &["branch", "topic"]);
        std::fs::write(dir.join("f.txt"), file(&[(3, "main"), (8, "main 8")])).unwrap();
        git(dir, home, &["commit", "-qam", "main edits"]);
        git(dir, home, &["switch", "-q", "topic"]);
        std::fs::write(dir.join("f.txt"), file(&[(3, "topic"), (10, "topic 10")])).unwrap();
        git(dir, home, &["commit", "-qam", "topic edits"]);
        git(dir, home, &["switch", "-q", "main"]);
        git(
            dir,
            home,
            &["merge", "-q", "--no-edit", "-X", option, "topic"],
        );

        let theirs = std::fs::read_to_string(dir.join("f.txt")).unwrap();
        assert_eq!(read(&repo, "f.txt"), theirs, "-X {option}");
    }
}
