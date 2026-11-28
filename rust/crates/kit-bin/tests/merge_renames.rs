//! `merge`, `cherry-pick`, `revert` and `rebase` follow a file that one
//! side renamed, with the similarity detection of `diff`.
//!
//! Invariants:
//! - One-sided rename: when one side renames `a` to `b` and the other side
//!   edits `a`, the result holds the edit in `b` and has no `a`.
//! - A rename against a delete, or two renames of one file to different
//!   names, is a conflict that names every path.
//! - Agreement with git on scripted histories: the same files with the same
//!   content.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

mod common;

use std::fmt::Write as _;
use std::path::Path;
use std::process::{Command, Output};

use common::Repo;

/// Twelve distinct lines, with line `i` replaced for each `(i, text)`.
fn body(edits: &[(usize, &str)]) -> Vec<u8> {
    let mut out = String::new();
    for i in 0..12 {
        match edits.iter().find(|(n, _)| *n == i) {
            Some((_, text)) => out.push_str(text),
            None => {
                let _ = write!(out, "line {i} of the file that moves");
            }
        }
        out.push('\n');
    }
    out.into_bytes()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn read(repo: &Repo, rel: &str) -> Option<Vec<u8>> {
    std::fs::read(repo.path().join(rel)).ok()
}

/// `main` edits line 2 of `a.txt`; `side` renames `a.txt` to `b.txt`.
/// `main` is checked out.
fn rename_against_edit() -> Repo {
    let repo = Repo::new();
    repo.commit_file("a.txt", &body(&[]), "base");
    repo.ok(&["checkout", "-b", "side"]);
    repo.ok(&["mv", "a.txt", "b.txt"]);
    repo.ok(&["commit", "-m", "rename a to b"]);
    repo.ok(&["checkout", "main"]);
    repo.write("a.txt", &body(&[(2, "edited on main")]));
    repo.ok(&["commit", "-a", "-m", "edit a"]);
    repo
}

fn assert_edit_moved(repo: &Repo, edits: &[(usize, &str)]) {
    assert_eq!(read(repo, "b.txt"), Some(body(edits)));
    assert_eq!(read(repo, "a.txt"), None);
    let tree = String::from_utf8_lossy(&repo.ok(&["ls-files"]).stdout).into_owned();
    assert_eq!(tree, "b.txt\n");
}

#[test]
fn merge_applies_an_edit_to_the_renamed_file() {
    let repo = rename_against_edit();
    repo.ok(&["merge", "side", "-m", "merge side"]);
    assert_edit_moved(&repo, &[(2, "edited on main")]);
}

#[test]
fn merge_follows_a_rename_on_our_side_too() {
    let repo = rename_against_edit();
    repo.ok(&["checkout", "side"]);
    repo.ok(&["merge", "main", "-m", "merge main"]);
    assert_edit_moved(&repo, &[(2, "edited on main")]);
}

#[test]
fn a_rename_with_an_edit_merges_with_an_edit_elsewhere() {
    let repo = Repo::new();
    repo.commit_file("a.txt", &body(&[]), "base");
    repo.ok(&["checkout", "-b", "side"]);
    repo.ok(&["mv", "a.txt", "b.txt"]);
    repo.write("b.txt", &body(&[(9, "edited on side")]));
    repo.ok(&["add", "b.txt"]);
    repo.ok(&["commit", "-m", "rename and edit"]);
    repo.ok(&["checkout", "main"]);
    repo.write("a.txt", &body(&[(2, "edited on main")]));
    repo.ok(&["commit", "-a", "-m", "edit a"]);
    repo.ok(&["merge", "side", "-m", "merge side"]);
    assert_edit_moved(&repo, &[(2, "edited on main"), (9, "edited on side")]);
}

#[test]
fn cherry_pick_applies_an_edit_to_the_renamed_file() {
    let repo = rename_against_edit();
    repo.ok(&["checkout", "side"]);
    repo.ok(&["cherry-pick", "main"]);
    assert_edit_moved(&repo, &[(2, "edited on main")]);
}

#[test]
fn rebase_replays_an_edit_onto_the_renamed_file() {
    let repo = rename_against_edit();
    repo.ok(&["rebase", "side"]);
    assert_edit_moved(&repo, &[(2, "edited on main")]);
}

#[test]
fn revert_undoes_an_edit_in_the_renamed_file() {
    let repo = Repo::new();
    repo.commit_file("a.txt", &body(&[]), "base");
    repo.write("a.txt", &body(&[(2, "a change to revert")]));
    repo.ok(&["commit", "-a", "-m", "edit a"]);
    repo.ok(&["mv", "a.txt", "b.txt"]);
    repo.ok(&["commit", "-m", "rename a to b"]);
    repo.ok(&["revert", "HEAD~1"]);
    assert_edit_moved(&repo, &[]);
}

#[test]
fn a_rename_against_a_delete_is_a_conflict() {
    let repo = Repo::new();
    repo.commit_file("a.txt", &body(&[]), "base");
    repo.ok(&["checkout", "-b", "side"]);
    repo.ok(&["mv", "a.txt", "b.txt"]);
    repo.ok(&["commit", "-m", "rename a to b"]);
    repo.ok(&["checkout", "main"]);
    repo.ok(&["rm", "a.txt"]);
    repo.ok(&["commit", "-m", "delete a"]);
    let out = repo.run(&["merge", "side", "-m", "merge side"]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    let err = stderr(&out);
    assert!(err.contains("CONFLICT (rename/delete)"), "{err}");
    assert!(err.contains("a.txt") && err.contains("b.txt"), "{err}");
    assert_eq!(read(&repo, "b.txt"), Some(body(&[])));
    assert_eq!(read(&repo, "a.txt"), None);
    // Keeping the renamed file resolves it.
    repo.ok(&["add", "b.txt"]);
    repo.ok(&["merge", "--continue"]);
    assert_eq!(read(&repo, "b.txt"), Some(body(&[])));
}

#[test]
fn two_renames_to_different_names_are_a_conflict() {
    let repo = Repo::new();
    repo.commit_file("a.txt", &body(&[]), "base");
    repo.ok(&["checkout", "-b", "side"]);
    repo.ok(&["mv", "a.txt", "b.txt"]);
    repo.ok(&["commit", "-m", "rename a to b"]);
    repo.ok(&["checkout", "main"]);
    repo.ok(&["mv", "a.txt", "c.txt"]);
    repo.ok(&["commit", "-m", "rename a to c"]);
    let out = repo.run(&["merge", "side", "-m", "merge side"]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    let err = stderr(&out);
    assert!(err.contains("CONFLICT (rename/rename)"), "{err}");
    for path in ["a.txt", "b.txt", "c.txt"] {
        assert!(err.contains(path), "{path}: {err}");
    }
    assert_eq!(read(&repo, "b.txt"), Some(body(&[])));
    assert_eq!(read(&repo, "c.txt"), Some(body(&[])));
    assert_eq!(read(&repo, "a.txt"), None);
}

#[test]
fn two_renames_to_the_same_name_merge_their_edits() {
    let repo = Repo::new();
    repo.commit_file("a.txt", &body(&[]), "base");
    repo.ok(&["checkout", "-b", "side"]);
    repo.ok(&["mv", "a.txt", "b.txt"]);
    repo.write("b.txt", &body(&[(9, "edited on side")]));
    repo.ok(&["add", "b.txt"]);
    repo.ok(&["commit", "-m", "rename and edit on side"]);
    repo.ok(&["checkout", "main"]);
    repo.ok(&["mv", "a.txt", "b.txt"]);
    repo.write("b.txt", &body(&[(2, "edited on main")]));
    repo.ok(&["add", "b.txt"]);
    repo.ok(&["commit", "-m", "rename and edit on main"]);
    repo.ok(&["merge", "side", "-m", "merge side"]);
    assert_edit_moved(&repo, &[(2, "edited on main"), (9, "edited on side")]);
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
        .env("GIT_AUTHOR_DATE", "2026-01-01T00:00:00Z")
        .env("GIT_COMMITTER_DATE", "2026-01-01T00:00:00Z")
        .output()
        .unwrap();
    assert!(out.status.success(), "git {args:?}: {}", stderr(&out));
    out
}

/// Tracked files and their content, in path order.
type Listing = Vec<(String, Vec<u8>)>;

/// The tracked files and their content after the same history in git and
/// in kit: `main` edits a line, `side` renames into a new directory and
/// edits another line, and `verb` brings `side` into `main`.
fn files_after(verb: &str) -> (Listing, Listing) {
    let base = body(&[]);
    let ours = body(&[(1, "edited on main")]);
    let theirs = body(&[(10, "edited on side")]);

    let repo = Repo::new();
    repo.commit_file("a.txt", &base, "base");
    repo.commit_file("keep.txt", b"unrelated\n", "keep");
    repo.ok(&["checkout", "-b", "side"]);
    std::fs::create_dir_all(repo.path().join("moved")).unwrap();
    repo.ok(&["mv", "a.txt", "moved/b.txt"]);
    repo.write("moved/b.txt", &theirs);
    repo.ok(&["add", "moved/b.txt"]);
    repo.ok(&["commit", "-m", "move and edit"]);
    repo.ok(&["checkout", "main"]);
    repo.write("a.txt", &ours);
    repo.ok(&["commit", "-a", "-m", "edit"]);
    match verb {
        "merge" => drop(repo.ok(&["merge", "side", "-m", "merge side"])),
        _ => drop(repo.ok(&["cherry-pick", "side"])),
    }

    let home = tempfile::tempdir().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let g = |args: &[&str]| git(dir.path(), home.path(), args);
    g(&["init", "-q", "-b", "main"]);
    std::fs::write(dir.path().join("a.txt"), &base).unwrap();
    g(&["add", "a.txt"]);
    g(&["commit", "-q", "-m", "base"]);
    std::fs::write(dir.path().join("keep.txt"), b"unrelated\n").unwrap();
    g(&["add", "keep.txt"]);
    g(&["commit", "-q", "-m", "keep"]);
    g(&["checkout", "-q", "-b", "side"]);
    std::fs::create_dir_all(dir.path().join("moved")).unwrap();
    g(&["mv", "a.txt", "moved/b.txt"]);
    std::fs::write(dir.path().join("moved/b.txt"), &theirs).unwrap();
    g(&["commit", "-q", "-a", "-m", "move and edit"]);
    g(&["checkout", "-q", "main"]);
    std::fs::write(dir.path().join("a.txt"), &ours).unwrap();
    g(&["commit", "-q", "-a", "-m", "edit"]);
    match verb {
        "merge" => drop(g(&["merge", "-q", "side", "-m", "merge side"])),
        _ => drop(g(&["cherry-pick", "side"])),
    }

    let listed = |root: &Path, out: &Output| -> Listing {
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(|p| (p.to_owned(), std::fs::read(root.join(p)).unwrap()))
            .collect()
    };
    let kit_files = listed(repo.path(), &repo.ok(&["ls-files"]));
    let git_files = listed(dir.path(), &g(&["ls-files"]));
    (kit_files, git_files)
}

#[test]
fn merge_agrees_with_git_on_a_moved_and_edited_file() {
    if !git_available() {
        return;
    }
    let (kit, git) = files_after("merge");
    assert_eq!(kit, git);
}

#[test]
fn cherry_pick_agrees_with_git_on_a_moved_and_edited_file() {
    if !git_available() {
        return;
    }
    let (kit, git) = files_after("cherry-pick");
    assert_eq!(kit, git);
}
