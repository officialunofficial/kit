//! `kit rebase --update-refs`: the branches stacked on the replayed commits
//! move to the replacements, all at the end, and only if none of them moved
//! during the rebase. The stub `$EDITOR` copies each todo list to
//! `$TODO_LOG` and rewrites it with the `sed` program in `$SED`.

#![cfg(unix)]
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Output;

use common::Repo;

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

struct Editor {
    dir: tempfile::TempDir,
    path: PathBuf,
}

impl Editor {
    fn todo(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("todo.log")).unwrap_or_default()
    }

    fn env<'a>(&'a self, sed: &'a str) -> Vec<(&'a str, String)> {
        vec![
            ("GIT_EDITOR", self.path.to_str().unwrap().to_owned()),
            ("SED", sed.to_owned()),
            (
                "TODO_LOG",
                self.dir
                    .path()
                    .join("todo.log")
                    .to_str()
                    .unwrap()
                    .to_owned(),
            ),
        ]
    }
}

fn editor() -> Editor {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("editor.sh");
    let script = r#"#!/bin/sh
f="$1"
if grep -q '^# Rebase' "$f"; then
    cat "$f" >> "$TODO_LOG"
    sed -e "${SED:-}" "$f" > "$f.tmp" && mv "$f.tmp" "$f"
fi
"#;
    std::fs::write(&path, script).unwrap();
    let mut perms = std::fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&path, perms).unwrap();
    Editor { dir, path }
}

fn run_with(repo: &Repo, args: &[&str], env: &[(&str, String)]) -> Output {
    let env: Vec<(&str, &str)> = env.iter().map(|(k, v)| (*k, v.as_str())).collect();
    repo.run_env(args, &env)
}

fn rev(repo: &Repo, spec: &str) -> String {
    stdout(&repo.ok(&["rev-parse", spec])).trim().to_owned()
}

fn subjects(repo: &Repo, spec: &str) -> Vec<String> {
    stdout(&repo.ok(&["log", "--oneline", spec]))
        .lines()
        .map(|l| l.split_once(' ').map_or("", |(_, s)| s).to_owned())
        .collect()
}

fn in_progress(repo: &Repo) -> bool {
    repo.kit_dir().join("rebase-apply").is_dir()
}

/// `main` is `base` then `M`. `a`, made from `base`, adds `A1` and `A2`.
/// `b`, made from `a`, adds `B1`. `other`, made from `base`, adds `O`.
/// `HEAD` is `b`.
fn stack() -> Repo {
    let repo = Repo::new();
    repo.commit_file("base.txt", b"base\n", "base");
    repo.ok(&["branch", "a"]);
    repo.ok(&["branch", "other"]);
    repo.commit_file("m.txt", b"M\n", "M");
    repo.ok(&["switch", "other"]);
    repo.commit_file("o.txt", b"O\n", "O");
    repo.ok(&["switch", "a"]);
    repo.commit_file("a1.txt", b"A1\n", "A1");
    repo.commit_file("a2.txt", b"A2\n", "A2");
    repo.ok(&["branch", "b"]);
    repo.ok(&["switch", "b"]);
    repo.commit_file("b1.txt", b"B1\n", "B1");
    repo
}

const EDIT_B1: &str = "s/^pick \\(.*\\) B1$/edit \\1 B1/";

#[test]
fn update_refs_moves_a_branch_stacked_below() {
    let repo = stack();
    let old_a = rev(&repo, "a");
    let other = rev(&repo, "other");
    let main = rev(&repo, "main");
    let out = repo.run(&["rebase", "--update-refs", "main"]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(stderr(&out).contains("refs/heads/a"), "{}", stderr(&out));
    assert_eq!(subjects(&repo, "b"), ["B1", "A2", "A1", "M", "base"]);
    // `a` points at the replacement of its old tip.
    assert_eq!(rev(&repo, "a"), rev(&repo, "b~1"));
    assert_eq!(subjects(&repo, "a"), ["A2", "A1", "M", "base"]);
    // Branches that do not point into the range never move.
    assert_eq!(rev(&repo, "other"), other);
    assert_eq!(rev(&repo, "main"), main);
    // The old tip of `a` is in the recovery log.
    let log = stdout(&repo.ok(&["reflog", "--recovery"]));
    assert!(log.contains(&old_a[..7]), "{log}");
}

#[test]
fn update_refs_reports_the_moved_branches_in_json() {
    let repo = stack();
    let out = repo.run(&["rebase", "--update-refs", "--format=json", "main"]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let line = stdout(&out);
    let value: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
    assert_eq!(value["kind"], "rebased");
    assert_eq!(value["updated_refs"], serde_json::json!(["a"]));
}

#[test]
fn without_update_refs_the_stacked_branch_stays() {
    let repo = stack();
    let old_a = rev(&repo, "a");
    repo.ok(&["rebase", "main"]);
    assert_eq!(rev(&repo, "a"), old_a);
}

#[test]
fn a_branch_checked_out_in_another_worktree_is_skipped_with_a_warning() {
    let repo = stack();
    let linked = tempfile::tempdir().unwrap();
    let linked_path = linked.path().join("a-tree");
    repo.ok(&["worktree", "add", linked_path.to_str().unwrap(), "a"]);
    let old_a = rev(&repo, "a");
    let out = repo.run(&["rebase", "--update-refs", "main"]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(stderr(&out).contains("warning"), "{}", stderr(&out));
    assert!(stderr(&out).contains('a'), "{}", stderr(&out));
    assert_eq!(rev(&repo, "a"), old_a);
    assert_eq!(subjects(&repo, "b"), ["B1", "A2", "A1", "M", "base"]);
}

#[test]
fn abort_moves_no_branch() {
    let repo = stack();
    let ed = editor();
    let old_a = rev(&repo, "a");
    let old_b = rev(&repo, "b");
    let out = run_with(
        &repo,
        &["rebase", "-i", "--update-refs", "main"],
        &ed.env(EDIT_B1),
    );
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(in_progress(&repo));
    // The step for `a` ran before the stop; nothing moved yet.
    assert_eq!(rev(&repo, "a"), old_a);
    repo.ok(&["rebase", "--abort"]);
    assert!(!in_progress(&repo));
    assert_eq!(rev(&repo, "a"), old_a);
    assert_eq!(rev(&repo, "b"), old_b);
}

#[test]
fn interactive_update_refs_lists_the_branch_after_its_commit() {
    let repo = stack();
    let ed = editor();
    let out = run_with(
        &repo,
        &["rebase", "-i", "--update-refs", "main"],
        &ed.env(""),
    );
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let todo = ed.todo();
    let steps: Vec<String> = todo
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            let words: Vec<&str> = l.split(' ').collect();
            match words.as_slice() {
                ["update-ref", r] => format!("update-ref {r}"),
                [verb, _id, rest @ ..] => format!("{verb} {}", rest.join(" ")),
                _ => l.to_owned(),
            }
        })
        .collect();
    assert_eq!(
        steps,
        ["pick A1", "pick A2", "update-ref refs/heads/a", "pick B1"],
        "{todo}"
    );
    assert_eq!(rev(&repo, "a"), rev(&repo, "b~1"));
}

#[test]
fn deleting_the_update_ref_line_leaves_the_branch() {
    let repo = stack();
    let ed = editor();
    let old_a = rev(&repo, "a");
    let out = run_with(
        &repo,
        &["rebase", "-i", "--update-refs", "main"],
        &ed.env("/^update-ref/d"),
    );
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(rev(&repo, "a"), old_a);
}

#[test]
fn a_typed_update_ref_line_moves_that_branch_to_the_commit_before_it() {
    let repo = stack();
    let ed = editor();
    // Put `other` after the first commit, without --update-refs.
    let out = run_with(
        &repo,
        &["rebase", "-i", "main"],
        &ed.env("s/^\\(pick .* A1\\)$/\\1\\nupdate-ref refs\\/heads\\/other/"),
    );
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(rev(&repo, "other"), rev(&repo, "b~2"));
}

#[test]
fn an_update_ref_line_for_a_bad_ref_is_refused_before_any_change() {
    let repo = stack();
    let ed = editor();
    let old_b = rev(&repo, "b");
    for line in [
        "update-ref refs/heads/no-such-branch",
        "update-ref refs/tags/v1",
        "update-ref refs/heads/b",
        "update-ref",
    ] {
        let sed = format!("1i\\\n{line}\n");
        let out = run_with(&repo, &["rebase", "-i", "main"], &ed.env(&sed));
        assert!(!out.status.success(), "{line}: {}", stderr(&out));
        assert!(!in_progress(&repo), "{line}");
        assert_eq!(rev(&repo, "b"), old_b, "{line}");
    }
}

#[test]
fn a_branch_that_moved_during_the_rebase_stops_every_move() {
    let repo = stack();
    let ed = editor();
    let old_a = rev(&repo, "a");
    let old_b = rev(&repo, "b");
    let linked = tempfile::tempdir().unwrap();
    let linked_path = linked.path().join("other-tree");
    repo.ok(&["worktree", "add", linked_path.to_str().unwrap(), "other"]);

    run_with(
        &repo,
        &["rebase", "-i", "--update-refs", "main"],
        &ed.env(EDIT_B1),
    );
    assert!(in_progress(&repo));
    // Move `a` from the linked tree while the rebase is stopped, then leave
    // it, so `a` is not checked out anywhere at the finish.
    let in_linked = |args: &[&str]| {
        let out = common::kit(&linked_path, repo.xdg(), args);
        assert!(out.status.success(), "{args:?}: {}", stderr(&out));
    };
    in_linked(&["switch", "a"]);
    std::fs::write(linked_path.join("late.txt"), b"late\n").unwrap();
    in_linked(&["add", "late.txt"]);
    in_linked(&["commit", "-m", "late"]);
    in_linked(&["switch", "other"]);
    let moved_a = rev(&repo, "a");
    assert_ne!(moved_a, old_a);

    let out = repo.run(&["rebase", "--continue"]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(stderr(&out).contains("'a'"), "{}", stderr(&out));
    assert!(in_progress(&repo));
    assert_eq!(rev(&repo, "a"), moved_a);
    assert_eq!(rev(&repo, "b"), old_b);

    repo.ok(&["rebase", "--abort"]);
    assert_eq!(rev(&repo, "a"), moved_a);
    assert_eq!(rev(&repo, "b"), old_b);
}

#[test]
fn rebase_update_refs_config_turns_it_on_and_the_flag_off() {
    let repo = stack();
    let old_a = rev(&repo, "a");
    let old_b = rev(&repo, "b");
    repo.ok(&["config", "rebase.updaterefs", "true"]);
    repo.ok(&["rebase", "--no-update-refs", "main"]);
    assert_eq!(rev(&repo, "a"), old_a);

    repo.ok(&["reset", "--hard", &old_b]);
    repo.ok(&["rebase", "main"]);
    assert_eq!(rev(&repo, "a"), rev(&repo, "b~1"));
}

#[test]
fn update_refs_refuses_to_combine_with_continue() {
    let repo = stack();
    let out = repo.run(&["rebase", "--continue", "--update-refs"]);
    assert_eq!(out.status.code(), Some(64), "{}", stderr(&out));
}
