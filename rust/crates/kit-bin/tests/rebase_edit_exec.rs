//! `kit rebase -i` with `edit` and `exec` todo lines, and `kit rebase
//! --exec`.
//!
//! An `edit` line replays its commit and stops, so the user can amend it or
//! add commits; `--continue` replays the rest. An `exec` line runs a shell
//! command, and a command that fails stops the rebase after that line. The
//! stub `$EDITOR` rewrites the todo list with the `sed` program in `$SED`,
//! and writes `$MSG` to any other file.

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
    _dir: tempfile::TempDir,
    path: PathBuf,
}

fn editor() -> Editor {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("editor.sh");
    let script = r#"#!/bin/sh
f="$1"
if grep -q '^# Rebase' "$f"; then
    sed -e "${SED:-}" "$f" > "$f.tmp" && mv "$f.tmp" "$f"
else
    printf '%s' "${MSG:-edited}" > "$f"
fi
"#;
    std::fs::write(&path, script).unwrap();
    let mut perms = std::fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&path, perms).unwrap();
    Editor { _dir: dir, path }
}

fn with_editor<'a>(editor: &'a Editor, sed: &'a str) -> [(&'a str, &'a str); 2] {
    [("GIT_EDITOR", editor.path.to_str().unwrap()), ("SED", sed)]
}

/// `main` is `base` then `M`. `topic`, made from `base`, adds `a.txt`,
/// `b.txt` and `c.txt` in the commits `A`, `B` and `C`. `HEAD` is `topic`.
fn setup() -> Repo {
    let repo = Repo::new();
    repo.commit_file("base.txt", b"base\n", "base");
    repo.ok(&["branch", "topic"]);
    repo.commit_file("m.txt", b"M\n", "M");
    repo.ok(&["switch", "topic"]);
    repo.commit_file("a.txt", b"A\n", "A");
    repo.commit_file("b.txt", b"B\n", "B");
    repo.commit_file("c.txt", b"C\n", "C");
    repo
}

fn subjects(repo: &Repo) -> Vec<String> {
    stdout(&repo.ok(&["log", "--oneline"]))
        .lines()
        .map(|l| l.split_once(' ').map_or("", |(_, s)| s).to_owned())
        .collect()
}

fn head_subject(repo: &Repo) -> String {
    subjects(repo).into_iter().next().unwrap()
}

fn in_progress(repo: &Repo) -> bool {
    repo.kit_dir().join("rebase-apply").is_dir()
}

fn files(repo: &Repo) -> String {
    stdout(&repo.ok(&["ls-tree", "-r", "HEAD"]))
}

const EDIT_B: &str = "s/^pick \\(.*\\) B$/edit \\1 B/";

#[test]
fn edit_stops_after_the_commit_and_an_amend_is_kept() {
    let repo = setup();
    let ed = editor();
    let out = repo.run_env(&["rebase", "-i", "main"], &with_editor(&ed, EDIT_B));
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(stderr(&out).contains("Stopped at"), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("kit rebase --continue"),
        "{}",
        stderr(&out)
    );
    assert!(in_progress(&repo));
    assert_eq!(head_subject(&repo), "B");
    assert!(repo.path().join("b.txt").is_file());
    assert!(!repo.path().join("c.txt").exists());

    repo.ok(&["commit", "--amend", "-m", "B amended"]);
    repo.ok(&["rebase", "--continue"]);
    assert!(!in_progress(&repo));
    assert_eq!(subjects(&repo), ["C", "B amended", "A", "M", "base"]);
    let branch = stdout(&repo.ok(&["rev-parse", "--abbrev-ref", "HEAD"]));
    assert_eq!(branch.trim(), "topic");
}

#[test]
fn a_commit_made_at_an_edit_stop_sits_before_the_next_pick() {
    let repo = setup();
    let ed = editor();
    repo.ok_env(&["rebase", "-i", "main"], &with_editor(&ed, EDIT_B));
    repo.commit_file("n.txt", b"N\n", "N");
    repo.ok(&["rebase", "--continue"]);
    assert_eq!(subjects(&repo), ["C", "N", "B", "A", "M", "base"]);
}

#[test]
fn edit_on_every_commit_with_no_change_matches_a_plain_rebase() {
    let plain = setup();
    plain.ok(&["rebase", "main"]);

    let repo = setup();
    let ed = editor();
    let out = repo.run_env(
        &["rebase", "-i", "main"],
        &with_editor(&ed, "s/^pick/edit/"),
    );
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let mut stops = 1;
    while in_progress(&repo) {
        assert!(stops <= 3, "more stops than commits");
        repo.ok(&["rebase", "--continue"]);
        stops += 1;
    }
    assert_eq!(stops, 4, "one stop for each of A, B and C, then the finish");
    assert_eq!(subjects(&repo), subjects(&plain));
    assert_eq!(files(&repo), files(&plain));
}

#[test]
fn abort_at_an_edit_stop_restores_the_branch() {
    let repo = setup();
    let before = stdout(&repo.ok(&["rev-parse", "HEAD"]));
    let ed = editor();
    repo.ok_env(&["rebase", "-i", "main"], &with_editor(&ed, EDIT_B));
    repo.ok(&["rebase", "--abort"]);
    assert!(!in_progress(&repo));
    assert_eq!(stdout(&repo.ok(&["rev-parse", "HEAD"])), before);
    assert!(repo.path().join("c.txt").is_file());
    assert!(!repo.path().join("m.txt").exists());
}

#[test]
fn skip_at_an_edit_stop_is_refused_and_changes_nothing() {
    let repo = setup();
    let ed = editor();
    repo.ok_env(&["rebase", "-i", "main"], &with_editor(&ed, EDIT_B));
    let head = stdout(&repo.ok(&["rev-parse", "HEAD"]));
    let out = repo.run(&["rebase", "--skip"]);
    assert_ne!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(stdout(&repo.ok(&["rev-parse", "HEAD"])), head);
    repo.ok(&["rebase", "--continue"]);
    assert_eq!(subjects(&repo), ["C", "B", "A", "M", "base"]);
}

#[test]
fn exec_runs_after_each_commit_in_order() {
    let repo = setup();
    let log = tempfile::tempdir().unwrap();
    let log = log.path().join("order");
    let first = format!("ls *.txt | tr '\\n' ' ' >> {}", log.display());
    let second = format!("echo >> {}", log.display());
    repo.ok(&["rebase", "--exec", &first, "-x", &second, "main"]);
    assert_eq!(
        std::fs::read_to_string(&log).unwrap(),
        "a.txt base.txt m.txt \n\
         a.txt b.txt base.txt m.txt \n\
         a.txt b.txt base.txt c.txt m.txt \n"
    );
    assert_eq!(subjects(&repo), ["C", "B", "A", "M", "base"]);
}

#[test]
fn a_failing_exec_stops_after_its_line_and_continue_goes_on() {
    let repo = setup();
    let out = repo.run(&["rebase", "--exec", "test -f b.txt", "main"]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(stderr(&out).contains("test -f b.txt"), "{}", stderr(&out));
    assert!(in_progress(&repo));
    assert_eq!(head_subject(&repo), "A");
    repo.ok(&["rebase", "--continue"]);
    assert!(!in_progress(&repo));
    assert_eq!(subjects(&repo), ["C", "B", "A", "M", "base"]);
}

#[test]
fn exec_lines_in_the_todo_list_run_where_they_stand() {
    let repo = setup();
    let ed = editor();
    let marker = tempfile::tempdir().unwrap();
    let marker = marker.path().join("marker");
    let sed = format!(
        "/^pick .* A$/a\\\nexec ls *.txt | tr '\\\\n' ' ' > {}",
        marker.display()
    );
    repo.ok_env(&["rebase", "-i", "main"], &with_editor(&ed, &sed));
    assert_eq!(
        std::fs::read_to_string(&marker).unwrap(),
        "a.txt base.txt m.txt "
    );
    assert_eq!(subjects(&repo), ["C", "B", "A", "M", "base"]);
}

#[test]
fn rebase_exec_lines_show_in_the_todo_list() {
    let repo = setup();
    let seen = tempfile::tempdir().unwrap();
    let seen = seen.path().join("todo");
    let ed = editor();
    // Copy the todo list aside, then leave it as it is.
    let sed = format!("w {}", seen.display());
    repo.ok_env(
        &["rebase", "-i", "-x", "true", "main"],
        &with_editor(&ed, &sed),
    );
    let todo = std::fs::read_to_string(&seen).unwrap();
    let lines: Vec<&str> = todo
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.split_whitespace().next().unwrap())
        .collect();
    assert_eq!(lines, ["pick", "exec", "pick", "exec", "pick", "exec"]);
}

#[test]
fn an_exec_command_with_a_newline_or_an_empty_exec_line_is_refused() {
    let repo = setup();
    let head = stdout(&repo.ok(&["rev-parse", "HEAD"]));
    let out = repo.run(&["rebase", "-x", "true\nfalse", "main"]);
    assert_eq!(out.status.code(), Some(64), "{}", stderr(&out));
    let ed = editor();
    let out = repo.run_env(
        &["rebase", "-i", "main"],
        &with_editor(&ed, "/^pick .* A$/a\\\nexec"),
    );
    assert_ne!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(!in_progress(&repo));
    assert_eq!(stdout(&repo.ok(&["rev-parse", "HEAD"])), head);
}

#[test]
fn a_plain_paused_rebase_keeps_the_old_actions_format() {
    // A rebase with no edit or exec line writes the format that the current
    // release reads, so either binary can continue it.
    let repo = Repo::new();
    repo.commit_file("f.txt", b"base\n", "base");
    repo.ok(&["branch", "topic"]);
    repo.commit_file("f.txt", b"main\n", "main");
    repo.ok(&["switch", "topic"]);
    repo.commit_file("f.txt", b"topic\n", "topic");
    let out = repo.run(&["rebase", "main"]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    let actions = std::fs::read_to_string(repo.kit_dir().join("rebase-apply/actions")).unwrap();
    assert_eq!(actions, "pick\n");
    repo.write("f.txt", b"resolved\n");
    repo.ok(&["add", "f.txt"]);
    repo.ok(&["rebase", "--continue"]);
    assert_eq!(subjects(&repo), ["topic", "main", "base"]);
}

#[test]
fn an_edit_stop_writes_the_versioned_actions_format() {
    let repo = setup();
    let ed = editor();
    repo.ok_env(
        &["rebase", "-i", "-x", "true", "main"],
        &with_editor(&ed, EDIT_B),
    );
    let dir = repo.kit_dir().join("rebase-apply");
    let actions = std::fs::read_to_string(dir.join("actions")).unwrap();
    assert_eq!(
        actions,
        "kit-rebase-actions 2\nexec true\npick\nexec true\n"
    );
    assert_eq!(
        std::fs::read_to_string(dir.join("todo"))
            .unwrap()
            .lines()
            .count(),
        1
    );
    repo.ok(&["rebase", "--continue"]);
    assert!(!in_progress(&repo));
}

#[test]
fn json_reports_an_edit_stop_and_a_failed_exec() {
    let repo = setup();
    let ed = editor();
    let out = repo.run_env(
        &["rebase", "-i", "--format=json", "main"],
        &with_editor(&ed, EDIT_B),
    );
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let head = stdout(&repo.ok(&["rev-parse", "HEAD"]));
    assert_eq!(
        stdout(&out).trim(),
        format!(
            r#"{{"ok":true,"kind":"stopped","commit":"{}"}}"#,
            head.trim()
        )
    );
    repo.ok(&["rebase", "--abort"]);

    let out = repo.run(&[
        "rebase",
        "--format=json",
        "-x",
        "echo noise; exit 3",
        "main",
    ]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(stderr(&out).contains("noise"), "{}", stderr(&out));
    assert_eq!(
        stdout(&out).trim(),
        r#"{"ok":false,"kind":"exec-failed","command":"echo noise; exit 3","status":3,"error":"rebase stopped: exec command failed"}"#
    );
}
