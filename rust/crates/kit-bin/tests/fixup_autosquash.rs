//! `kit commit --fixup` and `--squash`, and `kit rebase --autosquash`.
//!
//! `commit --fixup <rev>` writes `fixup! <subject of rev>` and `--squash`
//! writes `squash! <subject of rev>`. `rebase --autosquash` moves each such
//! commit to just after the commit it names and folds it in. The stub
//! `$EDITOR` copies each todo list to `$TODO_LOG` and each message seed to
//! `$SEED_LOG`, rewrites a todo list with the `sed` program in `$SED`, and
//! replaces a message with `$MSG` when it is set.

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
    fn todo_log(&self) -> PathBuf {
        self.dir.path().join("todo.log")
    }

    fn seed_log(&self) -> PathBuf {
        self.dir.path().join("seed.log")
    }

    fn todo(&self) -> String {
        std::fs::read_to_string(self.todo_log()).unwrap_or_default()
    }

    fn seeds(&self) -> String {
        std::fs::read_to_string(self.seed_log()).unwrap_or_default()
    }

    fn env<'a>(&'a self, sed: &'a str, msg: Option<&'a str>) -> Vec<(&'a str, String)> {
        let mut env = vec![
            ("GIT_EDITOR", self.path.to_str().unwrap().to_owned()),
            ("SED", sed.to_owned()),
            ("TODO_LOG", self.todo_log().to_str().unwrap().to_owned()),
            ("SEED_LOG", self.seed_log().to_str().unwrap().to_owned()),
        ];
        if let Some(msg) = msg {
            env.push(("MSG", msg.to_owned()));
        }
        env
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
else
    cat "$f" >> "$SEED_LOG"
    if [ -n "${MSG+set}" ]; then
        printf '%s' "$MSG" > "$f"
    fi
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

fn message(repo: &Repo, rev: &str) -> String {
    let out = repo.ok(&["log", "--format=json", "-n", "1", rev]);
    let line = stdout(&out);
    let value: serde_json::Value = serde_json::from_str(line.lines().next().unwrap()).unwrap();
    value["message"].as_str().unwrap().to_owned()
}

fn rev(repo: &Repo, spec: &str) -> String {
    stdout(&repo.ok(&["rev-parse", spec])).trim().to_owned()
}

fn files(repo: &Repo, rev: &str) -> String {
    stdout(&repo.ok(&["ls-tree", "-r", rev]))
}

/// The `ls-tree` line of one path.
fn entry(repo: &Repo, rev: &str, path: &str) -> String {
    files(repo, rev)
        .lines()
        .find(|l| l.ends_with(&format!("\t{path}")) || l.ends_with(&format!(" {path}")))
        .unwrap_or_default()
        .to_owned()
}

fn in_progress(repo: &Repo) -> bool {
    repo.kit_dir().join("rebase-apply").is_dir()
}

/// Change `path` and commit it with `kit commit <flag> <target>`.
fn commit_fixup(repo: &Repo, path: &str, body: &[u8], flag: &str, target: &str) {
    repo.write(path, body);
    repo.ok(&["add", path]);
    repo.ok(&["commit", flag, target]);
}

// --- commit --fixup and --squash -------------------------------------------

#[test]
fn fixup_names_the_subject_of_the_target_and_opens_no_editor() {
    let repo = setup();
    repo.write("a.txt", b"A fixed\n");
    repo.ok(&["add", "a.txt"]);
    // An editor that fails would fail the commit if it ran.
    repo.ok_env(&["commit", "--fixup", "HEAD~2"], &[("GIT_EDITOR", "false")]);
    assert_eq!(subjects(&repo)[0], "fixup! A");
    assert_eq!(message(&repo, "HEAD").trim_end(), "fixup! A");
}

#[test]
fn fixup_puts_the_message_option_in_the_body() {
    let repo = setup();
    repo.write("a.txt", b"A fixed\n");
    repo.ok(&["add", "a.txt"]);
    repo.ok(&["commit", "--fixup", "HEAD~2", "-m", "why it changed"]);
    assert_eq!(
        message(&repo, "HEAD").trim_end(),
        "fixup! A\n\nwhy it changed"
    );
}

#[test]
fn squash_opens_the_editor_on_the_subject() {
    let repo = setup();
    let ed = editor();
    repo.write("a.txt", b"A more\n");
    repo.ok(&["add", "a.txt"]);
    let out = run_with(&repo, &["commit", "--squash", "HEAD~2"], &ed.env("", None));
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(ed.seeds().starts_with("squash! A"), "{}", ed.seeds());
    assert_eq!(subjects(&repo)[0], "squash! A");
}

#[test]
fn squash_takes_its_body_from_the_message_option() {
    let repo = setup();
    repo.write("a.txt", b"A more\n");
    repo.ok(&["add", "a.txt"]);
    repo.ok_env(
        &["commit", "--squash", "HEAD~2", "-m", "more of A"],
        &[("GIT_EDITOR", "false")],
    );
    assert_eq!(message(&repo, "HEAD").trim_end(), "squash! A\n\nmore of A");
}

#[test]
fn fixup_refuses_amend_squash_and_a_missing_revision() {
    let repo = setup();
    repo.write("a.txt", b"A fixed\n");
    repo.ok(&["add", "a.txt"]);
    let head = rev(&repo, "HEAD");
    for args in [
        &["commit", "--fixup", "HEAD~1", "--amend"][..],
        &["commit", "--fixup", "HEAD~1", "--squash", "HEAD~1"][..],
        &["commit", "--squash", "HEAD~1", "--amend"][..],
    ] {
        let out = repo.run(args);
        assert_eq!(out.status.code(), Some(64), "{args:?}: {}", stderr(&out));
    }
    let out = repo.run(&["commit", "--fixup", "no-such-rev"]);
    assert!(!out.status.success(), "{}", stderr(&out));
    assert_eq!(rev(&repo, "HEAD"), head, "a refused commit moved HEAD");
}

// --- rebase --autosquash ----------------------------------------------------

#[test]
fn autosquash_folds_a_fixup_into_its_target() {
    let repo = setup();
    commit_fixup(&repo, "a.txt", b"A fixed\n", "--fixup", "HEAD~2");
    let fixed = entry(&repo, "HEAD", "a.txt");
    let out = repo.run(&["rebase", "--autosquash", "main"]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(!in_progress(&repo));
    assert_eq!(subjects(&repo), ["C", "B", "A", "M", "base"]);
    assert_eq!(entry(&repo, "HEAD~2", "a.txt"), fixed);
    assert_eq!(message(&repo, "HEAD~2").trim_end(), "A");
}

#[test]
fn autosquash_keeps_the_final_tree() {
    let plain = setup();
    commit_fixup(&plain, "a.txt", b"A fixed\n", "--fixup", "HEAD~2");
    commit_fixup(&plain, "b.txt", b"B fixed\n", "--fixup", "HEAD~2");
    plain.ok(&["rebase", "main"]);

    let repo = setup();
    commit_fixup(&repo, "a.txt", b"A fixed\n", "--fixup", "HEAD~2");
    commit_fixup(&repo, "b.txt", b"B fixed\n", "--fixup", "HEAD~2");
    repo.ok(&["rebase", "--autosquash", "main"]);
    assert_eq!(files(&repo, "HEAD"), files(&plain, "HEAD"));
    assert_eq!(subjects(&repo), ["C", "B", "A", "M", "base"]);
}

#[test]
fn autosquash_combines_a_squash_message_through_the_editor() {
    let repo = setup();
    let ed = editor();
    commit_fixup(&repo, "a.txt", b"A more\n", "--squash", "HEAD~2");
    // `--squash` opened the stub editor on its seed; start a clean log.
    let _ = std::fs::remove_file(ed.seed_log());
    let out = run_with(
        &repo,
        &["rebase", "--autosquash", "main"],
        &ed.env("", Some("A, with more")),
    );
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let seeds = ed.seeds();
    assert!(seeds.contains("A\n"), "{seeds}");
    assert!(seeds.contains("squash! A"), "{seeds}");
    assert_eq!(subjects(&repo), ["C", "B", "A, with more", "M", "base"]);
}

#[test]
fn a_nested_fixup_targets_the_innermost_subject() {
    let repo = setup();
    commit_fixup(&repo, "a.txt", b"A fixed\n", "--fixup", "HEAD~2");
    // `--fixup` of the fixup writes `fixup! fixup! A`.
    commit_fixup(&repo, "a.txt", b"A fixed twice\n", "--fixup", "HEAD");
    assert_eq!(subjects(&repo)[0], "fixup! fixup! A");
    let fixed = entry(&repo, "HEAD", "a.txt");
    repo.ok(&["rebase", "--autosquash", "main"]);
    assert_eq!(subjects(&repo), ["C", "B", "A", "M", "base"]);
    assert_eq!(entry(&repo, "HEAD~2", "a.txt"), fixed);
}

#[test]
fn several_fixups_of_one_target_keep_their_order() {
    let repo = setup();
    commit_fixup(&repo, "a.txt", b"A one\n", "--fixup", "HEAD~2");
    commit_fixup(&repo, "a.txt", b"A two\n", "--fixup", "HEAD~3");
    let last = entry(&repo, "HEAD", "a.txt");
    repo.ok(&["rebase", "--autosquash", "main"]);
    assert_eq!(subjects(&repo), ["C", "B", "A", "M", "base"]);
    assert_eq!(entry(&repo, "HEAD~2", "a.txt"), last);
}

#[test]
fn a_fixup_whose_target_is_outside_the_range_stays_a_pick() {
    let repo = setup();
    commit_fixup(&repo, "base.txt", b"base fixed\n", "--fixup", "main~1");
    assert_eq!(subjects(&repo)[0], "fixup! base");
    repo.ok(&["rebase", "--autosquash", "main"]);
    assert_eq!(subjects(&repo), ["fixup! base", "C", "B", "A", "M", "base"]);
}

#[test]
fn a_fixup_can_name_its_target_by_id_prefix() {
    let repo = setup();
    let a = rev(&repo, "HEAD~2");
    repo.write("a.txt", b"A fixed\n");
    repo.ok(&["add", "a.txt"]);
    repo.ok(&["commit", "-m", &format!("fixup! {}", &a[..10])]);
    repo.ok(&["rebase", "--autosquash", "main"]);
    assert_eq!(subjects(&repo), ["C", "B", "A", "M", "base"]);
}

#[test]
fn a_fixup_can_name_its_target_by_subject_prefix() {
    let repo = setup();
    repo.commit_file("d.txt", b"D\n", "Add the parser for dates");
    repo.write("d.txt", b"D fixed\n");
    repo.ok(&["add", "d.txt"]);
    repo.ok(&["commit", "-m", "fixup! Add the parser"]);
    repo.ok(&["rebase", "--autosquash", "main"]);
    assert_eq!(
        subjects(&repo),
        ["Add the parser for dates", "C", "B", "A", "M", "base"]
    );
}

#[test]
fn interactive_autosquash_opens_the_todo_list_arranged() {
    let repo = setup();
    let ed = editor();
    commit_fixup(&repo, "a.txt", b"A fixed\n", "--fixup", "HEAD~2");
    let out = run_with(
        &repo,
        &["rebase", "-i", "--autosquash", "main"],
        &ed.env("", None),
    );
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let todo = ed.todo();
    let steps: Vec<(&str, &str)> = todo
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            let mut parts = l.splitn(3, ' ');
            let verb = parts.next().unwrap();
            let _id = parts.next();
            (verb, parts.next().unwrap_or(""))
        })
        .collect();
    assert_eq!(
        steps,
        [
            ("pick", "A"),
            ("fixup", "fixup! A"),
            ("pick", "B"),
            ("pick", "C")
        ],
        "{todo}"
    );
    assert_eq!(subjects(&repo), ["C", "B", "A", "M", "base"]);
}

#[test]
fn rebase_autosquash_config_applies_to_interactive_rebases_only() {
    let repo = setup();
    let ed = editor();
    repo.ok(&["config", "rebase.autosquash", "true"]);
    commit_fixup(&repo, "a.txt", b"A fixed\n", "--fixup", "HEAD~2");
    let topic = rev(&repo, "HEAD");

    // Without `-i` the config does nothing.
    repo.ok(&["rebase", "main"]);
    assert_eq!(subjects(&repo), ["fixup! A", "C", "B", "A", "M", "base"]);

    // With `-i` it arranges the todo list.
    repo.ok(&["reset", "--hard", &topic]);
    let out = run_with(&repo, &["rebase", "-i", "main"], &ed.env("", None));
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(subjects(&repo), ["C", "B", "A", "M", "base"]);

    // `--no-autosquash` overrides it.
    repo.ok(&["reset", "--hard", &topic]);
    let out = run_with(
        &repo,
        &["rebase", "-i", "--no-autosquash", "main"],
        &ed.env("", None),
    );
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(subjects(&repo), ["fixup! A", "C", "B", "A", "M", "base"]);
}

#[test]
fn autosquash_refuses_to_combine_with_continue() {
    let repo = setup();
    let out = repo.run(&["rebase", "--continue", "--autosquash"]);
    assert_eq!(out.status.code(), Some(64), "{}", stderr(&out));
}
