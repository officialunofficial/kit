//! `kit am`: apply a mailbox of patch mails as commits (SPEC-PATCH §5, §6).
//!
//! The mails come from real `git format-patch` when git is on `PATH`, and
//! from hand-written mailboxes otherwise. The cases pin the commits, the
//! author, the stop on a patch that does not apply, `--continue`, `--skip`,
//! `--abort` and the operations that refuse while `am` is paused.
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

fn read(repo: &Repo, rel: &str) -> Option<String> {
    std::fs::read_to_string(repo.path().join(rel)).ok()
}

fn save(repo: &Repo, name: &str, text: &str) -> String {
    let path = repo.xdg().join(name);
    std::fs::write(&path, text).unwrap();
    path.to_string_lossy().into_owned()
}

fn rev(repo: &Repo, spec: &str) -> String {
    stdout(&repo.ok(&["rev-parse", spec])).trim().to_owned()
}

fn subjects(repo: &Repo, n: usize) -> Vec<String> {
    let out = stdout(&repo.ok(&["log", "--oneline", "-n", &n.to_string()]));
    out.lines()
        .map(|l| l.split_once(' ').map_or(l, |(_, s)| s).to_owned())
        .collect()
}

/// A mail as `git format-patch` writes it.
fn mail(from: &str, subject: &str, body: &str, diff: &str) -> String {
    format!(
        "From 0000000000000000000000000000000000000000 Mon Sep 17 00:00:00 2001\n\
         From: {from}\n\
         Date: Thu, 1 Jan 2026 00:00:00 +0000\n\
         Subject: {subject}\n\
         \n\
         {body}---\n \
         a.txt | 2 +-\n \
         1 file changed, 1 insertion(+), 1 deletion(-)\n\
         \n\
         {diff}\
         -- \n\
         2.40.0\n\
         \n"
    )
}

fn edit(old: &str, new: &str) -> String {
    format!(
        "diff --git a/a.txt b/a.txt\n\
         --- a/a.txt\n\
         +++ b/a.txt\n\
         @@ -1,3 +1,3 @@\n \
         top\n\
         -{old}\n\
         +{new}\n \
         bottom\n"
    )
}

/// `a.txt` is `top`, `one`, `bottom`.
fn base() -> Repo {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"top\none\nbottom\n", "base");
    repo
}

/// Three mails that turn `one` into `two`, `three` and `four`.
fn series() -> String {
    [
        mail(
            "Ann Author <ann@example.com>",
            "[PATCH 1/3] Say two",
            "The first change.\n\n",
            &edit("one", "two"),
        ),
        mail(
            "=?UTF-8?q?Bj=C3=B6rn?= <bjorn@example.com>",
            "[PATCH 2/3] Say three",
            "",
            &edit("two", "three"),
        ),
        mail(
            "Ann Author <ann@example.com>",
            "[PATCH 3/3] Say four",
            "",
            &edit("three", "four"),
        ),
    ]
    .concat()
}

#[test]
fn a_series_becomes_one_commit_per_mail() {
    let repo = base();
    let mbox = save(&repo, "series.mbox", &series());
    let out = repo.run(&["am", &mbox]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(read(&repo, "a.txt").unwrap(), "top\nfour\nbottom\n");
    assert_eq!(
        subjects(&repo, 4),
        ["Say four", "Say three", "Say two", "base"]
    );
    let log = stdout(&repo.ok(&["log", "-n", "3"]));
    assert!(
        log.contains("Author: Ann Author <ann@example.com>"),
        "{log}"
    );
    assert!(log.contains("Author: Björn <bjorn@example.com>"), "{log}");
    assert!(log.contains("The first change."), "{log}");
    assert!(!log.contains("1 file changed"), "{log}");
    assert!(!repo.kit_dir().join("am").exists());
    // The index and the worktree agree with the last commit.
    assert_eq!(stdout(&repo.ok(&["status", "--porcelain"])), "");
}

#[test]
fn a_mail_that_does_not_apply_stops_and_skip_goes_on() {
    let repo = base();
    let text = [
        mail(
            "A <a@example.com>",
            "[PATCH 1/3] Say two",
            "",
            &edit("one", "two"),
        ),
        mail(
            "A <a@example.com>",
            "[PATCH 2/3] Bad",
            "",
            &edit("nope", "x"),
        ),
        mail(
            "A <a@example.com>",
            "[PATCH 3/3] Say four",
            "",
            &edit("two", "four"),
        ),
    ]
    .concat();
    let mbox = save(&repo, "series.mbox", &text);
    let out = repo.run(&["am", &mbox]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(stderr(&out).contains("Bad"), "{}", stderr(&out));
    // The first mail is committed; the second changed nothing.
    assert_eq!(subjects(&repo, 2), ["Say two", "base"]);
    assert_eq!(read(&repo, "a.txt").unwrap(), "top\ntwo\nbottom\n");
    assert_eq!(stdout(&repo.ok(&["status", "--porcelain"])), "");

    repo.ok(&["am", "--skip"]);
    assert_eq!(subjects(&repo, 3), ["Say four", "Say two", "base"]);
    assert_eq!(read(&repo, "a.txt").unwrap(), "top\nfour\nbottom\n");
    assert!(!repo.kit_dir().join("am").exists());
}

#[test]
fn continue_commits_a_hand_applied_mail() {
    let repo = base();
    let text = [
        mail(
            "A <a@example.com>",
            "[PATCH 1/2] Fix by hand",
            "",
            &edit("nope", "two"),
        ),
        mail(
            "A <a@example.com>",
            "[PATCH 2/2] Say four",
            "",
            &edit("two", "four"),
        ),
    ]
    .concat();
    let mbox = save(&repo, "series.mbox", &text);
    let out = repo.run(&["am", &mbox]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));

    // Nothing staged: continue refuses.
    let out = repo.run(&["am", "--continue"]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));

    repo.write("a.txt", b"top\ntwo\nbottom\n");
    repo.ok(&["add", "a.txt"]);
    repo.ok(&["am", "--continue"]);
    assert_eq!(subjects(&repo, 3), ["Say four", "Fix by hand", "base"]);
    let log = stdout(&repo.ok(&["log", "-n", "2"]));
    assert!(log.contains("Author: A <a@example.com>"), "{log}");
    assert!(!repo.kit_dir().join("am").exists());
}

#[test]
fn abort_returns_to_where_am_started() {
    let repo = base();
    let start = rev(&repo, "HEAD");
    let text = [
        mail(
            "A <a@example.com>",
            "[PATCH 1/2] Say two",
            "",
            &edit("one", "two"),
        ),
        mail(
            "A <a@example.com>",
            "[PATCH 2/2] Bad",
            "",
            &edit("nope", "x"),
        ),
    ]
    .concat();
    let mbox = save(&repo, "series.mbox", &text);
    let out = repo.run(&["am", &mbox]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert_ne!(rev(&repo, "HEAD"), start);

    // A change that is not committed blocks the abort, and nothing moves.
    repo.write("a.txt", b"local\n");
    let out = repo.run(&["am", "--abort"]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert_eq!(read(&repo, "a.txt").unwrap(), "local\n");
    assert!(repo.kit_dir().join("am").exists());

    repo.ok(&["restore", "--force", "a.txt"]);
    repo.ok(&["am", "--abort"]);
    assert_eq!(rev(&repo, "HEAD"), start);
    assert_eq!(read(&repo, "a.txt").unwrap(), "top\none\nbottom\n");
    assert!(!repo.kit_dir().join("am").exists());
}

#[test]
fn other_operations_refuse_while_am_is_paused() {
    let repo = base();
    repo.ok(&["branch", "side"]);
    let mbox = save(
        &repo,
        "bad.mbox",
        &mail("A <a@example.com>", "[PATCH] Bad", "", &edit("nope", "x")),
    );
    let out = repo.run(&["am", &mbox]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    for args in [&["merge", "side"][..], &["am", &mbox], &["rebase", "side"]] {
        let out = repo.run(args);
        assert!(!out.status.success(), "{args:?} ran while am was paused");
        assert!(stderr(&out).contains("am"), "{args:?}: {}", stderr(&out));
    }
    // With no paused am, the flags that resume one refuse.
    repo.ok(&["am", "--abort"]);
    for flag in ["--continue", "--skip", "--abort"] {
        let out = repo.run(&["am", flag]);
        assert_eq!(out.status.code(), Some(1), "{flag}: {}", stderr(&out));
    }
}

#[test]
fn unsupported_mails_are_refused_before_any_commit() {
    let repo = base();
    let start = rev(&repo, "HEAD");
    let encoded = mail("A <a@example.com>", "[PATCH] B64", "", &edit("one", "two")).replace(
        "Subject: [PATCH] B64\n",
        "Subject: [PATCH] B64\nContent-Transfer-Encoding: base64\n",
    );
    for (text, what) in [
        (encoded, "encoding"),
        (
            "From 0 Mon Sep 17 00:00:00 2001\nFrom: A <a@example.com>\nSubject: hi\n\nno diff here\n"
                .to_owned(),
            "no patch",
        ),
    ] {
        let mbox = save(&repo, "bad.mbox", &text);
        let out = repo.run(&["am", &mbox]);
        assert_eq!(out.status.code(), Some(65), "{what}: {}", stderr(&out));
        assert!(stderr(&out).contains(what), "{what}: {}", stderr(&out));
        assert_eq!(rev(&repo, "HEAD"), start);
        assert!(!repo.kit_dir().join("am").exists());
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

#[test]
fn a_series_from_git_format_patch_applies() {
    if !git_available() {
        return;
    }
    let home = tempfile::tempdir().unwrap();
    let g = tempfile::tempdir().unwrap();
    let gdir = g.path();
    git(gdir, home.path(), &["init", "-q", "-b", "main"]);
    std::fs::write(gdir.join("a.txt"), "top\none\nbottom\n").unwrap();
    git(gdir, home.path(), &["add", "a.txt"]);
    git(gdir, home.path(), &["commit", "-q", "-m", "base"]);
    let steps = [
        (
            "a.txt",
            "top\ntwo\nbottom\n",
            "Say two\n\nWith a body line.",
        ),
        ("new.txt", "fresh\n", "Add new file"),
        ("a.txt", "top\nthree\nbottom\n", "Say three"),
    ];
    for (rel, body, msg) in steps {
        std::fs::write(gdir.join(rel), body).unwrap();
        git(gdir, home.path(), &["add", rel]);
        git(gdir, home.path(), &["commit", "-q", "-m", msg]);
    }
    let mbox = stdout(&git(
        gdir,
        home.path(),
        &["format-patch", "--stdout", "HEAD~3"],
    ));

    let repo = base();
    let path = save(&repo, "git.mbox", &mbox);
    let out = repo.run(&["am", &path]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(
        subjects(&repo, 4),
        ["Say three", "Add new file", "Say two", "base"]
    );
    assert_eq!(read(&repo, "a.txt").unwrap(), "top\nthree\nbottom\n");
    assert_eq!(read(&repo, "new.txt").unwrap(), "fresh\n");
    let log = stdout(&repo.ok(&["log", "-n", "3"]));
    assert!(log.contains("Author: parity <parity@example.com>"), "{log}");
    assert!(log.contains("With a body line."), "{log}");
}
