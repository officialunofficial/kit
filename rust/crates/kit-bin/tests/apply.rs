//! `kit apply`: apply a unified diff to the worktree, the index or both,
//! all or nothing (SPEC-PATCH).
//!
//! Fixed cases pin the targets, the flags and the refusals. A differential
//! case applies a patch that real `git diff` wrote, when git is on `PATH`.
//! A property test checks that a patch from `kit diff A B` turns A into B,
//! and that `-R` turns it back.
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

/// The patch from the commit before `HEAD` to `HEAD`, after which the
/// branch, the index and the files go back to the earlier commit.
fn patch_of_last_commit(repo: &Repo) -> String {
    let patch = stdout(&repo.ok(&["diff", "HEAD~1", "HEAD"]));
    repo.ok(&["reset", "--hard", "HEAD~1"]);
    patch
}

/// `a.txt`, `b.txt`, `run.sh` and `old.txt` committed as a base.
fn base() -> Repo {
    let repo = Repo::new();
    repo.write("a.txt", b"one\ntwo\nthree\nfour\nfive\nsix\nseven\n");
    repo.write("b.txt", b"keep\n");
    repo.write("run.sh", b"echo hi\n");
    repo.write("old.txt", b"moved content\nline two\nline three\n");
    repo.ok(&["add", "a.txt", "b.txt", "run.sh", "old.txt"]);
    repo.ok(&["commit", "-m", "base"]);
    repo
}

#[test]
fn a_patch_from_kit_diff_applies_to_the_worktree() {
    let repo = base();
    repo.write("a.txt", b"one\nTWO\nthree\nfour\nfive\nsix\nSEVEN\n");
    repo.write("new.txt", b"fresh\n");
    std::fs::remove_file(repo.path().join("b.txt")).unwrap();
    repo.ok(&["add", "a.txt", "new.txt"]);
    repo.ok(&["rm", "b.txt"]);
    repo.ok(&["commit", "-m", "change"]);
    let patch = save(&repo, "p.diff", &patch_of_last_commit(&repo));

    let out = repo.run(&["apply", &patch]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(
        read(&repo, "a.txt").unwrap(),
        "one\nTWO\nthree\nfour\nfive\nsix\nSEVEN\n"
    );
    assert_eq!(read(&repo, "new.txt").unwrap(), "fresh\n");
    assert_eq!(read(&repo, "b.txt"), None);
    // The index is untouched: the changes are unstaged.
    assert_eq!(stdout(&repo.ok(&["diff", "--cached", "--name-only"])), "");
}

#[test]
fn renames_and_mode_changes_apply() {
    let repo = base();
    repo.ok(&["mv", "old.txt", "renamed.txt"]);
    repo.write(
        "renamed.txt",
        b"moved content\nline two\nline three\nadded\n",
    );
    repo.ok(&["add", "renamed.txt"]);
    repo.write("run.sh", b"echo hi\n");
    set_executable(&repo.path().join("run.sh"));
    repo.ok(&["add", "run.sh"]);
    repo.ok(&["commit", "-m", "rename and chmod"]);
    let text = patch_of_last_commit(&repo);
    assert!(text.contains("rename from old.txt"), "{text}");
    assert!(text.contains("new mode 100755"), "{text}");
    let patch = save(&repo, "p.diff", &text);

    repo.ok(&["apply", "--index", &patch]);
    assert_eq!(read(&repo, "old.txt"), None);
    assert_eq!(
        read(&repo, "renamed.txt").unwrap(),
        "moved content\nline two\nline three\nadded\n"
    );
    assert!(is_executable(&repo.path().join("run.sh")));
    let staged = stdout(&repo.ok(&["diff", "--cached", "--name-status"]));
    assert!(staged.contains("renamed.txt"), "{staged}");
    assert!(staged.contains("run.sh"), "{staged}");
}

#[cfg(unix)]
fn set_executable(p: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755)).unwrap();
}

#[cfg(unix)]
fn is_executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).unwrap().permissions().mode() & 0o111 != 0
}

#[test]
fn a_hunk_applies_at_an_offset() {
    let repo = base();
    repo.write("a.txt", b"one\ntwo\nthree\nfour\nfive\nsix\nSEVEN\n");
    repo.ok(&["add", "a.txt"]);
    repo.ok(&["commit", "-m", "edit"]);
    let patch = save(&repo, "p.diff", &patch_of_last_commit(&repo));
    repo.write(
        "a.txt",
        b"zero\nminus\none\ntwo\nthree\nfour\nfive\nsix\nseven\n",
    );
    repo.ok(&["apply", &patch]);
    assert_eq!(
        read(&repo, "a.txt").unwrap(),
        "zero\nminus\none\ntwo\nthree\nfour\nfive\nsix\nSEVEN\n"
    );
}

#[test]
fn a_missing_final_newline_round_trips() {
    let repo = base();
    repo.write("b.txt", b"keep\nno newline");
    repo.ok(&["add", "b.txt"]);
    repo.ok(&["commit", "-m", "no newline"]);
    let text = patch_of_last_commit(&repo);
    assert!(text.contains("\\ No newline at end of file"), "{text}");
    let patch = save(&repo, "p.diff", &text);
    repo.ok(&["apply", &patch]);
    assert_eq!(read(&repo, "b.txt").unwrap(), "keep\nno newline");
    repo.ok(&["apply", "-R", &patch]);
    assert_eq!(read(&repo, "b.txt").unwrap(), "keep\n");
}

#[test]
fn cached_changes_the_index_only() {
    let repo = base();
    repo.write("a.txt", b"one\ntwo\nthree\nfour\nfive\nsix\nSEVEN\n");
    repo.ok(&["add", "a.txt"]);
    repo.ok(&["commit", "-m", "edit"]);
    let patch = save(&repo, "p.diff", &patch_of_last_commit(&repo));
    repo.ok(&["apply", "--cached", &patch]);
    assert_eq!(
        read(&repo, "a.txt").unwrap(),
        "one\ntwo\nthree\nfour\nfive\nsix\nseven\n"
    );
    assert_eq!(
        stdout(&repo.ok(&["diff", "--cached", "--name-only"])),
        "a.txt\n"
    );
}

#[test]
fn index_needs_the_file_to_match_the_index() {
    let repo = base();
    repo.write("a.txt", b"one\ntwo\nthree\nfour\nfive\nsix\nSEVEN\n");
    repo.ok(&["add", "a.txt"]);
    repo.ok(&["commit", "-m", "edit"]);
    let patch = save(&repo, "p.diff", &patch_of_last_commit(&repo));
    repo.write("a.txt", b"one\ntwo\nthree\nfour\nfive\nsix\nseven\nlocal\n");
    let out = repo.run(&["apply", "--index", &patch]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(stderr(&out).contains("a.txt"), "{}", stderr(&out));
    assert_eq!(
        read(&repo, "a.txt").unwrap(),
        "one\ntwo\nthree\nfour\nfive\nsix\nseven\nlocal\n"
    );
}

#[test]
fn check_writes_nothing() {
    let repo = base();
    repo.write("a.txt", b"one\nTWO\nthree\nfour\nfive\nsix\nseven\n");
    repo.ok(&["add", "a.txt"]);
    repo.ok(&["commit", "-m", "edit"]);
    let patch = save(&repo, "p.diff", &patch_of_last_commit(&repo));
    repo.ok(&["apply", "--check", &patch]);
    assert_eq!(
        read(&repo, "a.txt").unwrap(),
        "one\ntwo\nthree\nfour\nfive\nsix\nseven\n"
    );
    repo.write("a.txt", b"different\n");
    let out = repo.run(&["apply", "--check", &patch]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert_eq!(read(&repo, "a.txt").unwrap(), "different\n");
}

#[test]
fn one_bad_hunk_leaves_every_file_as_it_was() {
    let repo = base();
    repo.write("a.txt", b"one\nTWO\nthree\nfour\nfive\nsix\nseven\n");
    repo.write("b.txt", b"KEEP\n");
    repo.ok(&["add", "a.txt", "b.txt"]);
    repo.ok(&["commit", "-m", "two files"]);
    let patch = save(&repo, "p.diff", &patch_of_last_commit(&repo));
    // `b.txt` no longer matches its hunk; `a.txt` still would.
    repo.write("b.txt", b"changed\n");
    let index_before = std::fs::read(repo.kit_dir().join("index")).ok();
    let out = repo.run(&["apply", "--index", &patch]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    let out = repo.run(&["apply", &patch]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(stderr(&out).contains("b.txt"), "{}", stderr(&out));
    assert_eq!(
        read(&repo, "a.txt").unwrap(),
        "one\ntwo\nthree\nfour\nfive\nsix\nseven\n"
    );
    assert_eq!(read(&repo, "b.txt").unwrap(), "changed\n");
    assert_eq!(
        std::fs::read(repo.kit_dir().join("index")).ok(),
        index_before
    );
}

#[test]
fn reverse_undoes_the_patch() {
    let repo = base();
    repo.write("a.txt", b"one\nTWO\nthree\nfour\nfive\nsix\nseven\n");
    repo.write("new.txt", b"fresh\n");
    repo.ok(&["add", "a.txt", "new.txt"]);
    repo.ok(&["commit", "-m", "edit"]);
    let patch = save(
        &repo,
        "p.diff",
        &stdout(&repo.ok(&["diff", "HEAD~1", "HEAD"])),
    );
    repo.ok(&["apply", "-R", &patch]);
    assert_eq!(
        read(&repo, "a.txt").unwrap(),
        "one\ntwo\nthree\nfour\nfive\nsix\nseven\n"
    );
    assert_eq!(read(&repo, "new.txt"), None);
}

#[test]
fn stat_prints_a_summary_and_applies_nothing() {
    let repo = base();
    repo.write("a.txt", b"one\nTWO\nthree\nfour\nfive\nsix\nseven\neight\n");
    repo.ok(&["add", "a.txt"]);
    repo.ok(&["commit", "-m", "edit"]);
    let patch = save(&repo, "p.diff", &patch_of_last_commit(&repo));
    let out = stdout(&repo.ok(&["apply", "--stat", &patch]));
    assert!(out.contains("a.txt | 3 ++-"), "{out}");
    assert!(
        out.contains("1 file changed, 2 insertions(+), 1 deletion(-)"),
        "{out}"
    );
    assert_eq!(
        read(&repo, "a.txt").unwrap(),
        "one\ntwo\nthree\nfour\nfive\nsix\nseven\n"
    );
}

#[test]
fn malformed_and_unsupported_patches_are_refused() {
    let repo = base();
    let cases = [
        (
            "diff --git a/a.txt b/a.txt\n--- a/a.txt\n+++ b/a.txt\n@@ -1,2 +1,2 @@\n one\n-two\n+TWO\n",
            "count",
        ),
        (
            "diff --git a/b.bin b/b.bin\nindex 1..2 100644\nGIT binary patch\nliteral 3\nKcmZQz\n",
            "binary",
        ),
        (
            "diff --git a/../x b/../x\n--- a/../x\n+++ b/../x\n@@ -0,0 +1 @@\n+x\n",
            "path",
        ),
        ("not a patch at all\n", "no patch"),
    ];
    for (text, what) in cases {
        let patch = save(&repo, "bad.diff", text);
        let out = repo.run(&["apply", &patch]);
        assert_eq!(out.status.code(), Some(65), "{what}: {}", stderr(&out));
        assert!(stderr(&out).contains(what), "{what}: {}", stderr(&out));
    }
    assert_eq!(
        read(&repo, "a.txt").unwrap(),
        "one\ntwo\nthree\nfour\nfive\nsix\nseven\n"
    );
}

#[test]
fn usage_errors_exit_64() {
    let repo = base();
    for args in [&["apply"][..], &["apply", "--cached", "--index", "x"]] {
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
        .output()
        .unwrap();
    assert!(out.status.success(), "git {args:?}: {}", stderr(&out));
    out
}

#[test]
fn a_patch_from_git_diff_applies() {
    if !git_available() {
        return;
    }
    let home = tempfile::tempdir().unwrap();
    let g = tempfile::tempdir().unwrap();
    let gdir = g.path();
    git(gdir, home.path(), &["init", "-q", "-b", "main"]);
    let repo = base();
    for rel in ["a.txt", "b.txt", "run.sh", "old.txt"] {
        std::fs::copy(repo.path().join(rel), gdir.join(rel)).unwrap();
    }
    git(gdir, home.path(), &["add", "."]);
    git(gdir, home.path(), &["commit", "-q", "-m", "base"]);
    std::fs::write(
        gdir.join("a.txt"),
        "one\nTWO\nthree\nfour\nfive\nsix\nSEVEN\n",
    )
    .unwrap();
    std::fs::write(gdir.join("sp ace.txt"), "quoted\n").unwrap();
    git(gdir, home.path(), &["mv", "old.txt", "renamed.txt"]);
    git(gdir, home.path(), &["rm", "-q", "b.txt"]);
    git(gdir, home.path(), &["add", "."]);
    let patch = stdout(&git(gdir, home.path(), &["diff", "--cached", "-M"]));
    let patch = save(&repo, "git.diff", &patch);
    let out = repo.run(&["apply", "--index", &patch]);
    assert!(out.status.success(), "{}", stderr(&out));
    for rel in ["a.txt", "sp ace.txt", "renamed.txt", "run.sh"] {
        assert_eq!(
            read(&repo, rel),
            std::fs::read_to_string(gdir.join(rel)).ok(),
            "{rel}"
        );
    }
    assert_eq!(read(&repo, "old.txt"), None);
    assert_eq!(read(&repo, "b.txt"), None);
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 12, ..ProptestConfig::default() })]

    /// For any two trees A and B, `diff A B | apply` on A gives B, and
    /// `apply -R` then gives A back.
    #[test]
    fn diff_then_apply_round_trips(
        a in proptest::collection::btree_map("[a-d]", proptest::collection::vec("[xyz]{0,3}", 0..8), 1..4),
        b in proptest::collection::btree_map("[a-d]", proptest::collection::vec("[xyz]{0,3}", 0..8), 1..4),
    ) {
        let body = |lines: &Vec<String>| lines.iter().fold(String::new(), |mut s, l| {
            s.push_str(l);
            s.push('\n');
            s
        });
        let repo = Repo::new();
        let write_tree = |tree: &BTreeMap<String, Vec<String>>, msg: &str| {
            for entry in std::fs::read_dir(repo.path()).unwrap() {
                let p = entry.unwrap().path();
                if p.extension().is_some_and(|e| e == "txt") {
                    let rel = p.file_name().unwrap().to_string_lossy().into_owned();
                    repo.ok(&["rm", &rel]);
                }
            }
            for (name, lines) in tree {
                let rel = format!("{name}.txt");
                repo.write(&rel, body(lines).as_bytes());
                repo.ok(&["add", &rel]);
            }
            repo.ok(&["commit", "--allow-empty", "-m", msg]);
        };
        write_tree(&a, "A");
        write_tree(&b, "B");
        let patch = save(&repo, "p.diff", &stdout(&repo.ok(&["diff", "HEAD~1", "HEAD"])));
        repo.ok(&["reset", "--hard", "HEAD~1"]);
        repo.ok(&["apply", "--index", &patch]);
        for (name, lines) in &b {
            prop_assert_eq!(read(&repo, &format!("{name}.txt")), Some(body(lines)));
        }
        for name in a.keys().filter(|n| !b.contains_key(*n)) {
            prop_assert_eq!(read(&repo, &format!("{name}.txt")), None);
        }
        repo.ok(&["apply", "--index", "-R", &patch]);
        for (name, lines) in &a {
            prop_assert_eq!(read(&repo, &format!("{name}.txt")), Some(body(lines)));
        }
        for name in b.keys().filter(|n| !a.contains_key(*n)) {
            prop_assert_eq!(read(&repo, &format!("{name}.txt")), None);
        }
    }
}
