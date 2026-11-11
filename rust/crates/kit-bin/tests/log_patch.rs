//! `kit log -p` and `kit log --stat`: each commit followed by its diff against
//! its first parent. The diff text is that of `kit show`.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

mod common;

use std::process::Output;

use common::Repo;

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn stdout(out: &Output) -> String {
    text(&out.stdout)
}

/// Root commit adds `f.txt`. The second commit changes it and adds `g.txt`.
fn two_commits() -> Repo {
    let repo = Repo::new();
    repo.commit_file("f.txt", b"a\nb\n", "first");
    repo.write("f.txt", b"a\nc\n");
    repo.write("g.txt", b"x\n");
    repo.ok(&["add", "."]);
    repo.ok(&["commit", "-m", "second"]);
    repo
}

/// `main` and `feature` each add a file. `main` then merges `feature`.
fn merged() -> Repo {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"base\n", "base");
    repo.ok(&["branch", "feature"]);
    repo.ok(&["checkout", "feature"]);
    repo.commit_file("b.txt", b"feat\n", "feat");
    repo.ok(&["checkout", "main"]);
    repo.commit_file("c.txt", b"main\n", "main2");
    repo.ok(&["merge", "-m", "join", "feature"]);
    repo
}

#[test]
fn patch_follows_each_commit_with_its_diff() {
    let repo = two_commits();
    let out = stdout(&repo.ok(&["log", "-p"]));
    let (newest, oldest) = out
        .split_once("commit ")
        .unwrap()
        .1
        .split_once("\ncommit ")
        .unwrap();
    assert!(newest.contains("    second\n\ndiff --git a/f.txt b/f.txt\n"));
    assert!(newest.contains("-b\n+c\n"));
    assert!(newest.contains("diff --git a/g.txt b/g.txt\nnew file mode 100644\n"));
    assert!(oldest.contains("    first\n\ndiff --git a/f.txt b/f.txt\nnew file mode 100644\n"));
    assert!(oldest.contains("+a\n+b\n"));
    // A blank line ends each commit, so the next header starts a paragraph.
    assert!(out.contains("+x\n\ncommit "), "{out}");
}

#[test]
fn patch_text_is_the_text_of_show() {
    let repo = two_commits();
    for rev in ["HEAD", "HEAD~1"] {
        let log = stdout(&repo.ok(&["log", "-p", "-n1", rev]));
        let show = stdout(&repo.ok(&["show", rev]));
        assert_eq!(log, format!("{show}\n"), "{rev}");
    }
}

#[test]
fn long_patch_flag_is_the_same_as_short() {
    let repo = two_commits();
    assert_eq!(
        repo.ok(&["log", "--patch"]).stdout,
        repo.ok(&["log", "-p"]).stdout
    );
}

#[test]
fn stat_follows_each_commit_with_its_diffstat() {
    let repo = two_commits();
    let out = stdout(&repo.ok(&["log", "--stat"]));
    assert!(out.contains("    second\n\n f.txt | 2 +-\n g.txt | 1 +\n 2 files changed, 2 insertions(+), 1 deletion(-)\n\ncommit "));
    assert!(out.contains("    first\n\n f.txt | 2 ++\n 1 file changed, 2 insertions(+)\n\n"));
    assert!(!out.contains("diff --git"));
}

#[test]
fn stat_text_is_the_text_of_show() {
    let repo = two_commits();
    for rev in ["HEAD", "HEAD~1"] {
        let log = stdout(&repo.ok(&["log", "--stat", "-n1", rev]));
        let show = stdout(&repo.ok(&["show", "--stat", rev]));
        assert_eq!(log, format!("{show}\n"), "{rev}");
    }
}

#[test]
fn oneline_puts_the_diff_right_after_the_line() {
    let repo = two_commits();
    let out = stdout(&repo.ok(&["log", "--oneline", "-p", "-n1"]));
    let (line, rest) = out.split_once('\n').unwrap();
    assert!(line.ends_with(" second"), "{line}");
    assert!(rest.starts_with("diff --git a/f.txt b/f.txt\n"), "{rest}");
    let out = stdout(&repo.ok(&["log", "--oneline", "--stat", "-n1"]));
    assert!(out.contains(" second\n f.txt | 2 +-\n"), "{out}");
}

#[test]
fn a_root_commit_is_a_diff_against_an_empty_tree() {
    let repo = Repo::new();
    repo.commit_file("only.txt", b"x\n", "root");
    let patch = stdout(&repo.ok(&["log", "-p"]));
    assert!(patch.contains("diff --git a/only.txt b/only.txt\nnew file mode 100644\n"));
    assert!(patch.ends_with("+x\n\n"), "{patch}");
    let stat = stdout(&repo.ok(&["log", "--stat"]));
    assert!(stat.contains(" only.txt | 1 +\n 1 file changed, 1 insertion(+)\n"));
}

#[test]
fn a_merge_commit_shows_its_diff_against_the_first_parent() {
    let repo = merged();
    let out = stdout(&repo.ok(&["log", "-p", "-n1"]));
    assert!(out.contains("    join\n"), "{out}");
    assert!(out.contains("diff --git a/b.txt b/b.txt\n"), "{out}");
    assert!(!out.contains("c.txt"), "{out}");
    let show = stdout(&repo.ok(&["show", "HEAD"]));
    assert_eq!(out, format!("{show}\n"));
    let stat = stdout(&repo.ok(&["log", "--stat", "-n1"]));
    assert!(
        stat.contains(" b.txt | 1 +\n 1 file changed, 1 insertion(+)\n"),
        "{stat}"
    );
}

#[test]
fn first_parent_walk_shows_the_changes_of_the_mainline() {
    let repo = merged();
    let out = stdout(&repo.ok(&["log", "-p", "--first-parent"]));
    assert_eq!(out.matches("\ncommit ").count() + 1, 3, "{out}");
    assert!(out.contains("diff --git a/c.txt b/c.txt\n"));
    assert!(out.contains("diff --git a/b.txt b/b.txt\n"));
}

#[test]
fn a_range_and_a_limit_apply_before_the_diff() {
    let repo = two_commits();
    let out = stdout(&repo.ok(&["log", "-p", "HEAD~1..HEAD"]));
    assert_eq!(out.matches("diff --git").count(), 2);
    assert!(!out.contains("    first"));
    let none = stdout(&repo.ok(&["log", "-p", "-n", "0"]));
    assert!(none.is_empty());
}

#[test]
fn a_binary_file_shows_as_binary() {
    let repo = Repo::new();
    repo.commit_file("b.bin", b"\0bin", "binary");
    let patch = stdout(&repo.ok(&["log", "-p"]));
    assert!(
        patch.contains("Binary files /dev/null and b/b.bin differ\n"),
        "{patch}"
    );
    let stat = stdout(&repo.ok(&["log", "--stat"]));
    assert!(stat.contains(" b.bin | Bin 0 -> 4 bytes\n"), "{stat}");
}

#[test]
fn a_large_file_is_a_complete_patch() {
    let repo = Repo::new();
    let body = "line\n".repeat(5000);
    repo.commit_file("big.txt", body.as_bytes(), "big");
    let patch = stdout(&repo.ok(&["log", "-p"]));
    assert!(patch.contains("@@ -0,0 +1,5000 @@\n"), "{patch}");
    assert_eq!(patch.lines().filter(|l| *l == "+line").count(), 5000);
    let stat = stdout(&repo.ok(&["log", "--stat"]));
    assert!(stat.contains("| 5000 +"), "{stat}");
}

#[test]
fn a_commit_without_a_change_has_no_diff() {
    let repo = Repo::new();
    repo.commit_file("f.txt", b"a\n", "first");
    repo.ok(&["commit", "-m", "empty"]);
    let out = stdout(&repo.ok(&["log", "-p", "-n1"]));
    assert!(out.contains("    empty\n"), "{out}");
    assert!(!out.contains("diff --git"), "{out}");
    assert!(out.ends_with("    empty\n\n"), "{out}");
}

#[test]
fn a_repository_without_commits_prints_nothing() {
    let repo = Repo::new();
    let out = repo.ok(&["log", "-p"]);
    assert!(out.stdout.is_empty());
}

#[test]
fn patch_and_stat_exclude_each_other() {
    let repo = two_commits();
    let out = repo.run(&["log", "-p", "--stat"]);
    assert_eq!(out.status.code(), Some(64));
    assert!(out.stdout.is_empty());
}

#[test]
fn json_format_refuses_patch_and_stat() {
    let repo = two_commits();
    for flag in ["-p", "--stat"] {
        let out = repo.run(&["log", "--format=json", flag]);
        assert_eq!(out.status.code(), Some(64), "{flag}");
        assert!(out.stdout.is_empty(), "{flag}");
        assert!(text(&out.stderr).contains("--format=json"), "{flag}");
    }
}

#[test]
fn a_missing_blob_is_an_error_not_a_wrong_diff() {
    let repo = two_commits();
    let listing = stdout(&repo.ok(&["ls-tree", "HEAD"]));
    let id = listing
        .lines()
        .find_map(|l| {
            let (meta, name) = l.split_once('\t')?;
            (name == "g.txt").then(|| meta.split_whitespace().nth(2).unwrap().to_string())
        })
        .unwrap();
    let object = repo.kit_dir().join("objects").join(&id[..2]).join(&id[2..]);
    std::fs::remove_file(object).unwrap();
    for flag in ["-p", "--stat"] {
        let out = repo.run(&["log", flag]);
        assert_eq!(out.status.code(), Some(1), "{flag}");
        assert!(!text(&out.stderr).is_empty(), "{flag}");
    }
}
