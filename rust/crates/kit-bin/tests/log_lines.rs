//! `kit log -L <start>,<end>:<file>`: the history of a range of lines.
//!
//! Fixed cases pin the commits listed, the hunks of each, shift tracking,
//! several ranges, JSON and the usage errors. Differential cases compare
//! the commits and the diffs with real `git log -L`, and a property test
//! checks soundness and agreement with `kit blame -L` on random histories.
//! The property test does not compare with git: when a file repeats lines,
//! several smallest diffs exist, and kit's line diff may pick another one
//! than git's xdiff, which moves the range onto another copy of a line.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

mod common;

use std::collections::BTreeSet;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use common::Repo;
use proptest::prelude::*;

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn log(repo: &Repo, args: &[&str]) -> String {
    let mut all = vec!["log"];
    all.extend_from_slice(args);
    stdout(&repo.ok(&all))
}

/// Is `line` a line of a diff, rather than a commit line of `--oneline`?
fn is_diff_line(line: &str) -> bool {
    [
        "diff --git ",
        "index ",
        "new file mode ",
        "--- ",
        "+++ ",
        "@@ ",
        " ",
        "+",
        "-",
        "\\",
    ]
    .iter()
    .any(|p| line.starts_with(p))
}

/// An `index <old>..<new> [<mode>]` line with the ids dropped, since the
/// two tools hash differently; any other line as it is.
fn without_blob_ids(line: &str) -> String {
    match line.strip_prefix("index ") {
        Some(rest) => match rest.split_once(' ') {
            Some((_, mode)) => format!("index {mode}"),
            None => "index".to_owned(),
        },
        None => line.to_owned(),
    }
}

/// Whether `git log -L` prints the `index` and `new file mode` lines and
/// the function line of the standard diff output, as git 2.54 and later
/// do.
fn git_prints_file_headers() -> bool {
    let out = Command::new("git").arg("--version").output().unwrap();
    let text = stdout(&out);
    let version = text.trim().trim_start_matches("git version ");
    let mut parts = version.split('.').map(|p| p.parse::<u32>().unwrap_or(0));
    let (major, minor) = (parts.next().unwrap_or(0), parts.next().unwrap_or(0));
    (major, minor) >= (2, 54)
}

/// `--oneline` output with the ids dropped: each commit line becomes its
/// subject, diff lines stay, blank lines go.
fn strip_ids(text: &str) -> Vec<String> {
    text.lines()
        .filter(|l| !l.is_empty())
        .map(|l| {
            if is_diff_line(l) {
                l.to_owned()
            } else {
                l.split_once(' ').map_or("", |(_, s)| s).to_owned()
            }
        })
        .collect()
}

/// The subjects of the commits of `--oneline` output.
fn subjects(text: &str) -> Vec<String> {
    text.lines()
        .filter(|l| !l.is_empty() && !is_diff_line(l))
        .map(|l| l.split_once(' ').map_or("", |(_, s)| s).to_owned())
        .collect()
}

const FN_V1: &str = "header\nfn f() {\n    one();\n}\ntail\n";
const FN_V2: &str = "header\nfn f() {\n    two();\n}\ntail\n";
const FN_V3: &str = "use a;\nuse b;\nheader\nfn f() {\n    two();\n}\ntail\n";
const FN_V4: &str = "use a;\nuse b;\nheader\nfn f() {\n    two();\n    three();\n}\ntail\n";
const FN_V5: &str =
    "use a;\nuse b;\nuse c;\nheader\nfn f() {\n    four();\n    three();\n}\ntail\n";

/// A function edited three times after its creation, with unrelated edits
/// above it, then an edit below it.
fn function_history() -> Repo {
    let repo = Repo::new();
    repo.commit_file("f.rs", FN_V1.as_bytes(), "create");
    repo.commit_file("f.rs", FN_V2.as_bytes(), "edit one");
    repo.commit_file("f.rs", FN_V3.as_bytes(), "imports");
    repo.commit_file("f.rs", FN_V4.as_bytes(), "edit two");
    repo.commit_file("f.rs", FN_V5.as_bytes(), "edit three");
    repo.commit_file("f.rs", format!("{FN_V5}more\n").as_bytes(), "below");
    repo
}

#[test]
fn a_function_lists_the_commits_that_changed_it() {
    let repo = function_history();
    // Lines 5 to 8 are the function at HEAD.
    let out = log(&repo, &["--oneline", "-L", "5,8:f.rs"]);
    assert_eq!(
        subjects(&out),
        ["edit three", "edit two", "edit one", "create"],
        "{out}"
    );
}

#[test]
fn each_commit_shows_the_hunk_of_the_range() {
    let repo = function_history();
    let out = log(&repo, &["--oneline", "-L", "5,8:f.rs"]);
    let text: Vec<String> = strip_ids(&out)
        .iter()
        .map(|l| without_blob_ids(l))
        .collect();
    let text = text.join("\n");
    assert!(
        text.contains(
            "edit three\ndiff --git a/f.rs b/f.rs\nindex 100644\n--- a/f.rs\n+++ b/f.rs\n\
             @@ -4,4 +5,4 @@\n fn f() {\n-    two();\n+    four();\n     three();\n }"
        ),
        "{out}"
    );
    assert!(
        text.contains(
            "create\ndiff --git a/f.rs b/f.rs\nnew file mode 100644\nindex\n\
             --- /dev/null\n+++ b/f.rs\n@@ -0,0 +2,3 @@"
        ),
        "{out}"
    );
    // The ids are short blob ids, as git prints them, and a created file
    // starts from zeros.
    let index: Vec<&str> = out.lines().filter(|l| l.starts_with("index ")).collect();
    assert!(
        index.iter().any(|l| l.starts_with("index 0000000..")),
        "{out}"
    );
    assert!(
        index.iter().all(|l| {
            let ids = l.split(' ').nth(1).unwrap();
            ids.len() == 16 && ids.contains("..")
        }),
        "{out}"
    );
}

#[test]
fn a_hunk_header_names_the_function_above_it() {
    let repo = Repo::new();
    let body = "int f()\n{\n\ta;\n\tb;\n\tc;\n\td;\n\te;\n}\n";
    repo.commit_file("f.c", body.as_bytes(), "create");
    repo.commit_file("f.c", body.replace("\te;", "\tE;").as_bytes(), "edit e");
    let out = log(&repo, &["--oneline", "-n", "1", "-L", "7,7:f.c"]);
    assert!(
        out.contains("\n@@ -7,1 +7,1 @@ int f()\n-\te;\n+\tE;\n"),
        "{out}"
    );
}

#[test]
fn a_range_moved_down_by_an_insertion_still_tracks() {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"1\n2\n3\n4\n", "create");
    repo.commit_file("a.txt", b"1\n2\nthree\n4\n", "change three");
    repo.commit_file("a.txt", b"0\n0\n1\n2\nthree\n4\n", "insert above");
    // Line 5 is `three` at HEAD; the insertion above does not touch it.
    let out = log(&repo, &["--oneline", "-L", "5,5:a.txt"]);
    assert_eq!(subjects(&out), ["change three", "create"], "{out}");
    assert!(out.contains("@@ -3,1 +3,1 @@\n-3\n+three\n"), "{out}");
}

#[test]
fn several_ranges_and_files_combine() {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"1\n2\n3\n4\n5\n6\n", "a");
    repo.commit_file("b.txt", b"x\ny\n", "b");
    repo.commit_file("a.txt", b"1\nTWO\n3\n4\n5\n6\n", "a two");
    repo.commit_file("a.txt", b"1\nTWO\n3\n4\n5\nSIX\n", "a six");
    repo.commit_file("b.txt", b"x\nY\n", "b y");
    let out = log(
        &repo,
        &[
            "--oneline",
            "-L",
            "2,2:a.txt",
            "-L",
            "6,6:a.txt",
            "-L",
            "2:b.txt",
        ],
    );
    assert_eq!(subjects(&out), ["b y", "a six", "a two", "b", "a"], "{out}");
    // Overlapping ranges merge into one.
    let merged = log(&repo, &["--oneline", "-L", "2,3:a.txt", "-L", "3,4:a.txt"]);
    assert!(merged.contains("@@ -2,3 +2,3 @@"), "{merged}");
}

#[test]
fn limit_revision_and_first_parent_apply() {
    let repo = function_history();
    let out = log(&repo, &["--oneline", "-n", "2", "-L", "5,8:f.rs"]);
    assert_eq!(subjects(&out), ["edit three", "edit two"], "{out}");
    // The range is read in the file at the revision.
    let out = log(&repo, &["--oneline", "-L", "2,4:f.rs", "HEAD~4"]);
    assert_eq!(subjects(&out), ["edit one", "create"], "{out}");
}

#[test]
fn json_records_carry_the_hunks() {
    let repo = function_history();
    let out = log(&repo, &["--format=json", "-n", "1", "-L", "5,8:f.rs"]);
    let line = out.lines().next().unwrap();
    assert!(line.contains("\"title\":\"edit three\""), "{out}");
    assert!(
        line.contains(
            "\"hunks\":[{\"path\":\"f.rs\",\"old_start\":4,\"old_lines\":4,\
             \"new_start\":5,\"new_lines\":4,\"lines\":[\" fn f() {\",\
             \"-    two();\",\"+    four();\",\"     three();\",\" }\"]}]"
        ),
        "{out}"
    );
}

#[test]
fn a_merge_that_one_parent_explains_is_hidden() {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"1\n2\n3\n", "create");
    repo.ok(&["branch", "side"]);
    repo.commit_file("a.txt", b"1\n2\nthree\n", "main three");
    repo.ok(&["switch", "side"]);
    repo.commit_file("b.txt", b"b\n", "side b");
    repo.ok(&["switch", "main"]);
    repo.ok(&["merge", "side", "-m", "merge side"]);
    let out = log(&repo, &["--oneline", "-L", "3,3:a.txt"]);
    assert_eq!(subjects(&out), ["main three", "create"], "{out}");
}

#[test]
fn usage_errors_exit_64() {
    let repo = function_history();
    for args in [
        &["log", "-L", "5,8"][..],
        &["log", "-L", "x,y:f.rs"],
        &["log", "-L", "5,8:missing.rs"],
        &["log", "-L", "50,60:f.rs"],
        &["log", "-L", "5,8:f.rs", "--graph"],
        &["log", "-L", "5,8:f.rs", "--stat"],
        &["log", "-L", "5,8:f.rs", "--follow", "f.rs"],
        &["log", "-L", "5,8:f.rs", "HEAD~2..HEAD"],
        &["log", "-L", "5,8:f.rs", "--all"],
        &["log", "-L", "5,8:f.rs", "--", "f.rs"],
        &["log", "-L", "5,8:f.rs", "--author", "x"],
        &["log", "-L", "5,8:f.rs", "--no-merges"],
    ] {
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
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(out.status.success(), "git {args:?}: {}", stderr(&out));
    out
}

/// The same linear history in kit and in git: each step writes a file and
/// commits it with its index as the message.
struct Twin {
    kit: Repo,
    _home: tempfile::TempDir,
    _dir: tempfile::TempDir,
    home: std::path::PathBuf,
    dir: std::path::PathBuf,
}

impl Twin {
    fn new() -> Self {
        let home = tempfile::tempdir().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let (h, d) = (home.path().to_owned(), dir.path().to_owned());
        git(&d, &h, &["init", "-q", "-b", "main"]);
        Self {
            kit: Repo::new(),
            _home: home,
            _dir: dir,
            home: h,
            dir: d,
        }
    }

    fn commit(&self, rel: &str, body: &str, msg: &str) {
        self.kit.commit_file(rel, body.as_bytes(), msg);
        std::fs::write(self.dir.join(rel), body).unwrap();
        git(&self.dir, &self.home, &["add", rel]);
        git(&self.dir, &self.home, &["commit", "-q", "-m", msg]);
    }

    /// The `--oneline` output of both tools for `args`, ids dropped.
    fn both(&self, args: &[&str]) -> (Vec<String>, Vec<String>) {
        let mut all = vec!["log", "--oneline"];
        all.extend_from_slice(args);
        let ours: Vec<String> = strip_ids(&stdout(&self.kit.ok(&all)))
            .iter()
            .map(|l| without_blob_ids(l))
            .collect();
        let mut gall = vec!["log", "--oneline", "--no-color"];
        gall.extend_from_slice(args);
        let theirs: Vec<String> = strip_ids(&stdout(&git(&self.dir, &self.home, &gall)))
            .iter()
            .map(|l| without_blob_ids(l))
            .collect();
        (ours, theirs)
    }
}

#[test]
fn output_matches_git_log_l() {
    if !git_available() {
        return;
    }
    let t = Twin::new();
    for (i, body) in [FN_V1, FN_V2, FN_V3, FN_V4, FN_V5].iter().enumerate() {
        t.commit("f.rs", body, &format!("step {i}"));
    }
    t.commit("g.txt", "1\n2\n3\n4\n5\n6\n", "g");
    t.commit("g.txt", "1\n2\n3\nfour\n5\n", "g four");
    t.commit("f.rs", &format!("{FN_V5}more\n"), "below");
    for args in [
        &["-L", "5,8:f.rs"][..],
        &["-L", "1,3:f.rs"],
        &["-L", "5,+2:f.rs", "-L", "9:f.rs"],
        &["-L", "2,5:g.txt", "-L", "6,7:f.rs"],
        &["-L", "4,-2:g.txt"],
        &["-L", "5,8:f.rs", "HEAD~3"],
    ] {
        let (mut ours, theirs) = t.both(args);
        if !git_prints_file_headers() {
            ours.retain(|l| {
                l != "index" && !l.starts_with("index ") && !l.starts_with("new file mode ")
            });
            for l in &mut ours {
                if let Some(end) = l.strip_prefix("@@ ").and_then(|r| r.find(" @@ ")) {
                    l.truncate(end + 6);
                }
            }
        }
        assert_eq!(ours, theirs, "{args:?}");
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 12, ..ProptestConfig::default() })]

    /// On random histories of one file: every listed commit's hunks change
    /// a line, and every commit that `kit blame -L` credits for the range is
    /// listed.
    #[test]
    fn line_log_is_sound_and_complete(
        steps in proptest::collection::vec(
            proptest::collection::vec(0u8..6, 1..9),
            1..6,
        ),
        first in 1usize..4,
        len in 0usize..4,
    ) {
        let kit = Repo::new();
        let mut last_body = String::new();
        for (i, lines) in steps.iter().enumerate() {
            let body: String = lines.iter().map(|n| format!("l{n}")).collect::<Vec<_>>().join("\n") + "\n";
            // A step that changes nothing has no commit to make.
            if body != last_body {
                kit.commit_file("f.txt", body.as_bytes(), &format!("s{i}"));
                last_body = body;
            }
        }
        let total = steps.last().unwrap().len();
        let first = first.min(total);
        let last = (first + len).min(total);
        let spec = format!("{first},{last}:f.txt");
        let out = log(&kit, &["--oneline", "-L", &spec]);
        // Soundness: each commit block holds a changed line.
        let mut blocks: Vec<(String, Vec<String>)> = Vec::new();
        for l in out.lines().filter(|l| !l.is_empty()) {
            if is_diff_line(l) {
                if let Some(b) = blocks.last_mut() {
                    b.1.push(l.to_owned());
                }
            } else {
                blocks.push((l.split_once(' ').unwrap().1.to_owned(), Vec::new()));
            }
        }
        for (subject, lines) in &blocks {
            prop_assert!(
                lines.iter().any(|l| (l.starts_with('+') && !l.starts_with("+++"))
                    || (l.starts_with('-') && !l.starts_with("---"))),
                "{subject} changes no line: {out}"
            );
        }
        // Completeness against blame.
        let listed: BTreeSet<String> = blocks.iter().map(|b| b.0.clone()).collect();
        let blame = stdout(&kit.ok(&[
            "blame", "--format=json", "-L", &format!("{first},{last}"), "f.txt",
        ]));
        let log_all = stdout(&kit.ok(&["log", "--format=json"]));
        for line in blame.lines() {
            let commit = line.split("\"hash\":\"").nth(1).unwrap().split('"').next().unwrap();
            let key = format!("\"hash\":\"{commit}\"");
            let rec = log_all.lines().find(|r| r.contains(&key)).unwrap();
            let title = rec.split("\"title\":\"").nth(1).unwrap().split('"').next().unwrap();
            prop_assert!(listed.contains(title), "{title} credited by blame: {out}");
        }
    }
}
