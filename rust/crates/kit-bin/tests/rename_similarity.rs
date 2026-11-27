//! Rename detection by similarity: a file that moves and changes a little
//! still reports as a rename, with git's score.
//!
//! The fixed cases pin the output of `diff`, `status`, `show` and `log`. The
//! scores come from git 2.43 on the same bytes. A differential property test
//! runs random renames through kit and through `git` when it is on `PATH`,
//! and compares `diff --cached --name-status`.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

mod common;

use std::fmt::Write as _;
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

/// `1\n` to `20\n`.
fn twenty() -> String {
    (1..=20).fold(String::new(), |mut s, n| {
        let _ = writeln!(s, "{n}");
        s
    })
}

/// `twenty()` with line 5 replaced. git scores the pair 90%.
fn twenty_edited() -> String {
    twenty().replace("\n5\n", "\nfive\n")
}

/// `a.txt` committed, then moved to `b.txt` with one line changed, staged.
fn moved_and_edited() -> Repo {
    let repo = Repo::new();
    repo.commit_file("a.txt", twenty().as_bytes(), "add a");
    repo.ok(&["mv", "a.txt", "b.txt"]);
    repo.write("b.txt", twenty_edited().as_bytes());
    repo.ok(&["add", "b.txt"]);
    repo
}

#[test]
fn name_status_prints_the_similarity_score() {
    let repo = moved_and_edited();
    let out = repo.ok(&["diff", "--cached", "--name-status"]);
    assert_eq!(stdout(&out), "R090\ta.txt\tb.txt\n");
}

#[test]
fn name_status_z_prints_the_score_and_both_paths() {
    let repo = moved_and_edited();
    let out = repo.ok(&["diff", "--cached", "--name-status", "-z"]);
    assert_eq!(out.stdout, b"R090\0a.txt\0b.txt\0");
}

#[test]
fn patch_has_rename_headers_and_hunks() {
    let repo = moved_and_edited();
    let text = stdout(&repo.ok(&["diff", "--cached"]));
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines[0], "diff --git a/a.txt b/b.txt");
    assert_eq!(lines[1], "similarity index 90%");
    assert_eq!(lines[2], "rename from a.txt");
    assert_eq!(lines[3], "rename to b.txt");
    assert!(lines[4].starts_with("index "), "{text}");
    assert!(lines[4].ends_with(" 100644"), "{text}");
    assert_eq!(lines[5], "--- a/a.txt");
    assert_eq!(lines[6], "+++ b/b.txt");
    assert_eq!(lines[7], "@@ -2,7 +2,7 @@");
    assert!(text.contains("\n-5\n+five\n"), "{text}");
}

#[cfg(unix)]
#[test]
fn a_mode_change_prints_mode_lines_before_the_similarity() {
    use std::os::unix::fs::PermissionsExt;
    let repo = moved_and_edited();
    let path = repo.path().join("b.txt");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    repo.ok(&["add", "b.txt"]);
    let text = stdout(&repo.ok(&["diff", "--cached"]));
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(
        lines[..7].iter().map(|l| &l[..l.len().min(16)]).collect::<Vec<_>>(),
        [
            "diff --git a/a.t",
            "old mode 100644",
            "new mode 100755",
            "similarity index",
            "rename from a.tx",
            "rename to b.txt",
            "index ",
        ]
        .iter()
        .map(|l| &l[..l.len().min(16)])
        .collect::<Vec<_>>(),
        "{text}"
    );
    // The `index` line has no mode when the modes differ.
    assert!(!lines[6].ends_with("100644"), "{text}");
    assert!(!lines[6].ends_with("100755"), "{text}");
}

#[test]
fn an_exact_rename_still_scores_100_and_has_no_hunk() {
    let repo = Repo::new();
    repo.commit_file("a.txt", twenty().as_bytes(), "add a");
    repo.ok(&["mv", "a.txt", "b.txt"]);
    assert_eq!(
        stdout(&repo.ok(&["diff", "--cached", "--name-status"])),
        "R100\ta.txt\tb.txt\n"
    );
    let text = stdout(&repo.ok(&["diff", "--cached"]));
    assert_eq!(
        text,
        "diff --git a/a.txt b/b.txt\nsimilarity index 100%\nrename from a.txt\nrename to b.txt\n"
    );
}

#[test]
fn stat_names_both_sides_of_a_rename() {
    let repo = moved_and_edited();
    let text = stdout(&repo.ok(&["diff", "--cached", "--stat"]));
    assert!(text.starts_with(" a.txt => b.txt | 2 +-\n"), "{text}");
}

#[test]
fn stat_shortens_a_rename_to_the_changed_part() {
    let repo = Repo::new();
    repo.commit_file("dir/a.txt", twenty().as_bytes(), "add a");
    repo.ok(&["mv", "dir/a.txt", "dir/b.txt"]);
    let text = stdout(&repo.ok(&["diff", "--cached", "--stat"]));
    assert!(text.starts_with(" dir/{a.txt => b.txt} | 0\n"), "{text}");
}

#[test]
fn status_porcelain_v2_carries_the_score() {
    let repo = moved_and_edited();
    let text = stdout(&repo.ok(&["status", "--porcelain=v2"]));
    assert!(text.starts_with("2 R. N... 100644 100644 100644 "), "{text}");
    assert!(text.ends_with(" R90 b.txt\ta.txt\n"), "{text}");
}

#[test]
fn status_short_pairs_the_rename() {
    let repo = moved_and_edited();
    let text = stdout(&repo.ok(&["status", "--porcelain"]));
    assert_eq!(text, "R  a.txt -> b.txt\n");
}

#[test]
fn a_threshold_above_the_score_splits_the_pair() {
    let repo = moved_and_edited();
    for flag in ["-M95", "-M95%", "--find-renames=95", "--find-renames=0.95"] {
        let text = stdout(&repo.ok(&["diff", "--cached", "--name-status", flag]));
        assert_eq!(text, "D\ta.txt\nA\tb.txt\n", "{flag}");
    }
    let text = stdout(&repo.ok(&["status", "--porcelain", "--find-renames=95"]));
    assert_eq!(text, "D  a.txt\nA  b.txt\n");
}

#[test]
fn a_threshold_at_or_below_the_score_keeps_the_pair() {
    let repo = moved_and_edited();
    // git reads `-M9` as 0.9 and `-M100` as 0.100.
    for flag in ["-M", "-M90%", "-M9", "-M100", "--find-renames", "--find-renames=90"] {
        let text = stdout(&repo.ok(&["diff", "--cached", "--name-status", flag]));
        assert_eq!(text, "R090\ta.txt\tb.txt\n", "{flag}");
    }
}

#[test]
fn a_threshold_of_100_percent_keeps_only_exact_renames() {
    let repo = moved_and_edited();
    let text = stdout(&repo.ok(&["diff", "--cached", "--name-status", "-M100%"]));
    assert_eq!(text, "D\ta.txt\nA\tb.txt\n");
}

#[test]
fn a_bad_threshold_is_a_usage_error() {
    let repo = moved_and_edited();
    for flag in ["-Mx", "--find-renames=5x", "-M50%%"] {
        let out = repo.run(&["diff", "--cached", flag]);
        assert_eq!(out.status.code(), Some(64), "{flag}: {}", stderr(&out));
    }
    let out = repo.run(&["status", "--find-renames=abc"]);
    assert_eq!(out.status.code(), Some(64), "{}", stderr(&out));
}

#[test]
fn no_renames_shows_a_delete_and_an_add() {
    let repo = moved_and_edited();
    let text = stdout(&repo.ok(&["diff", "--cached", "--name-status", "--no-renames"]));
    assert_eq!(text, "D\ta.txt\nA\tb.txt\n");
}

#[test]
fn content_under_half_similar_is_not_a_rename() {
    let repo = Repo::new();
    repo.commit_file("a.txt", twenty().as_bytes(), "add a");
    repo.ok(&["rm", "a.txt"]);
    let half: String = twenty().lines().take(8).fold(String::new(), |mut s, l| {
        let _ = writeln!(s, "{l}");
        s
    }) + "x\ny\nz\nw\nv\nu\nt\ns\nr\nq\np\no\n";
    repo.write("b.txt", half.as_bytes());
    repo.ok(&["add", "b.txt"]);
    let text = stdout(&repo.ok(&["diff", "--cached", "--name-status"]));
    assert_eq!(text, "D\ta.txt\nA\tb.txt\n");
}

#[test]
fn each_source_pairs_with_its_best_destination() {
    // Two sources, two destinations, each destination closest to one source.
    let repo = Repo::new();
    let left: String = (1..=20).map(|n| format!("left {n}\n")).collect();
    let right: String = (1..=20).map(|n| format!("right {n}\n")).collect();
    repo.write("l.txt", left.as_bytes());
    repo.write("r.txt", right.as_bytes());
    repo.ok(&["add", "l.txt", "r.txt"]);
    repo.ok(&["commit", "-m", "base"]);
    repo.ok(&["rm", "l.txt", "r.txt"]);
    repo.write("x.txt", left.replace("left 3\n", "LEFT\n").as_bytes());
    repo.write("y.txt", right.replace("right 7\n", "RIGHT\n").as_bytes());
    repo.ok(&["add", "x.txt", "y.txt"]);
    let text = stdout(&repo.ok(&["diff", "--cached", "--name-status"]));
    let mut lines: Vec<&str> = text.lines().collect();
    lines.sort_unstable();
    assert_eq!(lines.len(), 2, "{text}");
    assert!(lines[0].starts_with('R') && lines[0].ends_with("\tl.txt\tx.txt"), "{text}");
    assert!(lines[1].starts_with('R') && lines[1].ends_with("\tr.txt\ty.txt"), "{text}");
}

#[test]
fn a_same_basename_match_wins_over_a_closer_file() {
    // git 2.43: `a/foo.txt` pairs with `b/foo.txt` (76%) over `c/bar.txt`
    // (88%), because a unique same-name match at or above the midpoint of
    // the threshold and 100% is taken first.
    let repo = Repo::new();
    repo.commit_file("a/foo.txt", twenty().as_bytes(), "add foo");
    repo.ok(&["rm", "a/foo.txt"]);
    let foo: String = (1..=16).map(|n| format!("{n}\n")).collect::<String>() + "x\ny\nz\nw\n";
    let bar: String = (1..=18).map(|n| format!("{n}\n")).collect::<String>() + "q\nr\n";
    repo.write("b/foo.txt", foo.as_bytes());
    repo.write("c/bar.txt", bar.as_bytes());
    repo.ok(&["add", "b/foo.txt", "c/bar.txt"]);
    let text = stdout(&repo.ok(&["diff", "--cached", "--name-status"]));
    assert_eq!(text, "R076\ta/foo.txt\tb/foo.txt\nA\tc/bar.txt\n");
}

#[test]
fn a_symlink_is_never_a_similarity_rename() {
    #[cfg(unix)]
    {
        let repo = Repo::new();
        std::os::unix::fs::symlink("target-one", repo.path().join("l1")).unwrap();
        repo.ok(&["add", "l1"]);
        repo.ok(&["commit", "-m", "link"]);
        repo.ok(&["rm", "l1"]);
        std::os::unix::fs::symlink("target-onf", repo.path().join("l2")).unwrap();
        repo.ok(&["add", "l2"]);
        let text = stdout(&repo.ok(&["diff", "--cached", "--name-status"]));
        assert_eq!(text, "D\tl1\nA\tl2\n");
    }
}

#[test]
fn past_the_rename_limit_only_exact_renames_are_found() {
    let repo = Repo::new();
    for i in 1..=3 {
        let body: String = (i..=30).map(|n| format!("{n}\n")).collect();
        repo.write(&format!("f{i}"), body.as_bytes());
    }
    repo.write("e1", b"exact\n");
    repo.ok(&["add", "."]);
    repo.ok(&["commit", "-m", "base"]);
    repo.ok(&["mv", "e1", "e2"]);
    repo.ok(&["rm", "f1", "f2", "f3"]);
    for i in 1..=3 {
        let body: String = (i..=29).map(|n| format!("{n}\n")).collect::<String>() + "z\n";
        repo.write(&format!("g{i}"), body.as_bytes());
    }
    repo.ok(&["add", "g1", "g2", "g3"]);

    let full = stdout(&repo.ok(&["diff", "--cached", "--name-status"]));
    assert_eq!(
        full,
        "R100\te1\te2\nR096\tf1\tg1\nR096\tf2\tg2\nR096\tf3\tg3\n"
    );

    let out = repo.ok(&["diff", "--cached", "--name-status", "-l1"]);
    assert_eq!(
        stdout(&out),
        "R100\te1\te2\nD\tf1\nD\tf2\nD\tf3\nA\tg1\nA\tg2\nA\tg3\n"
    );
    let err = stderr(&out);
    assert!(
        err.contains("warning: exhaustive rename detection was skipped due to too many files."),
        "{err}"
    );
    assert!(err.contains("at least 3"), "{err}");
}

#[test]
fn show_and_log_patch_detect_the_rename() {
    let repo = moved_and_edited();
    repo.ok(&["commit", "-m", "move a"]);
    let text = stdout(&repo.ok(&["show", "HEAD"]));
    assert!(text.contains("\nsimilarity index 90%\nrename from a.txt\nrename to b.txt\n"), "{text}");
    let text = stdout(&repo.ok(&["log", "-p", "-n", "1"]));
    assert!(text.contains("\nsimilarity index 90%\n"), "{text}");
    let text = stdout(&repo.ok(&["log", "--stat", "-n", "1"]));
    assert!(text.contains(" a.txt => b.txt | 2 +-\n"), "{text}");
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

/// The `index` line differs by design (BLAKE3 ids), so it is dropped.
fn without_index_lines(text: &str) -> String {
    text.lines()
        .filter(|l| !l.starts_with("index "))
        .fold(String::new(), |mut s, l| {
            let _ = writeln!(s, "{l}");
            s
        })
}

#[test]
fn the_patch_matches_git_apart_from_index_ids() {
    if !git_available() {
        eprintln!("SKIP: git not on PATH");
        return;
    }
    let repo = moved_and_edited();
    let home = tempfile::tempdir().unwrap();
    let g = tempfile::tempdir().unwrap();
    git(g.path(), home.path(), &["init", "-q"]);
    std::fs::write(g.path().join("a.txt"), twenty()).unwrap();
    git(g.path(), home.path(), &["add", "a.txt"]);
    git(g.path(), home.path(), &["commit", "-qm", "add a"]);
    git(g.path(), home.path(), &["mv", "a.txt", "b.txt"]);
    std::fs::write(g.path().join("b.txt"), twenty_edited()).unwrap();
    git(g.path(), home.path(), &["add", "b.txt"]);
    for args in [
        &["diff", "--cached"][..],
        &["diff", "--cached", "--stat"][..],
        &["diff", "--cached", "--name-status"][..],
    ] {
        let ours = without_index_lines(&stdout(&repo.ok(args)));
        let theirs = without_index_lines(&stdout(&git(g.path(), home.path(), args)));
        assert_eq!(ours, theirs, "{args:?}");
    }
}

/// A random file of distinct-looking lines.
fn body(lines: &[u16]) -> String {
    lines.iter().fold(String::new(), |mut s, n| {
        let _ = writeln!(s, "line {n} {}", n.wrapping_mul(7919));
        s
    })
}

/// How a destination derives from a source: keep a prefix of lines, then
/// append fresh ones.
#[derive(Debug, Clone)]
struct Derived {
    source: usize,
    keep: usize,
    fresh: Vec<u16>,
}

fn case() -> impl Strategy<Value = (Vec<Vec<u16>>, Vec<Derived>)> {
    prop::collection::vec(prop::collection::vec(0u16..5000, 4..24), 1..4).prop_flat_map(
        |sources| {
            let n = sources.len();
            let derived = prop::collection::vec(
                (0..n, 0usize..24, prop::collection::vec(5000u16..9000, 0..12)).prop_map(
                    |(source, keep, fresh)| Derived {
                        source,
                        keep,
                        fresh,
                    },
                ),
                1..4,
            );
            (Just(sources), derived)
        },
    )
}

fn derive(sources: &[Vec<u16>], d: &Derived) -> String {
    let src = &sources[d.source];
    let mut lines: Vec<u16> = src[..d.keep.min(src.len())].to_vec();
    lines.extend_from_slice(&d.fresh);
    body(&lines)
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: std::env::var("KIT_PROPTEST_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(10),
        failure_persistence: None,
        .. ProptestConfig::default()
    })]

    /// kit and git pair the same files with the same scores.
    #[test]
    fn name_status_matches_git((sources, derived) in case()) {
        if !git_available() {
            eprintln!("SKIP: git not on PATH");
            return Ok(());
        }
        let repo = Repo::new();
        let home = tempfile::tempdir().unwrap();
        let g = tempfile::tempdir().unwrap();
        git(g.path(), home.path(), &["init", "-q"]);
        let src_names: Vec<String> = (0..sources.len()).map(|i| format!("s{i}.txt")).collect();
        for (name, lines) in src_names.iter().zip(&sources) {
            repo.write(name, body(lines).as_bytes());
            std::fs::write(g.path().join(name), body(lines)).unwrap();
        }
        repo.ok(&["add", "."]);
        repo.ok(&["commit", "-m", "base"]);
        git(g.path(), home.path(), &["add", "."]);
        git(g.path(), home.path(), &["commit", "-qm", "base"]);
        let mut rm = vec!["rm"];
        rm.extend(src_names.iter().map(String::as_str));
        repo.ok(&rm);
        git(g.path(), home.path(), &rm);
        let dst_names: Vec<String> = (0..derived.len()).map(|i| format!("d{i}.txt")).collect();
        for (name, d) in dst_names.iter().zip(&derived) {
            let text = derive(&sources, d);
            repo.write(name, text.as_bytes());
            std::fs::write(g.path().join(name), text).unwrap();
        }
        let mut add = vec!["add"];
        add.extend(dst_names.iter().map(String::as_str));
        repo.ok(&add);
        git(g.path(), home.path(), &add);
        for args in [
            &["diff", "--cached", "--name-status"][..],
            &["diff", "--cached", "--name-status", "-M30%"][..],
            &["diff", "--cached", "--name-status", "-M80%"][..],
        ] {
            let ours = stdout(&repo.ok(args));
            let theirs = stdout(&git(g.path(), home.path(), args));
            prop_assert_eq!(ours, theirs, "{:?}", args);
        }
    }
}
