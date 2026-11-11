//! `kit log --graph`: the commit graph in the left margin.
//!
//! The commits of one test share a second, so the order of two commits that
//! are not ancestors of each other is not fixed. These tests compare the
//! shape of the graph, with each commit id replaced by `#`, and they sort the
//! lines that can swap.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

mod common;

use common::Repo;

fn stdout(repo: &Repo, args: &[&str]) -> String {
    String::from_utf8(repo.ok(args).stdout).unwrap()
}

/// The lines of `out`, each with its first 7-hex word, or the 64-hex word
/// after `commit`, replaced by `#`.
fn shape(out: &str) -> Vec<String> {
    out.lines()
        .map(|line| {
            line.split(' ')
                .map(|word| {
                    let hex = word.bytes().all(|b| b.is_ascii_hexdigit());
                    if hex && (word.len() == 7 || word.len() == 64) {
                        "#"
                    } else {
                        word
                    }
                })
                .collect::<Vec<_>>()
                .join(" ")
        })
        .collect()
}

/// `main` and `feature` each add a file to `base`. `main` merges `feature`.
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
fn a_linear_history_is_one_column() {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"1\n", "a");
    repo.commit_file("a.txt", b"2\n", "b");
    repo.commit_file("a.txt", b"3\n", "c");
    let out = stdout(&repo, &["log", "--graph", "--oneline"]);
    assert_eq!(shape(&out), ["* # c", "* # b", "* # a"]);
}

#[test]
fn a_merge_opens_a_column_that_joins_at_the_base() {
    let repo = merged();
    let out = stdout(&repo, &["log", "--graph", "--oneline"]);
    let lines = shape(&out);
    assert_eq!(lines.len(), 6, "{out}");
    assert_eq!(lines[0], "* # join");
    assert_eq!(lines[1], "|\\");
    let mut middle = lines[2..4].to_vec();
    middle.sort();
    assert_eq!(middle, ["* | # main2", "| * # feat"]);
    assert_eq!(lines[4], "|/");
    assert_eq!(lines[5], "* # base");
}

#[test]
fn two_branches_show_side_by_side_with_all() {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"base\n", "base");
    repo.ok(&["branch", "topic"]);
    repo.commit_file("m.txt", b"m\n", "on main");
    repo.ok(&["checkout", "topic"]);
    repo.commit_file("t.txt", b"t\n", "on topic");
    repo.ok(&["checkout", "main"]);
    let out = stdout(
        &repo,
        &["log", "--graph", "--oneline", "--all", "--decorate"],
    );
    let lines = shape(&out);
    assert_eq!(lines.len(), 4, "{out}");
    assert!(lines[0].starts_with("* # "), "{out}");
    assert!(lines[1].starts_with("| * # "), "{out}");
    let tips = format!("{}\n{}", lines[0], lines[1]);
    assert!(tips.contains("(HEAD -> main) on main"), "{out}");
    assert!(tips.contains("(topic) on topic"), "{out}");
    assert_eq!(lines[2], "|/");
    assert_eq!(lines[3], "* # base");
}

#[test]
fn a_root_commit_alone_is_one_star() {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"x\n", "only");
    let out = stdout(&repo, &["log", "--graph", "--oneline"]);
    assert_eq!(shape(&out), ["* # only"]);
}

#[test]
fn the_default_format_puts_the_margin_before_every_line() {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"1\n", "first");
    repo.commit_file("a.txt", b"2\n", "second");
    let out = stdout(&repo, &["log", "--graph"]);
    let lines = shape(&out);
    assert_eq!(lines[0], "* commit #");
    assert!(lines[1].starts_with("| Author: ed25519:"), "{out}");
    assert!(lines[2].starts_with("| Date:   "), "{out}");
    assert_eq!(lines[3], "|");
    assert_eq!(lines[4], "|     second");
    assert_eq!(lines[5], "|");
    assert_eq!(lines[6], "* commit #");
    // The root commit ends its column, so its lines have a blank margin.
    assert!(lines[7].starts_with("  Author: ed25519:"), "{out}");
    assert_eq!(lines[9], "");
    assert_eq!(lines[10], "      first");
}

#[test]
fn a_limit_leaves_no_open_line_below_the_last_commit() {
    let repo = merged();
    let out = stdout(&repo, &["log", "--graph", "--oneline", "-n", "1"]);
    assert_eq!(shape(&out), ["* # join"]);
}

#[test]
fn a_range_draws_no_edge_to_a_commit_it_leaves_out() {
    let repo = merged();
    let out = stdout(&repo, &["log", "--graph", "--oneline", "feature..main"]);
    let lines = shape(&out);
    assert_eq!(lines.len(), 2, "{out}");
    assert_eq!(lines[0], "* # join");
    assert_eq!(lines[1], "* # main2");
}

#[test]
fn first_parent_draws_one_column() {
    let repo = merged();
    let out = stdout(&repo, &["log", "--graph", "--oneline", "--first-parent"]);
    assert_eq!(shape(&out), ["* # join", "* # main2", "* # base"]);
}

#[test]
fn a_filter_hides_commits_and_their_edges() {
    let repo = merged();
    let out = stdout(&repo, &["log", "--graph", "--oneline", "--no-merges"]);
    let lines = shape(&out);
    assert_eq!(lines.len(), 4, "{out}");
    assert!(lines.iter().any(|l| l.ends_with("# base")));
}

#[test]
fn control_characters_in_a_message_do_not_reach_the_terminal() {
    let repo = Repo::new();
    repo.write("a.txt", b"x\n");
    repo.ok(&["add", "a.txt"]);
    repo.ok(&["commit", "-m", "evil\x1b[31m\u{202e}title"]);
    let out = stdout(&repo, &["log", "--graph"]);
    assert!(!out.contains('\x1b'), "{out:?}");
    assert!(!out.contains('\u{202e}'), "{out:?}");
    assert!(out.contains("\\u{1b}[31m"), "{out:?}");
}

#[test]
fn graph_excludes_patch_stat_and_json() {
    let repo = merged();
    for flag in ["-p", "--stat", "--format=json"] {
        let out = repo.run(&["log", "--graph", flag]);
        assert_eq!(out.status.code(), Some(64), "{flag}");
        assert!(out.stdout.is_empty(), "{flag}");
    }
}

#[test]
fn graph_is_off_by_default() {
    let repo = merged();
    let out = stdout(&repo, &["log", "--oneline"]);
    assert!(!out.contains("* "), "{out}");
    assert!(!out.contains('|'), "{out}");
}
