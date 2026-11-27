//! `kit reflog --recovery` and the `recovery@{N}` revision: the commits that
//! `commit --amend`, `reset`, `rebase` and `stash pop` replaced, and the way
//! back to them.
//!
//! The fixed cases pin the output, the numbering and the errors. A property
//! test drives random commit, amend and reset sequences through the binary
//! and checks every `recovery@{N}` against a model of the replaced tips.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

mod common;

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Output;

use common::Repo;
use proptest::prelude::*;

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn rev(repo: &Repo, spec: &str) -> String {
    stdout(&repo.ok(&["rev-parse", spec])).trim().to_owned()
}

fn recovery_lines(repo: &Repo, extra: &[&str]) -> Vec<String> {
    let mut args = vec!["reflog", "--recovery"];
    args.extend_from_slice(extra);
    stdout(&repo.ok(&args)).lines().map(str::to_owned).collect()
}

/// Two commits on `main`.
fn two_commits() -> Repo {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"1\n", "first");
    repo.commit_file("a.txt", b"2\n", "second");
    repo
}

#[test]
fn an_empty_log_prints_nothing() {
    let repo = two_commits();
    assert!(recovery_lines(&repo, &[]).is_empty());
    let out = repo.run(&["rev-parse", "recovery@{0}"]);
    assert!(!out.status.success());
}

#[test]
fn amend_records_the_replaced_commit_and_recovery_names_it() {
    let repo = two_commits();
    let before = rev(&repo, "HEAD");
    repo.ok(&["commit", "--amend", "-m", "second, amended"]);
    let lines = recovery_lines(&repo, &[]);
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_eq!(
        lines[0],
        format!("{} recovery@{{0}}: amend (main): second", &before[..8])
    );
    assert_eq!(rev(&repo, "recovery@{0}"), before);
    assert_eq!(rev(&repo, "recovery@{0}~1"), rev(&repo, "HEAD~1"));
}

#[test]
fn reset_hard_to_recovery_undoes_an_amend() {
    let repo = two_commits();
    let before = rev(&repo, "HEAD");
    repo.ok(&["commit", "--amend", "-m", "oops"]);
    repo.ok(&["reset", "--hard", "recovery@{0}"]);
    assert_eq!(rev(&repo, "HEAD"), before);
    assert_eq!(std::fs::read(repo.path().join("a.txt")).unwrap(), b"2\n");
}

#[test]
fn reset_and_rebase_record_their_op() {
    let repo = two_commits();
    let tip = rev(&repo, "HEAD");
    repo.ok(&["reset", "--hard", "HEAD~1"]);
    assert!(recovery_lines(&repo, &[])[0].contains("recovery@{0}: reset (main): second"));
    assert_eq!(rev(&repo, "recovery@{0}"), tip);

    repo.ok(&["branch", "topic"]);
    repo.ok(&["checkout", "topic"]);
    repo.commit_file("b.txt", b"topic\n", "topic work");
    let topic = rev(&repo, "HEAD");
    repo.ok(&["checkout", "main"]);
    repo.commit_file("c.txt", b"main\n", "main work");
    repo.ok(&["checkout", "topic"]);
    repo.ok(&["rebase", "main"]);
    let lines = recovery_lines(&repo, &[]);
    assert!(
        lines[0].contains("recovery@{0}: rebase (topic): topic work"),
        "{lines:?}"
    );
    assert_eq!(rev(&repo, "recovery@{0}"), topic);
    assert!(lines[1].contains("recovery@{1}: reset (main)"), "{lines:?}");
}

#[test]
fn the_newest_record_is_zero() {
    let repo = two_commits();
    let first = rev(&repo, "HEAD");
    repo.ok(&["commit", "--amend", "-m", "one"]);
    let second = rev(&repo, "HEAD");
    repo.ok(&["commit", "--amend", "-m", "two"]);
    assert_eq!(rev(&repo, "recovery@{0}"), second);
    assert_eq!(rev(&repo, "recovery@{1}"), first);
}

#[test]
fn a_recovered_commit_can_start_a_branch() {
    let repo = two_commits();
    let before = rev(&repo, "HEAD");
    repo.ok(&["commit", "--amend", "-m", "rewritten"]);
    repo.ok(&["switch", "-c", "rescue", "recovery@{0}"]);
    assert_eq!(rev(&repo, "HEAD"), before);
    assert_eq!(rev(&repo, "rescue"), before);
}

#[test]
fn reset_hard_to_recovery_keeps_the_data_loss_guard() {
    let repo = two_commits();
    repo.ok(&["commit", "--amend", "-m", "rewritten"]);
    repo.write("a.txt", b"local edit\n");
    let out = repo.run(&["reset", "--hard", "recovery@{0}"]);
    assert!(!out.status.success(), "the guard refuses to drop the edit");
    assert_eq!(
        std::fs::read(repo.path().join("a.txt")).unwrap(),
        b"local edit\n"
    );
}

#[test]
fn a_number_past_the_end_or_malformed_is_an_error() {
    let repo = two_commits();
    repo.ok(&["commit", "--amend", "-m", "rewritten"]);
    for spec in [
        "recovery@{1}",
        "recovery@{999}",
        "recovery@{-1}",
        "recovery@{x}",
        "recovery@{}",
    ] {
        let out = repo.run(&["rev-parse", spec]);
        assert!(!out.status.success(), "{spec}");
        assert!(
            stderr(&out).contains("recovery@{"),
            "{spec}: {}",
            stderr(&out)
        );
    }
}

#[test]
fn a_branch_filter_keeps_the_full_numbering() {
    let repo = two_commits();
    repo.ok(&["commit", "--amend", "-m", "main amend"]);
    repo.ok(&["branch", "topic"]);
    repo.ok(&["checkout", "topic"]);
    repo.commit_file("b.txt", b"1\n", "topic commit");
    repo.ok(&["commit", "--amend", "-m", "topic amend"]);
    let main = recovery_lines(&repo, &["main"]);
    assert_eq!(main.len(), 1, "{main:?}");
    assert!(main[0].contains("recovery@{1}: amend (main)"), "{main:?}");
    let topic = recovery_lines(&repo, &["topic"]);
    assert_eq!(topic.len(), 1, "{topic:?}");
    assert!(
        topic[0].contains("recovery@{0}: amend (topic)"),
        "{topic:?}"
    );
    assert_eq!(recovery_lines(&repo, &["-n", "1"]).len(), 1);
}

#[test]
fn json_has_one_record_per_line() {
    let repo = two_commits();
    let before = rev(&repo, "HEAD");
    repo.ok(&["commit", "--amend", "-m", "rewritten"]);
    let json = stdout(&repo.ok(&["reflog", "--recovery", "--format=json"]));
    let line = json.lines().next().unwrap();
    assert!(
        line.starts_with("{\"index\":0,\"selector\":\"recovery@{0}\","),
        "{line}"
    );
    assert!(line.contains(&format!("\"hash\":\"{before}\"")), "{line}");
    assert!(line.contains("\"op\":\"amend\""), "{line}");
    assert!(line.contains("\"branch\":\"main\""), "{line}");
    assert!(line.contains("\"title\":\"second\""), "{line}");
    assert!(line.contains("\"pruned\":false"), "{line}");
    assert!(line.contains("\"time\":"), "{line}");
}

/// Every file under `dir`, with its bytes.
fn snapshot(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else {
                out.insert(path.display().to_string(), std::fs::read(&path).unwrap());
            }
        }
    }
    out
}

#[test]
fn listing_writes_nothing() {
    let repo = two_commits();
    repo.ok(&["commit", "--amend", "-m", "rewritten"]);
    let before = snapshot(&repo.kit_dir());
    recovery_lines(&repo, &[]);
    repo.ok(&["reflog", "--recovery", "--format=json"]);
    repo.ok(&["rev-parse", "recovery@{0}"]);
    assert_eq!(snapshot(&repo.kit_dir()), before);
}

#[test]
fn gc_keeps_a_listed_commit() {
    let repo = two_commits();
    let before = rev(&repo, "HEAD");
    repo.ok(&["commit", "--amend", "-m", "rewritten"]);
    repo.ok(&["gc"]);
    assert_eq!(rev(&repo, "recovery@{0}"), before);
    let shown = stdout(&repo.ok(&["show", "recovery@{0}"]));
    assert!(shown.contains("second"), "{shown}");
}

#[test]
fn a_record_whose_commit_is_gone_prints_pruned() {
    let repo = two_commits();
    let missing = "ab".repeat(32);
    let log = repo.kit_dir().join("recovery-log");
    std::fs::write(&log, format!("100\treset\t{missing}\tmain\n")).unwrap();
    let lines = recovery_lines(&repo, &[]);
    assert_eq!(lines, ["abababab recovery@{0}: reset (main): (pruned)"]);
    let out = repo.run(&["rev-parse", "recovery@{0}"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("pruned"), "{}", stderr(&out));
}

#[test]
fn a_torn_last_line_is_ignored_and_a_bad_line_fails() {
    let repo = two_commits();
    let before = rev(&repo, "HEAD");
    repo.ok(&["commit", "--amend", "-m", "rewritten"]);
    let log = repo.kit_dir().join("recovery-log");
    let mut bytes = std::fs::read(&log).unwrap();
    bytes.extend_from_slice(b"123\tamend\tabc");
    std::fs::write(&log, &bytes).unwrap();
    assert_eq!(recovery_lines(&repo, &[]).len(), 1);
    assert_eq!(rev(&repo, "recovery@{0}"), before);
    bytes.extend_from_slice(b"\n");
    std::fs::write(&log, &bytes).unwrap();
    let out = repo.run(&["reflog", "--recovery"]);
    assert_eq!(out.status.code(), Some(65), "{}", stderr(&out));
}

// ---------------------------------------------------------------------------
// Property: random amend and reset sequences against a model.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
enum Op {
    Commit,
    Amend,
    ResetBack,
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![Just(Op::Commit), Just(Op::Amend), Just(Op::ResetBack)]
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: std::env::var("PROPTEST_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(12),
        ..ProptestConfig::default()
    })]

    /// `recovery@{N}` names the N-th most recently replaced tip, and
    /// `reset --hard recovery@{0}` restores the last replaced tip exactly.
    #[test]
    fn recovery_names_every_replaced_tip(ops in prop::collection::vec(op(), 1..7)) {
        let repo = Repo::new();
        repo.commit_file("f.txt", b"base\n", "base");
        let mut depth = 1usize;
        let mut replaced: Vec<String> = Vec::new();
        for (n, op) in ops.iter().enumerate() {
            match op {
                Op::Commit => {
                    repo.commit_file("f.txt", format!("c{n}\n").as_bytes(), &format!("c{n}"));
                    depth += 1;
                }
                Op::Amend => {
                    replaced.push(rev(&repo, "HEAD"));
                    repo.write("f.txt", format!("a{n}\n").as_bytes());
                    repo.ok(&["add", "f.txt"]);
                    repo.ok(&["commit", "--amend", "-m", &format!("a{n}")]);
                }
                Op::ResetBack if depth > 1 => {
                    replaced.push(rev(&repo, "HEAD"));
                    repo.ok(&["reset", "--hard", "HEAD~1"]);
                    depth -= 1;
                }
                Op::ResetBack => {}
            }
        }
        let lines = recovery_lines(&repo, &[]);
        prop_assert_eq!(lines.len(), replaced.len());
        for (k, tip) in replaced.iter().rev().enumerate() {
            prop_assert_eq!(&rev(&repo, &format!("recovery@{{{k}}}")), tip);
        }
        if let Some(last) = replaced.last() {
            repo.ok(&["reset", "--hard", "recovery@{0}"]);
            prop_assert_eq!(&rev(&repo, "HEAD"), last);
        }
    }
}
