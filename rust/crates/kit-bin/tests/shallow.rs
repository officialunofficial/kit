//! A shallow repository: the boundary record `.kit/shallow` and the
//! commands that stop at it (SPEC-SHALLOW §4 to §6).
//!
//! Until `clone --depth` exists, a test makes a repository shallow the way
//! the record allows: it writes the record, then runs `gc`, which keeps the
//! history only down to the record and drops what lies beyond it.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

mod common;

use std::process::Output;

use common::Repo;

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn rev(repo: &Repo, spec: &str) -> String {
    stdout(&repo.ok(&["rev-parse", spec])).trim().to_owned()
}

/// Write the record as `ids` in canonical order.
fn write_record(repo: &Repo, ids: &[&str]) {
    let mut ids: Vec<&str> = ids.to_vec();
    ids.sort_unstable();
    let body: String = ids.iter().map(|id| format!("{id}\n")).collect();
    std::fs::write(repo.kit_dir().join("shallow"), body).unwrap();
}

/// Commits `c1` to `c5` on `main`, with the record at `c3` and the history
/// beyond it dropped. Returns the ids, oldest first.
fn shallow_at_c3() -> (Repo, Vec<String>) {
    let repo = Repo::new();
    for i in 1..=5 {
        repo.commit_file("f.txt", format!("{i}\n").as_bytes(), &format!("c{i}"));
    }
    let ids: Vec<String> = (1..=5)
        .map(|i| rev(&repo, &format!("HEAD~{}", 5 - i)))
        .collect();
    write_record(&repo, &[&ids[2]]);
    repo.ok(&["gc", "--grace-secs", "0"]);
    (repo, ids)
}

fn object_exists(repo: &Repo, id: &str) -> bool {
    repo.run(&["cat-file", "-t", id]).status.success()
}

#[test]
fn gc_drops_the_history_beyond_the_boundary_and_keeps_the_boundary() {
    let (repo, ids) = shallow_at_c3();
    assert!(!object_exists(&repo, &ids[0]), "c1 is beyond the boundary");
    assert!(!object_exists(&repo, &ids[1]), "c2 is beyond the boundary");
    for id in &ids[2..] {
        assert!(object_exists(&repo, id), "the window stays: {id}");
    }
    // The record stays as it was.
    let record = std::fs::read_to_string(repo.kit_dir().join("shallow")).unwrap();
    assert_eq!(record, format!("{}\n", ids[2]));
}

#[test]
fn log_and_rev_list_stop_at_the_boundary() {
    let (repo, ids) = shallow_at_c3();
    let subjects: Vec<String> = stdout(&repo.ok(&["log", "--format=%s"]))
        .lines()
        .map(str::to_owned)
        .collect();
    assert_eq!(subjects, ["c5", "c4", "c3"]);
    let listed: Vec<String> = stdout(&repo.ok(&["rev-list", "HEAD"]))
        .lines()
        .map(str::to_owned)
        .collect();
    assert_eq!(listed, [ids[4].clone(), ids[3].clone(), ids[2].clone()]);
    assert_eq!(
        stdout(&repo.ok(&["rev-list", "--count", "HEAD"])).trim(),
        "3"
    );
    let short: Vec<String> = stdout(&repo.ok(&["shortlog", "-s", "HEAD"]))
        .lines()
        .map(|l| l.trim().split('\t').next().unwrap().to_owned())
        .collect();
    assert_eq!(short, ["3"]);
}

#[test]
fn log_decorate_marks_the_boundary_grafted() {
    let (repo, _) = shallow_at_c3();
    let out = stdout(&repo.ok(&["log", "--oneline", "--decorate"]));
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 3, "{out}");
    assert!(
        lines[2].contains("grafted") && lines[2].ends_with("c3"),
        "{out}"
    );
    assert!(
        !lines[0].contains("grafted") && !lines[1].contains("grafted"),
        "{out}"
    );
}

#[test]
fn closure_verify_accepts_the_window() {
    let (repo, _) = shallow_at_c3();
    let out = repo.run(&["closure", "verify", "HEAD", "--history"]);
    assert!(out.status.success(), "{}{}", stdout(&out), stderr(&out));
}

#[test]
fn closure_verify_refuses_a_record_that_names_a_whole_commit() {
    // c4's parent is present, so naming c4 breaks the record's rule that a
    // commit is in it exactly when a parent is missing.
    let (repo, ids) = shallow_at_c3();
    write_record(&repo, &[&ids[2], &ids[3]]);
    let out = repo.run(&["closure", "verify", "HEAD", "--history"]);
    assert_eq!(
        out.status.code(),
        Some(65),
        "{}{}",
        stdout(&out),
        stderr(&out)
    );
    assert!(stdout(&out).contains(&ids[3]) || stderr(&out).contains(&ids[3]));
}

#[test]
fn a_merge_base_beyond_the_boundary_is_a_typed_error() {
    // c1 - c2 - c3 - c4 - c5 on main, s1 on side from c2. The windows are
    // c4..c5 and s1, so the merge base c2 is beyond the boundary.
    let repo = Repo::new();
    repo.commit_file("f.txt", b"1\n", "c1");
    repo.commit_file("f.txt", b"2\n", "c2");
    repo.ok(&["branch", "side"]);
    for i in 3..=5 {
        repo.commit_file("f.txt", format!("{i}\n").as_bytes(), &format!("c{i}"));
    }
    repo.ok(&["switch", "side"]);
    repo.commit_file("g.txt", b"s\n", "s1");
    repo.ok(&["switch", "main"]);
    let (c4, s1) = (rev(&repo, "main~1"), rev(&repo, "side"));
    write_record(&repo, &[&c4, &s1]);
    repo.ok(&["gc", "--grace-secs", "0"]);
    let head = rev(&repo, "HEAD");

    for args in [&["merge-base", "main", "side"][..], &["merge", "side"]] {
        let out = repo.run(args);
        assert!(!out.status.success(), "{args:?}: {}", stdout(&out));
        let err = stderr(&out);
        assert!(
            err.contains("the merge base is beyond the shallow boundary")
                && err.contains("kit fetch --deepen"),
            "{args:?}: {err}"
        );
    }
    assert_eq!(rev(&repo, "HEAD"), head, "the merge changed nothing");
}

#[test]
fn a_merge_base_inside_the_window_is_found() {
    let (repo, ids) = shallow_at_c3();
    repo.ok(&["update-ref", "refs/heads/side", &ids[3]]);
    assert_eq!(
        stdout(&repo.ok(&["merge-base", "main", "side"])).trim(),
        ids[3]
    );
}

#[test]
fn a_record_that_is_not_canonical_is_refused() {
    let (repo, ids) = shallow_at_c3();
    let (a, b) = if ids[2] < ids[3] {
        (&ids[3], &ids[2])
    } else {
        (&ids[2], &ids[3])
    };
    for body in [
        format!("{a}\n{b}\n"),
        format!("{b}\n{b}\n"),
        String::new(),
        format!("{}\n", b.to_uppercase()),
        b.clone(),
    ] {
        std::fs::write(repo.kit_dir().join("shallow"), &body).unwrap();
        let out = repo.run(&["log", "--format=%s"]);
        assert!(!out.status.success(), "{body:?}: {}", stdout(&out));
        assert!(
            stderr(&out).contains("shallow"),
            "{body:?}: {}",
            stderr(&out)
        );
    }
}
