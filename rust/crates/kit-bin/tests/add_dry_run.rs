//! `kit add -n` / `--dry-run`: report what a real add would stage, and write
//! no index and no object.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

mod common;

use std::collections::BTreeMap;
use std::path::Path;

use common::Repo;

/// Every file under `dir`, by path relative to `dir`, with its bytes. The
/// empty lock files stay out: any command creates them on first use.
fn snapshot(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(root, &path, out);
            } else if path.extension().is_none_or(|e| e != "lock") {
                let rel = path.strip_prefix(root).unwrap().display().to_string();
                out.insert(rel, std::fs::read(&path).unwrap());
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(dir, dir, &mut out);
    out
}

fn stdout(repo: &Repo, args: &[&str]) -> String {
    String::from_utf8(repo.ok(args).stdout).unwrap()
}

#[test]
fn dry_run_lists_new_and_changed_files_and_writes_nothing() {
    let repo = Repo::new();
    repo.commit_file("kept.txt", b"kept\n", "first");
    repo.write("kept.txt", b"changed\n");
    repo.write("new.txt", b"new\n");
    repo.write("dir/inner.txt", b"inner\n");
    let before = snapshot(&repo.kit_dir());

    let out = stdout(&repo, &["add", "-n", "."]);
    assert_eq!(out, "add 'dir/inner.txt'\nadd 'kept.txt'\nadd 'new.txt'\n");
    assert_eq!(snapshot(&repo.kit_dir()), before);

    // The long flag and a named path answer the same way.
    assert_eq!(
        stdout(&repo, &["add", "--dry-run", "new.txt"]),
        "add 'new.txt'\n"
    );
    assert_eq!(snapshot(&repo.kit_dir()), before);
}

#[test]
fn dry_run_matches_what_a_real_add_stages() {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"a\n", "first");
    repo.write("a.txt", b"a2\n");
    repo.write("b.txt", b"b\n");

    let planned = stdout(&repo, &["add", "-n", "."]);
    assert_eq!(planned, "add 'a.txt'\nadd 'b.txt'\n");
    repo.ok(&["add", "."]);
    // Everything is staged now, so a second dry run has nothing to report.
    assert_eq!(stdout(&repo, &["add", "-n", "."]), "");
}

#[test]
fn dry_run_reports_deletions_with_all() {
    let repo = Repo::new();
    repo.commit_file("gone.txt", b"gone\n", "first");
    std::fs::remove_file(repo.path().join("gone.txt")).unwrap();
    let before = snapshot(&repo.kit_dir());

    assert_eq!(stdout(&repo, &["add", "-n", "-A"]), "remove 'gone.txt'\n");
    assert_eq!(snapshot(&repo.kit_dir()), before);
}

#[test]
fn dry_run_quotes_a_path_with_special_bytes() {
    let repo = Repo::new();
    repo.write("tab\there.txt", b"x\n");
    assert_eq!(
        stdout(&repo, &["add", "-n", "."]),
        "add \"tab\\there.txt\"\n"
    );
}

#[test]
fn dry_run_keeps_the_errors_of_a_real_add() {
    let repo = Repo::new();
    repo.write(".kitignore", b"skip.txt\n");
    repo.write("skip.txt", b"x\n");
    let before = snapshot(&repo.kit_dir());

    let out = repo.run(&["add", "-n", "skip.txt"]);
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    let out = repo.run(&["add", "-n", "missing.txt"]);
    assert!(!out.status.success());
    assert_eq!(snapshot(&repo.kit_dir()), before);
}

#[test]
fn dry_run_refuses_patch_and_update() {
    let repo = Repo::new();
    repo.write("f.txt", b"x\n");
    for flags in [["-n", "-p"], ["-n", "-u"]] {
        let out = repo.run(&["add", flags[0], flags[1], "f.txt"]);
        assert_eq!(out.status.code(), Some(64), "{flags:?}");
        assert!(out.stdout.is_empty(), "{flags:?}");
    }
}
