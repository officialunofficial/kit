//! `<rev>:<path>` in `show`, `cat-file` and `rev-parse`: the object at a path
//! in the tree of a revision.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

mod common;

use std::io::Write;
use std::process::{Command, Output, Stdio};

use common::Repo;

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn stdout(out: &Output) -> String {
    text(&out.stdout)
}

/// Three commits. `f.txt` is `v1`, then `dir/sub.txt` is added, then `f.txt`
/// is `v2`.
fn three_commits() -> Repo {
    let repo = Repo::new();
    repo.commit_file("f.txt", b"v1\n", "first");
    repo.commit_file("dir/sub.txt", b"sub\n", "second");
    repo.commit_file("f.txt", b"v2\n", "third");
    repo
}

/// The id of the entry `name` in the top tree of `rev`.
fn entry_id(repo: &Repo, rev: &str, name: &str) -> String {
    let listing = stdout(&repo.ok(&["ls-tree", rev]));
    listing
        .lines()
        .find_map(|l| {
            let (meta, n) = l.split_once('\t')?;
            (n == name).then(|| meta.split_whitespace().nth(2).unwrap().to_string())
        })
        .unwrap()
}

fn remove_object(repo: &Repo, id: &str) {
    let object = repo.kit_dir().join("objects").join(&id[..2]).join(&id[2..]);
    std::fs::remove_file(object).unwrap();
}

#[test]
fn show_prints_a_file_of_a_revision() {
    let repo = three_commits();
    assert_eq!(stdout(&repo.ok(&["show", "HEAD:f.txt"])), "v2\n");
    assert_eq!(stdout(&repo.ok(&["show", "HEAD~2:f.txt"])), "v1\n");
    assert_eq!(stdout(&repo.ok(&["show", "HEAD:dir/sub.txt"])), "sub\n");
    assert_eq!(stdout(&repo.ok(&["show", "main:f.txt"])), "v2\n");
}

#[test]
fn show_lists_a_directory_of_a_revision() {
    let repo = three_commits();
    let out = stdout(&repo.ok(&["show", "HEAD:dir"]));
    assert!(out.starts_with("100644 blob "), "{out}");
    assert!(out.ends_with("\tsub.txt\n"), "{out}");
}

#[test]
fn show_takes_several_paths() {
    let repo = three_commits();
    let out = stdout(&repo.ok(&["show", "HEAD~2:f.txt", "HEAD:f.txt"]));
    assert_eq!(out, "v1\nv2\n");
}

#[test]
fn cat_file_reads_a_path_of_a_revision() {
    let repo = three_commits();
    assert_eq!(stdout(&repo.ok(&["cat-file", "-p", "HEAD:f.txt"])), "v2\n");
    assert_eq!(
        stdout(&repo.ok(&["cat-file", "-t", "HEAD:f.txt"])),
        "blob\n"
    );
    assert_eq!(stdout(&repo.ok(&["cat-file", "-s", "HEAD:f.txt"])), "3\n");
    assert_eq!(stdout(&repo.ok(&["cat-file", "-t", "HEAD:dir"])), "tree\n");
    assert_eq!(
        stdout(&repo.ok(&["cat-file", "-p", "HEAD~2:f.txt"])),
        "v1\n"
    );
}

#[test]
fn cat_file_batch_reads_a_path_of_a_revision() {
    let repo = three_commits();
    let mut child = Command::new(env!("CARGO_BIN_EXE_kit"))
        .args(["cat-file", "--batch"])
        .current_dir(repo.path())
        .env("XDG_CONFIG_HOME", repo.xdg())
        .env("HOME", repo.xdg())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"HEAD:f.txt\nHEAD:nope\n")
        .unwrap();
    let out = child.wait_with_output().unwrap();
    let id = entry_id(&repo, "HEAD", "f.txt");
    assert_eq!(
        stdout(&out),
        format!("{id} blob 3\nv2\n\nHEAD:nope missing\n")
    );
}

#[test]
fn rev_parse_resolves_a_path_of_a_revision() {
    let repo = three_commits();
    let id = entry_id(&repo, "HEAD", "f.txt");
    assert_eq!(
        stdout(&repo.ok(&["rev-parse", "HEAD:f.txt"])),
        format!("{id}\n")
    );
    let old = entry_id(&repo, "HEAD~2", "f.txt");
    assert_ne!(id, old);
    assert_eq!(
        stdout(&repo.ok(&["rev-parse", "HEAD~2:f.txt"])),
        format!("{old}\n")
    );
    let short = stdout(&repo.ok(&["rev-parse", "--short=9", "HEAD:f.txt"]));
    assert_eq!(short, format!("{}\n", &id[..9]));
}

#[test]
fn a_root_commit_has_its_files() {
    let repo = Repo::new();
    repo.commit_file("only.txt", b"x\n", "root");
    assert_eq!(stdout(&repo.ok(&["show", "HEAD:only.txt"])), "x\n");
}

#[test]
fn a_tag_names_the_tree_of_its_commit() {
    let repo = three_commits();
    repo.ok(&["tag", "v1", "HEAD~2"]);
    assert_eq!(stdout(&repo.ok(&["show", "v1:f.txt"])), "v1\n");
}

#[test]
fn a_bad_path_fails_in_every_command() {
    let repo = three_commits();
    // Each spec with the text that its error message holds. `show` and
    // `rev-parse` exit 1. `cat-file` exits 65.
    let cases = [
        ("HEAD:", "the path is empty"),
        (":f.txt", "unknown revision"),
        ("HEAD:/f.txt", "empty"),
        ("HEAD:dir/", "empty"),
        ("HEAD:dir//sub.txt", "empty"),
        ("HEAD:../f.txt", "'..'"),
        ("HEAD:dir/../f.txt", "'..'"),
        ("HEAD:./f.txt", "'.'"),
        ("HEAD:missing", "does not exist"),
        ("HEAD:dir/missing", "does not exist"),
        ("HEAD:f.txt/more", "does not exist"),
        ("nope:f.txt", "unknown revision"),
    ];
    for (spec, message) in cases {
        for (args, code) in [
            (vec!["show", spec], 1),
            (vec!["cat-file", "-p", spec], 65),
            (vec!["rev-parse", spec], 1),
        ] {
            let out = repo.run(&args);
            assert_eq!(out.status.code(), Some(code), "{args:?}");
            assert!(out.stdout.is_empty(), "{args:?}: {}", stdout(&out));
            let err = text(&out.stderr);
            assert!(err.contains(message), "{args:?}: {err}");
        }
    }
}

#[test]
fn a_path_longer_than_the_limit_fails() {
    let repo = three_commits();
    let spec = format!("HEAD:{}", "a/".repeat(4097));
    let out = repo.run(&["show", &spec]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("too long"));
}

#[test]
fn a_missing_blob_object_is_an_error_not_a_wrong_answer() {
    let repo = three_commits();
    remove_object(&repo, &entry_id(&repo, "HEAD", "f.txt"));
    for args in [
        vec!["show", "HEAD:f.txt"],
        vec!["cat-file", "-p", "HEAD:f.txt"],
    ] {
        let out = repo.run(&args);
        assert!(!out.status.success(), "{args:?}");
        assert!(out.stdout.is_empty(), "{args:?}");
        assert_ne!(out.status.code(), Some(101), "{args:?}");
    }
}

#[test]
fn a_missing_tree_object_is_an_error_not_a_wrong_answer() {
    let repo = three_commits();
    remove_object(&repo, &entry_id(&repo, "HEAD", "dir"));
    let out = repo.run(&["show", "HEAD:dir/sub.txt"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("read object"));
}
