//! `kit rev-parse --verify`: exactly one revision that resolves to an object.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

mod common;

use std::process::Output;

use common::Repo;

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn repo() -> Repo {
    let repo = Repo::new();
    repo.commit_file("f.txt", b"one\n", "first");
    repo.commit_file("f.txt", b"two\n", "second");
    repo
}

fn head(repo: &Repo) -> String {
    text(&repo.ok(&["rev-parse", "HEAD"]).stdout)
        .trim()
        .to_string()
}

fn assert_fails_silently(out: &Output, code: i32) {
    assert_eq!(out.status.code(), Some(code), "{}", text(&out.stderr));
    assert!(out.stdout.is_empty());
}

#[test]
fn verify_prints_the_full_id_of_one_revision() {
    let repo = repo();
    let id = head(&repo);
    assert_eq!(id.len(), 64);
    for rev in ["HEAD", "main", id.as_str(), &id[..12]] {
        let out = repo.ok(&["rev-parse", "--verify", rev]);
        assert_eq!(text(&out.stdout), format!("{id}\n"), "{rev}");
    }
    let parent = text(&repo.ok(&["rev-parse", "HEAD~1"]).stdout);
    let out = repo.ok(&["rev-parse", "--verify", "HEAD~1"]);
    assert_eq!(text(&out.stdout), parent);
}

#[test]
fn verify_of_a_path_prints_the_blob_id() {
    let repo = repo();
    let plain = repo.ok(&["rev-parse", "HEAD:f.txt"]);
    let out = repo.ok(&["rev-parse", "--verify", "HEAD:f.txt"]);
    assert_eq!(out.stdout, plain.stdout);
    assert_ne!(text(&out.stdout).trim(), head(&repo));
    assert_fails_silently(&repo.run(&["rev-parse", "--verify", "HEAD:missing.txt"]), 1);
}

#[test]
fn verify_fails_on_an_unknown_revision_with_nothing_on_stdout() {
    let repo = repo();
    for rev in ["nope", "HEAD~9", "0".repeat(64).as_str(), "deadbeef"] {
        let out = repo.run(&["rev-parse", "--verify", rev]);
        assert_fails_silently(&out, 1);
        assert!(text(&out.stderr).contains("bad revision"), "{rev}");
    }
}

#[test]
fn verify_fails_on_an_object_the_store_lost() {
    let repo = repo();
    let blob = text(&repo.ok(&["rev-parse", "HEAD:f.txt"]).stdout)
        .trim()
        .to_string();
    let object = repo
        .kit_dir()
        .join("objects")
        .join(&blob[..2])
        .join(&blob[2..]);
    std::fs::remove_file(object).unwrap();
    assert_fails_silently(&repo.run(&["rev-parse", "--verify", "HEAD:f.txt"]), 1);
}

#[test]
fn quiet_drops_the_message_and_keeps_the_exit_code() {
    let repo = repo();
    for flag in ["-q", "--quiet"] {
        let out = repo.run(&["rev-parse", "--verify", flag, "nope"]);
        assert_fails_silently(&out, 1);
        assert!(out.stderr.is_empty(), "{flag}");
        let out = repo.ok(&["rev-parse", "--verify", flag, "HEAD"]);
        assert_eq!(text(&out.stdout), format!("{}\n", head(&repo)));
    }
}

#[test]
fn verify_takes_exactly_one_revision() {
    let repo = repo();
    assert_fails_silently(&repo.run(&["rev-parse", "--verify"]), 64);
    assert_fails_silently(&repo.run(&["rev-parse", "--verify", "HEAD", "HEAD~1"]), 64);
}

#[test]
fn verify_takes_short_and_refuses_the_other_modes() {
    let repo = repo();
    let out = repo.ok(&["rev-parse", "--verify", "--short=9", "HEAD"]);
    assert_eq!(text(&out.stdout), format!("{}\n", &head(&repo)[..9]));
    assert_fails_silently(
        &repo.run(&["rev-parse", "--verify", "--abbrev-ref", "HEAD"]),
        64,
    );
    assert_fails_silently(&repo.run(&["rev-parse", "--verify", "--show-toplevel"]), 64);
    assert_fails_silently(&repo.run(&["rev-parse", "-q", "HEAD"]), 64);
}
