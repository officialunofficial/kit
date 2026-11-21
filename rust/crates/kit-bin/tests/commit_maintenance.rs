//! `kit commit` runs the due maintenance step, so a repository that never
//! fetches does not build up packs. The step changes neither the exit code nor
//! the output, except for its own maintenance line.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

fn run_in(cwd: &Path, args: &[&str]) -> Output {
    let xdg = tempfile::tempdir().expect("xdg tempdir");
    Command::new(env!("CARGO_BIN_EXE_kit"))
        .args(args)
        .current_dir(cwd)
        .env("XDG_CONFIG_HOME", xdg.path())
        .output()
        .expect("spawn kit")
}

fn ok(cwd: &Path, args: &[&str]) -> Output {
    let out = run_in(cwd, args);
    assert!(out.status.success(), "{args:?} failed: {out:?}");
    out
}

/// `len` bytes that no two seeds share and that do not compress.
fn bytes(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state.to_le_bytes()[3]
        })
        .collect()
}

fn repo() -> tempfile::TempDir {
    let repo = tempfile::tempdir().unwrap();
    ok(repo.path(), &["init"]);
    ok(repo.path(), &["keygen"]);
    repo
}

/// Add one file above the chunking threshold, which leaves one pack pair.
fn add_large(repo: &Path, n: u64) {
    fs::write(repo.join(format!("f{n}")), bytes(n, 1024 * 1024 + 4096)).unwrap();
    ok(repo, &["add", &format!("f{n}")]);
}

fn pairs(repo: &Path) -> usize {
    fs::read_dir(repo.join(".kit/objects/pack")).map_or(0, |entries| {
        entries
            .filter(|entry| {
                let name = entry.as_ref().unwrap().file_name();
                let name = name.to_string_lossy();
                !name.starts_with('.') && name.ends_with(".pack")
            })
            .count()
    })
}

fn stamp(repo: &Path) -> Option<Vec<u8>> {
    fs::read(repo.join(".kit/gc-auto")).ok()
}

/// The outcome byte of a stamp: 2 is a complete collection.
const COMPLETE: u8 = 2;

fn build_up(repo: &Path, count: u64) {
    for n in 0..count {
        add_large(repo, n);
    }
    assert_eq!(pairs(repo), count as usize);
}

#[test]
fn a_commit_runs_the_due_step_and_a_second_commit_does_not() {
    let repo = repo();
    build_up(repo.path(), 33);
    assert_eq!(stamp(repo.path()), None, "an add never runs the step");

    let first = ok(repo.path(), &["commit", "-m", "one"]);
    let stamp_after = stamp(repo.path()).expect("the due step stamps");
    assert_eq!(stamp_after[8], COMPLETE);
    assert!(
        !String::from_utf8(first.stdout).unwrap().contains("maint"),
        "nothing is added to stdout"
    );

    fs::write(repo.path().join("g"), b"small").unwrap();
    ok(repo.path(), &["add", "g"]);
    let second = ok(repo.path(), &["commit", "-m", "two"]);
    assert_eq!(stamp(repo.path()), Some(stamp_after), "not due: untouched");
    assert!(!String::from_utf8(second.stderr).unwrap().contains("maintenance:"));
}

#[test]
fn a_commit_under_the_floor_runs_no_collection() {
    let repo = repo();
    build_up(repo.path(), 3);
    ok(repo.path(), &["commit", "-m", "one"]);
    assert_eq!(stamp(repo.path()).map(|s| s.len()), Some(0));
}

#[test]
fn gc_auto_false_skips_the_step() {
    let repo = repo();
    ok(repo.path(), &["config", "--local", "gc.auto", "false"]);
    build_up(repo.path(), 33);
    ok(repo.path(), &["commit", "-m", "one"]);
    assert_eq!(stamp(repo.path()), None);
}

#[test]
fn a_loose_only_repository_runs_no_collection() {
    let repo = repo();
    fs::write(repo.path().join("a"), b"one").unwrap();
    ok(repo.path(), &["add", "a"]);
    ok(repo.path(), &["commit", "-m", "one"]);
    assert_eq!(stamp(repo.path()).map(|s| s.len()), Some(0));
}

#[test]
fn the_step_leaves_the_commit_output_and_exit_code_alone() {
    let due = repo();
    build_up(due.path(), 33);
    let plain = repo();
    build_up(plain.path(), 3);

    let a = ok(due.path(), &["commit", "--format=json", "-m", "one"]);
    let b = ok(plain.path(), &["commit", "--format=json", "-m", "one"]);
    let keys = |out: &Output| -> Vec<String> {
        let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        json.as_object().unwrap().keys().cloned().collect()
    };
    assert_eq!(keys(&a), keys(&b));
    assert_eq!(a.status.code(), b.status.code());
}
