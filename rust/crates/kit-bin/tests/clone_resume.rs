//! `kit clone` into a directory that exists: a clone of the same remote that
//! stopped before it published anything resumes; anything else is refused
//! and left as it was.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn run_in(cwd: &Path, args: &[&str]) -> Output {
    let xdg = tempfile::tempdir().expect("xdg tempdir");
    let out = Command::new(env!("CARGO_BIN_EXE_kit"))
        .args(args)
        .current_dir(cwd)
        .env("XDG_CONFIG_HOME", xdg.path())
        .output()
        .expect("spawn kit");
    drop(xdg);
    out
}

fn stderr_str(out: &Output) -> String {
    String::from_utf8(out.stderr.clone()).unwrap()
}

fn read_ref(repo: &Path, name: &str) -> Option<String> {
    fs::read_to_string(repo.join(".kit").join(name))
        .ok()
        .map(|s| s.trim().to_string())
}

/// An upstream whose `main` took two pushes, so its remote holds more than
/// one pack. Returns the work tree, the bare remote, its URL and `main`'s
/// tip; both directories must stay alive.
fn upstream() -> (tempfile::TempDir, tempfile::TempDir, String, String) {
    let td = tempfile::tempdir().unwrap();
    let bare = tempfile::tempdir().unwrap();
    let url = format!("kit+file://{}", bare.path().display());
    assert!(run_in(td.path(), &["init"]).status.success());
    assert!(run_in(td.path(), &["keygen"]).status.success());
    assert!(
        run_in(td.path(), &["remote", "add", "origin", &url])
            .status
            .success()
    );
    for round in ["one", "two"] {
        fs::write(td.path().join(format!("{round}.txt")), round).unwrap();
        assert!(run_in(td.path(), &["add", "."]).status.success());
        assert!(run_in(td.path(), &["commit", "-m", round]).status.success());
        let push = run_in(td.path(), &["push", "origin", "main"]);
        assert!(push.status.success(), "{push:?}");
    }
    let tip = read_ref(td.path(), "refs/heads/main").unwrap();
    (td, bare, url, tip)
}

/// The remote's pack files, sorted.
fn packs(bare: &Path) -> Vec<PathBuf> {
    let mut packs: Vec<PathBuf> = fs::read_dir(bare.join("packs"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    packs.sort();
    packs
}

/// The remote's newest pack: the one the last push wrote.
fn newest_pack(bare: &Path) -> PathBuf {
    packs(bare)
        .into_iter()
        .max_by_key(|pack| fs::metadata(pack).unwrap().modified().unwrap())
        .unwrap()
}

/// Clone `url` into `target` with the remote's newest pack held back, so
/// the clone stops partway, as a lost connection or Ctrl-C stops it.
fn stopped_clone(bare: &Path, url: &str, cwd: &Path, target: &Path) {
    let pack = newest_pack(bare);
    let held = bare.join("held");
    fs::rename(&pack, &held).unwrap();
    let out = run_in(cwd, &["clone", url, target.to_str().unwrap()]);
    fs::rename(&held, &pack).unwrap();
    assert!(!out.status.success(), "the clone must stop: {out:?}");
    assert!(target.join(".kit").is_dir());
    assert_eq!(read_ref(target, "refs/heads/main"), None);
}

#[test]
fn a_stopped_clone_resumes_when_run_again() {
    let (_td, bare, url, tip) = upstream();
    assert!(packs(bare.path()).len() > 1);
    let dest = tempfile::tempdir().unwrap();
    let target = dest.path().join("clone");
    stopped_clone(bare.path(), &url, dest.path(), &target);

    let out = run_in(dest.path(), &["clone", &url, target.to_str().unwrap()]);
    assert!(out.status.success(), "{out:?}");
    assert!(
        stderr_str(&out).contains("Resuming the unfinished clone in"),
        "{}",
        stderr_str(&out)
    );
    assert_eq!(read_ref(&target, "refs/heads/main"), Some(tip));
    assert_eq!(fs::read(target.join("one.txt")).unwrap(), b"one");
    assert_eq!(fs::read(target.join("two.txt")).unwrap(), b"two");

    // Once finished, the clone is a repository like any other.
    let again = run_in(dest.path(), &["clone", &url, target.to_str().unwrap()]);
    assert_eq!(again.status.code(), Some(73), "{again:?}");
    assert!(stderr_str(&again).contains("already exists"));
}

#[test]
fn a_stopped_clone_of_another_remote_is_refused() {
    let (_td, bare, url, _tip) = upstream();
    let (_other_td, _other_bare, other_url, _other_tip) = upstream();
    let dest = tempfile::tempdir().unwrap();
    let target = dest.path().join("clone");
    stopped_clone(bare.path(), &url, dest.path(), &target);
    let config = fs::read(target.join(".kit/config")).unwrap();

    let out = run_in(
        dest.path(),
        &["clone", &other_url, target.to_str().unwrap()],
    );
    assert_eq!(out.status.code(), Some(73), "{out:?}");
    assert!(stderr_str(&out).contains("already exists"));
    assert_eq!(fs::read(target.join(".kit/config")).unwrap(), config);
    assert_eq!(read_ref(&target, "refs/heads/main"), None);
}

#[test]
fn an_unrelated_non_empty_directory_is_refused_and_left_alone() {
    let (_td, _bare, url, _tip) = upstream();
    let dest = tempfile::tempdir().unwrap();
    let target = dest.path().join("clone");
    fs::create_dir(&target).unwrap();
    fs::write(target.join("notes.txt"), b"mine").unwrap();

    let out = run_in(dest.path(), &["clone", &url, target.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(73), "{out:?}");
    assert!(stderr_str(&out).contains("already exists"));
    let entries: Vec<_> = fs::read_dir(&target)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(entries, ["notes.txt"]);
    assert_eq!(fs::read(target.join("notes.txt")).unwrap(), b"mine");
}

#[test]
fn a_clone_stopped_after_its_first_branch_resumes_when_run_again() {
    // `aside` is fetched before `main`, and its tracking ref is published
    // before `main`'s packs download. The push of `main` after it writes the
    // pack the stopped clone does not get.
    let td = tempfile::tempdir().unwrap();
    let bare = tempfile::tempdir().unwrap();
    let url = format!("kit+file://{}", bare.path().display());
    assert!(run_in(td.path(), &["init"]).status.success());
    assert!(run_in(td.path(), &["keygen"]).status.success());
    assert!(
        run_in(td.path(), &["remote", "add", "origin", &url])
            .status
            .success()
    );
    fs::write(td.path().join("one.txt"), "one").unwrap();
    assert!(run_in(td.path(), &["add", "."]).status.success());
    assert!(run_in(td.path(), &["commit", "-m", "one"]).status.success());
    assert!(run_in(td.path(), &["branch", "aside"]).status.success());
    let push = run_in(td.path(), &["push", "origin", "aside"]);
    assert!(push.status.success(), "{push:?}");
    fs::write(td.path().join("two.txt"), "two").unwrap();
    assert!(run_in(td.path(), &["add", "."]).status.success());
    assert!(run_in(td.path(), &["commit", "-m", "two"]).status.success());
    let push = run_in(td.path(), &["push", "origin", "main"]);
    assert!(push.status.success(), "{push:?}");
    let tip = read_ref(td.path(), "refs/heads/main").unwrap();

    let dest = tempfile::tempdir().unwrap();
    let target = dest.path().join("clone");
    stopped_clone(bare.path(), &url, dest.path(), &target);
    let tracking: Vec<_> = fs::read_dir(target.join(".kit/refs/remotes"))
        .unwrap()
        .collect();
    assert!(!tracking.is_empty(), "the first branch was published");

    let out = run_in(dest.path(), &["clone", &url, target.to_str().unwrap()]);
    assert!(out.status.success(), "{out:?}");
    assert!(stderr_str(&out).contains("Resuming the unfinished clone in"));
    assert_eq!(read_ref(&target, "refs/heads/main"), Some(tip));
    assert_eq!(fs::read(target.join("two.txt")).unwrap(), b"two");
}

#[test]
fn a_stopped_clone_holding_anything_a_clone_does_not_write_is_refused() {
    let (_td, bare, url, _tip) = upstream();
    let dest = tempfile::tempdir().unwrap();
    let target = dest.path().join("clone");
    stopped_clone(bare.path(), &url, dest.path(), &target);
    // A signing key a later commit would use: a clone never writes one.
    fs::create_dir(target.join(".kit/keys")).unwrap();
    fs::write(target.join(".kit/keys/default.key"), b"planted").unwrap();

    let out = run_in(dest.path(), &["clone", &url, target.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(73), "{out:?}");
    assert_eq!(read_ref(&target, "refs/heads/main"), None);
    assert_eq!(
        fs::read(target.join(".kit/keys/default.key")).unwrap(),
        b"planted"
    );
}

#[test]
fn a_stopped_clone_holding_a_ref_a_clone_does_not_write_is_refused() {
    let (_td, bare, url, tip) = upstream();
    let dest = tempfile::tempdir().unwrap();
    let target = dest.path().join("clone");
    stopped_clone(bare.path(), &url, dest.path(), &target);
    // A tag the resumed clone would keep: a stopped clone has none.
    let tags = target.join(".kit/refs/tags");
    fs::write(tags.join("v1"), format!("{tip}\n")).unwrap();

    let out = run_in(dest.path(), &["clone", &url, target.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(73), "{out:?}");
    assert_eq!(read_ref(&target, "refs/heads/main"), None);
    assert!(tags.join("v1").exists());
}
