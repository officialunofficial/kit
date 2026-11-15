//! A push decides "up to date" from the remote, not from the tracking ref.
//!
//! A remote that lost the branch, because its directory was deleted and made
//! again under the same name or because another client deleted the branch,
//! still gets it on the next push. The tracking ref only says what the remote
//! held when this repository last talked to it.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

mod common;

use std::fs;
use std::path::Path;

use common::Repo;

fn remote_main(remote_dir: &Path) -> Option<String> {
    fs::read_to_string(remote_dir.join("refs/heads/main"))
        .ok()
        .map(|s| s.trim().to_string())
}

fn local_main(repo: &Repo) -> String {
    fs::read_to_string(repo.kit_dir().join("refs/heads/main"))
        .unwrap()
        .trim()
        .to_string()
}

fn stderr(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// Push `main` to a new remote at `remote_dir`, and return the repository.
fn pushed(remote_dir: &Path) -> Repo {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"one\n", "one");
    let url = format!("kit+file://{}", remote_dir.display());
    repo.ok(&["remote", "add", "origin", &url]);
    repo.ok(&["push", "-u", "origin", "main"]);
    assert_eq!(remote_main(remote_dir), Some(local_main(&repo)));
    repo
}

#[test]
fn a_push_to_a_deleted_remote_sends_the_branch() {
    let remote = tempfile::tempdir().unwrap();
    let dir = remote.path().join("remote.kit");
    let repo = pushed(&dir);

    // Nothing changed: the remote holds the tip.
    let out = repo.ok(&["push"]);
    assert!(
        stderr(&out).contains("Everything up-to-date"),
        "{}",
        stderr(&out)
    );

    fs::remove_dir_all(&dir).unwrap();
    let out = repo.ok(&["push"]);
    assert!(
        !stderr(&out).contains("Everything up-to-date"),
        "{}",
        stderr(&out)
    );
    assert_eq!(remote_main(&dir), Some(local_main(&repo)));

    // The remote is whole: a clone of it checks out the file.
    let clone = tempfile::tempdir().unwrap();
    let target = clone.path().join("c");
    let url = format!("kit+file://{}", dir.display());
    repo.ok(&["clone", &url, target.to_str().unwrap()]);
    assert_eq!(fs::read(target.join("a.txt")).unwrap(), b"one\n");

    let out = repo.ok(&["push"]);
    assert!(
        stderr(&out).contains("Everything up-to-date"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn a_push_to_a_remote_made_again_by_another_repository_sends_the_branch() {
    let remote = tempfile::tempdir().unwrap();
    let dir = remote.path().join("remote.kit");
    let repo = pushed(&dir);

    fs::remove_dir_all(&dir).unwrap();
    let other = Repo::new();
    other.commit_file("b.txt", b"other\n", "other");
    other.ok(&["branch", "side"]);
    let url = format!("kit+file://{}", dir.display());
    other.ok(&["remote", "add", "origin", &url]);
    other.ok(&["push", "origin", "side"]);
    assert_eq!(remote_main(&dir), None);

    let out = repo.ok(&["push", "--format=json"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("\"up_to_date\":false"), "{stdout}");
    // The summary names what the remote held, not the stale tracking ref.
    assert!(stdout.contains("\"old\":null"), "{stdout}");
    assert!(stderr(&out).contains("[new branch]"), "{}", stderr(&out));
    assert_eq!(remote_main(&dir), Some(local_main(&repo)));
}

/// A remote branch that moved on is not overwritten: the push still refuses
/// a remote head it has not seen.
#[test]
fn a_remote_branch_that_moved_is_still_refused() {
    let remote = tempfile::tempdir().unwrap();
    let dir = remote.path().join("remote.kit");
    let repo = pushed(&dir);
    let url = format!("kit+file://{}", dir.display());

    let clone = tempfile::tempdir().unwrap();
    let target = clone.path().join("c");
    repo.ok(&["clone", &url, target.to_str().unwrap()]);
    common::install_fixed_key(&target).unwrap();
    fs::write(target.join("b.txt"), b"theirs\n").unwrap();
    for args in [
        &["add", "b.txt"][..],
        &["commit", "-m", "theirs"],
        &["push"],
    ] {
        let out = common::kit(&target, repo.xdg(), args);
        assert!(out.status.success(), "{args:?}: {}", stderr(&out));
    }
    let moved = remote_main(&dir);

    repo.commit_file("a.txt", b"two\n", "two");
    let out = repo.run(&["push"]);
    assert!(!out.status.success(), "{}", stderr(&out));
    assert_eq!(remote_main(&dir), moved);
}

/// New local commits made after the remote lost the branch go too, and a
/// push with `--force-with-lease` keeps its exact lease and refuses.
#[test]
fn a_branch_the_remote_lost_takes_newer_commits_but_not_a_lease() {
    let remote = tempfile::tempdir().unwrap();
    let dir = remote.path().join("remote.kit");
    let repo = pushed(&dir);
    fs::remove_dir_all(&dir).unwrap();
    repo.commit_file("a.txt", b"two\n", "two");

    let out = repo.run(&["push", "--force-with-lease"]);
    assert!(!out.status.success(), "{}", stderr(&out));
    assert_eq!(remote_main(&dir), None);

    repo.ok(&["push"]);
    assert_eq!(remote_main(&dir), Some(local_main(&repo)));
}

/// A remote that holds the tip while the tracking ref lags is up to date, and
/// the push moves the tracking ref to what the remote holds.
#[test]
fn a_lagging_tracking_ref_is_brought_up_to_date() {
    let remote = tempfile::tempdir().unwrap();
    let dir = remote.path().join("remote.kit");
    let repo = Repo::new();
    repo.commit_file("a.txt", b"one\n", "one");
    let first = local_main(&repo);
    repo.commit_file("a.txt", b"two\n", "two");
    let url = format!("kit+file://{}", dir.display());
    repo.ok(&["remote", "add", "origin", &url]);
    repo.ok(&["push", "-u", "origin", "main"]);
    let tracking = repo.kit_dir().join("refs/remotes/origin/main");
    fs::write(&tracking, format!("{first}\n")).unwrap();

    let out = repo.ok(&["push", "--format=json"]);
    assert!(
        stderr(&out).contains("Everything up-to-date"),
        "{}",
        stderr(&out)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("\"steps\":0"), "{stdout}");
    assert_eq!(
        fs::read_to_string(&tracking).unwrap().trim(),
        local_main(&repo)
    );
}

/// A push of every branch creates the branches a lost remote no longer holds.
#[test]
fn a_push_of_every_branch_to_a_deleted_remote_sends_them() {
    let remote = tempfile::tempdir().unwrap();
    let dir = remote.path().join("remote.kit");
    let repo = pushed(&dir);
    repo.ok(&["branch", "side"]);
    repo.ok(&["push", "origin", "side"]);
    fs::remove_dir_all(&dir).unwrap();

    repo.ok(&["push", "--all", "origin"]);
    assert_eq!(remote_main(&dir), Some(local_main(&repo)));
    let side = fs::read_to_string(dir.join("refs/heads/side")).unwrap();
    assert_eq!(side.trim(), local_main(&repo));
}
