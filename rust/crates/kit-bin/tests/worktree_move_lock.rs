//! `kit worktree move/lock/unlock/repair`, driven through the real binary:
//! a lock stops remove, prune and move; a move rewrites the links in both
//! directions; repair fixes a tree that moved by hand.

mod common;

use std::path::PathBuf;
use std::process::Output;

use common::{Repo, kit};

fn add_tree(repo: &Repo, host: &tempfile::TempDir, name: &str) -> PathBuf {
    let tree = host.path().join(name);
    repo.ok(&["worktree", "add", &tree.to_string_lossy()]);
    tree
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn seeded() -> Repo {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"one\n", "seed");
    repo
}

#[test]
fn lock_blocks_remove_and_needs_two_forces() {
    let repo = seeded();
    let host = tempfile::tempdir().unwrap();
    let tree = add_tree(&repo, &host, "topic");
    let tree_str = tree.to_string_lossy().into_owned();

    repo.ok(&["worktree", "lock", "--reason", "on a usb disk", &tree_str]);
    let porcelain = stdout(&repo.ok(&["worktree", "list", "--porcelain"]));
    assert!(porcelain.contains("locked on a usb disk\n"), "{porcelain}");
    assert!(stdout(&repo.ok(&["worktree", "list"])).contains(" locked"));

    let out = repo.run(&["worktree", "lock", &tree_str]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("already locked"));

    let out = repo.run(&["worktree", "remove", &tree_str]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("locked (on a usb disk)"),
        "{}",
        stderr(&out)
    );
    let out = repo.run(&["worktree", "remove", "-f", &tree_str]);
    assert!(!out.status.success());
    assert!(tree.exists());

    repo.ok(&["worktree", "remove", "-f", "-f", &tree_str]);
    assert!(!tree.exists());
    assert!(!repo.kit_dir().join("worktrees/topic").exists());
}

#[test]
fn unlock_allows_remove_and_refuses_an_unlocked_tree() {
    let repo = seeded();
    let host = tempfile::tempdir().unwrap();
    let tree = add_tree(&repo, &host, "topic");
    let tree_str = tree.to_string_lossy().into_owned();

    let out = repo.run(&["worktree", "unlock", &tree_str]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("not locked"));

    repo.ok(&["worktree", "lock", &tree_str]);
    assert!(stdout(&repo.ok(&["worktree", "list", "--porcelain"])).contains("locked\n"));
    repo.ok(&["worktree", "unlock", &tree_str]);
    assert!(!stdout(&repo.ok(&["worktree", "list", "--porcelain"])).contains("locked"));
    repo.ok(&["worktree", "remove", &tree_str]);
    assert!(!tree.exists());
}

#[test]
fn lock_refuses_the_main_tree_an_unknown_path_and_a_bad_reason() {
    let repo = seeded();
    let host = tempfile::tempdir().unwrap();
    let tree = add_tree(&repo, &host, "topic");
    let main = repo.path().to_string_lossy().into_owned();

    for sub in ["lock", "unlock"] {
        let out = repo.run(&["worktree", sub, &main]);
        assert!(!out.status.success());
        assert!(
            stderr(&out).contains("main working tree"),
            "{}",
            stderr(&out)
        );
    }
    let nowhere = host.path().join("nowhere").to_string_lossy().into_owned();
    let out = repo.run(&["worktree", "lock", &nowhere]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("not a linked worktree"));

    let out = repo.run(&[
        "worktree",
        "lock",
        "--reason",
        "two\nlines",
        &tree.to_string_lossy(),
    ]);
    assert!(!out.status.success());
    assert!(!repo.kit_dir().join("worktrees/topic/locked").exists());
}

#[test]
fn prune_keeps_a_locked_entry_whose_tree_is_gone() {
    let repo = seeded();
    let host = tempfile::tempdir().unwrap();
    let kept = add_tree(&repo, &host, "kept");
    let gone = add_tree(&repo, &host, "gone");
    repo.ok(&["worktree", "lock", &kept.to_string_lossy()]);
    repo.ok(&["worktree", "lock", &gone.to_string_lossy()]);
    std::fs::remove_dir_all(&kept).unwrap();
    std::fs::remove_dir_all(&gone).unwrap();
    repo.ok(&["worktree", "unlock", &gone.to_string_lossy()]);

    let out = repo.ok(&["worktree", "prune"]);
    assert!(stdout(&out).contains("pruned worktrees/gone"));
    assert!(!stdout(&out).contains("kept"));
    assert!(repo.kit_dir().join("worktrees/kept").exists());
    assert!(!repo.kit_dir().join("worktrees/gone").exists());
    let listed = stdout(&repo.ok(&["worktree", "list", "--porcelain"]));
    assert!(listed.contains("prunable"), "{listed}");
    assert!(listed.contains("locked\n"), "{listed}");
}

#[test]
fn move_relocates_the_tree_and_keeps_it_working() {
    let repo = seeded();
    let host = tempfile::tempdir().unwrap();
    let tree = add_tree(&repo, &host, "topic");
    let dest = host.path().join("moved");

    repo.ok(&[
        "worktree",
        "move",
        &tree.to_string_lossy(),
        &dest.to_string_lossy(),
    ]);
    assert!(!tree.exists());
    assert_eq!(std::fs::read(dest.join("a.txt")).unwrap(), b"one\n");

    let back = std::fs::read_to_string(repo.kit_dir().join("worktrees/topic/kitdir")).unwrap();
    let real = dest.canonicalize().unwrap();
    assert_eq!(back, format!("{}\n", real.join(".kit").display()));
    let pointer = std::fs::read_to_string(dest.join(".kit")).unwrap();
    assert!(pointer.starts_with("kitdir: "), "{pointer}");

    let listed = stdout(&repo.ok(&["worktree", "list", "--porcelain"]));
    assert!(
        listed.contains(&format!("worktree {}", real.display())),
        "{listed}"
    );
    assert!(!listed.contains("prunable"));

    // The moved tree is live.
    std::fs::write(dest.join("b.txt"), b"two\n").unwrap();
    for args in [&["add", "b.txt"][..], &["commit", "-m", "in moved"][..]] {
        let out = kit(&dest, repo.xdg(), args);
        assert!(out.status.success(), "{}", stderr(&out));
    }
    repo.ok(&["worktree", "remove", "--force", &dest.to_string_lossy()]);
}

#[test]
fn move_refuses_the_main_tree_and_the_current_tree() {
    let repo = seeded();
    let host = tempfile::tempdir().unwrap();
    let tree = add_tree(&repo, &host, "topic");
    let dest = host.path().join("moved").to_string_lossy().into_owned();

    let out = repo.run(&["worktree", "move", &repo.path().to_string_lossy(), &dest]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("main working tree"));

    let out = kit(&tree, repo.xdg(), &["worktree", "move", ".", &dest]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("currently inside"),
        "{}",
        stderr(&out)
    );
    assert!(tree.exists());
}

#[test]
fn move_refuses_a_locked_tree_unless_forced_twice() {
    let repo = seeded();
    let host = tempfile::tempdir().unwrap();
    let tree = add_tree(&repo, &host, "topic");
    let tree_str = tree.to_string_lossy().into_owned();
    let dest = host.path().join("moved");
    let dest_str = dest.to_string_lossy().into_owned();
    repo.ok(&["worktree", "lock", &tree_str]);

    let out = repo.run(&["worktree", "move", &tree_str, &dest_str]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("locked"));
    let out = repo.run(&["worktree", "move", "-f", &tree_str, &dest_str]);
    assert!(!out.status.success());
    assert!(tree.exists() && !dest.exists());

    repo.ok(&["worktree", "move", "-f", "-f", &tree_str, &dest_str]);
    assert!(dest.join("a.txt").exists());
    // The lock moves with the registry entry.
    assert!(stdout(&repo.ok(&["worktree", "list", "--porcelain"])).contains("locked\n"));
}

#[test]
fn move_validates_the_destination() {
    let repo = seeded();
    let host = tempfile::tempdir().unwrap();
    let tree = add_tree(&repo, &host, "topic");
    let tree_str = tree.to_string_lossy().into_owned();
    let try_move = |dest: &str| repo.run(&["worktree", "move", &tree_str, dest]);

    // An existing path is refused, even an empty directory or a dangling link.
    let empty = host.path().join("empty");
    std::fs::create_dir(&empty).unwrap();
    let out = try_move(&empty.to_string_lossy());
    assert!(!out.status.success());
    assert!(stderr(&out).contains("already exists"), "{}", stderr(&out));
    #[cfg(unix)]
    {
        let link = host.path().join("link");
        std::os::unix::fs::symlink(host.path().join("nowhere"), &link).unwrap();
        let out = try_move(&link.to_string_lossy());
        assert!(!out.status.success());
        assert!(stderr(&out).contains("already exists"), "{}", stderr(&out));
    }

    // A `..` component, a missing parent and a path inside a tree are refused.
    let escaping = format!("{}/x/../y", host.path().display());
    let out = try_move(&escaping);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("`..`"), "{}", stderr(&out));
    let orphan = host.path().join("absent/moved");
    let out = try_move(&orphan.to_string_lossy());
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("parent directory"),
        "{}",
        stderr(&out)
    );
    let inside = repo.path().join("inner");
    let out = try_move(&inside.to_string_lossy());
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("is inside the worktree"),
        "{}",
        stderr(&out)
    );
    let out = try_move("");
    assert!(!out.status.success());

    assert!(tree.join("a.txt").exists());
    assert!(!host.path().join("absent").exists());
}

#[test]
fn move_refuses_a_tree_that_is_gone() {
    let repo = seeded();
    let host = tempfile::tempdir().unwrap();
    let tree = add_tree(&repo, &host, "topic");
    std::fs::remove_dir_all(&tree).unwrap();
    let dest = host.path().join("moved");
    let out = repo.run(&[
        "worktree",
        "move",
        &tree.to_string_lossy(),
        &dest.to_string_lossy(),
    ]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("is missing"), "{}", stderr(&out));
}

#[test]
fn repair_with_a_path_fixes_a_tree_moved_by_hand() {
    let repo = seeded();
    let host = tempfile::tempdir().unwrap();
    let tree = add_tree(&repo, &host, "topic");
    let dest = host.path().join("by-hand");
    std::fs::rename(&tree, &dest).unwrap();
    assert!(stdout(&repo.ok(&["worktree", "list"])).contains("prunable"));

    let out = repo.ok(&["worktree", "repair", &dest.to_string_lossy()]);
    assert!(stdout(&out).contains("repaired worktrees/topic: back-pointer"));
    assert!(!stdout(&repo.ok(&["worktree", "list"])).contains("prunable"));

    // A second run has nothing to fix.
    let out = repo.ok(&["worktree", "repair", &dest.to_string_lossy()]);
    assert!(stdout(&out).is_empty());
}

#[test]
fn repair_refuses_a_path_that_is_not_a_linked_tree() {
    let repo = seeded();
    let host = tempfile::tempdir().unwrap();
    let plain = host.path().join("plain");
    std::fs::create_dir(&plain).unwrap();
    let out = repo.run(&["worktree", "repair", &plain.to_string_lossy()]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("cannot repair"), "{}", stderr(&out));
    let out = repo.run(&["worktree", "repair", &repo.path().to_string_lossy()]);
    assert!(!out.status.success());

    // A tree of another repository is not ours to repair.
    let other = Repo::new();
    other.commit_file("a.txt", b"x\n", "seed");
    let foreign = add_tree(&other, &host, "foreign");
    let out = repo.run(&["worktree", "repair", &foreign.to_string_lossy()]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("not a linked worktree of this repository"),
        "{}",
        stderr(&out)
    );
    assert!(
        !stdout(&other.ok(&["worktree", "list"])).contains("prunable"),
        "the foreign registry stays intact"
    );
}

#[test]
fn repair_without_a_path_rewrites_a_missing_pointer_file() {
    let repo = seeded();
    let host = tempfile::tempdir().unwrap();
    let tree = add_tree(&repo, &host, "topic");
    std::fs::remove_file(tree.join(".kit")).unwrap();
    assert!(stdout(&repo.ok(&["worktree", "list"])).contains("prunable"));

    let out = repo.ok(&["worktree", "repair"]);
    assert!(stdout(&out).contains("repaired worktrees/topic: pointer"));
    assert!(tree.join(".kit").is_file());
    assert!(!stdout(&repo.ok(&["worktree", "list"])).contains("prunable"));
    let out = kit(&tree, repo.xdg(), &["status"]);
    assert!(out.status.success(), "{}", stderr(&out));
}

#[test]
fn repair_without_a_path_leaves_a_gone_tree_and_a_live_foreign_pointer() {
    let repo = seeded();
    let host = tempfile::tempdir().unwrap();
    let gone = add_tree(&repo, &host, "gone");
    let a = add_tree(&repo, &host, "a");
    let b = add_tree(&repo, &host, "b");
    std::fs::remove_dir_all(&gone).unwrap();
    // Tree `a` now points at the state of `b`. Both registry entries name
    // a live tree, and entry `a` is prunable, but its tree is live under `b`.
    std::fs::copy(b.join(".kit"), a.join(".kit")).unwrap();

    let out = repo.ok(&["worktree", "repair"]);
    assert!(stdout(&out).is_empty(), "{}", stdout(&out));
    let pointer = std::fs::read_to_string(a.join(".kit")).unwrap();
    assert_eq!(pointer, std::fs::read_to_string(b.join(".kit")).unwrap());
    assert!(!gone.exists());
}
