//! Preserve exact filename spellings across staging and checkout.
#![allow(clippy::unwrap_used)]

mod common;

use std::fs;

use common::Repo;

#[test]
fn add_all_stages_only_the_new_spelling_after_a_shell_rename() {
    let repo = Repo::new();
    repo.commit_file("Folder/Foo", b"content\n", "base");
    repo.commit_file("Folder/Bar", b"second file\n", "second file");
    fs::rename(repo.path().join("Folder"), repo.path().join("folder")).unwrap();
    fs::rename(
        repo.path().join("folder/Foo"),
        repo.path().join("folder/foo"),
    )
    .unwrap();
    fs::rename(
        repo.path().join("folder/Bar"),
        repo.path().join("folder/bar"),
    )
    .unwrap();

    repo.ok(&["add", "-A"]);
    assert_eq!(repo.ok(&["ls-files"]).stdout, b"folder/bar\nfolder/foo\n");
    repo.ok(&["commit", "-m", "rename"]);
    assert!(repo.ok(&["status", "--porcelain"]).stdout.is_empty());
}

#[test]
fn add_all_leaves_a_checkout_recovery_file_untracked() {
    let repo = Repo::new();
    let recovery = ".kit-restore-backup.example/.kit-restore-tmp.1.2";
    repo.write(recovery, b"original\n");
    repo.write("candidate", b"stage\n");

    repo.ok(&["add", "-A"]);
    assert_eq!(repo.ok(&["ls-files"]).stdout, b"candidate\n");
    assert_eq!(fs::read(repo.path().join(recovery)).unwrap(), b"original\n");
}

#[test]
fn checkout_uses_the_spelling_and_content_of_each_tip() {
    let repo = Repo::new();
    repo.commit_file("Foo", b"original\n", "base");
    repo.ok(&["checkout", "-b", "rename"]);
    repo.ok(&["mv", "Foo", "foo"]);
    repo.commit_file("foo", b"renamed and edited\n", "rename");

    for (branch, name, old_name, content) in [
        ("main", "Foo", "foo", &b"original\n"[..]),
        ("rename", "foo", "Foo", &b"renamed and edited\n"[..]),
    ] {
        repo.ok(&["checkout", branch]);
        let names: Vec<_> = fs::read_dir(repo.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert!(names.iter().any(|entry| entry == name));
        assert!(!names.iter().any(|entry| entry == old_name));
        assert_eq!(fs::read(repo.path().join(name)).unwrap(), content);
        assert!(repo.ok(&["status", "--porcelain"]).stdout.is_empty());
    }
}

#[test]
fn checkout_changes_unicode_spelling_and_preserves_an_unrelated_hard_link() {
    let repo = Repo::new();
    repo.commit_file("Σ.txt", b"original\n", "base");
    repo.ok(&["checkout", "-b", "rename"]);
    repo.ok(&["mv", "Σ.txt", "ς.txt"]);
    repo.commit_file("ς.txt", b"renamed\n", "rename");
    fs::hard_link(repo.path().join("ς.txt"), repo.path().join("backup")).unwrap();

    repo.ok(&["checkout", "main"]);
    let names: Vec<_> = fs::read_dir(repo.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert!(names.iter().any(|name| name == "Σ.txt"));
    assert!(!names.iter().any(|name| name == "ς.txt"));
    assert_eq!(fs::read(repo.path().join("Σ.txt")).unwrap(), b"original\n");
    assert_eq!(fs::read(repo.path().join("backup")).unwrap(), b"renamed\n");
}

#[test]
fn checkout_refuses_an_untracked_case_alias() {
    let repo = Repo::new();
    repo.commit_file("base.txt", b"base\n", "base");
    repo.ok(&["checkout", "-b", "target"]);
    repo.commit_file("foo", b"target\n", "target");
    repo.ok(&["checkout", "main"]);
    repo.write("Foo", b"untracked\n");
    if !repo.path().join("foo").exists() {
        return;
    }

    let out = repo.run(&["checkout", "-f", "target"]);
    assert!(!out.status.success(), "{out:?}");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("has a different spelling on disk"),
        "{out:?}"
    );
    assert_eq!(fs::read(repo.path().join("Foo")).unwrap(), b"untracked\n");
    assert_eq!(repo.ok(&["branch", "--show-current"]).stdout, b"main\n");
}

#[test]
fn forced_checkout_refuses_an_occupied_case_alias() {
    let repo = Repo::new();
    repo.commit_file("Foo", b"old\n", "base");
    repo.ok(&["checkout", "-b", "rename"]);
    repo.ok(&["mv", "Foo", "foo"]);
    repo.ok(&["commit", "-m", "rename"]);
    repo.ok(&["checkout", "main"]);
    if !repo.path().join("foo").exists() {
        return;
    }

    let out = repo.run(&["checkout", "-f", "rename"]);
    assert!(!out.status.success(), "{out:?}");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("has a different spelling on disk"),
        "{out:?}"
    );
    assert_eq!(fs::read(repo.path().join("Foo")).unwrap(), b"old\n");
    assert_eq!(repo.ok(&["branch", "--show-current"]).stdout, b"main\n");
}

#[test]
fn forced_checkout_keeps_a_new_name_when_its_old_spelling_is_missing() {
    let repo = Repo::new();
    repo.commit_file("Foo", b"old\n", "base");
    repo.ok(&["checkout", "-b", "rename"]);
    repo.ok(&["mv", "Foo", "foo"]);
    repo.ok(&["commit", "-m", "rename"]);
    repo.ok(&["checkout", "main"]);
    fs::remove_file(repo.path().join("Foo")).unwrap();

    repo.ok(&["checkout", "-f", "rename"]);
    assert_eq!(fs::read(repo.path().join("foo")).unwrap(), b"old\n");
    assert!(repo.ok(&["status", "--porcelain"]).stdout.is_empty());
}

#[cfg(unix)]
#[test]
fn forced_checkout_can_drop_a_file_in_an_unlistable_directory() {
    use std::os::unix::fs::PermissionsExt as _;

    let repo = Repo::new();
    repo.commit_file("base.txt", b"base\n", "base");
    repo.ok(&["checkout", "-b", "other"]);
    repo.commit_file("sub/file", b"other\n", "other");
    let directory = repo.path().join("sub");
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o333)).unwrap();
    let out = repo.run(&["checkout", "-f", "main"]);
    if directory.exists() {
        fs::set_permissions(directory, fs::Permissions::from_mode(0o755)).unwrap();
    }
    assert!(out.status.success(), "{out:?}");
    assert!(!repo.path().join("sub/file").exists());
}
