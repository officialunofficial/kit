//! `status`, `commit`, ordinary checkout, clean merge and revert reuse
//! unchanged HEAD objects. A checkout, forced or not, still refuses to overwrite or
//! remove a file whose object the store lost, or to write one from it, and a
//! command whose restore rewrites every file refuses before it writes
//! anything.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

fn run_in(cwd: &Path, args: &[&str]) -> Output {
    // An empty XDG_CONFIG_HOME keeps the developer's config out.
    let xdg = tempfile::tempdir().unwrap();
    Command::new(env!("CARGO_BIN_EXE_kit"))
        .args(args)
        .current_dir(cwd)
        .env("XDG_CONFIG_HOME", xdg.path())
        .output()
        .unwrap()
}

fn ok(cwd: &Path, args: &[&str]) -> Output {
    let out = run_in(cwd, args);
    assert!(out.status.success(), "kit {args:?} failed: {out:?}");
    out
}

/// A repository on `main` with `a.txt` and `b.txt`, and a branch `other`
/// made by `change`.
fn repo(change: &dyn Fn(&Path)) -> tempfile::TempDir {
    let td = tempfile::tempdir().unwrap();
    let dir = td.path();
    ok(dir, &["init"]);
    ok(dir, &["keygen"]);
    fs::write(dir.join("a.txt"), b"alpha\n").unwrap();
    fs::write(dir.join("b.txt"), b"bravo\n").unwrap();
    ok(dir, &["add", "."]);
    ok(dir, &["commit", "-m", "main"]);
    ok(dir, &["checkout", "-b", "other"]);
    change(dir);
    ok(dir, &["commit", "-m", "other"]);
    ok(dir, &["checkout", "main"]);
    td
}

/// A named change that makes the branch `other`.
type Change<'a> = (&'a str, &'a dyn Fn(&Path));

/// Remove the object `HEAD` names at `path` from the store.
fn lose_object(dir: &Path, path: &str) -> String {
    let out = ok(dir, &["ls-tree", "-r", "HEAD", path]);
    let line = String::from_utf8(out.stdout).unwrap();
    let hash = line.split_whitespace().nth(2).unwrap().to_string();
    fs::remove_file(dir.join(".kit/objects").join(&hash[..2]).join(&hash[2..])).unwrap();
    hash
}

#[test]
fn status_commit_and_checkout_do_not_open_unchanged_objects() {
    let td = repo(&|dir| {
        fs::write(dir.join("b.txt"), b"other\n").unwrap();
        ok(dir, &["add", "b.txt"]);
    });
    let dir = td.path();
    lose_object(dir, "a.txt");

    ok(dir, &["status"]);
    fs::write(dir.join("b.txt"), b"bravo two\n").unwrap();
    ok(dir, &["add", "b.txt"]);
    ok(dir, &["commit", "-m", "edit b"]);
    // The target changes `b.txt` only, so `a.txt` stays as it is.
    ok(dir, &["checkout", "other"]);
    assert_eq!(fs::read(dir.join("a.txt")).unwrap(), b"alpha\n");
}

#[test]
fn a_restore_of_every_file_refuses_a_lost_object_before_writing() {
    let commands: [&[&str]; 3] = [
        &["checkout", "-f", "other"],
        &["reset", "--hard", "other"],
        &["reset", "--hard", "-f", "other"],
    ];
    for args in commands {
        // The target changes `a.txt`; the lost `b.txt` comes after it, so a
        // restore that started would already have written `a.txt`.
        let td = repo(&|dir| {
            fs::write(dir.join("a.txt"), b"other\n").unwrap();
            ok(dir, &["add", "a.txt"]);
        });
        let dir = td.path();
        lose_object(dir, "b.txt");
        let state = || {
            (
                fs::read(dir.join(".kit/HEAD")).unwrap(),
                fs::read(dir.join(".kit/refs/heads/main")).unwrap(),
                fs::read(dir.join("a.txt")).unwrap(),
            )
        };
        let before = state();

        let out = run_in(dir, args);
        assert!(!out.status.success(), "{args:?}: {out:?}");
        let stderr = String::from_utf8(out.stderr).unwrap();
        assert!(stderr.contains("not found"), "{args:?}: {stderr}");
        assert_eq!(state(), before, "{args:?} wrote nothing");
    }
}

#[test]
fn differential_merges_and_reverts_do_not_open_unchanged_objects() {
    for kind in ["fast-forward", "merge", "revert"] {
        let td = repo(&|dir| {
            fs::write(dir.join("a.txt"), b"other\n").unwrap();
            ok(dir, &["add", "a.txt"]);
        });
        let dir = td.path();
        if kind == "merge" {
            fs::write(dir.join("c.txt"), b"main\n").unwrap();
            ok(dir, &["add", "c.txt"]);
            ok(dir, &["commit", "-m", "diverge"]);
        } else if kind == "revert" {
            ok(dir, &["merge", "other"]);
        }
        let lost = lose_object(dir, "b.txt");
        let args: &[&str] = if kind == "revert" {
            &["revert", "HEAD"]
        } else {
            &["merge", "other"]
        };
        ok(dir, args);
        if kind == "merge" {
            assert_eq!(fs::read(dir.join("c.txt")).unwrap(), b"main\n");
        }
        assert_eq!(fs::read(dir.join("b.txt")).unwrap(), b"bravo\n");
        let expected: &[u8] = if kind == "revert" {
            b"alpha\n"
        } else {
            b"other\n"
        };
        assert_eq!(fs::read(dir.join("a.txt")).unwrap(), expected);
        // Differential restores leave unchanged corruption to verifying reads.
        assert!(!run_in(dir, &["cat", &lost]).status.success());
        assert!(!run_in(dir, &["closure", "verify", "HEAD"]).status.success());
    }
}

#[cfg(unix)]
#[test]
fn checkout_refuses_to_overwrite_or_remove_a_file_whose_object_is_lost() {
    let overwrite = |dir: &Path| {
        fs::write(dir.join("a.txt"), b"other\n").unwrap();
        ok(dir, &["add", "a.txt"]);
    };
    let remove = |dir: &Path| {
        ok(dir, &["rm", "a.txt"]);
    };
    let mode_only = |dir: &Path| {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir.join("a.txt"), fs::Permissions::from_mode(0o755)).unwrap();
        ok(dir, &["add", "a.txt"]);
    };
    let copy = |dir: &Path| {
        fs::copy(dir.join("a.txt"), dir.join("c.txt")).unwrap();
        ok(dir, &["add", "c.txt"]);
    };
    let changes: [Change<'_>; 4] = [
        ("overwrite", &overwrite),
        ("remove", &remove),
        ("mode only", &mode_only),
        ("copy to a new path", &copy),
    ];
    // A plain and a forced checkout, and a fast-forward merge, which checks
    // the restore without the checkout's own pass over dropped paths.
    let commands: [&[&str]; 3] = [
        &["checkout", "other"],
        &["checkout", "-f", "other"],
        &["merge", "other"],
    ];
    for (name, change) in changes {
        for args in commands {
            let td = repo(change);
            let dir = td.path();
            lose_object(dir, "a.txt");
            let state = || {
                use std::os::unix::fs::PermissionsExt;
                (
                    fs::read(dir.join(".kit/HEAD")).unwrap(),
                    fs::read(dir.join(".kit/refs/heads/main")).unwrap(),
                    fs::metadata(dir.join("a.txt"))
                        .unwrap()
                        .permissions()
                        .mode(),
                )
            };
            let before = state();

            let out = run_in(dir, args);
            assert!(!out.status.success(), "{name}, {args:?}: {out:?}");
            let stderr = String::from_utf8(out.stderr).unwrap();
            assert!(stderr.contains("not found"), "{name}, {args:?}: {stderr}");
            if name == "copy to a new path" && args == ["checkout", "other"] {
                // Only the check of the object a path is written from sees it.
                assert!(stderr.contains("restore cannot write"), "{stderr}");
            }
            assert_eq!(fs::read(dir.join("a.txt")).unwrap(), b"alpha\n");
            assert_eq!(state(), before, "HEAD, main and the mode of a.txt stay");
        }
    }
}

/// A sparse checkout rewrites every entry in its cone, so its check opens
/// every object and a lost one refuses it before HEAD moves.
#[cfg(feature = "sparse-checkout")]
#[test]
fn a_sparse_checkout_refuses_a_lost_object_before_writing() {
    let td = repo(&|dir| {
        fs::write(dir.join("a.txt"), b"other\n").unwrap();
        ok(dir, &["add", "a.txt"]);
    });
    let dir = td.path();
    lose_object(dir, "b.txt");
    let head = fs::read(dir.join(".kit/HEAD")).unwrap();

    let out = run_in(dir, &["checkout", "other", "--sparse", "a.txt", "b.txt"]);
    assert!(
        !out.status.success(),
        "sparse checkout must refuse: {out:?}"
    );
    assert!(String::from_utf8(out.stderr).unwrap().contains("not found"));
    assert_eq!(fs::read(dir.join(".kit/HEAD")).unwrap(), head);
    assert_eq!(fs::read(dir.join("a.txt")).unwrap(), b"alpha\n");
}

#[test]
fn cached_diff_skips_unchanged_objects_but_reads_changed_content() {
    let td = repo(&|dir| {
        fs::write(dir.join("b.txt"), b"other\n").unwrap();
        ok(dir, &["add", "b.txt"]);
    });
    let dir = td.path();
    let lost = lose_object(dir, "a.txt");
    ok(dir, &["diff", "--cached"]);
    fs::write(dir.join("b.txt"), b"staged\n").unwrap();
    ok(dir, &["add", "b.txt"]);
    let out = ok(dir, &["diff", "--cached"]);
    assert!(String::from_utf8(out.stdout).unwrap().contains("+staged"));
    // A read of the lost object still refuses it.
    assert!(!run_in(dir, &["cat", &lost]).status.success());
    assert!(!run_in(dir, &["closure", "verify", "HEAD"]).status.success());
}

#[test]
fn cached_diff_leaves_unchanged_corruption_to_verifying_reads() {
    let td = repo(&|dir| {
        fs::write(dir.join("b.txt"), b"other\n").unwrap();
        ok(dir, &["add", "b.txt"]);
    });
    let dir = td.path();
    let out = ok(dir, &["ls-tree", "-r", "HEAD", "a.txt"]);
    let line = String::from_utf8(out.stdout).unwrap();
    let hash = line.split_whitespace().nth(2).unwrap();
    let path = dir.join(".kit/objects").join(&hash[..2]).join(&hash[2..]);
    let mut bytes = fs::read(&path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    fs::write(path, bytes).unwrap();
    ok(dir, &["diff", "--cached"]);
    for args in [vec!["cat", hash], vec!["closure", "verify", "HEAD"]] {
        let out = run_in(dir, &args);
        assert!(!out.status.success());
        let message = format!(
            "{}{}",
            String::from_utf8(out.stdout).unwrap(),
            String::from_utf8(out.stderr).unwrap()
        );
        assert!(
            message.contains("bytes hash to") && message.contains(hash),
            "{args:?}: {message}"
        );
    }
}
