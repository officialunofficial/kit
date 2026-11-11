//! `kit init <dir>` and `kit init -q`.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

mod common;

use std::path::Path;
use std::process::Output;

use common::kit;

fn run(cwd: &Path, xdg: &Path, args: &[&str]) -> Output {
    kit(cwd, xdg, args)
}

fn is_repo(dir: &Path) -> bool {
    dir.join(".kit").join("format").is_file() && dir.join(".kit").join("HEAD").is_file()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn init_creates_a_missing_directory() {
    let (cwd, xdg) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let out = run(cwd.path(), xdg.path(), &["init", "proj"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(is_repo(&cwd.path().join("proj")));
    assert!(!cwd.path().join(".kit").exists());
    assert!(stderr(&out).contains("proj/.kit/"), "{}", stderr(&out));
}

#[test]
fn init_creates_nested_directories() {
    let (cwd, xdg) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let out = run(cwd.path(), xdg.path(), &["init", "a/b/c/"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(is_repo(&cwd.path().join("a/b/c")));
}

#[test]
fn init_takes_an_existing_empty_directory_and_dot() {
    let (cwd, xdg) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    std::fs::create_dir(cwd.path().join("empty")).unwrap();
    assert!(
        run(cwd.path(), xdg.path(), &["init", "empty"])
            .status
            .success()
    );
    assert!(is_repo(&cwd.path().join("empty")));
    assert!(run(cwd.path(), xdg.path(), &["init", "."]).status.success());
    assert!(is_repo(cwd.path()));
}

#[test]
fn init_in_an_existing_repository_is_an_error() {
    let (cwd, xdg) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    assert!(
        run(cwd.path(), xdg.path(), &["init", "proj"])
            .status
            .success()
    );
    // Once through the directory argument, once from inside the repository.
    for (target, args) in [
        (cwd.path().to_path_buf(), ["init", "proj"]),
        (cwd.path().join("proj"), ["init", "-q"]),
    ] {
        let out = run(&target, xdg.path(), &args);
        assert_eq!(out.status.code(), Some(1), "{args:?}");
        assert!(stderr(&out).contains("already a kit repository"));
    }
}

#[test]
fn quiet_drops_the_success_line_and_not_the_errors() {
    let (cwd, xdg) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    for flag in ["-q", "--quiet"] {
        let dir = format!("quiet{flag}");
        let out = run(cwd.path(), xdg.path(), &["init", flag, &dir]);
        assert!(out.status.success());
        assert!(out.stdout.is_empty() && out.stderr.is_empty(), "{flag}");
        assert!(is_repo(&cwd.path().join(&dir)));
    }
    let out = run(&cwd.path().join("quiet-q"), xdg.path(), &["init", "-q"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("already a kit repository"));
    // No directory argument: `-q` alone initialises the current directory.
    let plain = cwd.path().join("plain");
    std::fs::create_dir(&plain).unwrap();
    let out = run(&plain, xdg.path(), &["init", "-q"]);
    assert!(out.status.success() && out.stderr.is_empty());
    assert!(is_repo(&plain));
}

#[test]
fn init_refuses_a_symlink_as_the_directory() {
    let (cwd, xdg) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let elsewhere = tempfile::tempdir().unwrap();
    let link = cwd.path().join("link");
    std::os::unix::fs::symlink(elsewhere.path(), &link).unwrap();
    let dangling = cwd.path().join("dangling");
    std::os::unix::fs::symlink(cwd.path().join("nowhere"), &dangling).unwrap();

    for arg in ["link", "link/", "dangling", "dangling/"] {
        let out = run(cwd.path(), xdg.path(), &["init", arg]);
        assert_eq!(out.status.code(), Some(73), "{arg}: {}", stderr(&out));
        assert!(stderr(&out).contains("symbolic link"), "{arg}");
    }
    assert!(
        std::fs::read_dir(elsewhere.path())
            .unwrap()
            .next()
            .is_none()
    );
    assert!(!cwd.path().join("nowhere").exists());
}

#[test]
fn init_refuses_a_file_and_an_empty_name() {
    let (cwd, xdg) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    std::fs::write(cwd.path().join("file"), b"x").unwrap();
    let out = run(cwd.path(), xdg.path(), &["init", "file"]);
    assert_eq!(out.status.code(), Some(73));
    assert!(stderr(&out).contains("not a directory"));
    let out = run(cwd.path(), xdg.path(), &["init", "file/sub"]);
    assert_eq!(out.status.code(), Some(73));
    let out = run(cwd.path(), xdg.path(), &["init", ""]);
    assert_eq!(out.status.code(), Some(64));
}

#[test]
fn init_takes_one_directory() {
    let (cwd, xdg) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let out = run(cwd.path(), xdg.path(), &["init", "a", "b"]);
    assert_eq!(out.status.code(), Some(64));
    assert!(!cwd.path().join("a").exists());
}
