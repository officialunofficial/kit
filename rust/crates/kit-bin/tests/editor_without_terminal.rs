//! With no terminal on stdin and no editor set, `commit` without `-m`,
//! `tag -a` without `-m` and `rebase -i` fail at once with a clear message
//! instead of starting the default `vi`, which waits for a terminal. An
//! editor the user set runs as before, terminal or not.
#![cfg(unix)]
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

mod common;

use std::fs;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use common::{Repo, in_progress};

/// An editor that records that it ran and writes `message`.
fn editor_script(dir: &Path, message: &str) -> String {
    let path = dir.join("editor.sh");
    let marker = dir.join("editor-ran");
    fs::write(
        &path,
        format!(
            "#!/bin/sh\ntouch '{}'\nprintf '%s\\n' '{message}' > \"$1\"\n",
            marker.display()
        ),
    )
    .unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    }
    path.to_str().unwrap().to_owned()
}

/// Run `kit args` with stdin from /dev/null. `editor` is a variable and the
/// editor it names; with `None`, no editor is set.
fn run(repo: &Repo, args: &[&str], editor: Option<(&str, &str)>) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_kit"));
    cmd.args(args)
        .current_dir(repo.path())
        .env("XDG_CONFIG_HOME", repo.xdg())
        .env("HOME", repo.xdg())
        .env_remove("GIT_EDITOR")
        .env_remove("EDITOR")
        .env_remove("VISUAL")
        .stdin(Stdio::null());
    if let Some((var, editor)) = editor {
        cmd.env(var, editor);
    }
    cmd.output().unwrap()
}

#[test]
fn no_terminal_and_no_editor_fails_fast() {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"one\n", "one");
    repo.commit_file("a.txt", b"two\n", "two");
    repo.write("a.txt", b"three\n");
    repo.ok(&["add", "a.txt"]);
    for args in [
        &["commit"][..],
        &["tag", "-a", "v1"],
        &["rebase", "-i", "HEAD~1"],
    ] {
        let out = run(&repo, args, None);
        let stderr = String::from_utf8_lossy(&out.stderr);
        // EX_USAGE, as for any other missing argument.
        assert_eq!(out.status.code(), Some(64), "{args:?}: {stderr}");
        assert!(stderr.contains("not a terminal"), "{args:?}: {stderr}");
        assert!(stderr.contains("EDITOR"), "{args:?}: {stderr}");
        if args[0] != "rebase" {
            assert!(stderr.contains("pass -m"), "{args:?}: {stderr}");
        }
    }
    // Nothing moved: the commit and the tag were not made, and no rebase began.
    let log = repo.ok(&["log", "--oneline"]);
    assert_eq!(String::from_utf8_lossy(&log.stdout).lines().count(), 2);
    assert!(!repo.run(&["rev-parse", "v1"]).status.success());
    assert_eq!(in_progress(&repo.kit_dir()), None);
}

/// `EDITOR="code --wait"` in a script keeps working: an editor the user set
/// runs whether or not stdin is a terminal, whichever variable names it.
#[test]
fn a_set_editor_runs_without_a_terminal() {
    for var in ["GIT_EDITOR", "EDITOR", "VISUAL"] {
        let repo = Repo::new();
        repo.commit_file("a.txt", b"one\n", "one");
        repo.write("a.txt", b"two\n");
        repo.ok(&["add", "a.txt"]);
        let editor = editor_script(repo.xdg(), "from the editor");
        let out = run(&repo, &["commit"], Some((var, &editor)));
        assert!(
            out.status.success(),
            "{var}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(repo.xdg().join("editor-ran").exists(), "{var}");
        let log = repo.ok(&["log", "-n", "1", "--oneline"]);
        assert!(
            String::from_utf8_lossy(&log.stdout).contains("from the editor"),
            "{var}"
        );

        fs::remove_file(repo.xdg().join("editor-ran")).unwrap();
        let out = run(&repo, &["tag", "-a", "v1"], Some((var, &editor)));
        assert!(
            out.status.success(),
            "{var}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(repo.xdg().join("editor-ran").exists(), "{var}");
    }
}
