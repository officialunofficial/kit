//! SIGINT (Ctrl-C) and SIGTERM end a command promptly.
//!
//! A local command keeps the signal's default action, so it stops at once and
//! leaves the repository as an interrupted write leaves it: every write is a
//! temp file renamed into place, and `gc` sweeps the temp files. A command
//! that polls the shutdown flag stops at its next checkpoint, and a second
//! signal ends it at once wherever it waits.
#![cfg(unix)]
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

mod common;

use std::fs;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use common::{Repo, check_invariants};

const SIGINT: i32 = 2;
const SIGTERM: i32 = 15;

/// Whether this process ignores SIGINT, as a job started in the background
/// by a shell does. kit inherits that, and a command that installs no
/// handler keeps ignoring it.
fn sigint_ignored() -> bool {
    let Ok(status) = fs::read_to_string("/proc/self/status") else {
        return false;
    };
    status
        .lines()
        .find_map(|line| line.strip_prefix("SigIgn:"))
        .and_then(|mask| u64::from_str_radix(mask.trim(), 16).ok())
        .is_some_and(|mask| mask & (1 << (SIGINT - 1)) != 0)
}

/// The signals a test sends: SIGTERM always, and SIGINT unless this process
/// ignores it.
fn signals() -> Vec<i32> {
    if sigint_ignored() {
        vec![SIGTERM]
    } else {
        vec![SIGINT, SIGTERM]
    }
}

/// Start `kit args` in `repo`, isolated as `common::kit_env` isolates it.
fn spawn(repo: &Repo, args: &[&str], extra_env: &[(&str, &str)]) -> Child {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_kit"));
    cmd.args(args)
        .current_dir(repo.path())
        .env("XDG_CONFIG_HOME", repo.xdg())
        .env("HOME", repo.xdg())
        .env("TMPDIR", repo.xdg())
        .env("EDITOR", "true")
        .env("VISUAL", "true")
        .env("GIT_EDITOR", "true")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    cmd.spawn().expect("spawn kit")
}

fn interrupt(child: &Child, signal: i32) {
    let sent = Command::new("kill")
        .args([format!("-{signal}"), child.id().to_string()])
        .status()
        .unwrap();
    assert!(sent.success(), "could not signal kit");
}

/// Wait for `child` to end, at most `limit`.
fn wait_within(child: &mut Child, limit: Duration, what: &str) -> ExitStatus {
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if start.elapsed() > limit {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{what} still ran {limit:?} after the signal");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Hold the worktree lock of `repo`, as another kit command would.
fn hold_worktree_lock(repo: &Repo) -> fs::File {
    let file = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(repo.kit_dir().join("worktree.lock"))
        .unwrap();
    file.lock().unwrap();
    file
}

/// `len` bytes that do not compress.
fn noise(len: usize) -> Vec<u8> {
    let mut data = vec![0u8; len];
    let mut state = 0x2545_f491_4f6c_dd1d_u64;
    for byte in &mut data {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        *byte = state.to_le_bytes()[0];
    }
    data
}

/// Temp files left in the object store.
fn store_temp_files(kit_dir: &Path) -> Vec<String> {
    let mut found = Vec::new();
    let mut dirs = vec![kit_dir.join("objects")];
    while let Some(dir) = dirs.pop() {
        let Ok(read) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in read.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if entry.file_type().unwrap().is_dir() {
                dirs.push(entry.path());
            } else if name.contains(".tmp.") {
                found.push(name);
            }
        }
    }
    found
}

/// A local command waiting for the worktree lock stops on SIGINT, well
/// before the lock wait would time out, and the repository stays usable.
#[test]
fn a_local_command_stops_on_sigint() {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"one\n", "one");
    repo.ok(&["branch", "other"]);
    repo.commit_file("a.txt", b"two\n", "two");
    repo.write("b.txt", b"new\n");
    for signal in signals() {
        for args in [&["add", "b.txt"][..], &["checkout", "other"][..]] {
            let lock = hold_worktree_lock(&repo);
            let mut child = spawn(&repo, args, &[]);
            std::thread::sleep(Duration::from_millis(200));
            interrupt(&child, signal);
            let status = wait_within(&mut child, Duration::from_secs(3), args[0]);
            assert_eq!(status.signal(), Some(signal), "{args:?}: {status:?}");
            drop(lock);
            check_invariants(repo.path(), args[0]).unwrap();
        }
    }
    repo.ok(&["add", "b.txt"]);
    repo.ok(&["checkout", "-f", "other"]);
}

/// An `add` stopped while it writes objects leaves a repository that passes
/// every invariant, takes the same `add` again, and loses its temp files to
/// `gc`.
#[test]
fn an_interrupted_add_leaves_a_usable_repository() {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"one\n", "one");
    repo.write("big.bin", &noise(48 << 20));
    let signal = signals()[0];
    let mut child = spawn(&repo, &["add", "big.bin"], &[]);
    std::thread::sleep(Duration::from_millis(150));
    interrupt(&child, signal);
    let status = wait_within(&mut child, Duration::from_secs(3), "add");
    // A fast machine may finish the add before the signal lands.
    assert!(
        status.success() || status.signal() == Some(signal),
        "{status:?}"
    );
    check_invariants(repo.path(), "after an interrupted add").unwrap();
    repo.ok(&["add", "big.bin"]);
    repo.ok(&["commit", "-m", "big"]);
    repo.ok(&["gc", "--grace-secs", "0"]);
    assert_eq!(store_temp_files(&repo.kit_dir()), Vec::<String>::new());
    check_invariants(repo.path(), "after gc").unwrap();
}

/// Files in the worktree with a restore temporary name.
fn restore_temp_files(root: &Path) -> Vec<String> {
    fs::read_dir(root)
        .unwrap()
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with(".kit-restore-tmp."))
        .collect()
}

/// Stop `kit args` once its restore has a temporary file in the worktree,
/// so the signal lands mid-restore, and return how it ended.
fn interrupt_mid_restore(repo: &Repo, args: &[&str], signal: i32) -> ExitStatus {
    let before = restore_temp_files(repo.path());
    let mut child = spawn(repo, args, &[]);
    let start = Instant::now();
    while restore_temp_files(repo.path())
        .iter()
        .all(|name| before.contains(name))
    {
        if let Some(status) = child.try_wait().unwrap() {
            panic!("{args:?} ended before its restore wrote: {status:?}");
        }
        assert!(start.elapsed() < Duration::from_secs(20), "no restore");
        std::thread::sleep(Duration::from_millis(1));
    }
    interrupt(&child, signal);
    wait_within(&mut child, Duration::from_secs(3), args[0])
}

/// A checkout stopped while it writes a large file leaves its branch, HEAD
/// and the index where they were, as git does: nothing is staged, a file the
/// target drops is still tracked, and the same checkout run again with `-f`
/// finishes it and removes the temporary file the stopped one left.
#[test]
fn an_interrupted_checkout_leaves_head_and_the_index() {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"one\n", "one");
    repo.ok(&["checkout", "-b", "big"]);
    repo.write("big.bin", &noise(96 << 20));
    repo.ok(&["add", "big.bin"]);
    repo.ok(&["commit", "-m", "big"]);
    repo.ok(&["checkout", "main"]);
    repo.commit_file("gone.txt", b"main only\n", "gone");
    let main = fs::read_to_string(repo.kit_dir().join("refs/heads/main")).unwrap();
    let signal = signals()[0];
    let staged = |repo: &Repo| -> Vec<String> {
        let out = repo.ok(&["status", "--porcelain"]);
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter(|line| !line.starts_with(' ') && !line.starts_with("??"))
            .map(str::to_owned)
            .collect()
    };

    for args in [&["checkout", "big"][..], &["checkout", "-B", "main", "big"]] {
        let status = interrupt_mid_restore(&repo, args, signal);
        assert_eq!(status.signal(), Some(signal), "{args:?}: {status:?}");
        check_invariants(repo.path(), "after an interrupted checkout").unwrap();
        let head = fs::read_to_string(repo.kit_dir().join("HEAD")).unwrap();
        assert!(head.contains("refs/heads/main"), "{args:?}: {head}");
        assert_eq!(
            fs::read_to_string(repo.kit_dir().join("refs/heads/main")).unwrap(),
            main,
            "{args:?}"
        );
        assert_eq!(staged(&repo), Vec::<String>::new(), "{args:?}");
        assert!(repo.path().join("gone.txt").exists(), "{args:?}");
    }

    repo.ok(&["checkout", "-f", "big"]);
    assert_eq!(restore_temp_files(repo.path()), Vec::<String>::new());
    assert!(!repo.path().join("gone.txt").exists());
    let out = repo.ok(&["status", "--porcelain"]);
    assert_eq!(String::from_utf8_lossy(&out.stdout), "");
}

/// A push polls the shutdown flag, but not while it waits on its transport.
/// A second SIGINT ends it there.
#[test]
fn a_second_sigint_ends_a_command_that_polls() {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"one\n", "one");
    let script = repo.xdg().join("silent-ssh.sh");
    let started = repo.xdg().join("ssh-started");
    fs::write(
        &script,
        format!("#!/bin/sh\ntouch '{}'\nexec sleep 10\n", started.display()),
    )
    .unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    }
    repo.ok(&[
        "remote",
        "add",
        "origin",
        "kit+ssh://kit@example.invalid/repo",
    ]);
    let program = script.to_str().unwrap();
    let mut child = spawn(
        &repo,
        &["push", "-u", "origin", "main"],
        &[("KIT_SSH_PROGRAM", program)],
    );
    // Once the transport runs, the push has its handlers and waits on it.
    let start = Instant::now();
    while !started.exists() {
        assert!(start.elapsed() < Duration::from_secs(10), "no transport");
        std::thread::sleep(Duration::from_millis(10));
    }
    interrupt(&child, SIGINT);
    std::thread::sleep(Duration::from_millis(200));
    interrupt(&child, SIGINT);
    let status = wait_within(&mut child, Duration::from_secs(5), "push");
    assert_eq!(status.signal(), Some(SIGINT), "{status:?}");
}

/// An editor started by kit gets the terminal's Ctrl-C, and kit waits for it
/// rather than dying under it: both a command that keeps the default action
/// and one that takes the handlers survive two SIGINTs sent while the editor
/// runs.
#[test]
fn sigint_while_the_editor_runs_leaves_kit_waiting() {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"one\n", "one");
    repo.commit_file("a.txt", b"two\n", "two");
    let script = repo.xdg().join("editor.sh");
    // The editor is kit's child, so $PPID is kit.
    let body = r#"#!/bin/sh
kill -INT $PPID
sleep 0.2
kill -INT $PPID
sleep 0.2
grep -q '^# Rebase' "$1" || printf 'edited\n' > "$1"
"#;
    fs::write(&script, body).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let editor = script.to_str().unwrap();
    repo.write("a.txt", b"three\n");
    repo.ok(&["add", "a.txt"]);
    for args in [&["commit"][..], &["rebase", "-i", "HEAD~1"]] {
        let mut child = spawn(&repo, args, &[("GIT_EDITOR", editor)]);
        let status = wait_within(&mut child, Duration::from_secs(10), args[0]);
        assert!(status.success(), "{args:?}: {status:?}");
    }
    let log = repo.ok(&["log", "-n", "1", "--oneline"]);
    assert!(String::from_utf8_lossy(&log.stdout).contains("edited"));
    check_invariants(repo.path(), "after the editor").unwrap();
}

/// SIGTERM ends `rebase -i` at once while its editor runs, as it ends git:
/// only SIGINT is the editor's.
#[test]
fn sigterm_while_the_editor_runs_ends_kit() {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"one\n", "one");
    repo.commit_file("a.txt", b"two\n", "two");
    let script = repo.xdg().join("hung-editor.sh");
    fs::write(
        &script,
        r#"#!/bin/sh
printf '%s' "$1" > "${0%/*}/message-path"
printf '%s' "$$" > "${0%/*}/editor-pid"
kill -TERM $PPID
exec sleep 10
"#,
    )
    .unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let editor = script.to_str().unwrap();
    let mut child = spawn(
        &repo,
        &["rebase", "-i", "HEAD~1"],
        &[("GIT_EDITOR", editor)],
    );
    let status = wait_within(&mut child, Duration::from_secs(5), "rebase -i");
    let editor_pid: u32 = fs::read_to_string(repo.xdg().join("editor-pid"))
        .unwrap()
        .parse()
        .unwrap();
    assert!(
        Command::new("kill")
            .arg(editor_pid.to_string())
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(status.signal(), Some(SIGTERM), "{status:?}");
    let message = PathBuf::from(fs::read_to_string(repo.xdg().join("message-path")).unwrap());
    assert!(
        message.starts_with(repo.xdg()),
        "unowned editor scratch: {}",
        message.display()
    );
    assert_eq!(common::in_progress(&repo.kit_dir()), None);
    check_invariants(repo.path(), "after SIGTERM in the editor").unwrap();
}

/// A branch name `checkout -b` cannot create is refused before any file is
/// written, though the branch itself is written after the files.
#[test]
fn checkout_with_a_bad_branch_name_writes_nothing() {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"one\n", "one");
    repo.ok(&["checkout", "-b", "other"]);
    repo.commit_file("b.txt", b"other\n", "other");
    repo.ok(&["checkout", "main"]);
    let out = repo.run(&["checkout", "-b", ".bad", "other"]);
    assert!(!out.status.success());
    assert!(!repo.path().join("b.txt").exists());
    let out = repo.ok(&["status", "--porcelain"]);
    assert_eq!(String::from_utf8_lossy(&out.stdout), "");
}
