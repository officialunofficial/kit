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
    wait_within(&mut child, Duration::from_secs(20), args[0])
}

/// The first signal during a restore lets checkout publish a matching
/// worktree, HEAD and index, including when it moves an existing branch.
#[test]
fn the_first_sigint_during_checkout_leaves_a_clean_switch() {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"one\n", "one");
    repo.ok(&["checkout", "-b", "big"]);
    let big = noise(96 << 20);
    repo.commit_file("big.bin", &big, "big");
    let tip = fs::read_to_string(repo.kit_dir().join("refs/heads/big")).unwrap();
    repo.ok(&["checkout", "main"]);
    repo.commit_file("gone.txt", b"main only\n", "gone");

    for (args, branch) in [
        (&["checkout", "big"][..], "big"),
        (&["checkout", "-B", "main", "big"][..], "main"),
    ] {
        let status = interrupt_mid_restore(&repo, args, signals()[0]);
        assert!(status.success(), "{args:?}: {status:?}");
        check_invariants(repo.path(), "after an interrupted checkout").unwrap();
        let head = fs::read_to_string(repo.kit_dir().join("HEAD")).unwrap();
        assert!(head.contains(&format!("refs/heads/{branch}")), "{head}");
        assert_eq!(
            fs::read_to_string(repo.kit_dir().join("refs/heads").join(branch)).unwrap(),
            tip,
        );
        assert!(!repo.path().join("gone.txt").exists());
        let restored = fs::read(repo.path().join("big.bin")).unwrap();
        assert!(restored == big, "checkout restored different file contents");
        assert!(restore_temp_files(repo.path()).is_empty());
        assert!(repo.ok(&["status", "--porcelain"]).stdout.is_empty());
        repo.ok(&["checkout", "main"]);
    }
}

#[test]
fn restore_temp_files_are_hidden_and_cannot_be_staged() {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"one\n", "one");
    let temp = "sub/.kit-restore-tmp.123.456";
    repo.write(temp, b"left by a stopped restore\n");
    repo.write("sub/keep.txt", b"ordinary file\n");
    let link = "sub/.kit-restore-tmp.123.457";
    std::os::unix::fs::symlink("keep.txt", repo.path().join(link)).unwrap();

    assert_eq!(
        repo.ok(&["status", "--porcelain"]).stdout,
        b"?? sub/keep.txt\n"
    );
    repo.ok(&["add", "."]);
    assert!(!repo.run(&["add", "-f", temp]).status.success());
    assert!(!repo.run(&["add", "-f", link]).status.success());
    for alias in [
        "sub/.KIT-RESTORE-TMP.123.456",
        "sub/.\u{212a}it-restore-tmp.123.456",
        "sub/.ki\u{200d}t-restore-tmp.123.456",
    ] {
        if repo.path().join(alias).exists() {
            assert!(!repo.run(&["add", "-f", alias]).status.success());
        }
    }
    assert_eq!(repo.ok(&["ls-files"]).stdout, b"a.txt\nsub/keep.txt\n");
    assert!(repo.path().join(temp).is_file());
}

#[test]
fn a_restore_temp_file_cannot_replace_a_tracked_directory_in_the_index() {
    let repo = Repo::new();
    let temp = ".kit-restore-tmp.123.456";
    let child = ".kit-restore-tmp.123.456/keep.txt";
    repo.commit_file(child, b"tracked\n", "base");
    assert!(repo.ok(&["status", "--porcelain"]).stdout.is_empty());
    fs::remove_dir_all(repo.path().join(temp)).unwrap();
    repo.write(temp, b"left by a stopped restore\n");
    assert_eq!(
        repo.ok(&["status", "--porcelain"]).stdout,
        format!(" D {child}\n").as_bytes()
    );
    repo.ok(&["add", "."]);
    assert!(repo.ok(&["ls-files"]).stdout.is_empty());
}

#[test]
fn a_tracked_case_variant_cannot_pick_up_a_restore_temp_file() {
    let repo = Repo::new();
    let tracked = ".KIT-RESTORE-TMP.123.456";
    let temp = ".kit-restore-tmp.123.456";
    repo.commit_file(tracked, b"historical\n", "base");
    if !repo.path().join(temp).exists() {
        return;
    }
    fs::remove_file(repo.path().join(tracked)).unwrap();
    repo.write(temp, b"left by a stopped restore\n");

    assert!(!repo.run(&["add", tracked]).status.success());
    repo.ok(&["add", "-u"]);
    assert!(repo.ok(&["ls-files"]).stdout.is_empty());
}

#[test]
fn a_case_variant_of_a_tracked_ordinary_file_can_still_be_refreshed() {
    let repo = Repo::new();
    let tracked = "Dir/.KIT-RESTORE-TMP.123.456";
    repo.commit_file(tracked, b"old\n", "base");
    if !repo.path().join("dir").exists() {
        return;
    }
    fs::rename(repo.path().join("Dir"), repo.path().join("dir")).unwrap();
    repo.write("dir/.KIT-RESTORE-TMP.123.456", b"new\n");
    repo.ok(&["add", "-u"]);
    assert_eq!(
        repo.ok(&["ls-files"]).stdout,
        format!("{tracked}\n").as_bytes()
    );
}

#[test]
fn add_can_stage_an_ordinary_unicode_path_in_a_searchable_directory() {
    use std::os::unix::fs::PermissionsExt as _;

    let repo = Repo::new();
    let paths = ["private/café.1.2", "private/.kit-restore-tmp.1.2é"];
    let parent = repo.path().join("private");
    for path in paths {
        repo.write(path, b"ordinary file\n");
    }
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o111)).unwrap();
    let out = repo.run(&["add", paths[0], paths[1]]);
    fs::set_permissions(parent, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(out.status.success(), "{out:?}");
    let staged = repo.ok(&["ls-files", "-z"]).stdout;
    for path in paths {
        assert!(
            staged
                .split(|byte| *byte == 0)
                .any(|name| name == path.as_bytes())
        );
    }
}

#[test]
fn add_can_stage_a_case_alias_of_an_ordinary_hard_link() {
    let repo = Repo::new();
    let ordinary = ".kit-restore-tmp.1.2é";
    let alias = ".KIT-RESTORE-TMP.1.2é";
    repo.write(ordinary, b"ordinary file\n");
    if !repo.path().join(alias).exists() {
        return;
    }
    fs::hard_link(
        repo.path().join(ordinary),
        repo.path().join(".kit-restore-tmp.1.2"),
    )
    .unwrap();
    repo.ok(&["add", alias]);
    assert_eq!(
        repo.ok(&["ls-files", "-z"]).stdout,
        format!("{alias}\0").as_bytes()
    );
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
