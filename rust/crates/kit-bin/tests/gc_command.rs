//! `kit gc` end-to-end: prunes unreachable objects, honors
//! `--dry-run` and the grace window, and never reclaims a commit that the
//! recovery log pins (the amend/reset/rebase safety net). Spawns the real
//! binary.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::fs;
use std::path::Path;
use std::process::Command;

fn kit_bin() -> &'static str {
    env!("CARGO_BIN_EXE_kit")
}

fn run_in(cwd: &Path, args: &[&str]) -> std::process::Output {
    let xdg = tempfile::tempdir().expect("xdg tempdir");
    let out = Command::new(kit_bin())
        .args(args)
        .current_dir(cwd)
        .env("XDG_CONFIG_HOME", xdg.path())
        .output()
        .expect("spawn kit");
    drop(xdg);
    out
}

fn init_repo() -> tempfile::TempDir {
    let td = tempfile::tempdir().unwrap();
    assert!(run_in(td.path(), &["init"]).status.success());
    assert!(run_in(td.path(), &["keygen"]).status.success());
    td
}

fn commit(root: &Path, name: &str, content: &[u8], msg: &str) {
    fs::write(root.join(name), content).unwrap();
    assert!(run_in(root, &["add", name]).status.success(), "add {name}");
    assert!(
        run_in(root, &["commit", "-m", msg]).status.success(),
        "commit {msg}"
    );
}

/// Write an unreferenced blob via `kit hash`; returns its 64-hex id.
fn orphan_blob(root: &Path, content: &[u8]) -> String {
    fs::write(root.join("orphan.bin"), content).unwrap();
    let out = run_in(root, &["hash", "orphan.bin"]);
    assert!(out.status.success(), "hash: {out:?}");
    let h = String::from_utf8(out.stdout).unwrap().trim().to_owned();
    // Remove the worktree file so it isn't picked up as untracked content;
    // the stored blob object is now unreferenced.
    fs::remove_file(root.join("orphan.bin")).unwrap();
    h
}

fn object_exists(root: &Path, hex: &str) -> bool {
    run_in(root, &["cat", hex]).status.success()
}

#[test]
fn gc_prunes_unreachable_blob_with_zero_grace() {
    let td = init_repo();
    let root = td.path();
    commit(root, "a.txt", b"live\n", "live");
    let orphan = orphan_blob(root, b"orphan contents\n");
    assert!(object_exists(root, &orphan), "orphan present before gc");

    let out = run_in(root, &["gc", "--grace-secs", "0"]);
    assert!(out.status.success(), "gc: {out:?}");

    assert!(
        !object_exists(root, &orphan),
        "gc must prune the unreachable blob"
    );
    // The live history is intact.
    let log = run_in(root, &["log", "--oneline"]);
    assert!(
        String::from_utf8_lossy(&log.stdout).contains("live"),
        "gc must not touch live history"
    );
}

#[test]
fn gc_names_the_temp_files_it_prunes_and_only_then() {
    let td = init_repo();
    let root = td.path();
    commit(root, "a.txt", b"live\n", "live");

    let clean = run_in(root, &["gc", "--grace-secs", "0"]);
    assert!(clean.status.success(), "gc: {clean:?}");
    let clean_text = String::from_utf8_lossy(&clean.stderr).into_owned();
    assert!(
        clean_text.contains("pruned 0 object(s), "),
        "no temp files: {clean_text}"
    );
    assert!(!clean_text.contains("temp file"), "{clean_text}");

    // A dead writer's temp file: a dot name with `.tmp.` in it, in a shard.
    let shard = root.join(".kit/objects/ab");
    fs::create_dir_all(&shard).unwrap();
    let stray = shard.join(".stray.tmp.1");
    fs::write(&stray, b"half a write").unwrap();

    let dry = run_in(root, &["gc", "--dry-run", "--grace-secs", "0"]);
    let dry_text = String::from_utf8_lossy(&dry.stderr).into_owned();
    assert!(
        dry_text.contains("would prune 0 object(s) and 1 temp file(s), "),
        "{dry_text}"
    );
    assert!(stray.exists(), "a dry run keeps the file");

    let out = run_in(root, &["gc", "--grace-secs", "0"]);
    let text = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        text.contains("pruned 0 object(s) and 1 temp file(s), "),
        "{text}"
    );
    assert!(!stray.exists(), "gc removes the file");
}

#[test]
fn gc_dry_run_keeps_everything() {
    let td = init_repo();
    let root = td.path();
    commit(root, "a.txt", b"live\n", "live");
    let orphan = orphan_blob(root, b"orphan\n");

    let out = run_in(root, &["gc", "--dry-run", "--grace-secs", "0"]);
    assert!(out.status.success(), "gc --dry-run: {out:?}");
    assert!(
        object_exists(root, &orphan),
        "dry run must not delete the orphan"
    );
}

#[test]
fn gc_grace_window_keeps_recent_orphan() {
    let td = init_repo();
    let root = td.path();
    commit(root, "a.txt", b"live\n", "live");
    let orphan = orphan_blob(root, b"recent\n");

    // Default 14-day grace: the just-written orphan is too young to prune.
    let out = run_in(root, &["gc"]);
    assert!(out.status.success(), "gc: {out:?}");
    assert!(
        object_exists(root, &orphan),
        "default grace window must keep a freshly-written orphan"
    );
}

#[test]
fn gc_does_not_prune_recovery_logged_commit() {
    let td = init_repo();
    let root = td.path();
    commit(root, "a.txt", b"one\n", "one");
    let superseded = fs::read_to_string(root.join(".kit/refs/heads/main"))
        .unwrap()
        .trim()
        .to_owned();

    // amend records the old HEAD in the recovery log.
    assert!(
        run_in(root, &["commit", "--amend", "-m", "one-amended"])
            .status
            .success(),
        "amend"
    );
    assert_ne!(
        fs::read_to_string(root.join(".kit/refs/heads/main"))
            .unwrap()
            .trim(),
        superseded,
        "amend moved the branch"
    );

    // Even with grace 0, the superseded commit is pinned by the recovery
    // log and must survive gc.
    let out = run_in(root, &["gc", "--grace-secs", "0"]);
    assert!(out.status.success(), "gc: {out:?}");
    assert!(
        object_exists(root, &superseded),
        "gc must not prune a commit pinned by the recovery log"
    );
}

#[test]
fn gc_skips_a_bisect_commit_that_is_gone_and_warns_with_the_state_file() {
    let td = init_repo();
    let root = td.path();
    commit(root, "a.txt", b"one\n", "one");
    assert!(run_in(root, &["bisect", "start"]).status.success());
    // An older gc pruned the commit the bisect started from: its id is
    // the first line of the state file.
    let state = root.join(".kit/bisect");
    let text = fs::read_to_string(&state).unwrap();
    let (first, rest) = text.split_once('\n').unwrap();
    assert_eq!(first.len(), 64, "the first line is a hex id");
    fs::write(&state, format!("{}\n{rest}", "a".repeat(64))).unwrap();

    let out = run_in(root, &["gc", "--grace-secs", "0"]);
    assert!(out.status.success(), "gc: {out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    let warnings: Vec<&str> = stderr
        .lines()
        .filter(|line| line.starts_with("warning:") && line.contains(".kit/bisect"))
        .collect();
    assert_eq!(warnings.len(), 1, "one warning names the file: {stderr}");
    // The branch is untouched.
    let log = run_in(root, &["log", "--oneline"]);
    assert!(String::from_utf8_lossy(&log.stdout).contains("one"));
}

#[test]
fn missing_attestation_warns_without_operation_instructions() {
    let td = init_repo();
    let directory = td.path().join(".kit/attestations").join("77".repeat(32));
    fs::create_dir_all(&directory).unwrap();
    fs::write(
        directory.join(format!("{}.dsse", "88".repeat(32))),
        b"fixture",
    )
    .unwrap();
    let out = run_in(td.path(), &["gc", "--dry-run"]);
    assert!(out.status.success(), "{out:?}");
    let warning = String::from_utf8(out.stderr).unwrap();
    assert!(warning.contains("attested subject"), "{warning}");
    assert!(!warning.contains("finish or abort"), "{warning}");
}

/// Files past the first 64 of a large add are packed. After an amend that
/// changes half of them and an expired recovery log, `kit gc` frees the dead
/// blobs of the packs and leaves the live ones readable.
#[test]
fn gc_reclaims_the_small_files_of_a_large_add_after_an_amend() {
    let td = init_repo();
    let root = td.path();
    let body = |n: usize, round: u8| format!("file {n} round {round} {}\n", "x".repeat(300));
    for n in 0..300 {
        fs::write(root.join(format!("f{n:03}.txt")), body(n, 0)).unwrap();
    }
    assert!(run_in(root, &["add", "."]).status.success(), "add");
    assert!(
        run_in(root, &["commit", "-m", "all"]).status.success(),
        "commit"
    );
    let packs = |root: &Path| {
        fs::read_dir(root.join(".kit/objects/pack"))
            .map(|entries| {
                entries
                    .filter(|e| {
                        e.as_ref()
                            .unwrap()
                            .path()
                            .extension()
                            .is_some_and(|ext| ext == "pack")
                    })
                    .count()
            })
            .unwrap_or(0)
    };
    assert!(
        packs(root) >= 1,
        "the add packed the files past the first 64"
    );

    let id_of = |name: &str| {
        let out = run_in(root, &["hash", name]);
        String::from_utf8(out.stdout).unwrap().trim().to_owned()
    };
    // Which files stay loose depends on the order the workers reach them;
    // both of these are rewritten below, so each is freed either way.
    let (old_loose, old_packed) = (id_of("f000.txt"), id_of("f200.txt"));
    for n in (0..300).step_by(2) {
        fs::write(root.join(format!("f{n:03}.txt")), body(n, 1)).unwrap();
    }
    assert!(run_in(root, &["add", "."]).status.success(), "add again");
    assert!(
        run_in(root, &["commit", "--amend", "-m", "all again"])
            .status
            .success(),
        "amend"
    );
    // The recovery log pins the amended-away commit until its entry expires.
    fs::write(root.join(".kit/recovery-log"), b"").unwrap();

    let out = run_in(root, &["gc", "--grace-secs", "0"]);
    assert!(out.status.success(), "gc: {out:?}");
    for old in [&old_loose, &old_packed] {
        assert!(!object_exists(root, old), "gc must free the old blob {old}");
    }
    let status = run_in(root, &["status"]);
    assert!(
        String::from_utf8_lossy(&status.stdout).contains("nothing to commit"),
        "the tree is still clean after gc"
    );
    // Every file reads back from the store, packed or not.
    for n in 0..300 {
        fs::remove_file(root.join(format!("f{n:03}.txt"))).unwrap();
    }
    assert!(
        run_in(root, &["reset", "--hard", "-f", "HEAD"])
            .status
            .success()
    );
    for n in 0..300 {
        let expected = body(n, u8::from(n % 2 == 0));
        assert_eq!(
            fs::read_to_string(root.join(format!("f{n:03}.txt"))).unwrap(),
            expected
        );
    }
}
