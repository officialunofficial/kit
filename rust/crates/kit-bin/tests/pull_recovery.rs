//! Recovery through the command line must preserve later local work.
#![allow(clippy::unwrap_used)]

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

use kit_core::hash::{self, Hash};
use kit_core::layout::RepoLayout;
use kit_core::object::Object;
use kit_core::refs;
use kit_core::store::ObjectStore;

fn run(dir: &Path, args: &[&str]) -> Output {
    let config = tempfile::tempdir().unwrap();
    Command::new(env!("CARGO_BIN_EXE_kit"))
        .args(args)
        .current_dir(dir)
        .env("XDG_CONFIG_HOME", config.path())
        .output()
        .unwrap()
}

fn ok(dir: &Path, args: &[&str]) {
    let out = run(dir, args);
    assert!(
        out.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn tree(dir: &Path, tip: Hash) -> Hash {
    let store = ObjectStore::open(&RepoLayout::single(dir)).unwrap();
    let Object::Commit(commit) = store.read_object(&tip).unwrap() else {
        panic!("commit");
    };
    commit.tree_hash
}

fn marker_bytes(target: Hash, before_tree: Hash) -> Vec<u8> {
    kit_core::ops::pull_state::PullState {
        target,
        before_tree,
    }
    .encode()
    .to_vec()
}

struct Pending {
    _upstream: tempfile::TempDir,
    _bare: tempfile::TempDir,
    local: tempfile::TempDir,
    target: Hash,
}

impl Pending {
    fn new() -> Self {
        let upstream = tempfile::tempdir().unwrap();
        let bare = tempfile::tempdir().unwrap();
        let local = tempfile::tempdir().unwrap();
        ok(upstream.path(), &["init"]);
        ok(upstream.path(), &["keygen"]);
        fs::write(upstream.path().join("a.txt"), b"one\n").unwrap();
        fs::write(upstream.path().join("b.txt"), b"same\n").unwrap();
        fs::write(upstream.path().join(".a.txt.tmp.1.2"), b"tracked value\n").unwrap();
        ok(upstream.path(), &["add", "."]);
        ok(upstream.path(), &["commit", "-m", "base"]);
        let url = format!("kit+file://{}", bare.path().display());
        ok(upstream.path(), &["remote", "add", &url]);
        ok(upstream.path(), &["push"]);
        ok(local.path(), &["init"]);
        ok(local.path(), &["keygen"]);
        ok(local.path(), &["remote", "add", &url]);
        ok(local.path(), &["pull"]);
        let layout = RepoLayout::single(local.path());
        let before = tree(local.path(), refs::resolve_head(&layout).unwrap().unwrap());
        fs::write(upstream.path().join("a.txt"), b"two\n").unwrap();
        ok(upstream.path(), &["add", "a.txt"]);
        ok(upstream.path(), &["commit", "-m", "update"]);
        ok(upstream.path(), &["push"]);
        ok(local.path(), &["fetch"]);
        let target = refs::resolve_head(&RepoLayout::single(upstream.path()))
            .unwrap()
            .unwrap();
        fs::write(layout.pull_head_file(), marker_bytes(target, before)).unwrap();
        refs::write_ref(&layout, "main", &target).unwrap();
        Self {
            _upstream: upstream,
            _bare: bare,
            local,
            target,
        }
    }

    fn refuses_without_changes(&self) -> String {
        let layout = RepoLayout::single(self.local.path());
        let index = fs::read(layout.index_file()).unwrap();
        let marker = fs::read(layout.pull_head_file()).unwrap();
        let out = run(self.local.path(), &["pull"]);
        assert!(
            !out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(fs::read(layout.index_file()).unwrap(), index);
        assert_eq!(fs::read(layout.pull_head_file()).unwrap(), marker);
        assert_eq!(refs::resolve_head(&layout).unwrap(), Some(self.target));
        String::from_utf8(out.stderr).unwrap()
    }
}

#[test]
fn recovery_refuses_staged_edits_and_additions() {
    for path in ["a.txt", "b.txt"] {
        let pending = Pending::new();
        let dir = pending.local.path();
        fs::write(dir.join(path), b"staged edit\n").unwrap();
        fs::write(dir.join("new.txt"), b"new work\n").unwrap();
        ok(dir, &["add", path, "new.txt"]);
        pending.refuses_without_changes();
        assert_eq!(fs::read(dir.join(path)).unwrap(), b"staged edit\n");
        assert_eq!(fs::read(dir.join("new.txt")).unwrap(), b"new work\n");
        ok(dir, &["add", path]);
        pending.refuses_without_changes();
        assert_eq!(fs::read(dir.join(path)).unwrap(), b"staged edit\n");
    }
}

#[test]
fn recovery_checks_the_index_even_when_the_worktree_is_safe() {
    let pending = Pending::new();
    let dir = pending.local.path();
    fs::write(dir.join("b.txt"), b"staged edit\n").unwrap();
    ok(dir, &["add", "b.txt"]);
    fs::write(dir.join("b.txt"), b"same\n").unwrap();
    pending.refuses_without_changes();
    assert_eq!(fs::read(dir.join("b.txt")).unwrap(), b"same\n");
}

#[test]
fn recovery_refuses_soft_reset_work_with_a_stale_marker() {
    let pending = Pending::new();
    let dir = pending.local.path();
    ok(dir, &["reset", "--hard", "-f", "HEAD"]);
    fs::write(dir.join("w.txt"), b"new work\n").unwrap();
    ok(dir, &["add", "w.txt"]);
    ok(dir, &["commit", "-m", "local"]);
    ok(dir, &["reset", "--soft", "HEAD~1"]);
    pending.refuses_without_changes();
    assert_eq!(fs::read(dir.join("w.txt")).unwrap(), b"new work\n");
}

#[test]
fn recovery_cleans_a_regular_restore_temporary_file() {
    let pending = Pending::new();
    let dir = pending.local.path();
    let temporary = dir.join(".a.txt.tmp.123456.7");
    fs::write(&temporary, b"incomplete contents").unwrap();
    ok(dir, &["pull"]);
    assert!(!temporary.exists());
    assert_eq!(fs::read(dir.join("a.txt")).unwrap(), b"two\n");
}

#[test]
fn recovery_refuses_other_temporary_file_shapes() {
    let pending = Pending::new();
    let dir = pending.local.path();
    for name in [
        ".a.txt.tmp.1.x",
        ".a.txt.tmp..3",
        ".a.txt.tmp.+1.2",
        ".a.txt.tmp.１.2",
        ".a.txt.tmp.1.2.extra",
        ".unknown.tmp.12.3",
        ".a.txt.tmp.1",
    ] {
        let path = dir.join(name);
        fs::write(&path, b"local work").unwrap();
        let message = pending.refuses_without_changes();
        assert!(
            message.contains("move or remove it, then pull again"),
            "{message}"
        );
        assert_eq!(fs::read(&path).unwrap(), b"local work");
        fs::remove_file(path).unwrap();
    }
    let path = dir.join(".a.txt.tmp.12.3");
    fs::create_dir(&path).unwrap();
    pending.refuses_without_changes();
    assert!(path.is_dir());
}

#[test]
fn recovery_gives_working_actions_for_local_edits() {
    let pending = Pending::new();
    let dir = pending.local.path();
    fs::write(dir.join("b.txt"), b"local edit\n").unwrap();
    let message = pending.refuses_without_changes();
    assert!(
        message.contains("copy it elsewhere or run `kit restore -f <path>`, then pull again"),
        "{message}"
    );
    ok(dir, &["restore", "-f", "b.txt"]);
    ok(dir, &["pull"]);
    assert_eq!(fs::read(dir.join("b.txt")).unwrap(), b"same\n");
}

#[test]
fn recovery_gives_working_actions_for_staged_changes() {
    let pending = Pending::new();
    let dir = pending.local.path();
    fs::write(dir.join("b.txt"), b"staged edit\n").unwrap();
    fs::write(dir.join("new.txt"), b"new work\n").unwrap();
    ok(dir, &["add", "b.txt", "new.txt"]);
    let message = pending.refuses_without_changes();
    assert!(message.contains("kit checkout -f <branch>"), "{message}");
    ok(dir, &["checkout", "-f", "main"]);
    assert!(!dir.join("new.txt").exists());
    ok(dir, &["pull"]);
    assert_eq!(fs::read(dir.join("b.txt")).unwrap(), b"same\n");
}

#[test]
fn no_remote_branches_keep_the_local_json_identity() {
    let local = tempfile::tempdir().unwrap();
    let empty = tempfile::tempdir().unwrap();
    ok(local.path(), &["init"]);
    ok(local.path(), &["keygen"]);
    fs::write(local.path().join("a.txt"), b"one\n").unwrap();
    ok(local.path(), &["add", "."]);
    ok(local.path(), &["commit", "-m", "local"]);
    let tip = refs::resolve_head(&RepoLayout::single(local.path()))
        .unwrap()
        .unwrap();
    let url = format!("kit+file://{}", empty.path().display());
    ok(local.path(), &["remote", "add", &url]);
    let out = run(local.path(), &["pull", "--format", "json"]);
    assert!(out.status.success());
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["branch"], "main");
    assert_eq!(value["old"], hash::to_hex(&tip));
    assert_eq!(value["new"], hash::to_hex(&tip));
}

#[test]
fn no_remote_branches_refuse_an_unfinished_pull() {
    let pending = Pending::new();
    let empty = tempfile::tempdir().unwrap();
    let dir = pending.local.path();
    let url = format!("kit+file://{}", empty.path().display());
    ok(dir, &["remote", "add", "empty", &url]);
    let layout = RepoLayout::single(dir);
    let marker = fs::read(layout.pull_head_file()).unwrap();
    let out = run(dir, &["pull", "empty"]);
    assert!(!out.status.success());
    assert_eq!(fs::read(layout.pull_head_file()).unwrap(), marker);
    assert_eq!(fs::read(dir.join("a.txt")).unwrap(), b"one\n");
}

#[cfg(unix)]
#[test]
fn recovery_refuses_symlinks_with_temporary_names() {
    let pending = Pending::new();
    let dir = pending.local.path();
    let temporary = dir.join(".a.txt.tmp.987654.0");
    std::os::unix::fs::symlink("b.txt", &temporary).unwrap();
    pending.refuses_without_changes();
    assert_eq!(fs::read_link(&temporary).unwrap(), Path::new("b.txt"));
    assert_eq!(fs::read(dir.join("b.txt")).unwrap(), b"same\n");
}

#[test]
fn recovery_protects_tracked_files_with_temporary_names() {
    let pending = Pending::new();
    let path = pending.local.path().join(".a.txt.tmp.1.2");
    fs::write(&path, b"local edit\n").unwrap();
    pending.refuses_without_changes();
    assert_eq!(fs::read(path).unwrap(), b"local edit\n");
}
