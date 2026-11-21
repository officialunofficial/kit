//! Integration tests: `kit restore` and `kit reset`.
//!
//! Covered behaviours:
//! - `restore --staged <path>` unstages (the index entry reverts to HEAD)
//!   while the worktree file is left as-is.
//! - `restore <path>` discards an un-staged worktree edit by restoring
//!   from the index, but refuses (without `--force`) when that would
//!   clobber an un-staged change; `--force` overrides.
//! - `reset --soft` moves HEAD/branch only (index/worktree untouched).
//! - `reset --mixed` (default) moves HEAD and resets the index to the
//!   target tree, leaving the worktree.
//! - `reset` resolves `<commit>` as a short hash, branch name, and
//!   `HEAD~1` via the shared revspec resolver.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

fn kit_bin() -> &'static str {
    env!("CARGO_BIN_EXE_kit")
}

fn run(cwd: &Path, xdg: &Path, args: &[&str]) -> Output {
    Command::new(kit_bin())
        .args(args)
        .current_dir(cwd)
        .env("XDG_CONFIG_HOME", xdg)
        .output()
        .expect("spawn kit")
}

fn ok(cwd: &Path, xdg: &Path, args: &[&str]) -> Output {
    let out = run(cwd, xdg, args);
    assert!(
        out.status.success(),
        "expected `kit {}` to succeed: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

fn fail(cwd: &Path, xdg: &Path, args: &[&str]) -> Output {
    let out = run(cwd, xdg, args);
    assert!(
        !out.status.success(),
        "expected `kit {}` to fail but it succeeded",
        args.join(" ")
    );
    out
}

struct Repo {
    dir: tempfile::TempDir,
    xdg: tempfile::TempDir,
}

impl Repo {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let xdg = tempfile::tempdir().unwrap();
        ok(dir.path(), xdg.path(), &["init"]);
        ok(dir.path(), xdg.path(), &["keygen"]);
        Repo { dir, xdg }
    }
    fn path(&self) -> &Path {
        self.dir.path()
    }
    fn xdg(&self) -> &Path {
        self.xdg.path()
    }
    fn write(&self, rel: &str, body: &[u8]) {
        let p = self.path().join(rel);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(p, body).unwrap();
    }
    fn read(&self, rel: &str) -> String {
        fs::read_to_string(self.path().join(rel)).unwrap()
    }
    fn add(&self, rel: &str) {
        ok(self.path(), self.xdg(), &["add", rel]);
    }
    fn commit(&self, msg: &str) {
        ok(self.path(), self.xdg(), &["commit", "-m", msg]);
    }
    fn commit_file(&self, rel: &str, body: &[u8], msg: &str) {
        self.write(rel, body);
        self.add(rel);
        self.commit(msg);
    }
    /// The current HEAD commit hash (full hex) via `log --format=json`.
    /// The first JSONL record's leading field is `"hash":"<64-hex>"`.
    fn head_hash(&self) -> String {
        let out = ok(
            self.path(),
            self.xdg(),
            &["log", "--format=json", "-n", "1"],
        );
        let line = String::from_utf8(out.stdout).unwrap();
        let first = line.lines().next().expect("log produced no output");
        let needle = "\"hash\":\"";
        let start = first.find(needle).expect("log json has hash field") + needle.len();
        first[start..start + 64].to_string()
    }
    /// Whether `status --porcelain` reports a staged change for `path`.
    fn status_porcelain(&self) -> String {
        let out = ok(self.path(), self.xdg(), &["status", "--porcelain"]);
        String::from_utf8(out.stdout).unwrap()
    }
}

/// `restore --staged <path>` reverts the index entry to HEAD while the
/// worktree file keeps its new content.
#[test]
fn restore_staged_unstages_leaving_worktree() {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"v1\n", "base");

    // Stage a change.
    repo.write("a.txt", b"v2-staged\n");
    repo.add("a.txt");
    // Sanity: the change is staged (X column = 'M').
    let before = repo.status_porcelain();
    assert!(
        before.contains("M  a.txt"),
        "expected a.txt to be staged-modified before restore: {before:?}"
    );

    // Unstage it.
    ok(repo.path(), repo.xdg(), &["restore", "--staged", "a.txt"]);

    // The worktree file is unchanged (the edit survives).
    assert_eq!(
        repo.read("a.txt"),
        "v2-staged\n",
        "restore --staged must not touch the worktree file"
    );

    // The index entry reverted to HEAD: the edit is now an UN-staged
    // worktree modification (Y column = 'M'), not a staged one.
    let porcelain = repo.status_porcelain();
    assert!(
        porcelain.contains(" M a.txt"),
        "after unstage, a.txt must be reported as unstaged-modified: {porcelain:?}"
    );
    assert!(
        !porcelain.contains("M  a.txt"),
        "after unstage, a.txt must NOT be staged-modified: {porcelain:?}"
    );
}

/// `restore <path>` discards an un-staged worktree edit by restoring the
/// file from the staged (index) content.
#[test]
fn restore_worktree_discards_unstaged_edit_from_index() {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"committed\n", "base");

    // Stage a new version, then make a *further* un-staged worktree edit.
    repo.write("a.txt", b"staged\n");
    repo.add("a.txt");
    repo.write("a.txt", b"dirty-unstaged\n");

    // restore (no --staged) must refuse: it would clobber the un-staged
    // edit (worktree differs from the index).
    let out = fail(repo.path(), repo.xdg(), &["restore", "a.txt"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("unstaged") || stderr.contains("force"),
        "expected restore to refuse clobbering an un-staged edit: {stderr}"
    );
    assert_eq!(repo.read("a.txt"), "dirty-unstaged\n", "file untouched");

    // --force discards the un-staged edit, restoring the staged content.
    ok(repo.path(), repo.xdg(), &["restore", "--force", "a.txt"]);
    assert_eq!(
        repo.read("a.txt"),
        "staged\n",
        "restore --force must restore the staged content"
    );
}

/// `restore <path>` refuses to clobber an unstaged worktree edit even
/// when the index is clean (== HEAD): the worktree differs from the
/// index, so restore demands `--force`; with it, the committed content
/// comes back.
#[test]
fn restore_unstaged_edit_requires_force_even_with_clean_index() {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"committed\n", "base");

    // Edit the worktree but do NOT stage it. The index still matches HEAD,
    // so the worktree differs from the index — restore needs --force.
    repo.write("a.txt", b"local-edit\n");
    let refused = fail(repo.path(), repo.xdg(), &["restore", "a.txt"]);
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("force"),
        "an un-staged worktree edit is refused without --force"
    );
    ok(repo.path(), repo.xdg(), &["restore", "--force", "a.txt"]);
    assert_eq!(
        repo.read("a.txt"),
        "committed\n",
        "restore --force brings back the committed content"
    );
}

/// `reset --soft` moves the branch tip but leaves the index and worktree
/// untouched — the difference shows up as a staged change.
#[test]
fn reset_soft_moves_head_only() {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"one\n", "c1");
    let c1 = repo.head_hash();
    repo.commit_file("a.txt", b"two\n", "c2");

    // Soft-reset back to c1.
    ok(repo.path(), repo.xdg(), &["reset", "--soft", &c1]);

    // HEAD moved.
    assert_eq!(repo.head_hash(), c1, "reset --soft must move HEAD to c1");
    // Worktree is untouched (still the c2 content).
    assert_eq!(repo.read("a.txt"), "two\n", "worktree untouched by --soft");
    // The index still holds c2's tree, so a.txt shows as a STAGED change
    // (X column = 'M') relative to the now-current HEAD (c1).
    let porcelain = repo.status_porcelain();
    assert!(
        porcelain.contains("M  a.txt"),
        "soft reset leaves c2's content staged vs c1: {porcelain:?}"
    );
}

/// `reset --mixed` (and the bare default) moves HEAD and resets the index
/// to the target tree, leaving the worktree.
#[test]
fn reset_mixed_moves_head_and_index() {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"one\n", "c1");
    let c1 = repo.head_hash();
    repo.commit_file("a.txt", b"two\n", "c2");

    // Mixed-reset back to c1.
    ok(repo.path(), repo.xdg(), &["reset", "--mixed", &c1]);
    assert_eq!(repo.head_hash(), c1, "reset --mixed must move HEAD to c1");

    // Worktree untouched (still c2).
    assert_eq!(repo.read("a.txt"), "two\n", "worktree untouched by --mixed");

    // Index was reset to c1's tree, so the c2 content now shows as an
    // UN-staged worktree modification (Y column = 'M'), NOT staged.
    let porcelain = repo.status_porcelain();
    assert!(
        porcelain.contains(" M a.txt"),
        "mixed reset leaves a.txt as an unstaged worktree change: {porcelain:?}"
    );
    assert!(
        !porcelain.contains("M  a.txt"),
        "mixed reset must clear the staged entry for a.txt: {porcelain:?}"
    );
}

/// `reset` (bare, default mixed) targeting `HEAD` re-syncs the index to
/// HEAD's tree without moving the branch.
#[test]
fn reset_default_target_is_head() {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"one\n", "c1");
    let head = repo.head_hash();

    // Stage an extra change, then `reset` with no target — index reverts
    // to HEAD's tree, HEAD stays put.
    repo.write("b.txt", b"new\n");
    repo.add("b.txt");
    ok(repo.path(), repo.xdg(), &["reset"]);
    assert_eq!(repo.head_hash(), head, "bare reset must not move HEAD");
    // b.txt is no longer staged (index == HEAD tree), so it is untracked
    // ('??') in the worktree, not staged-added ('A ').
    let porcelain = repo.status_porcelain();
    assert!(
        porcelain.contains("?? b.txt"),
        "b.txt should now be untracked after reset: {porcelain:?}"
    );
    assert!(
        !porcelain.contains("A  b.txt"),
        "reset must clear the staged-add of b.txt: {porcelain:?}"
    );
}

/// `reset` resolves the target through the shared revspec resolver:
/// short-hash, branch name, and `HEAD~1` all work.
#[test]
fn reset_resolves_short_hash_branch_and_relative() {
    // Short hash.
    {
        let repo = Repo::new();
        repo.commit_file("a.txt", b"one\n", "c1");
        let c1 = repo.head_hash();
        repo.commit_file("a.txt", b"two\n", "c2");
        let short = &c1[..12];
        ok(repo.path(), repo.xdg(), &["reset", "--soft", short]);
        assert_eq!(repo.head_hash(), c1, "short-hash target must resolve");
    }
    // Branch name.
    {
        let repo = Repo::new();
        repo.commit_file("a.txt", b"one\n", "c1");
        let c1 = repo.head_hash();
        ok(repo.path(), repo.xdg(), &["branch", "saved"]);
        repo.commit_file("a.txt", b"two\n", "c2");
        ok(repo.path(), repo.xdg(), &["reset", "--soft", "saved"]);
        assert_eq!(repo.head_hash(), c1, "branch-name target must resolve");
    }
    // HEAD~1.
    {
        let repo = Repo::new();
        repo.commit_file("a.txt", b"one\n", "c1");
        let c1 = repo.head_hash();
        repo.commit_file("a.txt", b"two\n", "c2");
        ok(repo.path(), repo.xdg(), &["reset", "--soft", "HEAD~1"]);
        assert_eq!(repo.head_hash(), c1, "HEAD~1 target must resolve");
    }
}

/// `restore --staged --worktree` restores a clean file. The dirty guard
/// compares the worktree with the index as it was before the restore.
#[test]
fn restore_staged_and_worktree_restores_a_clean_file() {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"one\n", "base");
    repo.commit_file("a.txt", b"two\n", "next");

    ok(
        repo.path(),
        repo.xdg(),
        &[
            "restore",
            "--source",
            "HEAD~1",
            "--staged",
            "--worktree",
            "a.txt",
        ],
    );
    assert_eq!(repo.read("a.txt"), "one\n");

    repo.write("a.txt", b"edited\n");
    let out = fail(
        repo.path(),
        repo.xdg(),
        &["restore", "--staged", "--worktree", "a.txt"],
    );
    assert!(!out.stderr.is_empty());
    assert_eq!(repo.read("a.txt"), "edited\n");
}

/// A repo with files in several directories, all committed, then every
/// tracked file deleted from the worktree.
fn repo_with_deleted_tree() -> Repo {
    let repo = Repo::new();
    for rel in [
        "Makefile",
        "top.txt",
        "t/one.txt",
        "t/two.txt",
        "t/deep/three.txt",
        "t/deep/er/four.txt",
        "u/five.txt",
        "u/Makefile",
        "tt/six.txt",
    ] {
        repo.write(rel, rel.as_bytes());
    }
    ok(repo.path(), repo.xdg(), &["add", "-A"]);
    repo.commit("base");
    for entry in ["Makefile", "top.txt", "t", "u", "tt"] {
        let path = repo.path().join(entry);
        if path.is_dir() {
            fs::remove_dir_all(path).unwrap();
        } else {
            fs::remove_file(path).unwrap();
        }
    }
    repo
}

/// The files in the worktree, relative and sorted, without `.kit`.
fn worktree_files(repo: &Repo) -> Vec<String> {
    fn walk(dir: &Path, prefix: &str, out: &mut Vec<String>) {
        for entry in fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name().into_string().unwrap();
            if prefix.is_empty() && name == ".kit" {
                continue;
            }
            let path = if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            };
            if entry.file_type().unwrap().is_dir() {
                walk(&entry.path(), &path, out);
            } else {
                out.push(path);
            }
        }
    }
    let mut out = Vec::new();
    walk(repo.path(), "", &mut out);
    out.sort();
    out
}

/// `restore <dir>` brings back every file under that directory, nested ones
/// included, and nothing else, not even a sibling whose name starts the same.
#[test]
fn restore_directory_brings_back_only_that_directory() {
    let repo = repo_with_deleted_tree();
    ok(repo.path(), repo.xdg(), &["restore", "t"]);
    assert_eq!(
        worktree_files(&repo),
        [
            "t/deep/er/four.txt",
            "t/deep/three.txt",
            "t/one.txt",
            "t/two.txt"
        ]
    );
    assert_eq!(repo.read("t/deep/er/four.txt"), "t/deep/er/four.txt");
}

/// A nested directory pathspec restores that subtree only.
#[test]
fn restore_nested_directory_brings_back_only_that_subtree() {
    let repo = repo_with_deleted_tree();
    ok(repo.path(), repo.xdg(), &["restore", "t/deep"]);
    assert_eq!(
        worktree_files(&repo),
        ["t/deep/er/four.txt", "t/deep/three.txt"]
    );
}

/// One command naming a file and a directory restores both, and a file that
/// shares its name with a file in another directory is restored once, in
/// its own place.
#[test]
fn restore_file_and_directory_pathspecs_together() {
    let repo = repo_with_deleted_tree();
    ok(
        repo.path(),
        repo.xdg(),
        &["restore", "Makefile", "u", "t/one.txt"],
    );
    assert_eq!(
        worktree_files(&repo),
        ["Makefile", "t/one.txt", "u/Makefile", "u/five.txt"]
    );
}

/// Naming a path twice, or a directory and a file inside it, changes nothing.
#[test]
fn restore_overlapping_pathspecs_restore_each_file_once() {
    let repo = repo_with_deleted_tree();
    ok(
        repo.path(),
        repo.xdg(),
        &["restore", "tt", "tt/six.txt", "tt"],
    );
    assert_eq!(worktree_files(&repo), ["tt/six.txt"]);
}

/// A directory with some files present and some deleted gets the deleted
/// ones back and leaves the rest as they are.
#[test]
fn restore_directory_leaves_present_files_alone() {
    let repo = repo_with_deleted_tree();
    ok(repo.path(), repo.xdg(), &["restore", "t"]);
    fs::remove_file(repo.path().join("t/two.txt")).unwrap();
    ok(repo.path(), repo.xdg(), &["restore", "t"]);
    assert_eq!(repo.read("t/two.txt"), "t/two.txt");
    assert_eq!(repo.read("t/one.txt"), "t/one.txt");
}

/// A pathspec that matches no tracked file is still an error.
#[test]
fn restore_directory_without_tracked_files_is_refused() {
    let repo = repo_with_deleted_tree();
    let out = fail(repo.path(), repo.xdg(), &["restore", "nope"]);
    assert!(String::from_utf8_lossy(&out.stderr).contains("did not match"));
}

/// A pathspec names a path from the repository root and what lies below it. A
/// one-component pathspec such as `Makefile` does not also select a file with
/// that name in another directory the command reaches through a second
/// pathspec.
#[test]
fn restore_one_component_pathspec_selects_only_the_top_level_path() {
    let repo = repo_with_deleted_tree();
    ok(
        repo.path(),
        repo.xdg(),
        &["restore", "Makefile", "u/five.txt", "t/one.txt"],
    );
    assert_eq!(
        worktree_files(&repo),
        ["Makefile", "t/one.txt", "u/five.txt"]
    );
}
