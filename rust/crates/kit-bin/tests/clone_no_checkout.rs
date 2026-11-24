//! `kit clone --no-checkout`: fetch and set the branch and HEAD, write no
//! worktree file and no index. And a clone of a tree bomb refuses before it
//! writes anything.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::fs;
use std::path::Path;
use std::process::{Command, Output};
use std::time::{Duration, Instant};

use kit_core::hash::{self, ZERO};
use kit_core::layout::RepoLayout;
use kit_core::object::{Commit, Identity};
use kit_core::sign::{KeyPair, sign_commit};
use kit_core::{Blob, EntryMode, Object, ObjectStore, Tree, TreeEntry, serialize};

fn run_in(cwd: &Path, args: &[&str]) -> Output {
    let xdg = tempfile::tempdir().expect("xdg tempdir");
    let out = Command::new(env!("CARGO_BIN_EXE_kit"))
        .args(args)
        .current_dir(cwd)
        .env("XDG_CONFIG_HOME", xdg.path())
        .output()
        .expect("spawn kit");
    drop(xdg);
    out
}

fn stderr_str(out: &Output) -> String {
    String::from_utf8(out.stderr.clone()).unwrap()
}

fn read_ref(repo: &Path, name: &str) -> Option<String> {
    fs::read_to_string(repo.join(".kit").join(name))
        .ok()
        .map(|s| s.trim().to_string())
}

/// What a directory holds besides `.kit`.
fn worktree_entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|name| name != ".kit")
        .collect();
    names.sort();
    names
}

#[test]
fn no_checkout_writes_no_files_and_no_index_and_checkout_fills_the_worktree() {
    let up = tempfile::tempdir().unwrap();
    let bare = tempfile::tempdir().unwrap();
    let url = format!("kit+file://{}", bare.path().display());
    assert!(run_in(up.path(), &["init"]).status.success());
    assert!(run_in(up.path(), &["keygen"]).status.success());
    assert!(
        run_in(up.path(), &["remote", "add", "origin", &url])
            .status
            .success()
    );
    fs::create_dir(up.path().join("dir")).unwrap();
    fs::write(up.path().join("dir/a.txt"), "a").unwrap();
    fs::write(up.path().join("b.txt"), "b").unwrap();
    assert!(run_in(up.path(), &["add", "."]).status.success());
    assert!(run_in(up.path(), &["commit", "-m", "one"]).status.success());
    assert!(run_in(up.path(), &["push", "origin", "main"]).status.success());
    let tip = read_ref(up.path(), "refs/heads/main").unwrap();

    let parent = tempfile::tempdir().unwrap();
    let out = run_in(parent.path(), &["clone", "--no-checkout", &url, "copy"]);
    assert!(out.status.success(), "{}", stderr_str(&out));
    let copy = parent.path().join("copy");
    assert_eq!(read_ref(&copy, "refs/heads/main").as_deref(), Some(tip.as_str()));
    assert_eq!(
        fs::read_to_string(copy.join(".kit/HEAD")).unwrap().trim(),
        "ref: refs/heads/main"
    );
    assert_eq!(worktree_entries(&copy), Vec::<String>::new());
    assert!(!copy.join(".kit/index").exists());
    assert!(!copy.join(".kit/PULL_HEAD").exists());

    let out = run_in(&copy, &["checkout", "main"]);
    assert!(out.status.success(), "{}", stderr_str(&out));
    assert_eq!(fs::read_to_string(copy.join("dir/a.txt")).unwrap(), "a");
    assert_eq!(fs::read_to_string(copy.join("b.txt")).unwrap(), "b");
    let status = run_in(&copy, &["status", "--porcelain"]);
    assert!(status.status.success());
    assert!(status.stdout.is_empty(), "{status:?}");
}

#[test]
fn no_checkout_conflicts_with_sparse() {
    let parent = tempfile::tempdir().unwrap();
    let out = run_in(
        parent.path(),
        &["clone", "--no-checkout", "--sparse", "src", "kit+file:///none", "x"],
    );
    assert!(!out.status.success());
    assert!(!parent.path().join("x").exists());
}

/// A signed commit over a tree of `levels` doubling trees, in `repo`'s store.
fn bomb_commit(repo: &Path, levels: usize) -> String {
    let store = ObjectStore::open(&RepoLayout::single(repo)).unwrap();
    let put = |obj: &Object| store.write(&serialize::serialize(obj).unwrap()).unwrap();
    let entry = |name: &[u8], mode, object_hash| TreeEntry {
        name: name.to_vec(),
        mode,
        object_hash,
    };
    let blob = put(&Object::Blob(Blob { data: b"x\n".to_vec() }));
    let mut cur = put(&Object::Tree(Tree {
        entries: vec![entry(b"f", EntryMode::Blob, blob)],
    }));
    for _ in 0..levels {
        cur = put(&Object::Tree(Tree {
            entries: vec![
                entry(b"a", EntryMode::Tree, cur),
                entry(b"b", EntryMode::Tree, cur),
            ],
        }));
    }
    let kp = KeyPair::from_seed([0x33; 32]);
    let mut commit = Commit {
        tree_hash: cur,
        parents: vec![],
        author: Identity::ed25519(kp.public.0),
        signer: kp.public.0,
        message: b"bomb".to_vec(),
        timestamp: 1_726_300_000,
        message_hash: ZERO,
        content_digest: ZERO,
        signature: [0u8; 64],
    };
    commit.signature = sign_commit(&commit, &kp).unwrap().0;
    hash::to_hex(&put(&Object::Commit(commit)))
}

#[test]
fn clone_of_a_tree_bomb_fails_fast_and_leaves_no_worktree() {
    let up = tempfile::tempdir().unwrap();
    let bare = tempfile::tempdir().unwrap();
    let url = format!("kit+file://{}", bare.path().display());
    assert!(run_in(up.path(), &["init"]).status.success());
    assert!(
        run_in(up.path(), &["remote", "add", "origin", &url])
            .status
            .success()
    );
    let commit = bomb_commit(up.path(), 40);
    let refs = up.path().join(".kit/refs/heads");
    fs::create_dir_all(&refs).unwrap();
    fs::write(refs.join("main"), format!("{commit}\n")).unwrap();
    let push = run_in(up.path(), &["push", "--no-verify-signatures", "origin", "main"]);
    assert!(push.status.success(), "{}", stderr_str(&push));

    let parent = tempfile::tempdir().unwrap();
    let started = Instant::now();
    let out = run_in(
        parent.path(),
        &["clone", "--no-verify-signatures", &url, "copy"],
    );
    assert!(!out.status.success());
    assert!(
        stderr_str(&out).contains("expands to more than"),
        "{}",
        stderr_str(&out)
    );
    assert!(started.elapsed() < Duration::from_secs(30));
    assert_eq!(worktree_entries(&parent.path().join("copy")), Vec::<String>::new());
}
