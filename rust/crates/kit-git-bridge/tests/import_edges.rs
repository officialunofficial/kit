//! Edge kinds and ancestry depth in the importer: a commit's tree and
//! parents, and a tree's entries, must name objects of the right git
//! kind, and import of a long unmapped chain must succeed with a bounded stack.

#![allow(clippy::drop_non_drop)]
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use kit_core::object::{Commit, Tag};
use kit_core::sign::{KeyPair, sign_commit, sign_tag};
use kit_git_bridge::error::BridgeError;
use kit_git_bridge::gitobj::{Sha1Id, sha1_hex};
use kit_git_bridge::gitsrc::{CatFileBatch, GitObjKind};
use kit_git_bridge::import::{
    DepthMemo, ImportOptions, ImportSigner, Importer, MemGitSource, MemSink,
};
use std::collections::HashMap;
use std::fmt::Write as _;

fn commit_body(tree: &Sha1Id, parents: &[Sha1Id], ts: u64) -> Vec<u8> {
    let mut b = format!("tree {}\n", sha1_hex(tree));
    for p in parents {
        let _ = writeln!(b, "parent {}", sha1_hex(p));
    }
    let _ = write!(
        b,
        "author A <a@x> {ts} +0000\ncommitter C <c@x> {ts} +0000\n\nm\n"
    );
    b.into_bytes()
}

/// Import `tip` into a fresh sink. Returns the result and the map.
fn import(
    src: &mut MemGitSource,
    tip: &Sha1Id,
) -> (Result<(), BridgeError>, HashMap<Sha1Id, kit_core::Hash>) {
    let kp = KeyPair::from_seed([0x42; 32]);
    let mut sink = MemSink::default();
    let mut map = HashMap::new();
    let mut sc = |c: &Commit| {
        Ok(sign_commit(c, &kp)
            .map_err(|e| BridgeError::Source(e.to_string()))?
            .0)
    };
    let mut st = |t: &Tag| {
        Ok(sign_tag(t, &kp)
            .map_err(|e| BridgeError::Source(e.to_string()))?
            .0)
    };
    let mut retain = |_: &Sha1Id, _: &[u8]| Ok(());
    let mut imp = Importer {
        source: src,
        sink: &mut sink,
        signer: ImportSigner {
            public: kp.public.0,
            sign_commit: &mut sc,
            sign_tag: &mut st,
        },
        map: &mut map,
        retain_raw: &mut retain,
        options: ImportOptions::default(),
        depth_memo: DepthMemo::default(),
    };
    let r = imp.import_ref(tip).map(|_| ());
    drop(imp);
    (r, map)
}

fn tree_of(src: &mut MemGitSource, mode: &str, child: &Sha1Id) -> Sha1Id {
    let mut t = Vec::new();
    t.extend_from_slice(mode.as_bytes());
    t.extend_from_slice(b" f\0");
    t.extend_from_slice(child);
    src.put(GitObjKind::Tree, t)
}

#[test]
fn commit_tree_must_be_a_tree() {
    let mut src = MemGitSource::default();
    let blob = src.put(GitObjKind::Blob, b"x".to_vec());
    let c = src.put(GitObjKind::Commit, commit_body(&blob, &[], 5));
    let (r, map) = import(&mut src, &c);
    assert!(r.is_err());
    assert!(!map.contains_key(&c), "no signed twin for the commit");
}

#[test]
fn commit_parent_must_be_a_commit() {
    let mut src = MemGitSource::default();
    let blob = src.put(GitObjKind::Blob, b"x".to_vec());
    let tree = tree_of(&mut src, "100644", &blob);
    let c = src.put(GitObjKind::Commit, commit_body(&tree, &[blob], 5));
    let (r, map) = import(&mut src, &c);
    assert!(r.is_err());
    assert!(!map.contains_key(&c));
}

#[test]
fn tree_entry_commit_is_refused_before_it_is_imported() {
    let mut src = MemGitSource::default();
    let blob = src.put(GitObjKind::Blob, b"x".to_vec());
    let tree = tree_of(&mut src, "100644", &blob);
    let inner = src.put(GitObjKind::Commit, commit_body(&tree, &[], 4));
    let outer_tree = tree_of(&mut src, "100644", &inner);
    let outer = src.put(GitObjKind::Commit, commit_body(&outer_tree, &[], 5));
    let (r, map) = import(&mut src, &outer);
    assert!(r.is_err());
    assert!(!map.contains_key(&inner), "the commit is never translated");
}

/// A linear history of `n` commits built by the real `git` binary.
/// Returns the tip, or `None` when git is not installed.
fn real_git_chain(dir: &std::path::Path, n: usize) -> Option<Sha1Id> {
    use std::io::Write as _;
    use std::process::{Command, Stdio};
    let git = |args: &[&str]| {
        Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .output()
            .ok()
    };
    if !git(&["init", "-q", "--initial-branch=main"])?
        .status
        .success()
    {
        return None;
    }
    let mut stream = String::new();
    for i in 1..=n {
        let _ = write!(
            stream,
            "commit refs/heads/main\nmark :{i}\ncommitter C <c@x> {} +0000\ndata 2\nm\n",
            1_600_000_000 + i
        );
        if i > 1 {
            let _ = writeln!(stream, "from :{}", i - 1);
        }
        let _ = writeln!(stream, "M 100644 inline f\ndata 1\nx\n");
    }
    let mut child = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["fast-import", "--quiet"])
        .stdin(Stdio::piped())
        .spawn()
        .ok()?;
    child.stdin.take()?.write_all(stream.as_bytes()).ok()?;
    assert!(child.wait().ok()?.success());
    let out = git(&["rev-parse", "refs/heads/main"])?;
    kit_git_bridge::gitobj::sha1_from_hex(String::from_utf8_lossy(&out.stdout).trim())
}

#[test]
fn long_real_git_history_imports_from_its_tip() {
    let dir = tempfile::tempdir().unwrap();
    let Some(tip) = real_git_chain(dir.path(), 3000) else {
        return;
    };
    let mut src = CatFileBatch::open(&dir.path().join(".git")).unwrap();
    let kp = KeyPair::from_seed([0x42; 32]);
    let mut sink = MemSink::default();
    let mut map = HashMap::new();
    let mut sc = |c: &Commit| {
        Ok(sign_commit(c, &kp)
            .map_err(|e| BridgeError::Source(e.to_string()))?
            .0)
    };
    let mut st = |t: &Tag| {
        Ok(sign_tag(t, &kp)
            .map_err(|e| BridgeError::Source(e.to_string()))?
            .0)
    };
    let mut retain = |_: &Sha1Id, _: &[u8]| Ok(());
    let mut imp = Importer {
        source: &mut src,
        sink: &mut sink,
        signer: ImportSigner {
            public: kp.public.0,
            sign_commit: &mut sc,
            sign_tag: &mut st,
        },
        map: &mut map,
        retain_raw: &mut retain,
        options: ImportOptions::default(),
        depth_memo: DepthMemo::default(),
    };
    let done = imp.import_ref(&tip).unwrap();
    drop(imp);
    assert_eq!(
        done.new_pairs.len(),
        3000 + 2,
        "commits, one tree, one blob"
    );
    assert!(map.contains_key(&tip));
}

#[test]
fn very_deep_unmapped_chain_imports_without_overflowing_the_stack() {
    let mut src = MemGitSource::default();
    let blob = src.put(GitObjKind::Blob, b"x".to_vec());
    let tree = tree_of(&mut src, "100644", &blob);
    let mut tip = src.put(GitObjKind::Commit, commit_body(&tree, &[], 1));
    for ts in 2..10_000 {
        tip = src.put(GitObjKind::Commit, commit_body(&tree, &[tip], ts));
    }
    let (r, map) = import(&mut src, &tip);
    r.unwrap();
    assert!(map.contains_key(&tip));
}

#[test]
fn merge_ancestry_translates_each_commit_once_in_parent_order() {
    let mut src = MemGitSource::default();
    let blob = src.put(GitObjKind::Blob, b"x".to_vec());
    let tree = tree_of(&mut src, "100644", &blob);
    let root = src.put(GitObjKind::Commit, commit_body(&tree, &[], 1));
    let left = src.put(GitObjKind::Commit, commit_body(&tree, &[root], 2));
    let right = src.put(GitObjKind::Commit, commit_body(&tree, &[root], 3));
    let merge = src.put(GitObjKind::Commit, commit_body(&tree, &[left, right], 4));
    let (r, map) = import(&mut src, &merge);
    r.unwrap();
    for id in [root, left, right, merge] {
        assert!(map.contains_key(&id));
    }
}

#[test]
fn chain_within_the_cap_imports() {
    let mut src = MemGitSource::default();
    let blob = src.put(GitObjKind::Blob, b"x".to_vec());
    let tree = tree_of(&mut src, "100644", &blob);
    let mut tip = src.put(GitObjKind::Commit, commit_body(&tree, &[], 1));
    for ts in 2..20 {
        tip = src.put(GitObjKind::Commit, commit_body(&tree, &[tip], ts));
    }
    let (r, map) = import(&mut src, &tip);
    r.unwrap();
    assert!(map.contains_key(&tip));
}
