//! Edge kinds and ancestry depth in the importer: a commit's tree and
//! parents, and a tree's entries, must name objects of the right git
//! kind, and recursive import of a long chain must fail cleanly.

#![allow(clippy::drop_non_drop)]
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use kit_core::object::{Commit, Tag};
use kit_core::sign::{KeyPair, sign_commit, sign_tag};
use kit_git_bridge::error::BridgeError;
use kit_git_bridge::gitobj::{Sha1Id, sha1_hex};
use kit_git_bridge::gitsrc::GitObjKind;
use kit_git_bridge::import::{
    DepthMemo, ImportOptions, ImportSigner, Importer, MAX_COMMIT_RECURSION, MemGitSource, MemSink,
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

#[test]
fn deep_unmapped_chain_fails_without_overflowing_the_stack() {
    let mut src = MemGitSource::default();
    let blob = src.put(GitObjKind::Blob, b"x".to_vec());
    let tree = tree_of(&mut src, "100644", &blob);
    let mut tip = src.put(GitObjKind::Commit, commit_body(&tree, &[], 1));
    for ts in 2..(MAX_COMMIT_RECURSION as u64 + 20) {
        tip = src.put(GitObjKind::Commit, commit_body(&tree, &[tip], ts));
    }
    let (r, _) = import(&mut src, &tip);
    assert!(matches!(r, Err(BridgeError::Source(_))));
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
