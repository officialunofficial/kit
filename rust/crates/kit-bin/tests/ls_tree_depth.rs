//! `kit ls-tree -r` stops at the nesting depth checkout uses instead of
//! overflowing the stack on a hostile chain of trees.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::path::Path;
use std::process::Output;

use kit_core::layout::RepoLayout;
use kit_core::store::MAX_TREE_DEPTH;
use kit_core::{Blob, EntryMode, Object, ObjectStore, Tree, TreeEntry, serialize};

type Hash = [u8; 32];

fn kit(cwd: &Path, args: &[&str]) -> Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_kit"))
        .args(args)
        .current_dir(cwd)
        .output()
        .expect("spawn kit")
}

fn put(store: &ObjectStore, obj: &Object) -> Hash {
    store.write(&serialize::serialize(obj).unwrap()).unwrap()
}

/// A tree whose entry `d` names the next tree, `levels` trees below the root,
/// and whose deepest tree holds one blob `f`. Returns the root's hex id.
fn chain(root: &Path, levels: usize) -> String {
    let store = ObjectStore::open(&RepoLayout::single(root)).unwrap();
    let blob = put(
        &store,
        &Object::Blob(Blob {
            data: b"x\n".to_vec(),
        }),
    );
    let entry = |name: &[u8], mode, object_hash| TreeEntry {
        name: name.to_vec(),
        mode,
        object_hash,
    };
    let mut current = put(
        &store,
        &Object::Tree(Tree {
            entries: vec![entry(b"f", EntryMode::Blob, blob)],
        }),
    );
    for _ in 0..levels {
        current = put(
            &store,
            &Object::Tree(Tree {
                entries: vec![entry(b"d", EntryMode::Tree, current)],
            }),
        );
    }
    kit_core::hash::to_hex(&current)
}

#[test]
fn recursive_listing_stops_at_the_checkout_depth() {
    let dir = tempfile::tempdir().unwrap();
    assert!(kit(dir.path(), &["init"]).status.success());

    let at_limit = chain(dir.path(), MAX_TREE_DEPTH);
    let out = kit(dir.path(), &["ls-tree", "-r", &at_limit]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let listing = String::from_utf8(out.stdout).unwrap();
    assert!(listing.trim_end().ends_with("/f"), "{listing}");

    let past_limit = chain(dir.path(), MAX_TREE_DEPTH + 1);
    let out = kit(dir.path(), &["ls-tree", "-r", &past_limit]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("tree nesting exceeds 128 levels"),
        "{stderr}"
    );
}
