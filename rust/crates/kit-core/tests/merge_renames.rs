//! The three-way tree merge follows a file that one side renamed.
//!
//! Invariants:
//! - No rename, no change: when neither side adds or removes a file, the
//!   merge is the per-file three-way merge of each path.
//! - Side symmetry: swapping ours and theirs gives the same tree.
//! - Content preserved: a clean one-sided rename merge holds every line of
//!   the edits of both sides, at the new path, and the old path is gone.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::collections::BTreeMap;

use kit_core::layout::RepoLayout;
use kit_core::{
    Blob, ConflictKind, EntryMode, Object, ObjectStore, Tree, TreeEntry, merge_trees, serialize,
};
use proptest::prelude::*;
use tempfile::TempDir;

type Hash = [u8; 32];
type Files = BTreeMap<String, Vec<u8>>;

fn fresh() -> (TempDir, ObjectStore) {
    let d = TempDir::new().unwrap();
    let s = ObjectStore::init(&RepoLayout::single(d.path())).unwrap();
    (d, s)
}

fn put(s: &ObjectStore, object: &Object) -> Hash {
    s.write(&serialize::serialize(object).unwrap()).unwrap()
}

/// Write `files` as nested trees and return the root.
fn tree(s: &ObjectStore, files: &Files) -> Hash {
    let mut dirs: BTreeMap<String, Files> = BTreeMap::new();
    let mut entries = Vec::new();
    for (path, data) in files {
        match path.split_once('/') {
            Some((dir, rest)) => {
                dirs.entry(dir.to_owned())
                    .or_default()
                    .insert(rest.to_owned(), data.clone());
            }
            None => entries.push(TreeEntry {
                name: path.as_bytes().to_vec(),
                mode: EntryMode::Blob,
                object_hash: put(s, &Object::Blob(Blob { data: data.clone() })),
            }),
        }
    }
    for (dir, sub) in &dirs {
        entries.push(TreeEntry {
            name: dir.as_bytes().to_vec(),
            mode: EntryMode::Tree,
            object_hash: tree(s, sub),
        });
    }
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    put(s, &Object::Tree(Tree { entries }))
}

/// Read a tree back into its files.
fn files(s: &ObjectStore, root: Hash) -> Files {
    let mut out = Files::new();
    let mut stack = vec![(String::new(), root)];
    while let Some((prefix, hash)) = stack.pop() {
        let Object::Tree(t) = s.read_object(&hash).unwrap() else {
            panic!("not a tree");
        };
        for e in t.entries {
            let name = format!("{prefix}{}", String::from_utf8(e.name).unwrap());
            if e.mode == EntryMode::Tree {
                stack.push((format!("{name}/"), e.object_hash));
            } else {
                let Object::Blob(b) = s.read_object(&e.object_hash).unwrap() else {
                    panic!("not a blob");
                };
                out.insert(name, b.data);
            }
        }
    }
    out
}

/// Sixteen distinct lines of file `tag`, with line `i` replaced for each
/// `(i, text)`.
fn body(tag: &str, edits: &[(usize, String)]) -> Vec<u8> {
    (0..16)
        .map(|i| match edits.iter().find(|(n, _)| *n == i) {
            Some((_, text)) => format!("{text}\n"),
            None => format!("{tag} line {i} with enough words to compare\n"),
        })
        .collect::<String>()
        .into_bytes()
}

#[test]
fn a_one_sided_rename_takes_the_other_sides_edit() {
    let (_d, s) = fresh();
    let base = Files::from([("a.txt".into(), body("a", &[]))]);
    let ours = Files::from([("a.txt".into(), body("a", &[(2, "ours".into())]))]);
    let theirs = Files::from([("dir/b.txt".into(), body("a", &[]))]);
    let r = merge_trees(
        &s,
        Some(tree(&s, &base)),
        Some(tree(&s, &ours)),
        Some(tree(&s, &theirs)),
    )
    .unwrap();
    assert!(r.conflicts.is_empty(), "{:?}", r.conflicts);
    assert_eq!(
        files(&s, r.tree_hash),
        Files::from([("dir/b.txt".into(), body("a", &[(2, "ours".into())]))])
    );
}

#[test]
fn a_rename_against_a_delete_conflicts_at_the_new_path() {
    let (_d, s) = fresh();
    let base = Files::from([("a.txt".into(), body("a", &[]))]);
    let ours = Files::from([("b.txt".into(), body("a", &[]))]);
    let theirs = Files::new();
    let r = merge_trees(
        &s,
        Some(tree(&s, &base)),
        Some(tree(&s, &ours)),
        Some(tree(&s, &theirs)),
    )
    .unwrap();
    assert_eq!(r.conflicts.len(), 1, "{:?}", r.conflicts);
    assert_eq!(r.conflicts[0].path, "b.txt");
    assert_eq!(r.conflicts[0].kind, ConflictKind::DeleteModify);
    assert!(r.conflicts[0].base_hash.is_some() && r.conflicts[0].theirs_hash.is_none());
    assert_eq!(files(&s, r.tree_hash), ours);
}

#[test]
fn two_renames_to_different_names_conflict_at_both_paths() {
    let (_d, s) = fresh();
    let base = Files::from([("a.txt".into(), body("a", &[]))]);
    let ours = Files::from([("b.txt".into(), body("a", &[]))]);
    let theirs = Files::from([("c.txt".into(), body("a", &[]))]);
    let r = merge_trees(
        &s,
        Some(tree(&s, &base)),
        Some(tree(&s, &ours)),
        Some(tree(&s, &theirs)),
    )
    .unwrap();
    let paths: Vec<&str> = r.conflicts.iter().map(|c| c.path.as_str()).collect();
    assert_eq!(paths, ["b.txt", "c.txt"], "{:?}", r.conflicts);
    assert!(
        r.conflicts
            .iter()
            .all(|c| c.kind == ConflictKind::DeleteModify)
    );
    assert_eq!(
        files(&s, r.tree_hash),
        Files::from([
            ("b.txt".into(), body("a", &[])),
            ("c.txt".into(), body("a", &[]))
        ])
    );
}

/// A base of `count` files, the edits of each side as `(file, line)`, and
/// for the renaming side the file index and the new path.
type Scenario = (
    usize,
    Vec<(usize, usize)>,
    Vec<(usize, usize)>,
    usize,
    String,
);

fn scenario() -> impl Strategy<Value = Scenario> {
    (2usize..5).prop_flat_map(|count| {
        (
            Just(count),
            prop::collection::vec((0..count, 0usize..8), 0..3),
            prop::collection::vec((0..count, 8usize..16), 0..3),
            0..count,
            "(new/)?[m-p]{1,3}\\.txt",
        )
    })
}

fn side(count: usize, edits: &[(usize, usize)], label: &str) -> Files {
    (0..count)
        .map(|f| {
            let mine: Vec<(usize, String)> = edits
                .iter()
                .filter(|(file, _)| *file == f)
                .map(|(_, line)| (*line, format!("{label} edited line {line}")))
                .collect();
            (format!("f{f}.txt"), body(&format!("f{f}"), &mine))
        })
        .collect()
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 48, ..ProptestConfig::default() })]

    #[test]
    fn edits_without_renames_merge_per_file((count, ours_edits, theirs_edits, _, _) in scenario()) {
        let (_d, s) = fresh();
        let base = side(count, &[], "none");
        let ours = side(count, &ours_edits, "ours");
        let theirs = side(count, &theirs_edits, "theirs");
        let r = merge_trees(&s, Some(tree(&s, &base)), Some(tree(&s, &ours)), Some(tree(&s, &theirs)))
            .unwrap();
        prop_assert!(r.conflicts.is_empty());
        let both: Vec<(usize, usize)> = ours_edits.iter().chain(&theirs_edits).copied().collect();
        let merged = files(&s, r.tree_hash);
        for (f, data) in &merged {
            let i: usize = f[1..f.len() - 4].parse().unwrap();
            let expect: Vec<(usize, String)> = both
                .iter()
                .filter(|(file, _)| *file == i)
                .map(|(_, line)| {
                    let who = if *line < 8 { "ours" } else { "theirs" };
                    (*line, format!("{who} edited line {line}"))
                })
                .collect();
            prop_assert_eq!(data, &body(&format!("f{i}"), &expect));
        }
        prop_assert_eq!(merged.len(), count);
    }

    #[test]
    fn a_one_sided_rename_is_symmetric_and_keeps_both_edits(
        (count, ours_edits, theirs_edits, moved, to) in scenario(),
    ) {
        let (_d, s) = fresh();
        let base = side(count, &[], "none");
        let ours = side(count, &ours_edits, "ours");
        let mut theirs = side(count, &theirs_edits, "theirs");
        let from = format!("f{moved}.txt");
        let data = theirs.remove(&from).unwrap();
        theirs.insert(to.clone(), data);
        let (b, o, t) = (tree(&s, &base), tree(&s, &ours), tree(&s, &theirs));

        let r = merge_trees(&s, Some(b), Some(o), Some(t)).unwrap();
        prop_assert!(r.conflicts.is_empty(), "{:?}", r.conflicts);
        let swapped = merge_trees(&s, Some(b), Some(t), Some(o)).unwrap();
        prop_assert!(swapped.conflicts.is_empty());
        prop_assert_eq!(r.tree_hash, swapped.tree_hash);

        let merged = files(&s, r.tree_hash);
        prop_assert!(!merged.contains_key(&from));
        let moved_data = String::from_utf8(merged[&to].clone()).unwrap();
        for (file, line) in ours_edits.iter().chain(&theirs_edits) {
            if *file == moved {
                let who = if *line < 8 { "ours" } else { "theirs" };
                let expected = format!("{who} edited line {line}");
                prop_assert!(moved_data.contains(&expected), "{}", moved_data);
            }
        }
        prop_assert_eq!(merged.len(), count);
    }
}

#[test]
fn a_rename_out_of_a_directory_leaves_no_empty_directory() {
    let (_d, s) = fresh();
    let base = Files::from([("d/a.txt".into(), body("a", &[]))]);
    let ours = Files::from([("d/a.txt".into(), body("a", &[(3, "ours".into())]))]);
    let theirs = Files::from([("b.txt".into(), body("a", &[]))]);
    let r = merge_trees(
        &s,
        Some(tree(&s, &base)),
        Some(tree(&s, &ours)),
        Some(tree(&s, &theirs)),
    )
    .unwrap();
    assert!(r.conflicts.is_empty(), "{:?}", r.conflicts);
    assert_eq!(
        files(&s, r.tree_hash),
        Files::from([("b.txt".into(), body("a", &[(3, "ours".into())]))])
    );
}

#[test]
fn a_rename_blocked_by_a_file_on_the_other_side_is_not_followed() {
    let (_d, s) = fresh();
    let base = Files::from([("a.txt".into(), body("a", &[]))]);
    let ours = Files::from([
        ("a.txt".into(), body("a", &[(3, "ours".into())])),
        (
            "new".into(),
            b"a file where theirs needs a directory\n".to_vec(),
        ),
    ]);
    let theirs = Files::from([("new/b.txt".into(), body("a", &[]))]);
    let r = merge_trees(
        &s,
        Some(tree(&s, &base)),
        Some(tree(&s, &ours)),
        Some(tree(&s, &theirs)),
    )
    .unwrap();
    // Without the rename the edit meets a delete at the old path.
    assert!(
        r.conflicts
            .iter()
            .any(|c| c.path == "a.txt" && c.kind == ConflictKind::DeleteModify),
        "{:?}",
        r.conflicts
    );
}
