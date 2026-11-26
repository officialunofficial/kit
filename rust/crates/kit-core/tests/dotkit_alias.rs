//! Tree entry names that alias `.kit` (or a tree sibling) on a
//! case- and normalization-insensitive filesystem (macOS APFS).
//!
//! `TreeEntry::validate_name` folds only ASCII, so `.\u{212A}it` (KELVIN
//! SIGN, which APFS treats as `K`) passes decode. These tests check that
//! the restore preflight (`check_worktree_alias` / `check_name_collisions`
//! in `ops/restore.rs`) refuses such a tree on every restore entry point
//! before anything is written, and that the real `.kit/` is untouched.
//!
//! The aliasing names only alias on an insensitive filesystem; on a
//! case-sensitive one each test still passes (the restore either refuses
//! or writes a distinct directory entry, which the assertions allow).
#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use kit_core::layout::RepoLayout;
use kit_core::ops::restore::{self, RestoreOptions, parse_sparse_patterns};
use kit_core::{Blob, EntryMode, Hash, Object, ObjectStore, Tree, TreeEntry, serialize};

const KELVIN_KIT: &str = ".\u{212A}it";
const KELVIN_KIT_UPPER: &str = ".\u{212A}IT";
const HEAD_BYTES: &[u8] = b"ref: refs/heads/main\n";
const SENTINEL: &[u8] = b"sentinel-do-not-touch\n";

fn put_blob(s: &ObjectStore, data: &[u8]) -> Hash {
    s.write(
        &serialize::serialize(&Object::Blob(Blob {
            data: data.to_vec(),
        }))
        .unwrap(),
    )
    .unwrap()
}

fn put_tree(s: &ObjectStore, mut entries: Vec<TreeEntry>) -> Hash {
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    s.write(&serialize::serialize(&Object::Tree(Tree { entries })).unwrap())
        .unwrap()
}

fn entry(name: &str, mode: EntryMode, object_hash: Hash) -> TreeEntry {
    TreeEntry {
        name: name.as_bytes().to_vec(),
        mode,
        object_hash,
    }
}

/// Every path under `dir` (not following symlinks) with its kind and bytes.
fn snapshot(dir: &Path) -> BTreeMap<String, (char, Vec<u8>)> {
    fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<String, (char, Vec<u8>)>) {
        let Ok(rd) = fs::read_dir(dir) else { return };
        for e in rd {
            let p = e.unwrap().path();
            let rel = p.strip_prefix(root).unwrap().to_string_lossy().into_owned();
            let m = fs::symlink_metadata(&p).unwrap();
            if m.is_symlink() {
                let t = fs::read_link(&p).unwrap();
                out.insert(rel, ('l', t.as_os_str().as_encoded_bytes().to_vec()));
            } else if m.is_dir() {
                out.insert(rel, ('d', Vec::new()));
                walk(root, &p, out);
            } else {
                out.insert(rel, ('f', fs::read(&p).unwrap()));
            }
        }
    }
    let mut out = BTreeMap::new();
    if let Ok(m) = fs::symlink_metadata(dir)
        && !m.is_dir()
    {
        out.insert(String::new(), ('f', fs::read(dir).unwrap_or_default()));
        return out;
    }
    walk(dir, dir, &mut out);
    out
}

fn root_names(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

/// A worktree whose real `.kit/` is the object store's own state dir, plus
/// the files a repository holds and a sentinel.
struct Repo {
    _dir: tempfile::TempDir,
    root: std::path::PathBuf,
    store: ObjectStore,
}

fn repo() -> Repo {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("wt");
    fs::create_dir_all(&root).unwrap();
    let store = ObjectStore::init(&RepoLayout::single(&root)).unwrap();
    let kit = root.join(".kit");
    fs::write(kit.join("HEAD"), HEAD_BYTES).unwrap();
    fs::write(kit.join("config"), b"[core]\n").unwrap();
    fs::create_dir_all(kit.join("keys")).unwrap();
    fs::write(kit.join("keys/default.key"), [7u8; 32]).unwrap();
    fs::create_dir_all(kit.join("refs/heads")).unwrap();
    fs::write(kit.join("refs/heads/main"), b"00\n").unwrap();
    fs::write(kit.join("SENTINEL"), SENTINEL).unwrap();
    fs::create_dir_all(root.join("sub")).unwrap();
    fs::write(root.join("sub/keep"), b"orig\n").unwrap();
    Repo {
        _dir: dir,
        root,
        store,
    }
}

/// The three hostile shapes of an aliasing root entry.
fn hostile_trees(s: &ObjectStore, alias: &str) -> Vec<(&'static str, Hash)> {
    let evil = put_blob(s, b"EVIL\n");
    let head = put_blob(s, HEAD_BYTES);
    let keys = put_tree(s, vec![entry("default.key", EntryMode::Blob, evil)]);
    let heads = put_tree(s, vec![entry("main", EntryMode::Blob, evil)]);
    let refs = put_tree(s, vec![entry("heads", EntryMode::Tree, heads)]);
    let dot = put_tree(
        s,
        vec![
            entry("HEAD", EntryMode::Blob, head),
            entry("SENTINEL", EntryMode::Blob, evil),
            entry("config", EntryMode::Blob, evil),
            entry("keys", EntryMode::Tree, keys),
            entry("refs", EntryMode::Tree, refs),
        ],
    );
    let keep = put_blob(s, b"orig\n");
    let sub = put_tree(s, vec![entry("keep", EntryMode::Blob, keep)]);
    let ok = put_blob(s, b"ok\n");
    let target = put_blob(s, b"sub");
    let with = |e: TreeEntry| {
        put_tree(
            s,
            vec![
                e,
                entry("ok.txt", EntryMode::Blob, ok),
                entry("sub", EntryMode::Tree, sub),
            ],
        )
    };
    vec![
        ("dir", with(entry(alias, EntryMode::Tree, dot))),
        ("blob", with(entry(alias, EntryMode::Blob, evil))),
        ("exec", with(entry(alias, EntryMode::Executable, evil))),
        ("symlink", with(entry(alias, EntryMode::Symlink, target))),
    ]
}

/// The benign tree the worktree "already holds": `sub/keep` only.
fn benign_tree(s: &ObjectStore) -> Hash {
    let keep = put_blob(s, b"orig\n");
    let sub = put_tree(s, vec![entry("keep", EntryMode::Blob, keep)]);
    put_tree(s, vec![entry("sub", EntryMode::Tree, sub)])
}

#[allow(clippy::unnecessary_wraps)] // the restore reader callback returns a Result
fn no_read(_: &ObjectStore, h: &[Hash]) -> restore::RestoreResult<Vec<Vec<u8>>> {
    Ok(h.iter().map(|_| Vec::new()).collect())
}

/// Every restore entry point and option combination a CLI path uses.
fn run_all(s: &ObjectStore, tree: Hash, base: Hash, root: &Path) -> Vec<(String, bool, String)> {
    let clean = RestoreOptions::default();
    let keep = RestoreOptions {
        clean: false,
        sparse_patterns: None,
    };
    let sparse_all = RestoreOptions {
        clean: false,
        sparse_patterns: Some(parse_sparse_patterns("*\n")),
    };
    let sparse_clean = RestoreOptions {
        clean: true,
        sparse_patterns: Some(parse_sparse_patterns("/*\n")),
    };
    let mut out = Vec::new();
    let mut push = |label: &str, r: restore::RestoreResult<()>| {
        out.push((
            label.to_string(),
            r.is_err(),
            r.err().map(|e| e.to_string()).unwrap_or_default(),
        ));
    };
    // Fresh-clone first checkout / `checkout -f` / `reset --hard -f`.
    push(
        "to_worktree clean",
        restore::restore_tree_to_worktree(s, &tree, root, &clean).map(|_| ()),
    );
    // `reset --hard` / `restore` (clean: false).
    push(
        "to_worktree keep",
        restore::restore_tree_to_worktree(s, &tree, root, &keep).map(|_| ()),
    );
    // `switch` / `checkout <branch>` with a base tree (skip-unchanged path,
    // case-rename branch reachable for non-tree entries).
    push(
        "with base keep",
        restore::restore_tree_to_worktree_with(s, &tree, Some(base), root, &keep, &no_read)
            .map(|_| ()),
    );
    push(
        "with base clean",
        restore::restore_tree_to_worktree_with(s, &tree, Some(base), root, &clean, &no_read)
            .map(|_| ()),
    );
    push(
        "progress base keep",
        restore::restore_tree_to_worktree_progress(
            s,
            &tree,
            Some(base),
            root,
            &keep,
            &no_read,
            None,
            &mut |_, _| {},
        )
        .map(|_| ()),
    );
    // Sparse checkout.
    push(
        "sparse keep",
        restore::restore_tree_to_worktree(s, &tree, root, &sparse_all).map(|_| ()),
    );
    push(
        "sparse clean",
        restore::restore_tree_to_worktree(s, &tree, root, &sparse_clean).map(|_| ()),
    );
    // `stash` path.
    push(
        "restore_tree keep",
        restore::restore_tree(s, tree, root, &keep),
    );
    push(
        "restore_tree clean",
        restore::restore_tree(s, tree, root, &clean),
    );
    out
}

fn assert_refused(alias: &str) {
    let r = repo();
    let base = benign_tree(&r.store);
    let trees = hostile_trees(&r.store, alias);
    let kit_before = snapshot(&r.root.join(".kit"));
    let names_before = root_names(&r.root);
    let sub_before = snapshot(&r.root.join("sub"));
    let aliases = fs::symlink_metadata(r.root.join(alias)).is_ok();
    let mut failures = Vec::new();
    for (shape, tree) in trees {
        for (label, refused, err) in run_all(&r.store, tree, base, &r.root) {
            eprintln!("{alias:?} {shape} {label}: refused={refused} {err}");
            if aliases && !refused {
                failures.push(format!("{shape}/{label}: not refused"));
            }
            if snapshot(&r.root.join(".kit")) != kit_before {
                failures.push(format!("{shape}/{label}: .kit changed"));
            }
            if aliases && root_names(&r.root) != names_before {
                failures.push(format!(
                    "{shape}/{label}: root changed {:?}",
                    root_names(&r.root)
                ));
            }
            if snapshot(&r.root.join("sub")) != sub_before {
                failures.push(format!("{shape}/{label}: sub changed"));
            }
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn validate_name_accepts_kelvin_kit() {
    // The premise: decode-time validation lets these through.
    assert!(TreeEntry::validate_name(KELVIN_KIT.as_bytes()));
    assert!(TreeEntry::validate_name(KELVIN_KIT_UPPER.as_bytes()));
    assert!(!TreeEntry::validate_name(b".Kit"));
}

#[test]
fn kelvin_kit_root_entry_is_refused() {
    assert_refused(KELVIN_KIT);
}

#[test]
fn kelvin_kit_upper_root_entry_is_refused() {
    assert_refused(KELVIN_KIT_UPPER);
}

/// A spelling that does not alias `.kit` on APFS: a restore may write it, but
/// never into the real `.kit/`.
fn non_aliasing_spelling_never_touches_dot_kit(alias: &str) {
    let r = repo();
    let base = benign_tree(&r.store);
    let trees = hostile_trees(&r.store, alias);
    let kit_before = snapshot(&r.root.join(".kit"));
    for (shape, tree) in trees {
        for (label, refused, err) in run_all(&r.store, tree, base, &r.root) {
            eprintln!("{alias:?} {shape} {label}: refused={refused} {err}");
            assert_eq!(
                snapshot(&r.root.join(".kit")),
                kit_before,
                "{alias:?} {shape} {label}"
            );
        }
    }
}

#[test]
fn zero_width_non_joiner_spelling_never_touches_dot_kit() {
    non_aliasing_spelling_never_touches_dot_kit(".k\u{200C}it");
}

#[test]
fn zero_width_joiner_spelling_never_touches_dot_kit() {
    non_aliasing_spelling_never_touches_dot_kit(".kit\u{200D}");
}

#[test]
fn fullwidth_spelling_never_touches_dot_kit() {
    non_aliasing_spelling_never_touches_dot_kit(".\u{FF4B}it");
}

#[test]
fn variation_selector_spelling_never_touches_dot_kit() {
    non_aliasing_spelling_never_touches_dot_kit(".kit\u{FE0F}");
}

#[test]
fn dotless_i_spelling_never_touches_dot_kit() {
    non_aliasing_spelling_never_touches_dot_kit(".k\u{131}t");
}

/// Linked worktree: `.kit` is a pointer FILE, not a directory.
#[test]
fn kelvin_kit_over_pointer_file_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let common = dir.path().join("main");
    fs::create_dir_all(&common).unwrap();
    let store = ObjectStore::init(&RepoLayout::single(&common)).unwrap();
    fs::create_dir_all(common.join(".kit/worktrees/linked")).unwrap();
    let root = dir.path().join("linked");
    fs::create_dir_all(&root).unwrap();
    let pointer = format!(
        "kitdir: {}\n",
        common.join(".kit/worktrees/linked").display()
    );
    fs::write(root.join(".kit"), &pointer).unwrap();
    let base = benign_tree(&store);
    let mut failures = Vec::new();
    for alias in [KELVIN_KIT, KELVIN_KIT_UPPER] {
        let aliases = fs::symlink_metadata(root.join(alias)).is_ok();
        for (shape, tree) in hostile_trees(&store, alias) {
            for (label, refused, err) in run_all(&store, tree, base, &root) {
                eprintln!("pointer {alias:?} {shape} {label}: refused={refused} {err}");
                if aliases && !refused {
                    failures.push(format!("{alias:?} {shape}/{label}: not refused"));
                }
                let m = fs::symlink_metadata(root.join(".kit")).unwrap();
                if !m.is_file() || fs::read_to_string(root.join(".kit")).unwrap() != pointer {
                    failures.push(format!("{alias:?} {shape}/{label}: pointer changed"));
                    fs::remove_dir_all(root.join(".kit")).ok();
                    fs::remove_file(root.join(".kit")).ok();
                    fs::write(root.join(".kit"), &pointer).unwrap();
                }
            }
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// CVE-2021-21300 shape inside one tree: symlink `a -> sub` and directory
/// `A/` holding `x`. Nothing may be written through the symlink.
#[test]
fn case_sibling_symlink_and_dir_is_refused() {
    let r = repo();
    let base = benign_tree(&r.store);
    let s = &r.store;
    let x = put_blob(s, b"pwned\n");
    let keep = put_blob(s, b"orig\n");
    let a_dir = put_tree(
        s,
        vec![
            entry("x", EntryMode::Blob, x),
            entry("keep", EntryMode::Blob, x),
        ],
    );
    let sub = put_tree(s, vec![entry("keep", EntryMode::Blob, keep)]);
    let link = put_blob(s, b"sub");
    let trees = [
        (
            "A dir + a link",
            put_tree(
                s,
                vec![
                    entry("A", EntryMode::Tree, a_dir),
                    entry("a", EntryMode::Symlink, link),
                    entry("sub", EntryMode::Tree, sub),
                ],
            ),
        ),
        (
            "A link + a dir",
            put_tree(
                s,
                vec![
                    entry("A", EntryMode::Symlink, link),
                    entry("a", EntryMode::Tree, a_dir),
                    entry("sub", EntryMode::Tree, sub),
                ],
            ),
        ),
        (
            "NFC link + NFD dir",
            put_tree(
                s,
                vec![
                    entry("e\u{301}", EntryMode::Tree, a_dir),
                    entry("sub", EntryMode::Tree, sub),
                    entry("\u{e9}", EntryMode::Symlink, link),
                ],
            ),
        ),
    ];
    let probe_insensitive = {
        fs::create_dir(r.root.join("probeX")).unwrap();
        let yes = fs::symlink_metadata(r.root.join("PROBEx")).is_ok();
        fs::remove_dir(r.root.join("probeX")).unwrap();
        yes
    };
    let mut failures = Vec::new();
    for (shape, tree) in trees {
        for (label, refused, err) in run_all(s, tree, base, &r.root) {
            eprintln!("{shape} {label}: refused={refused} {err}");
            if probe_insensitive && !refused {
                failures.push(format!("{shape}/{label}: not refused"));
            }
            if fs::symlink_metadata(r.root.join("sub/x")).is_ok()
                || fs::read(r.root.join("sub/keep")).unwrap() != b"orig\n"
            {
                failures.push(format!("{shape}/{label}: wrote through symlink"));
                fs::remove_file(r.root.join("sub/x")).ok();
                fs::write(r.root.join("sub/keep"), b"orig\n").unwrap();
            }
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// Two-step CVE-2021-21300 shape: the worktree already holds symlink
/// `a -> sub` (from an earlier checkout); the next tree has `A/x`.
#[test]
fn case_alias_of_existing_symlink_is_refused() {
    let r = repo();
    let s = &r.store;
    let keep = put_blob(s, b"orig\n");
    let sub = put_tree(s, vec![entry("keep", EntryMode::Blob, keep)]);
    let link = put_blob(s, b"sub");
    let first = put_tree(
        s,
        vec![
            entry("a", EntryMode::Symlink, link),
            entry("sub", EntryMode::Tree, sub),
        ],
    );
    restore::restore_tree_to_worktree(s, &first, &r.root, &RestoreOptions::default()).unwrap();
    assert!(fs::symlink_metadata(r.root.join("a")).unwrap().is_symlink());
    let x = put_blob(s, b"pwned\n");
    let a_dir = put_tree(
        s,
        vec![
            entry("keep", EntryMode::Blob, x),
            entry("x", EntryMode::Blob, x),
        ],
    );
    let second = put_tree(
        s,
        vec![
            entry("A", EntryMode::Tree, a_dir),
            entry("sub", EntryMode::Tree, sub),
        ],
    );
    let insensitive = fs::symlink_metadata(r.root.join("A")).is_ok();
    let mut failures = Vec::new();
    for (label, refused, err) in run_all(s, second, first, &r.root) {
        eprintln!("existing-link {label}: refused={refused} {err}");
        if insensitive && !refused {
            failures.push(format!("{label}: not refused"));
        }
        if fs::symlink_metadata(r.root.join("sub/x")).is_ok()
            || fs::read(r.root.join("sub/keep")).unwrap() != b"orig\n"
        {
            failures.push(format!("{label}: wrote through symlink"));
            fs::remove_file(r.root.join("sub/x")).ok();
            fs::write(r.root.join("sub/keep"), b"orig\n").unwrap();
        }
        if !fs::symlink_metadata(r.root.join("a")).is_ok_and(|m| m.is_symlink()) {
            // A clean restore may legitimately drop `a`; put it back.
            fs::remove_dir_all(r.root.join("a")).ok();
            fs::remove_dir_all(r.root.join("A")).ok();
            std::os::unix::fs::symlink("sub", r.root.join("a")).unwrap();
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// Nested `.kit` alias: `sub/.\u{212A}it/HEAD` plants what APFS resolves as
/// `sub/.kit/HEAD`, a nested repository Kit would discover from `sub/`.
/// A restore must refuse the Kelvin spelling at any depth, whether the
/// directory that holds it is new or already on disk.
#[test]
fn nested_kelvin_kit_is_refused() {
    let r = repo();
    let s = &r.store;
    let head = put_blob(s, HEAD_BYTES);
    let dot = put_tree(s, vec![entry("HEAD", EntryMode::Blob, head)]);
    let inner = put_tree(s, vec![entry(KELVIN_KIT, EntryMode::Tree, dot)]);
    let tree = put_tree(s, vec![entry("nested", EntryMode::Tree, inner)]);
    let res = restore::restore_tree_to_worktree(s, &tree, &r.root, &RestoreOptions::default());
    let planted = fs::symlink_metadata(r.root.join("nested/.kit/HEAD")).is_ok();
    assert!(
        !planted,
        "restore planted nested/.kit/HEAD via {KELVIN_KIT:?}"
    );
    if is_kelvin_alias(&r.root) {
        assert!(res.is_err(), "restore accepted a nested alias of .kit");
    }
}

#[test]
fn nested_kelvin_kit_under_an_existing_directory_is_refused() {
    let r = repo();
    let s = &r.store;
    fs::create_dir_all(r.root.join("nested")).unwrap();
    let head = put_blob(s, HEAD_BYTES);
    let dot = put_tree(s, vec![entry("HEAD", EntryMode::Blob, head)]);
    let inner = put_tree(s, vec![entry(KELVIN_KIT, EntryMode::Tree, dot)]);
    let tree = put_tree(s, vec![entry("nested", EntryMode::Tree, inner)]);
    let res = restore::restore_tree_to_worktree(s, &tree, &r.root, &RestoreOptions::default());
    let planted = fs::symlink_metadata(r.root.join("nested/.kit/HEAD")).is_ok();
    assert!(
        !planted,
        "restore planted nested/.kit/HEAD via {KELVIN_KIT:?}"
    );
    if is_kelvin_alias(&r.root) {
        assert!(res.is_err(), "restore accepted a nested alias of .kit");
    }
}

/// Whether this filesystem treats the Kelvin spelling as `.kit`.
fn is_kelvin_alias(dir: &Path) -> bool {
    fs::symlink_metadata(dir.join(KELVIN_KIT)).is_ok()
}

#[test]
fn a_non_aliasing_unicode_name_below_the_root_is_restored() {
    let r = repo();
    let s = &r.store;
    let blob = put_blob(s, b"x\n");
    let inner = put_tree(s, vec![entry("caf\u{e9}", EntryMode::Blob, blob)]);
    let tree = put_tree(s, vec![entry("nested", EntryMode::Tree, inner)]);
    restore::restore_tree_to_worktree(s, &tree, &r.root, &RestoreOptions::default()).unwrap();
    assert_eq!(fs::read(r.root.join("nested/caf\u{e9}")).unwrap(), b"x\n");
}
