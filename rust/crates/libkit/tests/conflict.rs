//! The conflict material of a paused operation: written, checked and undone.
#![cfg(feature = "sync")]
#![allow(clippy::unwrap_used)] // unwrap is the assertion in tests

mod common;

use std::cell::RefCell;

use common::{Fixture, init};
use kit_core::hash::Hash;
use kit_core::index::{self, EntryStatus};
use kit_core::observer::{NoopObserver, Observer};
use kit_core::ops::conflict_state::ConflictRecord;
use kit_core::ops::merge::{MergeResult, merge_trees};
use libkit::conflict::{self, ConflictClass, Error, Event};

#[derive(Default)]
struct Recorder(RefCell<Vec<(String, ConflictClass)>>);

impl Observer<Event> for Recorder {
    fn event(&self, event: &Event) {
        let Event::Materialized { path, class } = event else {
            panic!("unexpected event");
        };
        self.0.borrow_mut().push((path.clone(), *class));
    }
}

struct Paused {
    f: Fixture,
    ours_tree: Hash,
    result: MergeResult,
}

/// Merge `theirs` into `ours` over `base`, with `ours` checked out.
fn pause(base: &[(&str, &str)], ours: &[(&str, &str)], theirs: &[(&str, &str)]) -> Paused {
    let f = init();
    let base = f.commit(base, &[], "base", 1);
    let ours = f.commit(ours, &[base], "ours", 2);
    let theirs = f.commit(theirs, &[base], "theirs", 3);
    f.checkout("main", ours);
    let tree = |h| f.commit_object(h).tree_hash;
    let result = merge_trees(
        &f.store,
        Some(tree(base)),
        Some(tree(ours)),
        Some(tree(theirs)),
    )
    .unwrap();
    Paused {
        ours_tree: tree(ours),
        f,
        result,
    }
}

fn materialize(p: &Paused, observer: &dyn Observer<Event>) -> Vec<ConflictRecord> {
    conflict::materialize(
        &p.f.layout,
        &p.f.store,
        p.result.tree_hash,
        &p.result.conflicts,
        observer,
    )
    .unwrap()
}

#[test]
fn a_text_conflict_gets_markers_and_stages_the_ours_side() {
    let p = pause(
        &[("a.txt", "base\n")],
        &[("a.txt", "ours")],
        &[("a.txt", "theirs\n")],
    );
    let recorder = Recorder::default();
    let records = materialize(&p, &recorder);
    assert_eq!(records.len(), 1);
    assert_eq!(
        recorder.0.into_inner(),
        [("a.txt".to_owned(), ConflictClass::TextMarkers)]
    );
    // A side without a final newline still ends the marker line.
    assert_eq!(
        p.f.read("a.txt"),
        "<<<<<<< ours\nours\n=======\ntheirs\n>>>>>>> theirs\n"
    );
    let idx = index::read_index(&p.f.layout).unwrap();
    let staged = idx.entries.iter().find(|e| e.path == "a.txt").unwrap();
    assert_eq!(staged.status, EntryStatus::Blob);
    assert_eq!(Some(staged.object_hash), records[0].ours_hash);
}

#[test]
fn a_binary_conflict_keeps_the_ours_side_whole() {
    let p = pause(
        &[("a.bin", "base\0")],
        &[("a.bin", "ours\0")],
        &[("a.bin", "theirs\0")],
    );
    let recorder = Recorder::default();
    materialize(&p, &recorder);
    assert_eq!(
        recorder.0.into_inner(),
        [("a.bin".to_owned(), ConflictClass::Binary)]
    );
    assert_eq!(p.f.read("a.bin"), "ours\0");
}

#[test]
fn a_delete_modify_conflict_keeps_the_side_that_survives() {
    let p = pause(
        &[("a.txt", "base\n"), ("b.txt", "b\n")],
        &[("b.txt", "b\n")],
        &[("a.txt", "theirs\n"), ("b.txt", "b\n")],
    );
    let recorder = Recorder::default();
    materialize(&p, &recorder);
    assert_eq!(
        recorder.0.into_inner(),
        [("a.txt".to_owned(), ConflictClass::DeleteModify)]
    );
    assert_eq!(p.f.read("a.txt"), "theirs\n");
    // Ours deleted the path, so the index holds a removal for it.
    let idx = index::read_index(&p.f.layout).unwrap();
    let staged = idx.entries.iter().find(|e| e.path == "a.txt").unwrap();
    assert_eq!(staged.status, EntryStatus::Removed);
}

#[test]
fn a_marker_block_blocks_a_resolution_and_an_unstaged_edit_is_found() {
    let p = pause(
        &[("a.txt", "base\n")],
        &[("a.txt", "ours\n")],
        &[("a.txt", "theirs\n")],
    );
    let records = materialize(&p, &NoopObserver);
    let root = p.f.layout.worktree_root();
    assert_eq!(
        conflict::first_unresolved_marker(root, &records).unwrap(),
        Some("a.txt".to_owned())
    );

    p.f.write("a.txt", "resolved\n");
    assert_eq!(
        conflict::first_unresolved_marker(root, &records).unwrap(),
        None
    );
    let err = conflict::ensure_staged(&p.f.layout, &p.f.store, &records).unwrap_err();
    assert!(
        matches!(err, Error::NotStaged(ref path) if path == "a.txt"),
        "{err:?}"
    );
    assert_eq!(
        err.to_string(),
        "'a.txt' is resolved in the worktree but not staged; run `kit add a.txt` (or `kit rm a.txt`) then `--continue`"
    );

    p.f.stage("a.txt");
    conflict::ensure_staged(&p.f.layout, &p.f.store, &records).unwrap();
}

#[test]
fn a_missing_file_holds_no_marker() {
    let p = pause(
        &[("a.txt", "base\n")],
        &[("a.txt", "ours\n")],
        &[("a.txt", "theirs\n")],
    );
    let records = materialize(&p, &NoopObserver);
    std::fs::remove_file(p.f.path("a.txt")).unwrap();
    assert_eq!(
        conflict::first_unresolved_marker(p.f.layout.worktree_root(), &records).unwrap(),
        None
    );
}

#[test]
fn reset_paths_puts_a_conflict_path_back_to_the_target() {
    let p = pause(
        &[("a.txt", "base\n")],
        &[("a.txt", "ours\n")],
        &[("a.txt", "theirs\n")],
    );
    let records = materialize(&p, &NoopObserver);
    conflict::ensure_abort_safe(&p.f.layout, &p.f.store, &records, p.ours_tree, None).unwrap();
    conflict::reset_paths(&p.f.layout, &p.f.store, &records, p.ours_tree, None).unwrap();
    assert_eq!(p.f.read("a.txt"), "ours\n");
}

#[test]
fn reset_paths_removes_a_path_that_the_operation_added() {
    let p = pause(
        &[("a.txt", "base\n")],
        &[("a.txt", "base\n")],
        &[("a.txt", "base\n"), ("new.txt", "new\n")],
    );
    assert!(p.result.conflicts.is_empty());
    conflict::materialize(
        &p.f.layout,
        &p.f.store,
        p.result.tree_hash,
        &p.result.conflicts,
        &NoopObserver,
    )
    .unwrap();
    assert!(p.f.path("new.txt").exists());

    // The result tree marks the added file as material of the operation.
    conflict::ensure_abort_safe(
        &p.f.layout,
        &p.f.store,
        &[],
        p.ours_tree,
        Some(p.result.tree_hash),
    )
    .unwrap();
    conflict::reset_paths(
        &p.f.layout,
        &p.f.store,
        &[],
        p.ours_tree,
        Some(p.result.tree_hash),
    )
    .unwrap();
    assert!(!p.f.path("new.txt").exists());
    let idx = index::read_index(&p.f.layout).unwrap();
    assert!(idx.entries.iter().all(|e| e.path != "new.txt"));
}

#[test]
fn an_abort_refuses_a_directory_where_the_target_has_a_file() {
    let p = pause(
        &[("a.txt", "base\n")],
        &[("a.txt", "ours\n")],
        &[("a.txt", "theirs\n")],
    );
    let records = materialize(&p, &NoopObserver);
    std::fs::remove_file(p.f.path("a.txt")).unwrap();
    std::fs::create_dir(p.f.path("a.txt")).unwrap();
    std::fs::write(p.f.path("a.txt/keep"), "mine\n").unwrap();

    let err =
        conflict::reset_paths(&p.f.layout, &p.f.store, &records, p.ours_tree, None).unwrap_err();
    assert!(
        matches!(err, Error::AbortReplacesDirectory(ref path) if path == "a.txt"),
        "{err:?}"
    );
    assert!(p.f.path("a.txt/keep").exists());
}

#[test]
fn stage_removals_adds_a_removal_for_each_deleted_path() {
    let p = pause(
        &[("a.txt", "a\n"), ("b.txt", "b\n")],
        &[("a.txt", "a\n"), ("b.txt", "b\n")],
        &[("a.txt", "a\n")],
    );
    libkit::sync::worktree::restore_worktree_and_index(&p.f.layout, &p.f.store, p.result.tree_hash)
        .unwrap();
    conflict::stage_removals(
        &p.f.layout,
        &p.f.store,
        Some(p.ours_tree),
        p.result.tree_hash,
    )
    .unwrap();
    let idx = index::read_index(&p.f.layout).unwrap();
    let removed = idx.entries.iter().find(|e| e.path == "b.txt").unwrap();
    assert_eq!(removed.status, EntryStatus::Removed);
    // A result without a deletion adds nothing.
    let live = idx.entries.iter().find(|e| e.path == "a.txt").unwrap();
    assert_eq!(live.status, EntryStatus::Blob);
}

#[test]
fn a_resolved_chunked_file_hashes_to_the_id_that_add_stages() {
    let p = pause(
        &[("a.txt", "base\n")],
        &[("a.txt", "ours\n")],
        &[("a.txt", "theirs\n")],
    );
    let records = materialize(&p, &NoopObserver);
    // A resolution of several megabytes cuts into chunks.
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut data = Vec::new();
    while data.len() < 3 * 1024 * 1024 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        data.extend_from_slice(&state.to_le_bytes());
    }
    std::fs::write(p.f.path("a.txt"), &data).unwrap();
    assert_eq!(
        conflict::first_unresolved_marker(p.f.layout.worktree_root(), &records).unwrap(),
        None
    );
    assert!(matches!(
        conflict::ensure_staged(&p.f.layout, &p.f.store, &records).unwrap_err(),
        Error::NotStaged(_)
    ));
    // `stage` stores the file as `kit add` does, whole.
    p.f.stage("a.txt");
    conflict::ensure_staged(&p.f.layout, &p.f.store, &records).unwrap();
}

#[test]
fn a_file_above_the_scan_limit_holds_no_marker_and_is_not_read() {
    let p = pause(
        &[("a.txt", "base\n")],
        &[("a.txt", "ours\n")],
        &[("a.txt", "theirs\n")],
    );
    let records = materialize(&p, &NoopObserver);
    // The marker lines start the file, so a scan that read it would find them.
    let file = std::fs::File::create(p.f.path("a.txt")).unwrap();
    std::io::Write::write_all(&mut &file, b"<<<<<<< ours\n=======\n>>>>>>> theirs\n").unwrap();
    file.set_len(1024 * 1024 * 1024 + 1).unwrap();
    // A read of the file fails, so only a scan that skips on the size passes.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(p.f.path("a.txt"), std::fs::Permissions::from_mode(0o000))
            .unwrap();
    }
    assert_eq!(
        conflict::first_unresolved_marker(p.f.layout.worktree_root(), &records).unwrap(),
        None
    );
}

mod marker_scan {
    use super::*;
    use kit_core::ops::merge::ConflictKind;
    use std::fs;
    use std::io::Write as _;

    const BLOCK: &str = "<<<<<<< ours\nmine\n=======\ntheirs\n>>>>>>> theirs\n";

    fn record(path: &str) -> ConflictRecord {
        ConflictRecord {
            path: path.to_owned(),
            kind: ConflictKind::ModifyModify,
            base_hash: None,
            ours_hash: None,
            theirs_hash: None,
            rename: None,
        }
    }

    /// A file of `len` bytes that starts with `head` and has a hole after it,
    /// so it takes no disk space.
    fn sparse_file(path: &std::path::Path, head: &[u8], len: u64) {
        let mut file = fs::File::create(path).unwrap();
        file.write_all(head).unwrap();
        file.set_len(len).unwrap();
    }

    /// The marker block of a file that is a few megabytes long is found, so
    /// the limit of the scan is far above the size of an ordinary file.
    #[test]
    fn a_marker_block_in_a_file_of_several_megabytes_is_found() {
        let dir = tempfile::tempdir().unwrap();
        let mut text = "filler line of text\n".repeat(150_000);
        assert!(text.len() > 2 * 1024 * 1024);
        text.push_str(BLOCK);
        fs::write(dir.path().join("big.txt"), &text).unwrap();
        assert_eq!(
            conflict::first_unresolved_marker(dir.path(), &[record("big.txt")]).unwrap(),
            Some("big.txt".to_owned())
        );
    }

    /// A path under a file is not "missing": the read fails and says so.
    #[test]
    fn a_path_below_a_file_is_a_read_error_not_a_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "plain\n").unwrap();
        let error =
            conflict::first_unresolved_marker(dir.path(), &[record("a.txt/inner")]).unwrap_err();
        assert!(
            matches!(&error, Error::ReadFile { path, .. } if path.ends_with("a.txt/inner")),
            "{error:?}"
        );
        // A path that is simply absent is skipped.
        assert_eq!(
            conflict::first_unresolved_marker(dir.path(), &[record("absent.txt")]).unwrap(),
            None
        );
    }

    /// The scan reads a file of exactly 1 GiB and leaves a larger one alone.
    #[test]
    #[ignore = "reads a 1 GiB file"]
    fn the_scan_covers_a_file_of_one_gibibyte_and_not_one_byte_more() {
        const GIB: u64 = 1024 * 1024 * 1024;
        let dir = tempfile::tempdir().unwrap();
        sparse_file(&dir.path().join("exact.txt"), BLOCK.as_bytes(), GIB);
        sparse_file(&dir.path().join("over.txt"), BLOCK.as_bytes(), GIB + 1);
        assert_eq!(
            conflict::first_unresolved_marker(dir.path(), &[record("exact.txt")]).unwrap(),
            Some("exact.txt".to_owned())
        );
        assert_eq!(
            conflict::first_unresolved_marker(dir.path(), &[record("over.txt")]).unwrap(),
            None
        );
    }

    /// A file that reports no size but yields more than the limit is
    /// skipped, as a file that grew after the size check is.
    #[cfg(unix)]
    #[test]
    #[ignore = "reads a 1 GiB stream"]
    fn a_file_that_grows_past_the_limit_is_skipped_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink("/dev/zero", dir.path().join("endless")).unwrap();
        assert_eq!(
            conflict::first_unresolved_marker(dir.path(), &[record("endless")]).unwrap(),
            None
        );
    }
}

#[test]
fn abort_refuses_a_missing_unchanged_object_before_resetting_a_resolution() {
    let p = pause(
        &[("a.txt", "base\n"), ("b.txt", "keep\n")],
        &[("a.txt", "ours\n"), ("b.txt", "keep\n")],
        &[("a.txt", "theirs\n"), ("b.txt", "keep\n")],
    );
    let records = materialize(&p, &NoopObserver);
    p.f.write("a.txt", "my resolution\n");
    let idx = index::read_index(&p.f.layout).unwrap();
    let h = idx
        .entries
        .iter()
        .find(|e| e.path == "b.txt")
        .unwrap()
        .object_hash;
    let hex = kit_core::hash::to_hex(&h);
    std::fs::remove_file(p.f.layout.objects_dir().join(&hex[..2]).join(&hex[2..])).unwrap();
    let error = conflict::ensure_abort_safe(
        &p.f.layout,
        &p.f.store,
        &records,
        p.ours_tree,
        Some(p.result.tree_hash),
    )
    .unwrap_err();
    assert!(error.to_string().contains("not found"), "{error}");
    assert_eq!(p.f.read("a.txt"), "my resolution\n");
}

#[test]
fn reset_refuses_a_case_alias_before_changing_conflict_material() {
    let f = init();
    std::fs::write(f.path("probe"), b"probe").unwrap();
    if !f.path("PROBE").exists() {
        return;
    }
    std::fs::remove_file(f.path("probe")).unwrap();
    let old = f.commit(&[("aaa", "keep"), ("readme", "keep readme")], &[], "old", 1);
    let target = f.commit(&[("README", "new"), ("aaa", "new")], &[old], "target", 2);
    f.checkout("main", old);
    let before = std::fs::read(f.layout.worktree_state_dir().join("index")).unwrap();
    let result = conflict::reset_paths(
        &f.layout,
        &f.store,
        &[],
        f.commit_object(target).tree_hash,
        Some(f.commit_object(old).tree_hash),
    );
    assert!(result.is_err());
    assert_eq!(std::fs::read(f.path("aaa")).unwrap(), b"keep");
    assert_eq!(std::fs::read(f.path("readme")).unwrap(), b"keep readme");
    assert_eq!(
        std::fs::read(f.layout.worktree_state_dir().join("index")).unwrap(),
        before
    );
}

/// The Kelvin sign spelling of `.kit`: the same directory as `.kit` on a
/// filesystem that folds Unicode (APFS), another name elsewhere.
const KELVIN_KIT: &str = ".\u{212A}it";

/// A commit whose root holds `keep.txt` and, when `dir_file` is set, the
/// directory `dir` with one file in it.
fn commit_with_dir(
    f: &common::Fixture,
    dir: &str,
    dir_file: Option<(&str, &str)>,
    parents: &[Hash],
    time: u64,
) -> Hash {
    use kit_core::object::{Blob, Commit, EntryMode, Identity, Object, Tree, TreeEntry};
    use kit_core::serialize;
    let put = |object: Object| {
        f.store
            .write(&serialize::serialize(&object).unwrap())
            .unwrap()
    };
    let blob = |text: &str| {
        put(Object::Blob(Blob {
            data: text.as_bytes().to_vec(),
        }))
    };
    // Entries sort by name: `d` and `.` come before `keep.txt`.
    let mut entries = Vec::new();
    if let Some((name, text)) = dir_file {
        let inner = put(Object::Tree(Tree {
            entries: vec![TreeEntry {
                name: name.as_bytes().to_vec(),
                mode: EntryMode::Blob,
                object_hash: blob(text),
            }],
        }));
        entries.push(TreeEntry {
            name: dir.as_bytes().to_vec(),
            mode: EntryMode::Tree,
            object_hash: inner,
        });
    }
    entries.push(TreeEntry {
        name: b"keep.txt".to_vec(),
        mode: EntryMode::Blob,
        object_hash: blob("keep\n"),
    });
    let tree = put(Object::Tree(Tree { entries }));
    put(Object::Commit(Commit::new_unannotated(
        tree,
        parents.to_vec(),
        Identity::ed25519([9; 32]),
        [9; 32],
        b"c".to_vec(),
        time,
        [0; 64],
    )))
}

/// Pause a merge whose only conflict is `dir/HEAD`: ours deleted it and
/// theirs changed it.
fn pause_on_dir_file(dir: &str) -> Paused {
    let f = init();
    let base = commit_with_dir(&f, dir, Some(("HEAD", "base\n")), &[], 1);
    let ours = commit_with_dir(&f, dir, None, &[base], 2);
    let theirs = commit_with_dir(&f, dir, Some(("HEAD", "theirs\n")), &[base], 3);
    f.checkout("main", ours);
    let tree = |h| f.commit_object(h).tree_hash;
    let result = merge_trees(
        &f.store,
        Some(tree(base)),
        Some(tree(ours)),
        Some(tree(theirs)),
    )
    .unwrap();
    Paused {
        ours_tree: tree(ours),
        f,
        result,
    }
}

#[test]
fn materialize_never_writes_to_the_repository_directory_under_another_spelling() {
    let p = pause_on_dir_file(KELVIN_KIT);
    assert_eq!(p.result.conflicts.len(), 1, "{:?}", p.result.conflicts);
    let head = p.f.read(".kit/HEAD");

    let result = conflict::materialize(
        &p.f.layout,
        &p.f.store,
        p.result.tree_hash,
        &p.result.conflicts,
        &NoopObserver,
    );

    assert_eq!(p.f.read(".kit/HEAD"), head, "{result:?}");
    // On a filesystem that folds the spelling the operation is refused; on
    // one that does not, the name is an ordinary directory.
    if std::fs::symlink_metadata(p.f.path(KELVIN_KIT)).is_ok_and(|m| m.is_dir()) {
        assert!(result.is_err());
    }
}

/// A repository that is at a commit whose tree holds the symlink `d -> .kit`,
/// and a delete/modify conflict at `d/HEAD`, as a merge that kept that link
/// would report it.
#[cfg(unix)]
fn paused_below_a_tracked_symlink() -> (Paused, kit_core::ops::merge::Conflict) {
    use kit_core::object::{Blob, Commit, EntryMode, Identity, Object, Tree, TreeEntry};
    use kit_core::serialize;
    let f = init();
    let put = |object: Object| {
        f.store
            .write(&serialize::serialize(&object).unwrap())
            .unwrap()
    };
    let blob = |text: &str| {
        put(Object::Blob(Blob {
            data: text.as_bytes().to_vec(),
        }))
    };
    let tree = put(Object::Tree(Tree {
        entries: vec![
            TreeEntry {
                name: b"d".to_vec(),
                mode: EntryMode::Symlink,
                object_hash: blob(".kit"),
            },
            TreeEntry {
                name: b"keep.txt".to_vec(),
                mode: EntryMode::Blob,
                object_hash: blob("keep\n"),
            },
        ],
    }));
    let commit = put(Object::Commit(Commit::new_unannotated(
        tree,
        vec![],
        Identity::ed25519([9; 32]),
        [9; 32],
        b"c".to_vec(),
        1,
        [0; 64],
    )));
    f.checkout("main", commit);
    assert!(std::fs::symlink_metadata(f.path("d")).unwrap().is_symlink());
    let conflict = kit_core::ops::merge::Conflict {
        path: "d/HEAD".to_owned(),
        kind: kit_core::ops::merge::ConflictKind::DeleteModify,
        base_hash: None,
        ours_hash: None,
        theirs_hash: Some(blob("theirs\n")),
        ours_mode: None,
        theirs_mode: Some(EntryMode::Blob),
        rename: None,
    };
    let paused = Paused {
        f,
        ours_tree: tree,
        result: MergeResult {
            tree_hash: tree,
            conflicts: vec![],
        },
    };
    (paused, conflict)
}

#[cfg(unix)]
#[test]
fn materialize_never_writes_through_a_symlinked_directory() {
    let (p, conflict) = paused_below_a_tracked_symlink();
    let head = p.f.read(".kit/HEAD");

    let result = conflict::materialize(
        &p.f.layout,
        &p.f.store,
        p.ours_tree,
        std::slice::from_ref(&conflict),
        &NoopObserver,
    );

    assert_eq!(p.f.read(".kit/HEAD"), head, "{result:?}");
    assert!(matches!(result, Err(Error::WriteFile { .. })), "{result:?}");
}

#[cfg(unix)]
#[test]
fn reset_paths_never_removes_through_a_symlinked_directory() {
    let (p, conflict) = paused_below_a_tracked_symlink();
    let head = p.f.read(".kit/HEAD");
    let records = [ConflictRecord::from(&conflict)];
    // The target tree holds no `d/HEAD`, so the reset removes it.
    let target = p.ours_tree;

    let result = conflict::reset_paths(&p.f.layout, &p.f.store, &records, target, None);

    assert_eq!(p.f.read(".kit/HEAD"), head, "{result:?}");
    assert!(result.is_ok(), "{result:?}");
}
