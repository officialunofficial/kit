//! A held `PruneGuard` keeps gc from deleting any object, at any grace
//! period, and releases the store when it drops.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::sync::mpsc;
use std::time::Duration;

use kit_core::hash::Hash;
use kit_core::layout::RepoLayout;
use kit_core::object::{Blob, Object};
use kit_core::ops::run_gc;
use kit_core::{ObjectStore, refs, serialize};

fn repo() -> (tempfile::TempDir, RepoLayout, ObjectStore) {
    let dir = tempfile::tempdir().unwrap();
    let layout = RepoLayout::single(dir.path());
    let store = ObjectStore::init(&layout).unwrap();
    refs::init(&layout).unwrap();
    (dir, layout, store)
}

/// Write `count` blobs that no ref reaches.
fn orphans(store: &ObjectStore, count: usize) -> Vec<Hash> {
    (0..count)
        .map(|i| {
            let blob = Object::Blob(Blob {
                data: format!("orphan {i}").into_bytes(),
            });
            store.write(&serialize::serialize(&blob).unwrap()).unwrap()
        })
        .collect()
}

#[test]
fn gc_at_grace_zero_prunes_nothing_while_the_guard_is_held() {
    let (_dir, layout, store) = repo();
    let ids = orphans(&store, 5);

    let guard = store.prune_guard().unwrap();
    let report = run_gc(&store, &layout, u64::MAX, 0, false).unwrap();
    assert_eq!(report.pruned, 0);
    assert_eq!(report.kept_recent, 5);
    assert!(ids.iter().all(|id| store.contains(id)));

    drop(guard);
    let report = run_gc(&store, &layout, u64::MAX, 0, false).unwrap();
    assert_eq!(report.pruned, 5);
    assert!(ids.iter().all(|id| !store.contains(id)));
}

#[test]
fn a_guard_held_from_another_thread_protects_the_store() {
    let (_dir, layout, store) = repo();
    let ids = orphans(&store, 3);
    let (held_tx, held_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel::<()>();

    std::thread::scope(|scope| {
        let layout_ref = &layout;
        let holder = scope.spawn(move || {
            // A second handle to the same store, as another process has.
            let other = ObjectStore::open(layout_ref).unwrap();
            let _guard = other.prune_guard().unwrap();
            held_tx.send(()).unwrap();
            release_rx.recv().unwrap();
        });
        held_rx.recv_timeout(Duration::from_secs(10)).unwrap();

        let report = run_gc(&store, &layout, u64::MAX, 0, false).unwrap();
        assert_eq!(report.pruned, 0);
        assert!(ids.iter().all(|id| store.contains(id)));

        release_tx.send(()).unwrap();
        holder.join().unwrap();
    });

    let report = run_gc(&store, &layout, u64::MAX, 0, false).unwrap();
    assert_eq!(report.pruned, 3);
}

#[test]
fn guards_coexist_and_never_block_writers() {
    let (_dir, _layout, store) = repo();
    let first = store.prune_guard().unwrap();
    let second = store.prune_guard().unwrap();
    // A bulk write takes the shared lock too, so the guards do not delay it.
    let written = orphans(&store, 2);
    assert!(written.iter().all(|id| store.contains(id)));
    drop(first);
    drop(second);
}

/// A temp file named the way an object write names it, with its modification
/// time `age_secs` in the past.
fn temp_file(store: &ObjectStore, name: &str, age_secs: u64) -> std::path::PathBuf {
    let shard = store.objects_root().join("ab");
    std::fs::create_dir_all(&shard).unwrap();
    let path = shard.join(name);
    std::fs::write(&path, b"partial object").unwrap();
    let modified = std::time::SystemTime::now() - Duration::from_secs(age_secs);
    std::fs::File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_modified(modified)
        .unwrap();
    path
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[test]
fn gc_removes_a_temp_file_older_than_the_grace_period_and_keeps_a_younger_one() {
    let (_dir, layout, store) = repo();
    let old = temp_file(&store, ".0123.tmp.77.1Xyz", 10_000);
    let bulk = temp_file(&store, ".kit.tmp.77.2Abc", 10_000);
    let young = temp_file(&store, ".4567.tmp.77.3Def", 10);

    let report = run_gc(&store, &layout, now_secs(), 1_000, true).unwrap();
    assert_eq!(report.temp_files_pruned, 2);
    assert!(old.exists() && bulk.exists() && young.exists(), "dry run");

    let report = run_gc(&store, &layout, now_secs(), 1_000, false).unwrap();
    assert_eq!(report.temp_files_pruned, 2);
    assert_eq!(report.bytes_reclaimed, 2 * 14);
    assert!(!old.exists() && !bulk.exists());
    assert!(young.exists());
}

#[test]
fn gc_keeps_an_old_temp_file_while_a_prune_guard_is_held() {
    let (_dir, layout, store) = repo();
    let old = temp_file(&store, ".0123.tmp.77.1Xyz", 10_000);

    let guard = store.prune_guard().unwrap();
    let report = run_gc(&store, &layout, now_secs(), 0, false).unwrap();
    assert_eq!(report.temp_files_pruned, 0);
    assert!(old.exists());

    drop(guard);
    let report = run_gc(&store, &layout, now_secs(), 1_000, false).unwrap();
    assert_eq!(report.temp_files_pruned, 1);
    assert!(!old.exists());
}

#[test]
fn gc_leaves_files_that_are_not_temp_files_alone() {
    let (_dir, layout, store) = repo();
    let ids = orphans(&store, 1);
    let shard = store.objects_root().join("ab");
    std::fs::create_dir_all(&shard).unwrap();
    let stray = shard.join("notes.txt");
    std::fs::write(&stray, b"x").unwrap();
    std::fs::File::options()
        .write(true)
        .open(&stray)
        .unwrap()
        .set_modified(std::time::SystemTime::now() - Duration::from_secs(10_000))
        .unwrap();

    let report = run_gc(&store, &layout, now_secs(), 1_000, false).unwrap();
    assert_eq!(report.temp_files_pruned, 0);
    assert!(stray.exists());
    assert!(store.contains(&ids[0]), "a young object stays too");
}
