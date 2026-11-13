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
    // A write takes the shared lock too, so the guards do not delay it.
    let written = orphans(&store, 2);
    assert!(written.iter().all(|id| store.contains(id)));
    drop(first);
    drop(second);
}
