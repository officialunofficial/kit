//! `WriteBatch::commit_in`: the flush of the bytes, the renames, and the names
//! left pending for the caller's flush.

use std::sync::Arc;

use tempfile::TempDir;

use super::testing::{Ev, RecordingSyncer};
use super::*;
use crate::durable::Parents;

fn recording_store() -> (TempDir, ObjectStore, Arc<RecordingSyncer>) {
    let dir = TempDir::new().unwrap();
    let mut store =
        ObjectStore::init(&crate::layout::RepoLayout::single(dir.path())).expect("init");
    let rec = Arc::new(RecordingSyncer::default());
    store.set_syncer(rec.clone());
    (dir, store, rec)
}

fn position(events: &[Ev], wanted: impl Fn(&Ev) -> bool) -> Option<usize> {
    events.iter().position(wanted)
}

fn fulls(events: &[Ev]) -> usize {
    events.iter().filter(|e| matches!(e, Ev::Full(_))).count()
}

#[test]
fn the_bytes_of_the_batch_and_of_the_caller_share_one_flush_before_any_rename() {
    let (dir, store, rec) = recording_store();
    let batch = store.batch();
    let hashes: Vec<Hash> = (0..3)
        .map(|n| batch.write(format!("object {n}").as_bytes()).unwrap())
        .collect();
    let mut group = store.group();
    let pointer = dir.path().join("pointer");
    let staged = group.stage(&pointer, b"ref", Parents::Existing).unwrap();

    batch.commit_in(&mut group).unwrap();

    let events = rec.events();
    assert_eq!(fulls(&events), 1, "the bytes: {events:?}");
    let flush = position(&events, |e| matches!(e, Ev::Full(_))).unwrap();
    let first_rename = position(&events, |e| matches!(e, Ev::Rename { .. })).unwrap();
    let last_rename = events
        .iter()
        .rposition(|e| matches!(e, Ev::Rename { .. }))
        .unwrap();
    assert!(flush < first_rename, "the flush comes before any rename");
    // The caller's temp file was written out before that flush.
    let temp = staged.temp_path().to_path_buf();
    let written = position(&events, |e| *e == Ev::Barrier(temp.clone())).unwrap();
    assert!(written < flush);
    // The names are pending: nothing flushes after the last rename.
    assert!(
        events[last_rename..]
            .iter()
            .all(|e| !matches!(e, Ev::Full(_)))
    );
    for hash in &hashes {
        assert!(store.contains(hash), "the object is visible");
    }
    assert_eq!(fs::read(staged.temp_path()).unwrap(), b"ref");
}

#[test]
fn the_dirents_are_written_out_with_objects_and_one_more_flush_makes_them_durable() {
    let (_dir, store, rec) = recording_store();
    let batch = store.batch();
    let hash = batch.write(b"one object").unwrap();
    let mut group = store.group();
    batch.commit_in(&mut group).unwrap();

    let shard = store.path_for(&hash).parent().unwrap().to_path_buf();
    let events = rec.events();
    assert!(events.contains(&Ev::DirBarrier(shard)));
    assert!(events.contains(&Ev::DirBarrier(store.objects_root().to_path_buf())));
    assert_eq!(fulls(&events), 1);

    let _named = group.flush().unwrap();
    let events = rec.events();
    assert_eq!(fulls(&events), 2);
    assert_eq!(
        events.last(),
        Some(&Ev::Full(store.objects_root().to_path_buf())),
        "the flush of the names is anchored at objects/"
    );
}

#[test]
fn a_token_from_before_the_renames_does_not_license_a_publish_after_them() {
    let (dir, store, _rec) = recording_store();
    let mut group = store.group();
    let pointer = dir.path().join("pointer");
    let staged = group.stage(&pointer, b"ref", Parents::Existing).unwrap();
    let early = group.flush().unwrap();
    let batch = store.batch();
    batch.write(b"object").unwrap();
    batch.commit_in(&mut group).unwrap();

    assert!(group.publish(staged, &early).is_err());
    assert!(!pointer.exists());

    let staged = group.stage(&pointer, b"ref", Parents::Existing).unwrap();
    let late = group.flush().unwrap();
    group.publish(staged, &late).unwrap();
    assert_eq!(fs::read(&pointer).unwrap(), b"ref");
}

#[test]
fn a_batch_with_nothing_staged_flushes_and_renames_nothing() {
    let (_dir, store, rec) = recording_store();
    let mut group = store.group();
    store.batch().commit_in(&mut group).unwrap();
    assert!(rec.events().is_empty(), "{:?}", rec.events());
    let _token = group.flush().unwrap();
    assert_eq!(fulls(&rec.events()), 0);
}

#[test]
fn a_dedup_hit_writes_out_its_locations_and_leaves_the_flush_to_the_caller() {
    let (_dir, store, rec) = recording_store();
    let hash = store.write(b"already here").unwrap();
    let before = rec.events().len();

    let batch = store.batch();
    assert_eq!(batch.write(b"already here").unwrap(), hash);
    let mut group = store.group();
    batch.commit_in(&mut group).unwrap();

    let events = rec.events()[before..].to_vec();
    let shard = store.path_for(&hash).parent().unwrap().to_path_buf();
    assert!(events.contains(&Ev::DirBarrier(shard)));
    assert!(events.contains(&Ev::DirBarrier(store.objects_root().to_path_buf())));
    assert_eq!(fulls(&events), 0, "nothing was staged: no flush of bytes");
    assert!(!events.iter().any(|e| matches!(e, Ev::Rename { .. })));

    let _token = group.flush().unwrap();
    assert_eq!(fulls(&rec.events()[before..]), 1);
}

#[test]
fn where_writeouts_are_durable_the_group_makes_no_flush_call() {
    let (_dir, store, rec) = recording_store();
    rec.durable_writeouts();
    let batch = store.batch();
    let hash = batch.write(b"object").unwrap();
    let mut group = store.group();
    batch.commit_in(&mut group).unwrap();
    let _token = group.flush().unwrap();
    assert_eq!(fulls(&rec.events()), 0);
    assert!(store.contains(&hash));
}

#[test]
fn a_failed_flush_makes_nothing_visible_and_poisons_the_group() {
    let (_dir, store, rec) = recording_store();
    rec.fail_flushes();
    let batch = store.batch();
    let hash = batch.write(b"object").unwrap();
    let mut group = store.group();
    assert!(batch.commit_in(&mut group).is_err());
    assert!(!store.contains(&hash), "no rename follows a failed flush");
    assert!(!rec.events().iter().any(|e| matches!(e, Ev::Rename { .. })));
    assert!(group.flush().is_err(), "the group is poisoned");
}

#[test]
fn a_failed_rename_ends_the_commit_and_the_objects_not_renamed_stay_invisible() {
    let (_dir, store, rec) = recording_store();
    rec.fail_renames_after(0);
    let batch = store.batch();
    let hash = batch.write(b"object").unwrap();
    let mut group = store.group();
    assert!(batch.commit_in(&mut group).is_err());
    assert!(!store.contains(&hash));
}

#[test]
fn per_object_writes_are_visible_already_and_only_their_locations_are_noted() {
    let (_dir, store, rec) = recording_store();
    let batch = store.batch_with_policy(SyncPolicy::PerObject);
    let hash = batch.write(b"object").unwrap();
    assert!(store.contains(&hash));
    let fulls_before = fulls(&rec.events());
    let mut group = store.group();
    batch.commit_in(&mut group).unwrap();
    // The write flushed its own bytes; commit_in adds none.
    assert_eq!(fulls(&rec.events()), fulls_before);
}
