//! A ref or `HEAD` written in two steps on a flush group: staged, then
//! published under the ref lock with a token.

use std::sync::Arc;

use tempfile::TempDir;

use super::*;
use crate::batch::Syncer;
use crate::batch::testing::{Ev, RecordingSyncer};

fn setup() -> (TempDir, RepoLayout, Arc<RecordingSyncer>, Group) {
    let dir = TempDir::new().unwrap();
    let layout = RepoLayout::single(dir.path());
    init(&layout).unwrap();
    let rec = Arc::new(RecordingSyncer::default());
    let group = Group::with_syncer(Arc::clone(&rec) as Arc<dyn Syncer>);
    (dir, layout, rec, group)
}

fn temps_in(dir: &Path) -> usize {
    fs::read_dir(dir)
        .unwrap()
        .filter(|e| {
            e.as_ref()
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".kit.tmp.")
        })
        .count()
}

#[test]
fn a_staged_ref_is_invisible_until_published_and_needs_a_flush() {
    let (_dir, layout, rec, mut group) = setup();
    let staged = stage_ref_update(&mut group, &layout, "main", &[7; 32]).unwrap();
    assert_eq!(read_ref(&layout, "main").unwrap(), None);
    // The bytes were written out, not flushed.
    assert!(
        rec.events()
            .iter()
            .any(|e| matches!(e, Ev::Barrier(p) if p.starts_with(layout.heads_dir())))
    );
    assert!(!rec.events().iter().any(|e| matches!(e, Ev::Full(_))));

    let token = group.flush().unwrap();
    let lock = publish_staged_ref(&mut group, staged, RefWriteCondition::Missing, &token).unwrap();
    assert_eq!(read_ref(&layout, "main").unwrap(), Some([7; 32]));
    // The rename is not durable yet: one more flush, with the lock held.
    let renamed = rec.events().len();
    let _named = group.flush().unwrap();
    assert!(matches!(rec.events()[renamed..], [Ev::Full(_)]));
    drop(lock);
}

#[test]
fn a_stale_token_publishes_nothing_and_leaves_no_temp() {
    let (_dir, layout, _rec, mut group) = setup();
    let early = group.flush().unwrap();
    let staged = stage_ref_update(&mut group, &layout, "main", &[7; 32]).unwrap();
    let error = publish_staged_ref(&mut group, staged, RefWriteCondition::Any, &early).unwrap_err();
    assert!(matches!(error, RefError::Io(_)), "{error:?}");
    assert_eq!(read_ref(&layout, "main").unwrap(), None);
    assert_eq!(temps_in(&layout.heads_dir()), 0);
}

#[test]
fn the_condition_is_checked_when_the_ref_is_published() {
    let (_dir, layout, _rec, mut group) = setup();
    write_ref(&layout, "main", &[1; 32]).unwrap();

    let staged = stage_ref_update(&mut group, &layout, "main", &[2; 32]).unwrap();
    let token = group.flush().unwrap();
    let error = publish_staged_ref(
        &mut group,
        staged,
        RefWriteCondition::Match([9; 32]),
        &token,
    )
    .unwrap_err();
    assert!(
        matches!(error, RefError::Conflict(ref name) if name == "main"),
        "{error:?}"
    );
    assert_eq!(read_ref(&layout, "main").unwrap(), Some([1; 32]));
    assert_eq!(temps_in(&layout.heads_dir()), 0, "the temp file is dropped");

    let staged = stage_ref_update(&mut group, &layout, "main", &[3; 32]).unwrap();
    let token = group.flush().unwrap();
    let error =
        publish_staged_ref(&mut group, staged, RefWriteCondition::Missing, &token).unwrap_err();
    assert!(matches!(error, RefError::Conflict(_)), "{error:?}");
    assert_eq!(read_ref(&layout, "main").unwrap(), Some([1; 32]));
    assert_eq!(temps_in(&layout.heads_dir()), 0);

    let staged = stage_ref_update(&mut group, &layout, "main", &[4; 32]).unwrap();
    let token = group.flush().unwrap();
    drop(
        publish_staged_ref(
            &mut group,
            staged,
            RefWriteCondition::Match([1; 32]),
            &token,
        )
        .unwrap(),
    );
    assert_eq!(read_ref(&layout, "main").unwrap(), Some([4; 32]));

    let staged = stage_ref_update(&mut group, &layout, "main", &[5; 32]).unwrap();
    let token = group.flush().unwrap();
    drop(publish_staged_ref(&mut group, staged, RefWriteCondition::Any, &token).unwrap());
    assert_eq!(read_ref(&layout, "main").unwrap(), Some([5; 32]));
}

#[test]
fn a_ref_below_a_new_directory_makes_the_directory() {
    let (_dir, layout, _rec, mut group) = setup();
    let staged = stage_ref_update(&mut group, &layout, "topic/deep/work", &[6; 32]).unwrap();
    let token = group.flush().unwrap();
    drop(publish_staged_ref(&mut group, staged, RefWriteCondition::Missing, &token).unwrap());
    assert_eq!(read_ref(&layout, "topic/deep/work").unwrap(), Some([6; 32]));
}

#[test]
fn an_invalid_name_is_refused_before_anything_is_written() {
    let (_dir, layout, rec, mut group) = setup();
    let error = stage_ref_update(&mut group, &layout, "bad name", &[7; 32]).unwrap_err();
    assert!(matches!(error, RefError::InvalidRefName(_)), "{error:?}");
    assert!(rec.events().is_empty());
}

#[test]
fn a_ref_and_the_index_of_one_commit_share_the_token() {
    let (_dir, layout, _rec, mut group) = setup();
    let staged = stage_ref_update(&mut group, &layout, "main", &[7; 32]).unwrap();
    let index = crate::index::stage_index(
        &mut group,
        &layout,
        &crate::index::Index::from_entries(Vec::new()),
    )
    .unwrap();
    let token = group.flush().unwrap();
    let lock = publish_staged_ref(&mut group, staged, RefWriteCondition::Missing, &token).unwrap();
    crate::index::publish_staged_index(&mut group, index, &token).unwrap();
    assert!(layout.index_file().is_file());
    assert_eq!(read_ref(&layout, "main").unwrap(), Some([7; 32]));
    group.finish().unwrap();
    drop(lock);
}

#[test]
fn a_staged_index_is_invisible_until_published() {
    let (_dir, layout, _rec, mut group) = setup();
    let staged = crate::index::stage_index(
        &mut group,
        &layout,
        &crate::index::Index::from_entries(Vec::new()),
    )
    .unwrap();
    assert!(!layout.index_file().exists());
    assert_eq!(staged.temp_path().parent(), layout.index_file().parent());
    let early = group.flush().unwrap();
    let other = crate::index::stage_index(
        &mut group,
        &layout,
        &crate::index::Index::from_entries(Vec::new()),
    )
    .unwrap();
    // A token from before the second file's writeout does not cover it.
    assert!(crate::index::publish_staged_index(&mut group, other, &early).is_err());
    assert!(!layout.index_file().exists());
    crate::index::publish_staged_index(&mut group, staged, &early).unwrap();
    assert!(layout.index_file().is_file());
}

#[test]
fn a_detached_head_is_staged_and_published_with_a_token() {
    let (_dir, layout, _rec, mut group) = setup();
    write_head_detached(&layout, &[1; 32]).unwrap();
    let staged = stage_head_detached(&mut group, &layout, &[2; 32]).unwrap();
    assert_eq!(resolve_head(&layout).unwrap(), Some([1; 32]));

    let early_group_token = group.flush().unwrap();
    publish_staged_head(&mut group, staged, &early_group_token).unwrap();
    assert_eq!(resolve_head(&layout).unwrap(), Some([2; 32]));

    let late = stage_head_detached(&mut group, &layout, &[3; 32]).unwrap();
    // The first rename came after this token.
    assert!(publish_staged_head(&mut group, late, &early_group_token).is_err());
    assert_eq!(resolve_head(&layout).unwrap(), Some([2; 32]));
}
