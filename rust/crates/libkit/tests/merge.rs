//! Merging a branch into `HEAD`, with a pause and a resume for conflicts.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in tests

mod common;

use std::cell::RefCell;

use common::{Fixture, TestSigning, init};
use kit_core::layout::RepoLayout;
use kit_core::observer::{NoopObserver, Observer};
use kit_core::ops::conflict_state::is_merge_in_progress;
use kit_core::refs;
use kit_core::sign;
use libkit::conflict::{self, ConflictClass};
use libkit::merge::{self, Error, Outcome, Request};
use libkit::signing::{self, ErrorKind, Signer, Signing};

fn merge_request(target: &str) -> Request<'_> {
    Request {
        target,
        no_commit: false,
        message: None,
    }
}

fn start(f: &Fixture, request: &Request<'_>) -> Result<Outcome, Error> {
    merge::start(&f.layout, &f.store, request, &TestSigning, &NoopObserver)
}

/// `main` and `topic` both change `a.txt`. `b.txt` is the same on both.
fn diverged(f: &Fixture) -> (kit_core::hash::Hash, kit_core::hash::Hash) {
    let base = f.commit(&[("a.txt", "one\n"), ("b.txt", "b\n")], &[], "base", 1);
    let ours = f.commit(&[("a.txt", "ours\n"), ("b.txt", "b\n")], &[base], "ours", 2);
    let theirs = f.commit(
        &[("a.txt", "theirs\n"), ("b.txt", "b\n")],
        &[base],
        "theirs",
        3,
    );
    refs::write_ref(&f.layout, "topic", &theirs).unwrap();
    f.checkout("main", ours);
    (ours, theirs)
}

#[derive(Default)]
struct Recorder(RefCell<Vec<conflict::Event>>);

impl Observer<conflict::Event> for Recorder {
    fn event(&self, event: &conflict::Event) {
        self.0.borrow_mut().push(event.clone());
    }
}

#[test]
fn a_target_that_is_head_is_up_to_date() {
    let f = init();
    let tip = f.commit(&[("a.txt", "one\n")], &[], "tip", 1);
    f.checkout("main", tip);
    assert_eq!(
        start(&f, &merge_request("main")).unwrap(),
        Outcome::UpToDate { head: tip }
    );
}

#[test]
fn a_target_ahead_of_head_fast_forwards_it() {
    let f = init();
    let base = f.commit(&[("a.txt", "one\n")], &[], "base", 1);
    let ahead = f.commit(&[("a.txt", "two\n"), ("c.txt", "c\n")], &[base], "ahead", 2);
    refs::write_ref(&f.layout, "topic", &ahead).unwrap();
    f.checkout("main", base);

    let outcome = start(&f, &merge_request("topic")).unwrap();
    assert_eq!(
        outcome,
        Outcome::FastForward {
            old: base,
            new: ahead
        }
    );
    assert_eq!(refs::read_ref(&f.layout, "main").unwrap(), Some(ahead));
    assert_eq!(f.read("a.txt"), "two\n");
    assert_eq!(f.read("c.txt"), "c\n");
}

#[test]
fn a_clean_merge_writes_a_signed_commit_with_two_parents() {
    let f = init();
    let base = f.commit(&[("a.txt", "one\n"), ("b.txt", "one\n")], &[], "base", 1);
    let ours = f.commit(
        &[("a.txt", "ours\n"), ("b.txt", "one\n")],
        &[base],
        "ours",
        2,
    );
    let theirs = f.commit(
        &[("a.txt", "one\n"), ("b.txt", "theirs\n")],
        &[base],
        "theirs",
        3,
    );
    refs::write_ref(&f.layout, "topic", &theirs).unwrap();
    f.checkout("main", ours);

    let Outcome::Merged(merged) = start(&f, &merge_request("topic")).unwrap() else {
        panic!("expected a merge commit");
    };
    assert_eq!((merged.ours, merged.theirs), (ours, theirs));
    let commit = f.commit_object(merged.commit);
    assert_eq!(commit.parents, [ours, theirs]);
    assert_eq!(commit.message, b"Merge branch 'topic'");
    assert_eq!(commit.tree_hash, merged.tree);
    sign::verify_commit(&commit).unwrap();
    assert_eq!(
        refs::read_ref(&f.layout, "main").unwrap(),
        Some(merged.commit)
    );
    assert_eq!(f.read("a.txt"), "ours\n");
    assert_eq!(f.read("b.txt"), "theirs\n");
}

#[test]
fn a_message_replaces_the_default() {
    let f = init();
    let base = f.commit(&[("a.txt", "one\n"), ("b.txt", "one\n")], &[], "base", 1);
    let ours = f.commit(
        &[("a.txt", "ours\n"), ("b.txt", "one\n")],
        &[base],
        "ours",
        2,
    );
    let theirs = f.commit(
        &[("a.txt", "one\n"), ("b.txt", "theirs\n")],
        &[base],
        "theirs",
        3,
    );
    refs::write_ref(&f.layout, "topic", &theirs).unwrap();
    f.checkout("main", ours);

    let request = Request {
        message: Some("custom"),
        ..merge_request("topic")
    };
    let Outcome::Merged(merged) = start(&f, &request).unwrap() else {
        panic!("expected a merge commit");
    };
    assert_eq!(f.commit_object(merged.commit).message, b"custom");
}

#[test]
fn a_remote_tracking_target_names_the_remote_in_the_message() {
    let f = init();
    let base = f.commit(&[("a.txt", "one\n"), ("b.txt", "one\n")], &[], "base", 1);
    let ours = f.commit(
        &[("a.txt", "ours\n"), ("b.txt", "one\n")],
        &[base],
        "ours",
        2,
    );
    let theirs = f.commit(
        &[("a.txt", "one\n"), ("b.txt", "theirs\n")],
        &[base],
        "theirs",
        3,
    );
    refs::write_remote_ref(&f.layout, "origin", "topic", &theirs).unwrap();
    f.checkout("main", ours);

    let Outcome::Merged(merged) = start(&f, &merge_request("origin/topic")).unwrap() else {
        panic!("expected a merge commit");
    };
    assert_eq!(
        f.commit_object(merged.commit).message,
        b"Merge remote-tracking branch 'origin/topic'"
    );
}

#[test]
fn a_conflict_pauses_with_markers_and_recorded_state() {
    let f = init();
    let (ours, _) = diverged(&f);
    let recorder = Recorder::default();

    let outcome = merge::start(
        &f.layout,
        &f.store,
        &merge_request("topic"),
        &TestSigning,
        &recorder,
    )
    .unwrap();
    let Outcome::Conflicted { conflicts } = outcome else {
        panic!("expected a conflict");
    };
    assert_eq!(conflicts.len(), 1);
    assert_eq!(conflicts[0].path, "a.txt");
    assert_eq!(
        recorder.0.into_inner(),
        [conflict::Event::Materialized {
            path: "a.txt".to_owned(),
            class: ConflictClass::TextMarkers,
        }]
    );
    assert_eq!(
        f.read("a.txt"),
        "<<<<<<< ours\nours\n=======\ntheirs\n>>>>>>> theirs\n"
    );
    assert!(is_merge_in_progress(&f.layout));
    // The branch has not moved.
    assert_eq!(refs::read_ref(&f.layout, "main").unwrap(), Some(ours));
}

#[test]
fn a_second_operation_is_refused_while_a_merge_is_paused() {
    let f = init();
    diverged(&f);
    start(&f, &merge_request("topic")).unwrap();
    let err = start(&f, &merge_request("topic")).unwrap_err();
    assert!(matches!(err, Error::InProgress("merge")), "{err:?}");
    assert_eq!(
        err.to_string(),
        "a merge is already in progress (use --continue or --abort)"
    );
}

#[test]
fn resume_refuses_markers_and_an_unstaged_resolution() {
    let f = init();
    diverged(&f);
    start(&f, &merge_request("topic")).unwrap();

    let err = merge::resume(&f.layout, &f.store, &TestSigning).unwrap_err();
    assert!(
        matches!(err, Error::UnresolvedMarkers(ref p) if p == "a.txt"),
        "{err:?}"
    );

    f.write("a.txt", "resolved\n");
    let err = merge::resume(&f.layout, &f.store, &TestSigning).unwrap_err();
    assert!(
        matches!(err, Error::Conflict(conflict::Error::NotStaged(ref p)) if p == "a.txt"),
        "{err:?}"
    );
    // A refusal keeps the state.
    assert!(is_merge_in_progress(&f.layout));
}

#[test]
fn resume_commits_the_resolved_index() {
    let f = init();
    let (ours, theirs) = diverged(&f);
    start(&f, &merge_request("topic")).unwrap();
    f.write("a.txt", "resolved\n");
    f.stage("a.txt");

    let merged = merge::resume(&f.layout, &f.store, &TestSigning).unwrap();
    assert_eq!((merged.ours, merged.theirs), (ours, theirs));
    let commit = f.commit_object(merged.commit);
    assert_eq!(commit.parents, [ours, theirs]);
    sign::verify_commit(&commit).unwrap();
    assert_eq!(
        f.files_of(merged.commit),
        [
            ("a.txt".to_owned(), "resolved\n".to_owned()),
            ("b.txt".to_owned(), "b\n".to_owned())
        ]
    );
    assert_eq!(
        refs::read_ref(&f.layout, "main").unwrap(),
        Some(merged.commit)
    );
    assert!(!is_merge_in_progress(&f.layout));
    assert_eq!(f.read("a.txt"), "resolved\n");
}

#[test]
fn abort_restores_the_branch_and_the_files() {
    let f = init();
    let (ours, _) = diverged(&f);
    start(&f, &merge_request("topic")).unwrap();

    assert_eq!(merge::abort(&f.layout, &f.store).unwrap(), ours);
    assert_eq!(f.read("a.txt"), "ours\n");
    assert_eq!(refs::read_ref(&f.layout, "main").unwrap(), Some(ours));
    assert!(!is_merge_in_progress(&f.layout));
}

#[test]
fn abort_refuses_to_discard_unrelated_staged_work() {
    let f = init();
    diverged(&f);
    start(&f, &merge_request("topic")).unwrap();
    f.write("b.txt", "mine\n");
    f.stage("b.txt");

    let err = merge::abort(&f.layout, &f.store).unwrap_err();
    assert!(
        matches!(err, Error::Conflict(conflict::Error::AbortOverwritesStaged(ref p)) if p == "b.txt"),
        "{err:?}"
    );
    // The refusal happens before any change, so the markers are still there.
    assert!(f.read("a.txt").starts_with("<<<<<<< ours"));
    assert!(is_merge_in_progress(&f.layout));
}

#[test]
fn no_commit_stages_the_merge_and_resume_finishes_it() {
    let f = init();
    let base = f.commit(&[("a.txt", "one\n"), ("b.txt", "one\n")], &[], "base", 1);
    let ours = f.commit(
        &[("a.txt", "ours\n"), ("b.txt", "one\n")],
        &[base],
        "ours",
        2,
    );
    let theirs = f.commit(
        &[("a.txt", "one\n"), ("b.txt", "theirs\n")],
        &[base],
        "theirs",
        3,
    );
    refs::write_ref(&f.layout, "topic", &theirs).unwrap();
    f.checkout("main", ours);

    let request = Request {
        no_commit: true,
        ..merge_request("topic")
    };
    let Outcome::Staged { tree } = start(&f, &request).unwrap() else {
        panic!("expected a staged merge");
    };
    assert_eq!(refs::read_ref(&f.layout, "main").unwrap(), Some(ours));
    assert!(is_merge_in_progress(&f.layout));

    let merged = merge::resume(&f.layout, &f.store, &TestSigning).unwrap();
    assert_eq!(merged.tree, tree);
    assert_eq!(f.commit_object(merged.commit).parents, [ours, theirs]);
}

#[test]
fn no_commit_keeps_a_merge_that_only_deletes_files() {
    let f = init();
    let base = f.commit(&[("a.txt", "one\n"), ("b.txt", "one\n")], &[], "base", 1);
    // `main` changes no file. `topic` deletes both. The merge result is an
    // empty tree, and only removal entries in the index keep that result.
    let ours = f.commit(
        &[("a.txt", "one\n"), ("b.txt", "one\n")],
        &[base],
        "ours",
        2,
    );
    let theirs = f.commit(&[], &[base], "theirs", 3);
    refs::write_ref(&f.layout, "topic", &theirs).unwrap();
    f.checkout("main", ours);

    let request = Request {
        no_commit: true,
        ..merge_request("topic")
    };
    start(&f, &request).unwrap();
    let merged = merge::resume(&f.layout, &f.store, &TestSigning).unwrap();
    assert_eq!(f.files_of(merged.commit), []);
}

#[test]
fn a_target_that_does_not_resolve_is_an_error_and_changes_nothing() {
    let f = init();
    let tip = f.commit(&[("a.txt", "one\n")], &[], "tip", 1);
    f.checkout("main", tip);
    let err = start(&f, &merge_request("nope")).unwrap_err();
    assert!(matches!(err, Error::Target(_)), "{err:?}");
    assert!(err.to_string().starts_with("merge target: "));
    assert_eq!(refs::read_ref(&f.layout, "main").unwrap(), Some(tip));
}

#[test]
fn a_head_without_a_commit_has_nothing_to_merge_into() {
    let f = init();
    let err = start(&f, &merge_request("main")).unwrap_err();
    assert!(matches!(err, Error::NoHeadCommit), "{err:?}");
}

#[test]
fn resume_and_abort_need_a_merge() {
    let f = init();
    let err = merge::resume(&f.layout, &f.store, &TestSigning).unwrap_err();
    assert!(matches!(err, Error::NoMergeInProgress), "{err:?}");
    let err = merge::abort(&f.layout, &f.store).unwrap_err();
    assert_eq!(err.to_string(), "no merge in progress");
}

struct Refusing(ErrorKind);

impl Signing for Refusing {
    fn open(&self, _layout: &RepoLayout) -> Result<Box<dyn Signer>, signing::Error> {
        Err(signing::Error::new(self.0, "no key"))
    }
}

#[test]
fn a_key_that_does_not_load_stops_the_merge_before_the_branch_moves() {
    let f = init();
    let base = f.commit(&[("a.txt", "one\n"), ("b.txt", "one\n")], &[], "base", 1);
    let ours = f.commit(
        &[("a.txt", "ours\n"), ("b.txt", "one\n")],
        &[base],
        "ours",
        2,
    );
    let theirs = f.commit(
        &[("a.txt", "one\n"), ("b.txt", "theirs\n")],
        &[base],
        "theirs",
        3,
    );
    refs::write_ref(&f.layout, "topic", &theirs).unwrap();
    f.checkout("main", ours);

    let err = merge::start(
        &f.layout,
        &f.store,
        &merge_request("topic"),
        &Refusing(ErrorKind::MissingInput),
        &NoopObserver,
    )
    .unwrap_err();
    assert!(
        matches!(&err, Error::Signing(e) if e.kind() == ErrorKind::MissingInput),
        "{err:?}"
    );
    assert_eq!(err.to_string(), "no key");
    assert_eq!(refs::read_ref(&f.layout, "main").unwrap(), Some(ours));
}

#[test]
fn a_fast_forward_loads_no_key() {
    let f = init();
    let base = f.commit(&[("a.txt", "one\n")], &[], "base", 1);
    let ahead = f.commit(&[("a.txt", "two\n")], &[base], "ahead", 2);
    refs::write_ref(&f.layout, "topic", &ahead).unwrap();
    f.checkout("main", base);

    let outcome = merge::start(
        &f.layout,
        &f.store,
        &merge_request("topic"),
        &Refusing(ErrorKind::Failed),
        &NoopObserver,
    )
    .unwrap();
    assert!(matches!(outcome, Outcome::FastForward { .. }));
}
