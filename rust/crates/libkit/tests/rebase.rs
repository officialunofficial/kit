//! Replaying the commits of a branch onto another base, with a pause for
//! conflicts and an editor for the todo list.
#![cfg(feature = "sync")]
#![allow(clippy::unwrap_used)] // unwrap is the assertion in tests

mod common;

use std::cell::RefCell;
use std::io;

use common::{Fixture, TestSigning, init};
use kit_core::hash::{self, Hash};
use kit_core::object::Identity;
use kit_core::observer::NoopObserver;
use kit_core::ops::rebase::is_rebase_in_progress;
use kit_core::refs::{self, Head};
use kit_core::sign;
use libkit::conflict;
use libkit::rebase::{
    self, Editor, Error, Event, MAX_TODO_BYTES, Outcome, RebaseAction, Request, TodoError,
};

/// Replies to the editor in order, and keeps the seeds that it was shown.
#[derive(Default)]
struct Script {
    replies: Vec<String>,
    seeds: Vec<String>,
}

impl Script {
    fn replying(replies: &[&str]) -> Self {
        Self {
            replies: replies.iter().map(ToString::to_string).collect(),
            seeds: Vec::new(),
        }
    }
}

impl Editor for Script {
    fn edit(&mut self, seed: &str) -> io::Result<String> {
        self.seeds.push(seed.to_owned());
        if self.replies.is_empty() {
            return Err(io::Error::other("the editor has no reply"));
        }
        Ok(self.replies.remove(0))
    }
}

#[derive(Default)]
struct Recorder(RefCell<Vec<Event>>);

impl libkit::Observer<Event> for Recorder {
    fn event(&self, event: &Event) {
        self.0.borrow_mut().push(event.clone());
    }
}

/// `main` is `base <- m1`. `topic` is `base <- t1 <- t2 <- t3`, and it is
/// checked out. Every commit adds one file, so no replay conflicts.
struct Linear {
    f: Fixture,
    m1: Hash,
    t: [Hash; 3],
}

fn linear() -> Linear {
    let f = init();
    let base = f.commit(&[("base.txt", "base\n")], &[], "base", 1);
    let m1 = f.commit(
        &[("base.txt", "base\n"), ("main.txt", "main\n")],
        &[base],
        "m1",
        2,
    );
    let t1 = f.commit(
        &[("base.txt", "base\n"), ("t1.txt", "1\n")],
        &[base],
        "t1",
        3,
    );
    let t2 = f.commit(
        &[("base.txt", "base\n"), ("t1.txt", "1\n"), ("t2.txt", "2\n")],
        &[t1],
        "t2",
        4,
    );
    let t3 = f.commit(
        &[
            ("base.txt", "base\n"),
            ("t1.txt", "1\n"),
            ("t2.txt", "2\n"),
            ("t3.txt", "3\n"),
        ],
        &[t2],
        "t3",
        5,
    );
    refs::write_ref(&f.layout, "main", &m1).unwrap();
    f.checkout("topic", t3);
    Linear {
        f,
        m1,
        t: [t1, t2, t3],
    }
}

fn start(
    f: &Fixture,
    onto: &str,
    interactive: bool,
    editor: &mut Script,
) -> Result<Outcome, Error> {
    rebase::start(
        &f.layout,
        &f.store,
        &Request { onto, interactive },
        &TestSigning,
        editor,
        &NoopObserver,
    )
}

fn resume(f: &Fixture, skip: bool, editor: &mut Script) -> Result<Outcome, Error> {
    rebase::resume(
        &f.layout,
        &f.store,
        skip,
        &TestSigning,
        editor,
        &NoopObserver,
    )
}

fn short(h: &Hash) -> String {
    hash::to_hex(h)[..12].to_owned()
}

/// The messages of a commit and its first-parent ancestors, tip first.
fn messages(f: &Fixture, tip: Hash, count: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut at = tip;
    for _ in 0..count {
        let c = f.commit_object(at);
        out.push(String::from_utf8(c.message).unwrap());
        match c.parents.first() {
            Some(p) => at = *p,
            None => break,
        }
    }
    out
}

fn finished(outcome: Outcome) -> (Hash, Hash, usize) {
    match outcome {
        Outcome::Finished {
            old, new, replayed, ..
        } => (old, new, replayed),
        other => panic!("expected a finished rebase: {other:?}"),
    }
}

#[test]
fn a_rebase_replays_signed_copies_that_keep_their_authorship() {
    let l = linear();
    let outcome = start(&l.f, "main", false, &mut Script::default()).unwrap();
    let Outcome::Finished {
        ref branch,
        old,
        new,
        replayed,
    } = outcome
    else {
        panic!("expected a finished rebase: {outcome:?}");
    };
    assert_eq!((branch.as_str(), old, replayed), ("topic", l.t[2], 3));
    assert_eq!(messages(&l.f, new, 5), ["t3", "t2", "t1", "m1", "base"]);
    for (commit, time) in [(new, 5), (l.f.commit_object(new).parents[0], 4)] {
        let c = l.f.commit_object(commit);
        assert_eq!(c.author, Identity::ed25519([9; 32]));
        assert_eq!(c.timestamp, time);
        sign::verify_commit(&c).unwrap();
    }
    assert_eq!(refs::read_ref(&l.f.layout, "topic").unwrap(), Some(new));
    assert_eq!(
        refs::read_head(&l.f.layout).unwrap(),
        Head::Branch("topic".to_owned())
    );
    assert!(!is_rebase_in_progress(&l.f.layout));
    for name in ["main.txt", "t1.txt", "t2.txt", "t3.txt"] {
        assert!(l.f.path(name).exists(), "{name}");
    }
}

#[test]
fn a_branch_at_the_base_is_up_to_date() {
    let l = linear();
    l.f.checkout("main", l.m1);
    let outcome = start(&l.f, "main", false, &mut Script::default()).unwrap();
    assert_eq!(
        outcome,
        Outcome::UpToDate {
            branch: "main".to_owned(),
            head: l.m1
        }
    );
}

#[test]
fn a_branch_behind_the_base_moves_forward() {
    let l = linear();
    let base = l.f.commit_object(l.m1).parents[0];
    l.f.checkout("topic", base);
    let (old, new, replayed) =
        finished(start(&l.f, "main", false, &mut Script::default()).unwrap());
    assert_eq!((old, new, replayed), (base, l.m1, 0));
    assert_eq!(refs::read_ref(&l.f.layout, "topic").unwrap(), Some(l.m1));
}

#[test]
fn a_detached_head_cannot_be_rebased() {
    let l = linear();
    refs::write_head_detached(&l.f.layout, &l.t[2]).unwrap();
    let err = start(&l.f, "main", false, &mut Script::default()).unwrap_err();
    assert!(matches!(err, Error::DetachedHead), "{err:?}");
    assert!(!is_rebase_in_progress(&l.f.layout));
}

#[test]
fn a_base_that_does_not_resolve_is_an_error() {
    let l = linear();
    let err = start(&l.f, "nope", false, &mut Script::default()).unwrap_err();
    assert!(matches!(err, Error::NoSuchCommit { .. }), "{err:?}");
    assert!(err.to_string().starts_with("no such commit: nope ("));
}

/// `main` and `topic` both change `shared.txt`. `topic` has a second commit
/// that adds `t2.txt`.
fn conflicting() -> (Fixture, Hash, [Hash; 2]) {
    let f = init();
    let base = f.commit(&[("shared.txt", "base\n")], &[], "base", 1);
    let m1 = f.commit(&[("shared.txt", "main\n")], &[base], "m1", 2);
    let t1 = f.commit(&[("shared.txt", "topic\n")], &[base], "t1", 3);
    let t2 = f.commit(
        &[("shared.txt", "topic\n"), ("t2.txt", "2\n")],
        &[t1],
        "t2",
        4,
    );
    refs::write_ref(&f.layout, "main", &m1).unwrap();
    f.checkout("topic", t2);
    (f, m1, [t1, t2])
}

#[test]
fn a_conflict_pauses_the_rebase_and_resume_commits_the_resolution() {
    let (f, m1, t) = conflicting();
    let outcome = start(&f, "main", false, &mut Script::default()).unwrap();
    let Outcome::Paused {
        replaying,
        conflicts,
    } = outcome
    else {
        panic!("expected a pause: {outcome:?}");
    };
    assert_eq!(replaying, t[0]);
    assert_eq!(conflicts.len(), 1);
    assert_eq!(conflicts[0].path, "shared.txt");
    assert!(is_rebase_in_progress(&f.layout));
    assert_eq!(refs::resolve_head(&f.layout).unwrap(), Some(m1));

    let err = resume(&f, false, &mut Script::default()).unwrap_err();
    assert!(
        matches!(err, Error::UnresolvedMarkers(ref p) if p == "shared.txt"),
        "{err:?}"
    );

    f.write("shared.txt", "resolved\n");
    let err = resume(&f, false, &mut Script::default()).unwrap_err();
    assert!(
        matches!(err, Error::Conflict(conflict::Error::NotStaged(_))),
        "{err:?}"
    );

    f.stage("shared.txt");
    let (old, new, replayed) = finished(resume(&f, false, &mut Script::default()).unwrap());
    assert_eq!((old, replayed), (t[1], 2));
    assert_eq!(messages(&f, new, 3), ["t2", "t1", "m1"]);
    assert_eq!(
        f.files_of(new),
        [
            ("shared.txt".to_owned(), "resolved\n".to_owned()),
            ("t2.txt".to_owned(), "2\n".to_owned())
        ]
    );
    assert!(!is_rebase_in_progress(&f.layout));
}

#[test]
fn skip_drops_the_paused_commit_and_goes_on() {
    let (f, m1, t) = conflicting();
    start(&f, "main", false, &mut Script::default()).unwrap();

    // `t2` leaves `shared.txt` as it is on `topic`, so its replay onto `main`
    // keeps the text of `main` and adds `t2.txt`.
    let (old, new, replayed) = finished(resume(&f, true, &mut Script::default()).unwrap());
    assert_eq!((old, replayed), (t[1], 1));
    assert_eq!(messages(&f, new, 2), ["t2", "m1"]);
    assert_eq!(f.commit_object(new).parents, [m1]);
    assert_eq!(
        f.files_of(new),
        [
            ("shared.txt".to_owned(), "main\n".to_owned()),
            ("t2.txt".to_owned(), "2\n".to_owned())
        ]
    );
}

#[test]
fn resume_after_a_finished_rebase_has_no_rebase_to_continue() {
    let l = linear();
    start(&l.f, "main", false, &mut Script::default()).unwrap();
    let err = resume(&l.f, true, &mut Script::default()).unwrap_err();
    assert!(matches!(err, Error::NoRebaseInProgress), "{err:?}");
}

#[test]
fn abort_puts_the_branch_and_the_files_back() {
    let (f, _, t) = conflicting();
    start(&f, "main", false, &mut Script::default()).unwrap();

    let aborted = rebase::abort(&f.layout, &f.store).unwrap();
    assert_eq!((aborted.branch.as_str(), aborted.head), ("topic", t[1]));
    assert_eq!(refs::read_ref(&f.layout, "topic").unwrap(), Some(t[1]));
    assert_eq!(
        refs::read_head(&f.layout).unwrap(),
        Head::Branch("topic".to_owned())
    );
    assert_eq!(f.read("shared.txt"), "topic\n");
    assert!(!is_rebase_in_progress(&f.layout));
}

#[test]
fn abort_refuses_to_discard_unrelated_staged_work() {
    let (f, _, _) = conflicting();
    start(&f, "main", false, &mut Script::default()).unwrap();
    f.write("t2.txt", "mine\n");
    f.stage("t2.txt");

    let err = rebase::abort(&f.layout, &f.store).unwrap_err();
    assert!(
        matches!(
            err,
            Error::Conflict(conflict::Error::AbortOverwritesStaged(_))
        ),
        "{err:?}"
    );
    assert!(is_rebase_in_progress(&f.layout));
}

#[test]
fn resume_and_abort_need_a_rebase() {
    let l = linear();
    let err = resume(&l.f, false, &mut Script::default()).unwrap_err();
    assert_eq!(err.to_string(), "no rebase in progress");
    let err = rebase::abort(&l.f.layout, &l.f.store).unwrap_err();
    assert!(matches!(err, Error::NoRebaseInProgress), "{err:?}");
}

#[test]
fn an_interactive_rebase_replays_the_todo_in_its_new_order() {
    let l = linear();
    let reply = format!("pick {}\npick {}\n", short(&l.t[2]), short(&l.t[0]));
    let mut script = Script::replying(&[&reply]);
    let (_, new, replayed) = finished(start(&l.f, "main", true, &mut script).unwrap());
    // `t2` is dropped by its absence from the todo.
    assert_eq!(replayed, 2);
    assert_eq!(messages(&l.f, new, 3), ["t1", "t3", "m1"]);

    let seed = &script.seeds[0];
    assert!(seed.starts_with(&format!("pick {} t1\n", short(&l.t[0]))));
    assert!(seed.contains("# Rebase "));
}

#[test]
fn reword_asks_the_editor_for_a_message_and_an_empty_reply_keeps_the_old_one() {
    let l = linear();
    let todo = format!("reword {}\nreword {}\n", short(&l.t[0]), short(&l.t[1]));
    let mut script = Script::replying(&[&todo, "new words\n", "\n"]);
    let recorder = Recorder::default();
    let outcome = rebase::start(
        &l.f.layout,
        &l.f.store,
        &Request {
            onto: "main",
            interactive: true,
        },
        &TestSigning,
        &mut script,
        &recorder,
    )
    .unwrap();
    let (_, new, _) = finished(outcome);
    assert_eq!(messages(&l.f, new, 3), ["t2", "new words\n", "m1"]);
    assert_eq!(recorder.0.into_inner(), [Event::EmptyReword]);
    assert!(script.seeds[1].starts_with("t1\n# Reword:"));
}

#[test]
fn squash_folds_into_the_previous_commit_with_a_combined_message() {
    let l = linear();
    let todo = format!("pick {}\nsquash {}\n", short(&l.t[0]), short(&l.t[1]));
    let mut script = Script::replying(&[&todo, "combined\n"]);
    let (_, new, replayed) = finished(start(&l.f, "main", true, &mut script).unwrap());
    assert_eq!(replayed, 2);
    assert_eq!(messages(&l.f, new, 2), ["combined\n", "m1"]);
    assert!(script.seeds[1].starts_with("t1\n\nt2\n\n# This is a combination of 2 commits"));
    assert_eq!(l.f.files_of(new).len(), 4);
}

#[test]
fn fixup_keeps_the_message_of_the_previous_commit_and_opens_no_editor() {
    let l = linear();
    let todo = format!("pick {}\nfixup {}\n", short(&l.t[0]), short(&l.t[1]));
    let mut script = Script::replying(&[&todo]);
    let (_, new, _) = finished(start(&l.f, "main", true, &mut script).unwrap());
    assert_eq!(messages(&l.f, new, 2), ["t1", "m1"]);
    assert_eq!(script.seeds.len(), 1);
}

#[test]
fn an_empty_todo_resets_the_branch_to_the_base() {
    let l = linear();
    let mut script = Script::replying(&["# nothing\n"]);
    let (_, new, replayed) = finished(start(&l.f, "main", true, &mut script).unwrap());
    assert_eq!((new, replayed), (l.m1, 0));
}

#[test]
fn a_bad_todo_stops_the_rebase_before_any_change() {
    let l = linear();
    let mut script = Script::replying(&["explode abc\n"]);
    let err = start(&l.f, "main", true, &mut script).unwrap_err();
    assert!(
        matches!(err, Error::Todo(TodoError::UnknownCommand(_))),
        "{err:?}"
    );
    assert!(!is_rebase_in_progress(&l.f.layout));
    assert_eq!(refs::read_ref(&l.f.layout, "topic").unwrap(), Some(l.t[2]));
    assert_eq!(
        refs::read_head(&l.f.layout).unwrap(),
        Head::Branch("topic".to_owned())
    );
}

#[test]
fn an_editor_that_fails_stops_the_rebase_before_any_change() {
    let l = linear();
    let err = start(&l.f, "main", true, &mut Script::default()).unwrap_err();
    assert!(matches!(err, Error::Editor(_)), "{err:?}");
    assert_eq!(err.to_string(), "editor: the editor has no reply");
    assert!(!is_rebase_in_progress(&l.f.layout));
}

#[test]
fn a_skip_that_leaves_a_fold_first_fails_before_any_change() {
    let (f, m1, t) = conflicting();
    let todo = format!("pick {}\nsquash {}\n", short(&t[0]), short(&t[1]));
    let mut script = Script::replying(&[&todo]);
    let outcome = start(&f, "main", true, &mut script).unwrap();
    assert!(matches!(outcome, Outcome::Paused { .. }), "{outcome:?}");

    let err = resume(&f, true, &mut Script::default()).unwrap_err();
    assert!(
        matches!(err, Error::Todo(TodoError::NothingToFoldInto(ref v)) if v == "squash"),
        "{err:?}"
    );
    // The state stays, so an abort still works.
    assert_eq!(refs::resolve_head(&f.layout).unwrap(), Some(m1));
    rebase::abort(&f.layout, &f.store).unwrap();
    assert_eq!(refs::read_ref(&f.layout, "topic").unwrap(), Some(t[1]));
}

fn candidates() -> [Hash; 3] {
    [hash::hash(b"one"), hash::hash(b"two"), hash::hash(b"three")]
}

#[test]
fn the_todo_parser_reads_every_verb_and_a_prefix() {
    let c = candidates();
    let text = format!(
        "# comment\n\n p {}\nr {}\n  squash   {}  extra words\nf {}\nd {}\n",
        short(&c[0]),
        short(&c[1]),
        hash::to_hex(&c[2]),
        hash::to_hex(&c[2])[..8].to_uppercase(),
        short(&c[1]),
    );
    let (todo, actions) = rebase::parse_todo(&c, &text).unwrap();
    assert_eq!(todo, [c[0], c[1], c[2], c[2]]);
    assert_eq!(
        actions,
        [
            RebaseAction::Pick,
            RebaseAction::Reword,
            RebaseAction::Squash,
            RebaseAction::Fixup
        ]
    );
}

#[test]
fn the_todo_parser_refuses_a_bad_line() {
    let c = candidates();
    let first = short(&c[0]);
    let cases: [(String, TodoError); 6] = [
        (format!("edit {first}\n"), TodoError::EditUnsupported),
        (
            format!("boom {first}\n"),
            TodoError::UnknownCommand("boom".to_owned()),
        ),
        (
            format!("s {first}\n"),
            TodoError::NothingToFoldInto("s".to_owned()),
        ),
        (
            "pick\n".to_owned(),
            TodoError::MissingCommit("pick".to_owned()),
        ),
        (
            "pick ffffffffffff\n".to_owned(),
            TodoError::UnknownCommit("pick ffffffffffff".to_owned()),
        ),
        (
            "drop ffffffffffff\n".to_owned(),
            TodoError::UnknownCommit("drop ffffffffffff".to_owned()),
        ),
    ];
    for (text, expected) in cases {
        assert_eq!(
            rebase::parse_todo(&c, &text).unwrap_err(),
            expected,
            "{text}"
        );
    }
}

#[test]
fn the_todo_parser_refuses_an_ambiguous_prefix() {
    // Find a one-character prefix that two of many candidates share.
    let many: Vec<Hash> = (0u32..64).map(|i| hash::hash(&i.to_le_bytes())).collect();
    let first = hash::to_hex(&many[0]).chars().next().unwrap().to_string();
    let err = rebase::parse_todo(&many, &format!("pick {first}\n")).unwrap_err();
    assert!(matches!(err, TodoError::AmbiguousCommit { .. }), "{err:?}");
}

#[test]
fn the_todo_parser_bounds_its_input() {
    let c = candidates();
    let text = "#".repeat(MAX_TODO_BYTES + 1);
    assert_eq!(
        rebase::parse_todo(&c, &text).unwrap_err(),
        TodoError::TooLong
    );
    let text = "#".repeat(MAX_TODO_BYTES);
    assert!(rebase::parse_todo(&c, &text).unwrap().0.is_empty());
}
