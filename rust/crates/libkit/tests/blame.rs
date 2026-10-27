//! Line attribution through an open `Repo`.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in tests

use std::fs;

use kit_core::hash::{self, Hash};
use kit_core::layout::RepoLayout;
use kit_core::object::{Blob, Commit, EntryMode, Identity, Object, Tree, TreeEntry};
use kit_core::ops::blame::BlameError;
use kit_core::refs;
use kit_core::serialize;
use kit_core::store::ObjectStore;
use libkit::blame::{self, CopyDetection, MoveDetection, Request, line_range};
use libkit::{Environment, Error, Repo};

/// Two commits of one file.
///
/// - `first` has `f.txt` with the lines `a`, `b` and `c`. The ref `old`
///   names it.
/// - `second` has `f.txt` with the lines `a`, `B`, `c` and `d`. The ref
///   `main` names it.
struct Fixture {
    dir: tempfile::TempDir,
    repo: Repo,
    first: Hash,
    second: Hash,
}

fn write_commit(store: &ObjectStore, data: &str, parents: Vec<Hash>, time: u64) -> Hash {
    let blob = Object::Blob(Blob {
        data: data.as_bytes().to_vec(),
    });
    let blob = store.write(&serialize::serialize(&blob).unwrap()).unwrap();
    let tree = Object::Tree(Tree {
        entries: vec![TreeEntry {
            name: b"f.txt".to_vec(),
            mode: EntryMode::Blob,
            object_hash: blob,
        }],
    });
    let tree = store.write(&serialize::serialize(&tree).unwrap()).unwrap();
    let commit = Commit::new_unannotated(
        tree,
        parents,
        Identity::ed25519([1; 32]),
        [1; 32],
        b"m".to_vec(),
        time,
        [0; 64],
    );
    store
        .write(&serialize::serialize(&Object::Commit(commit)).unwrap())
        .unwrap()
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let layout = RepoLayout::single(dir.path());
    let store = ObjectStore::init(&layout).unwrap();
    refs::init(&layout).unwrap();
    let first = write_commit(&store, "a\nb\nc\n", vec![], 1);
    let second = write_commit(&store, "a\nB\nc\nd\n", vec![first], 2);
    refs::write_ref(&layout, "old", &first).unwrap();
    refs::write_ref(&layout, "main", &second).unwrap();
    let repo = Repo::open(dir.path(), &Environment::new(dir.path())).unwrap();
    Fixture {
        dir,
        repo,
        first,
        second,
    }
}

/// A request for `f.txt` with every other field off.
fn request(revision: Option<&str>) -> Request<'_> {
    Request {
        file: "f.txt",
        revision,
        reverse: false,
        ignore_whitespace: false,
        moves: MoveDetection::Off,
        copies: CopyDetection::Off,
        ignore_revs: &[],
        ignore_revs_files: &[],
        ignore_rev_precise: false,
        first_parent: false,
        lines: None,
    }
}

/// The commits and the line numbers of a result.
fn summary(result: &blame::BlameResult) -> Vec<(usize, Hash)> {
    result
        .lines
        .iter()
        .map(|l| (l.line_num, l.commit_hash))
        .collect()
}

#[test]
fn blames_head_by_default() {
    let f = fixture();
    let result = blame::blame(&f.repo, &request(None)).unwrap();
    assert_eq!(
        summary(&result),
        vec![(1, f.first), (2, f.second), (3, f.first), (4, f.second)]
    );
}

#[test]
fn blames_an_older_revision() {
    let f = fixture();
    let result = blame::blame(&f.repo, &request(Some("old"))).unwrap();
    assert_eq!(
        summary(&result),
        vec![(1, f.first), (2, f.first), (3, f.first)]
    );
}

#[test]
fn a_range_of_lines_keeps_the_numbers_of_the_file() {
    let f = fixture();
    let mut r = request(None);
    r.lines = Some("2,3");
    let result = blame::blame(&f.repo, &r).unwrap();
    assert_eq!(summary(&result), vec![(2, f.second), (3, f.first)]);

    r.lines = Some("4,-2");
    let result = blame::blame(&f.repo, &r).unwrap();
    assert_eq!(summary(&result), vec![(3, f.first), (4, f.second)]);
}

#[test]
fn a_range_of_lines_past_the_end_is_an_error() {
    let f = fixture();
    let mut r = request(None);
    r.lines = Some("9,10");
    let error = blame::blame(&f.repo, &r).unwrap_err();
    assert!(matches!(
        error,
        blame::Error::Lines(line_range::Error::PastEnd { total: 4, .. })
    ));
    assert_eq!(error.to_string(), "file f.txt has only 4 lines");
}

#[test]
fn a_bad_range_of_lines_is_an_error() {
    let f = fixture();
    let mut r = request(None);
    r.lines = Some("0,2");
    let error = blame::blame(&f.repo, &r).unwrap_err();
    assert_eq!(error.to_string(), "-L invalid line number: 0");
}

#[test]
fn a_missing_file_is_an_error() {
    let f = fixture();
    let mut r = request(None);
    r.file = "nope.txt";
    assert!(matches!(
        blame::blame(&f.repo, &r),
        Err(blame::Error::Blame(BlameError::FileNotFound(_)))
    ));
}

#[test]
fn an_unknown_revision_is_an_error() {
    let f = fixture();
    assert!(matches!(
        blame::blame(&f.repo, &request(Some("nope"))),
        Err(blame::Error::Revision(_))
    ));
}

#[test]
fn a_repository_without_a_commit_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let layout = RepoLayout::single(dir.path());
    ObjectStore::init(&layout).unwrap();
    refs::init(&layout).unwrap();
    let repo = Repo::open(dir.path(), &Environment::new(dir.path())).unwrap();
    let error = blame::blame(&repo, &request(None)).unwrap_err();
    assert!(matches!(error, blame::Error::HeadWithoutCommit));
    assert_eq!(error.to_string(), "no commits yet");
}

#[test]
fn the_error_converts_into_the_library_error() {
    let error = Error::from(blame::Error::ReverseNeedsStart);
    assert!(matches!(
        error,
        Error::Blame(blame::Error::ReverseNeedsStart)
    ));
}

#[test]
fn reverse_gives_each_line_the_last_commit_that_had_it() {
    let f = fixture();
    let mut r = request(Some("old..main"));
    r.reverse = true;
    let result = blame::blame(&f.repo, &r).unwrap();
    // The lines of `first`. `a` and `c` live on in `second`. `b` does not.
    assert_eq!(
        summary(&result),
        vec![(1, f.second), (2, f.first), (3, f.second)]
    );
}

#[test]
fn reverse_with_an_empty_end_walks_to_head() {
    let f = fixture();
    let mut r = request(Some("old.."));
    r.reverse = true;
    let result = blame::blame(&f.repo, &r).unwrap();
    assert_eq!(
        summary(&result),
        vec![(1, f.second), (2, f.first), (3, f.second)]
    );
}

#[test]
fn reverse_rejects_a_bad_range() {
    let f = fixture();
    let cases: [(Option<&str>, &str); 5] = [
        (
            Some("old"),
            "--reverse requires a <start>..<end> range, got 'old'",
        ),
        (
            Some("old..main..old"),
            "--reverse requires a single <start>..<end> range, got 'old..main..old'",
        ),
        (
            Some("old...main"),
            "--reverse requires a single <start>..<end> range, got 'old...main'",
        ),
        (
            Some("..main"),
            "--reverse requires an explicit <start> revision",
        ),
        (
            Some("main..main"),
            "--reverse: empty revision range 'main..main'",
        ),
    ];
    for (revision, message) in cases {
        let mut r = request(revision);
        r.reverse = true;
        let error = blame::blame(&f.repo, &r).unwrap_err();
        assert_eq!(error.to_string(), message, "revision {revision:?}");
    }
}

#[test]
fn reverse_without_a_revision_is_an_error() {
    let f = fixture();
    let mut r = request(None);
    r.reverse = true;
    assert!(matches!(
        blame::blame(&f.repo, &r),
        Err(blame::Error::ReverseNeedsRange)
    ));
    r.file = "old..main";
    assert!(matches!(
        blame::blame(&f.repo, &r),
        Err(blame::Error::ReverseMissingFile(_))
    ));
}

#[test]
fn reverse_cannot_detect_moves_copies_or_skip_commits() {
    let f = fixture();
    let ignore = vec!["main".to_owned()];
    let mut moves = request(Some("old..main"));
    moves.reverse = true;
    moves.moves = MoveDetection::GIT_DEFAULT;
    let mut copies = moves;
    copies.moves = MoveDetection::Off;
    copies.copies = CopyDetection::git_default(1);
    let mut skips = request(Some("old..main"));
    skips.reverse = true;
    skips.ignore_revs = &ignore;
    for r in [moves, copies, skips] {
        assert!(matches!(
            blame::blame(&f.repo, &r),
            Err(blame::Error::ReverseWithDetection)
        ));
    }
}

#[test]
fn precise_matching_needs_a_commit_to_skip() {
    let f = fixture();
    let mut r = request(None);
    r.ignore_rev_precise = true;
    assert!(matches!(
        blame::blame(&f.repo, &r),
        Err(blame::Error::PreciseWithoutIgnore)
    ));
}

#[test]
fn a_skipped_commit_gives_its_lines_to_the_commit_before() {
    let f = fixture();
    let ignore = vec!["main".to_owned()];
    let mut r = request(None);
    r.ignore_revs = &ignore;
    let result = blame::blame(&f.repo, &r).unwrap();
    // `B` replaces `b`, so it falls through. `d` has no earlier line.
    assert_eq!(
        summary(&result),
        vec![(1, f.first), (2, f.first), (3, f.first), (4, f.second)]
    );
}

#[test]
fn a_skipped_revision_that_does_not_resolve_is_an_error() {
    let f = fixture();
    let ignore = vec!["nope".to_owned()];
    let mut r = request(None);
    r.ignore_revs = &ignore;
    let error = blame::blame(&f.repo, &r).unwrap_err();
    assert_eq!(error.to_string(), "cannot find revision nope to ignore");
}

#[test]
fn a_file_of_commit_names_skips_commits() {
    let f = fixture();
    let path = f.dir.path().join("ignore-revs");
    fs::write(
        &path,
        format!("# noise\n\n{}  # the edit\r\n", hash::to_hex(&f.second)),
    )
    .unwrap();
    let files = vec![path.to_str().unwrap().to_owned()];
    let mut r = request(None);
    r.ignore_revs_files = &files;
    let result = blame::blame(&f.repo, &r).unwrap();
    assert_eq!(result.lines[1].commit_hash, f.first);
    assert_eq!(result.lines[3].commit_hash, f.second);
}

#[test]
fn a_file_of_commit_names_rejects_a_short_name() {
    let f = fixture();
    let path = f.dir.path().join("ignore-revs");
    fs::write(&path, &hash::to_hex(&f.second)[..12]).unwrap();
    let files = vec![path.to_str().unwrap().to_owned()];
    let mut r = request(None);
    r.ignore_revs_files = &files;
    let error = blame::blame(&f.repo, &r).unwrap_err();
    assert!(matches!(error, blame::Error::InvalidObjectName(_)));
}

#[test]
fn a_missing_file_of_commit_names_is_an_error() {
    let f = fixture();
    let files = vec![f.dir.path().join("absent").to_str().unwrap().to_owned()];
    let mut r = request(None);
    r.ignore_revs_files = &files;
    assert!(matches!(
        blame::blame(&f.repo, &r),
        Err(blame::Error::IgnoreFileUnreadable(_))
    ));
}

#[test]
fn a_file_of_commit_names_that_is_not_text_is_an_error() {
    let f = fixture();
    let path = f.dir.path().join("ignore-revs");
    fs::write(&path, [0xff, 0xfe, b'\n']).unwrap();
    let files = vec![path.to_str().unwrap().to_owned()];
    let mut r = request(None);
    r.ignore_revs_files = &files;
    assert!(matches!(
        blame::blame(&f.repo, &r),
        Err(blame::Error::IgnoreFileUnreadable(_))
    ));
}

#[test]
fn a_file_of_commit_names_over_the_limit_is_an_error() {
    let f = fixture();
    let path = f.dir.path().join("ignore-revs");
    // A sparse file: it holds no data on disk until it is read.
    let file = fs::File::create(&path).unwrap();
    file.set_len(16 * 1024 * 1024 + 1).unwrap();
    let files = vec![path.to_str().unwrap().to_owned()];
    let mut r = request(None);
    r.ignore_revs_files = &files;
    assert!(matches!(
        blame::blame(&f.repo, &r),
        Err(blame::Error::IgnoreFileTooLong { .. })
    ));
}
