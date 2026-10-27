//! Move tracked files and directories, and stage the change.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in tests

use std::fs;
use std::path::PathBuf;

use kit_core::hash::{Hash, ZERO};
use kit_core::index::{self, EntryStatus, Index, IndexEntry};
use kit_core::layout::RepoLayout;
use kit_core::object::{Blob, Object};
use kit_core::refs;
use kit_core::serialize;
use kit_core::store::ObjectStore;
use libkit::NoopObserver;
use libkit::mv::{self, Error, SourceFault};

struct Fixture {
    _dir: tempfile::TempDir,
    root: PathBuf,
    layout: RepoLayout,
    store: ObjectStore,
}

impl Fixture {
    /// A repository whose index tracks `files`. The tree holds the files.
    fn new(files: &[(&str, &str)]) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let layout = RepoLayout::single(&root);
        let store = ObjectStore::init(&layout).unwrap();
        refs::init(&layout).unwrap();
        let mut idx = Index::new();
        for (path, content) in files {
            let full = root.join(path);
            fs::create_dir_all(full.parent().unwrap()).unwrap();
            fs::write(&full, content).unwrap();
            idx.upsert_entry(IndexEntry {
                path: (*path).to_owned(),
                status: EntryStatus::Blob,
                object_hash: blob(&store, content),
                mtime_ns: 0,
                size: 0,
                ino: 0,
                ctime_ns: 0,
            });
        }
        index::write_index(&layout, &idx).unwrap();
        Self {
            _dir: dir,
            root,
            layout,
            store,
        }
    }

    fn mv(&self, sources: &[&str], dest: &str, force: bool) -> Result<(), Error> {
        let sources: Vec<String> = sources.iter().map(|s| (*s).to_owned()).collect();
        mv::mv(
            &self.layout,
            &self.root,
            &sources,
            dest,
            force,
            &NoopObserver,
        )
    }

    /// The staged state of `path`: its status and hash, or `None` when the
    /// index has no live entry.
    fn staged(&self, path: &str) -> Option<(EntryStatus, Hash)> {
        let idx = index::read_index(&self.layout).unwrap();
        let entry = &idx.entries[idx.find_entry(path)?];
        (entry.status != EntryStatus::Removed).then_some((entry.status, entry.object_hash))
    }

    fn read(&self, path: &str) -> String {
        fs::read_to_string(self.root.join(path)).unwrap()
    }

    fn exists(&self, path: &str) -> bool {
        self.root.join(path).symlink_metadata().is_ok()
    }
}

fn blob(store: &ObjectStore, content: &str) -> Hash {
    let object = Object::Blob(Blob {
        data: content.as_bytes().to_vec(),
    });
    store
        .write(&serialize::serialize(&object).unwrap())
        .unwrap()
}

#[test]
fn a_rename_moves_the_file_and_stages_its_blob_at_the_new_path() {
    let f = Fixture::new(&[("a.txt", "one\n")]);
    let hash = blob(&f.store, "one\n");
    f.mv(&["a.txt"], "b.txt", false).unwrap();
    assert!(!f.exists("a.txt"));
    assert_eq!(f.read("b.txt"), "one\n");
    assert_eq!(f.staged("a.txt"), None);
    assert_eq!(f.staged("b.txt"), Some((EntryStatus::Blob, hash)));
    let idx = index::read_index(&f.layout).unwrap();
    let old = &idx.entries[idx.find_entry("a.txt").unwrap()];
    assert_eq!(old.object_hash, ZERO);
}

#[test]
fn several_sources_move_into_a_directory() {
    let f = Fixture::new(&[("a.txt", "a"), ("b.txt", "b"), ("d/keep", "k")]);
    f.mv(&["a.txt", "b.txt"], "d", false).unwrap();
    assert_eq!(f.read("d/a.txt"), "a");
    assert_eq!(f.read("d/b.txt"), "b");
    assert!(f.staged("d/a.txt").is_some() && f.staged("d/b.txt").is_some());
    assert!(f.staged("a.txt").is_none() && f.staged("b.txt").is_none());
    assert!(f.staged("d/keep").is_some());
}

#[test]
fn one_source_moves_into_an_existing_directory() {
    let f = Fixture::new(&[("a.txt", "a"), ("d/keep", "k")]);
    f.mv(&["a.txt"], "d", false).unwrap();
    assert_eq!(f.read("d/a.txt"), "a");
    assert!(f.staged("d/a.txt").is_some());
}

#[test]
fn a_directory_moves_with_its_untracked_files() {
    let f = Fixture::new(&[("src/a.txt", "a"), ("src/sub/b.txt", "b")]);
    fs::write(f.root.join("src/untracked"), "u").unwrap();
    f.mv(&["src"], "dst", false).unwrap();
    assert!(!f.exists("src"));
    assert_eq!(f.read("dst/untracked"), "u");
    assert!(f.staged("dst/a.txt").is_some());
    assert!(f.staged("dst/sub/b.txt").is_some());
    assert!(f.staged("src/a.txt").is_none());
    assert!(f.staged("src/sub/b.txt").is_none());
}

#[test]
fn a_destination_in_use_needs_force_and_force_replaces_a_file() {
    let f = Fixture::new(&[("a.txt", "a"), ("b.txt", "b")]);
    let err = f.mv(&["a.txt"], "b.txt", false).unwrap_err();
    assert!(
        matches!(err, Error::DestinationExists(ref p) if p == "b.txt"),
        "{err:?}"
    );
    assert_eq!(
        err.to_string(),
        "destination exists (use -f to overwrite): b.txt"
    );
    assert_eq!(f.read("a.txt"), "a");
    assert_eq!(f.read("b.txt"), "b");

    f.mv(&["a.txt"], "b.txt", true).unwrap();
    assert!(!f.exists("a.txt"));
    assert_eq!(f.read("b.txt"), "a");
    assert_eq!(f.staged("b.txt").unwrap().1, blob(&f.store, "a"));
}

#[test]
fn a_directory_never_overwrites_a_path_even_with_force() {
    let f = Fixture::new(&[("d/x", "x"), ("e/d/y", "y")]);
    let err = f.mv(&["d"], "e", true).unwrap_err();
    assert!(
        matches!(err, Error::DirectoryDestinationExists(ref p) if p == "e/d"),
        "{err:?}"
    );
    assert_eq!(
        err.to_string(),
        "destination already exists: e/d (refusing to overwrite it — -f does not clobber a directory)"
    );
    assert_eq!(f.read("d/x"), "x");
    assert_eq!(f.read("e/d/y"), "y");
}

#[test]
fn a_file_cannot_replace_a_directory_even_with_force() {
    let f = Fixture::new(&[("z", "z"), ("d/keep", "k")]);
    // `z` goes into `d`, where an untracked directory has its name.
    fs::create_dir(f.root.join("d/z")).unwrap();
    let err = f.mv(&["z"], "d", true).unwrap_err();
    assert!(
        matches!(err, Error::DestinationIsDirectory(ref p) if p == "d/z"),
        "{err:?}"
    );
    assert!(f.exists("z"));
}

#[test]
fn a_source_that_is_not_tracked_is_refused() {
    let f = Fixture::new(&[("a.txt", "a")]);
    fs::write(f.root.join("loose"), "l").unwrap();
    let err = f.mv(&["loose"], "x", false).unwrap_err();
    assert!(
        matches!(err, Error::NotTracked(ref p) if p == "loose"),
        "{err:?}"
    );
    assert_eq!(err.to_string(), "not under version control: loose");
    assert!(f.exists("loose"));
}

#[test]
fn a_source_that_is_gone_from_the_tree_is_refused() {
    let f = Fixture::new(&[("a.txt", "a")]);
    fs::remove_file(f.root.join("a.txt")).unwrap();
    let err = f.mv(&["a.txt"], "b.txt", false).unwrap_err();
    assert!(
        matches!(
            err,
            Error::BadSource {
                fault: SourceFault::Missing,
                ..
            }
        ),
        "{err:?}"
    );
    assert_eq!(err.to_string(), "bad source: a.txt");
}

#[test]
fn a_source_and_a_destination_that_are_the_same_are_refused() {
    let f = Fixture::new(&[("a.txt", "a")]);
    let err = f.mv(&["a.txt"], "./a.txt", false).unwrap_err();
    assert!(matches!(err, Error::SameSourceAndDestination(_)), "{err:?}");
}

#[test]
fn a_directory_does_not_move_into_itself() {
    let f = Fixture::new(&[("d/x", "x")]);
    let err = f.mv(&["d"], "d/inner", false).unwrap_err();
    assert!(
        matches!(err, Error::MoveIntoItself(ref p) if p == "d"),
        "{err:?}"
    );
    assert_eq!(err.to_string(), "cannot move 'd' into itself");
}

#[test]
fn several_sources_need_a_directory_that_exists() {
    let f = Fixture::new(&[("a.txt", "a"), ("b.txt", "b")]);
    let err = f.mv(&["a.txt", "b.txt"], "nope", false).unwrap_err();
    assert!(
        matches!(err, Error::DestinationNotDirectory(ref p) if p == "nope"),
        "{err:?}"
    );
}

#[test]
fn a_path_that_leaves_the_repository_is_refused() {
    let f = Fixture::new(&[("a.txt", "a")]);
    let err = f.mv(&["a.txt"], "../out", false).unwrap_err();
    assert!(matches!(err, Error::Path(_)), "{err:?}");
    assert_eq!(err.to_string(), "invalid path: ../out");
}

#[test]
fn a_bad_batch_changes_neither_the_tree_nor_the_index() {
    let f = Fixture::new(&[("a.txt", "a"), ("d/keep", "k")]);
    let before = fs::read(f.layout.index_file()).unwrap();
    let err = f.mv(&["a.txt", "missing"], "d", false).unwrap_err();
    assert!(matches!(err, Error::NotTracked(_)), "{err:?}");
    assert_eq!(f.read("a.txt"), "a");
    assert_eq!(fs::read(f.layout.index_file()).unwrap(), before);
}

#[test]
fn two_sources_may_not_land_on_one_path() {
    let f = Fixture::new(&[("x/n", "1"), ("y/n", "2"), ("d/keep", "k")]);
    let err = f.mv(&["x/n", "y/n"], "d", false).unwrap_err();
    assert!(
        matches!(err, Error::SameDestination(ref p) if p == "d/n"),
        "{err:?}"
    );
    assert!(f.exists("x/n") && f.exists("y/n"));
}

#[test]
fn two_directories_may_not_land_on_one_root() {
    let f = Fixture::new(&[("x/dir/a", "1"), ("y/dir/b", "2"), ("d/keep", "k")]);
    let err = f.mv(&["x/dir", "y/dir"], "d", false).unwrap_err();
    assert!(
        matches!(err, Error::SameDirectoryDestination(ref p) if p == "d/dir"),
        "{err:?}"
    );
    assert!(f.exists("x/dir/a") && f.exists("y/dir/b"));
}

#[test]
fn a_source_may_not_appear_twice_or_inside_another() {
    let f = Fixture::new(&[("d/x", "x"), ("e/keep", "k")]);
    let err = f.mv(&["d", "d"], "e", false).unwrap_err();
    assert!(
        matches!(err, Error::DuplicateSource(ref p) if p == "d"),
        "{err:?}"
    );
    let err = f.mv(&["d", "d/x"], "e", false).unwrap_err();
    assert!(
        matches!(err, Error::OverlappingSources { ref outer, ref inner } if outer == "d" && inner == "d/x"),
        "{err:?}"
    );
    assert!(f.exists("d/x"));
}

#[test]
fn a_destination_below_a_tracked_file_is_refused() {
    let f = Fixture::new(&[("a.txt", "a"), ("b", "b")]);
    fs::remove_file(f.root.join("b")).unwrap();
    fs::create_dir(f.root.join("b")).unwrap();
    let err = f.mv(&["a.txt"], "b", false).unwrap_err();
    // `b` is a directory in the tree, so `a.txt` goes into it. The index
    // tracks `b` as a file, and `b/a.txt` would sit below it.
    assert!(
        matches!(err, Error::DestinationUnderFile(ref p) if p == "b"),
        "{err:?}"
    );
    assert_eq!(f.read("a.txt"), "a");
}

#[cfg(unix)]
#[test]
fn a_symlink_above_the_destination_is_refused() {
    use std::os::unix::fs::symlink;

    let f = Fixture::new(&[("a.txt", "a"), ("real/keep", "k")]);
    let outside = tempfile::tempdir().unwrap();
    symlink(outside.path(), f.root.join("out")).unwrap();
    let err = f.mv(&["a.txt"], "out/a.txt", false).unwrap_err();
    assert!(matches!(err, Error::DestinationEscapes(_)), "{err:?}");
    assert!(!outside.path().join("a.txt").exists());

    symlink(f.root.join("real"), f.root.join("link")).unwrap();
    let err = f.mv(&["a.txt"], "link/a.txt", false).unwrap_err();
    assert!(
        matches!(err, Error::DestinationSymlink(ref p) if p == "link/a.txt"),
        "{err:?}"
    );
    assert_eq!(f.read("a.txt"), "a");
}

#[cfg(unix)]
#[test]
fn a_source_behind_a_symlink_is_refused() {
    use std::os::unix::fs::symlink;

    let f = Fixture::new(&[("real/a.txt", "a")]);
    symlink(f.root.join("real"), f.root.join("link")).unwrap();
    let mut idx = index::read_index(&f.layout).unwrap();
    idx.upsert_entry(IndexEntry {
        path: "link/a.txt".to_owned(),
        status: EntryStatus::Blob,
        object_hash: blob(&f.store, "a"),
        mtime_ns: 0,
        size: 0,
        ino: 0,
        ctime_ns: 0,
    });
    index::write_index(&f.layout, &idx).unwrap();
    let err = f.mv(&["link/a.txt"], "moved", false).unwrap_err();
    assert!(
        matches!(
            err,
            Error::BadSource {
                fault: SourceFault::SymlinkAncestor,
                ..
            }
        ),
        "{err:?}"
    );
    assert_eq!(
        err.to_string(),
        "bad source: link/a.txt (path traverses a symlink)"
    );
}

#[test]
fn a_repository_without_a_store_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let layout = RepoLayout::single(&root);
    let err = mv::mv(&layout, &root, &["a".to_owned()], "b", false, &NoopObserver).unwrap_err();
    assert!(matches!(err, Error::NotARepository(_)), "{err:?}");
    assert!(err.to_string().starts_with("not a kit repo: "));
}
