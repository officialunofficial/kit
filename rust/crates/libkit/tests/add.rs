//! Stage files into the index.
#![cfg(feature = "sync")]
#![allow(clippy::unwrap_used)] // unwrap is the assertion in tests

use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::Mutex;

use kit_core::hash::Hash;
use kit_core::index::{self, EntryStatus, Index, IndexEntry};
use kit_core::layout::RepoLayout;
use kit_core::object::{Blob, Object};
use kit_core::observer::Observer;
use kit_core::refs;
use kit_core::serialize;
use kit_core::store::ObjectStore;
use libkit::add::{self, Choice, Error, Event, HunkChooser, PatchHunk, Request};
use libkit::repo::StoreConfig;
use libkit::{Environment, NoopObserver};

struct Fixture {
    _dir: tempfile::TempDir,
    root: PathBuf,
    layout: RepoLayout,
    store: ObjectStore,
}

/// A chooser that fails the test when it is asked to choose.
struct NoChooser;

impl HunkChooser for NoChooser {
    fn choose(&mut self, path: &str, _hunks: &[PatchHunk]) -> io::Result<Choice> {
        panic!("the chooser must not run for {path}");
    }
}

/// Takes the hunks of a list, and records how many hunks it was offered.
struct Picks {
    selected: Vec<usize>,
    offered: Vec<usize>,
}

impl HunkChooser for Picks {
    fn choose(&mut self, _path: &str, hunks: &[PatchHunk]) -> io::Result<Choice> {
        self.offered.push(hunks.len());
        Ok(Choice {
            selected: self.selected.clone(),
            quit: false,
        })
    }
}

#[derive(Default)]
struct Events(Mutex<Vec<Event>>);

impl Observer<Event> for Events {
    fn event(&self, event: &Event) {
        self.0.lock().unwrap().push(event.clone());
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

impl Fixture {
    /// A repository with no commit. The index tracks `tracked`, and the tree
    /// holds `tracked` and `loose`.
    fn new(tracked: &[(&str, &str)], loose: &[(&str, &str)]) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let layout = RepoLayout::single(&root);
        let store = ObjectStore::init(&layout).unwrap();
        refs::init(&layout).unwrap();
        refs::write_head_branch(&layout, "main").unwrap();
        let mut idx = Index::new();
        for (path, content) in tracked {
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
        for (path, content) in tracked.iter().chain(loose) {
            let full = root.join(path);
            fs::create_dir_all(full.parent().unwrap()).unwrap();
            fs::write(full, content).unwrap();
        }
        Self {
            _dir: dir,
            root,
            layout,
            store,
        }
    }

    fn run(&self, request: &Request<'_>) -> Result<(), Error> {
        self.run_with(request, &mut NoChooser, &NoopObserver)
    }

    fn run_with(
        &self,
        request: &Request<'_>,
        chooser: &mut dyn HunkChooser,
        observer: &dyn Observer<Event>,
    ) -> Result<(), Error> {
        let environment = Environment {
            cwd: self.root.clone(),
            ..Environment::default()
        };
        add::stage(
            &self.layout,
            &StoreConfig {
                environment: &environment,
                observer: &NoopObserver,
            },
            &self.root,
            request,
            chooser,
            &NoopObserver,
            observer,
        )
    }

    fn paths(&self, paths: &[&str]) -> Result<(), Error> {
        let paths: Vec<String> = paths.iter().map(|p| (*p).to_owned()).collect();
        self.run(&Request {
            all: false,
            update: false,
            patch: false,
            force: false,
            dry_run: false,
            paths: &paths,
        })
    }

    /// The content that the index holds for `path`, or `None` when it has no
    /// live entry.
    fn staged(&self, path: &str) -> Option<String> {
        let idx = index::read_index(&self.layout).unwrap();
        let entry = &idx.entries[idx.find_entry(path)?];
        if entry.status == EntryStatus::Removed {
            return None;
        }
        match self.store.read_object(&entry.object_hash).unwrap() {
            Object::Blob(b) => Some(String::from_utf8(b.data).unwrap()),
            other => panic!("not a blob: {other:?}"),
        }
    }
}

const BULK: Request<'static> = Request {
    all: false,
    update: false,
    patch: false,
    force: false,
    dry_run: false,
    paths: &[],
};

#[test]
fn a_named_path_is_staged() {
    let f = Fixture::new(&[], &[("a.txt", "one\n"), ("b.txt", "two\n")]);
    f.paths(&["a.txt"]).unwrap();
    assert_eq!(f.staged("a.txt").as_deref(), Some("one\n"));
    assert_eq!(f.staged("b.txt"), None);
}

#[test]
fn a_dot_stages_the_whole_tree_and_not_the_repository_directory() {
    let f = Fixture::new(&[], &[("a.txt", "one\n"), ("d/b.txt", "two\n")]);
    f.paths(&["."]).unwrap();
    assert_eq!(f.staged("a.txt").as_deref(), Some("one\n"));
    assert_eq!(f.staged("d/b.txt").as_deref(), Some("two\n"));
    let idx = index::read_index(&f.layout).unwrap();
    assert!(
        idx.entries.iter().all(|e| !e.path.starts_with(".kit")),
        "{:?}",
        idx.entries
    );
}

#[test]
fn an_ignored_path_needs_force() {
    let f = Fixture::new(&[], &[(".kitignore", "*.log\n"), ("run.log", "x\n")]);
    let error = f.paths(&["run.log"]).unwrap_err();
    assert!(
        matches!(error, Error::Ignored(ref p) if p == "run.log"),
        "{error:?}"
    );
    assert_eq!(
        error.to_string(),
        "path 'run.log' is ignored; use -f to add it anyway"
    );
    assert_eq!(f.staged("run.log"), None);

    let paths = ["run.log".to_owned()];
    f.run(&Request {
        force: true,
        dry_run: false,
        paths: &paths,
        ..BULK
    })
    .unwrap();
    assert_eq!(f.staged("run.log").as_deref(), Some("x\n"));
}

#[test]
fn all_stages_new_files_changes_and_deletions() {
    let f = Fixture::new(
        &[
            ("keep.txt", "k\n"),
            ("edit.txt", "old\n"),
            ("gone.txt", "g\n"),
        ],
        &[("new.txt", "n\n")],
    );
    fs::write(f.root.join("edit.txt"), "new\n").unwrap();
    fs::remove_file(f.root.join("gone.txt")).unwrap();
    f.run(&Request { all: true, ..BULK }).unwrap();
    assert_eq!(f.staged("keep.txt").as_deref(), Some("k\n"));
    assert_eq!(f.staged("edit.txt").as_deref(), Some("new\n"));
    assert_eq!(f.staged("new.txt").as_deref(), Some("n\n"));
    assert_eq!(f.staged("gone.txt"), None);
}

#[test]
fn update_restages_tracked_files_and_adds_no_new_file() {
    let f = Fixture::new(
        &[("edit.txt", "old\n"), ("gone.txt", "g\n")],
        &[("new.txt", "n\n")],
    );
    fs::write(f.root.join("edit.txt"), "new\n").unwrap();
    fs::remove_file(f.root.join("gone.txt")).unwrap();
    f.run(&Request {
        update: true,
        ..BULK
    })
    .unwrap();
    assert_eq!(f.staged("edit.txt").as_deref(), Some("new\n"));
    assert_eq!(f.staged("gone.txt"), None);
    assert_eq!(f.staged("new.txt"), None);
}

#[test]
fn stage_tracked_works_under_a_lock_that_the_caller_holds() {
    let f = Fixture::new(&[("edit.txt", "old\n")], &[]);
    fs::write(f.root.join("edit.txt"), "new\n").unwrap();
    let _lock = libkit::lock::acquire_worktree(&f.layout, &NoopObserver).unwrap();
    add::stage_tracked(&f.layout, &f.store).unwrap();
    assert_eq!(f.staged("edit.txt").as_deref(), Some("new\n"));
}

#[test]
fn modes_that_exclude_each_other_are_refused_in_the_old_order() {
    let f = Fixture::new(&[], &[("a.txt", "one\n")]);
    let named = ["a.txt".to_owned()];
    let cases: [(Request<'_>, &str); 5] = [
        (
            Request {
                patch: true,
                all: true,
                paths: &named,
                ..BULK
            },
            "-p/--patch cannot be combined with -A/--all or -u/--update",
        ),
        (
            Request {
                patch: true,
                ..BULK
            },
            "-p/--patch requires one or more file paths",
        ),
        (
            Request {
                all: true,
                update: true,
                ..BULK
            },
            "cannot combine -A/--all with -u/--update",
        ),
        (
            Request {
                all: true,
                paths: &named,
                ..BULK
            },
            "-A/--all and -u/--update take no path arguments",
        ),
        (
            BULK,
            "no paths given (use `.`, -A, -u, or one or more paths)",
        ),
    ];
    for (request, text) in cases {
        let error = f.run(&request).unwrap_err();
        assert_eq!(error.to_string(), text, "{error:?}");
    }
    assert_eq!(f.staged("a.txt"), None);
}

#[test]
fn a_path_that_leaves_the_repository_is_refused() {
    let f = Fixture::new(&[], &[("a.txt", "one\n")]);
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("o.txt"), "o").unwrap();
    let target = outside.path().join("o.txt");
    let error = f.paths(&[target.to_str().unwrap()]).unwrap_err();
    assert!(matches!(error, Error::Outside(_)), "{error:?}");
    let error = f.paths(&["../o.txt"]).unwrap_err();
    assert!(
        matches!(
            error,
            Error::Outside(_) | Error::InvalidPath(_) | Error::ResolveParent { .. }
        ),
        "{error:?}"
    );
    assert_eq!(f.staged("o.txt"), None);
}

#[cfg(unix)]
#[test]
fn a_path_through_a_symlink_is_refused() {
    let f = Fixture::new(&[], &[("real/o.txt", "o")]);
    std::os::unix::fs::symlink(f.root.join("real"), f.root.join("link")).unwrap();
    let error = f.paths(&["link/o.txt"]).unwrap_err();
    assert!(matches!(error, Error::ThroughSymlink(_)), "{error:?}");
    assert_eq!(f.staged("link/o.txt"), None);

    // A symlink to a directory outside the repository leads out of it.
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("o.txt"), "o").unwrap();
    std::os::unix::fs::symlink(outside.path(), f.root.join("away")).unwrap();
    let error = f.paths(&["away/o.txt"]).unwrap_err();
    assert!(matches!(error, Error::Outside(_)), "{error:?}");
    assert_eq!(f.staged("away/o.txt"), None);
}

#[test]
fn a_directory_without_a_store_is_not_a_repository() {
    let dir = tempfile::tempdir().unwrap();
    let layout = RepoLayout::single(dir.path());
    let environment = Environment::default();
    let error = add::stage(
        &layout,
        &StoreConfig {
            environment: &environment,
            observer: &NoopObserver,
        },
        dir.path(),
        &BULK,
        &mut NoChooser,
        &NoopObserver,
        &NoopObserver,
    )
    .unwrap_err();
    assert!(matches!(error, Error::NotARepository(_)), "{error:?}");
    assert!(error.to_string().starts_with("not a kit repo: "));
}

fn numbered(change: &[usize]) -> String {
    (1..=30)
        .map(|n| {
            if change.contains(&n) {
                format!("CHANGED {n}\n")
            } else {
                format!("line {n}\n")
            }
        })
        .collect()
}

#[test]
fn patch_stages_only_the_chosen_hunks() {
    let f = Fixture::new(&[("a.txt", &numbered(&[]))], &[]);
    fs::write(f.root.join("a.txt"), numbered(&[2, 29])).unwrap();
    let paths = ["a.txt".to_owned()];
    let mut picks = Picks {
        selected: vec![0],
        offered: Vec::new(),
    };
    let events = Events::default();
    f.run_with(
        &Request {
            patch: true,
            paths: &paths,
            ..BULK
        },
        &mut picks,
        &events,
    )
    .unwrap();
    assert_eq!(picks.offered, vec![2]);
    assert_eq!(f.staged("a.txt").unwrap(), numbered(&[2]));
    assert_eq!(
        *events.0.lock().unwrap(),
        vec![Event::HunksStaged {
            path: "a.txt".to_owned(),
            selected: 1,
            total: 2,
        }]
    );
}

#[test]
fn patch_reports_a_file_with_no_change_and_asks_nothing() {
    let f = Fixture::new(&[("a.txt", "same\n")], &[]);
    let paths = ["a.txt".to_owned()];
    let events = Events::default();
    f.run_with(
        &Request {
            patch: true,
            paths: &paths,
            ..BULK
        },
        &mut NoChooser,
        &events,
    )
    .unwrap();
    assert_eq!(
        *events.0.lock().unwrap(),
        vec![Event::NoChanges {
            path: "a.txt".to_owned()
        }]
    );
}

/// A file of `len` bytes that starts with `head` and has a hole after it, so
/// it takes no disk space.
fn sparse_file(path: &std::path::Path, head: &[u8], len: u64) {
    use std::io::Write as _;
    let mut file = fs::File::create(path).unwrap();
    file.write_all(head).unwrap();
    file.set_len(len).unwrap();
}

/// `len` bytes from a fixed xorshift stream. They hold NUL bytes, and a file of
/// them cuts into chunks.
fn pseudo_random(len: usize) -> Vec<u8> {
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.extend_from_slice(&state.to_le_bytes());
    }
    out.truncate(len);
    out
}

fn patch_request(paths: &[String]) -> Request<'_> {
    Request {
        patch: true,
        paths,
        ..BULK
    }
}

#[test]
fn patch_skips_a_binary_file_above_the_memory_limit_without_reading_it() {
    let f = Fixture::new(&[], &[]);
    let mut head = vec![b'a'; 100];
    head[10] = 0;
    sparse_file(
        &f.root.join("big.bin"),
        &head,
        kit_core::worktree::MAX_FILE_BYTES + 1,
    );
    let paths = ["big.bin".to_owned()];
    let events = Events::default();
    f.run_with(&patch_request(&paths), &mut NoChooser, &events)
        .unwrap();
    assert_eq!(
        *events.0.lock().unwrap(),
        vec![Event::BinarySkipped {
            path: "big.bin".to_owned()
        }]
    );
}

#[test]
fn patch_refuses_a_text_file_above_the_memory_limit() {
    let f = Fixture::new(&[], &[]);
    sparse_file(
        &f.root.join("big.txt"),
        "line\n".repeat(4000).as_bytes(),
        kit_core::worktree::MAX_FILE_BYTES + 1,
    );
    let paths = ["big.txt".to_owned()];
    let err = f
        .run_with(&patch_request(&paths), &mut NoChooser, &NoopObserver)
        .unwrap_err();
    assert!(
        matches!(
            err,
            Error::ReadFile {
                source: kit_core::worktree::WorktreeError::FileTooLarge(_),
                ..
            }
        ),
        "{err:?}"
    );
}

#[test]
fn patch_skips_a_chunked_binary_blob_that_is_staged() {
    let f = Fixture::new(&[], &[]);
    let data = pseudo_random(3 * 1024 * 1024);
    let staged = kit_core::worktree::store_file_object(&f.store, &data).unwrap();
    assert!(matches!(
        f.store.read_object(&staged).unwrap(),
        Object::ChunkedBlob(_)
    ));
    let mut idx = Index::new();
    idx.upsert_entry(IndexEntry {
        path: "big.bin".to_owned(),
        status: EntryStatus::Blob,
        object_hash: staged,
        mtime_ns: 0,
        size: 0,
        ino: 0,
        ctime_ns: 0,
    });
    index::write_index(&f.layout, &idx).unwrap();
    // The file in the tree is text, so only the staged side is binary.
    fs::write(f.root.join("big.bin"), "text\n").unwrap();
    let paths = ["big.bin".to_owned()];
    let events = Events::default();
    f.run_with(&patch_request(&paths), &mut NoChooser, &events)
        .unwrap();
    assert_eq!(
        *events.0.lock().unwrap(),
        vec![Event::BinarySkipped {
            path: "big.bin".to_owned()
        }]
    );
}

/// The number of files under the object directory.
fn object_files(f: &Fixture) -> usize {
    fn walk(dir: &std::path::Path) -> usize {
        fs::read_dir(dir)
            .unwrap()
            .map(|entry| {
                let path = entry.unwrap().path();
                if path.is_dir() { walk(&path) } else { 1 }
            })
            .sum()
    }
    walk(&f.root.join(".kit/objects"))
}

#[test]
fn a_dry_run_of_a_file_of_many_chunks_stores_nothing_and_reports_what_add_stages() {
    let f = Fixture::new(&[], &[]);
    fs::write(f.root.join("big.bin"), pseudo_random(24 * 1024 * 1024)).unwrap();
    let before = object_files(&f);
    let paths = ["big.bin".to_owned()];
    let request = Request {
        dry_run: true,
        paths: &paths,
        ..BULK
    };
    let events = Events::default();
    f.run_with(&request, &mut NoChooser, &events).unwrap();
    assert_eq!(
        *events.0.lock().unwrap(),
        vec![Event::WouldAdd {
            path: "big.bin".to_owned()
        }]
    );
    assert_eq!(object_files(&f), before);
    assert!(index::read_index(&f.layout).unwrap().entries.is_empty());

    // The same request without `dry_run` stages the path that was reported.
    f.paths(&["big.bin"]).unwrap();
    let idx = index::read_index(&f.layout).unwrap();
    assert_eq!(idx.entries.len(), 1);
    assert_eq!(idx.entries[0].path, "big.bin");
    assert!(object_files(&f) > before);
}
