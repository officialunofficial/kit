//! What a `kit+file://` remote can hold that kit must refuse: a branch whose
//! tip is a tree, and a FIFO where a pack or a pack map should be.
//!
//! The tests run the real `kit` binary.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers
#![cfg(unix)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use kit_core::layout::RepoLayout;
use kit_core::object::Object;
use kit_core::protocol::{RefWriteCondition, Transport};
use kit_core::refs;
use kit_core::store::ObjectStore;
use kit_transport_file::FileTransport;

fn kit_bin() -> &'static str {
    env!("CARGO_BIN_EXE_kit")
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn ok(out: &Output, what: &str) {
    assert!(out.status.success(), "{what}: {}", stderr(out));
}

/// The longest a command may take. A hang, and not a slow machine, is what
/// the tests look for: every command here ends in well under a second.
const DEADLINE: Duration = Duration::from_secs(60);

/// A source repository with one signed commit on `main`, pushed to a
/// `kit+file://` remote named `origin`.
struct Fixture {
    work: tempfile::TempDir,
    xdg: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let fx = Self {
            work: tempfile::tempdir().unwrap(),
            xdg: tempfile::tempdir().unwrap(),
        };
        let (source, remote) = (fx.source(), fx.remote());
        for dir in [&source, &remote] {
            fs::create_dir_all(dir).unwrap();
            ok(&fx.kit(dir, &["init"]), "init");
        }
        ok(&fx.kit(&source, &["keygen"]), "keygen");
        ok(
            &fx.kit(&source, &["remote", "add", "origin", &fx.url()]),
            "remote add",
        );
        fx.commit("one");
        ok(&fx.kit(&source, &["push", "origin"]), "push");
        fx
    }

    /// Run `kit <args>` in `dir`, isolated from the developer's environment,
    /// and fail the test if it does not end within [`DEADLINE`].
    fn kit(&self, dir: &Path, args: &[&str]) -> Output {
        let mut child = Command::new(kit_bin())
            .args(args)
            .current_dir(dir)
            .env("XDG_CONFIG_HOME", self.xdg.path())
            .env("HOME", self.xdg.path())
            .env("EDITOR", "true")
            .env("VISUAL", "true")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn kit");
        let start = Instant::now();
        while child.try_wait().unwrap().is_none() {
            if start.elapsed() > DEADLINE {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("`kit {}` did not end within {DEADLINE:?}", args.join(" "));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        child.wait_with_output().unwrap()
    }

    fn source(&self) -> PathBuf {
        self.work.path().join("source")
    }

    fn remote(&self) -> PathBuf {
        self.work.path().join("remote")
    }

    fn url(&self) -> String {
        format!("kit+file://{}", self.remote().display())
    }

    fn commit(&self, text: &str) {
        let source = self.source();
        fs::write(source.join("file.txt"), text).unwrap();
        ok(&self.kit(&source, &["add", "."]), "add");
        ok(&self.kit(&source, &["commit", "-m", text]), "commit");
    }

    fn clone_into(&self, name: &str) -> (PathBuf, Output) {
        let dir = self.work.path().join(name);
        let out = self.kit(
            self.work.path(),
            &["clone", "-o", "origin", &self.url(), dir.to_str().unwrap()],
        );
        (dir, out)
    }

    /// The tree of the commit at the tip of `main` in the source.
    fn tree_of_main(&self) -> kit_core::hash::Hash {
        let layout = RepoLayout::single(self.source());
        let tip = refs::read_ref(&layout, "main").unwrap().unwrap();
        match ObjectStore::open(&layout)
            .unwrap()
            .read_object(&tip)
            .unwrap()
        {
            Object::Commit(commit) => commit.tree_hash,
            other => panic!("not a commit: {other:?}"),
        }
    }

    /// Point `refs/heads/main` of the remote at `value`.
    fn move_remote_main(&self, value: &kit_core::hash::Hash) {
        FileTransport::new(self.remote())
            .update_ref("refs/heads/main", RefWriteCondition::Any, value)
            .unwrap();
    }
}

/// Replace the file at `path` with a FIFO.
fn replace_with_fifo(path: &Path) {
    fs::remove_file(path).unwrap();
    let status = Command::new("mkfifo").arg(path).status().unwrap();
    assert!(status.success(), "mkfifo");
}

fn tracked(dir: &Path, branch: &str) -> Option<kit_core::hash::Hash> {
    refs::read_remote_ref(&RepoLayout::single(dir), "origin", branch).unwrap()
}

/// A branch of the remote that points at a tree is refused by clone, fetch and
/// pull: the whole fetch fails, as for any bad object, and no tracking ref
/// takes the tree.
#[test]
fn a_branch_that_points_at_a_tree_is_refused() {
    let fx = Fixture::new();
    let (clone, out) = fx.clone_into("good");
    ok(&out, "clone");
    let good = tracked(&clone, "main").unwrap();
    fx.move_remote_main(&fx.tree_of_main());

    let (bad, out) = fx.clone_into("bad");

    assert!(!out.status.success(), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("remote branch 'main' points at a tree, not a commit"),
        "{}",
        stderr(&out)
    );
    assert_eq!(
        refs::list_remote_refs(&RepoLayout::single(&bad), "origin").map_or(0, |r| r.len()),
        0
    );

    let out = fx.kit(&clone, &["fetch", "origin"]);
    assert!(!out.status.success(), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("remote branch 'main' points at a tree, not a commit"),
        "{}",
        stderr(&out)
    );
    assert_eq!(
        tracked(&clone, "main"),
        Some(good),
        "the tracking ref stays"
    );

    let out = fx.kit(&clone, &["pull", "origin"]);
    assert!(!out.status.success(), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("remote branch 'main' points at a tree, not a commit"),
        "{}",
        stderr(&out)
    );
    assert_eq!(tracked(&clone, "main"), Some(good));
}

/// A FIFO where a pack map should be fails a clone at once. It does not wait
/// for a writer.
#[test]
fn a_fifo_at_a_pack_map_path_fails_a_clone_at_once() {
    let fx = Fixture::new();
    replace_with_fifo(&fx.remote().join("refs/kit/packmap/main"));

    let (_, out) = fx.clone_into("clone");

    assert!(!out.status.success(), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("not a regular file"),
        "{}",
        stderr(&out)
    );
}

/// A FIFO where a pack should be fails a clone at once.
#[test]
fn a_fifo_at_a_pack_path_fails_a_clone_at_once() {
    let fx = Fixture::new();
    let packs = fx.remote().join("packs");
    let mut files: Vec<PathBuf> = fs::read_dir(&packs)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.is_file())
        .collect();
    assert!(!files.is_empty(), "the push stored packs");
    files.sort();
    for pack in &files {
        replace_with_fifo(pack);
    }

    let (_, out) = fx.clone_into("clone");

    assert!(!out.status.success(), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("not a regular file"),
        "{}",
        stderr(&out)
    );
}

/// A FIFO at the ref of a branch the clone has to read ends a fetch with
/// prune and a push at once.
#[test]
fn a_fifo_at_a_branch_ref_path_fails_fetch_prune_and_push_at_once() {
    let fx = Fixture::new();
    let (clone, out) = fx.clone_into("clone");
    ok(&out, "clone");
    replace_with_fifo(&fx.remote().join("refs/heads/main"));

    let out = fx.kit(&clone, &["fetch", "--prune", "origin"]);
    assert!(!out.status.success(), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("not a regular file"),
        "{}",
        stderr(&out)
    );
    fx.commit("two");
    let out = fx.kit(&fx.source(), &["push", "origin"]);
    assert!(!out.status.success(), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("not a regular file"),
        "{}",
        stderr(&out)
    );
}
