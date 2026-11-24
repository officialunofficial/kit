//! The full flushes of one small edit, counted per command.
//!
//! A command is slow on a laptop mostly by the device flushes it makes, so the
//! count of each command of the edit loop is pinned: `add`, `commit`, `push`,
//! `fetch` and `pull`. The commands run as the real binary against a
//! `kit+file://` remote. The binary of this test build appends a line to the
//! file named by `KIT_FLUSH_LOG` for each full flush (see `kit_core::flush`),
//! and the test counts the lines.
//!
//! The counts are for Apple file systems, where a per-file writeout is
//! `fsync(2)`, a full flush is `F_FULLFSYNC`, and the batch makes one full flush
//! for its objects and one for each directory it names. Linux flushes the
//! shard directories one by one, so its counts differ.
#![cfg(target_os = "macos")]
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

mod common;

use std::fs;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use common::{Repo, kit_env};

/// The full flushes `kit <args>` makes in `cwd`.
fn flushes(cwd: &Path, xdg: &Path, log: &Path, args: &[&str]) -> usize {
    let _ = fs::remove_file(log);
    let log_path = log.to_str().unwrap();
    let out = kit_env(cwd, xdg, args, &[("KIT_FLUSH_LOG", log_path)]);
    assert!(
        out.status.success(),
        "kit {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    fs::read_to_string(log).map_or(0, |lines| lines.lines().count())
}

/// Edit one small file of `repo`, so the commit has a few trees to build.
fn edit(repo: &Repo, round: u32) {
    repo.write("dir/sub/edited.txt", format!("round {round}\n").as_bytes());
}

#[test]
fn each_command_of_the_edit_loop_makes_the_pinned_number_of_full_flushes() {
    let origin = Repo::new();
    for dir in ["a", "b", "dir/sub"] {
        for file in 0..4 {
            origin.write(
                &format!("{dir}/f{file}.txt"),
                format!("{dir} {file}\n").as_bytes(),
            );
        }
    }
    origin.ok(&["add", "."]);
    origin.ok(&["commit", "-m", "base"]);
    let store = origin.path().join("store");
    fs::create_dir_all(&store).unwrap();
    let url = format!("kit+file://{}", store.display());
    origin.ok(&["remote", "add", "origin", &url]);
    origin.ok(&["push", "-u", "origin", "main"]);

    let consumer_xdg = tempfile::tempdir().unwrap();
    let consumer_dir = tempfile::tempdir().unwrap();
    let out = kit_env(
        consumer_dir.path(),
        consumer_xdg.path(),
        &["clone", "-o", "origin", &url, "work"],
        &[],
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let work = consumer_dir.path().join("work");

    let logs = tempfile::tempdir().unwrap();
    let log = logs.path().join("flushes");
    let count = |repo: &Repo, args: &[&str]| flushes(repo.path(), repo.xdg(), &log, args);

    edit(&origin, 1);
    let add = count(&origin, &["add", "dir/sub/edited.txt"]);
    let unchanged = count(&origin, &["add", "dir/sub/edited.txt"]);
    let commit = count(&origin, &["commit", "-m", "round 1"]);
    let push = count(&origin, &["push", "origin", "main"]);
    let fetch = flushes(&work, consumer_xdg.path(), &log, &["fetch", "origin"]);

    edit(&origin, 2);
    origin.ok(&["add", "dir/sub/edited.txt"]);
    origin.ok(&["commit", "-m", "round 2"]);
    origin.ok(&["push", "origin", "main"]);
    let head = work.join(".kit/HEAD");
    let head_before = (fs::read(&head).unwrap(), fs::metadata(&head).unwrap().ino());
    let pull = flushes(&work, consumer_xdg.path(), &log, &["pull", "origin"]);
    let head_after = (fs::read(&head).unwrap(), fs::metadata(&head).unwrap().ino());
    assert_eq!(
        head_after, head_before,
        "a pull that keeps the branch leaves HEAD alone"
    );

    // add: an object and the objects directory, the index and its directory.
    // commit: an object and the objects directory, the branch ref and its
    // directory; the index stays as it is.
    // push: the remote's pack, node and two refs, each with a directory flush,
    // and the tracking ref with its directory.
    // fetch: the format marker and its directory, the objects directory, the
    // pack and its index with their directories, and the tracking ref with its
    // directory.
    // pull: the fetch, then the pull record, the branch ref and the index, each
    // with a directory flush, and the flush that clears the pull record. HEAD
    // is not written.
    assert_eq!(
        [add, unchanged, commit, push, fetch, pull],
        [4, 0, 4, 10, 9, 16],
        "full flushes of add, an unchanged add, commit, push, fetch and pull"
    );
}
