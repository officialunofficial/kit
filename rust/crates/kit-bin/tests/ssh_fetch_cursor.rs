//! A fetch of an unchanged `kit+ssh://` remote costs one request when the
//! served repository offers a cursor (SPEC-TRANSPORT §4.2.2).
//!
//! The tests run the real `kit` binary against a real `kit serve`. A
//! `/bin/sh` stand-in for `ssh` records every byte that the client sends and
//! passes it to `kit serve <path>`, so the tests count the requests on the
//! wire. The file transport offers a cursor on Linux only. Elsewhere the
//! tests check that the fetch still works and costs more than one request.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers
#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, SystemTime};

use kit_core::protocol::{RefWriteCondition, Transport};
use kit_core::refs;
use kit_rpc::kit::rpc::v1::ssh::{SshFrame, ssh_frame};
use kit_transport_file::FileTransport;

const OFFERS_CURSOR: bool = cfg!(target_os = "linux");

fn kit_bin() -> &'static str {
    env!("CARGO_BIN_EXE_kit")
}

/// Run `kit` in `cwd`, isolated from the developer's environment.
fn run_in(cwd: &Path, xdg: &Path, args: &[&str], extra_env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(kit_bin());
    cmd.args(args)
        .current_dir(cwd)
        .env("XDG_CONFIG_HOME", xdg)
        .env("HOME", xdg)
        .env("EDITOR", "true")
        .env("VISUAL", "true")
        .stdin(Stdio::null());
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    cmd.output().expect("spawn kit")
}

fn ok(out: &Output, what: &str) {
    assert!(
        out.status.success(),
        "{what}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// An `ssh` stand-in. It copies what the client sends to `$KIT_SSH_FRAME_LOG`
/// and passes it to `kit serve <path>`.
fn write_ssh_wrapper(dir: &Path) -> PathBuf {
    let wrapper = dir.join("fake_ssh.sh");
    let script = r#"#!/bin/sh
set -eu
found=0
path=""
for a in "$@"; do
  if [ "$found" = 2 ]; then
    path="$a"
    break
  fi
  if [ "$found" = 1 ] && [ "$a" = serve ]; then
    found=2
    continue
  fi
  if [ "$a" = kit ]; then
    found=1
  fi
done
if [ -z "$path" ]; then
  echo "fake_ssh: could not locate 'kit serve <path>' in argv" >&2
  exit 64
fi
tee -a "$KIT_SSH_FRAME_LOG" | "$KIT_SSH_TARGET_BIN" serve "$path"
"#;
    fs::write(&wrapper, script).unwrap();
    let mut perms = fs::metadata(&wrapper).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&wrapper, perms).unwrap();
    wrapper
}

/// The requests in a log of client frames: every frame but the `Hello` of
/// each connection and its `Close`.
fn requests(log: &Path) -> Vec<&'static str> {
    let bytes = fs::read(log).unwrap_or_default();
    let mut cursor = std::io::Cursor::new(bytes.as_slice());
    let mut out = Vec::new();
    let len = bytes.len() as u64;
    while cursor.position() < len {
        let frame: SshFrame = kit_rpc::read_frame(&mut cursor).unwrap();
        match frame.body {
            Some(ssh_frame::Body::Hello(_) | ssh_frame::Body::Close(_)) => {}
            other => out.push(kit_rpc::body_name(&other)),
        }
    }
    out
}

/// A source repository with one commit, pushed to the served `remote`.
struct Fixture {
    work: tempfile::TempDir,
    xdg: tempfile::TempDir,
    wrapper: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let work = tempfile::tempdir().unwrap();
        let xdg = tempfile::tempdir().unwrap();
        let wrapper = write_ssh_wrapper(work.path());
        let fx = Self { work, xdg, wrapper };
        let (source, remote) = (fx.source(), fx.remote());
        for dir in [&source, &remote] {
            fs::create_dir_all(dir).unwrap();
            ok(&run_in(dir, fx.xdg.path(), &["init"], &[]), "init");
        }
        ok(&run_in(&source, fx.xdg.path(), &["keygen"], &[]), "keygen");
        fx.commit("one");
        let url = format!("kit+file://{}", remote.display());
        ok(
            &run_in(
                &source,
                fx.xdg.path(),
                &["remote", "add", "origin", &url],
                &[],
            ),
            "remote add",
        );
        ok(
            &run_in(&source, fx.xdg.path(), &["push", "origin"], &[]),
            "push",
        );
        fx
    }

    fn source(&self) -> PathBuf {
        self.work.path().join("source")
    }

    fn remote(&self) -> PathBuf {
        self.work.path().join("remote")
    }

    fn commit(&self, text: &str) {
        let source = self.source();
        fs::write(source.join("file.txt"), text).unwrap();
        ok(&run_in(&source, self.xdg.path(), &["add", "."], &[]), "add");
        ok(
            &run_in(&source, self.xdg.path(), &["commit", "-m", text], &[]),
            "commit",
        );
    }

    /// Make `branches` branches in all, each at the head of `main` with its
    /// packmap, written by a writer that is not `kit serve`.
    fn add_branches(&self, branches: usize) {
        let tx = FileTransport::new(self.remote());
        let head = tx.read_ref("refs/heads/main").unwrap().unwrap();
        let packmap = tx.read_ref("refs/kit/packmap/main").unwrap().unwrap();
        for i in 1..branches {
            for (name, id) in [
                (format!("refs/kit/packmap/b{i}"), packmap),
                (format!("refs/heads/b{i}"), head),
            ] {
                tx.update_ref(&name, RefWriteCondition::Missing, &id)
                    .unwrap();
            }
        }
    }

    /// Let every ref directory of the remote look as old as an idle one, which
    /// the file transport needs before it offers a cursor.
    fn settle(&self) {
        let hour = Duration::from_secs(3600);
        stamp_dirs(&self.remote().join("refs"), SystemTime::now() - hour);
    }

    /// Run `kit <args>` in `dir` over the served remote. The frames that the
    /// client sent go to `log`.
    fn over_ssh(&self, dir: &Path, args: &[&str], log: &str) -> (Output, Vec<&'static str>) {
        let log = self.work.path().join(log);
        let out = run_in(
            dir,
            self.xdg.path(),
            args,
            &[
                ("KIT_SSH_PROGRAM", self.wrapper.to_str().unwrap()),
                ("KIT_SSH_FRAME_LOG", log.to_str().unwrap()),
                ("KIT_SSH_TARGET_BIN", kit_bin()),
            ],
        );
        (out, requests(&log))
    }

    fn url(&self) -> String {
        format!("kit+ssh://e2e@localhost{}", self.remote().display())
    }

    fn tracking(clone: &Path, branch: &str) -> Option<String> {
        let layout = kit_core::layout::RepoLayout::single(clone);
        refs::read_remote_ref(&layout, "origin", branch)
            .unwrap()
            .map(|h| kit_core::to_hex(&h))
    }
}

fn stamp_dirs(dir: &Path, when: SystemTime) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            stamp_dirs(&path, when);
        }
    }
    fs::File::open(dir).unwrap().set_modified(when).unwrap();
}

/// A clone over ssh, then a fetch that finds nothing and, with `then_move`, a
/// fetch after another writer moved `main`.
fn unchanged_fetch_costs_one_request(branches: usize, then_move: bool) {
    let fx = Fixture::new();
    fx.add_branches(branches);
    fx.settle();
    let clone = fx.work.path().join("clone");
    let (out, _) = fx.over_ssh(
        fx.work.path(),
        &["clone", "-o", "origin", &fx.url(), clone.to_str().unwrap()],
        "clone.frames",
    );
    ok(&out, "clone");
    assert!(Fixture::tracking(&clone, &format!("b{}", branches - 1)).is_some());

    let (out, sent) = fx.over_ssh(&clone, &["fetch", "origin"], "unchanged.frames");
    ok(&out, "unchanged fetch");
    if OFFERS_CURSOR {
        assert_eq!(
            sent,
            ["read_repo_cursor"],
            "an unchanged fetch is one request"
        );
    } else {
        // The served repository offers no cursor: the fetch does its full
        // work, as it did before the request existed.
        assert_eq!(sent[0], "read_repo_cursor");
        assert!(
            sent.len() > 1 + 2 * (branches - 1),
            "{} requests",
            sent.len()
        );
    }

    if !then_move {
        return;
    }
    // Another writer, which is not a session of `kit serve`, moves `main`.
    let before = Fixture::tracking(&clone, "main").unwrap();
    fx.commit("two");
    ok(
        &run_in(&fx.source(), fx.xdg.path(), &["push", "origin"], &[]),
        "push",
    );
    let moved = refs::read_ref(&kit_core::layout::RepoLayout::single(fx.source()), "main")
        .unwrap()
        .map(|h| kit_core::to_hex(&h))
        .unwrap();
    assert_ne!(before, moved);
    fx.settle();
    let (out, sent) = fx.over_ssh(&clone, &["fetch", "origin"], "moved.frames");
    ok(&out, "fetch after a push");
    assert!(sent.len() > 1, "a changed remote is fetched in full");
    assert_eq!(Fixture::tracking(&clone, "main"), Some(moved));
}

#[test]
fn an_unchanged_fetch_of_10_branches_is_one_request() {
    unchanged_fetch_costs_one_request(10, true);
}

#[test]
fn an_unchanged_fetch_of_1000_branches_is_one_request() {
    unchanged_fetch_costs_one_request(1000, false);
}

/// A ref that another writer creates after the last fetch, with the
/// repository settled again, is fetched.
#[test]
fn a_branch_written_by_another_writer_is_fetched() {
    let fx = Fixture::new();
    fx.add_branches(3);
    fx.settle();
    let clone = fx.work.path().join("clone");
    let (out, _) = fx.over_ssh(
        fx.work.path(),
        &["clone", "-o", "origin", &fx.url(), clone.to_str().unwrap()],
        "clone.frames",
    );
    ok(&out, "clone");
    let (out, _) = fx.over_ssh(&clone, &["fetch", "origin"], "first.frames");
    ok(&out, "fetch");

    let tx = FileTransport::new(fx.remote());
    let head = tx.read_ref("refs/heads/main").unwrap().unwrap();
    let packmap = tx.read_ref("refs/kit/packmap/main").unwrap().unwrap();
    tx.update_ref(
        "refs/kit/packmap/late",
        RefWriteCondition::Missing,
        &packmap,
    )
    .unwrap();
    tx.update_ref("refs/heads/late", RefWriteCondition::Missing, &head)
        .unwrap();
    assert_eq!(Fixture::tracking(&clone, "late"), None);

    // Fetched at once, while the new ref's directory is fresh, and fetched
    // again when the repository has settled.
    let (out, sent) = fx.over_ssh(&clone, &["fetch", "origin"], "fresh.frames");
    ok(&out, "fetch right after the write");
    assert!(sent.len() > 1);
    assert!(Fixture::tracking(&clone, "late").is_some());

    tx.update_ref(
        "refs/kit/packmap/later",
        RefWriteCondition::Missing,
        &packmap,
    )
    .unwrap();
    tx.update_ref("refs/heads/later", RefWriteCondition::Missing, &head)
        .unwrap();
    fx.settle();
    let (out, sent) = fx.over_ssh(&clone, &["fetch", "origin"], "settled.frames");
    ok(&out, "fetch after the repository settled");
    assert!(sent.len() > 1);
    assert!(Fixture::tracking(&clone, "later").is_some());
}
