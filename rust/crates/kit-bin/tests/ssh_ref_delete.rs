//! `kit push --delete` over ssh (SPEC-TRANSPORT §4.2.1, §7.3).
//!
//! The tests run the real `kit` binary against a real `kit serve`, through a
//! `/bin/sh` stand-in for `ssh`. One test stands a server that predates
//! deletes in its place: the stand-in plays back the frames such a server
//! answers.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers
#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use kit_core::hash::Hash;
use kit_core::layout::RepoLayout;
use kit_core::protocol::{RefWriteCondition, Transport};
use kit_core::refs;
use kit_rpc::kit::rpc::v1::ssh::{HelloResponse, ReadRefResponse, SshFrame, ssh_frame};
use kit_rpc::kit::rpc::v1::{Error as RpcError, ErrorCode, ProtocolVersion};
use kit_transport_file::FileTransport;

fn kit_bin() -> &'static str {
    env!("CARGO_BIN_EXE_kit")
}

fn ok(out: &Output, what: &str) {
    assert!(
        out.status.success(),
        "{what}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// An `ssh` stand-in that runs `kit serve <path>`, or, when
/// `$KIT_SSH_CANNED` names a file, writes that file's frames back and reads
/// what the client sends until it closes.
fn write_ssh_wrapper(dir: &Path) -> PathBuf {
    let wrapper = dir.join("fake_ssh.sh");
    let script = r#"#!/bin/sh
set -eu
if [ -n "${KIT_SSH_CANNED:-}" ]; then
  cat "$KIT_SSH_CANNED"
  exec cat >/dev/null
fi
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
exec "$KIT_SSH_TARGET_BIN" serve "$path"
"#;
    fs::write(&wrapper, script).unwrap();
    let mut perms = fs::metadata(&wrapper).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&wrapper, perms).unwrap();
    wrapper
}

/// A source repository with one signed commit on `main`, pushed to a served
/// repository named as the remote `origin` over `kit+ssh://`.
struct Fixture {
    work: tempfile::TempDir,
    xdg: tempfile::TempDir,
    wrapper: PathBuf,
}

const MAIN: &str = "refs/heads/main";
const MAIN_MAP: &str = "refs/kit/packmap/main";
const V1: &str = "refs/tags/v1";
const V1_MAP: &str = "refs/kit/tagmap/v1";

impl Fixture {
    fn new() -> Self {
        let work = tempfile::tempdir().unwrap();
        let xdg = tempfile::tempdir().unwrap();
        let wrapper = write_ssh_wrapper(work.path());
        let fx = Self { work, xdg, wrapper };
        let (source, remote) = (fx.source(), fx.remote());
        for dir in [&source, &remote] {
            fs::create_dir_all(dir).unwrap();
            ok(&fx.kit(dir, &["init"], &[]), "init");
        }
        ok(&fx.kit(&source, &["keygen"], &[]), "keygen");
        ok(
            &fx.kit(&source, &["remote", "add", "origin", &fx.url()], &[]),
            "remote add",
        );
        fs::write(source.join("file.txt"), "one").unwrap();
        ok(&fx.kit(&source, &["add", "."], &[]), "add");
        ok(&fx.kit(&source, &["commit", "-m", "one"], &[]), "commit");
        ok(&fx.push(&["origin"]), "push main");
        fx
    }

    /// Run `kit <args>` in `dir`, isolated from the developer's environment,
    /// with `ssh` standing for `kit serve`.
    fn kit(&self, dir: &Path, args: &[&str], env: &[(&str, &Path)]) -> Output {
        let mut cmd = Command::new(kit_bin());
        cmd.args(args)
            .current_dir(dir)
            .env("XDG_CONFIG_HOME", self.xdg.path())
            .env("HOME", self.xdg.path())
            .env("EDITOR", "true")
            .env("VISUAL", "true")
            .env("KIT_SSH_PROGRAM", &self.wrapper)
            .env("KIT_SSH_TARGET_BIN", kit_bin())
            .stdin(Stdio::null());
        for (key, value) in env {
            cmd.env(key, value);
        }
        cmd.output().expect("spawn kit")
    }

    fn source(&self) -> PathBuf {
        self.work.path().join("source")
    }

    fn remote(&self) -> PathBuf {
        self.work.path().join("remote")
    }

    fn url(&self) -> String {
        format!("kit+ssh://e2e@localhost{}", self.remote().display())
    }

    fn tx(&self) -> FileTransport {
        FileTransport::new(self.remote())
    }

    fn push(&self, args: &[&str]) -> Output {
        let mut full = vec!["push"];
        full.extend_from_slice(args);
        self.kit(&self.source(), &full, &[])
    }

    fn tracking(&self) -> Option<Hash> {
        refs::read_remote_ref(&RepoLayout::single(self.source()), "origin", "main").unwrap()
    }
}

/// A branch and its packmap go, and so does the tracking ref.
#[test]
fn a_branch_is_deleted_over_ssh_with_its_packmap_and_tracking_ref() {
    let fx = Fixture::new();
    let tx = fx.tx();
    assert!(tx.read_ref(MAIN_MAP).unwrap().is_some());
    assert!(fx.tracking().is_some());

    let out = fx.push(&["--delete", "origin", "main"]);

    ok(&out, "push --delete");
    assert!(
        stderr(&out).contains(" - [deleted]         refs/heads/main"),
        "{}",
        stderr(&out)
    );
    assert_eq!(tx.read_ref(MAIN).unwrap(), None);
    assert_eq!(tx.read_ref(MAIN_MAP).unwrap(), None);
    assert_eq!(fx.tracking(), None);
}

/// A tag and its tag map go. The local tag stays.
#[test]
fn a_tag_is_deleted_over_ssh_with_its_tag_map() {
    let fx = Fixture::new();
    let source = fx.source();
    ok(&fx.kit(&source, &["tag", "v1"], &[]), "tag");
    ok(&fx.push(&["origin", "v1"]), "push v1");
    let tx = fx.tx();
    assert!(tx.read_ref(V1_MAP).unwrap().is_some());

    ok(&fx.push(&["--delete", "origin", "refs/tags/v1"]), "delete");

    assert_eq!(tx.read_ref(V1).unwrap(), None);
    assert_eq!(tx.read_ref(V1_MAP).unwrap(), None);
    assert!(
        refs::read_tag(&RepoLayout::single(&source), "v1")
            .unwrap()
            .is_some()
    );
    assert!(tx.read_ref(MAIN).unwrap().is_some(), "main stays");
}

/// A remote branch that moved since the last fetch is not deleted: the
/// lease is the tracking ref, and the push fails with nothing changed.
#[test]
fn a_stale_lease_over_ssh_deletes_nothing() {
    let fx = Fixture::new();
    let tx = fx.tx();
    let tip = tx.read_ref(MAIN).unwrap().unwrap();
    let map = tx.read_ref(MAIN_MAP).unwrap();
    let moved = [7u8; 32];
    tx.update_ref(MAIN, RefWriteCondition::Match(tip), &moved)
        .unwrap();

    let out = fx.push(&["--delete", "origin", "main"]);

    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("refs/heads/main on the remote is not at the value"),
        "{}",
        stderr(&out)
    );
    assert_eq!(tx.read_ref(MAIN).unwrap(), Some(moved));
    assert_eq!(tx.read_ref(MAIN_MAP).unwrap(), map);
    assert_eq!(fx.tracking(), Some(tip), "the tracking ref stays");
}

/// A server that predates deletes reads the empty `new_id` as a malformed
/// update and refuses it. The client reads the ref, finds it there, and
/// surfaces the server's words.
#[test]
fn a_server_that_predates_deletes_has_its_refusal_surfaced() {
    let fx = Fixture::new();
    let tip = fx.tx().read_ref(MAIN).unwrap().unwrap();
    let map = fx.tx().read_ref(MAIN_MAP).unwrap().unwrap();
    let frames = [
        ssh_frame::Body::HelloResponse(Box::new(
            HelloResponse::default().with_proto(ProtocolVersion::ProtocolVersion1),
        )),
        // The packmap read before the delete.
        ssh_frame::Body::ReadRefResponse(Box::new(
            ReadRefResponse::default().with_object_id(map.to_vec()),
        )),
        // The delete, as a server without deletes refuses it.
        ssh_frame::Body::Error(Box::new(
            RpcError::default()
                .with_code(ErrorCode::InvalidRequest)
                .with_message("new_id must be 32 bytes"),
        )),
        // The read that tells the refusal from an absent ref.
        ssh_frame::Body::ReadRefResponse(Box::new(
            ReadRefResponse::default().with_object_id(tip.to_vec()),
        )),
    ];
    let canned = fx.work.path().join("canned");
    let mut bytes = Vec::new();
    for body in frames {
        let frame = SshFrame {
            body: Some(body),
            ..Default::default()
        };
        kit_rpc::write_frame(&mut bytes, &frame).unwrap();
    }
    fs::write(&canned, bytes).unwrap();

    let out = fx.kit(
        &fx.source(),
        &["push", "--delete", "origin", "refs/heads/main"],
        &[("KIT_SSH_CANNED", &canned)],
    );

    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(
        stderr(&out)
            .contains("deleting `refs/heads/main` failed: remote error: new_id must be 32 bytes"),
        "{}",
        stderr(&out)
    );
    assert_eq!(fx.tracking(), Some(tip), "the tracking ref stays");
    assert_eq!(fx.tx().read_ref(MAIN).unwrap(), Some(tip));
}

/// `--dry-run` names the delete and contacts nothing; `--delete` needs a
/// ref and does not combine with a write of its own.
#[test]
fn delete_flags_are_checked_and_a_dry_run_deletes_nothing() {
    let fx = Fixture::new();
    let tx = fx.tx();
    let tip = tx.read_ref(MAIN).unwrap();

    let out = fx.push(&["--dry-run", "--delete", "origin", "main"]);
    ok(&out, "dry run");
    assert!(
        stderr(&out).contains("(dry-run) would delete main on origin"),
        "{}",
        stderr(&out)
    );
    assert_eq!(tx.read_ref(MAIN).unwrap(), tip);
    assert!(fx.tracking().is_some());

    for args in [
        &["--delete", "origin"][..],
        &["--delete", "--force", "origin", "main"],
        &["--delete", "--tags", "origin", "main"],
        &["--delete", "--all", "origin"],
        &["--delete", "-u", "origin", "main"],
    ] {
        let out = fx.push(args);
        assert_eq!(out.status.code(), Some(64), "{args:?}: {}", stderr(&out));
    }
    assert_eq!(tx.read_ref(MAIN).unwrap(), tip);
}
