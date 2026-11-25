//! A repository with many branches, over ssh (SPEC-TRANSPORT §4.2.3).
//!
//! The test runs the real `kit` binary against a real `kit serve`, through a
//! `/bin/sh` stand-in for `ssh`. The listing of 20,000 branches is several
//! times one 1 MiB frame, so clone, fetch and pull read it in pages, and a
//! fetch of that many branches spends more than one session.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers
#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use kit_core::layout::RepoLayout;
use kit_core::refs;
use kit_rpc::kit::common::v1::RefEntry;
use kit_rpc::kit::rpc::v1::ssh::{HelloResponse, ListRefsResponse, SshFrame, ssh_frame};
use kit_rpc::kit::rpc::v1::{Error as RpcError, ErrorCode, ProtocolVersion};

/// Past the 4,997 branches one session holds, so a clone spends more than one
/// session, and well past the 1,000 refs of one page.
const SOME_BRANCHES: usize = 5_100;
/// Several times the 13,400 names of 30 characters that one frame once held.
const MANY_BRANCHES: usize = 20_000;

fn kit_bin() -> &'static str {
    env!("CARGO_BIN_EXE_kit")
}

fn ok(out: &Output, what: &str) {
    assert!(out.status.success(), "{what}: {}", stderr(out));
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// An `ssh` stand-in that runs `kit serve <path>`.
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
printf 'session\n' >> "$KIT_SSH_SESSION_LOG"
exec "$KIT_SSH_TARGET_BIN" serve "$path"
"#;
    fs::write(&wrapper, script).unwrap();
    let mut perms = fs::metadata(&wrapper).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&wrapper, perms).unwrap();
    wrapper
}

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
            ok(&fx.kit(dir, &["init"]), "init");
        }
        ok(&fx.kit(&source, &["keygen"]), "keygen");
        ok(
            &fx.kit(&source, &["remote", "add", "origin", &fx.url()]),
            "remote add",
        );
        fx.commit("one");
        ok(&fx.kit(&source, &["push", "origin"]), "push main");
        fx
    }

    fn kit(&self, dir: &Path, args: &[&str]) -> Output {
        self.kit_with(dir, args, &[])
    }

    fn kit_with(&self, dir: &Path, args: &[&str], env: &[(&str, &Path)]) -> Output {
        Command::new(kit_bin())
            .args(args)
            .envs(env.iter().copied())
            .current_dir(dir)
            .env("XDG_CONFIG_HOME", self.xdg.path())
            .env("HOME", self.xdg.path())
            .env("EDITOR", "true")
            .env("VISUAL", "true")
            .env("KIT_SSH_PROGRAM", &self.wrapper)
            .env("KIT_SSH_TARGET_BIN", kit_bin())
            .env("KIT_SSH_SESSION_LOG", self.work.path().join("sessions"))
            .stdin(Stdio::null())
            .output()
            .expect("spawn kit")
    }

    fn source(&self) -> PathBuf {
        self.work.path().join("source")
    }

    fn remote(&self) -> PathBuf {
        self.work.path().join("remote")
    }

    fn clone_dir(&self) -> PathBuf {
        self.work.path().join("clone")
    }

    fn url(&self) -> String {
        format!("kit+ssh://e2e@localhost{}", self.remote().display())
    }

    /// A new commit on `main` of the source, pushed.
    fn commit(&self, text: &str) {
        let source = self.source();
        fs::write(source.join("file.txt"), text).unwrap();
        ok(&self.kit(&source, &["add", "."]), "add");
        ok(&self.kit(&source, &["commit", "-m", text]), "commit");
        if text != "one" {
            ok(&self.kit(&source, &["push", "origin"]), "push");
        }
    }

    /// `branches` more branches of 30-character names at the head of `main`,
    /// each with its packmap, written as the ref files a file root holds.
    fn add_branches(&self, branches: usize) {
        let (heads, maps) = (
            self.remote().join("refs/heads"),
            self.remote().join("refs/kit/packmap"),
        );
        let (head, map) = (
            fs::read(heads.join("main")).unwrap(),
            fs::read(maps.join("main")).unwrap(),
        );
        for i in 0..branches {
            let name = format!("branch-{i:023}");
            assert_eq!(name.len(), 30);
            fs::write(heads.join(&name), &head).unwrap();
            fs::write(maps.join(&name), &map).unwrap();
        }
    }

    fn sessions(&self) -> usize {
        fs::read_to_string(self.work.path().join("sessions")).map_or(0, |log| log.lines().count())
    }
}

/// The remote-tracking branches of `origin` in `dir`.
fn tracked(dir: &Path) -> usize {
    refs::list_remote_refs(&RepoLayout::single(dir), "origin")
        .unwrap()
        .len()
}

/// A clone, a fetch that finds a new commit and a pull each read the listing
/// in pages, and each ends with every branch tracked.
fn clones_fetches_and_pulls(branches: usize) {
    let fx = Fixture::new();
    fx.add_branches(branches);
    let clone = fx.clone_dir();

    ok(
        &fx.kit(
            fx.work.path(),
            &["clone", "-o", "origin", &fx.url(), clone.to_str().unwrap()],
        ),
        "clone",
    );
    assert_eq!(tracked(&clone), branches + 1);
    let clone_sessions = fx.sessions();
    assert!(
        clone_sessions > 1,
        "a fetch of this size spends more than one session"
    );

    fx.commit("two");
    ok(&fx.kit(&clone, &["fetch", "origin"]), "fetch");
    assert_eq!(tracked(&clone), branches + 1);
    assert!(fx.sessions() > clone_sessions);

    fx.commit("three");
    ok(&fx.kit(&clone, &["pull", "origin"]), "pull");
    assert_eq!(tracked(&clone), branches + 1);
    assert_eq!(fs::read_to_string(clone.join("file.txt")).unwrap(), "three");
}

/// 5,100 branches with 30-character names: more than one session and six
/// pages of a listing.
#[test]
fn a_repository_with_thousands_of_branches_clones_fetches_and_pulls_over_ssh() {
    clones_fetches_and_pulls(SOME_BRANCHES);
}

/// 20,000 branches with 30-character names take about 1.6 MiB to list, more
/// than one frame holds. Every branch costs durable writes, so this runs in
/// the serial lane of long tests.
#[test]
#[ignore = "writes 20,000 tracking refs; runs in the ignored-lane profile"]
fn a_repository_with_many_branches_clones_fetches_and_pulls_over_ssh() {
    clones_fetches_and_pulls(MANY_BRANCHES);
}

/// A server that plays back `pages` as the answers to a fetch's listing of
/// branches, after the handshake, a refusal of the cursor request and an absent
/// attestation map.
fn fetch_against_pages(fx: &Fixture, pages: Vec<(Vec<&str>, Option<&str>)>) -> Output {
    let mut frames = vec![
        ssh_frame::Body::HelloResponse(Box::new(
            HelloResponse::default().with_proto(ProtocolVersion::ProtocolVersion1),
        )),
        ssh_frame::Body::Error(Box::new(
            RpcError::default()
                .with_code(ErrorCode::InvalidRequest)
                .with_message("unknown request"),
        )),
        // The read of the attestation map, which holds no value.
        ssh_frame::Body::ReadRefResponse(Box::default()),
    ];
    for (names, next) in pages {
        let refs = names
            .into_iter()
            .map(|name| RefEntry {
                name: Some(name.to_owned()),
                object_id: Some(vec![7; 32]),
                ..Default::default()
            })
            .collect();
        let page = ListRefsResponse {
            refs,
            next_page_token: next.map(str::to_owned),
            ..Default::default()
        };
        frames.push(ssh_frame::Body::ListRefsResponse(Box::new(page)));
    }
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
    fx.kit_with(
        &fx.source(),
        &["fetch", "origin"],
        &[("KIT_SSH_CANNED", &canned)],
    )
}

/// The fetch failed at once because of a reply that cannot be a listing, not
/// after a lost connection and its retries.
fn assert_invalid_response(out: &Output) {
    assert!(!out.status.success(), "{}", stderr(out));
    assert!(stderr(out).contains("invalid response"), "{}", stderr(out));
}

/// A server that sends a page token again, pages that are not in name order,
/// or an empty page with a token, cannot keep a client listing: the fetch fails with an invalid
/// response and ends.
#[test]
fn a_listing_that_repeats_a_token_or_leaves_name_order_fails() {
    let fx = Fixture::new();

    let out = fetch_against_pages(&fx, vec![(vec!["a"], Some("a")), (vec!["b"], Some("a"))]);
    assert_invalid_response(&out);

    let out = fetch_against_pages(&fx, vec![(vec!["b"], Some("b")), (vec!["a"], None)]);
    assert_invalid_response(&out);

    let out = fetch_against_pages(&fx, vec![(vec!["b", "a"], None)]);
    assert_invalid_response(&out);

    let out = fetch_against_pages(&fx, vec![(vec![], Some("a"))]);
    assert_invalid_response(&out);
}
