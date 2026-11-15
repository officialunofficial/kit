//! `kit push --tags` and `kit push <remote> <tag>` (SPEC-TRANSPORT §7.2).
//!
//! The ssh tests run the real `kit` binary against a real `kit serve`,
//! through a `/bin/sh` stand-in for `ssh`, and clone the result back.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers
#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use kit_core::hash::Hash;
use kit_core::layout::RepoLayout;
use kit_core::protocol::Transport;
use kit_core::refs;
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

/// An `ssh` stand-in that runs `kit serve <path>`.
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
exec "$KIT_SSH_TARGET_BIN" serve "$path"
"#;
    fs::write(&wrapper, script).unwrap();
    let mut perms = fs::metadata(&wrapper).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&wrapper, perms).unwrap();
    wrapper
}

/// A source repository with one signed commit on `main`, and an empty
/// served repository named as the remote `origin` over `kit+ssh://`.
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
        fx
    }

    /// Run `kit <args>` in `dir`, isolated from the developer's environment,
    /// with `ssh` standing for `kit serve`.
    fn kit(&self, dir: &Path, args: &[&str]) -> Output {
        Command::new(kit_bin())
            .args(args)
            .current_dir(dir)
            .env("XDG_CONFIG_HOME", self.xdg.path())
            .env("HOME", self.xdg.path())
            .env("EDITOR", "true")
            .env("VISUAL", "true")
            .env("KIT_SSH_PROGRAM", &self.wrapper)
            .env("KIT_SSH_TARGET_BIN", kit_bin())
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

    fn tx(&self) -> FileTransport {
        FileTransport::new(self.remote())
    }

    fn commit(&self, text: &str) {
        let source = self.source();
        fs::write(source.join("file.txt"), text).unwrap();
        ok(&self.kit(&source, &["add", "."]), "add");
        ok(&self.kit(&source, &["commit", "-m", text]), "commit");
    }

    fn local_tag(dir: &Path, t: &str) -> Option<Hash> {
        refs::read_tag(&RepoLayout::single(dir), t).unwrap()
    }

    fn push(&self, args: &[&str]) -> Output {
        let mut full = vec!["push"];
        full.extend_from_slice(args);
        self.kit(&self.source(), &full)
    }
}

/// `push --tags` over ssh publishes a lightweight and a signed tag with
/// their tag maps; a clone over ssh takes both, the signed tag verifies, and
/// its object is the same bytes as the source's.
#[test]
fn tags_pushed_over_ssh_clone_and_verify() {
    let fx = Fixture::new();
    let source = fx.source();
    ok(&fx.push(&["origin"]), "push main");
    ok(&fx.kit(&source, &["tag", "v1"]), "tag v1");
    fx.commit("two");
    ok(
        &fx.kit(&source, &["tag", "-s", "v2", "-m", "release 2"]),
        "tag v2",
    );

    let out = fx.push(&["origin", "--tags"]);

    ok(&out, "push --tags");
    let err = stderr(&out);
    assert!(err.contains(" * [new tag]         v1 -> v1"), "{err}");
    assert!(err.contains(" * [new tag]         v2 -> v2"), "{err}");
    let tx = fx.tx();
    for t in ["v1", "v2"] {
        assert_eq!(
            tx.read_ref(&format!("refs/tags/{t}")).unwrap(),
            Fixture::local_tag(&source, t)
        );
        assert!(
            tx.read_ref(&format!("refs/kit/tagmap/{t}"))
                .unwrap()
                .is_some()
        );
    }
    let again = fx.push(&["origin", "--tags"]);
    ok(&again, "push --tags again");
    assert!(stderr(&again).contains("Everything up-to-date"));

    let clone = fx.clone_dir();
    ok(
        &fx.kit(
            fx.work.path(),
            &["clone", "-o", "origin", &fx.url(), clone.to_str().unwrap()],
        ),
        "clone",
    );
    let v2 = Fixture::local_tag(&clone, "v2").unwrap();
    assert_eq!(Some(v2), Fixture::local_tag(&source, "v2"));
    assert_eq!(
        Fixture::local_tag(&clone, "v1"),
        Fixture::local_tag(&source, "v1")
    );
    ok(&fx.kit(&clone, &["verify", "v2"]), "verify v2");
    let bytes = |dir: &Path| {
        kit_core::store::ObjectStore::open(&RepoLayout::single(dir))
            .unwrap()
            .read(&v2)
            .unwrap()
    };
    assert_eq!(bytes(&clone), bytes(&source));
}

/// A tag push over ssh refuses a new tag that would take the remote's tag
/// listing past one frame, before it writes anything, and exits 1.
#[test]
fn a_tag_past_the_ssh_listing_bound_is_refused() {
    let fx = Fixture::new();
    ok(&fx.push(&["origin"]), "push main");
    // Tags of 200-byte names at the head, written as the ref files a file
    // root holds, filling the listing to just past the bound.
    let remote = fx.remote();
    let wire = fs::read(remote.join("refs/heads/main")).unwrap();
    let dir = remote.join("refs/tags");
    fs::create_dir_all(&dir).unwrap();
    let count = kit_sync::push::MAX_TAG_LISTING_BYTES / (200 + 48) + 1;
    for i in 0..count {
        fs::write(dir.join(format!("{i:0200}")), &wire).unwrap();
    }
    ok(&fx.kit(&fx.source(), &["tag", "v1"]), "tag v1");

    let out = fx.push(&["origin", "v1"]);

    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    let err = stderr(&out);
    assert!(
        err.contains(" ! [rejected]        v1 -> v1 (the remote holds too many tags to list)"),
        "{err}"
    );
    assert_eq!(fx.tx().read_ref("refs/tags/v1").unwrap(), None);
    assert_eq!(fx.tx().read_ref("refs/kit/tagmap/v1").unwrap(), None);
}

/// `kit push <remote> <tag>` pushes that tag alone, by its bare name or its
/// `refs/tags/` name; a name that is both a branch and a tag is refused.
#[test]
fn a_named_tag_pushes_alone_and_an_ambiguous_name_is_refused() {
    let fx = Fixture::new();
    let source = fx.source();
    ok(&fx.push(&["origin"]), "push main");
    ok(&fx.kit(&source, &["tag", "v1"]), "tag v1");
    ok(&fx.kit(&source, &["tag", "v2"]), "tag v2");

    let out = fx.push(&["origin", "v1", "--format", "json"]);

    ok(&out, "push origin v1");
    let json = String::from_utf8_lossy(&out.stdout);
    assert!(json.contains(r#""ok":true"#), "{json}");
    assert!(json.contains(r#""tags_pushed":1"#), "{json}");
    let tx = fx.tx();
    assert!(tx.read_ref("refs/tags/v1").unwrap().is_some());
    assert_eq!(tx.read_ref("refs/tags/v2").unwrap(), None);
    ok(&fx.push(&["origin", "refs/tags/v2"]), "push refs/tags/v2");
    assert!(tx.read_ref("refs/tags/v2").unwrap().is_some());

    ok(&fx.kit(&source, &["branch", "v1"]), "branch v1");
    let out = fx.push(&["origin", "v1"]);
    assert_eq!(out.status.code(), Some(64), "{}", stderr(&out));
    assert!(stderr(&out).contains("v1"), "{}", stderr(&out));

    let out = fx.push(&["origin", "refs/tags/missing"]);
    assert_eq!(out.status.code(), Some(65), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("tag 'missing' does not exist"),
        "{}",
        stderr(&out)
    );

    let out = fx.push(&["origin", "--tags", "--all"]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("cannot be used with"),
        "{}",
        stderr(&out)
    );
}
