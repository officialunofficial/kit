//! `kit clone` and `kit fetch` take the remote's tags over `kit+ssh://`
//! (SPEC-TRANSPORT §1.4).
//!
//! The tests run the real `kit` binary against a real `kit serve`, through a
//! `/bin/sh` stand-in for `ssh`. Each seeds the served repository the way a
//! tag push leaves it: `refs/tags/<t>`, and `refs/kit/tagmap/<t>` naming a
//! pack list node grafted on the branch chain.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers
#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use kit_core::hash::{self, Hash};
use kit_core::layout::RepoLayout;
use kit_core::pack::{self, PackWriter};
use kit_core::protocol::{PackKey, RefWriteCondition, Transport};
use kit_core::refs;
use kit_core::store::ObjectStore;
use kit_transport_file::FileTransport;

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

/// A source repository with one signed commit, pushed to the served
/// `remote`.
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
        let url = format!("kit+file://{}", remote.display());
        ok(
            &fx.kit(&source, &["remote", "add", "origin", &url]),
            "remote add",
        );
        fx.commit_and_push("one");
        fx
    }

    fn kit(&self, dir: &Path, args: &[&str]) -> Output {
        run_in(dir, self.xdg.path(), args, &[])
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

    fn tx(&self) -> FileTransport {
        FileTransport::new(self.remote())
    }

    fn commit_and_push(&self, text: &str) {
        let source = self.source();
        fs::write(source.join("file.txt"), text).unwrap();
        ok(&self.kit(&source, &["add", "."]), "add");
        ok(&self.kit(&source, &["commit", "-m", text]), "commit");
        ok(&self.kit(&source, &["push", "origin"]), "push");
    }

    /// Publish the source's tag `t` on the remote. A lightweight tag reuses
    /// the branch chain. An annotated tag uploads one pack of its tag object
    /// and a node grafted on the branch chain.
    fn publish_tag(&self, t: &str) -> Hash {
        let layout = RepoLayout::single(self.source());
        let value = refs::read_tag(&layout, t).unwrap().unwrap();
        let tx = self.tx();
        let packmap = tx.read_ref("refs/kit/packmap/main").unwrap().unwrap();
        let store = ObjectStore::open(&layout).unwrap();
        let object = store.read_object(&value).unwrap();
        let map = if matches!(object, kit_core::object::Object::Tag(_)) {
            let mut writer = PackWriter::new();
            writer
                .push_raw(value, &kit_core::serialize::serialize(&object).unwrap())
                .unwrap();
            let bytes = writer.finish().unwrap();
            let key = pack::pack_key(&bytes);
            tx.upload_pack(&bytes, &PackKey::from_hash(key)).unwrap();
            let node = kit_core::transfer::encode_packlist(Some(packmap), &[key]).unwrap();
            let node_key = hash::hash(&node);
            tx.upload_blob(&node, &PackKey::from_hash(node_key))
                .unwrap();
            node_key
        } else {
            packmap
        };
        for (name, id) in [
            (format!("refs/kit/tagmap/{t}"), map),
            (format!("refs/tags/{t}"), value),
        ] {
            tx.update_ref(&name, RefWriteCondition::Any, &id).unwrap();
        }
        value
    }

    /// Run `kit <args>` in `dir` over the served remote.
    fn over_ssh(&self, dir: &Path, args: &[&str]) -> Output {
        run_in(
            dir,
            self.xdg.path(),
            args,
            &[
                ("KIT_SSH_PROGRAM", self.wrapper.to_str().unwrap()),
                ("KIT_SSH_TARGET_BIN", kit_bin()),
            ],
        )
    }

    fn url(&self) -> String {
        format!("kit+ssh://e2e@localhost{}", self.remote().display())
    }

    fn clone(&self) -> Output {
        let clone = self.clone_dir();
        self.over_ssh(
            self.work.path(),
            &[
                "clone",
                "-o",
                "origin",
                &self.url(),
                clone.to_str().unwrap(),
            ],
        )
    }

    fn local_tag(&self, t: &str) -> Option<Hash> {
        refs::read_tag(&RepoLayout::single(self.clone_dir()), t).unwrap()
    }

    fn tracking_main(&self) -> Option<Hash> {
        refs::read_remote_ref(&RepoLayout::single(self.clone_dir()), "origin", "main").unwrap()
    }
}

/// A lightweight tag and a signed annotated tag arrive with the clone, and
/// `kit verify` passes on the clone.
#[test]
fn a_clone_over_ssh_takes_lightweight_and_signed_tags() {
    let fx = Fixture::new();
    let source = fx.source();
    ok(&fx.kit(&source, &["tag", "v1"]), "tag v1");
    ok(
        &fx.kit(&source, &["tag", "-s", "v2", "-m", "release 2"]),
        "tag v2",
    );
    let v1 = fx.publish_tag("v1");
    let v2 = fx.publish_tag("v2");

    let out = fx.clone();

    ok(&out, "clone");
    let err = stderr(&out);
    assert!(err.contains(" * [new tag]         v1 -> v1"), "{err}");
    assert!(err.contains(" * [new tag]         v2 -> v2"), "{err}");
    assert_eq!(fx.local_tag("v1"), Some(v1));
    assert_eq!(fx.local_tag("v2"), Some(v2));
    ok(&fx.kit(&fx.clone_dir(), &["verify", "v2"]), "verify v2");
}

/// The remote moves a tag the clone holds. The fetch refuses it, exits 1,
/// and still publishes the branch.
#[test]
fn a_tag_that_would_clobber_a_local_tag_exits_1_and_the_branch_still_moves() {
    let fx = Fixture::new();
    let source = fx.source();
    ok(&fx.kit(&source, &["tag", "v1"]), "tag v1");
    let old = fx.publish_tag("v1");
    ok(&fx.clone(), "clone");
    fx.commit_and_push("two");
    ok(&fx.kit(&source, &["tag", "-d", "v1"]), "tag -d");
    ok(&fx.kit(&source, &["tag", "v1"]), "tag v1 again");
    let moved = fx.publish_tag("v1");
    assert_ne!(old, moved);
    let head = fx.tx().read_ref("refs/heads/main").unwrap();

    let out = fx.over_ssh(&fx.clone_dir(), &["fetch", "origin"]);

    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    let err = stderr(&out);
    assert!(err.contains(" ! [rejected]        v1 -> v1 ("), "{err}");
    assert_eq!(fx.local_tag("v1"), Some(old));
    assert_eq!(fx.tracking_main(), head);

    let out = fx.over_ssh(&fx.clone_dir(), &["fetch", "origin", "--format", "json"]);
    assert_eq!(out.status.code(), Some(1));
    let json = String::from_utf8_lossy(&out.stdout);
    assert!(json.contains(r#""ok":false"#), "{json}");
    assert!(
        json.contains(r#""tags_rejected":[{"name":"v1","reason":"#),
        "{json}"
    );
}

/// `--no-tags` skips the tag phase, and a later fetch takes the tags.
#[test]
fn fetch_no_tags_then_fetch_takes_the_tags() {
    let fx = Fixture::new();
    ok(&fx.kit(&fx.source(), &["tag", "v1"]), "tag v1");
    let v1 = fx.publish_tag("v1");
    let clone = fx.clone_dir();
    ok(
        &fx.over_ssh(
            fx.work.path(),
            &[
                "clone",
                "--no-tags",
                "-o",
                "origin",
                &fx.url(),
                clone.to_str().unwrap(),
            ],
        ),
        "clone --no-tags",
    );
    assert_eq!(fx.local_tag("v1"), None);

    ok(
        &fx.over_ssh(&clone, &["fetch", "origin", "--no-tags"]),
        "fetch --no-tags",
    );
    assert_eq!(fx.local_tag("v1"), None);
    ok(
        &fx.over_ssh(&clone, &["fetch", "origin", "--tags"]),
        "fetch --tags",
    );
    assert_eq!(fx.local_tag("v1"), Some(v1));
}

/// A tag listing larger than one `kit serve` frame fails. The fetch stops the
/// tag phase with the stated message and exits 1, and the branch is still
/// published.
#[test]
fn an_over_size_tag_listing_stops_only_the_tag_phase() {
    let fx = Fixture::new();
    ok(&fx.clone(), "clone");
    fx.commit_and_push("two");
    let head = fx.tx().read_ref("refs/heads/main").unwrap();
    // About 25,000 tags at the head, written as the ref files a file root
    // holds. One frame carries about 17,000 short names.
    let remote = fx.remote();
    let wire = fs::read(remote.join("refs/heads/main")).unwrap();
    let dir = remote.join("refs/tags");
    fs::create_dir_all(&dir).unwrap();
    for i in 0..25_000 {
        fs::write(dir.join(format!("bulk-{i:05}")), &wire).unwrap();
    }

    let out = fx.over_ssh(&fx.clone_dir(), &["fetch", "origin"]);

    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    let err = stderr(&out);
    assert!(
        err.contains("error: tag listing failed (possibly too many tags): "),
        "{err}"
    );
    assert_eq!(fx.tracking_main(), head);
    assert_eq!(fx.local_tag("bulk-00000"), None);
}

/// A refused tag fails the clone with exit 1, and the branch is still
/// checked out.
#[test]
fn a_clone_with_a_refused_tag_exits_1_and_checks_out_the_branch() {
    let fx = Fixture::new();
    let source = fx.source();
    ok(
        &fx.kit(&source, &["tag", "-s", "v1", "-m", "release 1"]),
        "tag v1",
    );
    // The tag ref with no tag map: its object is on no chain.
    let value = refs::read_tag(&RepoLayout::single(&source), "v1")
        .unwrap()
        .unwrap();
    fx.tx()
        .update_ref("refs/tags/v1", RefWriteCondition::Any, &value)
        .unwrap();

    let out = fx.clone();

    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    let err = stderr(&out);
    assert!(
        err.contains(" ! [rejected]        v1 -> v1 (the remote has no tag map for it)"),
        "{err}"
    );
    assert_eq!(fx.local_tag("v1"), None);
    assert_eq!(
        fs::read_to_string(fx.clone_dir().join("file.txt")).unwrap(),
        "one"
    );
}

/// The remote moves a tag the clone holds. The pull refuses it and exits 1
/// after the fast-forward of the branch.
#[test]
fn a_pull_that_refuses_a_tag_exits_1_after_the_fast_forward() {
    let fx = Fixture::new();
    let source = fx.source();
    ok(&fx.kit(&source, &["tag", "v1"]), "tag v1");
    let old = fx.publish_tag("v1");
    ok(&fx.clone(), "clone");
    fx.commit_and_push("two");
    ok(&fx.kit(&source, &["tag", "-d", "v1"]), "tag -d");
    ok(&fx.kit(&source, &["tag", "v1"]), "tag v1 again");
    fx.publish_tag("v1");

    let out = fx.over_ssh(&fx.clone_dir(), &["pull", "origin"]);

    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    let err = stderr(&out);
    assert!(err.contains(" ! [rejected]        v1 -> v1 ("), "{err}");
    assert_eq!(fx.local_tag("v1"), Some(old));
    assert_eq!(
        fs::read_to_string(fx.clone_dir().join("file.txt")).unwrap(),
        "two"
    );
}

/// A remote tag whose name no push could write warns, and the fetch exits 0.
#[test]
fn a_remote_tag_name_over_the_bound_warns_and_exits_0() {
    let fx = Fixture::new();
    ok(&fx.clone(), "clone");
    // 497 bytes in two directory levels, so each file name fits.
    let (dir, file) = ("d".repeat(248), "f".repeat(248));
    let remote = fx.remote();
    let wire = fs::read(remote.join("refs/heads/main")).unwrap();
    fs::create_dir_all(remote.join("refs/tags").join(&dir)).unwrap();
    fs::write(remote.join("refs/tags").join(&dir).join(&file), &wire).unwrap();
    let name = format!("{dir}/{file}");
    assert_eq!(name.len(), refs::MAX_TAG_NAME_BYTES + 1);

    let out = fx.over_ssh(&fx.clone_dir(), &["fetch", "origin"]);

    ok(&out, "fetch");
    let err = stderr(&out);
    assert!(
        err.contains(&format!("warning: skipped remote tag '{name}': ")),
        "{err}"
    );
    assert!(!fx.clone_dir().join(".kit/refs/tags").join(&dir).exists());
}
