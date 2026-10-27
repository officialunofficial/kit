//! Plan a push, and record the upstream, through the layout of a tree.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in tests
#![cfg(feature = "sync")]

use std::path::Path;

use kit_core::hash::Hash;
use kit_core::layout::RepoLayout;
use kit_core::object::{Commit, Identity, Object};
use kit_core::observer::NoopObserver;
use kit_core::refs;
use kit_core::serialize;
use kit_core::store::ObjectStore;
use libkit::Environment;
use libkit::config::{self, Config, LayeredConfig, RemoteEntry, Upstream};
use libkit::push::{self, Error, PushLease};

fn commit(store: &ObjectStore, parents: Vec<Hash>, message: &[u8]) -> Hash {
    let commit = Commit::new_unannotated(
        [1; 32],
        parents,
        Identity::ed25519([1; 32]),
        [1; 32],
        message.to_vec(),
        0,
        [0; 64],
    );
    store
        .write(&serialize::serialize(&Object::Commit(commit)).unwrap())
        .unwrap()
}

/// A repository on `main` with the history `root <- tip`.
fn repo() -> (tempfile::TempDir, RepoLayout, Hash, Hash) {
    let dir = tempfile::tempdir().unwrap();
    let layout = RepoLayout::single(dir.path());
    let store = ObjectStore::init(&layout).unwrap();
    refs::init(&layout).unwrap();
    let root = commit(&store, vec![], b"root");
    let tip = commit(&store, vec![root], b"tip");
    refs::write_ref(&layout, "main", &tip).unwrap();
    refs::write_head_branch(&layout, "main").unwrap();
    (dir, layout, root, tip)
}

fn environment(dir: &Path) -> Environment {
    Environment {
        home: Some(dir.to_path_buf()),
        ..Environment::new(dir)
    }
}

fn layered(layout: &RepoLayout, dir: &Path) -> LayeredConfig {
    config::read_layered(layout, &environment(dir), &NoopObserver).unwrap()
}

fn with_remotes(layout: &RepoLayout) {
    let mut cfg = Config::default();
    cfg.remotes.insert(
        "origin".to_owned(),
        RemoteEntry {
            url: "kit+file:///origin".to_owned(),
            remote_type: "file".to_owned(),
        },
    );
    config::write(layout, &cfg).unwrap();
}

#[test]
fn the_force_switches_give_one_lease() {
    assert!(matches!(
        push::lease(false, false).unwrap(),
        PushLease::FastForward
    ));
    assert!(matches!(
        push::lease(true, false).unwrap(),
        PushLease::Force
    ));
    assert!(matches!(
        push::lease(false, true).unwrap(),
        PushLease::WithLease
    ));
    let err = push::lease(true, true).unwrap_err();
    assert!(matches!(err, Error::ConflictingForce), "{err:?}");
    assert_eq!(
        err.to_string(),
        "--force and --force-with-lease are mutually exclusive"
    );
}

#[test]
fn a_named_remote_receives_the_branch_under_its_own_name() {
    let (dir, layout, root, tip) = repo();
    with_remotes(&layout);
    refs::write_remote_ref(&layout, "origin", "main", &root).unwrap();
    let plan = push::plan(&layout, &layered(&layout, dir.path()), Some("origin")).unwrap();
    assert_eq!(plan.branch, "main");
    assert_eq!(plan.remote.name, "origin");
    assert_eq!(plan.remote.endpoint, "kit+file:///origin");
    assert_eq!(plan.remote_branch, "main");
    assert_eq!(plan.local_tip, Some(tip));
    assert_eq!(plan.tracked, Some(root));
    assert!(!plan.is_up_to_date(false));
}

#[test]
fn a_branch_that_the_remote_holds_is_up_to_date_unless_forced() {
    let (dir, layout, _root, tip) = repo();
    with_remotes(&layout);
    refs::write_remote_ref(&layout, "origin", "main", &tip).unwrap();
    let plan = push::plan(&layout, &layered(&layout, dir.path()), Some("origin")).unwrap();
    assert!(plan.is_up_to_date(false));
    assert!(!plan.is_up_to_date(true));
}

#[test]
fn the_upstream_decides_when_no_remote_is_named() {
    let (dir, layout, _root, _tip) = repo();
    let mut cfg = Config::default();
    cfg.remotes.insert(
        "origin".to_owned(),
        RemoteEntry {
            url: "kit+file:///origin".to_owned(),
            remote_type: "file".to_owned(),
        },
    );
    cfg.branch_upstreams.insert(
        "main".to_owned(),
        Upstream {
            remote: "origin".to_owned(),
            branch: "trunk".to_owned(),
        },
    );
    config::write(&layout, &cfg).unwrap();
    let plan = push::plan(&layout, &layered(&layout, dir.path()), None).unwrap();
    assert_eq!(plan.remote.name, "origin");
    assert_eq!(plan.remote_branch, "trunk");
}

#[test]
fn the_default_remote_is_the_upstream_when_none_is_set() {
    let (dir, layout, _root, _tip) = repo();
    let cfg = Config {
        remote_endpoint: "kit+file:///default".to_owned(),
        remote_type: "file".to_owned(),
        ..Config::default()
    };
    config::write(&layout, &cfg).unwrap();
    let plan = push::plan(&layout, &layered(&layout, dir.path()), None).unwrap();
    assert_eq!(plan.remote.name, "default");
    assert_eq!(plan.remote_branch, "main");
}

#[test]
fn a_plan_names_what_is_missing() {
    let (dir, layout, tip, _) = {
        let (dir, layout, root, tip) = repo();
        (dir, layout, tip, root)
    };
    let cfg = layered(&layout, dir.path());
    let err = push::plan(&layout, &cfg, None).unwrap_err();
    assert!(
        matches!(err, Error::NoUpstream(ref b) if b == "main"),
        "{err:?}"
    );
    assert!(
        err.to_string()
            .starts_with("no upstream configured for branch 'main'")
    );
    let err = push::plan(&layout, &cfg, Some("nope")).unwrap_err();
    assert!(
        matches!(err, Error::UnknownRemote(ref n) if n == "nope"),
        "{err:?}"
    );
    assert_eq!(
        err.to_string(),
        "unknown remote 'nope' — add it with `kit remote add nope <url>`"
    );
    refs::write_head_detached(&layout, &tip).unwrap();
    let err = push::plan(&layout, &cfg, Some("nope")).unwrap_err();
    assert!(matches!(err, Error::DetachedHead), "{err:?}");
}

#[test]
fn a_mirror_push_resolves_the_default_remote_or_the_named_one() {
    let (dir, layout, _root, _tip) = repo();
    let cfg = layered(&layout, dir.path());
    let err = push::plan_all(&cfg, None).unwrap_err();
    assert!(matches!(err, Error::NoRemote), "{err:?}");
    with_remotes(&layout);
    let cfg = layered(&layout, dir.path());
    assert_eq!(push::plan_all(&cfg, Some("origin")).unwrap().name, "origin");
    assert!(matches!(push::plan_all(&cfg, None), Err(Error::NoRemote)));
}

#[test]
fn a_fast_forward_needs_the_old_tip_to_be_an_ancestor() {
    let (_dir, layout, root, tip) = repo();
    let store = ObjectStore::open(&layout).unwrap();
    let other = commit(&store, vec![root], b"other");
    assert!(push::is_fast_forward(&layout, None, tip).unwrap());
    assert!(push::is_fast_forward(&layout, Some(tip), tip).unwrap());
    assert!(push::is_fast_forward(&layout, Some(root), tip).unwrap());
    assert!(!push::is_fast_forward(&layout, Some(tip), root).unwrap());
    assert!(!push::is_fast_forward(&layout, Some(other), tip).unwrap());
}

fn upstream(remote: &str, branch: &str) -> Upstream {
    Upstream {
        remote: remote.to_owned(),
        branch: branch.to_owned(),
    }
}

#[test]
fn the_first_push_records_the_upstream_and_a_later_one_keeps_it() {
    let (dir, layout, _root, _tip) = repo();
    let env = environment(dir.path());
    let cfg = layered(&layout, dir.path());
    push::record_upstream(
        &layout,
        &cfg,
        &env,
        &NoopObserver,
        "main",
        upstream("origin", "main"),
        false,
    )
    .unwrap();
    let cfg = layered(&layout, dir.path());
    assert_eq!(
        cfg.repo.branch_upstreams["main"],
        upstream("origin", "main")
    );

    push::record_upstream(
        &layout,
        &cfg,
        &env,
        &NoopObserver,
        "main",
        upstream("other", "main"),
        false,
    )
    .unwrap();
    let cfg = layered(&layout, dir.path());
    assert_eq!(
        cfg.repo.branch_upstreams["main"],
        upstream("origin", "main")
    );

    push::record_upstream(
        &layout,
        &cfg,
        &env,
        &NoopObserver,
        "main",
        upstream("other", "trunk"),
        true,
    )
    .unwrap();
    let cfg = layered(&layout, dir.path());
    assert_eq!(
        cfg.repo.branch_upstreams["main"],
        upstream("other", "trunk")
    );
}
