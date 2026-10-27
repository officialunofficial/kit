//! Add, change, remove, rename and list remotes through the layout of a tree.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in tests
#![cfg(feature = "sync")]

use std::cell::RefCell;
use std::fs;
use std::path::Path;

use kit_core::layout::RepoLayout;
use kit_core::observer::{NoopObserver, Observer};
use kit_core::store::ObjectStore;
use libkit::config::{self, Config, RemoteEntry, Upstream};
use libkit::remote::{self, Error, Event, Remote};

#[derive(Default)]
struct Recorder {
    events: RefCell<Vec<Event>>,
}

impl Observer<Event> for Recorder {
    fn event(&self, event: &Event) {
        self.events.borrow_mut().push(event.clone());
    }
}

fn repo() -> (tempfile::TempDir, RepoLayout) {
    let dir = tempfile::tempdir().unwrap();
    let layout = RepoLayout::single(dir.path());
    ObjectStore::init(&layout).unwrap();
    (dir, layout)
}

/// The repo layer of the config, as the command reads it.
fn read(layout: &RepoLayout, home: &Path) -> Config {
    let env = libkit::Environment {
        home: Some(home.to_path_buf()),
        ..libkit::Environment::new(layout.worktree_root())
    };
    config::read_layered(layout, &env, &NoopObserver)
        .unwrap()
        .repo
}

fn touch(path: &Path) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, b"x").unwrap();
}

#[test]
fn add_sets_the_default_remote_and_a_named_remote() {
    let (dir, layout) = repo();
    let mut cfg = Config::default();
    remote::add(&layout, &mut cfg, None, "kit+https://example.test/r").unwrap();
    remote::add(&layout, &mut cfg, Some("origin"), "kit+ssh://host/r").unwrap();
    remote::add(
        &layout,
        &mut cfg,
        Some("bridge"),
        "git+https://example.test/g",
    )
    .unwrap();

    let stored = read(&layout, dir.path());
    assert_eq!(stored.remote_endpoint, "kit+https://example.test/r");
    assert_eq!(stored.remote_type, "http");
    assert_eq!(stored.remotes["origin"].remote_type, "ssh");
    assert_eq!(stored.remotes["bridge"].remote_type, "git");
}

#[test]
fn add_refuses_a_bad_address_and_writes_nothing() {
    let (_dir, layout) = repo();
    let mut cfg = Config::default();
    for url in ["https://example.test/r", "kit+ftp://x", "", "KIT+FILE:///r"] {
        let err = remote::add(&layout, &mut cfg, None, url).unwrap_err();
        assert!(
            matches!(err, Error::UnsupportedScheme(ref u) if u == url),
            "{url}"
        );
    }
    let err = remote::add(&layout, &mut cfg, None, "kit+file:///r\nremote.x.url = y").unwrap_err();
    assert!(matches!(err, Error::UrlControlCharacters(_)), "{err:?}");
    assert_eq!(
        err.to_string(),
        "invalid remote URL 'kit+file:///r\nremote.x.url = y': contains control characters"
    );
    assert_eq!(cfg, Config::default());
    assert!(!layout.config_file().exists());
}

#[test]
fn add_refuses_a_bad_name() {
    let (_dir, layout) = repo();
    let mut cfg = Config::default();
    for name in ["default", "a.b", "", "..", "a b\\c", "/x"] {
        let err = remote::add(&layout, &mut cfg, Some(name), "kit+file:///r").unwrap_err();
        assert!(matches!(err, Error::InvalidName(_)), "{name:?}: {err:?}");
    }
    let err = remote::add(&layout, &mut cfg, Some("a\nb"), "kit+file:///r").unwrap_err();
    assert!(matches!(err, Error::NameControlCharacters(_)), "{err:?}");
    assert!(cfg.remotes.is_empty());
}

#[test]
fn the_address_is_checked_before_the_name() {
    let (_dir, layout) = repo();
    let mut cfg = Config::default();
    let err = remote::add(&layout, &mut cfg, Some("default"), "nope").unwrap_err();
    assert!(matches!(err, Error::UnsupportedScheme(_)), "{err:?}");
}

#[test]
fn set_url_changes_the_default_and_a_named_remote() {
    let (dir, layout) = repo();
    let mut cfg = Config::default();
    remote::add(&layout, &mut cfg, None, "kit+file:///a").unwrap();
    remote::add(&layout, &mut cfg, Some("origin"), "kit+file:///b").unwrap();
    remote::set_url(&layout, &mut cfg, "default", "kit+s3://bucket/r").unwrap();
    remote::set_url(&layout, &mut cfg, "origin", "kit+https://h/r").unwrap();

    let stored = read(&layout, dir.path());
    assert_eq!(stored.remote_endpoint, "kit+s3://bucket/r");
    assert_eq!(stored.remote_type, "s3");
    assert_eq!(stored.remotes["origin"].url, "kit+https://h/r");
    assert_eq!(stored.remotes["origin"].remote_type, "http");
}

#[test]
fn set_url_needs_an_existing_remote() {
    let (_dir, layout) = repo();
    let mut cfg = Config::default();
    let err = remote::set_url(&layout, &mut cfg, "default", "kit+file:///a").unwrap_err();
    assert!(matches!(err, Error::NoDefault), "{err:?}");
    assert_eq!(err.to_string(), "no default remote configured");
    let err = remote::set_url(&layout, &mut cfg, "origin", "kit+file:///a").unwrap_err();
    assert!(
        matches!(err, Error::NotFound(ref n) if n == "origin"),
        "{err:?}"
    );
    assert_eq!(err.to_string(), "remote 'origin' not found");
    let err = remote::set_url(&layout, &mut cfg, "origin", "bad").unwrap_err();
    assert!(matches!(err, Error::UnsupportedScheme(_)), "{err:?}");
}

#[test]
fn url_of_reads_the_merged_config() {
    let mut merged = Config::default();
    assert!(matches!(
        remote::url_of(&merged, "default"),
        Err(Error::NotFound(_))
    ));
    merged.remote_endpoint = "kit+file:///a".to_owned();
    merged.remotes.insert(
        "origin".to_owned(),
        RemoteEntry {
            url: "kit+file:///b".to_owned(),
            remote_type: "file".to_owned(),
        },
    );
    assert_eq!(remote::url_of(&merged, "default").unwrap(), "kit+file:///a");
    assert_eq!(remote::url_of(&merged, "origin").unwrap(), "kit+file:///b");
    assert!(matches!(
        remote::url_of(&merged, "other"),
        Err(Error::NotFound(ref n)) if n == "other"
    ));
}

#[test]
fn list_gives_the_default_first_then_the_names_in_order() {
    let mut merged = Config::default();
    let empty = remote::list(&merged);
    assert!(empty.default.is_none() && empty.named.is_empty());

    merged.remote_endpoint = "kit+file:///a".to_owned();
    "file".clone_into(&mut merged.remote_type);
    for name in ["zed", "alpha"] {
        merged.remotes.insert(
            name.to_owned(),
            RemoteEntry {
                url: format!("kit+file:///{name}"),
                remote_type: "file".to_owned(),
            },
        );
    }
    let listing = remote::list(&merged);
    assert_eq!(
        listing.default,
        Some(Remote {
            name: "default".to_owned(),
            url: "kit+file:///a".to_owned(),
            transport: "file".to_owned(),
        })
    );
    let names: Vec<&str> = listing.named.iter().map(|r| r.name.as_str()).collect();
    assert_eq!(names, ["alpha", "zed"]);
}

#[test]
fn remove_drops_the_remote_and_its_tracking_refs() {
    let (dir, layout) = repo();
    let mut cfg = Config::default();
    remote::add(&layout, &mut cfg, Some("origin"), "kit+file:///b").unwrap();
    touch(&layout.remotes_dir().join("origin/main"));
    let recorder = Recorder::default();
    remote::remove(&layout, &mut cfg, "origin", &recorder).unwrap();

    assert!(read(&layout, dir.path()).remotes.is_empty());
    assert!(!layout.remotes_dir().join("origin").exists());
    assert!(recorder.events.borrow().is_empty());
    let err = remote::remove(&layout, &mut cfg, "origin", &recorder).unwrap_err();
    assert!(matches!(err, Error::NotFound(_)), "{err:?}");
}

#[test]
fn remove_default_clears_the_flat_remote() {
    let (dir, layout) = repo();
    let mut cfg = Config::default();
    let err = remote::remove(&layout, &mut cfg, "default", &NoopObserver).unwrap_err();
    assert!(matches!(err, Error::NoDefault), "{err:?}");
    remote::add(&layout, &mut cfg, None, "kit+file:///a").unwrap();
    remote::remove(&layout, &mut cfg, "default", &NoopObserver).unwrap();
    let stored = read(&layout, dir.path());
    assert!(stored.remote_endpoint.is_empty() && stored.remote_type.is_empty());
}

#[test]
fn remove_keeps_the_refs_of_a_nested_remote_and_says_the_bridge_state_stays() {
    let (_dir, layout) = repo();
    let mut cfg = Config::default();
    remote::add(&layout, &mut cfg, Some("a"), "kit+file:///a").unwrap();
    remote::add(&layout, &mut cfg, Some("a/b"), "kit+file:///ab").unwrap();
    touch(&layout.remotes_dir().join("a/main"));
    touch(&layout.remotes_dir().join("a/b/main"));
    touch(&layout.git_state_dir().join("a/map"));
    let recorder = Recorder::default();
    remote::remove(&layout, &mut cfg, "a", &recorder).unwrap();

    assert!(!layout.remotes_dir().join("a/main").exists());
    assert!(layout.remotes_dir().join("a/b/main").exists());
    assert!(layout.git_state_dir().join("a/map").exists());
    assert_eq!(
        *recorder.events.borrow(),
        [Event::BridgeStateRemains {
            name: "a".to_owned()
        }]
    );
}

#[test]
fn rename_moves_the_config_the_upstreams_and_the_state() {
    let (dir, layout) = repo();
    let mut cfg = Config::default();
    remote::add(&layout, &mut cfg, Some("origin"), "kit+file:///b").unwrap();
    cfg.branch_upstreams.insert(
        "main".to_owned(),
        Upstream {
            remote: "origin".to_owned(),
            branch: "main".to_owned(),
        },
    );
    cfg.branch_upstreams.insert(
        "dev".to_owned(),
        Upstream {
            remote: "other".to_owned(),
            branch: "dev".to_owned(),
        },
    );
    config::write(&layout, &cfg).unwrap();
    touch(&layout.remotes_dir().join("origin/main"));
    touch(&layout.git_state_dir().join("origin/map"));
    let recorder = Recorder::default();
    remote::rename(&layout, &mut cfg, "origin", "up", &recorder).unwrap();

    let stored = read(&layout, dir.path());
    assert!(!stored.remotes.contains_key("origin"));
    assert_eq!(stored.remotes["up"].url, "kit+file:///b");
    assert_eq!(stored.branch_upstreams["main"].remote, "up");
    assert_eq!(stored.branch_upstreams["dev"].remote, "other");
    assert!(layout.remotes_dir().join("up/main").exists());
    assert!(!layout.remotes_dir().join("origin").exists());
    assert!(layout.git_state_dir().join("up/map").exists());
    assert!(recorder.events.borrow().is_empty());
}

#[test]
fn rename_refuses_a_bad_request_and_changes_nothing() {
    let (_dir, layout) = repo();
    let mut cfg = Config::default();
    remote::add(&layout, &mut cfg, Some("one"), "kit+file:///1").unwrap();
    remote::add(&layout, &mut cfg, Some("two"), "kit+file:///2").unwrap();
    let before = cfg.clone();

    let err = remote::rename(&layout, &mut cfg, "default", "x", &NoopObserver).unwrap_err();
    assert!(matches!(err, Error::RenameDefault), "{err:?}");
    let err = remote::rename(&layout, &mut cfg, "one", "default", &NoopObserver).unwrap_err();
    assert!(matches!(err, Error::RenameDefault), "{err:?}");
    let err = remote::rename(&layout, &mut cfg, "one", "a.b", &NoopObserver).unwrap_err();
    assert!(matches!(err, Error::InvalidName(_)), "{err:?}");
    let err = remote::rename(&layout, &mut cfg, "none", "x", &NoopObserver).unwrap_err();
    assert!(
        matches!(err, Error::NotFound(ref n) if n == "none"),
        "{err:?}"
    );
    let err = remote::rename(&layout, &mut cfg, "one", "two", &NoopObserver).unwrap_err();
    assert!(
        matches!(err, Error::AlreadyExists(ref n) if n == "two"),
        "{err:?}"
    );
    assert_eq!(err.to_string(), "remote 'two' already exists");
    assert_eq!(cfg, before);
}

#[test]
fn rename_between_a_prefix_and_its_extension_moves_the_state() {
    let (_dir, layout) = repo();
    let mut cfg = Config::default();
    remote::add(&layout, &mut cfg, Some("a"), "kit+file:///a").unwrap();
    touch(&layout.remotes_dir().join("a/main"));
    let recorder = Recorder::default();
    remote::rename(&layout, &mut cfg, "a", "a/sub", &recorder).unwrap();
    assert!(layout.remotes_dir().join("a/sub/main").exists());
    remote::rename(&layout, &mut cfg, "a/sub", "a", &recorder).unwrap();
    assert!(layout.remotes_dir().join("a/main").exists());
    assert!(recorder.events.borrow().is_empty());
}

#[test]
fn rename_keeps_a_nested_remote_in_place() {
    let (_dir, layout) = repo();
    let mut cfg = Config::default();
    remote::add(&layout, &mut cfg, Some("a"), "kit+file:///a").unwrap();
    remote::add(&layout, &mut cfg, Some("a/b"), "kit+file:///ab").unwrap();
    touch(&layout.remotes_dir().join("a/main"));
    touch(&layout.remotes_dir().join("a/b/main"));
    remote::rename(&layout, &mut cfg, "a", "c", &NoopObserver).unwrap();
    assert!(layout.remotes_dir().join("c/main").exists());
    assert!(layout.remotes_dir().join("a/b/main").exists());
    assert!(!layout.remotes_dir().join("a/main").exists());
}

#[test]
fn rename_into_an_occupied_sibling_fails_closed() {
    let (_dir, layout) = repo();
    let mut cfg = Config::default();
    remote::add(&layout, &mut cfg, Some("a/b"), "kit+file:///ab").unwrap();
    remote::add(&layout, &mut cfg, Some("a/x"), "kit+file:///ax").unwrap();
    touch(&layout.remotes_dir().join("a/b/main"));
    touch(&layout.remotes_dir().join("a/x/main"));
    let recorder = Recorder::default();
    remote::rename(&layout, &mut cfg, "a/b", "a", &recorder).unwrap();

    // The config changed. The tracking refs did not move, and the event says so.
    assert!(layout.remotes_dir().join("a/b/main").exists());
    assert!(layout.remotes_dir().join("a/x/main").exists());
    let events = recorder.events.borrow();
    assert!(
        matches!(
            events.as_slice(),
            [Event::TrackingRefsNotMoved { old, new, .. }] if old == "a/b" && new == "a"
        ),
        "{events:?}"
    );
}
