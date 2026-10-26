//! The repository handle and its environment.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in tests

use std::fs;
use std::path::Path;

use kit_core::layout::RepoLayout;
use kit_core::store::ObjectStore;
use libkit::repo::Error;
use libkit::{Environment, Repo};

fn assert_send_sync<T: Send + Sync>() {}

fn init(root: &Path) {
    ObjectStore::init(&RepoLayout::single(root)).unwrap();
}

#[test]
fn handle_types_are_send_and_sync() {
    assert_send_sync::<Repo>();
    assert_send_sync::<Environment>();
    assert_send_sync::<Error>();
}

#[test]
fn open_finds_the_repository() {
    let dir = tempfile::tempdir().unwrap();
    init(dir.path());
    let env = Environment::new(dir.path());
    let repo = Repo::open(dir.path(), &env).unwrap();
    assert_eq!(repo.layout().worktree_root(), dir.path());
    assert_eq!(repo.environment().cwd, dir.path());
    let clone = repo.clone();
    assert_eq!(clone.layout(), repo.layout());
}

#[test]
fn open_resolves_a_relative_path_against_the_environment() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir(dir.path().join("proj")).unwrap();
    init(&dir.path().join("proj"));
    let env = Environment::new(dir.path());
    let repo = Repo::open(Path::new("proj"), &env).unwrap();
    assert_eq!(repo.layout().worktree_root(), dir.path().join("proj"));
}

#[test]
fn discover_walks_up_from_a_subdirectory() {
    let dir = tempfile::tempdir().unwrap();
    init(dir.path());
    let sub = dir.path().join("a").join("b");
    fs::create_dir_all(&sub).unwrap();
    let env = Environment::new(&sub);
    let repo = Repo::discover(&sub, &env).unwrap();
    assert_eq!(repo.layout().worktree_root(), dir.path());
    let repo = Repo::discover(Path::new("."), &env).unwrap();
    assert_eq!(repo.layout().worktree_root(), dir.path());
}

#[test]
fn missing_repository_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let env = Environment::new(dir.path());
    assert!(matches!(
        Repo::open(dir.path(), &env),
        Err(Error::NotARepository(_))
    ));
    let sub = dir.path().join("sub");
    fs::create_dir(&sub).unwrap();
    // A missing repository above the temp directory is not guaranteed on
    // every host, so only the open path asserts the exact error.
    if let Err(e) = Repo::discover(&sub, &env) {
        assert!(matches!(e, Error::NotARepository(_)));
    }
}

#[test]
fn directory_without_objects_is_not_a_repository() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir(dir.path().join(".kit")).unwrap();
    let env = Environment::new(dir.path());
    assert!(matches!(
        Repo::open(dir.path(), &env),
        Err(Error::NotARepository(_))
    ));
    assert!(matches!(
        Repo::discover(dir.path(), &env),
        Err(Error::NotARepository(_))
    ));
}

#[test]
fn parent_components_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    init(dir.path());
    let sub = dir.path().join("sub");
    fs::create_dir(&sub).unwrap();
    let env = Environment::new(&sub);
    assert!(matches!(
        Repo::open(Path::new(".."), &env),
        Err(Error::PathTraversal(_))
    ));
    assert!(matches!(
        Repo::discover(Path::new("../.."), &env),
        Err(Error::PathTraversal(_))
    ));
    let sneaky = sub.join("..");
    assert!(matches!(
        Repo::open(&sneaky, &env),
        Err(Error::PathTraversal(_))
    ));
}

#[test]
fn relative_working_directory_is_refused() {
    let env = Environment::new("relative");
    assert!(matches!(
        Repo::open(Path::new("x"), &env),
        Err(Error::NotAbsolute(_))
    ));
}
