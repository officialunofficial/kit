//! The library error type.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in tests

use std::error::Error as _;
use std::path::PathBuf;

use libkit::{Environment, Error, Repo, repo};

fn assert_error<T: std::error::Error + Send + Sync + 'static>() {}

#[test]
fn error_types_meet_the_error_contract() {
    assert_error::<Error>();
    assert_error::<repo::Error>();
}

#[test]
fn a_module_error_converts_and_keeps_its_text() {
    let inner = repo::Error::PathTraversal(PathBuf::from("../x"));
    let text = inner.to_string();
    let error = Error::from(inner);
    assert!(matches!(
        error,
        Error::Repo(repo::Error::PathTraversal(ref p)) if p == &PathBuf::from("../x")
    ));
    assert_eq!(error.to_string(), text);
    assert!(error.source().is_none());
}

#[test]
fn the_question_mark_operator_wraps_a_repo_failure() {
    fn open(dir: &std::path::Path) -> Result<Repo, Error> {
        Ok(Repo::open(dir, &Environment::new(dir))?)
    }
    let dir = tempfile::tempdir().unwrap();
    let error = open(dir.path()).unwrap_err();
    assert!(matches!(error, Error::Repo(repo::Error::NotARepository(_))));
}

#[test]
fn a_store_cause_keeps_its_text() {
    let io = std::io::Error::other("disk");
    let inner = repo::Error::Store(kit_core::store::StoreError::Io(io));
    let error = Error::from(inner);
    assert!(error.to_string().contains("disk"));
}
