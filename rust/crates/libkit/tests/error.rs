//! The library error type.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in tests

use std::error::Error as _;
use std::path::PathBuf;

use kit_core::layout::DiscoverError;
use kit_core::refs::RefError;
use kit_core::repo_lock::LockError;
use libkit::{Environment, Error, Repo, head, lock, repo, revspec, worktrees};

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

#[test]
fn every_module_error_converts_and_keeps_its_text() {
    let errors: Vec<Error> = vec![
        revspec::Error::Unknown("nope".to_owned()).into(),
        lock::Error::Registry(LockError::Busy("worktrees.lock".to_owned())).into(),
        head::Error::ReadHead(RefError::NoHead).into(),
        worktrees::Error::Registry(DiscoverError::PointerMalformed(PathBuf::from("/w"))).into(),
    ];
    assert!(matches!(errors[0], Error::Revspec(_)));
    assert!(matches!(errors[1], Error::Lock(_)));
    assert!(matches!(errors[2], Error::Head(_)));
    assert!(matches!(errors[3], Error::Worktrees(_)));
    assert_eq!(errors[0].to_string(), "unknown revision 'nope'");
    assert!(
        errors[1]
            .to_string()
            .starts_with("worktree registry lock: ")
    );
    assert!(errors[2].to_string().starts_with("read HEAD: "));
    assert!(errors[3].to_string().starts_with("worktree registry: "));
}
