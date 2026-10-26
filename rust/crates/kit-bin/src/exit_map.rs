//! The map from library errors to the exit codes in `docs/CLI.md`.
//!
//! This table is the one place that decides which code a library error
//! gets. A command turns a [`libkit::Error`] into a code with [`exit_code`]
//! and into the text for stderr with [`message`].

use kit_core::store::StoreError;
use libkit::repo;

use crate::exit;

/// The exit code for `error`.
///
/// An error variant that this table does not list yet fails closed with
/// [`exit::GENERAL_ERROR`].
#[must_use]
pub fn exit_code(error: &libkit::Error) -> u8 {
    match error {
        libkit::Error::Repo(inner) => repo_exit_code(inner),
        _ => exit::GENERAL_ERROR,
    }
}

#[allow(clippy::match_same_arms)] // the table lists each variant, even when its code equals the fallback
fn repo_exit_code(error: &repo::Error) -> u8 {
    match error {
        // The caller named a path that the library refuses.
        repo::Error::PathTraversal(_) => exit::USAGE,
        // The working directory is unusable, so there is no input to read.
        repo::Error::NotAbsolute(_) => exit::NOINPUT,
        repo::Error::NotARepository(_) | repo::Error::Store(_) => exit::GENERAL_ERROR,
        // A broken linked-worktree pointer is malformed input.
        repo::Error::Discover(_) => exit::DATAERR,
        _ => exit::GENERAL_ERROR,
    }
}

/// The text that follows `error: ` on stderr for `error`.
#[must_use]
pub fn message(error: &libkit::Error) -> String {
    match error {
        libkit::Error::Repo(repo::Error::Discover(inner)) => {
            format!("worktree discovery: {inner}")
        }
        libkit::Error::Repo(repo::Error::NotARepository(_)) => {
            format!("not a kit repo: {}", StoreError::NotAKitRepository)
        }
        libkit::Error::Repo(repo::Error::Store(inner)) => format!("not a kit repo: {inner}"),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use kit_core::layout::DiscoverError;

    use super::*;

    fn path() -> PathBuf {
        PathBuf::from("/work")
    }

    /// Every library error variant with the code that `docs/CLI.md` assigns.
    fn table() -> Vec<(libkit::Error, u8)> {
        vec![
            (repo::Error::PathTraversal(path()).into(), exit::USAGE),
            (repo::Error::NotAbsolute(path()).into(), exit::NOINPUT),
            (
                repo::Error::NotARepository(path()).into(),
                exit::GENERAL_ERROR,
            ),
            (
                repo::Error::Discover(DiscoverError::PointerMalformed(path())).into(),
                exit::DATAERR,
            ),
            (
                repo::Error::Store(StoreError::AlreadyInitialized).into(),
                exit::GENERAL_ERROR,
            ),
        ]
    }

    #[test]
    fn each_variant_has_its_documented_code() {
        for (error, code) in table() {
            assert_eq!(exit_code(&error), code, "{error:?}");
        }
    }

    #[test]
    fn every_code_is_a_documented_code() {
        let documented = [
            exit::OK,
            exit::GENERAL_ERROR,
            exit::USAGE,
            exit::DATAERR,
            exit::NOINPUT,
            exit::UNAVAILABLE,
            exit::SOFTWARE,
            exit::CANTCREAT,
            exit::TEMPFAIL,
            exit::PROTOCOL_ERROR,
            exit::NOPERM,
            exit::CONFIG_ERROR,
        ];
        for (error, _) in table() {
            assert!(documented.contains(&exit_code(&error)), "{error:?}");
        }
    }

    #[test]
    fn messages_keep_the_established_wording() {
        let discover: libkit::Error =
            repo::Error::Discover(DiscoverError::PointerMalformed(path())).into();
        assert!(message(&discover).starts_with("worktree discovery: "));
        let missing: libkit::Error = repo::Error::NotARepository(path()).into();
        assert_eq!(
            message(&missing),
            "not a kit repo: path is not a kit repository (missing .kit/objects)"
        );
        let store: libkit::Error = repo::Error::Store(StoreError::AlreadyInitialized).into();
        assert_eq!(
            message(&store),
            "not a kit repo: .kit already exists in this directory"
        );
        let traversal: libkit::Error = repo::Error::PathTraversal(path()).into();
        assert!(message(&traversal).contains(".."));
    }
}
