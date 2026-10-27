//! Moving the current branch or a detached HEAD.

use kit_core::hash::Hash;
use kit_core::layout::RepoLayout;
use kit_core::refs::{self, Head, RefError, RefWriteCondition};

/// Errors from moving HEAD.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// HEAD could not be read. The function wrote nothing. In particular it
    /// does not guess a branch name, because a guess could create or
    /// overwrite a branch that the user never had.
    #[error("read HEAD: {0}")]
    ReadHead(RefError),
    /// The branch ref could not be written. A [`RefError::Conflict`] inside
    /// means the branch no longer matched the condition of the caller.
    #[error("write ref: {source}")]
    WriteRef {
        /// The branch that HEAD names.
        branch: String,
        /// Why the write failed.
        source: RefError,
    },
    /// The detached HEAD could not be written.
    #[error("update HEAD: {0}")]
    WriteHead(RefError),
}

/// Point the current branch, or a detached HEAD, at `new_head`.
///
/// A branch write goes through [`refs::write_ref_recording_history`], so a
/// build with `history-mmr` publishes the ancestry of the branch under its
/// history and ref guards. `condition` guards that write: pass
/// [`RefWriteCondition::Match`] with the tip that the new commit was built on
/// to refuse a write that would discard a concurrent advance. A detached HEAD
/// has no branch name, so `condition` does not apply to it.
///
/// The caller holds the worktree lock when the operation also changes the
/// index or the files. See [`crate::lock`].
///
/// # Errors
/// [`Error::ReadHead`] when HEAD is unreadable or missing. [`Error::WriteRef`]
/// or [`Error::WriteHead`] when the write fails.
pub fn advance(
    layout: &RepoLayout,
    new_head: &Hash,
    condition: RefWriteCondition,
) -> Result<(), Error> {
    match refs::read_head(layout).map_err(Error::ReadHead)? {
        Head::Branch(branch) => {
            refs::write_ref_recording_history(layout, &branch, condition, new_head)
                .map_err(|source| Error::WriteRef { branch, source })
        }
        Head::Detached(_) => refs::write_head_detached(layout, new_head).map_err(Error::WriteHead),
    }
}

#[cfg(test)]
mod tests {
    use kit_core::object::{Commit, Identity, Object};
    use kit_core::serialize;
    use kit_core::store::ObjectStore;

    use super::*;

    fn fresh_repo() -> (tempfile::TempDir, RepoLayout) {
        let dir = tempfile::tempdir().unwrap();
        let layout = RepoLayout::single(dir.path());
        // Ancestry publication reads the real first-parent graph.
        ObjectStore::init(&layout).unwrap();
        refs::init(&layout).unwrap();
        (dir, layout)
    }

    fn commit(layout: &RepoLayout, message: &[u8], parents: Vec<Hash>) -> Hash {
        let store = ObjectStore::open(layout).unwrap();
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

    fn seed_main(layout: &RepoLayout, tip: &Hash) {
        refs::write_ref_recording_history(layout, "main", RefWriteCondition::Missing, tip).unwrap();
    }

    #[test]
    fn a_missing_head_is_an_error_and_writes_no_branch() {
        let dir = tempfile::tempdir().unwrap();
        let layout = RepoLayout::single(dir.path());
        let err = advance(&layout, &[0x11; 32], RefWriteCondition::Any).unwrap_err();
        assert!(matches!(err, Error::ReadHead(_)), "got {err:?}");
        assert!(err.to_string().starts_with("read HEAD: "));
        assert!(
            !layout.heads_dir().join("main").exists(),
            "advance must not create refs/heads/main when HEAD is unreadable"
        );
    }

    #[test]
    fn an_unconditional_advance_moves_the_branch() {
        let (_dir, layout) = fresh_repo();
        let t0 = commit(&layout, b"t0", vec![]);
        seed_main(&layout, &t0);
        let c1 = commit(&layout, b"c1", vec![t0]);
        advance(&layout, &c1, RefWriteCondition::Any).unwrap();
        assert_eq!(refs::read_ref(&layout, "main").unwrap(), Some(c1));
    }

    #[test]
    fn a_matching_condition_advances_the_branch() {
        let (_dir, layout) = fresh_repo();
        let t0 = commit(&layout, b"t0", vec![]);
        seed_main(&layout, &t0);
        let c1 = commit(&layout, b"c1", vec![t0]);
        advance(&layout, &c1, RefWriteCondition::Match(t0)).unwrap();
        assert_eq!(refs::read_ref(&layout, "main").unwrap(), Some(c1));
    }

    #[test]
    fn a_branch_that_moved_is_refused_and_keeps_its_new_value() {
        let (_dir, layout) = fresh_repo();
        let t0 = commit(&layout, b"t0", vec![]);
        seed_main(&layout, &t0);
        let moved = commit(&layout, b"moved", vec![t0]);
        refs::write_ref_recording_history(&layout, "main", RefWriteCondition::Match(t0), &moved)
            .unwrap();

        let new_commit = commit(&layout, b"new", vec![t0]);
        let err = advance(&layout, &new_commit, RefWriteCondition::Match(t0)).unwrap_err();
        assert!(
            matches!(
                &err,
                Error::WriteRef { branch, source: RefError::Conflict(_) } if branch == "main"
            ),
            "got {err:?}"
        );
        assert_eq!(refs::read_ref(&layout, "main").unwrap(), Some(moved));
    }

    #[test]
    fn a_missing_condition_creates_a_fresh_branch_and_refuses_an_existing_one() {
        let (_dir, layout) = fresh_repo();
        let first = commit(&layout, b"first", vec![]);
        advance(&layout, &first, RefWriteCondition::Missing).unwrap();
        assert_eq!(refs::read_ref(&layout, "main").unwrap(), Some(first));

        let second = commit(&layout, b"second", vec![]);
        let err = advance(&layout, &second, RefWriteCondition::Missing).unwrap_err();
        assert!(matches!(err, Error::WriteRef { .. }), "got {err:?}");
        assert_eq!(refs::read_ref(&layout, "main").unwrap(), Some(first));
    }

    #[test]
    fn a_detached_head_moves_without_touching_a_branch() {
        let (_dir, layout) = fresh_repo();
        let t0 = commit(&layout, b"t0", vec![]);
        seed_main(&layout, &t0);
        refs::write_head_detached(&layout, &t0).unwrap();
        let c1 = commit(&layout, b"c1", vec![t0]);
        advance(&layout, &c1, RefWriteCondition::Any).unwrap();
        assert_eq!(refs::resolve_head(&layout).unwrap(), Some(c1));
        assert_eq!(refs::read_ref(&layout, "main").unwrap(), Some(t0));
    }
}
