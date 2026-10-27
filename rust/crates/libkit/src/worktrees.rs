//! The trees of one repository.
//!
//! A repository has one main tree and any number of linked trees. The
//! registry in the common directory lists the linked trees.

use std::path::PathBuf;

use kit_core::layout::{self, DiscoverError, RepoLayout};
use kit_core::refs::{self, Head, RefError};

/// Errors from reading the trees of a repository.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The registry cannot be listed.
    #[error("worktree registry: {0}")]
    Registry(DiscoverError),
    /// The HEAD of a sibling tree cannot be read.
    #[error("read HEAD of worktree at {}: {source}", tree_root.display())]
    ReadHead {
        /// The root of the sibling tree.
        tree_root: PathBuf,
        /// Why HEAD is unreadable.
        source: RefError,
    },
}

/// Every tree of the repository of `layout`, as `(tree root, layout)` pairs.
/// The main tree comes first, then each healthy linked tree from the
/// registry. A broken registry entry is skipped, because it has no live HEAD.
/// `worktree prune` removes it.
///
/// # Errors
/// [`Error::Registry`] when the registry cannot be listed. The function fails
/// closed, so a caller that reads the HEADs of sibling trees never mistakes an
/// unreadable registry for "no siblings".
pub fn all_layouts(layout: &RepoLayout) -> Result<Vec<(PathBuf, RepoLayout)>, Error> {
    let mut out = Vec::new();
    if let Some(main_root) = layout.common_dir().parent() {
        out.push((main_root.to_path_buf(), RepoLayout::single(main_root)));
    }
    for wt in layout::worktrees(layout).map_err(Error::Registry)? {
        if wt.prunable.is_some() {
            continue;
        }
        let Some(tree_root) = wt.tree_root else {
            continue;
        };
        out.push((
            tree_root.clone(),
            RepoLayout::linked(tree_root, wt.state_dir, layout.common_dir()),
        ));
    }
    Ok(out)
}

/// The root of a tree other than the one of `layout` that has `branch`
/// checked out, if there is one.
///
/// A branch has one writer at a time, because the ancestry journal assumes it.
/// So `checkout`, `switch` and `worktree add` refuse to put one branch on two
/// trees, and `branch -d` and `branch -m` refuse to pull a branch from under a
/// sibling tree. A caller holds the registry lock from [`crate::lock`] across
/// this check and the change that depends on it.
///
/// # Errors
/// [`Error::Registry`] or [`Error::ReadHead`]. The function fails closed on
/// both.
pub fn checked_out_elsewhere(layout: &RepoLayout, branch: &str) -> Result<Option<PathBuf>, Error> {
    let self_state = layout
        .worktree_state_dir()
        .canonicalize()
        .unwrap_or_else(|_| layout.worktree_state_dir().to_path_buf());
    for (tree_root, candidate) in all_layouts(layout)? {
        let candidate_state = candidate
            .worktree_state_dir()
            .canonicalize()
            .unwrap_or_else(|_| candidate.worktree_state_dir().to_path_buf());
        if candidate_state == self_state {
            continue; // the tree of the caller
        }
        match refs::read_head(&candidate) {
            Ok(Head::Branch(name)) if name == branch => return Ok(Some(tree_root)),
            // A sibling with no HEAD yet, in the middle of `worktree add`,
            // holds no branch.
            Ok(_) | Err(RefError::NoHead) => {}
            Err(source) => return Err(Error::ReadHead { tree_root, source }),
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use kit_core::store::ObjectStore;

    use super::*;

    /// A main tree with the branch `main` checked out and a linked tree
    /// `tree` with the branch `topic` checked out.
    fn scaffold(tmp: &Path) -> (RepoLayout, RepoLayout) {
        let main_layout = RepoLayout::single(tmp.join("main"));
        fs::create_dir_all(main_layout.worktree_root()).unwrap();
        ObjectStore::init(&main_layout).unwrap();
        refs::init(&main_layout).unwrap();
        refs::write_head_branch(&main_layout, "main").unwrap();

        let tree = tmp.join("tree");
        let state = main_layout.worktree_state_dir_for("tree");
        fs::create_dir_all(&state).unwrap();
        fs::create_dir_all(&tree).unwrap();
        fs::write(state.join(layout::COMMONDIR_FILE_NAME), b"../..\n").unwrap();
        fs::write(
            state.join(layout::BACKPOINTER_FILE_NAME),
            format!("{}\n", tree.join(kit_core::KIT_DIR).display()),
        )
        .unwrap();
        layout::write_pointer_file(&tree, &state).unwrap();
        let linked = layout::discover(&tree).unwrap();
        refs::write_head_branch(&linked, "topic").unwrap();
        (main_layout, linked)
    }

    #[test]
    fn all_layouts_lists_the_main_tree_then_each_linked_tree() {
        let tmp = tempfile::tempdir().unwrap();
        let (main_layout, _linked) = scaffold(tmp.path());
        let roots: Vec<_> = all_layouts(&main_layout)
            .unwrap()
            .into_iter()
            .map(|(root, _)| root)
            .collect();
        assert_eq!(
            roots,
            vec![tmp.path().join("main"), tmp.path().join("tree")]
        );
    }

    #[test]
    fn all_layouts_skips_a_broken_registry_entry() {
        let tmp = tempfile::tempdir().unwrap();
        let (main_layout, _linked) = scaffold(tmp.path());
        fs::create_dir_all(main_layout.worktree_state_dir_for("orphan")).unwrap();
        assert_eq!(all_layouts(&main_layout).unwrap().len(), 2);
    }

    #[test]
    fn a_branch_in_a_sibling_tree_is_found_from_either_side() {
        let tmp = tempfile::tempdir().unwrap();
        let (main_layout, linked) = scaffold(tmp.path());
        assert_eq!(
            checked_out_elsewhere(&main_layout, "topic").unwrap(),
            Some(tmp.path().join("tree"))
        );
        assert_eq!(
            checked_out_elsewhere(&linked, "main").unwrap(),
            Some(tmp.path().join("main"))
        );
    }

    #[test]
    fn the_branch_of_the_calling_tree_is_not_elsewhere() {
        let tmp = tempfile::tempdir().unwrap();
        let (main_layout, linked) = scaffold(tmp.path());
        assert_eq!(checked_out_elsewhere(&main_layout, "main").unwrap(), None);
        assert_eq!(checked_out_elsewhere(&linked, "topic").unwrap(), None);
        assert_eq!(checked_out_elsewhere(&main_layout, "absent").unwrap(), None);
    }

    #[test]
    fn a_sibling_without_a_head_holds_no_branch() {
        let tmp = tempfile::tempdir().unwrap();
        let (main_layout, linked) = scaffold(tmp.path());
        fs::remove_file(linked.head_file()).unwrap();
        assert_eq!(checked_out_elsewhere(&main_layout, "topic").unwrap(), None);
    }

    #[test]
    fn an_unreadable_registry_fails_closed() {
        let tmp = tempfile::tempdir().unwrap();
        let (main_layout, _linked) = scaffold(tmp.path());
        // A regular file where the registry directory belongs.
        fs::remove_dir_all(main_layout.worktrees_dir()).unwrap();
        fs::write(main_layout.worktrees_dir(), b"x").unwrap();
        let err = checked_out_elsewhere(&main_layout, "topic").unwrap_err();
        assert!(matches!(err, Error::Registry(_)), "got {err:?}");
        assert!(err.to_string().starts_with("worktree registry: "));
    }
}
