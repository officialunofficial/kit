//! The repository handle.

use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use kit_core::layout::{self, DiscoverError, RepoLayout};
use kit_core::store::{KIT_DIR, ObjectStore, StoreError};

use crate::Environment;

/// Errors from opening or discovering a repository.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The path has a `..` component. The library refuses to walk out of the
    /// path that the caller named.
    #[error("path {0} contains a `..` component")]
    PathTraversal(PathBuf),
    /// The path is relative and the environment working directory is not
    /// absolute.
    #[error("path {0} is not absolute after joining the working directory")]
    NotAbsolute(PathBuf),
    /// No repository exists at the path, or above it.
    #[error("{0} is not inside a kit repository")]
    NotARepository(PathBuf),
    /// A linked worktree pointer is broken.
    #[error(transparent)]
    Discover(#[from] DiscoverError),
    /// The object store cannot be opened.
    #[error(transparent)]
    Store(StoreError),
}

struct Inner {
    layout: RepoLayout,
    store: ObjectStore,
    environment: Environment,
}

/// A handle to one open repository.
///
/// Cloning is cheap. All clones share the same state, and the handle is
/// `Send + Sync`.
#[derive(Clone)]
pub struct Repo {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for Repo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Repo")
            .field("layout", &self.inner.layout)
            .finish_non_exhaustive()
    }
}

impl Repo {
    /// Open the repository whose working tree root is `path`.
    ///
    /// A relative `path` resolves against `environment.cwd`.
    ///
    /// # Errors
    /// [`Error::PathTraversal`] when `path` has a `..` component.
    /// [`Error::NotARepository`] when `path` has no repository.
    /// [`Error::Discover`] when a linked worktree pointer is broken.
    /// [`Error::Store`] when the object store is unusable.
    pub fn open(path: &Path, environment: &Environment) -> Result<Self, Error> {
        let root = resolve(path, environment)?;
        Self::open_root(root, environment)
    }

    /// Find the repository that contains `start`, then open it.
    ///
    /// The search checks `start` and then each parent. It stops at the first
    /// directory that has a `.kit` entry. That entry must open as a
    /// repository. The search does not skip a broken one.
    ///
    /// # Errors
    /// The errors of [`Repo::open`]. [`Error::NotARepository`] when no
    /// directory up to the filesystem root has a `.kit` entry.
    pub fn discover(start: &Path, environment: &Environment) -> Result<Self, Error> {
        let start = resolve(start, environment)?;
        for dir in start.ancestors() {
            if std::fs::symlink_metadata(dir.join(KIT_DIR)).is_ok() {
                return Self::open_root(dir.to_path_buf(), environment);
            }
        }
        Err(Error::NotARepository(start))
    }

    fn open_root(root: PathBuf, environment: &Environment) -> Result<Self, Error> {
        let layout = layout::discover(&root)?;
        let store = ObjectStore::open(&layout).map_err(|e| match e {
            StoreError::NotAKitRepository => Error::NotARepository(root),
            other => Error::Store(other),
        })?;
        Ok(Self {
            inner: Arc::new(Inner {
                layout,
                store,
                environment: environment.clone(),
            }),
        })
    }

    /// The on-disk layout of the repository.
    #[must_use]
    pub fn layout(&self) -> &RepoLayout {
        &self.inner.layout
    }

    /// The object store.
    #[must_use]
    pub fn store(&self) -> &ObjectStore {
        &self.inner.store
    }

    /// The environment that the handle was opened with.
    #[must_use]
    pub fn environment(&self) -> &Environment {
        &self.inner.environment
    }
}

/// Join `path` to the working directory and refuse `..` and relative results.
fn resolve(path: &Path, environment: &Environment) -> Result<PathBuf, Error> {
    if path.components().any(|c| c == Component::ParentDir) {
        return Err(Error::PathTraversal(path.to_path_buf()));
    }
    let full = environment.cwd.join(path);
    if !full.is_absolute() {
        return Err(Error::NotAbsolute(full));
    }
    Ok(full)
}
