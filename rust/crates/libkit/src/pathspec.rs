//! Path arguments of the commands that name tracked files.
//!
//! [`index_path_for_arg`] turns the text of an argument into the path form of
//! the index. The result is relative to the root, uses `/` and passes
//! [`kit_core::index::validate_index_path`].

use std::ffi::OsString;
use std::io;
use std::path::{Component, Path, PathBuf};

/// Errors from reading a path argument.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The root of the repository cannot be resolved.
    #[error("repo root: {0}")]
    RepoRoot(io::Error),
    /// The argument is not a path of the index.
    #[error("invalid path: {0}")]
    Invalid(String),
    /// A component of the argument is not valid UTF-8.
    #[error("path is not valid UTF-8")]
    NotUtf8,
    /// The argument leads out of the repository.
    #[error("path is outside repository: {0}")]
    Outside(String),
    /// A directory above the argument cannot be resolved.
    #[error("path {}: {source}", path.display())]
    Resolve {
        /// The directory.
        path: PathBuf,
        /// Why it cannot be resolved.
        source: io::Error,
    },
}

/// Resolve `arg` to a path of the index under `root`.
///
/// An absolute argument maps under `root`, and it may name a leaf that does
/// not exist yet. The function removes `.` components and resolves `..`
/// components by text. A `..` that leaves `root` is an error.
///
/// # Errors
/// [`Error`] when the argument is not a valid path of the index.
pub fn index_path_for_arg(root: &Path, arg: &Path) -> Result<String, Error> {
    let rel = if arg.is_absolute() {
        absolute_arg_to_repo_relative(root, arg)?
    } else {
        arg.to_path_buf()
    };

    let mut parts: Vec<String> = Vec::new();
    for component in rel.components() {
        match component {
            Component::Normal(part) => {
                let part = part.to_str().ok_or(Error::NotUtf8)?;
                parts.push(part.to_owned());
            }
            Component::CurDir => {}
            Component::ParentDir => {
                if parts.pop().is_none() {
                    return Err(Error::Invalid(arg.display().to_string()));
                }
            }
            Component::Prefix(_) | Component::RootDir => {
                return Err(Error::Invalid(arg.display().to_string()));
            }
        }
    }

    let path = parts.join("/");
    if !kit_core::index::validate_index_path(&path) {
        return Err(Error::Invalid(path));
    }
    Ok(path)
}

/// Map an absolute argument to a path relative to `root`. The leaf may not
/// exist yet, such as the destination of a move.
fn absolute_arg_to_repo_relative(root: &Path, arg: &Path) -> Result<PathBuf, Error> {
    let root = root.canonicalize().map_err(Error::RepoRoot)?;

    if let Ok(rel) = arg.strip_prefix(&root) {
        return Ok(rel.to_path_buf());
    }

    let invalid = || Error::Invalid(arg.display().to_string());
    let outside = || Error::Outside(arg.display().to_string());
    let mut suffix: Vec<OsString> = vec![arg.file_name().ok_or_else(invalid)?.to_os_string()];
    let mut ancestor = arg.parent().ok_or_else(invalid)?;
    while ancestor.symlink_metadata().is_err() {
        let name = ancestor.file_name().ok_or_else(outside)?;
        suffix.push(name.to_os_string());
        ancestor = ancestor.parent().ok_or_else(outside)?;
    }

    let mut normalized = ancestor.canonicalize().map_err(|source| Error::Resolve {
        path: ancestor.to_path_buf(),
        source,
    })?;
    for component in suffix.iter().rev() {
        normalized.push(component);
    }

    normalized
        .strip_prefix(&root)
        .map(Path::to_path_buf)
        .map_err(|_| outside())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_relative_argument_is_normalised_by_text() {
        let root = Path::new("/nonexistent-root");
        let ok = |arg: &str| index_path_for_arg(root, Path::new(arg)).unwrap();
        assert_eq!(ok("a/b"), "a/b");
        assert_eq!(ok("./a//b/"), "a/b");
        assert_eq!(ok("a/../b"), "b");
    }

    #[test]
    fn a_relative_argument_cannot_leave_the_root() {
        let err = index_path_for_arg(Path::new("/r"), Path::new("../x")).unwrap_err();
        assert!(
            matches!(err, Error::Invalid(ref p) if p == "../x"),
            "{err:?}"
        );
        assert_eq!(err.to_string(), "invalid path: ../x");
        let err = index_path_for_arg(Path::new("/r"), Path::new("")).unwrap_err();
        assert!(matches!(err, Error::Invalid(_)), "{err:?}");
    }

    #[test]
    fn an_absolute_argument_maps_under_the_root() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        std::fs::create_dir(root.join("d")).unwrap();
        let got = index_path_for_arg(&root, &root.join("d").join("new")).unwrap();
        assert_eq!(got, "d/new");
        let err = index_path_for_arg(&root, Path::new("/")).unwrap_err();
        assert!(matches!(err, Error::Invalid(_)), "{err:?}");
        let other = tempfile::tempdir().unwrap();
        let err = index_path_for_arg(&root, &other.path().join("x")).unwrap_err();
        assert!(matches!(err, Error::Outside(_)), "{err:?}");
    }
}
