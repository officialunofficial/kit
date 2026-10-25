//! One served repository: its refs, its packs and who may write.
//!
//! The refs are the files that [`FileTransport`] reads and writes. Every ref
//! write takes its ref lock, so `kit+file://` remotes and this server
//! serialize on the same lock. Reads take no lock, because every write is one
//! atomic rename.

use std::fmt;
use std::io::{self, ErrorKind};
use std::path::{Path, PathBuf};
use std::time::Duration;

use kit_core::hash::Hash;
use kit_core::protocol::PackKey;
use kit_core::refs::{RefWriteCondition, validate_ref_prefix};
use kit_transport_file::{FileTransport, RefFileError, SERVER_META_MARKER};

use crate::packs::{self, PackReader, PackWriter};
use crate::refs::{MAX_REF_NAME_BYTES, SERVED_REFS_PREFIX, is_served_ref_name, list_scan_prefix};

/// Who may write to a repository. Reads are always allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WritePolicy {
    /// Every session may write.
    Open,
    /// Only a session that the transport authenticated as this Ed25519 key
    /// may write.
    OwnedBy([u8; 32]),
    /// No session may write.
    ReadOnly,
}

impl WritePolicy {
    /// Whether a session with `key` may write.
    #[must_use]
    pub fn allows(&self, key: Option<&[u8; 32]>) -> bool {
        match self {
            Self::Open => true,
            Self::OwnedBy(owner) => key == Some(owner),
            Self::ReadOnly => false,
        }
    }
}

/// Why a repository could not be opened.
#[derive(Debug)]
#[non_exhaustive]
pub enum OpenError {
    /// The root carries the marker of a server that keeps its refs in a
    /// database. Serving its ref files would keep a second, diverging copy.
    RefsElsewhere(PathBuf),
    /// The marker could not be checked.
    Io(io::Error),
}

impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RefsElsewhere(path) => write!(
                f,
                "repository root {} is marked {SERVER_META_MARKER}: its refs live in a database, \
                 and its ref files would be a second, diverging copy. Move the refs back to \
                 files and remove the marker by hand.",
                path.display()
            ),
            Self::Io(e) => write!(f, "cannot check the repository root: {e}"),
        }
    }
}

impl std::error::Error for OpenError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::RefsElsewhere(_) => None,
            Self::Io(e) => Some(e),
        }
    }
}

/// The result of a ref update that did not fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefUpdate {
    /// The ref now holds the new id.
    Committed,
    /// The condition did not hold. `current` is the ref's id, or `None` if
    /// the ref is absent.
    Conflict {
        /// The ref's id now.
        current: Option<Hash>,
    },
}

/// A repository on disk, served over ssh.
#[derive(Debug)]
pub struct Repo {
    tx: FileTransport,
    policy: WritePolicy,
}

impl Repo {
    /// Open the repository at `root`.
    ///
    /// # Errors
    /// [`OpenError::RefsElsewhere`] for a root that keeps its refs in a
    /// database, [`OpenError::Io`] when the root cannot be checked.
    pub fn open(root: impl Into<PathBuf>, policy: WritePolicy) -> Result<Self, OpenError> {
        let root = root.into();
        let marker = root.join(SERVER_META_MARKER);
        match std::fs::symlink_metadata(&marker) {
            Ok(_) => Err(OpenError::RefsElsewhere(root)),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(Self {
                tx: FileTransport::new(root),
                policy,
            }),
            Err(e) => Err(OpenError::Io(e)),
        }
    }

    /// The root directory.
    #[must_use]
    pub fn root(&self) -> &Path {
        self.tx.root()
    }

    /// The write policy.
    #[must_use]
    pub const fn policy(&self) -> WritePolicy {
        self.policy
    }

    /// Remove the temp files that crashed uploads left in the pack
    /// directory, once they are `min_age` old. Call this only while no
    /// other server of this root runs an upload. Returns how many files it
    /// removed.
    ///
    /// # Errors
    /// The pack directory could not be listed.
    pub fn sweep_stale_uploads(&self, min_age: Duration) -> io::Result<usize> {
        packs::sweep_stale_uploads(self.root(), min_age)
    }

    /// Whether the pack `key` exists.
    pub(crate) fn pack_exists(&self, key: &PackKey) -> bool {
        std::fs::metadata(packs::pack_path(self.root(), key)).is_ok_and(|m| m.is_file())
    }

    /// Open the pack `key` for download; `None` if it does not exist.
    pub(crate) fn open_pack(&self, key: &PackKey) -> io::Result<Option<PackReader>> {
        PackReader::open(self.root(), key)
    }

    /// Start an upload of the pack `key`.
    pub(crate) fn begin_upload(&self, key: PackKey) -> io::Result<PackWriter> {
        PackWriter::begin(self.root(), key)
    }

    /// The id of the ref `name`; `None` if it is absent. A ref file that
    /// holds no id is an error, never absent.
    pub(crate) fn read_ref(&self, name: &str) -> Result<Option<Hash>, RefFileError> {
        if !is_served_ref_name(name) {
            return Err(RefFileError::InvalidName(name.to_owned()));
        }
        self.tx.read_ref_strict(name)
    }

    /// Every ref under `prefix` at a path-component boundary, with the
    /// prefix and its `/` removed from each name (SPEC-REFS §4), sorted by
    /// name. A file that is no ref, and a ref file with a name over the
    /// limit, are skipped.
    pub(crate) fn list_refs(&self, prefix: &str) -> Result<Vec<(String, Hash)>, RefFileError> {
        if prefix.trim_end_matches('/').len() > MAX_REF_NAME_BYTES || !validate_ref_prefix(prefix) {
            return Err(RefFileError::InvalidName(prefix.to_owned()));
        }
        let scan = list_scan_prefix(prefix);
        let mut out = Vec::new();
        for (name, id) in self.tx.list_ref_files(SERVED_REFS_PREFIX)? {
            let (Some(id), Some(short)) = (id, name.strip_prefix(scan.as_str())) else {
                continue;
            };
            if name.len() <= MAX_REF_NAME_BYTES && is_served_ref_name(&name) {
                out.push((short.to_owned(), id));
            }
        }
        Ok(out)
    }

    /// Set the ref `name` to `new` if `condition` holds. The check and the
    /// write are one step under the ref lock.
    pub(crate) fn update_ref(
        &self,
        name: &str,
        condition: RefWriteCondition,
        new: &Hash,
    ) -> Result<RefUpdate, RefFileError> {
        if !is_served_ref_name(name) {
            return Err(RefFileError::InvalidName(name.to_owned()));
        }
        self.tx.with_ref_lock(|refs| {
            // A ref file that holds no id fails a `MISSING` or `MATCH`
            // write, so no condition passes over it. `ANY` replaces it.
            if condition != RefWriteCondition::Any {
                let current = refs.read_ref(name)?;
                let holds = match condition {
                    RefWriteCondition::Missing => current.is_none(),
                    RefWriteCondition::Match(want) => current == Some(want),
                    RefWriteCondition::Any => true,
                };
                if !holds {
                    return Ok(RefUpdate::Conflict { current });
                }
            }
            match refs.update_ref(name, condition, new) {
                Ok(()) => Ok(RefUpdate::Committed),
                Err(RefFileError::Conflict) => Ok(RefUpdate::Conflict {
                    current: refs.read_ref(name)?,
                }),
                Err(e) => Err(e),
            }
        })?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kit_core::protocol::Transport as _;

    fn repo(td: &tempfile::TempDir) -> Repo {
        Repo::open(td.path(), WritePolicy::Open).unwrap()
    }

    const MAIN: &str = "refs/heads/main";

    #[test]
    fn the_policy_decides_who_writes() {
        let owner = [1; 32];
        assert!(WritePolicy::Open.allows(None));
        assert!(WritePolicy::Open.allows(Some(&owner)));
        assert!(WritePolicy::OwnedBy(owner).allows(Some(&owner)));
        assert!(!WritePolicy::OwnedBy(owner).allows(Some(&[2; 32])));
        assert!(!WritePolicy::OwnedBy(owner).allows(None));
        assert!(!WritePolicy::ReadOnly.allows(Some(&owner)));
    }

    #[test]
    fn a_root_that_keeps_refs_elsewhere_is_refused() {
        let td = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(td.path().join(".kit")).unwrap();
        std::fs::write(td.path().join(SERVER_META_MARKER), b"").unwrap();
        let err = Repo::open(td.path(), WritePolicy::Open).unwrap_err();
        assert!(matches!(err, OpenError::RefsElsewhere(_)));
        assert!(err.to_string().contains(SERVER_META_MARKER));
    }

    #[test]
    fn update_follows_the_condition() {
        let td = tempfile::tempdir().unwrap();
        let r = repo(&td);
        let (a, b, c) = ([1; 32], [2; 32], [3; 32]);
        let update = |cond, id| r.update_ref(MAIN, cond, id).unwrap();
        assert_eq!(
            update(RefWriteCondition::Match(a), &b),
            RefUpdate::Conflict { current: None }
        );
        assert_eq!(update(RefWriteCondition::Missing, &a), RefUpdate::Committed);
        assert_eq!(
            update(RefWriteCondition::Missing, &b),
            RefUpdate::Conflict { current: Some(a) }
        );
        assert_eq!(
            update(RefWriteCondition::Match(c), &b),
            RefUpdate::Conflict { current: Some(a) }
        );
        assert_eq!(
            update(RefWriteCondition::Match(a), &b),
            RefUpdate::Committed
        );
        assert_eq!(update(RefWriteCondition::Any, &c), RefUpdate::Committed);
        assert_eq!(r.read_ref(MAIN).unwrap(), Some(c));
    }

    #[test]
    fn names_outside_refs_are_invalid() {
        let td = tempfile::tempdir().unwrap();
        let r = repo(&td);
        assert!(r.read_ref("main").is_err());
        assert!(
            r.update_ref("main", RefWriteCondition::Any, &[1; 32])
                .is_err()
        );
        assert!(!td.path().join("main").exists());
    }

    #[test]
    fn a_ref_file_without_an_id_is_never_absent() {
        let td = tempfile::tempdir().unwrap();
        let r = repo(&td);
        std::fs::create_dir_all(td.path().join("refs/heads")).unwrap();
        std::fs::write(td.path().join(MAIN), b"junk").unwrap();
        assert!(r.read_ref(MAIN).is_err());
        assert!(
            r.update_ref(MAIN, RefWriteCondition::Missing, &[1; 32])
                .is_err()
        );
        assert!(
            r.update_ref(MAIN, RefWriteCondition::Match([1; 32]), &[2; 32])
                .is_err()
        );
        assert_eq!(
            r.update_ref(MAIN, RefWriteCondition::Any, &[3; 32])
                .unwrap(),
            RefUpdate::Committed
        );
    }

    #[test]
    fn listing_cuts_at_component_boundaries() {
        let td = tempfile::tempdir().unwrap();
        let r = repo(&td);
        for (name, id) in [
            ("refs/heads/feat/x", [1; 32]),
            ("refs/heads/featx", [2; 32]),
            ("refs/heads/main", [3; 32]),
            ("refs/tags/v1", [4; 32]),
        ] {
            r.update_ref(name, RefWriteCondition::Any, &id).unwrap();
        }
        let names = |prefix: &str| -> Vec<String> {
            r.list_refs(prefix)
                .unwrap()
                .into_iter()
                .map(|(n, _)| n)
                .collect()
        };
        assert_eq!(names("refs/heads"), ["feat/x", "featx", "main"]);
        assert_eq!(names("refs/heads/"), ["feat/x", "featx", "main"]);
        assert_eq!(names("refs/heads/feat"), ["x"]);
        assert!(names("refs/heads/ma").is_empty());
        assert!(names("refs/heads/main").is_empty());
        assert!(names("heads/").is_empty());
        assert_eq!(names("refs//").len(), 4);
        assert_eq!(names("").len(), 4);
        assert!(r.list_refs("/bad").is_err());
        assert!(r.list_refs(&"a/".repeat(MAX_REF_NAME_BYTES)).is_err());
    }

    #[test]
    fn listing_skips_files_that_are_no_refs() {
        let td = tempfile::tempdir().unwrap();
        let r = repo(&td);
        r.update_ref(MAIN, RefWriteCondition::Any, &[1; 32])
            .unwrap();
        std::fs::write(td.path().join("refs/heads/README"), b"not a ref\n").unwrap();
        // A file outside `refs/` is never listed, whatever the prefix.
        std::fs::write(td.path().join("loose"), format!("{}\n", "a".repeat(64))).unwrap();
        let listed = r.list_refs("").unwrap();
        assert_eq!(listed, [("refs/heads/main".to_owned(), [1; 32])]);
        assert!(r.list_refs("loose").unwrap().is_empty());
    }

    #[test]
    fn listing_skips_a_name_over_the_limit() {
        let td = tempfile::tempdir().unwrap();
        let r = repo(&td);
        let long = format!("refs/heads/{}", vec!["a".repeat(200); 3].join("/"));
        let path = long
            .split('/')
            .fold(td.path().to_path_buf(), |p, s| p.join(s));
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, kit_core::refs::encode_ref_wire(&[9; 32])).unwrap();
        r.update_ref(MAIN, RefWriteCondition::Any, &[1; 32])
            .unwrap();
        assert_eq!(
            r.list_refs("refs/heads/").unwrap(),
            [("main".to_owned(), [1; 32])]
        );
        assert!(r.read_ref(&long).is_err());
        assert!(
            r.update_ref(&long, RefWriteCondition::Match([9; 32]), &[8; 32])
                .is_err()
        );
        assert_eq!(
            std::fs::read(&path).unwrap(),
            kit_core::refs::encode_ref_wire(&[9; 32])
        );
    }

    #[test]
    fn refs_are_the_files_of_the_file_transport() {
        let td = tempfile::tempdir().unwrap();
        let r = repo(&td);
        r.update_ref(MAIN, RefWriteCondition::Any, &[5; 32])
            .unwrap();
        let tx = FileTransport::new(td.path());
        assert_eq!(tx.read_ref(MAIN).unwrap(), Some([5; 32]));
        tx.update_ref("refs/heads/dev", RefWriteCondition::Any, &[6; 32])
            .unwrap();
        assert_eq!(r.read_ref("refs/heads/dev").unwrap(), Some([6; 32]));
    }
}
