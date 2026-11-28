//! A read-only [`Transport`] over a `kit closure export` directory, the
//! backend of `kit+closure://` remotes.
//!
//! The directory holds `MANIFEST.mkcl` and one `<pack_key hex>.pack` file
//! per pack (SPEC-DISCLOSURE §7). The transport presents it as a remote with
//! one branch, the one the manifest records, whose tip is the root and whose
//! pack map is a single pack-list node that lists every pack of the
//! manifest in order. The node is built in memory and never written. A
//! fetch then reads the export as it reads any remote: it checks each pack
//! against its key, the closure of the tip and every signature.
//!
//! The manifest is read and decoded once, when the transport opens, so a
//! damaged manifest fails before any ref is read. A manifest that records no
//! branch cannot be opened: no ref would name its root.

use std::fs;
use std::io::{self, ErrorKind, Read as _};
use std::path::{Path, PathBuf};

use kit_core::bounded_read;
use kit_core::hash::{Hash, to_hex};
use kit_core::pack::SPOOL_BUFFER;
use kit_core::protocol::{
    PACK_BODY_LIMIT, PackBody, PackKey, PackSink, Transport, TransportError, TransportResult,
};
use kit_core::refs::{BRANCH_REF_PREFIX, PACKMAP_REF_PREFIX, Ref, RefWriteCondition};
use kit_core::transfer::encode_packlist;
use kit_core::verify::{ClosureManifest, MAX_MANIFEST_BYTES, VerifyError};

/// The file name of the manifest in an export directory.
pub const MANIFEST_FILE: &str = "MANIFEST.mkcl";

/// Why an export directory cannot be opened as a remote.
#[derive(Debug)]
#[non_exhaustive]
pub enum ClosureOpenError {
    /// The manifest could not be read.
    Read {
        /// The manifest's path.
        path: PathBuf,
        /// The read error.
        source: io::Error,
    },
    /// The manifest does not decode.
    Manifest {
        /// The manifest's path.
        path: PathBuf,
        /// The decode error.
        source: VerifyError,
    },
    /// The manifest records no branch, so no ref names its root.
    NoBranch {
        /// The manifest's path.
        path: PathBuf,
    },
}

impl std::fmt::Display for ClosureOpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Read { path, source } => write!(f, "read {}: {source}", path.display()),
            Self::Manifest { path, source } => write!(f, "{}: {source}", path.display()),
            Self::NoBranch { path } => write!(
                f,
                "{} records no branch, so a fetch cannot name its tip; re-export it with `kit closure export --history --branch <name>`",
                path.display()
            ),
        }
    }
}

impl std::error::Error for ClosureOpenError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Read { source, .. } => Some(source),
            Self::Manifest { source, .. } => Some(source),
            Self::NoBranch { .. } => None,
        }
    }
}

/// A closure export directory, opened as a read-only remote.
#[derive(Debug)]
pub struct ClosureTransport {
    dir: PathBuf,
    manifest: ClosureManifest,
    branch: String,
    /// The pack-list node that lists every pack, and its key.
    node: Vec<u8>,
    node_key: Hash,
}

impl ClosureTransport {
    /// Open the export at `path`: its directory, or the path of its
    /// `MANIFEST.mkcl`.
    ///
    /// # Errors
    /// The manifest cannot be read or decoded, or records no branch.
    pub fn open(path: &Path) -> Result<Self, ClosureOpenError> {
        let dir = if path.file_name().is_some_and(|n| n == MANIFEST_FILE) && !path.is_dir() {
            path.parent().unwrap_or(Path::new(".")).to_path_buf()
        } else {
            path.to_path_buf()
        };
        let manifest_path = dir.join(MANIFEST_FILE);
        let bytes =
            bounded_read::read_capped(&manifest_path, MAX_MANIFEST_BYTES).map_err(|source| {
                ClosureOpenError::Read {
                    path: manifest_path.clone(),
                    source,
                }
            })?;
        let manifest =
            ClosureManifest::decode(&bytes).map_err(|source| ClosureOpenError::Manifest {
                path: manifest_path.clone(),
                source,
            })?;
        let Some(branch) = manifest.branch.clone() else {
            return Err(ClosureOpenError::NoBranch {
                path: manifest_path,
            });
        };
        // The manifest holds at most 65,536 packs, far below the pack-list
        // bound, so one node lists them all.
        let node =
            encode_packlist(None, &manifest.packs).map_err(|_| ClosureOpenError::Manifest {
                path: manifest_path,
                source: VerifyError::ClosureManifestMalformed,
            })?;
        let node_key = kit_core::hash::hash(&node);
        Ok(Self {
            dir,
            manifest,
            branch,
            node,
            node_key,
        })
    }

    /// The export's directory.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The decoded manifest.
    #[must_use]
    pub fn manifest(&self) -> &ClosureManifest {
        &self.manifest
    }

    fn head_ref(&self) -> String {
        format!("{BRANCH_REF_PREFIX}{}", self.branch)
    }

    fn packmap_ref(&self) -> String {
        format!("{PACKMAP_REF_PREFIX}{}", self.branch)
    }

    /// The file of `key`, when the manifest lists it.
    fn pack_path(&self, key: &PackKey) -> Option<PathBuf> {
        self.manifest
            .packs
            .contains(key.as_bytes())
            .then(|| self.dir.join(format!("{}.pack", to_hex(key.as_bytes()))))
    }

    fn read_only() -> TransportError {
        TransportError::RemoteError("a closure export is read-only".into())
    }
}

impl Transport for ClosureTransport {
    fn upload_pack(
        &self,
        _pack: &dyn PackBody,
        _key: &PackKey,
        _head_ref: Option<&str>,
    ) -> TransportResult<()> {
        Err(Self::read_only())
    }

    /// Stream the pack file of a listed key, its length declared first. A
    /// key the manifest does not list is not found, whatever files the
    /// directory holds.
    fn download_pack(
        &self,
        key: &PackKey,
        _ref_hint: Option<&str>,
        sink: &mut dyn PackSink,
    ) -> TransportResult<()> {
        let path = self.pack_path(key).ok_or(TransportError::PackNotFound)?;
        let io_err = |e: io::Error| match e.kind() {
            ErrorKind::NotFound => TransportError::PackNotFound,
            _ => TransportError::RemoteError(format!("read {}: {e}", path.display())),
        };
        let mut file = crate::open_pack_file(&path).map_err(io_err)?;
        let len = file.metadata().map_err(io_err)?.len();
        if len > PACK_BODY_LIMIT {
            return Err(TransportError::PayloadTooLarge(
                usize::try_from(len).unwrap_or(usize::MAX),
            ));
        }
        sink.begin(Some(len))?;
        let mut buf = vec![0u8; usize::try_from(len).map_or(SPOOL_BUFFER, |n| n.min(SPOOL_BUFFER))];
        let mut left = len;
        while left > 0 {
            let n = usize::try_from(left).map_or(buf.len(), |left| left.min(buf.len()));
            file.read_exact(&mut buf[..n]).map_err(io_err)?;
            sink.write(&buf[..n])?;
            left -= n as u64;
        }
        Ok(())
    }

    fn pack_exists(&self, key: &PackKey, ref_hint: Option<&str>) -> TransportResult<bool> {
        Ok(self.pack_len(key, ref_hint)?.is_some())
    }

    fn pack_len(&self, key: &PackKey, _ref_hint: Option<&str>) -> TransportResult<Option<u64>> {
        Ok(self.pack_path(key).and_then(|path| {
            fs::symlink_metadata(path)
                .ok()
                .filter(fs::Metadata::is_file)
                .map(|meta| meta.len())
        }))
    }

    /// The one pack-list node; every other blob is not found.
    fn download_blob(
        &self,
        key: &PackKey,
        _ref_hint: Option<&str>,
        max: u64,
    ) -> TransportResult<Vec<u8>> {
        if *key.as_bytes() != self.node_key {
            return Err(TransportError::PackNotFound);
        }
        if self.node.len() as u64 > max {
            return Err(TransportError::PayloadTooLarge(self.node.len()));
        }
        Ok(self.node.clone())
    }

    fn update_ref(
        &self,
        _name: &str,
        _condition: RefWriteCondition,
        _hash: &Hash,
    ) -> TransportResult<()> {
        Err(Self::read_only())
    }

    fn delete_ref(&self, _name: &str, _expected: &Hash) -> TransportResult<()> {
        Err(Self::read_only())
    }

    fn read_ref(&self, name: &str) -> TransportResult<Option<Hash>> {
        Ok(if name == self.head_ref() {
            Some(self.manifest.root)
        } else if name == self.packmap_ref() {
            Some(self.node_key)
        } else {
            None
        })
    }

    fn list_refs(&self, prefix: &str) -> TransportResult<Vec<Ref>> {
        let mut refs = Vec::new();
        for (name, hash) in [
            (self.head_ref(), self.manifest.root),
            (self.packmap_ref(), self.node_key),
        ] {
            if let Some(rest) = name.strip_prefix(prefix) {
                refs.push(Ref {
                    name: rest.to_owned(),
                    hash: Some(hash),
                });
            }
        }
        refs.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(refs)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use kit_core::ops::graph::ClosureMode;
    use kit_core::protocol::MemorySink;
    use kit_core::transfer::decode_packlist;

    fn export_dir(branch: Option<&str>) -> (tempfile::TempDir, Vec<Vec<u8>>, ClosureManifest) {
        let dir = tempfile::tempdir().unwrap();
        let packs = vec![b"pack one".to_vec(), b"pack two".to_vec()];
        let mut manifest = ClosureManifest::new(
            [9u8; 32],
            ClosureMode::History,
            packs.iter().map(|p| kit_core::hash::hash(p)).collect(),
        );
        manifest.branch = branch.map(str::to_owned);
        fs::write(dir.path().join(MANIFEST_FILE), manifest.encode()).unwrap();
        for (pack, key) in packs.iter().zip(&manifest.packs) {
            fs::write(dir.path().join(format!("{}.pack", to_hex(key))), pack).unwrap();
        }
        (dir, packs, manifest)
    }

    #[test]
    fn the_export_is_a_remote_with_one_branch() {
        let (dir, packs, manifest) = export_dir(Some("main"));
        let t = ClosureTransport::open(dir.path()).unwrap();
        let heads = t.list_refs("refs/heads/").unwrap();
        assert_eq!(heads.len(), 1);
        assert_eq!(heads[0].name, "main");
        assert_eq!(heads[0].hash, Some(manifest.root));
        assert!(t.list_refs("refs/tags/").unwrap().is_empty());
        assert!(t.list_refs("refs/kit/tagmap/").unwrap().is_empty());
        let node_key = t.read_ref("refs/kit/packmap/main").unwrap().unwrap();
        let node = t
            .download_blob(&PackKey::from_hash(node_key), None, 1 << 20)
            .unwrap();
        let decoded = decode_packlist(&node).unwrap();
        assert_eq!(decoded.prev, None);
        assert_eq!(decoded.packs, manifest.packs);
        for (pack, key) in packs.iter().zip(&manifest.packs) {
            let mut sink = MemorySink::new(1 << 20);
            t.download_pack(&PackKey::from_hash(*key), None, &mut sink)
                .unwrap();
            assert_eq!(&sink.into_bytes().unwrap(), pack);
        }
    }

    #[test]
    fn the_manifest_path_opens_the_same_export() {
        let (dir, _, manifest) = export_dir(Some("main"));
        let t = ClosureTransport::open(&dir.path().join(MANIFEST_FILE)).unwrap();
        assert_eq!(t.manifest(), &manifest);
        assert_eq!(t.dir(), dir.path());
    }

    #[test]
    fn a_file_the_manifest_does_not_list_is_not_served() {
        let (dir, _, _) = export_dir(Some("main"));
        let stray = kit_core::hash::hash(b"stray");
        fs::write(
            dir.path().join(format!("{}.pack", to_hex(&stray))),
            b"stray",
        )
        .unwrap();
        let t = ClosureTransport::open(dir.path()).unwrap();
        let mut sink = MemorySink::new(1 << 20);
        assert!(matches!(
            t.download_pack(&PackKey::from_hash(stray), None, &mut sink),
            Err(TransportError::PackNotFound)
        ));
        assert!(!t.pack_exists(&PackKey::from_hash(stray), None).unwrap());
    }

    #[test]
    fn a_manifest_without_a_branch_does_not_open() {
        let (dir, _, _) = export_dir(None);
        assert!(matches!(
            ClosureTransport::open(dir.path()),
            Err(ClosureOpenError::NoBranch { .. })
        ));
    }

    #[test]
    fn a_damaged_manifest_does_not_open() {
        let (dir, _, _) = export_dir(Some("main"));
        let path = dir.path().join(MANIFEST_FILE);
        let mut bytes = fs::read(&path).unwrap();
        bytes[10] ^= 1;
        fs::write(&path, bytes).unwrap();
        assert!(matches!(
            ClosureTransport::open(dir.path()),
            Err(ClosureOpenError::Manifest { .. })
        ));
    }

    #[test]
    fn every_write_is_refused() {
        let (dir, _, _) = export_dir(Some("main"));
        let t = ClosureTransport::open(dir.path()).unwrap();
        assert!(t.write_ref("refs/heads/main", &[0u8; 32]).is_err());
        assert!(t.delete_ref("refs/heads/main", &[9u8; 32]).is_err());
        assert!(
            t.upload_blob(b"x", &PackKey::from_hash([1u8; 32]), None)
                .is_err()
        );
    }
}
