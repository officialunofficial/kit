//! Building the window of a shallow fetch from the served packs
//! (SPEC-SHALLOW §8.2).
//!
//! The root holds packs, not objects, so a window request first unpacks
//! every pack into a private object store in the system temporary
//! directory, never under the root. A delta pack can name a base that
//! another pack holds, so a pack whose base is not there yet waits for a
//! later round; files that are not packs, such as packlist nodes, are
//! skipped. The window, its boundary and its packs then come from that
//! store, and the store is removed when the request ends.
//!
//! The cost grows with the repository, not the window: the client saves
//! the download, the server does the full unpack. A later version can keep
//! the store between requests.

use std::fs::{self, File};
use std::io::{self, Read as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use kit_core::hash::{self, Hash};
use kit_core::layout::RepoLayout;
use kit_core::pack::{PackError, PackReader, PackSpool};
use kit_core::protocol::{PACK_BODY_LIMIT, PackKey, WindowRequest};
use kit_core::shallow;
use kit_core::store::ObjectStore;

/// The most bytes of packs one window may hold. A larger window is
/// refused: it would not fit the session budget anyway.
pub(crate) const MAX_WINDOW_BYTES: u64 = 1024 * 1024 * 1024;

/// Why a window could not be built.
#[derive(Debug)]
pub(crate) enum WindowServeError {
    /// The request names a tip this server does not hold, or a commit of
    /// the window has a parent it does not hold.
    Missing,
    /// The window's packs pass [`MAX_WINDOW_BYTES`].
    TooLarge,
    /// A local failure.
    Internal,
}

/// The packs of a window, each with its key, and its boundary.
pub(crate) type BuiltWindow = (Vec<(PackKey, Vec<u8>)>, Vec<Hash>);

/// The packs and boundary of the window `request` names, from the packs
/// under `root`.
pub(crate) fn build_window(
    root: &Path,
    request: &WindowRequest,
) -> Result<BuiltWindow, WindowServeError> {
    let scratch = Scratch::new().map_err(|_| WindowServeError::Internal)?;
    let layout = RepoLayout::single(scratch.path());
    let store = ObjectStore::init(&layout).map_err(|_| WindowServeError::Internal)?;
    unpack_all(root, &store).map_err(|_| WindowServeError::Internal)?;
    let tips: Vec<(Hash, u32)> = request.tips.iter().map(|t| (*t, request.depth)).collect();
    let window = shallow::window_in(&store, &tips).map_err(|e| match e {
        shallow::WindowError::Missing(_) | shallow::WindowError::NotACommit(_) => {
            WindowServeError::Missing
        }
        _ => WindowServeError::Internal,
    })?;
    let have: Vec<Hash> = request
        .have
        .iter()
        .copied()
        .filter(|h| store.read_object(h).is_ok())
        .collect();
    let objects =
        shallow::window_objects(&store, &window, &have).map_err(|_| WindowServeError::Missing)?;
    let mut total = 0u64;
    for id in &objects {
        total += store
            .read(id)
            .map_err(|_| WindowServeError::Internal)?
            .len() as u64;
        if total > MAX_WINDOW_BYTES {
            return Err(WindowServeError::TooLarge);
        }
    }
    let packs =
        shallow::window_packs(&store, &window, &have).map_err(|_| WindowServeError::Internal)?;
    Ok((packs, window.boundary.iter().copied().collect()))
}

/// Unpack every pack under `root/packs` into `store`, in rounds until a
/// round makes no progress.
fn unpack_all(root: &Path, store: &ObjectStore) -> io::Result<()> {
    let dir = root.join("packs");
    let mut waiting: Vec<(PackKey, PathBuf)> = Vec::new();
    match fs::read_dir(&dir) {
        Ok(entries) => {
            for entry in entries {
                let entry = entry?;
                let name = entry.file_name();
                let Some(key) = name
                    .to_str()
                    .and_then(|n| hash::from_hex(n).ok())
                    .map(PackKey::from_hash)
                else {
                    continue;
                };
                waiting.push((key, entry.path()));
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    }
    waiting.sort_by_key(|(key, _)| *key.as_bytes());
    loop {
        let before = waiting.len();
        let mut later = Vec::new();
        for (key, path) in waiting {
            // Any other failure is a file that is not a pack, or a pack this
            // server cannot read: the window check reports what it misses.
            if let Err(PackError::DeltaBaseMissing(_)) = unpack_one(store, &key, &path) {
                later.push((key, path));
            }
        }
        waiting = later;
        if waiting.is_empty() || waiting.len() == before {
            return Ok(());
        }
    }
}

fn unpack_one(store: &ObjectStore, key: &PackKey, path: &Path) -> Result<(), PackError> {
    let mut file = File::open(path)?;
    let len = file.metadata()?.len();
    let mut spool = PackSpool::create(&store.spool_dir(), len.min(PACK_BODY_LIMIT))?;
    spool.begin(Some(len))?;
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        spool.write(&buf[..n])?;
    }
    let pack = spool.finish(key)?;
    PackReader::read_verified(&pack, store)?;
    Ok(())
}

/// A private directory in the system temporary directory, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "kit-serve-window-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use kit_core::object::{Blob, Commit, EntryMode, Identity, Object, Tree, TreeEntry};
    use kit_core::pack::PackWriter;
    use kit_core::serialize;

    fn put(store: &ObjectStore, object: &Object) -> Hash {
        store.write(&serialize::serialize(object).unwrap()).unwrap()
    }

    /// A served root whose packs hold a line of `n` commits, one pack per
    /// commit, as `n` pushes leave it.
    fn served(n: usize) -> (tempfile::TempDir, Vec<Hash>) {
        let root = tempfile::TempDir::new().unwrap();
        let work = tempfile::TempDir::new().unwrap();
        let store = ObjectStore::init(&RepoLayout::single(work.path())).unwrap();
        fs::create_dir(root.path().join("packs")).unwrap();
        let mut commits: Vec<Hash> = Vec::new();
        for i in 0..n {
            let blob = put(
                &store,
                &Object::Blob(Blob {
                    data: format!("{i}\n").into_bytes(),
                }),
            );
            let tree = put(
                &store,
                &Object::Tree(Tree {
                    entries: vec![TreeEntry {
                        name: b"f".to_vec(),
                        mode: EntryMode::Blob,
                        object_hash: blob,
                    }],
                }),
            );
            let commit = put(
                &store,
                &Object::Commit(Commit {
                    tree_hash: tree,
                    parents: commits.last().copied().into_iter().collect(),
                    author: Identity::ed25519([0; 32]),
                    signer: [0; 32],
                    message: format!("c{i}").into_bytes(),
                    timestamp: i as u64,
                    message_hash: [0; 32],
                    content_digest: [0; 32],
                    signature: [0; 64],
                }),
            );
            let mut writer = PackWriter::new_raw_only();
            for id in [blob, tree, commit] {
                writer.push_raw(id, &store.read(&id).unwrap()).unwrap();
            }
            let (bytes, key) = writer.finish_with_key().unwrap();
            fs::write(root.path().join("packs").join(hash::to_hex(&key)), bytes).unwrap();
            commits.push(commit);
        }
        // A file that is not a pack, as a packlist node is.
        fs::write(
            root.path().join("packs").join(hash::to_hex(&[7; 32])),
            b"node",
        )
        .unwrap();
        (root, commits)
    }

    #[test]
    fn a_window_comes_from_the_served_packs() {
        let (root, c) = served(4);
        let request = WindowRequest {
            tips: vec![c[3]],
            depth: 2,
            have: vec![],
        };
        let (packs, boundary) = build_window(root.path(), &request).unwrap();
        assert_eq!(boundary, vec![c[2]]);
        let mut count = 0;
        for (_, pack) in &packs {
            count += kit_core::pack::PackEntries::new(pack).unwrap().count();
        }
        assert_eq!(count, 6, "two commits, each with its tree and blob");
        let names: Vec<_> = fs::read_dir(root.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(
            names,
            vec![std::ffi::OsString::from("packs")],
            "nothing written under the root"
        );
    }

    #[test]
    fn an_unknown_tip_is_missing() {
        let (root, _) = served(1);
        let request = WindowRequest {
            tips: vec![[9; 32]],
            depth: 1,
            have: vec![],
        };
        assert!(matches!(
            build_window(root.path(), &request),
            Err(WindowServeError::Missing)
        ));
    }
}
