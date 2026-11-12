//! Read-side object sources and adapters over the durable [`ObjectStore`].
//!
//! [`ObjectSource`] is the read trait shared by the store and its overlays;
//! [`EphemeralSink`] is the in-memory snapshot overlay for query commands;
//! [`DisplaySource`] is the display-only adapter that opts a render path out of
//! per-read hash verification. Extracted from `store.rs`: these are
//! consumers of the store's read API, distinct from its on-disk write/fsync
//! machinery.

use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::hash::Hash;
use crate::object::{Object, object_id_from_parts};
use crate::serialize;

use super::{
    ChunkOrigin, MAX_RAW_OBJECT_SIZE, ObjectSink, ObjectStore, StoreError, StoreResult, check_hash,
};

/// Read source shared by [`ObjectStore`] and snapshot overlays, so
/// tree-diff code can resolve objects from either the durable store or
/// an in-memory [`EphemeralSink`].
pub trait ObjectSource {
    /// Read and integrity-verify the raw bytes of `h`.
    ///
    /// # Errors
    /// [`StoreError::ObjectNotFound`] / [`StoreError::HashMismatch`] /
    /// I/O errors, as for [`ObjectStore::read`].
    fn read(&self, h: &Hash) -> StoreResult<Vec<u8>>;

    /// Read and decode `h` into a typed [`Object`].
    ///
    /// # Errors
    /// As [`Self::read`], plus decode errors.
    fn read_object(&self, h: &Hash) -> StoreResult<Object> {
        Ok(serialize::deserialize(&self.read(h)?)?)
    }

    /// Read `h` without integrity verification, for display-only
    /// rendering — see [`ObjectStore::read_unverified`] for the full
    /// policy. Defaults to the fully-verifying [`Self::read`], so
    /// every existing and third-party [`ObjectSource`] stays verifying
    /// unless it explicitly opts in by overriding this method.
    ///
    /// # Errors
    /// As [`Self::read`] (an opting-in override may narrow this to never
    /// return [`StoreError::HashMismatch`]).
    fn read_unverified(&self, h: &Hash) -> StoreResult<Vec<u8>> {
        self.read(h)
    }
}

impl ObjectSource for ObjectStore {
    fn read(&self, h: &Hash) -> StoreResult<Vec<u8>> {
        ObjectStore::read(self, h)
    }

    fn read_unverified(&self, h: &Hash) -> StoreResult<Vec<u8>> {
        ObjectStore::read_unverified(self, h)
    }

    /// Overrides the trait default (`deserialize(self.read(h)?)`, which
    /// would decode a `Tree`/`ChunkedBlob` twice — once inside `read`'s
    /// id verification, once again here) to delegate to the inherent
    /// [`ObjectStore::read_object`], which decodes once and reuses the
    /// result. Every caller generic over `S: ObjectSource` (`diff::load_tree`,
    /// `LoadedBlob::load`, …) resolves `read_object` through this trait
    /// impl rather than the inherent method even when `S = ObjectStore`,
    /// so without this override those call sites — the primary
    /// Tree/ChunkedBlob decoding paths — would keep paying for the
    /// double decode the inherent method was written to avoid.
    fn read_object(&self, h: &Hash) -> StoreResult<Object> {
        ObjectStore::read_object(self, h)
    }
}

/// In-memory object overlay for **ephemeral worktree snapshots**
/// (`status`, `diff`, conflict/restore safety checks).
///
/// Writes never touch the durable store: objects whose hash already
/// exists on disk are deduplicated against it (the store's
/// visible-implies-durable invariant makes that safe), everything else
/// lives in a private map that vanishes with the sink. This is what
/// keeps query commands from (a) paying any durability cost, (b)
/// growing `objects/` with throwaway snapshot trees, and (c) ever
/// making a non-durable object *visible* where another writer's dedup
/// could durably reference it.
///
/// Reads fall through to the underlying store, so diff walkers can
/// resolve a snapshot tree that references committed objects.
///
/// A chunk blob cut from a worktree file is not copied. The overlay keeps the
/// file path, the offset and the length of the chunk, about 64 bytes, and reads
/// the chunk back from the file when asked. The read checks the chunk's id, so
/// a file that changed since the snapshot fails the read and never returns
/// other bytes. A snapshot of a file of many chunks then costs memory in
/// proportion to its chunk count and not to its size.
#[derive(Debug)]
pub struct EphemeralSink<'s> {
    store: &'s ObjectStore,
    objects: Mutex<HashMap<Hash, Vec<u8>>>,
    chunks: Mutex<ChunkRefs>,
}

/// Chunk blobs the overlay reads back from worktree files.
#[derive(Debug, Default)]
struct ChunkRefs {
    /// Each distinct file path once, so a chunk entry holds an index.
    paths: Vec<PathBuf>,
    path_index: HashMap<PathBuf, u32>,
    by_id: HashMap<Hash, ChunkRef>,
}

#[derive(Debug, Clone, Copy)]
struct ChunkRef {
    path: u32,
    offset: u64,
    len: u32,
}

impl<'s> EphemeralSink<'s> {
    /// Create an empty overlay over `store`.
    #[must_use]
    pub fn new(store: &'s ObjectStore) -> Self {
        Self {
            store,
            objects: Mutex::new(HashMap::new()),
            chunks: Mutex::new(ChunkRefs::default()),
        }
    }

    /// Read a chunk blob back from the file it was cut from. `None` when the
    /// overlay holds no such chunk.
    fn read_chunk(&self, h: &Hash) -> Option<StoreResult<Vec<u8>>> {
        let (path, found) = {
            let chunks = self.chunks.lock().expect("ephemeral sink chunk mutex");
            let found = *chunks.by_id.get(h)?;
            (chunks.paths[found.path as usize].clone(), found)
        };
        Some(read_chunk_blob(h, &path, found))
    }
}

/// The canonical bytes of the chunk blob `found` in `path`, checked against
/// `h`.
fn read_chunk_blob(h: &Hash, path: &Path, found: ChunkRef) -> StoreResult<Vec<u8>> {
    let len = found.len as usize;
    let prologue = serialize::blob_prologue(len)?;
    let mut file = crate::worktree::open_regular_file(path)?;
    file.seek(SeekFrom::Start(found.offset))?;
    let mut bytes = Vec::with_capacity(prologue.len() + len);
    bytes.extend_from_slice(&prologue);
    bytes.resize(prologue.len() + len, 0);
    file.read_exact(&mut bytes[prologue.len()..])
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::UnexpectedEof => std::io::Error::other(format!(
                "{} changed while it was being read",
                path.display()
            )),
            _ => e,
        })?;
    if check_hash(h, &object_id_from_parts(&[&bytes])).is_err() {
        return Err(StoreError::Io(std::io::Error::other(format!(
            "{} changed while it was being read",
            path.display()
        ))));
    }
    Ok(bytes)
}

impl ObjectSink for EphemeralSink<'_> {
    fn put(&self, bytes: &[u8]) -> StoreResult<Hash> {
        self.put_parts(&[bytes])
    }

    fn put_parts(&self, parts: &[&[u8]]) -> StoreResult<Hash> {
        let mut total: usize = 0;
        for p in parts {
            total = total
                .checked_add(p.len())
                .ok_or(StoreError::ObjectTooLarge)?;
        }
        if total > MAX_RAW_OBJECT_SIZE {
            return Err(StoreError::ObjectTooLarge);
        }
        let h = object_id_from_parts(parts);
        // Dedup against the durable store: visible store objects are durable
        // by invariant, and skipping them keeps the overlay's memory bounded
        // by the *changed* content, not the worktree. The overlay only ever
        // materialises the bytes on a dedup miss.
        if self.store.contains(&h) {
            return Ok(h);
        }
        self.objects
            .lock()
            .expect("ephemeral sink mutex")
            .entry(h)
            .or_insert_with(|| {
                let mut buf = Vec::with_capacity(total);
                for p in parts {
                    buf.extend_from_slice(p);
                }
                buf
            });
        Ok(h)
    }

    fn has(&self, h: &Hash) -> bool {
        self.objects
            .lock()
            .expect("ephemeral sink mutex")
            .contains_key(h)
            || self
                .chunks
                .lock()
                .expect("ephemeral sink chunk mutex")
                .by_id
                .contains_key(h)
            || self.store.contains(h)
    }

    /// Keeps the origin of a chunk of a worktree file and no copy of its
    /// bytes. `parts` is the blob prologue and then the chunk.
    fn put_chunk_parts(&self, parts: &[&[u8]], origin: ChunkOrigin<'_>) -> StoreResult<Hash> {
        let &[_, chunk] = parts else {
            return self.put_parts(parts);
        };
        let len = u32::try_from(chunk.len()).map_err(|_| StoreError::ObjectTooLarge)?;
        let h = object_id_from_parts(parts);
        if self.store.contains(&h)
            || self
                .objects
                .lock()
                .expect("ephemeral sink mutex")
                .contains_key(&h)
        {
            return Ok(h);
        }
        let mut chunks = self.chunks.lock().expect("ephemeral sink chunk mutex");
        let ChunkRefs {
            paths,
            path_index,
            by_id,
        } = &mut *chunks;
        if by_id.contains_key(&h) {
            return Ok(h);
        }
        let path = if let Some(&i) = path_index.get(origin.path) {
            i
        } else {
            let i = u32::try_from(paths.len()).map_err(|_| StoreError::ObjectTooLarge)?;
            paths.push(origin.path.to_path_buf());
            path_index.insert(origin.path.to_path_buf(), i);
            i
        };
        by_id.insert(
            h,
            ChunkRef {
                path,
                offset: origin.offset,
                len,
            },
        );
        Ok(h)
    }
}

impl EphemeralSink<'_> {
    /// The private-map half of a read: bytes this process already built
    /// (via `put`/`put_parts`) and never persisted anywhere else to be
    /// corrupted, shared by both [`ObjectSource::read`] and
    /// [`ObjectSource::read_unverified`] below — the two differ only in
    /// what they do on a miss.
    fn overlay_get(&self, h: &Hash) -> Option<Vec<u8>> {
        self.objects
            .lock()
            .expect("ephemeral sink mutex")
            .get(h)
            .cloned()
    }
}

impl ObjectSource for EphemeralSink<'_> {
    fn read(&self, h: &Hash) -> StoreResult<Vec<u8>> {
        if let Some(bytes) = self.overlay_get(h) {
            return Ok(bytes);
        }
        match self.read_chunk(h) {
            Some(read) => read,
            None => self.store.read(h),
        }
    }

    /// Overrides the trait default for the same reason `impl ObjectSource
    /// for ObjectStore` does: a private-map hit only ever needs one
    /// decode (the default's `deserialize(self.read(h)?)` already gives
    /// that), but a store fall-through would otherwise re-decode a
    /// `Tree`/`ChunkedBlob` a second time on top of the decode
    /// `ObjectStore::read`'s id verification already does internally.
    /// Delegating to `self.store.read_object` on a miss reuses that
    /// store-side decode instead — `diff`/`status`, which resolve staged
    /// trees through this overlay, are the paths this matters for.
    fn read_object(&self, h: &Hash) -> StoreResult<Object> {
        if let Some(bytes) = self.overlay_get(h) {
            return Ok(serialize::deserialize(&bytes)?);
        }
        match self.read_chunk(h) {
            Some(read) => Ok(serialize::deserialize(&read?)?),
            None => self.store.read_object(h),
        }
    }

    fn read_unverified(&self, h: &Hash) -> StoreResult<Vec<u8>> {
        // Private-map hits are already trusted, same as the verifying
        // `read` path above. Only the store fall-through actually skips a
        // hash check.
        if let Some(bytes) = self.overlay_get(h) {
            return Ok(bytes);
        }
        match self.read_chunk(h) {
            Some(read) => read,
            None => self.store.read_unverified(h),
        }
    }
}

/// Adapter that makes any [`ObjectSource`] read without BLAKE3
/// verification, for display-only rendering (`diff`, `show`, and the
/// commit/merge/pull post-op summaries). Wrap the source once at the
/// render call site — `DisplaySource::new(&store)` — and pass the
/// wrapper wherever a generic `S: ObjectSource` render function expects
/// its source. Every existing render function (`render_stat`,
/// `emit_entry_patch`, `LoadedBlob::load`/`prefix`/`into_content`) works
/// unchanged: the verify/no-verify policy lives entirely in which source
/// gets passed in, never in a flag threaded through render code.
///
/// # When to use
/// kit never feeds unverified bytes into state that kit itself writes,
/// or into output that kit's own tooling round-trips (format-patch →
/// `git am`) — a diffstat or patch preview that only a human reads and
/// discards is neither, so it's fair game. NEVER wrap a source feeding
/// publication (commit/merge/rebase tree writes), dedup, fetch/apply, or
/// any path whose output becomes durable state or gets applied elsewhere
/// (e.g. the format-patch body in `git_tools.rs`, which is deliberately
/// NOT wrapped because `git am` applies it into new commits), including
/// [`crate::verify::build_disclosure_from`], whose bundles are published
/// proofs. See
/// [`ObjectStore::read_unverified`] for the full policy this wrapper
/// exists to apply consistently.
pub struct DisplaySource<'a, S: ObjectSource + ?Sized> {
    inner: &'a S,
}

impl<'a, S: ObjectSource + ?Sized> DisplaySource<'a, S> {
    /// Wrap `inner` so reads through this adapter skip verification.
    #[must_use]
    pub fn new(inner: &'a S) -> Self {
        Self { inner }
    }
}

// Manual `Debug` (rather than `derive`) so this doesn't force an
// unnecessary `S: Debug` bound on every generic render fn that only
// needs `S: ObjectSource`.
impl<S: ObjectSource + ?Sized> std::fmt::Debug for DisplaySource<'_, S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DisplaySource").finish_non_exhaustive()
    }
}

impl<S: ObjectSource + ?Sized> ObjectSource for DisplaySource<'_, S> {
    fn read(&self, h: &Hash) -> StoreResult<Vec<u8>> {
        self.inner.read_unverified(h)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::RepoLayout;
    use std::fs::OpenOptions;
    use std::io::{self, Seek, Write};
    use tempfile::TempDir;

    fn fresh_store() -> (TempDir, ObjectStore) {
        let dir = TempDir::new().expect("tempdir");
        let store = ObjectStore::init(&RepoLayout::single(dir.path())).expect("init");
        (dir, store)
    }

    /// Flip the first byte of the on-disk object file for `h`, in place.
    /// Shared by the `DisplaySource` corruption tests below — the same
    /// "the bytes on disk no longer match `h`" setup the corruption tests
    /// in `store.rs` use (deliberately duplicated there rather than
    /// exposing a test-support seam).
    fn corrupt_first_byte(store: &ObjectStore, h: &Hash, first_byte: u8) {
        let path = store.path_for(h);
        let mut f = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        f.seek(io::SeekFrom::Start(0)).unwrap();
        f.write_all(&[first_byte ^ 0xFF]).unwrap();
        f.sync_all().unwrap();
    }

    #[test]
    fn display_source_delegates_to_unverified() {
        // `DisplaySource` is the intended call-site adapter: wrapping the
        // store must make `ObjectSource::read` succeed on an object that
        // `ObjectStore::read` itself would reject.
        let (_dir, store) = fresh_store();
        let bytes = b"trustworthy".to_vec();
        let h = store.write(&bytes).unwrap();
        corrupt_first_byte(&store, &h, bytes[0]);
        assert!(matches!(
            store.read(&h).unwrap_err(),
            StoreError::HashMismatch { .. }
        ));

        let display = DisplaySource::new(&store);
        let mut corrupted = bytes.clone();
        corrupted[0] ^= 0xFF;
        assert_eq!(
            display.read(&h).unwrap(),
            corrupted,
            "DisplaySource::read must delegate to the store's unverified read"
        );
    }

    /// Regression test for the `EphemeralSink::read_object` override:
    /// both a private-map (overlay) hit and a store fall-through must
    /// decode a `Tree` correctly, and the store fall-through must still
    /// surface `HashMismatch` on corruption — through `&dyn ObjectSource`,
    /// the shape every `diff`/`status` caller actually uses.
    #[test]
    fn ephemeral_sink_read_object_tree_overlay_and_fallthrough() {
        use crate::object::{EntryMode, Tree, TreeEntry};
        let tree = |name: &[u8]| {
            Object::Tree(Tree {
                entries: vec![TreeEntry {
                    name: name.to_vec(),
                    mode: EntryMode::Blob,
                    object_hash: crate::hash::hash(b"x"),
                }],
            })
        };

        let (_dir, store) = fresh_store();

        // Store fall-through: object lives only in the durable store.
        let durable_obj = tree(b"durable.txt");
        let durable_bytes = serialize::serialize(&durable_obj).unwrap();
        let durable_h = store.write(&durable_bytes).unwrap();

        // Overlay hit: object lives only in the sink's private map.
        let overlay_obj = tree(b"overlay.txt");
        let overlay_bytes = serialize::serialize(&overlay_obj).unwrap();

        let sink = EphemeralSink::new(&store);
        let overlay_h = sink.put(&overlay_bytes).unwrap();

        let via_trait: &dyn ObjectSource = &sink;
        assert_eq!(via_trait.read_object(&durable_h).unwrap(), durable_obj);
        assert_eq!(via_trait.read_object(&overlay_h).unwrap(), overlay_obj);

        corrupt_first_byte(&store, &durable_h, durable_bytes[0]);
        assert!(matches!(
            via_trait.read_object(&durable_h).unwrap_err(),
            StoreError::HashMismatch { .. }
        ));
    }

    #[test]
    fn ephemeral_sink_unverified_falls_through() {
        // Two shapes an `EphemeralSink` reader can hit: a private-map
        // object built by this snapshot (never touches disk, so nothing to
        // corrupt) and a store-backed object corrupted on disk. Both must
        // read fine through `DisplaySource<EphemeralSink>`.
        let (_dir, store) = fresh_store();
        let durable_bytes = b"trustworthy".to_vec();
        let durable_h = store.write(&durable_bytes).unwrap();
        corrupt_first_byte(&store, &durable_h, durable_bytes[0]);

        let sink = EphemeralSink::new(&store);
        let private_h = sink.put(b"snapshot-only").unwrap();

        let display = DisplaySource::new(&sink);
        assert_eq!(display.read(&private_h).unwrap(), b"snapshot-only");

        let mut corrupted = durable_bytes.clone();
        corrupted[0] ^= 0xFF;
        assert_eq!(display.read(&durable_h).unwrap(), corrupted);
    }

    fn random_file(dir: &TempDir, name: &str, len: usize, seed: u64) -> (PathBuf, Vec<u8>) {
        let mut state = seed;
        let data: Vec<u8> = (0..len)
            .map(|_| {
                state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
                let mut z = state;
                z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
                ((z ^ (z >> 31)) & 0xFF) as u8
            })
            .collect();
        let path = dir.path().join(name);
        std::fs::write(&path, &data).unwrap();
        (path, data)
    }

    #[test]
    fn ephemeral_sink_keeps_the_origin_of_a_chunk_and_not_its_bytes() {
        let (_dir, store) = fresh_store();
        let work = TempDir::new().unwrap();
        let (path, data) = random_file(&work, "big.bin", 4 * 1024 * 1024, 0xFEED);

        let sink = EphemeralSink::new(&store);
        let (h, _) = crate::worktree::hash_file_with_metadata(&sink, &path).unwrap();

        let Object::ChunkedBlob(manifest) = sink.read_object(&h).unwrap() else {
            panic!("expected a chunked blob");
        };
        assert!(manifest.chunks.len() > 32);
        // The overlay holds the manifest as bytes and every chunk as an origin.
        assert_eq!(sink.objects.lock().unwrap().len(), 1);
        assert_eq!(
            sink.chunks.lock().unwrap().by_id.len(),
            manifest.chunks.len()
        );
        for chunk in &manifest.chunks {
            assert!(sink.has(chunk));
            assert!(!store.contains(chunk), "nothing reaches the store");
        }
        // The snapshot still reads back whole, and the id matches a stored copy.
        assert_eq!(crate::worktree::read_blob(&sink, &h).unwrap(), data);
        assert_eq!(
            crate::worktree::store_file_object(&store, &data).unwrap(),
            h
        );
    }

    #[test]
    fn ephemeral_sink_refuses_a_chunk_whose_file_changed() {
        let (_dir, store) = fresh_store();
        let work = TempDir::new().unwrap();
        let (path, mut data) = random_file(&work, "big.bin", 2 * 1024 * 1024, 0xBEEF);

        let sink = EphemeralSink::new(&store);
        let (h, _) = crate::worktree::hash_file_with_metadata(&sink, &path).unwrap();
        data[1024 * 1024] ^= 0xFF;
        std::fs::write(&path, &data).unwrap();
        assert!(
            crate::worktree::read_blob(&sink, &h).is_err(),
            "a changed file never yields other bytes"
        );

        std::fs::remove_file(&path).unwrap();
        assert!(crate::worktree::read_blob(&sink, &h).is_err());
    }

    #[test]
    fn ephemeral_sink_names_the_file_that_changed() {
        let (_dir, store) = fresh_store();
        let work = TempDir::new().unwrap();
        let (path, data) = random_file(&work, "big.bin", 2 * 1024 * 1024, 0xABCD);
        let sink = EphemeralSink::new(&store);
        let (h, _) = crate::worktree::hash_file_with_metadata(&sink, &path).unwrap();

        // A truncated file and a file with other bytes both fail the read.
        std::fs::write(&path, &data[..data.len() / 2]).unwrap();
        let err = crate::worktree::read_blob(&sink, &h).unwrap_err();
        assert!(err.to_string().contains("big.bin changed"), "got {err}");
        let mut other = data;
        other[0] ^= 1;
        std::fs::write(&path, &other).unwrap();
        let err = crate::worktree::read_blob(&sink, &h).unwrap_err();
        assert!(err.to_string().contains("big.bin changed"), "got {err}");

        // A symlink in place of the file is refused.
        #[cfg(unix)]
        {
            std::fs::remove_file(&path).unwrap();
            let target = work.path().join("target.bin");
            std::fs::write(&target, &other).unwrap();
            std::os::unix::fs::symlink(&target, &path).unwrap();
            assert!(crate::worktree::read_blob(&sink, &h).is_err());
        }
    }

    #[test]
    fn ephemeral_sink_skips_a_chunk_the_store_holds() {
        let (_dir, store) = fresh_store();
        let work = TempDir::new().unwrap();
        let (path, data) = random_file(&work, "big.bin", 2 * 1024 * 1024, 0xCAFE);
        crate::worktree::store_file_object(&store, &data).unwrap();

        let sink = EphemeralSink::new(&store);
        let (h, _) = crate::worktree::hash_file_with_metadata(&sink, &path).unwrap();
        assert!(sink.chunks.lock().unwrap().by_id.is_empty());
        assert!(sink.objects.lock().unwrap().is_empty());
        assert_eq!(crate::worktree::read_blob(&sink, &h).unwrap(), data);
    }

    #[test]
    fn read_unverified_default_is_verifying_read() {
        // A minimal `ObjectSource` impl that only defines `read` must get
        // fully-verifying behaviour from `read_unverified`'s default body
        // — the whole safety net for third-party/future implementors that
        // haven't opted in to the unverified path.
        struct OnlyReadImpl<'s>(&'s ObjectStore);
        impl ObjectSource for OnlyReadImpl<'_> {
            fn read(&self, h: &Hash) -> StoreResult<Vec<u8>> {
                self.0.read(h)
            }
        }

        let (_dir, store) = fresh_store();
        let bytes = b"trustworthy".to_vec();
        let h = store.write(&bytes).unwrap();
        corrupt_first_byte(&store, &h, bytes[0]);

        let only_read = OnlyReadImpl(&store);
        assert!(matches!(
            only_read.read_unverified(&h).unwrap_err(),
            StoreError::HashMismatch { .. }
        ));
    }
}
