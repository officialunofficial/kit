//! Local content-addressed object store.
//!
//! Layout (under the [`crate::layout::RepoLayout`] common dir passed to
//! [`ObjectStore::open`] / [`ObjectStore::init`]):
//!
//! ```text
//! .kit/
//!   objects/
//!     <2-hex>/<62-hex>   # raw canonical object bytes, BLAKE3-named
//! ```
//!
//! Writes are atomic: bytes are first written to a sibling temp file, made
//! durable, then renamed into place. Temp names start with
//! `.kit.tmp.<pid>.<seq>` and end with a random suffix.
//! [`ObjectStore::iter_object_hashes`] keeps only files named with 62 hex
//! digits, so temp files are never objects. A crash mid-write leaves only
//! the temp file behind and never produces a visible object that fails the
//! read-time hash check.
//!
//! Durability comes in three shapes (see [`crate::batch`] for the full
//! contract): [`ObjectStore::write`] flushes per object
//! ([`SyncPolicy::PerObject`]); [`ObjectStore::batch`] defers visibility
//! and amortises durability to **one** full flush per batch — the write
//! path used by every multi-object command (add, commit, pack unpack);
//! and [`ObjectStore::bulk_writer`] fsyncs each object's contents before
//! the rename and batches the dir fsyncs at commit (git import). In all
//! three an object is never visible before its bytes are durable, so a
//! ref or index written after the write/commit returns can never
//! reference a non-durable object.
//!
//! Verified reads recompute the type-dependent id from the bytes
//! and comparing against the requested hash; mismatch returns
//! [`StoreError::HashMismatch`]. The one opt-in exception is
//! [`ObjectStore::read_unverified`] (and the [`DisplaySource`] adapter
//! built on it), reserved for display-only rendering where a corrupt
//! object should surface as a bad render, never as durable state — see
//! its doc for the full policy.
//!
//! See `docs/specs/SPEC-OBJECTS.md` §10 for the path-layout rule.

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use crate::batch::{RealSyncer, Syncer};
pub use crate::batch::{SyncPolicy, WriteBatch};
use crate::hash::{self, Hash, object_path, to_hex};
use crate::layout::RepoLayout;
use crate::object::{KitError, Object, object_id_from_bytes, verified_id_and_object};
use crate::serialize;

mod format;
mod local_pack;
mod memory;
mod memory_overlay;
mod source;
mod tree_budget;
pub(crate) use local_pack::Catalog as PackCatalog;
#[cfg(test)]
pub(crate) use local_pack::set_test_output_entries;
pub use local_pack::{LocalPackWriter, PACK_SEAL_BYTES, PACK_SEAL_ENTRIES, SealJob};
pub(crate) use local_pack::{PackSweep, Verify};
pub use memory::MemorySource;
pub use memory_overlay::{MemoryOverlay, MemoryOverlayLimits};
pub use source::{
    ClosureSource, DisplaySource, EphemeralSink, GuardedStore, HashOnlySink, ObjectSource,
};
pub(crate) use tree_budget::WalkBudget;
pub use tree_budget::{MAX_TREE_LEAVES, check_tree_leaves};

/// Where a blob's bytes sit in a worktree file. An inline blob starts at
/// offset zero.
#[derive(Debug, Clone, Copy)]
pub struct ChunkOrigin<'a> {
    /// The worktree file.
    pub path: &'a Path,
    /// The offset of the blob's first byte in that file.
    pub offset: u64,
}

/// A canonical blob chunk whose id is already computed, with its prologue and
/// payload in order.
///
/// The fields are private and [`Self::new`] hashes the bytes, so code outside
/// kit-core can make a chunk only by hashing it, and a sink may trust the id.
/// The bytes are an owned buffer or a borrow of a reader window, never a
/// mapping, so they cannot change between the hash and the write.
#[derive(Debug, Clone, Copy)]
pub struct HashedChunk<'a> {
    id: Hash,
    prologue: [u8; serialize::BLOB_PROLOGUE_LEN],
    data: &'a [u8],
    origin: Option<ChunkOrigin<'a>>,
}

impl<'a> HashedChunk<'a> {
    /// Build the canonical blob of `data` and hash it, with the same id
    /// dispatch as [`WriteBatch::write_parts`].
    ///
    /// # Errors
    /// [`KitError`] when `data` is longer than a blob may be.
    pub fn new(data: &'a [u8]) -> Result<Self, KitError> {
        let prologue = serialize::blob_prologue(data.len())?;
        let id = crate::object::object_id_from_parts(&[&prologue, data]);
        Ok(Self {
            id,
            prologue,
            data,
            origin: None,
        })
    }

    /// Record where the chunk sits in a worktree file, for a sink that keeps
    /// the location instead of the bytes.
    #[must_use]
    pub fn at(mut self, origin: ChunkOrigin<'a>) -> Self {
        self.origin = Some(origin);
        self
    }

    /// The content address of the blob.
    #[must_use]
    pub fn id(&self) -> Hash {
        self.id
    }

    /// The prologue and the payload, in order.
    #[must_use]
    pub fn parts(&self) -> [&[u8]; 2] {
        [&self.prologue, self.data]
    }

    /// The serialized length of the blob.
    #[must_use]
    pub fn len(&self) -> usize {
        self.prologue.len() + self.data.len()
    }

    /// Never true: a blob has a prologue.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Where the chunk sits in its worktree file, if the caller said.
    #[must_use]
    pub fn origin(&self) -> Option<ChunkOrigin<'a>> {
        self.origin
    }
}

/// Top-level repository directory name.
pub const KIT_DIR: &str = ".kit";
/// Subdirectory under `.kit/` that holds raw object files.
pub const OBJECTS_DIR: &str = "objects";
/// File under `.kit/` declaring the object-addressing format. Written at
/// [`ObjectStore::init`] and required (and matched) at [`ObjectStore::open`]
/// so an older flat-hash-addressed repository is rejected loudly rather
/// than silently mis-read once merkle addressing is in effect.
pub const FORMAT_FILE: &str = "format";
/// The only supported object-addressing format value (see
/// `docs/specs/SPEC-MERKLE-OBJECTS.md`): Tree/ChunkedBlob keyed by BMT root.
pub const FORMAT_VALUE: &str = "bmt-v2";

/// Longest format marker that kit reads. The real value is a few bytes.
const FORMAT_MAX_BYTES: u64 = 64;

/// The largest packed frame the mark's probe reads whole in one call, to hash
/// it. A larger one streams, so the probe never holds more than this.
const GC_SMALL_FRAME: usize = 16 * 1024;

/// Hard cap on raw object size, enforced on both [`ObjectStore::write`]
/// and [`ObjectStore::read`].
pub const MAX_RAW_OBJECT_SIZE: usize = 1024 * 1024 * 1024; // 1 GiB

/// Hard cap on tree-walk recursion depth.
///
/// Every core tree-walker (`index::from_tree`, `ops::diff`, `ops::merge`,
/// `ops::restore`) recurses one native stack frame per directory level.
/// Content-addressing prevents true cycles (a child's hash can never equal
/// its parent's), but a crafted untrusted repo can still nest a few thousand
/// single-entry trees in a tiny pack and overflow the stack — a denial of
/// service reachable from `clone`/`checkout`/`merge`/`diff`. Walkers thread a
/// depth counter and abort with a typed `TreeTooDeep` error once
/// `depth > MAX_TREE_DEPTH`.
///
/// 128 is far beyond any legitimately-deep source tree (Git's own working
/// trees rarely exceed a couple dozen levels) while remaining comfortably
/// within a default 8 MiB thread stack. Mirrors the `MAX_REF_WALK_DEPTH` cap on
/// the ref-tree walker in `refs.rs`.
pub const MAX_TREE_DEPTH: usize = 128;

/// Errors raised by the [`ObjectStore`] surface. Distinct from
/// [`KitError`] so callers can pattern-match on filesystem failures
/// without losing the structured-decode-error variants.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    #[error("path is not a kit repository (missing .kit/objects)")]
    NotAKitRepository,
    #[error(".kit already exists in this directory")]
    AlreadyInitialized,
    #[error(
        "repository object-addressing format is {found:?}, expected \"{}\". This kit cannot read the repository. Update kit for newer capabilities or local pack versions. To move a `bmt-v1` repository, run `kit git export` with kit 0.7.3, then `kit git import` with this kit, or commit a checkout into a new `kit init` repository. See docs/specs/SPEC-MERKLE-OBJECTS.md.",
        FORMAT_VALUE
    )]
    IncompatibleRepoFormat { found: Option<String> },
    #[error("object {0} not found")]
    ObjectNotFound(String),
    #[error("object exceeds {} byte cap", MAX_RAW_OBJECT_SIZE)]
    ObjectTooLarge,
    #[error("tree nesting exceeds {} levels", MAX_TREE_DEPTH)]
    TreeTooDeep,
    /// A tree expands to more than [`MAX_TREE_LEAVES`] files, or to paths an
    /// index file could not hold.
    #[error("tree expands to more files, or longer paths, than a repository holds")]
    TreeTooLarge,
    /// A caller-selected in-memory operation budget was exhausted.
    #[error("object operation exceeded {0} limit")]
    OperationLimitExceeded(&'static str),
    #[error("on-disk bytes hash to {actual}, expected {expected}")]
    HashMismatch { expected: String, actual: String },
    /// A local pack or its index failed a check: a bad header, size,
    /// checksum, frame, extent or key. A failed read stays [`Self::Io`].
    #[error("local pack {pack}: {reason}")]
    LocalPackDamaged {
        /// The path of the damaged pack or index file.
        pack: Box<str>,
        /// What the check found.
        reason: Box<str>,
    },
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Decode(#[from] KitError),
    /// [`crate::transfer::plan_pack_with`]'s `encode_deltas` callback
    /// returned a different number of results than the candidate slice it
    /// was given — a contract violation by the caller (see that
    /// function's docs), never a normal runtime condition. Reported as a
    /// typed error rather than a panic: the built-in caller
    /// (`kit-bin`'s push path) can never trigger this since rayon's
    /// `IndexedParallelIterator::collect` always preserves length, but a
    /// future or third-party `encode_deltas` with a bug should fail the
    /// `push` cleanly rather than crash the process.
    #[error("encode_deltas callback returned {actual} results for {expected} candidates")]
    DeltaBatchLengthMismatch { expected: usize, actual: usize },
}

/// Deferred-fsync writer returned by [`ObjectStore::bulk_writer`].
/// See that method for the crash-safety contract.
#[derive(Debug)]
pub struct BulkWriter<'a> {
    store: &'a ObjectStore,
    dirs: std::collections::HashSet<PathBuf>,
    files: std::collections::HashSet<PathBuf>,
    refreshed: std::collections::HashSet<Hash>,
}

impl BulkWriter<'_> {
    /// Write one object durable-before-visible: contents are fsynced
    /// before the rename publishes the object, and only the shard-dir
    /// fsync (rename durability) is deferred to commit. This upholds the
    /// store's global invariant (an object is never visible before its
    /// bytes are durable), so another process's `contains()` dedup can
    /// never reference a half-written object. An existing path is
    /// byte-verified: matched objects are left in place with a refreshed
    /// `mtime` (SPEC-GC "Concurrent writers and the grace window"; still fsynced at commit, see below), torn ones
    /// are rewritten.
    ///
    /// # Panics
    /// Never in practice: object paths always have a 2-hex shard
    /// parent by construction.
    pub fn write(&mut self, bytes: &[u8]) -> StoreResult<Hash> {
        if bytes.len() > MAX_RAW_OBJECT_SIZE {
            return Err(StoreError::ObjectTooLarge);
        }
        // Before this writer's own shared guard, which would make the try miss.
        self.store.ensure_packed_once()?;
        let _guard = self.store.lock_writer()?;
        let h = object_id_from_bytes(bytes);
        let final_path = self.store.path_for(&h);
        // VERIFY-skip an existing object: content addressing makes
        // byte-equality the exact durability test — a good file (from
        // a previously committed session, possibly referenced by
        // native history) must NOT be replaced with an unsynced inode
        // a power loss could tear, while a torn file from a crashed
        // session fails the comparison and is healed by the rewrite.
        let shard_dir = final_path
            .parent()
            .expect("object path always has a 2-hex parent");
        // A match whose mtime cannot be refreshed (SPEC-GC "Concurrent writers and the grace window", see
        // `refresh_mtime`) is rewritten like a torn file.
        if let Ok(existing) = fs::read(&final_path)
            && existing == bytes
            && (self.refreshed.contains(&h) || refresh_mtime(&final_path).is_ok())
        {
            // The bytes may have matched out of the PAGE CACHE of a
            // crashed session's unsynced write — byte equality is not a
            // durability test, so this pre-existing file still needs a
            // content fsync at commit.
            self.dirs.insert(shard_dir.to_path_buf());
            self.files.insert(final_path);
            self.refreshed.insert(h);
            return Ok(h);
        }
        // `self.dirs` already records every shard this session has
        // touched — a shard present there was `create_dir_all`'d (or
        // observed via the byte-match branch above, which also implies
        // it exists) by an earlier `write` call in this same session,
        // so a repeat `create_dir_all` here is a guaranteed-redundant
        // mkdir + is_dir stat (std's fallback path on `AlreadyExists`).
        // At most 256 shards exist, so memoizing saves ~2 syscalls per
        // object on large bulk ingests (git-import) — the same
        // `created_shards` memoization `WriteBatch::write_prehashed`
        // already applies to the batched-add path.
        if !self.dirs.contains(shard_dir) {
            fs::create_dir_all(shard_dir)?;
        }
        // Content fsync happens BEFORE the rename, so the object is
        // durable the instant it becomes visible. Only the rename's
        // durability (the shard dir fsync) is deferred to commit.
        crate::atomic::write_content_synced(&final_path, bytes)?;
        self.dirs.insert(shard_dir.to_path_buf());
        self.refreshed.insert(h);
        Ok(h)
    }

    /// Refresh a cached object's grace window and return its immediate history
    /// references without re-hashing it. The import map already identifies the
    /// object; this is retention bookkeeping, not an integrity check.
    /// Missing objects or malformed reference metadata refuse reuse. Visit the
    /// returned references too, including chunks absent from the git map.
    ///
    /// # Panics
    /// Object paths always have a shard parent; panics if that internal
    /// path-layout invariant is violated.
    pub fn reuse_object(&mut self, h: &Hash) -> StoreResult<Vec<Hash>> {
        let _guard = self.store.lock_writer()?;
        self.store.packs.lookup(self.store, h, true, |location| {
            let mut contents = location.open()?;
            let (object_type, _) = head_at(&mut contents)?;
            let children = if location.is_packed()
                || !matches!(
                    object_type,
                    crate::object::ObjectType::Blob | crate::object::ObjectType::Delta
                ) {
                let bytes = ObjectStore::raw_at(&location)?;
                if location.is_packed() {
                    ObjectStore::verify_at(&location, h, &bytes)?;
                }
                let object = serialize::deserialize_owned(bytes)?;
                crate::ops::graph::children(&object, crate::ops::graph::ClosureMode::History)
            } else {
                Vec::new()
            };
            let path = location.path();
            if !self.refreshed.contains(h) {
                refresh_mtime(path)?;
                self.refreshed.insert(*h);
            }
            self.dirs
                .insert(path.parent().expect("object path has parent").to_path_buf());
            if location.is_packed() {
                self.dirs.insert(self.store.objects_root.clone());
            }
            self.files.insert(path.to_path_buf());
            Ok(children)
        })
    }

    /// Make the session durable: fsync the CONTENTS of any pre-existing
    /// objects this batch re-used (newly written objects were already
    /// content-fsynced before their rename in [`write`](Self::write)),
    /// then every touched shard directory (renames become durable).
    pub fn commit(self) -> StoreResult<()> {
        for file in &self.files {
            sync_reused_file(file)?;
        }
        for dir in &self.dirs {
            crate::atomic::sync_dir(dir)?;
        }
        Ok(())
    }
}

/// Proof that the holder keeps gc from deleting objects. See
/// [`ObjectStore::prune_guard`]. The lock is released when the guard drops.
#[must_use = "the guard protects the store only while it is alive"]
#[derive(Debug)]
pub struct PruneGuard {
    format: File,
    objects_root: PathBuf,
}

/// Result alias used throughout this module.
pub type StoreResult<T> = Result<T, StoreError>;

#[derive(Debug, Default)]
struct PackWrites {
    direct_catalog: OnceLock<Option<Arc<PackCatalog>>>,
    direct_synced: Mutex<bool>,
    root_synced: std::sync::atomic::AtomicBool,
    /// Set once this handle's one try at the activation has missed. A try that
    /// activates the store is recorded as enabled, and a failed try is not
    /// recorded, so it is returned again. Other
    /// threads wait on the lock, so none takes a shared guard that would make
    /// the first try miss.
    activation: Mutex<bool>,
    /// The marker and the parents of `pack/` were synced and `pack/` exists,
    /// so a later pack writer only checks the marker under its own guard.
    pack_dir_prepared: std::sync::atomic::AtomicBool,
}

/// Local content-addressed object store backed by the filesystem.
#[derive(Debug, Clone)]
pub struct ObjectStore {
    /// Absolute path to `<root>/.kit/objects`.
    objects_root: PathBuf,
    packs: Arc<local_pack::LocalPacks>,
    pack_writes: Arc<PackWrites>,
    /// Flush/rename primitive seam. Production code always uses
    /// [`RealSyncer`]; unit tests inject a recording double to assert
    /// flush ordering and counts (the O(1)-flushes-per-batch contract).
    syncer: Arc<dyn Syncer>,
    /// Policy handed out by [`Self::batch`]. Defaults to
    /// [`SyncPolicy::Batch`]; the CLI maps the repo config key
    /// `durability.objects = per-object` onto it for deployments that
    /// want the strict historical schedule.
    default_policy: SyncPolicy,
    /// Test-only counter of physical reads (`read_raw` calls) this store
    /// has performed. There is no read-side equivalent of `syncer` to
    /// inject a recording double against, so this is a plain counter
    /// instead — used to prove callers (e.g. the pack reader's delta-base
    /// resolution) hit the store at most once per distinct
    /// object rather than once per reference to it.
    #[cfg(test)]
    read_calls: Arc<AtomicU64>,
    /// Test-only: bytes of packed blobs that a gc type probe hashed.
    #[cfg(test)]
    gc_hashed_bytes: Arc<AtomicU64>,
    /// Test-only: gc type probes that the one-read path answered.
    #[cfg(test)]
    gc_one_read_probes: Arc<AtomicU64>,
    /// Test-only: set to send every gc type probe down the streaming path,
    /// to compare it with the one-read path.
    #[cfg(test)]
    gc_stream_only: Arc<std::sync::atomic::AtomicBool>,
}

impl ObjectStore {
    /// Open the existing repository described by `layout`. Returns
    /// [`StoreError::NotAKitRepository`] if the layout's `objects/`
    /// directory does not exist. The object store is common-dir
    /// (shared) state — see [`crate::layout`].
    pub fn open(layout: &RepoLayout) -> StoreResult<Self> {
        let objects_root = layout.objects_dir();
        if !objects_root.is_dir() {
            return Err(StoreError::NotAKitRepository);
        }
        let packed = format::check(&layout.format_file())?;
        Ok(Self {
            objects_root,
            packs: Arc::new(local_pack::LocalPacks::new(packed)),
            pack_writes: Arc::default(),
            syncer: Arc::new(RealSyncer),
            default_policy: SyncPolicy::Batch,
            #[cfg(test)]
            read_calls: Arc::new(AtomicU64::new(0)),
            #[cfg(test)]
            gc_hashed_bytes: Arc::new(AtomicU64::new(0)),
            #[cfg(test)]
            gc_one_read_probes: Arc::new(AtomicU64::new(0)),
            #[cfg(test)]
            gc_stream_only: Arc::default(),
        })
    }

    /// Initialise a fresh common dir for the repository described by
    /// `layout`. Returns [`StoreError::AlreadyInitialized`] if the
    /// common dir already exists, unless a killed `init` made it: a common
    /// dir with no format marker and no objects holds nothing and is
    /// initialised again, as `git init` does.
    pub fn init(layout: &RepoLayout) -> StoreResult<Self> {
        if layout.common_dir().exists() && !is_unfinished_init(layout)? {
            return Err(StoreError::AlreadyInitialized);
        }
        let objects_root = layout.objects_dir();
        fs::create_dir_all(&objects_root)?;
        // Declare the object-addressing format, with the packed capability,
        // so a different kit fails loudly (SPEC-OBJECTS §7). The marker is
        // synced before `init` returns, so a crash leaves no marker or the
        // whole one.
        let marker = format::init_marker(&layout.format_file());
        crate::atomic::write_atomic(&layout.format_file(), marker, false)?;
        Ok(Self {
            objects_root,
            packs: Arc::new(local_pack::LocalPacks::new(marker == format::PACKED)),
            pack_writes: Arc::default(),
            syncer: Arc::new(RealSyncer),
            default_policy: SyncPolicy::Batch,
            #[cfg(test)]
            read_calls: Arc::new(AtomicU64::new(0)),
            #[cfg(test)]
            gc_hashed_bytes: Arc::new(AtomicU64::new(0)),
            #[cfg(test)]
            gc_one_read_probes: Arc::new(AtomicU64::new(0)),
            #[cfg(test)]
            gc_stream_only: Arc::default(),
        })
    }

    /// Test-only: a new store with the legacy marker, as an earlier kit made it.
    #[cfg(test)]
    pub(crate) fn init_loose(layout: &RepoLayout) -> StoreResult<Self> {
        Self::init(layout)?;
        fs::write(layout.format_file(), format!("{FORMAT_VALUE}\n").as_bytes())?;
        Self::open(layout)
    }

    /// Select the [`SyncPolicy`] that [`Self::batch`] hands out. The
    /// CLI wires the repo config key `durability.objects` here so
    /// deployments on filesystems where they prefer the strict
    /// per-object schedule can opt into it (SPEC-OBJECTS §10.1).
    pub fn set_sync_policy(&mut self, policy: SyncPolicy) {
        self.default_policy = policy;
    }

    /// Replace the flush/rename primitives. Test-only seam — see the
    /// `syncer` field. Not exposed publicly so the production sync
    /// strategy cannot be silently weakened by downstream code.
    #[cfg(test)]
    pub(crate) fn set_syncer(&mut self, syncer: Arc<dyn Syncer>) {
        self.syncer = syncer;
    }

    /// The active flush/rename primitives, shared with [`WriteBatch`].
    pub(crate) fn syncer(&self) -> &Arc<dyn Syncer> {
        &self.syncer
    }

    /// Test-only: number of physical filesystem reads this store has
    /// performed (via [`Self::read`] or [`Self::read_unverified`]) since
    /// creation. See the `read_calls` field doc for why this is a plain
    /// counter rather than an injectable double like [`Self::set_syncer`].
    #[cfg(test)]
    pub(crate) fn read_call_count(&self) -> u64 {
        self.read_calls.load(Ordering::Relaxed)
    }

    /// Test-only: bytes of packed blobs hashed by gc type probes so far.
    #[cfg(test)]
    pub(crate) fn gc_hashed_byte_count(&self) -> u64 {
        self.gc_hashed_bytes.load(Ordering::Relaxed)
    }

    /// Test-only: gc type probes that the one-read path answered so far.
    #[cfg(test)]
    pub(crate) fn gc_one_read_probe_count(&self) -> u64 {
        self.gc_one_read_probes.load(Ordering::Relaxed)
    }

    /// Test-only: probe every packed object through the streaming path.
    #[cfg(test)]
    pub(crate) fn gc_probe_streaming_only(&self) {
        self.gc_stream_only.store(true, Ordering::Relaxed);
    }

    /// Start a batched write with the store's configured policy
    /// (default [`SyncPolicy::Batch`]): objects staged by the batch
    /// become durable and visible together at [`WriteBatch::commit`],
    /// with O(1) full flushes per batch instead of per object.
    #[must_use]
    pub fn batch(&self) -> WriteBatch<'_> {
        self.batch_with_policy(self.default_policy)
    }

    /// Start a batched write with an explicit [`SyncPolicy`].
    #[must_use]
    pub fn batch_with_policy(&self, policy: SyncPolicy) -> WriteBatch<'_> {
        WriteBatch::new(self, policy)
    }

    /// Returns `true` when `root` contains a `.kit/objects` directory.
    #[must_use]
    pub fn is_repo_root(root: &Path) -> bool {
        root.join(KIT_DIR).join(OBJECTS_DIR).is_dir()
    }

    /// Absolute path to the `objects/` directory.
    #[must_use]
    pub fn objects_root(&self) -> &Path {
        &self.objects_root
    }

    /// The directory transfers spool packs in: `tmp/` beside `objects/`, so
    /// a spool takes its space from the repository's filesystem. It is
    /// created on demand. Spools in it are unnamed files, see
    /// [`crate::pack::sweep_spool_dir`].
    #[must_use]
    pub fn spool_dir(&self) -> PathBuf {
        self.objects_root
            .parent()
            .map_or_else(|| self.objects_root.join("tmp"), |kit| kit.join("tmp"))
    }

    /// Length of the path of the objects directory, which every staged and
    /// stored object path starts with.
    pub(crate) fn objects_root_len(&self) -> usize {
        self.objects_root.as_os_str().len()
    }

    /// Compute the on-disk path for `hash`, joined under `objects/`.
    /// `pub(crate)` so [`WriteBatch`] shares the single layout rule.
    pub(crate) fn path_for(&self, h: &Hash) -> PathBuf {
        let p = object_path(h);
        // Both halves are ASCII hex by construction in `object_path`.
        let dir = std::str::from_utf8(&p.dir).expect("ascii hex");
        let file = std::str::from_utf8(&p.file).expect("ascii hex");
        self.objects_root.join(dir).join(file)
    }

    /// Returns `true` when the object `h` is present in the store. Does
    /// **not** verify integrity — use [`Self::read`] for that.
    #[must_use]
    pub fn contains(&self, h: &Hash) -> bool {
        self.check_presence(h).is_ok()
    }

    /// Check for a usable location without verifying the object body.
    ///
    /// # Errors
    /// Returns a lookup failure or `ObjectNotFound` for a confirmed miss.
    pub fn check_presence(&self, h: &Hash) -> StoreResult<()> {
        self.packs
            .lookup(self, h, true, |location| location.present())
    }

    /// Write `bytes` to the store, returning their BLAKE3 hash. Atomic:
    /// writes to a sibling temp file, `fsync`s, then renames into place.
    /// Idempotent — re-writing the same bytes is a no-op (the temp file
    /// is unlinked on the early-return path).
    ///
    /// # Panics
    ///
    /// Panics only if the internal hash-to-path mapping produces a path
    /// without a parent directory, which is impossible by construction.
    pub fn write(&self, bytes: &[u8]) -> StoreResult<Hash> {
        if bytes.len() > MAX_RAW_OBJECT_SIZE {
            return Err(StoreError::ObjectTooLarge);
        }
        self.ensure_packed_once()?;
        let h = object_id_from_bytes(bytes);
        let final_path = self.path_for(&h);
        if final_path.exists() {
            // Dedup hit: the object is visible, but if another process
            // renamed it and has not yet flushed the dirent, it may not
            // be durable — and our caller is about to reference it.
            // The `mtime` is left alone: callers hold locks gc also
            // takes, so gc's grace window does not apply to them (see
            // `refresh_mtime`).
            // Flush its shard dir before returning (SPEC-OBJECTS §10.1
            // dedup rule, mirroring WriteBatch's touched_shards).
            self.syncer()
                .dir_sync(final_path.parent().expect("object path has parent"))?;
            return Ok(h);
        }
        if self.reuse_direct_pack(&h, bytes.len() as u64)? {
            return Ok(h);
        }
        let shard_dir = final_path
            .parent()
            .expect("object path always has a 2-hex parent");
        // A shard that this call creates is an entry of `objects/`, which the
        // shard flush in `write_atomic` does not cover.
        let new_shard = fs::create_dir(shard_dir).is_ok();
        // A no-op when the shard exists; otherwise it makes `objects/` or names
        // why the shard cannot be made.
        fs::create_dir_all(shard_dir)?;
        write_atomic(&final_path, bytes, &**self.syncer())?;
        if new_shard {
            self.syncer().dir_sync(&self.objects_root)?;
        }
        Ok(h)
    }

    fn reuse_direct_pack(&self, h: &Hash, size: u64) -> StoreResult<bool> {
        let Some(catalog) = self
            .pack_writes
            .direct_catalog
            .get_or_init(|| self.discover_write_packs().map(|(_, catalog)| catalog))
        else {
            return Ok(false);
        };
        if !catalog.may_contain(h) {
            return Ok(false);
        }
        let _guard = self.prune_guard()?;
        if !self.has_packed_size(catalog, h, size) {
            return Ok(false);
        }
        let mut synced = self
            .pack_writes
            .direct_synced
            .lock()
            .expect("pack sync mutex");
        if !*synced {
            self.syncer().dir_sync(&self.pack_dir())?;
            if self.pack_parent_needs_sync() {
                self.syncer().dir_sync(self.objects_root())?;
                self.mark_pack_parent_synced();
            }
            *synced = true;
        }
        Ok(true)
    }

    pub(crate) fn discover_write_packs(&self) -> Option<(PruneGuard, Arc<PackCatalog>)> {
        if !self.local_packs_enabled().unwrap_or(false) {
            return None;
        }
        let guard = self.prune_guard().ok()?;
        let catalog = self.packs.write_catalog(self).ok()?;
        Some((guard, catalog))
    }

    pub(crate) fn has_packed_size(&self, catalog: &PackCatalog, h: &Hash, size: u64) -> bool {
        self.packs.has_packed_size(catalog, h, size)
    }

    pub(crate) fn pack_parent_needs_sync(&self) -> bool {
        !self
            .pack_writes
            .root_synced
            .load(std::sync::atomic::Ordering::Acquire)
    }

    pub(crate) fn mark_pack_parent_synced(&self) {
        self.pack_writes
            .root_synced
            .store(true, std::sync::atomic::Ordering::Release);
    }

    /// Begin a bulk-write session: each new object is written
    /// durable-before-visible (contents fsynced, then renamed), and
    /// [`BulkWriter::commit`] batches the directory fsyncs (rename
    /// durability) plus a content fsync of any re-used pre-existing
    /// objects once at the end, instead of fsyncing a dir per write.
    ///
    /// Because content is durable before the rename, the session upholds
    /// the store's global invariant even under concurrent readers: an
    /// object another process can `contains()`-dedup against is always
    /// backed by durable bytes.
    ///
    /// Crash-safety contract (deliberately weaker than [`Self::write`]
    /// only for the rename/dirent half, for callers whose whole
    /// operation is idempotent — e.g. the deterministic git-import,
    /// which re-runs from a retained source mirror): after a crash
    /// BEFORE `commit`, a just-renamed object's dirent may be lost (the
    /// shard dir is not yet fsynced), so objects may be missing — never
    /// torn, since contents were fsynced first. Existing paths are
    /// VERIFIED (byte compare)
    /// rather than blindly rewritten or blindly trusted: a matching
    /// file is left in place with only its `mtime` refreshed (it may be
    /// durable and referenced by native history — replacing it with an
    /// unsynced inode would put it at risk), a torn one is healed by
    /// rewrite, and reads always
    /// BLAKE3-verify. Callers MUST gate bulk sessions behind their
    /// own crash marker and re-run on detection.
    #[must_use]
    pub fn bulk_writer(&self) -> BulkWriter<'_> {
        BulkWriter {
            store: self,
            dirs: std::collections::HashSet::new(),
            files: std::collections::HashSet::new(),
            refreshed: std::collections::HashSet::new(),
        }
    }

    fn raw_at(location: &local_pack::Location) -> StoreResult<Vec<u8>> {
        let contents = location.open()?;
        let len = contents.len;
        let capacity = raw_capacity(len)?;
        let bytes = read_to_end_capped(contents, capacity, MAX_RAW_OBJECT_SIZE)?;
        if location.is_packed() && bytes.len() as u64 != len {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
        }
        Ok(bytes)
    }

    /// Retain one rejected copy only for the closure verifier's diagnostic.
    /// Try every location for a verified copy first.
    pub(crate) fn read_raw_for_verification(&self, h: &Hash) -> StoreResult<Vec<u8>> {
        let mut rejected = None;
        self.read_with(h, |location| {
            let bytes = Self::raw_at(&location)?;
            let result = Self::verify_at(&location, h, &bytes);
            if let Err(e) = result {
                if matches!(e, StoreError::HashMismatch { .. }) && rejected.is_none() {
                    rejected = Some(location);
                }
                return Err(e);
            }
            Ok(bytes)
        })
        .or_else(|e| {
            if matches!(e, StoreError::IncompatibleRepoFormat { .. }) {
                return Err(e);
            }
            match rejected {
                Some(location) => Self::raw_at(&location),
                None => Err(e),
            }
        })
    }

    fn read_with<T>(
        &self,
        h: &Hash,
        use_location: impl FnMut(local_pack::Location) -> StoreResult<T>,
    ) -> StoreResult<T> {
        self.read_with_in(h, None, use_location)
    }

    fn read_with_in<T>(
        &self,
        h: &Hash,
        currency: Option<&local_pack::Currency>,
        use_location: impl FnMut(local_pack::Location) -> StoreResult<T>,
    ) -> StoreResult<T> {
        #[cfg(test)]
        self.read_calls.fetch_add(1, Ordering::Relaxed);
        self.packs.lookup_in(self, h, true, currency, use_location)
    }

    fn verify_at(location: &local_pack::Location, h: &Hash, bytes: &[u8]) -> StoreResult<()> {
        let id = if location.is_packed() {
            match local_pack::canonical_id(bytes) {
                Ok(id) => id,
                Err(e) => {
                    check_hash(h, blake3::hash(bytes).as_bytes())?;
                    return Err(local_pack::named(location.path(), e));
                }
            }
        } else {
            object_id_from_bytes(bytes)
        };
        check_hash(h, &id)
    }

    /// Read and verify the contents of the requested object.
    pub fn read(&self, h: &Hash) -> StoreResult<Vec<u8>> {
        self.read_in(h, None)
    }

    fn read_in(&self, h: &Hash, currency: Option<&local_pack::Currency>) -> StoreResult<Vec<u8>> {
        self.read_with_in(h, currency, |location| {
            let bytes = Self::raw_at(&location)?;
            Self::verify_at(&location, h, &bytes)?;
            Ok(bytes)
        })
    }

    /// Try each location, reserving bytes before reading it through the
    /// caller's allocator.
    pub(crate) fn read_with_allocator<E: From<StoreError>>(
        &self,
        h: &Hash,
        mut allocate: impl FnMut(usize) -> Result<Vec<u8>, E>,
    ) -> Result<Vec<u8>, E> {
        let mut allocation_error = None;
        let result = self.read_with(h, |location| {
            let mut contents = location.open()?;
            let len = raw_capacity(contents.len)?;
            let mut bytes = match allocate(len) {
                Ok(bytes) => bytes,
                Err(e) => {
                    allocation_error.get_or_insert(e);
                    return Err(StoreError::OperationLimitExceeded("object allocation"));
                }
            };
            bytes.resize(len, 0);
            contents.read_exact(&mut bytes)?;
            if contents.read(&mut [0])? != 0 {
                return Err(StoreError::ObjectTooLarge);
            }
            Self::verify_at(&location, h, &bytes)?;
            Ok(bytes)
        });
        result.map_err(|e| match e {
            StoreError::IncompatibleRepoFormat { .. } => E::from(e),
            other => allocation_error.unwrap_or_else(|| E::from(other)),
        })
    }

    /// Read a loose object's bytes without the BLAKE3 check that
    /// [`Self::read`] performs. Packed reads always verify the object's
    /// encoding and id because the locator is separate from the payload.
    ///
    /// # Policy — display-only paths ONLY
    /// This exists for hot read-only rendering (`diff`/`show`/commit
    /// summaries formatting a diffstat or patch preview). It is the same
    /// "cheap read" tradeoff [`Self::object_type`] already makes for shape
    /// checks (see its doc and [`Self::verify_object_type`], which is the
    /// *verifying* twin used by tree-publication paths) — extended here to
    /// the full object body.
    ///
    /// NEVER use this for publication (commit/merge/rebase tree writes),
    /// dedup, fetch/apply, or any path whose output is consumed as data
    /// rather than displayed and discarded. kit never feeds unverified
    /// bytes into state that kit itself writes, or into output that
    /// kit's own tooling round-trips (e.g. `format-patch` piped into
    /// `git am`). On corruption, callers of `read` get a loud, typed error
    /// before anything downstream can act on bad bytes; callers of
    /// `read_unverified` get whatever a decoder makes of the corrupt bytes
    /// — a decode error, or in the worst case garbage in the *rendered
    /// output* — but never durable state, because display paths write
    /// nothing back to the store.
    ///
    /// Prefer wrapping the source with [`DisplaySource`] at the render
    /// call site over calling this directly; that keeps the verify/
    /// no-verify choice at the boundary instead of threading a flag
    /// through render code.
    pub fn read_unverified(&self, h: &Hash) -> StoreResult<Vec<u8>> {
        self.read_unverified_in(h, None)
    }

    fn read_unverified_in(
        &self,
        h: &Hash,
        currency: Option<&local_pack::Currency>,
    ) -> StoreResult<Vec<u8>> {
        self.read_with_in(h, currency, |location| {
            let bytes = Self::raw_at(&location)?;
            if location.is_packed() {
                Self::verify_at(&location, h, &bytes)?;
            }
            Ok(bytes)
        })
    }

    /// The object's type tag, from its 6-byte prologue — without
    /// reading or hash-verifying the body. Backs cheap shape checks
    /// (e.g. "is this staged hash blob-like?") that previously paid a
    /// full read+BLAKE3 of every staged blob per status/commit; the
    /// real read path still integrity-verifies at use time.
    ///
    /// # Errors
    /// [`StoreError::ObjectNotFound`] if absent; [`StoreError::Decode`]
    /// for a short file, bad magic/version, or unknown tag.
    pub fn object_type(&self, h: &Hash) -> StoreResult<crate::object::ObjectType> {
        self.object_type_in(h, None)
    }

    fn object_type_in(
        &self,
        h: &Hash,
        currency: Option<&local_pack::Currency>,
    ) -> StoreResult<crate::object::ObjectType> {
        self.packs.lookup_in(self, h, true, currency, |location| {
            let mut prologue = [0; 6];
            match location.read_head(&mut prologue)? {
                Ok(6) => parse_type(&prologue),
                _ => Err(StoreError::Decode(KitError::EmptyData)),
            }
        })
    }

    /// Verify a packed leaf before letting its type end a retention walk.
    /// An index can locate bytes of a different object. Non-leaf types are
    /// followed by a verified read of the object before their edges are used.
    pub(crate) fn gc_object_type(&self, h: &Hash) -> StoreResult<crate::object::ObjectType> {
        self.gc_probe(h, true)
    }

    /// The type of an id that a manifest lists, for the mark's chunk pass.
    ///
    /// A chunk is a leaf by rule: gc follows no edge from it, so what a copy
    /// holds past its head cannot change what the mark keeps. For a packed
    /// copy this reads the 10-byte head and checks that a blob's prologue
    /// names the frame length. It does not read or hash the payload. Every
    /// step that deletes or replaces a copy in reliance on a packed copy
    /// verifies that copy itself, and an integrity scan reports a bad
    /// payload. The local writer's reuse of a packed copy by id and length
    /// does not verify it either. An id that the walk reaches as a file goes
    /// through [`Self::gc_object_type`] instead.
    pub(crate) fn gc_chunk_type(&self, h: &Hash) -> StoreResult<crate::object::ObjectType> {
        self.gc_probe(h, false)
    }

    fn gc_probe(&self, h: &Hash, verify: bool) -> StoreResult<crate::object::ObjectType> {
        use crate::object::ObjectType;

        self.packs.lookup(self, h, true, |location| {
            if let Some(ty) = self.gc_probe_in_one_read(&location, h, verify)? {
                #[cfg(test)]
                self.gc_one_read_probes.fetch_add(1, Ordering::Relaxed);
                return Ok(ty);
            }
            let mut contents = location.open()?;
            let mut header = [0; serialize::BLOB_PROLOGUE_LEN];
            contents
                .read_exact(&mut header[..6])
                .map_err(|_| StoreError::Decode(KitError::EmptyData))?;
            let ty = parse_type(&header[..6])?;
            if !location.is_packed() {
                return Ok(ty);
            }
            match ty {
                ObjectType::Blob => {
                    contents.read_exact(&mut header[6..])?;
                    let payload_len = raw_capacity(contents.len)? - header.len();
                    if header != serialize::blob_prologue(payload_len)? {
                        return Err(local_pack::invalid_at(
                            location.path(),
                            "invalid packed blob header",
                        ));
                    }
                    if verify {
                        #[cfg(test)]
                        self.gc_hashed_bytes
                            .fetch_add(contents.len, Ordering::Relaxed);
                        let mut hash = blake3::Hasher::new();
                        hash.update(&header);
                        hash.update_reader(contents)?;
                        check_hash(h, hash.finalize().as_bytes())?;
                    }
                    Ok(ty)
                }
                ObjectType::Delta => Err(local_pack::invalid_at(
                    location.path(),
                    "delta object in local pack",
                )),
                _ => Ok(ty),
            }
        })
    }

    /// [`Self::gc_probe`] of a packed copy whose probe one read answers: the
    /// head of any frame when `verify` is false, and the whole frame when
    /// `verify` is true and the frame is at most [`GC_SMALL_FRAME`] bytes.
    /// The read checks the frame header against the index first, as opening
    /// the frame does. Each check below is the one the streaming path makes.
    /// `None` leaves the probe to that path: a loose copy, a frame too short
    /// for a blob head, a frame too large to hold in memory, or a failed read,
    /// so that a damaged pack gives the same error.
    #[cfg_attr(not(test), allow(clippy::unused_self))] // the counters exist only in tests
    fn gc_probe_in_one_read(
        &self,
        location: &local_pack::Location,
        h: &Hash,
        verify: bool,
    ) -> StoreResult<Option<crate::object::ObjectType>> {
        use crate::object::ObjectType;

        #[cfg(test)]
        if self.gc_stream_only.load(Ordering::Relaxed) {
            return Ok(None);
        }
        let Some(raw_len) = location.frame_len() else {
            return Ok(None);
        };
        let frame_len = raw_len as usize;
        let whole = verify && frame_len <= GC_SMALL_FRAME;
        if frame_len < serialize::BLOB_PROLOGUE_LEN || (verify && !whole) {
            return Ok(None);
        }
        let want = if whole {
            frame_len
        } else {
            serialize::BLOB_PROLOGUE_LEN
        };
        let mut bytes = vec![0; want];
        if !matches!(location.read_head(&mut bytes)?, Ok(len) if len == bytes.len()) {
            return Ok(None);
        }
        let ty = parse_type(&bytes[..6])?;
        match ty {
            ObjectType::Blob => {
                let payload_len = raw_capacity(u64::from(raw_len))? - serialize::BLOB_PROLOGUE_LEN;
                if bytes[..serialize::BLOB_PROLOGUE_LEN] != serialize::blob_prologue(payload_len)? {
                    return Err(local_pack::invalid_at(
                        location.path(),
                        "invalid packed blob header",
                    ));
                }
                if whole {
                    #[cfg(test)]
                    self.gc_hashed_bytes
                        .fetch_add(frame_len as u64, Ordering::Relaxed);
                    check_hash(h, blake3::hash(&bytes).as_bytes())?;
                }
                Ok(Some(ty))
            }
            ObjectType::Delta => Err(local_pack::invalid_at(
                location.path(),
                "delta object in local pack",
            )),
            _ => Ok(Some(ty)),
        }
    }

    /// The object's type tag and, for a `Blob`, its content length, from the
    /// first 10 bytes — without reading or hash-verifying the body. The
    /// chunk check of [`crate::ops::graph::check_closure_present`] uses it:
    /// a chunk is a `Blob` whose length is its manifest span.
    ///
    /// # Errors
    /// As [`Self::object_type`], and [`StoreError::Decode`] for a `Blob`
    /// shorter than its 10-byte prologue.
    pub fn object_head(&self, h: &Hash) -> StoreResult<(crate::object::ObjectType, Option<u64>)> {
        self.object_head_in(h, None)
    }

    fn object_head_in(
        &self,
        h: &Hash,
        currency: Option<&local_pack::Currency>,
    ) -> StoreResult<(crate::object::ObjectType, Option<u64>)> {
        self.packs.lookup_in(self, h, true, currency, |location| {
            let mut head = [0; 10];
            let len = location.read_head(&mut head)??;
            head_of(&head[..len])
        })
    }

    /// Convenience: read raw bytes and decode into a typed [`Object`].
    ///
    /// A merkelized type ([`Object::Tree`] / [`Object::ChunkedBlob`]) is
    /// already decoded once by `verified_id_and_object` to compute its
    /// BMT-root id for the integrity check below — reused directly here
    /// instead of a second `deserialize` of the same bytes (the two
    /// decodes this function used to pay for every tree/chunked-blob
    /// read, once inside [`Self::read`]'s verification and once here).
    /// Every other type was only ever decoded once (verification there is
    /// a plain `BLAKE3(bytes)`, no decode).
    ///
    /// A `Blob` keeps the buffer it was read into: the 10-byte head is
    /// shifted out in place, so the payload is never copied into a second
    /// allocation. A head that is not the canonical prologue for the
    /// payload's length goes to [`serialize::deserialize`], so every
    /// outcome, object or error, matches the generic decoder.
    pub fn read_object(&self, h: &Hash) -> StoreResult<Object> {
        self.read_object_in(h, None)
    }

    fn read_object_in(
        &self,
        h: &Hash,
        currency: Option<&local_pack::Currency>,
    ) -> StoreResult<Object> {
        self.read_with_in(h, currency, |location| {
            let bytes = Self::raw_at(&location)?;
            let (actual, decoded) = verified_id_and_object(&bytes);
            check_hash(h, &actual)?;
            let object = match decoded {
                Some(object) => object,
                None => serialize::deserialize_owned(bytes)?,
            };
            if location.is_packed() && matches!(object, Object::Delta(_)) {
                return Err(local_pack::invalid_at(
                    location.path(),
                    "delta object in local pack",
                ));
            }
            Ok(object)
        })
    }

    /// Hash-verifying variant of [`object_type`](Self::object_type): reads
    /// the whole object and confirms its content hashes to `h` before
    /// returning the declared type. This is the integrity guard for
    /// tree-publication paths (commit, merge, rebase, …) — `object_type`
    /// alone reads only the 6-byte prologue, so a staged object corrupted
    /// after `add` would otherwise be published into a durable tree and
    /// only fail at later read time. A commit skips the objects its parent
    /// tree already names at the same path (see
    /// [`build_tree_from_index_against`](crate::worktree::build_tree_from_index_against)).
    /// Use `object_type` on hot read-only paths (status/diff snapshots)
    /// where nothing durable is published.
    pub fn verify_object_type(&self, h: &Hash) -> StoreResult<crate::object::ObjectType> {
        parse_type(&self.read(h)?)
    }

    /// Enumerate every object hash currently in the store by walking
    /// `objects/<2-hex>/<62-hex>`. Entries whose names are not the
    /// expected hex shape (stray files, atomic-write temp files, unknown
    /// dirs) are skipped — they are not objects. Holds every id at once; a
    /// caller that can work a directory at a time uses
    /// [`list_shard`](Self::list_shard).
    ///
    /// # Errors
    /// [`StoreError::Io`] if a directory cannot be read (gc must then
    /// fail closed rather than prune against a partial enumeration).
    pub fn iter_object_hashes(&self) -> StoreResult<Vec<Hash>> {
        let mut out = Vec::new();
        let shards = match fs::read_dir(&self.objects_root) {
            Ok(rd) => rd,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(StoreError::Io(e)),
        };
        for shard in shards {
            let shard = shard?;
            if !shard.file_type()?.is_dir() {
                continue;
            }
            let dir_name = shard.file_name();
            let Some(dir) = dir_name.to_str() else {
                continue;
            };
            if dir.len() != 2 || !dir.bytes().all(|b| b.is_ascii_hexdigit()) {
                continue;
            }
            read_shard_dir(&shard.path(), dir, &mut out)?;
        }
        self.packs.collect(self, &mut out)?;
        out.sort_unstable();
        out.dedup();
        Ok(out)
    }

    /// Enumerate the objects in one shard directory, `objects/<2-hex>/`,
    /// where `shard` is the first byte of their ids. The names that
    /// [`iter_object_hashes`](Self::iter_object_hashes) skips are skipped
    /// here too, and an absent directory has no objects. Holds one
    /// directory's ids, not the whole store's.
    ///
    /// # Errors
    /// [`StoreError::Io`] if the directory cannot be read.
    pub fn list_shard(&self, shard: u8) -> StoreResult<Vec<Hash>> {
        let mut out = self.list_loose_shard(shard)?;
        self.packs.list_shard(self, shard, &mut out)?;
        out.sort_unstable();
        out.dedup();
        Ok(out)
    }

    pub(crate) fn list_loose_shard(&self, shard: u8) -> StoreResult<Vec<Hash>> {
        let dir = format!("{shard:02x}");
        let path = self.objects_root.join(&dir);
        // Like `iter_object_hashes`, which skips an entry that is not a
        // directory in its own right, a symlink here is not a shard.
        match fs::symlink_metadata(&path) {
            Ok(meta) if meta.is_dir() => {}
            Ok(_) => return Ok(Vec::new()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(StoreError::Io(e)),
        }
        let mut out = Vec::new();
        read_shard_dir(&path, &dir, &mut out)?;
        Ok(out)
    }

    /// Serialized size of the object, regardless of storage location.
    ///
    /// # Errors
    /// Returns a lookup failure or `ObjectNotFound` for a confirmed miss.
    pub fn object_size(&self, h: &Hash) -> StoreResult<u64> {
        self.size_lookup(h, true)
    }

    pub(crate) fn cached_object_size(&self, h: &Hash) -> StoreResult<u64> {
        self.size_lookup(h, false)
    }

    fn size_lookup(&self, h: &Hash, refresh: bool) -> StoreResult<u64> {
        self.packs
            .lookup(self, h, refresh, |location| location.size())
    }

    pub(crate) fn known_object(&self, h: &Hash) -> bool {
        self.packs
            .lookup(self, h, false, |location| location.present())
            .is_ok()
    }

    /// Make durable the directory entries of the shard directories
    /// `objects/<2-hex>/` named by `shards`, each the first byte of the ids
    /// it holds and of the pack directory in a packed store. Issue a
    /// barrier per directory and one device flush. With no shards, skip
    /// the barriers and the flush.
    ///
    /// Call it before a ref names objects this process found in the store
    /// rather than wrote. A visible object's bytes are durable, but another
    /// process may have renamed it into place and not yet flushed its
    /// directory entry (SPEC-OBJECTS §10.1).
    ///
    /// # Errors
    /// [`StoreError::Io`] if a barrier or the flush fails.
    pub fn sync_shards(&self, shards: impl IntoIterator<Item = u8>) -> StoreResult<()> {
        let mut dirs: std::collections::BTreeSet<PathBuf> = shards
            .into_iter()
            .map(|shard| self.objects_root.join(format!("{shard:02x}")))
            .collect();
        if !dirs.is_empty() && self.local_packs_enabled()? {
            dirs.insert(self.objects_root.join("pack"));
        }
        crate::batch::flush_dirents(self, dirs)?;
        Ok(())
    }

    /// Filesystem metadata for object `h` (size + mtime), for gc's
    /// grace-window check.
    ///
    /// # Errors
    /// [`StoreError::ObjectNotFound`] if absent, else [`StoreError::Io`].
    pub fn object_metadata(&self, h: &Hash) -> StoreResult<fs::Metadata> {
        fs::metadata(self.path_for(h)).map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => StoreError::ObjectNotFound(to_hex(h)),
            _ => StoreError::Io(e),
        })
    }

    /// The temp files in one shard directory, `objects/<2-hex>/`: the files a
    /// writer names `.kit.tmp.*` before it renames them into
    /// place. A writer that dies leaves its temp file behind. An absent
    /// directory has none.
    ///
    /// A live writer owns these files, so a caller deletes one only through
    /// [`prune_temp_file_if_old`](Self::prune_temp_file_if_old).
    ///
    /// # Errors
    /// [`StoreError::Io`] if the directory cannot be read.
    pub(crate) fn list_shard_temp_files(&self, shard: u8) -> StoreResult<Vec<PathBuf>> {
        let path = self.objects_root.join(format!("{shard:02x}"));
        match fs::symlink_metadata(&path) {
            Ok(meta) if meta.is_dir() => {}
            Ok(_) => return Ok(Vec::new()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(StoreError::Io(e)),
        }
        let mut out = Vec::new();
        for entry in fs::read_dir(&path)? {
            let entry = entry?;
            if entry.file_type()?.is_file() && is_temp_file_name(&entry.file_name()) {
                out.push(entry.path());
            }
        }
        Ok(out)
    }

    // The `format` inode is never replaced or unlinked. Reuse it as a
    // kernel-lock anchor, so exclusion needs no new on-disk state. Each guard
    // owns a separately opened handle; dropping it (including process death)
    // releases the lock. Object bytes never leave their canonical path.
    fn lock_writer(&self) -> io::Result<File> {
        let file = File::open(self.objects_root.with_file_name(FORMAT_FILE))?;
        file.lock_shared()?;
        Ok(file)
    }

    /// Keep gc from deleting any object of this store until the guard drops.
    ///
    /// The guard holds the shared lock on the `format` file. gc's only delete
    /// path, `prune_if_old`, needs the exclusive lock and keeps the object
    /// when it cannot take it, so no object is deleted at any grace period
    /// while a guard is alive. A process that dies releases it with its file
    /// handle, so no marker file is needed. A fetch takes the guard before it
    /// reads its record of applied packs and keeps it until its last ref
    /// publish, because an object a fetch reuses keeps its old modification
    /// time, so the grace period does not protect it. A push holds it from
    /// before it plans until its last remote-tracking ref write, so gc cannot
    /// prune the tip that ref names.
    ///
    /// The guard protects only against a gc that holds the worktree locks
    /// across its mark and sweep, as `kit gc` does: a gc that marks before the
    /// fetch or push publishes and sweeps after the guard drops would not see
    /// the new ref. Both publish under the worktree lock for that reason. It
    /// stops the delete step, not the mark.
    ///
    /// The guard relies on a local filesystem that honours kernel file locks,
    /// as SPEC-CONCURRENCY already requires. On Linux NFS a shared lock can
    /// vanish when another handle to the file closes.
    ///
    /// # Errors
    /// [`StoreError::Io`] if the `format` file cannot be opened or locked.
    pub fn prune_guard(&self) -> StoreResult<PruneGuard> {
        Ok(PruneGuard {
            format: self.lock_writer()?,
            objects_root: self.objects_root.clone(),
        })
    }

    /// Final grace-window check and unlink, excluded from concurrent bulk
    /// refreshes. Contention or uncertain age keeps the object. A crash before
    /// unlink leaves the canonical file; afterwards only an old orphan is gone.
    ///
    /// The exclusive lock is always a `try_lock`, never a blocking one. A
    /// fetch holds the shared lock (see [`prune_guard`](Self::prune_guard))
    /// for hours, so a process that waited for the exclusive lock would wait
    /// that long. No code may block on the exclusive lock of `format`.
    pub(crate) fn prune_if_old(&self, h: &Hash, now: u64, grace: u64) -> StoreResult<Option<u64>> {
        self.prune_if_old_with_hook(h, now, grace, || {})
    }

    fn prune_if_old_with_hook(
        &self,
        h: &Hash,
        now: u64,
        grace: u64,
        before_unlink: impl FnOnce(),
    ) -> StoreResult<Option<u64>> {
        self.prune_file_if_old(&self.path_for(h), now, grace, before_unlink)
    }

    /// [`prune_if_old`](Self::prune_if_old) for a temp file of
    /// [`list_shard_temp_files`](Self::list_shard_temp_files). Returns the
    /// bytes freed.
    ///
    /// A writer that is alive does not lose its file. A fetch or a bulk write
    /// holds the shared lock this needs to be free. A writer that holds a
    /// worktree lock (add, commit, merge and the like) is kept out of gc's
    /// sweep by that lock. A writer that holds neither, such as `kit
    /// hash-object -w` or a caller of `ObjectStore::write` with no lock, is
    /// protected only by the age of its temp file. A writer that has gone
    /// quiet for the whole grace period is taken to be dead.
    pub(crate) fn prune_temp_file_if_old(
        &self,
        path: &Path,
        now: u64,
        grace: u64,
    ) -> StoreResult<Option<u64>> {
        self.prune_file_if_old(path, now, grace, || {})
    }

    /// The final age check and unlink of `path` under the exclusive lock of
    /// `format`. Contention, uncertain age or a file already gone keep it.
    fn prune_file_if_old(
        &self,
        path: &Path,
        now: u64,
        grace: u64,
        before_unlink: impl FnOnce(),
    ) -> StoreResult<Option<u64>> {
        let guard = File::open(self.objects_root.with_file_name(FORMAT_FILE))?;
        if guard.try_lock().is_err() {
            return Ok(None);
        }
        let Ok(meta) = fs::metadata(path) else {
            return Ok(None);
        };
        if !old_enough(&meta, now, grace) {
            return Ok(None);
        }
        before_unlink();
        match fs::remove_file(path) {
            Ok(()) => Ok(Some(meta.len())),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Some(meta.len())),
            Err(e) => Err(StoreError::Io(e)),
        }
    }

    /// Delete object `h` from the store. Idempotent: a missing object is
    /// not an error (it may have been pruned already). For tests that model a
    /// damaged store; a build with the `fault-injection` feature has it.
    ///
    /// # Errors
    /// [`StoreError::Io`] on a filesystem failure other than not-found.
    #[cfg(any(test, feature = "fault-injection"))]
    pub fn remove_object(&self, h: &Hash) -> StoreResult<()> {
        match fs::remove_file(self.path_for(h)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(StoreError::Io(e)),
        }
    }
}

/// Append the ids of the objects in shard directory `path`, named `dir`, to
/// `out`. A name that is not a 62-hex file name is not an object and is
/// skipped.
fn read_shard_dir(path: &std::path::Path, dir: &str, out: &mut Vec<Hash>) -> StoreResult<()> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let file_name = entry.file_name();
        let Some(file) = file_name.to_str() else {
            continue;
        };
        if file.len() != 62 {
            continue;
        }
        // Reassemble the 64-hex id and parse it; skips non-objects.
        if let Ok(h) = hash::from_hex(&format!("{dir}{file}")) {
            out.push(h);
        }
    }
    Ok(())
}

/// Whether `name` is a temp file of an object write. No object file starts
/// with a dot.
fn is_temp_file_name(name: &std::ffi::OsStr) -> bool {
    name.to_str()
        .is_some_and(|name| name.starts_with('.') && name.contains(".tmp."))
}

pub(crate) fn old_enough(meta: &fs::Metadata, now: u64, grace: u64) -> bool {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .is_some_and(|mtime| now.saturating_sub(mtime.as_secs()) >= grace)
}

fn sync_reused_file(path: &Path) -> io::Result<()> {
    let mut options = fs::OpenOptions::new();
    if cfg!(unix) {
        options.read(true);
    } else {
        // Windows FlushFileBuffers requires GENERIC_WRITE. Do not silently
        // accept a failed content flush or change object permissions.
        options.write(true);
    }
    crate::flush::file(&options.open(path)?)
}

/// Fill the header buffer unless the reader reaches EOF.
fn parse_type(prologue: &[u8]) -> StoreResult<crate::object::ObjectType> {
    if prologue.len() < 6 {
        return Err(StoreError::Decode(KitError::EmptyData));
    }
    if prologue[1..5] != crate::object::MAGIC {
        return Err(StoreError::Decode(KitError::InvalidMagic));
    }
    let object_type = crate::object::ObjectType::from_u8(prologue[0])?;
    if prologue[5] != object_type.schema_version() {
        return Err(StoreError::Decode(KitError::UnsupportedObjectVersion));
    }
    Ok(object_type)
}

pub(crate) fn head_at(
    reader: &mut impl Read,
) -> StoreResult<(crate::object::ObjectType, Option<u64>)> {
    let mut head = [0; 10];
    let len = read_header_prefix(reader, &mut head)?;
    head_of(&head[..len])
}

/// The type and blob length that the first bytes of an object name.
fn head_of(head: &[u8]) -> StoreResult<(crate::object::ObjectType, Option<u64>)> {
    let object_type = parse_type(head)?;
    if object_type != crate::object::ObjectType::Blob {
        return Ok((object_type, None));
    }
    let size: [u8; 4] = head
        .get(6..10)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(StoreError::Decode(KitError::EmptyData))?;
    Ok((object_type, Some(u64::from(u32::from_le_bytes(size)))))
}

fn read_header_prefix(reader: &mut impl Read, mut remaining: &mut [u8]) -> io::Result<usize> {
    let len = remaining.len();
    while !remaining.is_empty() {
        match reader.read(remaining) {
            Ok(0) => break,
            Ok(n) => remaining = &mut remaining[n..],
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(len - remaining.len())
}

/// Shared by [`ObjectStore::read`] and [`ObjectStore::read_object`]: both
/// compute an `actual` id from the on-disk bytes their own way (plain
/// `object_id_from_bytes`, or the decode-reusing [`verified_id_and_object`])
/// and then need the exact same requested-vs-actual check and
/// [`StoreError::HashMismatch`] shape — kept in one place so the two can't
/// drift apart.
fn check_hash(expected: &Hash, actual: &Hash) -> StoreResult<()> {
    if actual != expected {
        return Err(StoreError::HashMismatch {
            expected: to_hex(expected),
            actual: to_hex(actual),
        });
    }
    Ok(())
}

/// Whether `layout`'s common dir is what a killed `init` leaves: no format
/// marker, because the marker is written last, and no object under
/// `objects/`.
fn is_unfinished_init(layout: &RepoLayout) -> io::Result<bool> {
    if layout.format_file().try_exists()? {
        return Ok(false);
    }
    if !layout.objects_dir().try_exists()? {
        return Ok(true);
    }
    Ok(fs::read_dir(layout.objects_dir())?.next().is_none())
}

/// Atomically write `bytes` to `final_path` with per-object durability
/// ([`SyncPolicy::PerObject`]): temp file, full flush, rename into
/// place, parent-dir flush. On Unix, `rename(2)` is atomic with respect
/// to concurrent readers and replaces the destination. On Windows,
/// [`tempfile::NamedTempFile::persist`] uses `MOVEFILE_REPLACE_EXISTING`
/// semantics so the replace-existing path works there too.
///
/// After a successful rename we flush the parent directory on Unix to
/// commit the dirent update — without this, the rename can survive a
/// power loss only in the page cache and the file appears missing on
/// reboot.
///
/// All flush/rename primitives go through `syncer` so unit tests can
/// assert ordering; [`RealSyncer`] preserves the historical behaviour
/// exactly.
fn write_atomic(final_path: &Path, bytes: &[u8], syncer: &dyn Syncer) -> io::Result<()> {
    let parent = final_path.parent().expect("write_atomic: path has parent");
    let mut tmp = crate::atomic::temp_file_in(parent)?;
    #[cfg(feature = "fault-injection")]
    crate::fault::check(crate::fault::Site::Store)?;
    tmp.as_file_mut().write_all(bytes)?;
    syncer.full(tmp.as_file(), tmp.path())?;

    // NamedTempFile::persist uses a cross-platform atomic replace:
    // rename(2) on Unix, MoveFileExW with MOVEFILE_REPLACE_EXISTING on Windows.
    syncer.rename(tmp.into_temp_path(), final_path)?;

    syncer.dir_sync(parent)?;
    Ok(())
}

/// Write target shared by [`ObjectStore`] (per-object durability) and
/// [`WriteBatch`] (batched durability), so ingest code can be written
/// once against either sink.
pub trait ObjectSink {
    /// Store `bytes` as one object, returning its BLAKE3 hash.
    fn put(&self, bytes: &[u8]) -> StoreResult<Hash>;
    /// Store the concatenation of `parts` as one object without the
    /// caller having to materialise the concatenated buffer.
    fn put_parts(&self, parts: &[&[u8]]) -> StoreResult<Hash>;
    /// True when the object is already present (or staged) in this sink.
    fn has(&self, h: &Hash) -> bool;
    /// Store the canonical blob at `origin`, with its prologue and payload
    /// in `parts`. This covers an inline file or a chunk of a file. A sink may
    /// keep the origin and read the payload back from the file. The default
    /// stores the bytes. A batch that packs also sends the small files past
    /// its first 64 to its open local pack.
    fn put_chunk_parts(&self, parts: &[&[u8]], _origin: ChunkOrigin<'_>) -> StoreResult<Hash> {
        self.put_parts(parts)
    }
    /// Store a chunk whose id is already computed. The default stores its
    /// bytes through [`Self::put_chunk_parts`] when the chunk has an origin,
    /// and through [`Self::put_parts`] when it has none.
    fn put_hashed_chunk(&self, chunk: &HashedChunk<'_>) -> StoreResult<Hash> {
        let parts = chunk.parts();
        match chunk.origin() {
            Some(origin) => self.put_chunk_parts(&parts, origin),
            None => self.put_parts(&parts),
        }
    }
    /// True when this sink wants the chunks of a file in file order through
    /// [`Self::put_hashed_chunk`], hashed once. A caller that can hash its
    /// chunks in parallel hashes them first, then hands them over in order.
    /// The default is false: such a sink takes chunks in any order.
    fn orders_chunks(&self) -> bool {
        false
    }
    /// Buffers that live as long as this sink, for the pipeline that cuts and
    /// hashes the chunks of each large file it takes, so that a sequence of
    /// files reuses one set. The default is none: each file allocates its own.
    #[doc(hidden)]
    fn chunk_buffers(&self) -> Option<&crate::chunker::ChunkBuffers> {
        None
    }
    /// Make the loose objects stored so far durable and visible, so a writer
    /// of many objects keeps its staged set bounded. An object in an open
    /// local pack becomes visible when the pack seals or at commit, so a
    /// caller must not read a chunk or small file back before its commit. A checkpoint never
    /// makes an object visible before the objects it names. The default does
    /// nothing, for a sink that is durable or keeps no state per object.
    fn checkpoint(&self) -> StoreResult<()> {
        Ok(())
    }
}

impl ObjectSink for ObjectStore {
    fn put(&self, bytes: &[u8]) -> StoreResult<Hash> {
        self.write(bytes)
    }

    fn put_parts(&self, parts: &[&[u8]]) -> StoreResult<Hash> {
        // Per-object path is the rare sink; hot ingest paths use
        // WriteBatch, whose put_parts is copy-free.
        let total: usize = parts.iter().map(|p| p.len()).sum();
        let mut bytes = Vec::with_capacity(total);
        for p in parts {
            bytes.extend_from_slice(p);
        }
        self.write(&bytes)
    }

    fn has(&self, h: &Hash) -> bool {
        self.contains(h)
    }
}

/// Reset an existing object file's `mtime` to now, on a dedup hit.
///
/// gc's grace window is measured from the object file's on-disk
/// `mtime` (SPEC-GC "Concurrent writers and the grace window"). A
/// writer outside gc's lock set that dedups against an OLD unreachable
/// object and then publishes a ref over it would otherwise lose the
/// object to a gc run in between (SPEC-GC "Concurrent writers and the grace window"). The only such writer into
/// this store is git import, through [`BulkWriter`], so only
/// [`BulkWriter::write`] calls this. [`ObjectStore::write`] and
/// [`crate::batch::WriteBatch`] callers hold `worktree.lock`, which gc
/// also takes, and refreshing there would dirty the inode right before
/// their per-hit shard-dir fsync, turning a ~10 µs dedup hit into a
/// journal commit (~3 ms on APFS). The caller treats an `Err` as "not
/// refreshed" and falls back to rewriting the object, which gives it a
/// fresh inode and `mtime`; it never reports a dedup hit whose `mtime`
/// was not refreshed.
///
/// - Permissions: on Unix, setting an explicit time needs ownership,
///   not write access, so a read-only fd works on a read-only object
///   file; a non-owner gets `EPERM` and so rewrites. Windows needs a
///   write-capable handle for `SetFileTime`.
/// - Durability: the new `mtime` is not fsynced. It only has to hold
///   between this dedup hit and the writer's ref publish, in the same
///   boot, where gc reads it from the in-memory inode. A crash ends the
///   writer: a ref it already published durably makes the object a gc
///   root, and an unpublished one never needed it, so a reverted
///   `mtime` after a crash cannot lose a reachable object.
/// - Cost: one `open` + `futimens` (plus `close`) per dedup hit.
///
/// Callers hold the shared format-file lock until refresh or rewrite is
/// complete; gc holds its exclusive counterpart over its final age check
/// and unlink, so a successful refresh cannot target a detached inode.
pub(crate) fn refresh_mtime(path: &Path) -> io::Result<()> {
    #[cfg(test)]
    if FAIL_REFRESH.get() {
        return Err(io::ErrorKind::NotFound.into());
    }
    let mut opts = fs::OpenOptions::new();
    if cfg!(unix) {
        opts.read(true);
    } else {
        opts.write(true);
    }
    opts.open(path)?.set_modified(std::time::SystemTime::now())
}

#[cfg(test)]
thread_local! {
    /// Test seam: make [`refresh_mtime`] fail on this thread, as a
    /// concurrent gc unlink (`NotFound`) would, to exercise the
    /// callers' rewrite fallback.
    static FAIL_REFRESH: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

fn raw_capacity(len: u64) -> StoreResult<usize> {
    let len = usize::try_from(len).map_err(|_| StoreError::ObjectTooLarge)?;
    if len > MAX_RAW_OBJECT_SIZE {
        return Err(StoreError::ObjectTooLarge);
    }
    Ok(len)
}

/// Read `reader` to its end into a buffer pre-sized for `size` bytes.
/// The read stops after `limit + 1` bytes, so a file that grew after
/// the size check cannot grow the buffer past the limit.
fn read_to_end_capped<R: Read>(reader: R, size: usize, limit: usize) -> StoreResult<Vec<u8>> {
    let mut bytes = Vec::with_capacity(size.min(limit));
    reader.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(StoreError::ObjectTooLarge);
    }
    Ok(bytes)
}

/// Run `read_to_end_capped` over a byte slice for fuzzing harnesses.
#[cfg(feature = "fuzzing")]
pub fn fuzz_read_to_end_capped(bytes: &[u8], size: usize, limit: usize) -> StoreResult<Vec<u8>> {
    read_to_end_capped(bytes, size, limit)
}

/// Exercise local pack index validation without accessing the filesystem.
#[cfg(feature = "fuzzing")]
pub fn fuzz_local_pack_index(bytes: &[u8]) {
    local_pack::fuzz_index(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::Blob;
    use std::fs::OpenOptions;
    use std::io::Seek;
    use tempfile::TempDir;

    fn fresh_store() -> (TempDir, ObjectStore) {
        let dir = TempDir::new().expect("tempdir");
        let store = ObjectStore::init(&RepoLayout::single(dir.path())).expect("init");
        (dir, store)
    }

    #[test]
    fn init_creates_layout() {
        let dir = TempDir::new().unwrap();
        let _ = ObjectStore::init(&RepoLayout::single(dir.path())).unwrap();
        assert!(dir.path().join(KIT_DIR).is_dir());
        assert!(dir.path().join(KIT_DIR).join(OBJECTS_DIR).is_dir());
    }

    #[test]
    fn init_again_after_a_killed_init_that_left_no_marker() {
        let dir = TempDir::new().unwrap();
        let layout = RepoLayout::single(dir.path());
        // `init` stopped after it made `objects/` and before it wrote the
        // format marker.
        fs::create_dir_all(layout.objects_dir()).unwrap();
        ObjectStore::init(&layout).unwrap();
        assert!(layout.format_file().is_file());
        // A directory with nothing in it at all counts as new too.
        let bare = TempDir::new().unwrap();
        let bare_layout = RepoLayout::single(bare.path());
        fs::create_dir_all(bare_layout.common_dir()).unwrap();
        ObjectStore::init(&bare_layout).unwrap();
        assert!(ObjectStore::open(&bare_layout).is_ok());
    }

    #[test]
    fn a_write_that_creates_a_shard_syncs_the_objects_dir() {
        use crate::batch::testing::{Ev, RecordingSyncer};
        let dir = TempDir::new().unwrap();
        let layout = RepoLayout::single(dir.path());
        let mut store = ObjectStore::init(&layout).unwrap();
        let rec = Arc::new(RecordingSyncer::default());
        store.set_syncer(rec.clone());
        let root = store.objects_root().to_path_buf();
        let synced = |rec: &RecordingSyncer| {
            rec.events()
                .iter()
                .filter(|ev| matches!(ev, Ev::DirSync(dir) if *dir == root))
                .count()
        };

        // Each object that opens a new shard flushes `objects/` once. One that
        // lands in a shard that already exists does not.
        let mut shards = std::collections::BTreeSet::new();
        let mut repeated = false;
        for n in 0..300_u32 {
            let id = store.write(format!("object {n}").as_bytes()).unwrap();
            let shard = store.path_for(&id).parent().unwrap().to_path_buf();
            repeated |= !shards.insert(shard);
            assert_eq!(synced(&rec), shards.len(), "after object {n}");
        }
        assert!(repeated, "300 objects must reuse a shard of 256");
        // The same bytes again hit the dedup path and create no shard.
        let before = synced(&rec);
        store.write(b"object 0").unwrap();
        assert_eq!(synced(&rec), before);
    }

    #[test]
    fn init_refuses_a_common_dir_with_objects_but_no_marker() {
        let dir = TempDir::new().unwrap();
        let layout = RepoLayout::single(dir.path());
        fs::create_dir_all(layout.objects_dir().join("ab")).unwrap();
        let err = ObjectStore::init(&layout).unwrap_err();
        assert!(matches!(err, StoreError::AlreadyInitialized));
    }

    #[test]
    fn init_rejects_already_initialized() {
        let dir = TempDir::new().unwrap();
        let layout = RepoLayout::single(dir.path());
        ObjectStore::init(&layout).unwrap();
        let err = ObjectStore::init(&layout).unwrap_err();
        assert!(matches!(err, StoreError::AlreadyInitialized));
    }

    #[test]
    fn open_rejects_non_repo() {
        let dir = TempDir::new().unwrap();
        let err = ObjectStore::open(&RepoLayout::single(dir.path())).unwrap_err();
        assert!(matches!(err, StoreError::NotAKitRepository));
    }

    #[test]
    fn init_writes_format_marker_and_open_accepts_it() {
        let dir = TempDir::new().unwrap();
        let layout = RepoLayout::single(dir.path());
        ObjectStore::init(&layout).unwrap();
        let marker = fs::read_to_string(dir.path().join(KIT_DIR).join(FORMAT_FILE)).unwrap();
        assert_eq!(marker, format!("{FORMAT_VALUE}\nP"));
        // A freshly-init'd repo opens cleanly.
        ObjectStore::open(&layout).unwrap();
    }

    #[test]
    fn open_rejects_repo_missing_or_wrong_format_marker() {
        // A repo with an objects dir and no format marker must be
        // rejected loudly rather than silently mis-read.
        let dir = TempDir::new().unwrap();
        let layout = RepoLayout::single(dir.path());
        ObjectStore::init(&layout).unwrap();
        let marker_path = dir.path().join(KIT_DIR).join(FORMAT_FILE);

        fs::remove_file(&marker_path).unwrap();
        assert!(matches!(
            ObjectStore::open(&layout),
            Err(StoreError::IncompatibleRepoFormat { found: None })
        ));

        // A repo declaring some other (e.g. future) format is also rejected.
        fs::write(&marker_path, b"flat-v0\n").unwrap();
        assert!(matches!(
            ObjectStore::open(&layout),
            Err(StoreError::IncompatibleRepoFormat { found: Some(_) })
        ));

        // A repo of the format before chunk spans is refused, with no
        // migration: every chunked id differs.
        fs::write(&marker_path, b"bmt-v1\n").unwrap();
        assert!(matches!(
            ObjectStore::open(&layout),
            Err(StoreError::IncompatibleRepoFormat { found: Some(ref found) }) if found == "bmt-v1"
        ));
        // The error says how to move the repository.
        let message = ObjectStore::open(&layout).err().unwrap().to_string();
        assert!(
            message.contains("`kit git export` with kit 0.7.3"),
            "{message}"
        );
        assert!(message.contains("`kit git import`"), "{message}");
    }

    #[test]
    fn open_rejects_a_marker_that_is_too_long_or_not_utf8() {
        let dir = TempDir::new().unwrap();
        let layout = RepoLayout::single(dir.path());
        ObjectStore::init(&layout).unwrap();
        let marker_path = dir.path().join(KIT_DIR).join(FORMAT_FILE);
        let too_long = vec![b'a'; usize::try_from(FORMAT_MAX_BYTES).unwrap() + 1];
        for bytes in [too_long, vec![0xff, 0xfe, b'\n']] {
            fs::write(&marker_path, &bytes).unwrap();
            assert!(matches!(
                ObjectStore::open(&layout),
                Err(StoreError::IncompatibleRepoFormat { found: Some(_) })
            ));
        }
    }

    #[test]
    fn open_reports_a_marker_it_cannot_read_as_an_io_error() {
        let dir = TempDir::new().unwrap();
        let layout = RepoLayout::single(dir.path());
        ObjectStore::init(&layout).unwrap();
        let marker_path = dir.path().join(KIT_DIR).join(FORMAT_FILE);
        // A directory in place of the marker cannot be read. That is a failure
        // of the disk, not a format this kit does not know.
        fs::remove_file(&marker_path).unwrap();
        fs::create_dir(&marker_path).unwrap();
        assert!(matches!(ObjectStore::open(&layout), Err(StoreError::Io(_))));
    }

    #[test]
    fn object_head_reads_an_object_that_ends_at_its_prologue() {
        use crate::object::{MAGIC, ObjectType};
        let (_dir, store) = fresh_store();
        let id = [0x42; 32];
        let path = store.path_for(&id);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut prologue = vec![ObjectType::Tree as u8];
        prologue.extend_from_slice(&MAGIC);
        prologue.push(ObjectType::Tree.schema_version());
        assert_eq!(prologue.len(), 6);

        // The six bytes of the prologue name a tree, which has no length.
        fs::write(&path, &prologue).unwrap();
        assert_eq!(store.object_head(&id).unwrap(), (ObjectType::Tree, None));

        // One byte fewer holds no complete prologue.
        fs::write(&path, &prologue[..5]).unwrap();
        assert!(matches!(
            store.object_head(&id),
            Err(StoreError::Decode(KitError::EmptyData))
        ));
    }

    #[test]
    fn object_head_requires_the_complete_blob_length() {
        use crate::object::ObjectType;
        let (_dir, store) = fresh_store();
        let body = serialize::serialize(&Object::Blob(Blob {
            data: b"chunk payload".to_vec(),
        }))
        .unwrap();
        let id = store.write(&body).unwrap();
        let path = store.path_for(&id);
        for len in 6..10 {
            fs::write(&path, &body[..len]).unwrap();
            assert!(matches!(
                store.object_head(&id),
                Err(StoreError::Decode(KitError::EmptyData))
            ));
        }
        fs::write(&path, &body[..10]).unwrap();
        assert_eq!(
            store.object_head(&id).unwrap(),
            (ObjectType::Blob, Some(13))
        );
    }

    #[test]
    fn object_head_retries_interrupted_and_short_reads() {
        struct HeaderReader<'a> {
            source: &'a [u8],
            interrupted: bool,
        }

        impl Read for HeaderReader<'_> {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                assert!(!buf.is_empty());
                if !self.interrupted {
                    self.interrupted = true;
                    return Err(io::ErrorKind::Interrupted.into());
                }
                self.source.read(&mut buf[..1])
            }
        }

        struct BrokenReader(bool);

        impl Read for BrokenReader {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                assert!(!std::mem::replace(&mut self.0, true));
                Err(io::ErrorKind::PermissionDenied.into())
            }
        }

        let mut reader = HeaderReader {
            source: b"0123456789x",
            interrupted: false,
        };
        let mut head = [0; 10];
        assert_eq!(read_header_prefix(&mut reader, &mut head).unwrap(), 10);
        assert_eq!(&head, b"0123456789");
        assert_eq!(reader.source, b"x");
        assert_eq!(
            read_header_prefix(&mut BrokenReader(false), &mut head)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn is_repo_root_predicate() {
        let dir = TempDir::new().unwrap();
        assert!(!ObjectStore::is_repo_root(dir.path()));
        ObjectStore::init(&RepoLayout::single(dir.path())).unwrap();
        assert!(ObjectStore::is_repo_root(dir.path()));
    }

    #[test]
    fn write_then_read_roundtrip() {
        let (_dir, store) = fresh_store();
        let bytes = b"hello world".to_vec();
        let h = store.write(&bytes).unwrap();
        assert!(store.contains(&h));
        let got = store.read(&h).unwrap();
        assert_eq!(got, bytes);
    }

    #[test]
    fn read_object_deserialises() {
        let (_dir, store) = fresh_store();
        let obj = Object::Blob(Blob {
            data: b"object bytes".to_vec(),
        });
        let bytes = serialize::serialize(&obj).unwrap();
        let h = store.write(&bytes).unwrap();
        let parsed = store.read_object(&h).unwrap();
        assert_eq!(parsed, obj);
    }

    /// The outcome of `deserialize` for `bytes`, in `read_object`'s error
    /// domain, rendered so two outcomes compare with `==`.
    fn expected_read(bytes: &[u8]) -> Result<Object, String> {
        serialize::deserialize(bytes).map_err(|e| format!("{:?}", StoreError::Decode(e)))
    }

    /// Write `bytes` verbatim, whether or not they decode. A `Blob`-tagged
    /// object is byte-hashed, so its id is `BLAKE3(bytes)` either way.
    fn write_verbatim(store: &ObjectStore, bytes: &[u8]) -> Hash {
        let h = store.write(bytes).unwrap();
        assert_eq!(h, crate::hash::hash(bytes));
        h
    }

    /// Invariant: for any stored `Blob`-tagged bytes, `read_object` returns
    /// exactly what `deserialize` returns, the same object or the same
    /// decode error. A blob read skips the generic decoder, so this pins it
    /// to that decoder on short, malformed, truncated, padded and valid
    /// inputs alike.
    #[test]
    fn read_object_blob_matches_deserialize_on_edge_inputs() {
        let (_dir, store) = fresh_store();
        let valid = serialize::serialize(&Object::Blob(Blob {
            data: b"payload".to_vec(),
        }))
        .unwrap();
        let mut cases: Vec<Vec<u8>> = vec![
            valid.clone(),
            serialize::serialize(&Object::Blob(Blob { data: Vec::new() })).unwrap(),
        ];
        // Every proper prefix: shorter than the prologue, shorter than the
        // length field, and shorter than the declared payload.
        cases.extend((1..valid.len()).map(|n| valid[..n].to_vec()));
        // Trailing bytes after the payload.
        cases.push([valid.as_slice(), b"x"].concat());
        // Length field one more and one less than the payload.
        for delta in [1i64, -1] {
            let mut v = valid.clone();
            let len = i64::from(u32::from_le_bytes(v[6..10].try_into().unwrap())) + delta;
            v[6..10].copy_from_slice(&u32::try_from(len).unwrap().to_le_bytes());
            cases.push(v);
        }
        // Bad magic and a wrong schema version.
        let mut bad_magic = valid.clone();
        bad_magic[2] ^= 0xFF;
        cases.push(bad_magic);
        let mut bad_version = valid.clone();
        bad_version[5] = bad_version[5].wrapping_add(1);
        cases.push(bad_version);

        for bytes in cases {
            let h = write_verbatim(&store, &bytes);
            let got = store.read_object(&h).map_err(|e| format!("{e:?}"));
            assert_eq!(got, expected_read(&bytes), "input {bytes:?}");
        }
    }

    /// A blob whose on-disk bytes no longer hash to its id reports
    /// `HashMismatch`, never a decode error or the corrupt payload.
    #[test]
    fn read_object_blob_detects_corruption() {
        let (_dir, store) = fresh_store();
        let bytes = serialize::serialize(&Object::Blob(Blob {
            data: b"object bytes".to_vec(),
        }))
        .unwrap();
        let h = store.write(&bytes).unwrap();
        let mut corrupt = bytes.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        fs::write(store.path_for(&h), &corrupt).unwrap();
        assert!(matches!(
            store.read_object(&h),
            Err(StoreError::HashMismatch { .. })
        ));
        // A length field that disagrees with the file still fails on the
        // hash first, as `read` does.
        let mut short = bytes.clone();
        short[6] ^= 1;
        fs::write(store.path_for(&h), &short).unwrap();
        assert!(matches!(
            store.read_object(&h),
            Err(StoreError::HashMismatch { .. })
        ));
    }

    proptest::proptest! {
        /// Invariant: `read_object` agrees with `deserialize(read(h))` for
        /// arbitrary `Blob`-tagged bytes and for every valid blob payload.
        #[test]
        fn read_object_blob_matches_deserialize(
            payload in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..2048),
            raw in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..64),
        ) {
            let (_dir, store) = fresh_store();
            let valid = serialize::serialize(&Object::Blob(Blob { data: payload.clone() })).unwrap();
            let mut arbitrary = vec![crate::object::ObjectType::Blob as u8];
            arbitrary.extend_from_slice(&raw);
            for bytes in [valid, arbitrary] {
                let h = write_verbatim(&store, &bytes);
                let got = store.read_object(&h).map_err(|e| format!("{e:?}"));
                proptest::prop_assert_eq!(got, expected_read(&bytes));
                let via_trait: &dyn ObjectSource = &store;
                let got = via_trait.read_object(&h).map_err(|e| format!("{e:?}"));
                proptest::prop_assert_eq!(got, expected_read(&bytes));
            }
        }
    }

    /// `read_object` on a merkelized type (the path `verified_id_and_object`
    /// added a decoded-object fast path for) round-trips correctly — the
    /// non-merkle `read_object_deserialises` case above can't exercise the
    /// `Some(obj)` branch at all.
    #[test]
    fn read_object_deserialises_tree() {
        use crate::object::{EntryMode, Tree, TreeEntry};
        let (_dir, store) = fresh_store();
        let obj = Object::Tree(Tree {
            entries: vec![
                TreeEntry {
                    name: b"a.txt".to_vec(),
                    mode: EntryMode::Blob,
                    object_hash: crate::hash::hash(b"a"),
                },
                TreeEntry {
                    name: b"b.txt".to_vec(),
                    mode: EntryMode::Blob,
                    object_hash: crate::hash::hash(b"b"),
                },
            ],
        });
        let bytes = serialize::serialize(&obj).unwrap();
        let h = store.write(&bytes).unwrap();
        let parsed = store.read_object(&h).unwrap();
        assert_eq!(parsed, obj);
        // Every `S: ObjectSource + ?Sized` caller (diff/blame/worktree
        // blob loading) resolves `read_object` through this trait impl,
        // not the inherent method above — pin that it agrees.
        let via_trait: &dyn ObjectSource = &store;
        assert_eq!(via_trait.read_object(&h).unwrap(), obj);
    }

    /// Regression test for the double-decode fix: corrupting a stored
    /// `Tree`'s bytes must still surface `HashMismatch` through
    /// `read_object`'s merkle (`Some(obj)`-reusing) branch, not just
    /// through `read`'s. Also exercises `read_object` via the
    /// `ObjectSource` trait object — the actual call shape every
    /// `S: ObjectSource + ?Sized` caller (`diff::load_tree`,
    /// `LoadedBlob::load`) uses — to pin `impl ObjectSource for
    /// ObjectStore`'s `read_object` override against regressing back to
    /// the trait's double-decoding default.
    #[test]
    fn read_object_detects_tree_corruption_via_store_and_trait() {
        use crate::object::{EntryMode, Tree, TreeEntry};
        let (_dir, store) = fresh_store();
        let obj = Object::Tree(Tree {
            entries: vec![TreeEntry {
                name: b"a.txt".to_vec(),
                mode: EntryMode::Blob,
                object_hash: crate::hash::hash(b"a"),
            }],
        });
        let bytes = serialize::serialize(&obj).unwrap();
        let h = store.write(&bytes).unwrap();

        let path = store.path_for(&h);
        let mut f = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        f.seek(io::SeekFrom::Start(0)).unwrap();
        f.write_all(&[bytes[0] ^ 0xFF]).unwrap();
        f.sync_all().unwrap();

        assert!(matches!(
            store.read_object(&h).unwrap_err(),
            StoreError::HashMismatch { .. }
        ));
        let via_trait: &dyn ObjectSource = &store;
        assert!(matches!(
            via_trait.read_object(&h).unwrap_err(),
            StoreError::HashMismatch { .. }
        ));
    }

    #[test]
    fn write_is_idempotent() {
        let (_dir, store) = fresh_store();
        let bytes = b"duplicate".to_vec();
        let h1 = store.write(&bytes).unwrap();
        let h2 = store.write(&bytes).unwrap();
        assert_eq!(h1, h2);
        // Second write must not have produced any stray temp files.
        let shard = store.path_for(&h1);
        let parent = shard.parent().unwrap();
        let entries: Vec<_> = fs::read_dir(parent).unwrap().collect();
        assert_eq!(
            entries.len(),
            1,
            "shard dir should contain exactly the final object, no temp leaks"
        );
    }

    #[test]
    fn read_missing_returns_not_found() {
        let (_dir, store) = fresh_store();
        let phony = hash::hash(b"never written");
        let err = store.read(&phony).unwrap_err();
        assert!(matches!(err, StoreError::ObjectNotFound(_)));
        assert!(!store.contains(&phony));
    }

    #[test]
    fn write_rejects_oversize() {
        let (_dir, store) = fresh_store();
        // A REAL cap+1 body: `vec![0u8; n]` is `alloc_zeroed`, so the
        // 1 GiB+1 buffer costs lazily mapped zero pages, not RSS — and
        // the guard rejects on `len()` before anything reads the bytes.
        let oversize = vec![0u8; MAX_RAW_OBJECT_SIZE + 1];
        let err = store.write(&oversize).unwrap_err();
        assert!(matches!(err, StoreError::ObjectTooLarge), "got {err:?}");
        drop(oversize);
        // A realistic small write still works after the rejection.
        let h = store.write(&[0u8; 16]).unwrap();
        assert!(store.contains(&h));
    }

    #[test]
    fn read_rejects_oversize_on_disk() {
        // Construct an oversize on-disk blob by hand and confirm `read`
        // refuses it. We use a sentinel size = MAX + 1 file padded with
        // zeros; this allocates ~1 GiB of disk, which is unfriendly in
        // unit tests, so instead we monkey-patch via a smaller-cap copy
        // of the read path: we synthesise a too-large file by truncating
        // a real one and verifying the comparison logic at the boundary.
        //
        // We exercise `MAX_RAW_OBJECT_SIZE` indirectly by writing a
        // small object and then *replacing* the on-disk file with one
        // whose `metadata().len()` exceeds the cap. We use sparse
        // truncation so no real disk is consumed.
        let (_dir, store) = fresh_store();
        let h = store.write(b"seed").unwrap();
        let path = store.path_for(&h);
        let f = OpenOptions::new().write(true).open(&path).unwrap();
        // Sparse extend to cap+1 bytes; allocates effectively no blocks.
        f.set_len(MAX_RAW_OBJECT_SIZE as u64 + 1).unwrap();
        drop(f);
        let err = store.read(&h).unwrap_err();
        assert!(matches!(err, StoreError::ObjectTooLarge));
    }

    #[test]
    fn raw_capacity_accepts_the_limit_and_refuses_larger_objects() {
        assert_eq!(
            raw_capacity(MAX_RAW_OBJECT_SIZE as u64).unwrap(),
            MAX_RAW_OBJECT_SIZE
        );
        for len in [MAX_RAW_OBJECT_SIZE as u64 + 1, u64::MAX] {
            assert!(matches!(raw_capacity(len), Err(StoreError::ObjectTooLarge)));
        }
    }

    #[test]
    fn capped_read_stops_at_the_limit() {
        // The declared size is small, but the stream is longer than the
        // limit. The read must refuse and must not buffer the whole stream.
        let stream = io::repeat(7).take(1_000_000);
        let err = read_to_end_capped(stream, 4, 16).unwrap_err();
        assert!(matches!(err, StoreError::ObjectTooLarge));
        let ok = read_to_end_capped(&[1u8, 2, 3][..], 3, 3).unwrap();
        assert_eq!(ok, [1, 2, 3]);
        let err = read_to_end_capped(&[0u8; 4][..], 3, 3).unwrap_err();
        assert!(matches!(err, StoreError::ObjectTooLarge));
    }

    #[test]
    fn read_detects_corruption() {
        let (_dir, store) = fresh_store();
        let bytes = b"trustworthy".to_vec();
        let h = store.write(&bytes).unwrap();
        // Flip a single byte in the on-disk file and expect HashMismatch.
        let path = store.path_for(&h);
        {
            let mut f = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .unwrap();
            f.seek(io::SeekFrom::Start(0)).unwrap();
            f.write_all(&[bytes[0] ^ 0xFF]).unwrap();
            f.sync_all().unwrap();
        }
        let err = store.read(&h).unwrap_err();
        match err {
            StoreError::HashMismatch { expected, actual } => {
                assert_eq!(expected, to_hex(&h));
                assert_ne!(actual, expected, "actual must differ once corrupted");
            }
            other => panic!("expected HashMismatch, got {other:?}"),
        }
    }

    /// Flip the first byte of the on-disk object file for `h`, in place —
    /// the "the bytes on disk no longer match `h`" setup for the
    /// `read`-vs-`read_unverified` corruption split test below. (The
    /// `DisplaySource` corruption tests carry their own copy in
    /// `source.rs`.)
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
    fn read_unverified_returns_bytes_read_rejects_corruption() {
        // The core split this whole feature exists for: `read` must still
        // fail loudly on a corrupted object, while `read_unverified`
        // returns the (corrupt) bytes as-is — display paths only ever get
        // a bad render, never silently-wrong durable state.
        let (_dir, store) = fresh_store();
        let bytes = b"trustworthy".to_vec();
        let h = store.write(&bytes).unwrap();
        corrupt_first_byte(&store, &h, bytes[0]);

        assert!(matches!(
            store.read(&h).unwrap_err(),
            StoreError::HashMismatch { .. }
        ));

        let mut corrupted = bytes.clone();
        corrupted[0] ^= 0xFF;
        assert_eq!(store.read_unverified(&h).unwrap(), corrupted);
    }

    #[test]
    fn path_layout_is_2_then_62_hex() {
        let (_dir, store) = fresh_store();
        let bytes = b"layout test".to_vec();
        let h = store.write(&bytes).unwrap();
        let hex = to_hex(&h);
        let path = store.path_for(&h);
        let parent = path.parent().unwrap();
        let parent_name = parent.file_name().unwrap().to_str().unwrap();
        let file_name = path.file_name().unwrap().to_str().unwrap();
        assert_eq!(parent_name.len(), 2);
        assert_eq!(file_name.len(), 62);
        assert_eq!(parent_name, &hex[..2]);
        assert_eq!(file_name, &hex[2..]);
        assert!(path.is_file(), "object file must exist at expected path");
    }

    #[test]
    fn list_shard_lists_one_directory_and_all_shards_list_the_store() {
        let (_dir, store) = fresh_store();
        let ids: Vec<Hash> = (0..300)
            .map(|i| {
                store
                    .write(
                        &crate::serialize::serialize(&Object::Blob(Blob {
                            data: format!("object {i}").into_bytes(),
                        }))
                        .unwrap(),
                    )
                    .unwrap()
            })
            .collect();
        let mut union = Vec::new();
        for shard in 0..=u8::MAX {
            let mut listed = store.list_shard(shard).unwrap();
            let mut expected: Vec<Hash> = ids.iter().copied().filter(|h| h[0] == shard).collect();
            listed.sort_unstable();
            expected.sort_unstable();
            assert_eq!(listed, expected, "shard {shard:02x}");
            union.extend(listed);
        }
        let mut all = store.iter_object_hashes().unwrap();
        union.sort_unstable();
        all.sort_unstable();
        assert_eq!(union, all);
        assert_eq!(all.len(), ids.len());
    }

    #[test]
    fn list_shard_skips_what_is_not_an_object() {
        let (_dir, store) = fresh_store();
        let id = store.write(b"an object").unwrap();
        let shard = store.path_for(&id).parent().unwrap().to_path_buf();
        let name = id[0];
        // A stale temp file, a short name, a directory and a non-hex name of
        // the right length are not objects.
        fs::write(shard.join(".tmp.1.2"), b"partial").unwrap();
        fs::write(shard.join("short"), b"x").unwrap();
        fs::create_dir(shard.join("d".repeat(62))).unwrap();
        fs::write(shard.join("z".repeat(62)), b"x").unwrap();
        assert_eq!(store.list_shard(name).unwrap(), vec![id]);
        assert_eq!(store.iter_object_hashes().unwrap(), vec![id]);
    }

    #[test]
    fn list_shard_of_an_absent_or_misplaced_directory_is_empty() {
        let (_dir, store) = fresh_store();
        assert!(store.list_shard(0x00).unwrap().is_empty());
        // A file where the directory belongs is not a shard.
        fs::write(store.objects_root.join("ab"), b"x").unwrap();
        assert!(store.list_shard(0xab).unwrap().is_empty());
        #[cfg(unix)]
        {
            // Nor is a link to a directory that holds an object.
            let real = TempDir::new().unwrap();
            let id = hash::hash(b"elsewhere");
            let name = hash::to_hex(&id);
            fs::write(real.path().join(&name[2..]), b"x").unwrap();
            std::os::unix::fs::symlink(real.path(), store.objects_root.join(&name[..2])).unwrap();
            assert!(store.list_shard(id[0]).unwrap().is_empty());
            assert!(store.iter_object_hashes().unwrap().is_empty());
        }
    }

    /// A failure to look at a shard other than its absence is an error. If
    /// it were an empty listing, a sweep would pass over objects it cannot see.
    #[cfg(unix)]
    #[test]
    fn list_shard_reports_a_directory_it_cannot_inspect() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, store) = fresh_store();
        let id = store.write(b"an object").unwrap();
        let root = store.objects_root.clone();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o000)).unwrap();
        let listed = store.list_shard(id[0]);
        // A superuser reads the directory anyway, and the test has nothing to
        // show.
        let denied = fs::read_dir(&root).is_err();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        if !denied {
            return;
        }
        assert!(
            matches!(listed, Err(StoreError::Io(ref e)) if e.kind() == io::ErrorKind::PermissionDenied),
            "{listed:?}"
        );
    }

    #[test]
    fn temp_file_left_behind_does_not_satisfy_contains() {
        // Simulate a crash mid-write: drop a stale `.tmp.*` file in the
        // shard dir without ever renaming. `contains()` must report the
        // object as absent, and the shard dir must not contain a real
        // entry that passes the hash check.
        let (_dir, store) = fresh_store();
        let target = hash::hash(b"never finalised");
        let final_path = store.path_for(&target);
        let shard = final_path.parent().unwrap();
        fs::create_dir_all(shard).unwrap();
        let stale = shard.join(format!(
            ".{}.tmp.0.0",
            final_path.file_name().unwrap().to_string_lossy()
        ));
        fs::write(&stale, b"partial").unwrap();
        assert!(stale.is_file());
        assert!(!store.contains(&target));
        // No file in the shard dir should hash to `target`.
        for entry in fs::read_dir(shard).unwrap() {
            let p = entry.unwrap().path();
            let bytes = fs::read(&p).unwrap();
            assert_ne!(
                hash::hash(&bytes),
                target,
                "stale temp file must not satisfy the target hash"
            );
        }
    }
}

#[cfg(test)]
mod bulk_writer_tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn bulk_writer_reuses_read_only_object() {
        let td = tempfile::tempdir().unwrap();
        let store = ObjectStore::init(&RepoLayout::single(td.path())).unwrap();
        let bytes = b"existing read-only object";
        let h = store.write(bytes).unwrap();
        let path = store.path_for(&h);
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_readonly(true);
        fs::set_permissions(&path, permissions).unwrap();
        let mut writer = store.bulk_writer();
        assert_eq!(writer.write(bytes).unwrap(), h);
        writer.commit().unwrap();
        assert_eq!(store.read(&h).unwrap(), bytes);
    }

    #[cfg(feature = "fault-injection")]
    #[test]
    fn a_reused_object_is_flushed_with_its_content() {
        let td = tempfile::tempdir().unwrap();
        let path = td.path().join("object");
        fs::write(&path, b"bytes").unwrap();
        let before = crate::fault::flushes();
        sync_reused_file(&path).unwrap();
        assert_eq!(crate::fault::flushes(), before + 1);
        assert!(sync_reused_file(&td.path().join("missing")).is_err());
    }

    #[test]
    fn bulk_writer_round_trips_and_rewrites() {
        let td = tempfile::tempdir().unwrap();
        let store = ObjectStore::init(&RepoLayout::single(td.path())).unwrap();
        let obj = crate::serialize::serialize(&crate::object::Object::Blob(crate::object::Blob {
            data: b"bulk".to_vec(),
        }))
        .unwrap();
        let mut bw = store.bulk_writer();
        let h1 = bw.write(&obj).unwrap();
        // No existence short-circuit: rewriting is fine and heals
        // torn files on idempotent re-runs.
        let h2 = bw.write(&obj).unwrap();
        assert_eq!(h1, h2);
        bw.commit().unwrap();
        assert_eq!(store.read(&h1).unwrap(), obj);
        // Interoperates with the normal (fsynced) writer.
        assert_eq!(store.write(&obj).unwrap(), h1);
    }
}

/// SPEC-GC "Concurrent writers and the grace window": a dedup hit must refresh the existing object's `mtime`, so
/// a writer outside gc's lock set (git import) that is about to publish
/// a ref over an old unreachable object does not lose it to a gc with a
/// grace window (SPEC-GC "Concurrent writers and the grace window").
#[cfg(test)]
mod dedup_mtime_tests {
    use super::*;
    use crate::layout::RepoLayout;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    const DAY: u64 = 24 * 60 * 60;
    /// gc's default grace window (SPEC-GC "Status").
    const GRACE: u64 = 14 * DAY;

    fn repo() -> (tempfile::TempDir, ObjectStore) {
        let td = tempfile::tempdir().unwrap();
        let store = ObjectStore::init(&RepoLayout::single(td.path())).unwrap();
        crate::refs::init(&RepoLayout::single(td.path())).unwrap();
        (td, store)
    }

    fn mtime(store: &ObjectStore, h: &Hash) -> SystemTime {
        fs::metadata(store.path_for(h)).unwrap().modified().unwrap()
    }

    /// Age the object file past the grace window, as an object written
    /// long ago and since orphaned (e.g. a superseded commit whose
    /// recovery entry expired) would be.
    fn backdate(store: &ObjectStore, h: &Hash) -> SystemTime {
        let old = SystemTime::now() - Duration::from_secs(30 * DAY);
        File::open(store.path_for(h))
            .unwrap()
            .set_modified(old)
            .unwrap();
        assert!(mtime(store, h) <= old + Duration::from_secs(1));
        old
    }

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// Write an object, age it, dedup-write it again through `rewrite`,
    /// then run a gc with the default grace: the re-written object must
    /// have a fresh `mtime` and survive, while an equally old orphan
    /// nobody re-wrote is pruned (so the gc really sweeps).
    fn assert_dedup_refreshes(rewrite: impl Fn(&ObjectStore, &[u8]) -> Hash) {
        let (td, store) = repo();
        let bytes = b"object the import is about to publish".to_vec();
        let h = store.write(&bytes).unwrap();
        let control = store.write(b"old orphan nobody writes again").unwrap();
        backdate(&store, &h);
        backdate(&store, &control);

        let before = SystemTime::now() - Duration::from_secs(1);
        assert_eq!(rewrite(&store, &bytes), h);
        assert!(
            mtime(&store, &h) >= before,
            "dedup hit must refresh the object's mtime"
        );

        let report = crate::ops::gc::run_gc(
            &store,
            &RepoLayout::single(td.path()),
            now_secs(),
            GRACE,
            false,
            &mut |_, _, _| {},
        )
        .unwrap();
        assert!(store.contains(&h), "re-written object pruned: {report:?}");
        assert_eq!(store.read(&h).unwrap(), bytes);
        assert!(!store.contains(&control), "control orphan kept: {report:?}");
    }

    /// A failed refresh must not be reported as a dedup hit:
    /// `BulkWriter` falls back to rewriting the object, which gives it
    /// a fresh `mtime` too.
    #[test]
    fn failed_refresh_falls_back_to_rewrite() {
        fn failing<T>(f: impl FnOnce() -> T) -> T {
            FAIL_REFRESH.set(true);
            let out = f();
            FAIL_REFRESH.set(false);
            out
        }
        assert_dedup_refreshes(|s, b| {
            let mut bw = s.bulk_writer();
            let h = failing(|| bw.write(b).unwrap());
            bw.commit().unwrap();
            h
        });
    }

    #[test]
    fn bulk_writer_dedup_refreshes_mtime() {
        assert_dedup_refreshes(|s, b| {
            let mut bw = s.bulk_writer();
            let h = bw.write(b).unwrap();
            bw.commit().unwrap();
            h
        });
    }
}

#[cfg(test)]
mod sweep_crash_tests {
    use super::*;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    struct ChildGuard(std::process::Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    fn sweep_crash_child() {
        let Some(root) = std::env::var_os("KIT_SWEEP_CRASH_ROOT") else {
            return;
        };
        let layout = RepoLayout::single(Path::new(&root));
        let store = ObjectStore::open(&layout).unwrap();
        let h = object_id_from_bytes(b"crash sweep candidate");
        store
            .prune_if_old_with_hook(&h, u64::MAX, 10, || {
                fs::write(Path::new(&root).join("checked"), b"ready").unwrap();
                loop {
                    std::thread::park();
                }
            })
            .unwrap();
        panic!("child should be killed before unlink");
    }

    #[test]
    fn crash_after_final_check_leaves_object_for_next_gc() {
        let td = tempfile::tempdir().unwrap();
        let layout = RepoLayout::single(td.path());
        let store = ObjectStore::init(&layout).unwrap();
        crate::refs::init(&layout).unwrap();
        let bytes = b"crash sweep candidate";
        let h = store.write(bytes).unwrap();
        let control = store.write(b"unrefreshed crash orphan").unwrap();
        for h in [h, control] {
            File::open(store.path_for(&h))
                .unwrap()
                .set_modified(UNIX_EPOCH)
                .unwrap();
        }
        let mut child = ChildGuard(
            Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "store::sweep_crash_tests::sweep_crash_child"])
                .env("KIT_SWEEP_CRASH_ROOT", td.path())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let start = Instant::now();
        while !td.path().join("checked").exists() {
            assert!(
                start.elapsed() < Duration::from_secs(30),
                "child did not reach final check"
            );
            assert!(child.0.try_wait().unwrap().is_none(), "child exited early");
            std::thread::sleep(Duration::from_millis(10));
        }
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        let reopened = ObjectStore::open(&layout).unwrap();
        assert_eq!(reopened.read(&h).unwrap(), bytes);
        let mut writer = reopened.bulk_writer();
        writer.write(bytes).unwrap();
        writer.commit().unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let report =
            crate::ops::gc::run_gc(&reopened, &layout, now, 10, false, &mut |_, _, _| {}).unwrap();
        assert!(reopened.contains(&h), "refreshed survivor lost: {report:?}");
        assert!(!reopened.contains(&control));
        assert_eq!(report.pruned, 1);
    }
}

#[cfg(test)]
mod temp_file_tests {
    #![allow(clippy::unwrap_used)] // unwrap is the assertion in tests

    use super::*;
    use std::time::UNIX_EPOCH;

    fn store() -> (tempfile::TempDir, ObjectStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = ObjectStore::init(&RepoLayout::single(dir.path())).unwrap();
        (dir, store)
    }

    fn old_file(path: &Path) {
        fs::write(path, b"partial").unwrap();
        File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(UNIX_EPOCH)
            .unwrap();
    }

    #[test]
    fn only_dot_tmp_files_are_temp_files() {
        for name in [".ab.tmp.1.2xyz", ".kit.tmp.7.0abc"] {
            assert!(is_temp_file_name(std::ffi::OsStr::new(name)), "{name}");
        }
        for name in ["notes.tmp.1", ".hidden", "tmp.1", &"a".repeat(62)] {
            assert!(!is_temp_file_name(std::ffi::OsStr::new(name)), "{name}");
        }
    }

    #[test]
    fn the_temp_files_of_a_shard_are_listed_and_nothing_else() {
        let (_dir, store) = store();
        let shard = store.objects_root().join("ab");
        fs::create_dir_all(&shard).unwrap();
        fs::write(shard.join(".x.tmp.1.2"), b"t").unwrap();
        fs::write(shard.join("keep.txt"), b"t").unwrap();
        fs::create_dir(shard.join(".dir.tmp.1.3")).unwrap();
        let listed = store.list_shard_temp_files(0xab).unwrap();
        assert_eq!(listed, vec![shard.join(".x.tmp.1.2")]);
        // A shard directory that was never created has none.
        let _ = fs::remove_dir_all(store.objects_root().join("cd"));
        assert!(store.list_shard_temp_files(0xcd).unwrap().is_empty());
    }

    /// A symlink named like a shard is not a shard, as for objects.
    #[cfg(unix)]
    #[test]
    fn a_symlinked_shard_has_no_temp_files() {
        let (dir, store) = store();
        let outside = dir.path().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join(".x.tmp.1.2"), b"t").unwrap();
        let shard = store.objects_root().join("ab");
        let _ = fs::remove_dir_all(&shard);
        std::os::unix::fs::symlink(&outside, shard).unwrap();
        assert!(store.list_shard_temp_files(0xab).unwrap().is_empty());
    }

    /// An error other than a missing directory is an error, not an empty shard.
    #[test]
    fn an_unreadable_shard_path_is_an_error() {
        let (dir, store) = store();
        fs::remove_dir_all(store.objects_root()).unwrap();
        fs::write(store.objects_root(), b"not a directory").unwrap();
        let error = store.list_shard_temp_files(0xab).unwrap_err();
        assert!(matches!(error, StoreError::Io(_)), "{error:?}");
        drop(dir);
    }

    #[test]
    fn a_temp_file_that_is_gone_at_the_final_check_still_counts_as_removed() {
        let (dir, store) = store();
        let path = dir.path().join(".x.tmp.1.2");
        old_file(&path);
        let freed = store
            .prune_file_if_old(&path, u64::MAX, 10, || fs::remove_file(&path).unwrap())
            .unwrap();
        assert_eq!(freed, Some(7));
    }

    #[test]
    fn a_failed_unlink_is_an_error() {
        let (dir, store) = store();
        let path = dir.path().join(".x.tmp.1.2");
        old_file(&path);
        // The file turns into a directory between the check and the unlink.
        let result = store.prune_file_if_old(&path, u64::MAX, 10, || {
            fs::remove_file(&path).unwrap();
            fs::create_dir(&path).unwrap();
        });
        assert!(matches!(result, Err(StoreError::Io(_))), "{result:?}");
    }

    #[test]
    fn a_young_temp_file_is_kept() {
        let (dir, store) = store();
        let path = dir.path().join(".x.tmp.1.2");
        fs::write(&path, b"partial").unwrap();
        assert_eq!(
            store
                .prune_file_if_old(&path, now(), 1_000, || unreachable!())
                .unwrap(),
            None
        );
        assert!(path.exists());
    }

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
}
