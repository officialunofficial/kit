//! Refs subsystem.
//!
//! Implements the local-disk side of `docs/specs/SPEC-REFS.md`: ref names,
//! the 65-byte wire encoding, the symbolic-or-detached `HEAD` file, and
//! shallow-boundary persistence at `.kit/shallow`.
//!
//! Wire format (per SPEC-REFS §1): exactly 64 lowercase-hex characters
//! plus a trailing `0x0A` newline = 65 bytes. Uppercase hex is rejected
//! on read. Trailing `\r` and ASCII whitespace are tolerated when
//! parsing local files (so a Windows-edited HEAD does not brick a
//! repo), but fresh writes always emit the strict 65-byte form.
//!
//! Ref name grammar (SPEC-REFS §3): `[A-Za-z0-9._-]+` segments joined
//! by `/`, with no leading/trailing `/`, no `.`/`..` segments, no
//! backslashes, no NULs. In addition, no segment may end in `.lock`
//! (the canonical lock-file suffix) and the final segment may not be
//! the literal `HEAD` (which would shadow the repo-level HEAD
//! pointer). We share the validator with the future transport layer
//! via [`validate_ref_name`] / [`validate_ref_prefix`].
//!
//! CAS variants for [`update_ref`] follow SPEC-REFS §5: `Any` (clobber),
//! `Missing` (fail if it exists), `Match(H)` (fail if current value !=
//! H). Every local-filesystem ref mutation (all three write conditions,
//! conditional and unconditional deletes, tags, remote-tracking refs and
//! [`RemoteRefBatch`] writes) runs its critical section under a per-ref
//! `refs-<digest>.lock` in the common dir, where `<digest>` is the
//! lowercase BLAKE3 hex of the ref's path relative to the common dir
//! (`cas_lock_name`; SPEC-CONCURRENCY §2). It uses the same blocking
//! kernel-lock primitive as `repo_lock` elsewhere, so a mutation is atomic
//! across processes regardless of what other locks each caller holds, and
//! mutations of different refs never contend. The lock is keyed per ref.
//! History-aware
//! branch writers take `refs-history-<digest>.lock` first
//! (SPEC-CONCURRENCY §4).

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::bounded_read;
use crate::durable::{Flushed, Group, Parents, Staged};
use crate::hash::{HASH_LEN, HEX_LEN, Hash, to_hex};
use crate::layout::RepoLayout;

/// Subdirectory holding all refs (`.kit/refs`).
pub const REFS_DIR: &str = "refs";
/// Subdirectory holding branch refs (`.kit/refs/heads`).
pub const HEADS_DIR: &str = "refs/heads";
/// Subdirectory holding tag refs (`.kit/refs/tags`).
pub const TAGS_DIR: &str = "refs/tags";
/// Subdirectory holding remote-tracking refs (`.kit/refs/remotes`).
pub const REMOTES_DIR: &str = "refs/remotes";
/// HEAD file relative to the `.kit` root.
pub const HEAD_FILE: &str = "HEAD";
/// Shallow-boundary file relative to the `.kit` root.
pub const SHALLOW_FILE: &str = "shallow";

/// Symbolic-ref prefix written to `HEAD` when pointing at a branch.
const HEAD_REF_PREFIX: &str = "ref: refs/heads/";

/// Hard cap on how many bytes we are willing to read from `HEAD`.
const HEAD_MAX_BYTES: u64 = 4 * 1024;
/// Hard cap on how many bytes we are willing to read from a single ref
/// file. The wire form is always 65 bytes; a few more is fine if the
/// file picked up extra whitespace, but anything pathological is
/// rejected.
pub const REF_FILE_MAX_BYTES: u64 = 128;
/// Hard cap on `.kit/shallow` (1 MiB).
const SHALLOW_MAX_BYTES: u64 = 1024 * 1024;

/// Errors raised by this module.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RefError {
    /// `name` failed [`validate_ref_name_grammar`].
    #[error("invalid ref name '{0}'")]
    InvalidRefName(String),
    /// A new ref's name is over its kind's bound: [`MAX_REF_NAME_BYTES`]
    /// for a ref name, [`MAX_BRANCH_NAME_BYTES`] for a branch and
    /// [`MAX_TAG_NAME_BYTES`] for a tag (SPEC-REFS §3).
    #[error("{}", too_long_message(.name, *.len, *.kind))]
    RefNameTooLong {
        /// The name.
        name: String,
        /// Its length in bytes.
        len: usize,
        /// Which bound it broke.
        kind: RefNameKind,
    },
    /// On-disk bytes were not a valid 65-byte ref wire (length wrong,
    /// uppercase hex, non-hex byte, etc.).
    #[error("invalid ref content for '{0}'")]
    InvalidRef(String),
    /// `HEAD` content was neither a valid symbolic ref nor a valid
    /// detached hash.
    #[error("HEAD is not a valid symbolic-ref or detached-hash file")]
    InvalidHead,
    /// `HEAD` is missing.
    #[error("HEAD is not present")]
    NoHead,
    /// CAS condition failed: ref does not match expected state.
    #[error("ref '{0}' did not satisfy CAS condition")]
    Conflict(String),
    /// Tried to delete a ref that does not exist.
    #[error("ref '{0}' not found")]
    NotFound(String),
    /// Tried to delete the branch HEAD currently points to.
    #[error("cannot delete the current branch '{0}'")]
    CurrentBranch(String),
    /// Underlying I/O failure.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// A [`list_refs_with`]-style batch callback returned a different
    /// number of outcomes than candidates it was given — the caller's
    /// contract violation, not a clean exit-coded error, but caught here
    /// rather than silently desyncing names from hashes.
    #[error("read_batch callback returned {actual} outcomes for a {expected}-candidate batch")]
    RefBatchLengthMismatch { expected: usize, actual: usize },
}

/// Result alias used throughout this module.
pub type RefResult<T> = Result<T, RefError>;

/// CAS condition for [`update_ref`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefWriteCondition {
    /// Unconditional write — clobbers any existing value.
    Any,
    /// Write only if the ref does not currently exist.
    Missing,
    /// Write only if the ref currently contains this exact hash.
    Match(Hash),
}

/// HEAD pointer: either a symbolic reference to a branch name, or a
/// detached hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Head {
    /// Symbolic — `HEAD` was `ref: refs/heads/<branch>\n`.
    Branch(String),
    /// Detached — `HEAD` was a bare 64-char hex hash.
    Detached(Hash),
}

/// A listed ref entry: name (with `refs/heads/` or similar prefix
/// stripped) plus the resolved hash, when readable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ref {
    /// Ref name relative to the namespace (e.g. `"main"`, `"v1.0"`).
    pub name: String,
    /// Resolved 32-byte hash, or `None` if the on-disk bytes were
    /// malformed (the entry is then silently skipped by callers that
    /// only care about valid refs).
    pub hash: Option<Hash>,
}

/// Longest ref name, in bytes (SPEC-REFS §3). The bound keeps every ref
/// inside a server's storage key; clients check it before sending
/// (`kit_rpc::MAX_REF_NAME`).
pub const MAX_REF_NAME_BYTES: usize = 512;

/// Most `/`-separated segments a new ref name may have (SPEC-REFS §3).
/// A local ref stored before this bound existed keeps working: see
/// [`MAX_REF_WALK_DEPTH`].
pub const MAX_REF_SEGMENTS: usize = 32;

/// Directory levels the ref walkers descend. A name of at most
/// [`MAX_REF_NAME_BYTES`] bytes has at most half that many segments, so
/// the walkers reach every ref a length-bounded name can name, including
/// a ref stored before [`MAX_REF_SEGMENTS`] existed. Deeper directories
/// are not refs of any bounded name.
pub const MAX_REF_WALK_DEPTH: usize = MAX_REF_NAME_BYTES / 2;

/// The wire name prefix of a branch head.
pub const BRANCH_REF_PREFIX: &str = "refs/heads/";
/// The wire name prefix of a branch's packmap ref, which a push writes
/// next to its head (`refs/kit/packmap/<branch>`).
pub const PACKMAP_REF_PREFIX: &str = "refs/kit/packmap/";
/// The wire name prefix of a tag.
pub const TAG_REF_PREFIX: &str = "refs/tags/";
/// The wire name prefix of a tag's transfer chain ref, valued like a packmap
/// (`refs/kit/tagmap/<tag>`, SPEC-REFS §2).
pub const TAGMAP_REF_PREFIX: &str = "refs/kit/tagmap/";
/// Repository-wide pack-list chain of attestation envelopes.
pub const ATTESTMAP_REF: &str = "refs/kit/attestmap";

/// The ref that carries published bridge attestations on a git mirror
/// (SPEC-GIT-BRIDGE §11).
pub const ATTESTATIONS_REF: &str = "refs/kit/attestations";

/// Longest new branch name, in bytes: a push writes both
/// `refs/heads/<branch>` and `refs/kit/packmap/<branch>`, and each must
/// fit [`MAX_REF_NAME_BYTES`], so the longer prefix sets the bound (495).
pub const MAX_BRANCH_NAME_BYTES: usize = MAX_REF_NAME_BYTES - PACKMAP_REF_PREFIX.len();
/// Longest new tag name, in bytes: a tag travels as `refs/tags/<tag>` and
/// `refs/kit/tagmap/<tag>`, and each must fit [`MAX_REF_NAME_BYTES`], so the
/// longer prefix sets the bound (496).
pub const MAX_TAG_NAME_BYTES: usize = MAX_REF_NAME_BYTES - TAGMAP_REF_PREFIX.len();

const _: () = assert!(PACKMAP_REF_PREFIX.len() >= BRANCH_REF_PREFIX.len());
const _: () = assert!(TAGMAP_REF_PREFIX.len() >= TAG_REF_PREFIX.len());

/// Which name bound a [`RefError::RefNameTooLong`] broke.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RefNameKind {
    /// A full ref name, or a remote-tracking or remote name:
    /// [`MAX_REF_NAME_BYTES`].
    Ref,
    /// A local branch name: [`MAX_BRANCH_NAME_BYTES`].
    Branch,
    /// A local tag name: [`MAX_TAG_NAME_BYTES`].
    Tag,
}

impl RefNameKind {
    /// The bound, in bytes.
    #[must_use]
    pub const fn max_bytes(self) -> usize {
        match self {
            Self::Ref => MAX_REF_NAME_BYTES,
            Self::Branch => MAX_BRANCH_NAME_BYTES,
            Self::Tag => MAX_TAG_NAME_BYTES,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Ref => "ref",
            Self::Branch => "branch",
            Self::Tag => "tag",
        }
    }

    /// Where the bound comes from.
    const fn why(self) -> &'static str {
        match self {
            Self::Ref => "",
            Self::Branch => {
                ", because refs/heads/<name> and refs/kit/packmap/<name> must \
                 each fit the 512-byte ref-name limit"
            }
            Self::Tag => {
                ", because refs/tags/<name> and refs/kit/tagmap/<name> must \
                 each fit the 512-byte ref-name limit"
            }
        }
    }
}

/// The first 64 bytes of a name, for error messages about long names.
fn name_preview(name: &str) -> String {
    const SHOWN: usize = 64;
    match name.get(..SHOWN) {
        Some(head) if name.len() > SHOWN => format!("{head}..."),
        _ => name.to_owned(),
    }
}

/// `<kind> name too long (<len> bytes; at most <max><why>, SPEC-REFS §3):
/// '<preview>'`.
fn too_long_message(name: &str, len: usize, kind: RefNameKind) -> String {
    format!(
        "{} name too long ({len} bytes; at most {}{}, SPEC-REFS §3): '{}'",
        kind.label(),
        kind.max_bytes(),
        kind.why(),
        name_preview(name)
    )
}

/// Validate a ref name per SPEC-REFS §3: [`validate_ref_name_grammar`]
/// and at most [`MAX_REF_NAME_BYTES`] bytes. Used at every transport
/// boundary and for every ref written; transports MUST NOT silently
/// lower-case or canonicalise.
#[must_use]
pub fn validate_ref_name(name: &str) -> bool {
    name.len() <= MAX_REF_NAME_BYTES && validate_ref_name_grammar(name)
}

/// Check the name of a ref about to be created or written: the
/// SPEC-REFS §3 grammar and length bound.
///
/// # Errors
/// [`RefError::RefNameTooLong`] for a grammatical name over
/// [`MAX_REF_NAME_BYTES`], [`RefError::InvalidRefName`] otherwise.
pub fn check_new_ref_name(name: &str) -> RefResult<()> {
    check_new_name(name, RefNameKind::Ref)
}

/// Check a new name of `kind` against its grammar and bound.
///
/// # Errors
/// As [`check_new_ref_name`], with `kind`'s bound.
pub fn check_new_name(name: &str, kind: RefNameKind) -> RefResult<()> {
    if !validate_ref_name_grammar(name) {
        return Err(RefError::InvalidRefName(name.to_string()));
    }
    if name.len() > kind.max_bytes() {
        return Err(RefError::RefNameTooLong {
            name: name.to_string(),
            len: name.len(),
            kind,
        });
    }
    Ok(())
}

/// Check the wire names a push of `branch` writes, `refs/heads/<branch>`
/// and `refs/kit/packmap/<branch>`, against [`MAX_REF_NAME_BYTES`]. A
/// local branch named before the branch bound existed can be longer than
/// [`MAX_BRANCH_NAME_BYTES`] and still be used locally, but not pushed.
///
/// # Errors
/// [`RefError::RefNameTooLong`] naming the longer wire name.
pub fn check_pushable_branch(branch: &str) -> RefResult<()> {
    check_new_name(&format!("{PACKMAP_REF_PREFIX}{branch}"), RefNameKind::Ref)?;
    check_new_name(&format!("{BRANCH_REF_PREFIX}{branch}"), RefNameKind::Ref)
}

/// Check the wire names a transfer of tag `tag` uses, `refs/tags/<tag>` and
/// `refs/kit/tagmap/<tag>`: each must be a valid ref name, so the tag has at
/// most [`MAX_TAG_NAME_BYTES`] bytes and at most [`MAX_REF_SEGMENTS`] less
/// three segments. A local tag made before this bound stays readable and
/// deletable, but is neither pushed nor fetched.
///
/// # Errors
/// [`RefError::RefNameTooLong`] for a tag over [`MAX_TAG_NAME_BYTES`], and
/// [`RefError::InvalidRefName`] naming `tag` for any other failure.
pub fn check_pushable_tag(tag: &str) -> RefResult<()> {
    check_new_name(tag, RefNameKind::Tag)?;
    if validate_ref_name_grammar(&format!("{TAGMAP_REF_PREFIX}{tag}")) {
        Ok(())
    } else {
        Err(RefError::InvalidRefName(tag.to_owned()))
    }
}

/// Check a new name of `kind` for a local write: [`check_new_name`], and for a
/// tag, [`check_pushable_tag`].
fn check_new_local_name(name: &str, kind: RefNameKind) -> RefResult<()> {
    match kind {
        RefNameKind::Tag => check_pushable_tag(name),
        RefNameKind::Ref | RefNameKind::Branch => check_new_name(name, kind),
    }
}

/// Check a local branch or tag name about to be written under `sub_dir`.
/// A name within `kind`'s bound always passes. A longer one passes only
/// while the ref already exists and fits [`MAX_REF_NAME_BYTES`]: a ref
/// created before the per-kind bound keeps working locally, while a new
/// one is refused.
fn check_local_write(
    common_dir: &Path,
    sub_dir: &str,
    name: &str,
    kind: RefNameKind,
) -> RefResult<()> {
    // A ref stored before a bound existed keeps working locally. The
    // bounds are the per-kind length and the segment count.
    let stored_before_bounds = name.len() <= MAX_REF_NAME_BYTES
        && name_grammar_ok(name, usize::MAX)
        && ref_path(common_dir, sub_dir, name).is_file();
    match check_new_local_name(name, kind) {
        Err(RefError::RefNameTooLong { .. } | RefError::InvalidRefName(_))
            if stored_before_bounds =>
        {
            Ok(())
        }
        other => other,
    }
}

/// Check the name of a ref that may already exist, for a read, a listing
/// or a delete: the grammar without the segment bound, so a local ref
/// written before SPEC-REFS §3 bounded names stays visible, resolvable and
/// deletable.
fn check_existing_ref_name(name: &str) -> RefResult<()> {
    if name_grammar_ok(name, usize::MAX) {
        Ok(())
    } else {
        Err(RefError::InvalidRefName(name.to_string()))
    }
}

/// The SPEC-REFS §3 grammar without its length bound: what a local ref
/// that already exists must satisfy to be read, listed or deleted. New
/// refs and every transport use [`validate_ref_name`].
///
/// Grammar:
/// - Non-empty.
/// - Segments split on `/`, each segment matches `[A-Za-z0-9._-]+`.
/// - No segment may start with `.` (this also rejects the exact `.`
///   and `..` segments) — git's `check-ref-format` rule, kept for
///   parity: a dot-leading component is invalid in both grammars, so
///   nothing on-disk under a dot-leading directory (e.g. crash debris
///   from a temp-directory rename, or an in-flight `durable::write_pointer`
///   temp file) can ever surface as a ref in `collect_refs` / listings.
///   No empty segments (no `//`, no leading `/`, no trailing `/`).
/// - No `\\` or NUL bytes.
/// - No segment may end in `.lock` (the canonical lock-file suffix).
/// - The final segment may not be the literal `HEAD`, since that
///   would shadow the repo-level `HEAD` pointer.
/// - At most [`MAX_REF_SEGMENTS`] segments.
#[must_use]
pub fn validate_ref_name_grammar(name: &str) -> bool {
    name_grammar_ok(name, MAX_REF_SEGMENTS)
}

/// The SPEC-REFS §3 grammar with `max_segments` as the segment bound.
/// Only a local ref that already exists passes `usize::MAX`.
fn name_grammar_ok(name: &str, max_segments: usize) -> bool {
    if name.is_empty() {
        return false;
    }
    if name.bytes().filter(|&c| c == b'/').count() >= max_segments {
        return false;
    }
    if name.starts_with('/') {
        return false;
    }
    let mut last_part: &str = "";
    for part in name.split('/') {
        if part.is_empty() {
            return false;
        }
        if part.starts_with('.') {
            return false;
        }
        // Reject the canonical lock-file suffix. Byte-level check so
        // clippy's case-sensitive file-extension lint (which assumes a
        // path extension) does not fire — ref segments are not paths
        // and `.lock` is a spec-mandated exact-match suffix.
        let bytes = part.as_bytes();
        if bytes.len() >= 5 && &bytes[bytes.len() - 5..] == b".lock" {
            return false;
        }
        for &c in part.as_bytes() {
            if c == 0 || c == b'\\' {
                return false;
            }
            let allowed = c.is_ascii_alphanumeric() || c == b'.' || c == b'_' || c == b'-';
            if !allowed {
                return false;
            }
        }
        last_part = part;
    }
    if last_part == "HEAD" {
        return false;
    }
    true
}

/// Canonical per-branch lock name for ancestry publication and recovery.
#[cfg(feature = "history-mmr")]
pub(crate) fn history_lock_name(branch: &str) -> String {
    // ASCII-folded, like `cas_lock_name`.
    let full_ref = format!("refs/heads/{}", branch.to_ascii_lowercase());
    format!(
        "refs-history-{}.lock",
        to_hex(&crate::hash::hash(full_ref.as_bytes()))
    )
}

pub(crate) mod ancestry_state;
/// The branch history a build with history records writes beside a branch.
pub use ancestry_state::DIRECTORY as BRANCH_HISTORY_DIR;

/// Retention roots of unfinished history publications, including when the
/// history-mmr feature is disabled. Corruption must abort GC.
pub fn pending_history_roots(layout: &RepoLayout) -> RefResult<BTreeSet<Hash>> {
    ancestry_state::pending_roots(layout.common_dir())
}

/// The `refs-<ref>.lock` filename every ref mutation
/// acquires, keyed off `path` relative to `common_dir` (not just a
/// bare name) so a branch and a tag/remote-ref sharing the same bare
/// name get distinct locks. Named for the same reason as
/// [`history_lock_name`]: a test that independently recomputes this
/// formula would stop catching a regression the moment production's
/// formula changed without the test's copy changing too.
/// Hash the complete identity so nested or punctuation-heavy names cannot
/// overflow a single lock filename. Namespace prefixes remain in the digest;
/// history and mutation guards also have distinct filename prefixes.
///
/// The key is ASCII-lowercased. On a case-insensitive file system `Main` and
/// `main` are one ref file, and two spellings must share one lock, as git's
/// `Main.lock` and `main.lock` do. On a case-sensitive file system the two
/// refs only share a lock, which is safe.
pub(crate) fn cas_lock_name(common_dir: &Path, path: &Path) -> String {
    let ref_key = path
        .strip_prefix(common_dir)
        .map_or_else(|_| path.to_string_lossy(), |p| p.to_string_lossy())
        .to_ascii_lowercase();
    format!(
        "refs-{}.lock",
        to_hex(&crate::hash::hash(ref_key.as_bytes()))
    )
}

/// Validate a prefix passed to `list_refs`. An empty prefix is allowed.
/// A single trailing `/` is allowed; otherwise the prefix must satisfy
/// [`validate_ref_name`].
#[must_use]
pub fn validate_ref_prefix(prefix: &str) -> bool {
    if prefix.is_empty() {
        return true;
    }
    let trimmed = prefix.trim_end_matches('/');
    if trimmed.is_empty() {
        return false;
    }
    validate_ref_name(trimmed)
}

/// Encode `h` to its 65-byte wire form (lowercase hex + `\n`).
#[must_use]
pub fn encode_ref_wire(h: &Hash) -> [u8; 65] {
    let hex = to_hex(h);
    let bytes = hex.as_bytes();
    let mut out = [0u8; 65];
    out[..HEX_LEN].copy_from_slice(bytes);
    out[HEX_LEN] = b'\n';
    out
}

/// Decode a ref wire blob into a [`Hash`](tyalias@Hash). Tolerates a trailing
/// newline / `\r` / ASCII whitespace (so files round-tripped through a
/// Windows editor still parse), but rejects uppercase hex per
/// SPEC-REFS §1.
///
/// Returns `None` for any malformed input; callers wrap the absent
/// case into a domain-specific [`RefError::InvalidRef`].
#[must_use]
pub fn decode_ref_wire(data: &[u8]) -> Option<Hash> {
    let s = core::str::from_utf8(data).ok()?;
    let trimmed = s.trim_end_matches(['\n', '\r', ' ', '\t']);
    if trimmed.len() != HEX_LEN {
        return None;
    }
    parse_lowercase_hash(trimmed.as_bytes())
}

/// Strict lowercase-only hex parser: exactly [`HEX_LEN`] lowercase-hex
/// bytes, decoded in a single pass. SPEC-REFS §1 forbids uppercase on read;
/// the general `hash::from_hex` tolerates both cases for programmatic
/// callers, so this is the stricter variant every on-the-wire / on-disk
/// reader (ref wire blobs, the applied-packs record) shares to keep a
/// hand-edited or foreign-cased line malformed rather than silently accepted.
#[must_use]
pub fn parse_lowercase_hash(bytes: &[u8]) -> Option<Hash> {
    if bytes.len() != HEX_LEN {
        return None;
    }
    let mut out = [0u8; HASH_LEN];
    for i in 0..HASH_LEN {
        let hi = lowercase_nibble(bytes[i * 2])?;
        let lo = lowercase_nibble(bytes[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn lowercase_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(10 + (b - b'a')),
        _ => None,
    }
}

/// Initialise the ref layout: creates `refs/`, `refs/heads/`,
/// `refs/tags/`, `refs/remotes/` under the common dir and writes a
/// default `HEAD = ref: refs/heads/main\n` into the worktree state
/// dir if `HEAD` does not already exist.
pub fn init(layout: &RepoLayout) -> RefResult<()> {
    fs::create_dir_all(layout.refs_dir())?;
    fs::create_dir_all(layout.heads_dir())?;
    fs::create_dir_all(layout.tags_dir())?;
    fs::create_dir_all(layout.remotes_dir())?;
    let head_path = layout.head_file();
    if !head_path.exists() {
        let body = format!("{HEAD_REF_PREFIX}main\n");
        crate::durable::write_pointer(&head_path, body.as_bytes(), Parents::Existing)?;
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// HEAD
// -----------------------------------------------------------------------------

/// Read this worktree's `HEAD`.
///
/// # Errors
/// - [`RefError::NoHead`] if the file is missing.
/// - [`RefError::InvalidHead`] for malformed content.
pub fn read_head(layout: &RepoLayout) -> RefResult<Head> {
    let path = layout.head_file();
    let raw = match bounded_read::read_capped(&path, HEAD_MAX_BYTES) {
        Ok(raw) => raw,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(RefError::NoHead),
        Err(e) if e.kind() == io::ErrorKind::InvalidData => return Err(RefError::InvalidHead),
        Err(e) => return Err(RefError::Io(e)),
    };
    let s = core::str::from_utf8(&raw).map_err(|_| RefError::InvalidHead)?;
    let trimmed = s.trim_end_matches(['\n', '\r', ' ', '\t']);
    if let Some(branch) = trimmed.strip_prefix(HEAD_REF_PREFIX) {
        // Grammar only: a branch named before SPEC-REFS §3 bounded names
        // stays checked out; a write to it names the limit.
        if !name_grammar_ok(branch, usize::MAX) {
            return Err(RefError::InvalidHead);
        }
        return Ok(Head::Branch(branch.to_string()));
    }
    if trimmed.len() == HEX_LEN {
        let h = parse_lowercase_hash(trimmed.as_bytes()).ok_or(RefError::InvalidHead)?;
        return Ok(Head::Detached(h));
    }
    Err(RefError::InvalidHead)
}

/// Read the previous HEAD saved by checkout in this worktree.
/// Missing state returns `NoHead`; unreadable or malformed state is an error.
pub fn read_previous_head(layout: &RepoLayout) -> RefResult<Head> {
    let raw = bounded_read::read_capped(
        &layout.worktree_state_dir().join("PREVIOUS_HEAD"),
        HEAD_MAX_BYTES,
    )
    .map_err(|e| {
        if e.kind() == io::ErrorKind::NotFound {
            RefError::NoHead
        } else {
            RefError::Io(e)
        }
    })?;
    parse_previous_head(&raw)
}

fn parse_previous_head(raw: &[u8]) -> RefResult<Head> {
    let text = core::str::from_utf8(raw).map_err(|_| RefError::InvalidHead)?;
    if let Some(branch) = text
        .strip_prefix(HEAD_REF_PREFIX)
        .and_then(|s| s.strip_suffix('\n'))
    {
        if validate_ref_name(branch) {
            return Ok(Head::Branch(branch.to_owned()));
        }
    } else if let Some(h) = text
        .strip_suffix('\n')
        .and_then(|s| parse_lowercase_hash(s.as_bytes()))
    {
        return Ok(Head::Detached(h));
    }
    Err(RefError::InvalidHead)
}

/// Exercise the previous HEAD byte parser without filesystem I/O.
#[cfg(feature = "fuzzing")]
#[must_use]
pub fn fuzz_parse_previous_head(raw: &[u8]) -> Option<Head> {
    parse_previous_head(raw).ok()
}

/// The most previous HEADs that `HEAD_HISTORY` holds, so the largest N of
/// `@{-N}` (SPEC-WORKTREE).
pub const HEAD_HISTORY_MAX: usize = 16;

/// The largest `HEAD_HISTORY` file a reader accepts.
const HEAD_HISTORY_MAX_BYTES: u64 = 64 * 1024;

/// One previous HEAD in the HEAD encoding, newline included.
fn encode_previous_head(head: &Head) -> String {
    match head {
        Head::Branch(branch) => format!("{HEAD_REF_PREFIX}{branch}\n"),
        Head::Detached(h) => format!("{}\n", crate::hash::to_hex(h)),
    }
}

/// Parse a `HEAD_HISTORY` body, oldest first. A last line with no newline
/// is a torn write and is ignored. More than [`HEAD_HISTORY_MAX`] complete
/// lines, or a line that is not in the HEAD encoding, is an error.
fn parse_head_history(raw: &[u8]) -> RefResult<Vec<Head>> {
    let mut out = Vec::new();
    for line in raw.split_inclusive(|&b| b == b'\n') {
        if line.last() != Some(&b'\n') {
            break;
        }
        if out.len() == HEAD_HISTORY_MAX {
            return Err(RefError::InvalidHead);
        }
        out.push(parse_previous_head(line)?);
    }
    Ok(out)
}

/// Exercise the `HEAD_HISTORY` parser without filesystem I/O.
#[cfg(feature = "fuzzing")]
#[must_use]
pub fn fuzz_parse_head_history(raw: &[u8]) -> Option<Vec<Head>> {
    parse_head_history(raw).ok()
}

/// Encode a record as `HEAD_HISTORY` bytes, for the fuzz round trip.
#[cfg(feature = "fuzzing")]
#[must_use]
pub fn fuzz_encode_head_history(record: &[Head]) -> Vec<u8> {
    record
        .iter()
        .map(encode_previous_head)
        .collect::<String>()
        .into_bytes()
}

/// The previous HEADs of this worktree, oldest first (SPEC-WORKTREE). A
/// missing record reads as the one entry in `PREVIOUS_HEAD`, and so does a
/// record whose last entry is not `PREVIOUS_HEAD`, which an older kit left
/// stale.
///
/// # Errors
/// [`RefError::InvalidHead`] for a malformed record or `PREVIOUS_HEAD`;
/// [`RefError::Io`] when a file cannot be read.
pub fn read_head_history(layout: &RepoLayout) -> RefResult<Vec<Head>> {
    let previous = match read_previous_head(layout) {
        Ok(head) => head,
        Err(RefError::NoHead) => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let raw = match bounded_read::read_capped(
        &layout.worktree_state_dir().join("HEAD_HISTORY"),
        HEAD_HISTORY_MAX_BYTES,
    ) {
        Ok(raw) => raw,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(vec![previous]),
        Err(e) if e.kind() == io::ErrorKind::InvalidData => return Err(RefError::InvalidHead),
        Err(e) => return Err(RefError::Io(e)),
    };
    let record = parse_head_history(&raw)?;
    if record.last() == Some(&previous) {
        Ok(record)
    } else {
        Ok(vec![previous])
    }
}

/// The N-th previous HEAD of this worktree, counted from 1, or `None` when
/// the record holds fewer.
///
/// # Errors
/// As [`read_head_history`].
pub fn nth_previous_head(layout: &RepoLayout, n: usize) -> RefResult<Option<Head>> {
    if n == 0 {
        return Ok(None);
    }
    let record = read_head_history(layout)?;
    Ok(record.len().checked_sub(n).map(|i| record[i].clone()))
}

/// The N of a `@{-N}` revision: a positive decimal number of at most two
/// digits with no leading zero. Anything else is `None`.
#[must_use]
pub fn parse_previous_spec(spec: &str) -> Option<usize> {
    let digits = spec.strip_prefix("@{-")?.strip_suffix('}')?;
    if digits.is_empty()
        || digits.len() > 2
        || digits.starts_with('0')
        || !digits.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    digits.parse().ok()
}

/// Record `old` as the newest previous HEAD: write `PREVIOUS_HEAD`, then
/// append to `HEAD_HISTORY` and keep its last [`HEAD_HISTORY_MAX`] entries.
/// A malformed record is replaced. The caller holds the worktree lock.
///
/// # Errors
/// [`RefError::Io`] when a file cannot be read or written.
pub fn record_previous_head(layout: &RepoLayout, old: &Head) -> RefResult<()> {
    let mut record = match read_head_history(layout) {
        Ok(record) => record,
        Err(RefError::InvalidHead) => Vec::new(),
        Err(e) => return Err(e),
    };
    // `PREVIOUS_HEAD` first: a crash before the record is written leaves a
    // stale record, which reads as `PREVIOUS_HEAD` alone.
    write_previous_head(layout, old)?;
    record.push(old.clone());
    let excess = record.len().saturating_sub(HEAD_HISTORY_MAX);
    record.drain(..excess);
    let body: String = record.iter().map(encode_previous_head).collect();
    crate::durable::write_pointer(
        &layout.worktree_state_dir().join("HEAD_HISTORY"),
        body.as_bytes(),
        Parents::Existing,
    )?;
    Ok(())
}

/// Atomically save one previous HEAD. The caller holds the worktree lock.
pub fn write_previous_head(layout: &RepoLayout, head: &Head) -> RefResult<()> {
    let body = encode_previous_head(head);
    crate::durable::write_pointer(
        &layout.worktree_state_dir().join("PREVIOUS_HEAD"),
        body.as_bytes(),
        Parents::Existing,
    )?;
    Ok(())
}

/// Write `HEAD` as a symbolic ref pointing at `branch`.
///
/// # Errors
/// - [`RefError::InvalidRefName`] if `branch` does not satisfy
///   [`validate_ref_name`].
/// - [`RefError::Io`] for filesystem failures.
pub fn write_head_branch(layout: &RepoLayout, branch: &str) -> RefResult<()> {
    check_local_write(layout.common_dir(), HEADS_DIR, branch, RefNameKind::Branch)?;
    let body = format!("{HEAD_REF_PREFIX}{branch}\n");
    crate::durable::write_pointer(&layout.head_file(), body.as_bytes(), Parents::Existing)?;
    Ok(())
}

/// Write `HEAD` as a detached hash.
///
/// # Errors
/// - [`RefError::Io`] for filesystem failures.
pub fn write_head_detached(layout: &RepoLayout, h: &Hash) -> RefResult<()> {
    let wire = encode_ref_wire(h);
    crate::durable::write_pointer(&layout.head_file(), &wire, Parents::Existing)?;
    Ok(())
}

/// Resolve `HEAD` to a commit hash. Returns `Ok(None)` when HEAD points
/// at a branch that has no commit yet.
pub fn resolve_head(layout: &RepoLayout) -> RefResult<Option<Hash>> {
    let head = match read_head(layout) {
        Ok(h) => h,
        Err(RefError::NoHead) => return Ok(None),
        Err(e) => return Err(e),
    };
    match head {
        Head::Branch(name) => read_ref(layout, &name),
        Head::Detached(h) => Ok(Some(h)),
    }
}

/// Update the ref HEAD currently points at (or HEAD itself, if
/// detached) to `commit_hash`.
pub fn update_head(layout: &RepoLayout, commit_hash: &Hash) -> RefResult<()> {
    let head = read_head(layout)?;
    match head {
        Head::Branch(name) => write_ref(layout, &name, commit_hash),
        Head::Detached(_) => write_head_detached(layout, commit_hash),
    }
}

// -----------------------------------------------------------------------------
// Branch refs (refs/heads/<name>)
// -----------------------------------------------------------------------------

/// Read the hash a branch ref points to. Returns `Ok(None)` if the ref
/// file does not exist.
///
/// # Errors
/// - [`RefError::InvalidRefName`] if `branch` does not validate.
/// - [`RefError::InvalidRef`] if the on-disk bytes are not a valid wire.
pub fn read_ref(layout: &RepoLayout, branch: &str) -> RefResult<Option<Hash>> {
    check_existing_ref_name(branch)?;
    read_ref_under(layout.common_dir(), HEADS_DIR, branch)
}

/// Write a branch ref (unconditional — equivalent to
/// `update_ref(branch, RefWriteCondition::Any, h)`).
pub fn write_ref(layout: &RepoLayout, branch: &str, h: &Hash) -> RefResult<()> {
    update_ref(layout, branch, RefWriteCondition::Any, h)
}

/// CAS-aware ref write per SPEC-REFS §5.
///
/// # Errors
/// - [`RefError::InvalidRefName`] if `branch` is not a valid name.
/// - [`RefError::Conflict`] if `condition` is not satisfied.
/// - [`RefError::Io`] for filesystem failures.
pub fn update_ref(
    layout: &RepoLayout,
    branch: &str,
    condition: RefWriteCondition,
    h: &Hash,
) -> RefResult<()> {
    check_local_write(layout.common_dir(), HEADS_DIR, branch, RefNameKind::Branch)?;
    let path = ref_path(layout.common_dir(), HEADS_DIR, branch);
    let wire = encode_ref_wire(h);
    cas_write(layout.common_dir(), &path, &wire, branch, condition)
}

/// A branch ref write staged in a [`Group`]: its temp file is written out and
/// invisible until [`publish_staged_ref`].
#[derive(Debug)]
#[must_use = "a staged ref is invisible until it is published"]
pub struct StagedRef {
    staged: Staged,
    common_dir: PathBuf,
    path: PathBuf,
    name: String,
    wire: [u8; 65],
}

/// Stage the write of `h` to the branch `branch`, as [`update_ref`] makes it
/// but in two steps, so its bytes share the flush of the objects it names.
/// The name is checked now, the condition at [`publish_staged_ref`].
///
/// # Errors
/// As [`update_ref`] for the name, [`RefError::Io`] when the temp file cannot
/// be written, or the group is poisoned.
pub fn stage_ref_update(
    group: &mut Group,
    layout: &RepoLayout,
    branch: &str,
    h: &Hash,
) -> RefResult<StagedRef> {
    check_local_write(layout.common_dir(), HEADS_DIR, branch, RefNameKind::Branch)?;
    let path = ref_path(layout.common_dir(), HEADS_DIR, branch);
    let wire = encode_ref_wire(h);
    let staged = group.stage(&path, &wire, Parents::Create)?;
    Ok(StagedRef {
        staged,
        common_dir: layout.common_dir().to_path_buf(),
        path,
        name: branch.to_string(),
        wire,
    })
}

/// The lock of a branch ref whose staged write was published. A ref write
/// holds its lock until its rename is durable (SPEC-REFS §5.1.1): flush the
/// group, then drop this.
#[derive(Debug)]
#[must_use = "the ref stays locked until this is dropped; flush the group first"]
pub struct PublishedRef(#[allow(dead_code)] RefMutation);

impl std::fmt::Debug for RefMutation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RefMutation")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

/// Publish a staged branch ref: take the ref lock, check `condition` and
/// rename. `after` must come from a flush of `group` that covers the objects
/// the ref names. The rename is not durable yet: the caller flushes `group`,
/// and only then drops the returned lock, so that no other writer reads the
/// ref before it is durable.
///
/// # Errors
/// [`RefError::Conflict`] when `condition` fails, as [`update_ref`]. A
/// refused token or a failed rename is [`RefError::Io`]. The staged file is
/// dropped on any error.
pub fn publish_staged_ref(
    group: &mut Group,
    staged: StagedRef,
    condition: RefWriteCondition,
    after: &Flushed,
) -> RefResult<PublishedRef> {
    let StagedRef {
        staged,
        common_dir,
        path,
        name,
        wire,
    } = staged;
    let mutation = RefMutation::acquire(&common_dir, &path, &name)?;
    mutation.write_staged(group, staged, &wire, condition, after)?;
    Ok(PublishedRef(mutation))
}

/// A detached `HEAD` write staged in a [`Group`].
#[derive(Debug)]
#[must_use = "a staged HEAD is invisible until it is published"]
pub struct StagedHead(Staged);

/// Stage the write of a detached `HEAD`, as [`write_head_detached`] makes it
/// but in two steps.
///
/// # Errors
/// [`RefError::Io`] when the temp file cannot be written, or the group is
/// poisoned.
pub fn stage_head_detached(
    group: &mut Group,
    layout: &RepoLayout,
    h: &Hash,
) -> RefResult<StagedHead> {
    let wire = encode_ref_wire(h);
    Ok(StagedHead(group.stage(
        &layout.head_file(),
        &wire,
        Parents::Existing,
    )?))
}

/// Publish a staged detached `HEAD`. The caller flushes `group` for the
/// rename before it reports success.
///
/// # Errors
/// As [`publish_staged_ref`], without the condition.
pub fn publish_staged_head(
    group: &mut Group,
    staged: StagedHead,
    after: &Flushed,
) -> RefResult<()> {
    group.publish_sibling(staged.0, after)?;
    Ok(())
}

// -----------------------------------------------------------------------------
// History-coupled ref writes (feature: history-mmr)
// -----------------------------------------------------------------------------

/// Acquire the complete nested guard for a history transaction or snapshot.
#[cfg(feature = "history-mmr")]
pub(crate) fn acquire_history_mutation(
    layout: &RepoLayout,
    branch: &str,
) -> RefResult<(crate::repo_lock::RepoLock, RefMutation)> {
    // Grammar only: deletes take this guard too; writes check the bound
    // first.
    check_existing_ref_name(branch)?;
    let history =
        crate::repo_lock::acquire_default(layout.common_dir(), &history_lock_name(branch))
            .map_err(|e| RefError::InvalidRef(format!("{branch}: history lock: {e}")))?;
    let path = ref_path(layout.common_dir(), HEADS_DIR, branch);
    let mutation = RefMutation::acquire(layout.common_dir(), &path, branch)?;
    Ok((history, mutation))
}

/// Publish a branch's canonical first-parent ancestry, with an explicit
/// generation and crash-recoverable descriptor.
#[cfg(feature = "history-mmr")]
pub fn update_ref_with_ancestry(
    layout: &RepoLayout,
    branch: &str,
    condition: RefWriteCondition,
    target: &Hash,
    store: &crate::store::ObjectStore,
) -> RefResult<()> {
    check_local_write(layout.common_dir(), HEADS_DIR, branch, RefNameKind::Branch)?;
    let (_history, mutation) = acquire_history_mutation(layout, branch)?;
    crate::history::ancestry::advance(layout, branch, &mutation, condition, *target, store).map_err(
        |e| match e {
            crate::history::HistoryError::Ref(e) => e,
            other => RefError::InvalidRef(format!("{branch}: ancestry publication: {other}")),
        },
    )
}

/// Write a branch ref. With the `history-mmr` feature on, the write also
/// publishes a versioned first-parent ancestry snapshot.
///
/// The history-aware path locks the history first, then the full ref
/// identity. It recovers a pending publication before it accepts the write.
/// Detached HEAD updates claim no branch membership, so they do not use this
/// function.
///
/// # Errors
/// The errors of [`update_ref`]. With `history-mmr`, also
/// [`RefError::InvalidRef`] when the object store or the ancestry cannot be
/// used.
pub fn write_ref_recording_history(
    layout: &RepoLayout,
    branch: &str,
    condition: RefWriteCondition,
    new_hash: &Hash,
) -> RefResult<()> {
    #[cfg(feature = "history-mmr")]
    {
        let store = crate::store::ObjectStore::open(layout)
            .map_err(|e| RefError::InvalidRef(format!("{branch}: open object store: {e}")))?;
        update_ref_with_ancestry(layout, branch, condition, new_hash, &store)
    }
    #[cfg(not(feature = "history-mmr"))]
    {
        update_ref(layout, branch, condition, new_hash)
    }
}

/// Delete a branch after recovering any pending ancestry publication. Archived
/// generation snapshots remain evidence; the current
/// descriptor is invalidated before the ref disappears.
#[cfg(feature = "history-mmr")]
pub fn delete_ref_with_ancestry(
    layout: &RepoLayout,
    branch: &str,
    expected: Option<Hash>,
    store: &crate::store::ObjectStore,
) -> RefResult<()> {
    let (_history, mutation) = acquire_history_mutation(layout, branch)?;
    crate::history::ancestry::recover(layout, branch, &mutation, store)
        .map_err(|e| RefError::InvalidRef(format!("{branch}: history recovery: {e}")))?;
    mutation.delete(expected)
}

/// Delete a branch ref. Errors with [`RefError::NotFound`] if absent.
pub fn delete_ref(layout: &RepoLayout, branch: &str) -> RefResult<()> {
    check_existing_ref_name(branch)?;
    let path = ref_path(layout.common_dir(), HEADS_DIR, branch);
    RefMutation::acquire(layout.common_dir(), &path, branch)?.delete(None)
}

/// Delete a branch ref unless it is the currently checked-out branch.
pub fn delete_ref_safe(layout: &RepoLayout, branch: &str) -> RefResult<()> {
    match read_head(layout) {
        Ok(Head::Branch(current)) if current == branch => {
            Err(RefError::CurrentBranch(branch.to_string()))
        }
        _ => delete_ref(layout, branch),
    }
}

/// CAS-guarded delete: removes a branch ref only if its current on-disk
/// value is exactly `expected`.
///
/// [`delete_ref`] is unconditional — it removes whatever is at `path`
/// regardless of what a caller last read. That is fine for the
/// user-initiated `branch -d`/`-D` path (deleting a specific named
/// branch is meaningful even if its tip moved since the user last
/// looked), but it is NOT fine for `branch -m`'s rename: a rename reads
/// the source branch's tip, publishes it under the new name, and then
/// drops the source ref. If a concurrent `commit` (via
/// [`RefWriteCondition::Match`], see `kit-bin`'s `advance_head`)
/// advances the source branch in the window between the rename's read
/// and its delete, an unconditional delete destroys that freshly-landed
/// commit's only ref with no error to either caller — commit reports
/// success, rename reports success, and the commit becomes unreachable.
///
/// This closes that gap by making the delete itself compare-and-swap:
/// it acquires the SAME per-ref lock every `cas_write` condition takes
/// (via `cas_lock_name`, keyed off the ref's path so it can never
/// collide with an unrelated ref of the same bare name), reads the
/// current value under that lock, and only removes the file if it is
/// still exactly `expected`. Because a concurrent `Match`-conditioned
/// advance on the SAME ref takes the identical lock, the two can never
/// interleave: either the advance's CAS write lands first (this call
/// then sees the new value, doesn't match, and errors `Conflict`
/// without touching the file) or this delete lands first (the advance's
/// subsequent `Match(expected)` then sees the ref gone and itself fails
/// `Conflict`) — never both "succeeding" against the same prior state.
///
/// All writers, including `Any`, and both delete forms take the same
/// per-ref guard. Callers do not need to establish a separate exclusion rule.
///
/// # Errors
/// - [`RefError::InvalidRefName`] if `branch` is not a valid name.
/// - [`RefError::Conflict`] if the ref's current value is not exactly
///   `expected` — this includes the ref not existing at all. The ref
///   file is left completely untouched in this case.
/// - [`RefError::Io`] for filesystem or lock-acquisition failures.
pub fn delete_ref_if_matches(layout: &RepoLayout, branch: &str, expected: Hash) -> RefResult<()> {
    check_existing_ref_name(branch)?;
    let path = ref_path(layout.common_dir(), HEADS_DIR, branch);
    RefMutation::acquire(layout.common_dir(), &path, branch)?.delete(Some(expected))
}

/// List all branch refs, sorted lexicographically by name.
pub fn list_refs(layout: &RepoLayout) -> RefResult<Vec<Ref>> {
    list_refs_under(layout.common_dir(), HEADS_DIR)
}

// -----------------------------------------------------------------------------
// Remote-tracking refs (refs/remotes/<remote>/<branch>)
// -----------------------------------------------------------------------------

/// Read a remote-tracking branch ref.
pub fn read_remote_ref(layout: &RepoLayout, remote: &str, branch: &str) -> RefResult<Option<Hash>> {
    check_existing_ref_name(remote)?;
    check_existing_ref_name(branch)?;
    read_ref_under(layout.common_dir(), &remote_ref_dir(remote), branch)
}

/// Write a remote-tracking branch ref unconditionally.
pub fn write_remote_ref(
    layout: &RepoLayout,
    remote: &str,
    branch: &str,
    h: &Hash,
) -> RefResult<()> {
    check_new_ref_name(remote)?;
    check_new_ref_name(branch)?;
    let path = ref_path(layout.common_dir(), &remote_ref_dir(remote), branch);
    let wire = encode_ref_wire(h);
    cas_write(
        layout.common_dir(),
        &path,
        &wire,
        branch,
        RefWriteCondition::Any,
    )
}

/// Batched writer for remote-tracking refs: amortises the
/// parent-directory fsync across every ref written into it, instead of
/// paying one per ref like [`write_remote_ref`] in a loop.
///
/// `push`/`fetch` publish one tracking ref per branch
/// (`refs/remotes/<remote>/<branch>`) in a loop; each individual
/// [`write_remote_ref`] call goes through `write_pointer`'s
/// temp+fsync+rename+**dirsync** pattern, so N branches cost N serial
/// directory fsyncs even though every write lands under the same
/// `refs/remotes/<remote>/` tree. `RemoteRefBatch` instead:
///
/// 1. [`Self::write`]s each ref durable-content-before-visible (fsyncs
///    the wire bytes, then renames — same invariant
///    `crate::durable::write_content_synced` gives object writes: a
///    reader can never observe a torn file), immediately, one call at a
///    time, deferring only the directory fsync that makes the RENAME
///    itself crash-durable;
/// 2. [`Self::commit`] fsyncs every distinct directory touched, once
///    each, deduplicated — O(distinct directories) instead of O(refs).
///    For the common case (one remote, flat branch names) that is
///    exactly one fsync for the whole batch.
///
/// This is deliberately scoped to `refs/remotes/*` ONLY — see
/// `durable`'s module docs for why branch heads (`refs/heads/*`,
/// [`write_ref`]/[`update_ref`]) keep the unbatched per-write contract:
/// tracking refs are a locally-cached, recomputable-from-a-re-fetch
/// view of another repository, not a pointer anything else orders
/// against.
///
/// # Partial-failure semantics
///
/// Best-effort, fail-fast — the same contract
/// [`crate::batch::WriteBatch::commit`] documents for the object store's
/// batched writes. [`Self::write`] renames each ref as soon as it
/// validates and its content is durable, so a ref that made it through
/// `write` is visible to readers immediately, exactly as it would have
/// been under the old per-ref loop. If a later `write` in the same
/// batch fails (bad name or I/O error), earlier successful writes are
/// **not** rolled back — content-addressed dedup isn't in play here,
/// but the same reasoning applies: remote-tracking refs are
/// recomputable, so a partially-applied batch is exactly as safe to
/// retry as the old loop was after failing at the same point. Callers
/// that want the successful prefix to be durable even when the batch as
/// a whole errors out should call [`Self::commit`] regardless of
/// whether the write loop returned early (see
/// `remote_dispatch::push_all_with` / `kit-sync`'s `fetch_objects_inner` for the
/// pattern).
#[derive(Debug)]
pub struct RemoteRefBatch<'a> {
    layout: &'a RepoLayout,
    sub_dir: String,
    touched_dirs: BTreeSet<PathBuf>,
}

impl<'a> RemoteRefBatch<'a> {
    /// Start a batch for `remote`.
    ///
    /// # Errors
    /// [`RefError::InvalidRefName`] if `remote` fails [`validate_ref_name`].
    pub fn new(layout: &'a RepoLayout, remote: &str) -> RefResult<Self> {
        check_new_ref_name(remote)?;
        Ok(Self {
            layout,
            sub_dir: remote_ref_dir(remote),
            touched_dirs: BTreeSet::new(),
        })
    }

    /// Write one remote-tracking ref: validates `branch`, fsyncs its
    /// wire-encoded content, then renames it into place — visible
    /// immediately, same as [`write_remote_ref`]. Only the directory
    /// fsync (rename durability) is deferred to [`Self::commit`].
    ///
    /// # Errors
    /// - [`RefError::InvalidRefName`] if `branch` fails
    ///   [`validate_ref_name`] — no I/O is attempted for an invalid name.
    /// - [`RefError::Io`] for filesystem failures.
    ///
    /// # Panics
    /// Never in practice: `ref_path` always produces a path with a
    /// parent (it is `self.layout.common_dir()` joined with at least the
    /// remote's subdirectory and the branch name).
    pub fn write(&mut self, branch: &str, h: &Hash) -> RefResult<()> {
        check_new_ref_name(branch)?;
        let path = ref_path(self.layout.common_dir(), &self.sub_dir, branch);
        let guard = RefMutation::acquire(self.layout.common_dir(), &path, branch)?;
        guard.invalidate_history()?;
        let parent = path
            .parent()
            .expect("remote-tracking ref path always has a parent")
            .to_path_buf();
        fs::create_dir_all(&parent)?;
        let wire = encode_ref_wire(h);
        crate::durable::write_content_synced(&path, &wire)?;
        self.touched_dirs.insert(parent);
        Ok(())
    }

    /// Fsync every directory touched by a completed [`Self::write`],
    /// once each. Idempotent to call on a batch with nothing staged (a
    /// no-op). MUST be called after the last `write` a caller intends to
    /// make durable — refs written but never committed are visible but
    /// not crash-durable (the rename may not have reached stable
    /// storage), the same window [`crate::store::BulkWriter::commit`]
    /// documents for bulk object writes.
    ///
    /// # Errors
    /// [`RefError::Io`] on the first directory fsync failure. Directories
    /// are synced in sorted order for determinism; a failure partway
    /// through leaves the remaining directories un-synced (best-effort,
    /// matching [`Self::write`]'s partial-failure contract).
    pub fn commit(self) -> RefResult<()> {
        for dir in &self.touched_dirs {
            crate::durable::flush_dir(dir)?;
        }
        Ok(())
    }
}

/// Delete a remote-tracking branch ref (e.g. after the upstream
/// deleted the branch). Errors with [`RefError::NotFound`] if absent.
pub fn delete_remote_ref(layout: &RepoLayout, remote: &str, branch: &str) -> RefResult<()> {
    check_existing_ref_name(remote)?;
    check_existing_ref_name(branch)?;
    let path = ref_path(layout.common_dir(), &remote_ref_dir(remote), branch);
    RefMutation::acquire(layout.common_dir(), &path, &format!("{remote}/{branch}"))?.delete(None)
}

/// List all remote-tracking refs for one remote.
pub fn list_remote_refs(layout: &RepoLayout, remote: &str) -> RefResult<Vec<Ref>> {
    check_existing_ref_name(remote)?;
    list_refs_under(layout.common_dir(), &remote_ref_dir(remote))
}

/// Like [`list_remote_refs`], but hands the batch of discovered ref files
/// to a caller-supplied `read_batch` — see [`list_refs_with`]'s docs for
/// the shape and the `RefBatchLengthMismatch` contract.
pub fn list_remote_refs_with(
    layout: &RepoLayout,
    remote: &str,
    read_batch: impl FnOnce(&[RefCandidate]) -> Vec<RefReadOutcome>,
) -> RefResult<Vec<Ref>> {
    check_existing_ref_name(remote)?;
    list_refs_under_with(layout.common_dir(), &remote_ref_dir(remote), read_batch)
}

/// List the remote names that have at least one tracking ref on disk
/// (the immediate subdirectories of `refs/remotes/`), sorted. A
/// missing `refs/remotes/` yields an empty list. Entries whose names
/// fail the ref grammar are skipped (consistent with how malformed
/// ref files are skipped by [`list_refs`]).
pub fn list_remote_names(layout: &RepoLayout) -> RefResult<Vec<String>> {
    let dir = layout.remotes_dir();
    let entries = match fs::read_dir(&dir) {
        Ok(e) => e,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(RefError::Io(e)),
    };
    let mut names = Vec::new();
    for entry in entries {
        let entry = entry.map_err(RefError::Io)?;
        if !entry.file_type().map_err(RefError::Io)?.is_dir() {
            continue;
        }
        if let Some(name) = entry.file_name().to_str()
            && name_grammar_ok(name, usize::MAX)
        {
            names.push(name.to_owned());
        }
    }
    names.sort();
    Ok(names)
}

// -----------------------------------------------------------------------------
// Tags (refs/tags/<name>)
// -----------------------------------------------------------------------------

/// Read the hash a tag points to.
pub fn read_tag(layout: &RepoLayout, name: &str) -> RefResult<Option<Hash>> {
    check_existing_ref_name(name)?;
    read_ref_under(layout.common_dir(), TAGS_DIR, name)
}

/// Write a tag ref (unconditional).
pub fn write_tag(layout: &RepoLayout, name: &str, h: &Hash) -> RefResult<()> {
    update_tag(layout, name, RefWriteCondition::Any, h)
}

/// CAS-aware tag write — same semantics as [`update_ref`] but for
/// `refs/tags/`.
pub fn update_tag(
    layout: &RepoLayout,
    name: &str,
    condition: RefWriteCondition,
    h: &Hash,
) -> RefResult<()> {
    check_local_write(layout.common_dir(), TAGS_DIR, name, RefNameKind::Tag)?;
    let path = ref_path(layout.common_dir(), TAGS_DIR, name);
    let wire = encode_ref_wire(h);
    cas_write(layout.common_dir(), &path, &wire, name, condition)
}

/// Delete a tag ref.
pub fn delete_tag(layout: &RepoLayout, name: &str) -> RefResult<()> {
    check_existing_ref_name(name)?;
    let path = ref_path(layout.common_dir(), TAGS_DIR, name);
    RefMutation::acquire(layout.common_dir(), &path, name)?.delete(None)
}

/// List all tag refs, sorted lexicographically by name.
pub fn list_tags(layout: &RepoLayout) -> RefResult<Vec<Ref>> {
    list_refs_under(layout.common_dir(), TAGS_DIR)
}

/// Like [`list_tags`], but hands the batch of discovered ref files to a
/// caller-supplied `read_batch` — see [`list_refs_with`]'s docs for the
/// shape and the `RefBatchLengthMismatch` contract.
pub fn list_tags_with(
    layout: &RepoLayout,
    read_batch: impl FnOnce(&[RefCandidate]) -> Vec<RefReadOutcome>,
) -> RefResult<Vec<Ref>> {
    list_refs_under_with(layout.common_dir(), TAGS_DIR, read_batch)
}

// -----------------------------------------------------------------------------
// Shallow boundaries (.kit/shallow)
// -----------------------------------------------------------------------------

/// Load shallow-boundary hashes from `.kit/shallow`. Returns `Ok(None)`
/// if the file does not exist or is empty.
pub fn load_shallow_boundaries(layout: &RepoLayout) -> RefResult<Option<Vec<Hash>>> {
    let path = layout.shallow_file();
    let bytes = match bounded_read::read_capped(&path, SHALLOW_MAX_BYTES) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) if e.kind() == io::ErrorKind::InvalidData => {
            return Err(RefError::InvalidRef("shallow file too large".to_string()));
        }
        Err(e) => return Err(RefError::Io(e)),
    };
    if bytes.is_empty() {
        return Ok(None);
    }
    let s = core::str::from_utf8(&bytes).map_err(|_| RefError::InvalidHead)?;
    let mut out = Vec::new();
    for line in s.split('\n') {
        let trimmed = line.trim_end_matches(['\r', ' ', '\t']);
        if trimmed.len() != HEX_LEN {
            continue;
        }
        if let Some(h) = parse_lowercase_hash(trimmed.as_bytes()) {
            out.push(h);
        }
    }
    if out.is_empty() {
        return Ok(None);
    }
    Ok(Some(out))
}

/// Write shallow-boundary hashes to `.kit/shallow`. Passing an empty
/// slice removes the file.
pub fn write_shallow_boundaries(layout: &RepoLayout, boundaries: &[Hash]) -> RefResult<()> {
    let path = layout.shallow_file();
    if boundaries.is_empty() {
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(RefError::Io(e)),
        }
    } else {
        let mut out = Vec::with_capacity(boundaries.len() * 65);
        for h in boundaries {
            out.extend_from_slice(&encode_ref_wire(h));
        }
        crate::durable::write_pointer(&path, &out, Parents::Create)?;
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Internals
// -----------------------------------------------------------------------------

fn ref_path(common_dir: &Path, sub_dir: &str, name: &str) -> PathBuf {
    let mut path = common_dir.join(sub_dir);
    for segment in name.split('/') {
        path.push(segment);
    }
    path
}

fn remote_ref_dir(remote: &str) -> String {
    format!("{REMOTES_DIR}/{remote}")
}

fn read_ref_under(common_dir: &Path, sub_dir: &str, name: &str) -> RefResult<Option<Hash>> {
    let path = ref_path(common_dir, sub_dir, name);
    let bytes = match bounded_read::read_capped(&path, REF_FILE_MAX_BYTES) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) if e.kind() == io::ErrorKind::InvalidData => {
            return Err(RefError::InvalidRef(name.to_string()));
        }
        Err(e) => return Err(RefError::Io(e)),
    };
    let h = decode_ref_wire(&bytes).ok_or_else(|| RefError::InvalidRef(name.to_string()))?;
    Ok(Some(h))
}

/// A held mutation transaction for exactly one full ref identity. Every
/// write condition and delete uses this guard; history callers acquire their
/// history lock first and may call the guarded primitives without relocking.
pub(crate) struct RefMutation {
    path: PathBuf,
    common_dir: PathBuf,
    name: String,
    _lock: crate::repo_lock::RepoLock,
}

impl RefMutation {
    fn acquire(common_dir: &Path, path: &Path, name: &str) -> RefResult<Self> {
        let lock = crate::repo_lock::acquire_default(common_dir, &cas_lock_name(common_dir, path))
            .map_err(|e| match e {
                crate::repo_lock::LockError::Io(io) => RefError::Io(io),
                other => RefError::InvalidRef(format!("{name}: ref mutation lock: {other}")),
            })?;
        Ok(Self {
            path: path.to_path_buf(),
            common_dir: common_dir.to_path_buf(),
            name: name.to_string(),
            _lock: lock,
        })
    }

    pub(crate) fn current(&self) -> RefResult<Option<Hash>> {
        match bounded_read::read_capped(&self.path, REF_FILE_MAX_BYTES) {
            Ok(bytes) => decode_ref_wire(&bytes)
                .map(Some)
                .ok_or_else(|| RefError::InvalidRef(self.name.clone())),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) if e.kind() == io::ErrorKind::InvalidData => {
                Err(RefError::InvalidRef(self.name.clone()))
            }
            Err(e) => Err(RefError::Io(e)),
        }
    }

    pub(crate) fn check(&self, condition: RefWriteCondition) -> RefResult<()> {
        let matches = match condition {
            RefWriteCondition::Any => true,
            RefWriteCondition::Missing => !self.path.try_exists()?,
            RefWriteCondition::Match(expected) => self.current()? == Some(expected),
        };
        if matches {
            Ok(())
        } else {
            Err(RefError::Conflict(self.name.clone()))
        }
    }

    fn invalidate_history(&self) -> RefResult<()> {
        if let Ok(full_ref) = self.path.strip_prefix(&self.common_dir) {
            ancestry_state::invalidate(&self.common_dir, &full_ref.to_string_lossy())?;
        }
        Ok(())
    }

    fn write(&self, wire: &[u8; 65], condition: RefWriteCondition) -> RefResult<()> {
        self.check(condition)?;
        self.guard_history(wire)?;
        self.write_preserving_history(wire, condition)
    }

    /// The history rule of a write of `wire`. Even a same-tip raw write
    /// refuses to bypass an outstanding intent. Ordinary writes preserve a
    /// matching snapshot only for a true no-op.
    fn guard_history(&self, wire: &[u8; 65]) -> RefResult<()> {
        if self.current().ok().flatten() != decode_ref_wire(wire) {
            self.invalidate_history()?;
        } else if ancestry_state::Transaction::read(&ancestry_state::branch_dir(
            &self.common_dir,
            &self
                .path
                .strip_prefix(&self.common_dir)
                .unwrap_or(&self.path)
                .to_string_lossy(),
        ))?
        .is_some()
        {
            return Err(RefError::InvalidRef("pending history publication".into()));
        }
        Ok(())
    }

    /// [`Self::write`] of a staged temp file: the check and the rename that
    /// `after` licenses, under this lock. The caller flushes the rename
    /// before it releases the lock (SPEC-REFS §5.1.1).
    fn write_staged(
        &self,
        group: &mut Group,
        staged: Staged,
        wire: &[u8; 65],
        condition: RefWriteCondition,
        after: &Flushed,
    ) -> RefResult<()> {
        self.check(condition)?;
        self.guard_history(wire)?;
        if matches!(condition, RefWriteCondition::Missing) {
            if !group.publish_new_sibling(staged, after)? {
                return Err(RefError::Conflict(self.name.clone()));
            }
        } else {
            group.publish_sibling(staged, after)?;
        }
        Ok(())
    }

    pub(crate) fn write_preserving_history(
        &self,
        wire: &[u8; 65],
        condition: RefWriteCondition,
    ) -> RefResult<()> {
        self.check(condition)?;
        if matches!(condition, RefWriteCondition::Missing) {
            if !crate::durable::write_pointer_new(&self.path, wire, Parents::Create)? {
                return Err(RefError::Conflict(self.name.clone()));
            }
        } else {
            crate::durable::write_pointer(&self.path, wire, Parents::Create)?;
        }
        Ok(())
    }

    fn delete(&self, expected: Option<Hash>) -> RefResult<()> {
        if let Some(expected) = expected {
            self.check(RefWriteCondition::Match(expected))?;
        }
        self.invalidate_history()?;
        match fs::remove_file(&self.path) {
            Ok(()) => {
                crate::durable::flush_dir(self.path.parent().expect("ref path has parent"))?;
                Ok(())
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                if expected.is_some() {
                    Err(RefError::Conflict(self.name.clone()))
                } else {
                    Err(RefError::NotFound(self.name.clone()))
                }
            }
            Err(e) => Err(RefError::Io(e)),
        }
    }
}

fn cas_write(
    common_dir: &Path,
    path: &Path,
    wire: &[u8; 65],
    name_for_err: &str,
    condition: RefWriteCondition,
) -> RefResult<()> {
    RefMutation::acquire(common_dir, path, name_for_err)?.write(wire, condition)
}

fn list_refs_under(common_dir: &Path, sub_dir: &str) -> RefResult<Vec<Ref>> {
    list_refs_under_with(common_dir, sub_dir, sequential_read_batch)
}

/// The default, sequential `read_batch`: reads and decodes each candidate
/// one at a time, exactly `collect_refs`'s old inline behavior. What
/// [`list_refs_under`] (and therefore [`list_refs`]/[`list_remote_refs`]/
/// tag listing) still uses.
fn sequential_read_batch(candidates: &[RefCandidate]) -> Vec<RefReadOutcome> {
    candidates.iter().map(read_ref_candidate).collect()
}

/// Read and decode one [`RefCandidate`]'s wire content. The single
/// definition of "how to turn a candidate into a [`RefReadOutcome`]",
/// shared by `sequential_read_batch` and every caller-supplied
/// `read_batch` in kit-bin's rayon fan-out and its bench — so the
/// `Unreadable`-vs-`Decoded(None)` policy (an I/O failure drops the
/// entry; malformed-but-readable content keeps it with `hash: None`)
/// can't drift between a sequential and a parallel caller.
#[must_use]
pub fn read_ref_candidate(candidate: &RefCandidate) -> RefReadOutcome {
    use std::io::Read;

    // A valid ref is HEX_LEN bytes plus optional trailing whitespace, and
    // ref files are written whole and renamed into place (never appended
    // to), so one `read` into a stack buffer sees the entire file. This is
    // open+read+close, versus `fs::read`'s extra size-hint `statx` and
    // EOF-probe `read` — the dominant per-ref cost when listing thousands.
    // A file that fills the buffer falls back to a capped read. An
    // oversized file is malformed content, so it keeps `hash: None`.
    let mut buf = [0u8; 256];
    let read = fs::File::open(&candidate.path).and_then(|mut f| {
        loop {
            match f.read(&mut buf) {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                r => break r,
            }
        }
    });
    match read {
        Ok(n) if n < buf.len() => RefReadOutcome::Decoded(decode_ref_wire(&buf[..n])),
        Ok(_) => match bounded_read::read_capped(&candidate.path, REF_FILE_MAX_BYTES) {
            Ok(bytes) => RefReadOutcome::Decoded(decode_ref_wire(&bytes)),
            Err(e) if e.kind() == io::ErrorKind::InvalidData => RefReadOutcome::Decoded(None),
            Err(_) => RefReadOutcome::Unreadable,
        },
        Err(_) => RefReadOutcome::Unreadable,
    }
}

/// One ref file discovered by `list_refs_under_with`'s directory walk:
/// its logical name (relative to the listed namespace, e.g. a branch or
/// tag name) and the on-disk path to read its wire content from.
#[derive(Debug, Clone)]
pub struct RefCandidate {
    pub name: String,
    pub path: PathBuf,
}

/// The outcome of reading and decoding one [`RefCandidate`]'s wire
/// content — matching `collect_refs`'s old per-entry handling exactly:
/// an I/O failure drops the entry from the listing entirely (the same
/// silently-skip posture the sequential path already had for a transient
/// read failure or a race with concurrent deletion); malformed-but-
/// readable content keeps the entry with [`Ref::hash`] `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefReadOutcome {
    Unreadable,
    Decoded(Option<Hash>),
}

/// Like [`list_refs`], but hands the *whole* batch of discovered ref
/// files to a caller-supplied `read_batch` instead of reading and
/// decoding each one sequentially inside the same call that walks the
/// directory tree — e.g. a rayon fan-out, the same parallel-batch shape
/// already used for pack-entry compression, delta encoding, and
/// post-fetch signature verification (`kit-bin`'s `remote_dispatch`).
/// The directory walk itself (`fs::read_dir`, cheap metadata-only calls)
/// stays sequential; only the per-file read-and-decode step, one syscall
/// each and independent of every other entry, is worth fanning out.
/// `read_batch` must return exactly one [`RefReadOutcome`] per candidate,
/// in the same order — a mismatched length is
/// [`RefError::RefBatchLengthMismatch`], not a silently desynced listing.
pub fn list_refs_with(
    layout: &RepoLayout,
    read_batch: impl FnOnce(&[RefCandidate]) -> Vec<RefReadOutcome>,
) -> RefResult<Vec<Ref>> {
    list_refs_under_with(layout.common_dir(), HEADS_DIR, read_batch)
}

fn list_refs_under_with(
    common_dir: &Path,
    sub_dir: &str,
    read_batch: impl FnOnce(&[RefCandidate]) -> Vec<RefReadOutcome>,
) -> RefResult<Vec<Ref>> {
    let root = common_dir.join(sub_dir);
    let mut candidates = Vec::new();
    if !root.is_dir() {
        return Ok(Vec::new());
    }
    collect_ref_candidates(&root, "", &mut candidates, 0)?;
    let outcomes = read_batch(&candidates);
    if outcomes.len() != candidates.len() {
        return Err(RefError::RefBatchLengthMismatch {
            expected: candidates.len(),
            actual: outcomes.len(),
        });
    }
    let mut out = Vec::with_capacity(candidates.len());
    for (candidate, outcome) in candidates.into_iter().zip(outcomes) {
        match outcome {
            RefReadOutcome::Unreadable => {}
            RefReadOutcome::Decoded(hash) => out.push(Ref {
                name: candidate.name,
                hash,
            }),
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

fn collect_ref_candidates(
    root: &Path,
    prefix: &str,
    out: &mut Vec<RefCandidate>,
    depth: usize,
) -> RefResult<()> {
    if depth > MAX_REF_WALK_DEPTH {
        // Silently stop — same "skip malformed" posture as below for
        // individual files. Callers get a partial result rather than a
        // stack overflow on adversarial input.
        return Ok(());
    }
    let dir_path = if prefix.is_empty() {
        root.to_path_buf()
    } else {
        root.join(prefix)
    };
    let iter = match fs::read_dir(&dir_path) {
        Ok(i) => i,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(RefError::Io(e)),
    };
    // Subdirectories wait until this directory handle closes, so a deep
    // tree holds one open handle at a time.
    let mut subdirs = Vec::new();
    for entry in iter {
        let entry = entry?;
        let file_name = match entry.file_name().to_str() {
            Some(s) => s.to_string(),
            None => continue, // Non-UTF-8 names cannot be valid ref names.
        };
        let child_name = if prefix.is_empty() {
            file_name.clone()
        } else {
            format!("{prefix}/{file_name}")
        };
        let ft = entry.file_type()?;
        if ft.is_dir() {
            subdirs.push(child_name);
            continue;
        }
        if !ft.is_file() {
            continue;
        }
        // Grammar only: a ref named before SPEC-REFS §3 bounded names is
        // still listed, so it can be seen, renamed or deleted.
        if !name_grammar_ok(&child_name, usize::MAX) {
            continue;
        }
        out.push(RefCandidate {
            name: child_name,
            path: entry.path(),
        });
    }
    for child_name in subdirs {
        collect_ref_candidates(root, &child_name, out, depth + 1)?;
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// Internal hash helper re-exports for goldens
// -----------------------------------------------------------------------------

/// Internal re-export used by the integration tests to hand-roll wire
/// bytes without round-tripping through `hash::from_hex`.
#[doc(hidden)]
#[must_use]
pub fn _hash_from_lowercase_hex_for_tests(s: &str) -> Option<Hash> {
    parse_lowercase_hash(s.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash;
    use std::sync::Barrier;
    use tempfile::TempDir;

    fn fresh_repo() -> (TempDir, RepoLayout) {
        let dir = TempDir::new().unwrap();
        let layout = RepoLayout::single(dir.path());
        fs::create_dir_all(layout.common_dir()).unwrap();
        init(&layout).unwrap();
        (dir, layout)
    }

    fn h(seed: &str) -> Hash {
        hash::hash(seed.as_bytes())
    }

    // --- previous HEADs --------------------------------------------------

    #[test]
    fn previous_spec_accepts_one_or_two_digits_without_a_leading_zero() {
        assert_eq!(parse_previous_spec("@{-1}"), Some(1));
        assert_eq!(parse_previous_spec("@{-16}"), Some(16));
        assert_eq!(parse_previous_spec("@{-99}"), Some(99));
        for bad in [
            "@{-0}", "@{-01}", "@{-100}", "@{-}", "@{1}", "@{-1", "@{-x}", "@{--1}",
        ] {
            assert_eq!(parse_previous_spec(bad), None, "{bad}");
        }
    }

    #[test]
    fn head_history_is_bounded_and_keeps_the_newest() {
        let (_d, layout) = fresh_repo();
        for i in 0..20 {
            record_previous_head(&layout, &Head::Branch(format!("b{i}"))).unwrap();
        }
        let record = read_head_history(&layout).unwrap();
        assert_eq!(record.len(), HEAD_HISTORY_MAX);
        assert_eq!(record.first(), Some(&Head::Branch("b4".into())));
        assert_eq!(
            nth_previous_head(&layout, 1).unwrap(),
            Some(Head::Branch("b19".into()))
        );
        assert_eq!(
            nth_previous_head(&layout, 16).unwrap(),
            Some(Head::Branch("b4".into()))
        );
        assert_eq!(nth_previous_head(&layout, 17).unwrap(), None);
        assert_eq!(nth_previous_head(&layout, 0).unwrap(), None);
    }

    #[test]
    fn head_history_parser_rules() {
        let line = |b: &str| format!("ref: refs/heads/{b}\n");
        let hex = format!("{}\n", hash::to_hex(&h("x")));
        let two = format!("{}{hex}", line("a"));
        assert_eq!(
            parse_head_history(two.as_bytes()).unwrap(),
            vec![Head::Branch("a".into()), Head::Detached(h("x"))]
        );
        // A torn tail is ignored.
        let torn = format!("{two}ref: refs/he");
        assert_eq!(parse_head_history(torn.as_bytes()).unwrap().len(), 2);
        // Seventeen complete lines, or a bad line, are refused.
        let long: String = (0..17).map(|i| line(&format!("b{i}"))).collect();
        assert!(parse_head_history(long.as_bytes()).is_err());
        assert!(parse_head_history(b"junk\n").is_err());
        assert!(parse_head_history(hex.to_uppercase().as_bytes()).is_err());
        assert_eq!(parse_head_history(b"").unwrap(), Vec::new());
    }

    #[test]
    fn a_missing_record_falls_back_to_previous_head() {
        let (_d, layout) = fresh_repo();
        assert!(read_head_history(&layout).unwrap().is_empty());
        write_previous_head(&layout, &Head::Branch("old".into())).unwrap();
        assert_eq!(
            read_head_history(&layout).unwrap(),
            vec![Head::Branch("old".into())]
        );
        record_previous_head(&layout, &Head::Branch("new".into())).unwrap();
        assert_eq!(
            read_head_history(&layout).unwrap(),
            vec![Head::Branch("old".into()), Head::Branch("new".into())]
        );
        // An older kit moves PREVIOUS_HEAD alone; the record is then stale.
        write_previous_head(&layout, &Head::Branch("other".into())).unwrap();
        assert_eq!(
            read_head_history(&layout).unwrap(),
            vec![Head::Branch("other".into())]
        );
    }

    #[test]
    fn a_malformed_record_is_replaced_on_the_next_switch() {
        let (_d, layout) = fresh_repo();
        write_previous_head(&layout, &Head::Branch("a".into())).unwrap();
        fs::write(layout.worktree_state_dir().join("HEAD_HISTORY"), b"junk\n").unwrap();
        assert!(read_head_history(&layout).is_err());
        record_previous_head(&layout, &Head::Branch("b".into())).unwrap();
        assert_eq!(
            read_head_history(&layout).unwrap(),
            vec![Head::Branch("b".into())]
        );
    }

    // --- name grammar ---------------------------------------------------

    #[test]
    fn validate_accepts_simple_names() {
        assert!(validate_ref_name("main"));
        assert!(validate_ref_name("feat/v1.0-beta"));
        assert!(validate_ref_name("release/2024_09"));
    }

    #[test]
    fn validate_rejects_empty() {
        assert!(!validate_ref_name(""));
    }

    #[test]
    fn validate_rejects_leading_slash() {
        assert!(!validate_ref_name("/main"));
    }

    #[test]
    fn validate_rejects_dotdot_segment() {
        assert!(!validate_ref_name("feat/.."));
        assert!(!validate_ref_name("../escape"));
        assert!(!validate_ref_name("feat/./topic"));
    }

    #[test]
    fn validate_rejects_dot_leading_segment() {
        // git's check-ref-format rule: no slash-separated component may
        // begin with '.'. This also inertifies crash debris parked at a
        // dot-leading directory (e.g. a `.rename.tmp.<pid>.<seq>` orphan)
        // as a ref name, not just the exact `.`/`..` shapes above.
        assert!(!validate_ref_name(".hidden"));
        assert!(!validate_ref_name("refs/.hidden/main"));
        assert!(!validate_ref_name(".rename.tmp.12345.0"));
        assert!(!validate_ref_name("refs/remotes/.rename.tmp.12345.0/main"));
    }

    #[test]
    fn validate_rejects_double_slash() {
        assert!(!validate_ref_name("refs//heads/main"));
        assert!(!validate_ref_name("main/"));
    }

    #[test]
    fn validate_rejects_disallowed_bytes() {
        assert!(!validate_ref_name("main@v1"));
        assert!(!validate_ref_name("feat\\branch"));
        assert!(!validate_ref_name("with space"));
    }

    #[test]
    fn validate_rejects_lock_suffix() {
        assert!(!validate_ref_name("refs/heads/main.lock"));
    }

    #[test]
    fn validate_rejects_head_final_segment() {
        assert!(!validate_ref_name("refs/heads/HEAD"));
        assert!(!validate_ref_name("HEAD"));
    }

    #[test]
    fn validate_accepts_main_regression() {
        assert!(validate_ref_name("refs/heads/main"));
    }

    #[test]
    fn validate_accepts_non_lock_suffix_regression() {
        // Only trailing ".lock" should reject; "lockfile" is fine.
        assert!(validate_ref_name("refs/heads/lockfile"));
    }

    #[test]
    fn validate_accepts_headless_regression() {
        // Only the exact final segment "HEAD" is rejected.
        assert!(validate_ref_name("refs/heads/HEADless"));
    }

    /// A name of `len` bytes in 100-byte segments (each well under a file
    /// name's limit).
    fn long_name(len: usize) -> String {
        let mut name = String::new();
        while name.len() < len {
            if !name.is_empty() {
                name.push('/');
            }
            let seg = (len - name.len()).min(100);
            name.push_str(&"a".repeat(seg));
        }
        assert_eq!(name.len(), len);
        name
    }

    /// SPEC-REFS §3: at most `MAX_REF_NAME_BYTES` bytes; the grammar alone
    /// has no bound.
    #[test]
    fn validate_bounds_name_length() {
        let longest = long_name(MAX_REF_NAME_BYTES);
        let over = long_name(MAX_REF_NAME_BYTES + 1);
        assert!(validate_ref_name(&longest));
        assert!(!validate_ref_name(&over));
        assert!(validate_ref_name_grammar(&over));
        assert!(check_new_ref_name(&longest).is_ok());
        let err = check_new_ref_name(&over).unwrap_err();
        assert!(matches!(err, RefError::RefNameTooLong { len: 513, .. }));
        let shown = err.to_string();
        assert!(
            shown.contains("ref name too long (513 bytes; at most 512"),
            "{shown}"
        );
        assert!(shown.len() < 200, "the name is shortened: {shown}");
        assert!(matches!(
            check_new_ref_name("bad..name/.x"),
            Err(RefError::InvalidRefName(_))
        ));
        assert!(validate_ref_prefix(&format!("{longest}/")));
        assert!(!validate_ref_prefix(&over));
    }

    /// A new branch name must leave `refs/heads/<b>` and
    /// `refs/kit/packmap/<b>` within 512 bytes (495), a new tag
    /// `refs/tags/<t>` and `refs/kit/tagmap/<t>` (496); a branch or tag
    /// created before that bound stays writable locally but cannot be pushed.
    #[test]
    fn branch_and_tag_bounds_derive_from_their_wire_names() {
        assert_eq!(MAX_BRANCH_NAME_BYTES, 495);
        assert_eq!(MAX_TAG_NAME_BYTES, 496);
        let (_dir, layout) = fresh_repo();
        let id = h("c");
        update_ref(&layout, &long_name(495), RefWriteCondition::Missing, &id).unwrap();
        check_pushable_branch(&long_name(495)).unwrap();
        let err =
            update_ref(&layout, &long_name(496), RefWriteCondition::Missing, &id).unwrap_err();
        assert!(matches!(
            err,
            RefError::RefNameTooLong {
                len: 496,
                kind: RefNameKind::Branch,
                ..
            }
        ));
        let shown = err.to_string();
        assert!(
            shown.contains("branch name too long (496 bytes; at most 495")
                && shown.contains("refs/kit/packmap/<name>"),
            "{shown}"
        );
        assert!(matches!(
            write_head_branch(&layout, &long_name(496)),
            Err(RefError::RefNameTooLong { .. })
        ));
        write_tag(&layout, &long_name(496), &id).unwrap();
        check_pushable_tag(&long_name(496)).unwrap();
        let err = write_tag(&layout, &long_name(497), &id).unwrap_err();
        assert!(
            err.to_string()
                .contains("tag name too long (497 bytes; at most 496")
                && err.to_string().contains("refs/kit/tagmap/<name>"),
            "{err}"
        );
        // 29 segments fit `refs/kit/tagmap/<t>`; 30 do not, though the short
        // name alone is within the 32-segment bound.
        let deep = |n: usize| vec!["s"; n].join("/");
        write_tag(&layout, &deep(29), &id).unwrap();
        check_pushable_tag(&deep(29)).unwrap();
        assert!(matches!(
            write_tag(&layout, &deep(30), &id),
            Err(RefError::InvalidRefName(name)) if name == deep(30)
        ));
        assert!(matches!(
            check_pushable_tag(&deep(30)),
            Err(RefError::InvalidRefName(name)) if name == deep(30)
        ));

        // A 500-byte tag made before the bound: readable, writable,
        // deletable, not pushable.
        let old_tag = long_name(500);
        let path = ref_path(layout.common_dir(), TAGS_DIR, &old_tag);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, encode_ref_wire(&id)).unwrap();
        assert_eq!(read_tag(&layout, &old_tag).unwrap(), Some(id));
        write_tag(&layout, &old_tag, &h("next")).unwrap();
        assert!(check_pushable_tag(&old_tag).is_err());
        delete_tag(&layout, &old_tag).unwrap();

        // A 500-byte branch made before the bound: writable, not pushable.
        let old = long_name(500);
        let path = ref_path(layout.common_dir(), HEADS_DIR, &old);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, encode_ref_wire(&id)).unwrap();
        write_ref(&layout, &old, &h("next")).unwrap();
        write_head_branch(&layout, &old).unwrap();
        let err = check_pushable_branch(&old).unwrap_err();
        assert!(
            err.to_string()
                .contains("ref name too long (517 bytes; at most 512")
                && err.to_string().contains("'refs/kit/packmap/"),
            "{err}"
        );
    }

    /// A new branch, tag, remote-tracking ref or HEAD target over the bound
    /// is refused, naming the limit.
    #[test]
    fn new_refs_over_the_bound_are_refused() {
        let (_dir, layout) = fresh_repo();
        let over = long_name(MAX_REF_NAME_BYTES + 1);
        let id = h("c");
        let too_long = |r: RefResult<()>| matches!(r, Err(RefError::RefNameTooLong { .. }));
        assert!(too_long(update_ref(
            &layout,
            &over,
            RefWriteCondition::Missing,
            &id
        )));
        assert!(too_long(write_ref(&layout, &over, &id)));
        assert!(too_long(write_tag(&layout, &over, &id)));
        assert!(too_long(write_remote_ref(&layout, "origin", &over, &id)));
        assert!(too_long(write_head_branch(&layout, &over)));
        let mut batch = RemoteRefBatch::new(&layout, "origin").unwrap();
        assert!(too_long(batch.write(&over, &id)));
        assert!(!layout.heads_dir().join("a".repeat(100)).exists());
    }

    /// A branch file named over the bound, written before SPEC-REFS §3
    /// bounded names, keeps the repository working: it is listed, read,
    /// resolved through HEAD and deletable; only writes to it are refused.
    #[test]
    fn existing_ref_over_the_bound_stays_usable_and_deletable() {
        let (_dir, layout) = fresh_repo();
        let over = long_name(MAX_REF_NAME_BYTES + 1);
        let id = h("over-bound");
        let path = ref_path(layout.common_dir(), HEADS_DIR, &over);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, encode_ref_wire(&id)).unwrap();
        write_ref(&layout, "main", &h("main")).unwrap();

        let listed: Vec<_> = list_refs(&layout)
            .unwrap()
            .into_iter()
            .map(|r| r.name)
            .collect();
        assert!(listed.contains(&over) && listed.contains(&"main".to_owned()));
        assert_eq!(read_ref(&layout, &over).unwrap(), Some(id));
        fs::write(layout.head_file(), format!("{HEAD_REF_PREFIX}{over}\n")).unwrap();
        assert_eq!(read_head(&layout).unwrap(), Head::Branch(over.clone()));
        assert_eq!(resolve_head(&layout).unwrap(), Some(id));
        assert!(matches!(
            update_head(&layout, &h("next")),
            Err(RefError::RefNameTooLong { .. })
        ));
        assert_eq!(read_ref(&layout, &over).unwrap(), Some(id), "unchanged");

        // The way out: switch away, then delete it (or rename it).
        write_head_branch(&layout, "main").unwrap();
        delete_ref_if_matches(&layout, &over, id).unwrap();
        assert_eq!(read_ref(&layout, &over).unwrap(), None);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, encode_ref_wire(&id)).unwrap();
        delete_ref_safe(&layout, &over).unwrap();
        assert!(!path.exists());

        // Tags and remote-tracking refs the same way.
        let tag = ref_path(layout.common_dir(), TAGS_DIR, &over);
        fs::create_dir_all(tag.parent().unwrap()).unwrap();
        fs::write(&tag, encode_ref_wire(&id)).unwrap();
        assert!(list_tags(&layout).unwrap().iter().any(|r| r.name == over));
        assert_eq!(read_tag(&layout, &over).unwrap(), Some(id));
        delete_tag(&layout, &over).unwrap();
        let remote = ref_path(layout.common_dir(), &remote_ref_dir("origin"), &over);
        fs::create_dir_all(remote.parent().unwrap()).unwrap();
        fs::write(&remote, encode_ref_wire(&id)).unwrap();
        assert!(
            list_remote_refs(&layout, "origin")
                .unwrap()
                .iter()
                .any(|r| r.name == over)
        );
        assert_eq!(read_remote_ref(&layout, "origin", &over).unwrap(), Some(id));
        delete_remote_ref(&layout, "origin", &over).unwrap();
    }

    #[test]
    fn validate_prefix() {
        assert!(validate_ref_prefix(""));
        assert!(validate_ref_prefix("refs/heads/"));
        assert!(validate_ref_prefix("refs/heads"));
        assert!(!validate_ref_prefix("refs//heads/"));
        assert!(!validate_ref_prefix("/"));
    }

    // --- wire encoding --------------------------------------------------

    #[test]
    fn wire_round_trip() {
        let original = h("test-ref");
        let wire = encode_ref_wire(&original);
        assert_eq!(wire.len(), 65);
        assert_eq!(wire[64], b'\n');
        let parsed = decode_ref_wire(&wire).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn wire_rejects_uppercase() {
        let original = h("test-ref");
        let mut wire = encode_ref_wire(&original);
        // Upper-case the first letter we find; SPEC-REFS §1 forbids
        // uppercase hex on read.
        let mut flipped = false;
        for b in &mut wire[..HEX_LEN] {
            if (b'a'..=b'f').contains(b) {
                *b -= b'a' - b'A';
                flipped = true;
                break;
            }
        }
        assert!(flipped, "test fixture should contain at least one a-f");
        assert!(decode_ref_wire(&wire).is_none());
    }

    #[test]
    fn wire_rejects_short_input() {
        let bad = b"deadbeef\n";
        assert!(decode_ref_wire(bad).is_none());
    }

    #[test]
    fn wire_rejects_non_hex() {
        let mut wire = encode_ref_wire(&h("x"));
        wire[1] = b'g';
        assert!(decode_ref_wire(&wire).is_none());
    }

    #[test]
    fn wire_tolerates_trailing_cr() {
        // Files round-tripped through Windows editors may pick up CRs.
        let original = h("eol");
        let mut buf = encode_ref_wire(&original).to_vec();
        buf.insert(64, b'\r');
        let parsed = decode_ref_wire(&buf).unwrap();
        assert_eq!(parsed, original);
    }

    // --- HEAD ----------------------------------------------------------

    #[test]
    fn init_writes_default_head() {
        let (_dir, kit) = fresh_repo();
        let head = read_head(&kit).unwrap();
        assert_eq!(head, Head::Branch("main".to_string()));
    }

    #[test]
    fn write_and_read_branch_ref() {
        let (_dir, kit) = fresh_repo();
        let commit = h("commit1");
        write_ref(&kit, "main", &commit).unwrap();
        let read = read_ref(&kit, "main").unwrap();
        assert_eq!(read, Some(commit));
    }

    #[test]
    fn resolve_head_with_no_commits_returns_none() {
        let (_dir, kit) = fresh_repo();
        assert_eq!(resolve_head(&kit).unwrap(), None);
    }

    #[test]
    fn resolve_head_after_commit() {
        let (_dir, kit) = fresh_repo();
        let commit = h("commit1");
        write_ref(&kit, "main", &commit).unwrap();
        assert_eq!(resolve_head(&kit).unwrap(), Some(commit));
    }

    #[test]
    fn update_head_updates_current_branch() {
        let (_dir, kit) = fresh_repo();
        let h1 = h("c1");
        update_head(&kit, &h1).unwrap();
        assert_eq!(resolve_head(&kit).unwrap(), Some(h1));
        let h2 = h("c2");
        update_head(&kit, &h2).unwrap();
        assert_eq!(resolve_head(&kit).unwrap(), Some(h2));
    }

    #[test]
    fn detached_head_round_trip() {
        let dir = TempDir::new().unwrap();
        let kit = RepoLayout::single(dir.path());
        fs::create_dir_all(kit.common_dir()).unwrap();
        let commit = h("detached");
        write_head_detached(&kit, &commit).unwrap();
        match read_head(&kit).unwrap() {
            Head::Detached(got) => assert_eq!(got, commit),
            other @ Head::Branch(_) => panic!("expected detached, got {other:?}"),
        }
        assert_eq!(resolve_head(&kit).unwrap(), Some(commit));
    }

    #[test]
    fn read_head_rejects_oversize_file() {
        // SPEC-REFS §6: HEAD content is capped at 4 KiB.
        let dir = TempDir::new().unwrap();
        let kit = RepoLayout::single(dir.path());
        fs::create_dir_all(kit.common_dir()).unwrap();
        fs::write(
            kit.head_file(),
            vec![b'a'; usize::try_from(HEAD_MAX_BYTES).unwrap() + 1],
        )
        .unwrap();
        let err = read_head(&kit).unwrap_err();
        assert!(matches!(err, RefError::InvalidHead));
    }

    #[test]
    fn nonexistent_branch_returns_none() {
        let (_dir, kit) = fresh_repo();
        assert_eq!(read_ref(&kit, "nonexistent").unwrap(), None);
    }

    #[test]
    fn read_ref_rejects_oversize_file() {
        // SPEC-REFS §6: a single ref file is capped at 128 bytes.
        let (_dir, kit) = fresh_repo();
        let path = ref_path(kit.common_dir(), HEADS_DIR, "main");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(
            &path,
            vec![b'0'; usize::try_from(REF_FILE_MAX_BYTES).unwrap() + 1],
        )
        .unwrap();
        let err = read_ref(&kit, "main").unwrap_err();
        assert!(matches!(err, RefError::InvalidRef(_)));
    }

    #[test]
    fn list_refs_empty() {
        let (_dir, kit) = fresh_repo();
        let refs = list_refs(&kit).unwrap();
        assert!(refs.is_empty());
    }

    #[test]
    fn list_refs_sorted() {
        let (_dir, kit) = fresh_repo();
        write_ref(&kit, "main", &h("m")).unwrap();
        write_ref(&kit, "dev", &h("d")).unwrap();
        let refs = list_refs(&kit).unwrap();
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0].name, "dev");
        assert_eq!(refs[1].name, "main");
    }

    #[test]
    fn nested_refs_listed_recursively() {
        let (_dir, kit) = fresh_repo();
        write_ref(&kit, "feature/deep/topic", &h("nested")).unwrap();
        let refs = list_refs(&kit).unwrap();
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].name, "feature/deep/topic");
    }

    #[test]
    fn list_refs_skips_directories_nested_beyond_the_walk_depth() {
        // SPEC-REFS §6: listing recurses with a hard depth cap to defeat
        // adversarial nesting; anything deeper is silently skipped (not an
        // error, not a stack overflow). A directory tree that bypassed the
        // writer is the only way to build one.
        let (dir, kit) = fresh_repo();
        write_ref(&kit, "main", &h("shallow")).unwrap();
        let mut deep = kit.common_dir().join(HEADS_DIR);
        for _ in 0..MAX_REF_WALK_DEPTH + 5 {
            deep.push("d");
        }
        let cleanup = crate::test_support::DeepRefCleanup::new(
            deep.join("leaf"),
            kit.common_dir().join(HEADS_DIR),
        );
        fs::create_dir_all(&deep).unwrap();
        fs::write(deep.join("leaf"), encode_ref_wire(&h("deep"))).unwrap();

        let refs = list_refs(&kit).unwrap();
        let names: Vec<&str> = refs.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"main"), "shallow ref must still be listed");
        assert_eq!(names.len(), 1, "deep entry must be skipped: {names:?}");
        drop(cleanup);
        dir.close().unwrap();
    }

    /// A local ref stored before names had a segment bound stays listed,
    /// readable, writable and deletable, however deep it nests, up to
    /// the longest name the length bound allows. Only a new name is
    /// held to the segment bound.
    #[test]
    fn legacy_deep_ref_stays_visible_and_deletable() {
        let (_dir, kit) = fresh_repo();
        let name = vec!["a"; 3 * MAX_REF_SEGMENTS].join("/");
        assert!(name.len() <= MAX_REF_NAME_BYTES);
        assert!(!validate_ref_name(&name), "a new or remote name is refused");
        let path = ref_path(kit.common_dir(), HEADS_DIR, &name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, encode_ref_wire(&h("old"))).unwrap();

        let refs = list_refs(&kit).unwrap();
        assert_eq!(refs.len(), 1, "listed: {refs:?}");
        assert_eq!(refs[0].name, name);
        assert_eq!(read_ref(&kit, &name).unwrap(), Some(h("old")));
        write_ref(&kit, &name, &h("new")).unwrap();
        assert_eq!(read_ref(&kit, &name).unwrap(), Some(h("new")));
        delete_ref(&kit, &name).unwrap();
        assert_eq!(read_ref(&kit, &name).unwrap(), None);

        let other = vec!["b"; 3 * MAX_REF_SEGMENTS].join("/");
        assert!(write_ref(&kit, &other, &h("fresh")).is_err());
    }

    #[test]
    fn legacy_deep_branch_can_stay_checked_out() {
        let (_dir, kit) = fresh_repo();
        let name = vec!["a"; 2 * MAX_REF_SEGMENTS].join("/");
        fs::write(kit.head_file(), format!("ref: refs/heads/{name}\n")).unwrap();
        assert!(matches!(read_head(&kit).unwrap(), Head::Branch(b) if b == name));
    }

    /// SPEC-REFS §3: a name has at most `MAX_REF_SEGMENTS` segments, so
    /// every accepted name is within reach of the listing walker.
    #[test]
    fn validate_bounds_segment_count() {
        let at = vec!["a"; MAX_REF_SEGMENTS].join("/");
        let over = vec!["a"; MAX_REF_SEGMENTS + 1].join("/");
        assert!(validate_ref_name(&at));
        assert!(!validate_ref_name(&over));
        assert!(!validate_ref_name_grammar(&over));
        assert!(matches!(
            check_new_ref_name(&over),
            Err(RefError::InvalidRefName(_))
        ));
        let (_dir, kit) = fresh_repo();
        assert!(write_ref(&kit, &over, &h("deep")).is_err());
        write_ref(&kit, &at, &h("edge")).unwrap();
        let refs = list_refs(&kit).unwrap();
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].name, at);
    }

    /// A `read_batch` that behaves exactly like the sequential default
    /// (the same read-and-decode each candidate gets in `list_refs`) must
    /// produce byte-for-byte the same listing — this is `list_refs_with`'s
    /// core contract: the caller's batching/parallelism strategy is not
    /// supposed to be observable in the result, only in how it's computed.
    #[test]
    fn list_refs_with_sequential_batch_matches_list_refs() {
        let (_dir, kit) = fresh_repo();
        write_ref(&kit, "main", &h("m")).unwrap();
        write_ref(&kit, "dev", &h("d")).unwrap();
        write_ref(&kit, "feature/deep/topic", &h("nested")).unwrap();

        let via_list_refs = list_refs(&kit).unwrap();
        let via_with = list_refs_with(&kit, sequential_read_batch).unwrap();
        assert_eq!(via_list_refs, via_with);
    }

    /// `list_refs_with`'s two outcome kinds must be handled distinctly:
    /// `Unreadable` drops the candidate from the listing entirely (as the
    /// old inline `fs::read` failure did), while `Decoded(None)` keeps it
    /// with `Ref::hash == None` (malformed-but-readable content) — the two
    /// are not interchangeable, so a `read_batch` that collapsed one into
    /// the other would be a real, if narrow, behavior change from the
    /// sequential path it replaced.
    #[test]
    fn list_refs_with_distinguishes_unreadable_from_malformed() {
        let (_dir, kit) = fresh_repo();
        write_ref(&kit, "ok", &h("ok")).unwrap();
        write_ref(&kit, "will-be-dropped", &h("d")).unwrap();
        write_ref(&kit, "will-be-malformed", &h("m")).unwrap();

        let refs = list_refs_with(&kit, |candidates| {
            candidates
                .iter()
                .map(|c| {
                    if c.name == "will-be-dropped" {
                        RefReadOutcome::Unreadable
                    } else if c.name == "will-be-malformed" {
                        RefReadOutcome::Decoded(None)
                    } else {
                        sequential_read_batch(std::slice::from_ref(c))
                            .into_iter()
                            .next()
                            .unwrap()
                    }
                })
                .collect()
        })
        .unwrap();

        let names: Vec<&str> = refs.iter().map(|r| r.name.as_str()).collect();
        assert!(
            !names.contains(&"will-be-dropped"),
            "Unreadable must drop the entry entirely, got {names:?}"
        );
        let malformed = refs
            .iter()
            .find(|r| r.name == "will-be-malformed")
            .expect("Decoded(None) must still be listed");
        assert_eq!(malformed.hash, None);
        let ok = refs.iter().find(|r| r.name == "ok").unwrap();
        assert_eq!(ok.hash, Some(h("ok")));
    }

    /// A `read_batch` that violates the "exactly one outcome per
    /// candidate" contract must fail closed with
    /// [`RefError::RefBatchLengthMismatch`], not silently zip a short or
    /// long outcome list against the wrong candidates.
    #[test]
    fn list_refs_with_rejects_mismatched_batch_length() {
        let (_dir, kit) = fresh_repo();
        write_ref(&kit, "main", &h("m")).unwrap();
        write_ref(&kit, "dev", &h("d")).unwrap();

        let err =
            list_refs_with(&kit, |_candidates| vec![RefReadOutcome::Decoded(None)]).unwrap_err();
        assert!(matches!(
            err,
            RefError::RefBatchLengthMismatch {
                expected: 2,
                actual: 1
            }
        ));
    }

    #[test]
    fn delete_ref_basic() {
        let (_dir, kit) = fresh_repo();
        write_ref(&kit, "feature", &h("f")).unwrap();
        delete_ref(&kit, "feature").unwrap();
        assert_eq!(read_ref(&kit, "feature").unwrap(), None);
    }

    #[test]
    fn delete_nonexistent_ref_errors() {
        let (_dir, kit) = fresh_repo();
        let err = delete_ref(&kit, "nope").unwrap_err();
        assert!(matches!(err, RefError::NotFound(_)));
    }

    #[test]
    fn refuse_delete_current_branch() {
        let (_dir, kit) = fresh_repo();
        write_ref(&kit, "main", &h("m")).unwrap();
        let err = delete_ref_safe(&kit, "main").unwrap_err();
        assert!(matches!(err, RefError::CurrentBranch(_)));
    }

    // --- CAS variants ---------------------------------------------------

    #[test]
    fn cas_any_clobbers() {
        let (_dir, kit) = fresh_repo();
        update_ref(&kit, "main", RefWriteCondition::Any, &h("a")).unwrap();
        update_ref(&kit, "main", RefWriteCondition::Any, &h("b")).unwrap();
        assert_eq!(read_ref(&kit, "main").unwrap(), Some(h("b")));
    }

    #[test]
    fn cas_missing_succeeds_when_absent() {
        let (_dir, kit) = fresh_repo();
        update_ref(&kit, "main", RefWriteCondition::Missing, &h("a")).unwrap();
        assert_eq!(read_ref(&kit, "main").unwrap(), Some(h("a")));
    }

    #[test]
    fn cas_missing_fails_when_present() {
        let (_dir, kit) = fresh_repo();
        write_ref(&kit, "main", &h("a")).unwrap();
        let err = update_ref(&kit, "main", RefWriteCondition::Missing, &h("b")).unwrap_err();
        assert!(matches!(err, RefError::Conflict(_)));
    }

    #[test]
    fn cas_match_succeeds_on_correct_hash() {
        let (_dir, kit) = fresh_repo();
        write_ref(&kit, "main", &h("a")).unwrap();
        update_ref(&kit, "main", RefWriteCondition::Match(h("a")), &h("b")).unwrap();
        assert_eq!(read_ref(&kit, "main").unwrap(), Some(h("b")));
    }

    #[test]
    fn cas_match_fails_on_wrong_hash() {
        let (_dir, kit) = fresh_repo();
        write_ref(&kit, "main", &h("a")).unwrap();
        let err = update_ref(&kit, "main", RefWriteCondition::Match(h("z")), &h("b")).unwrap_err();
        assert!(matches!(err, RefError::Conflict(_)));
    }

    #[test]
    fn cas_match_fails_on_missing_ref() {
        let (_dir, kit) = fresh_repo();
        let err = update_ref(&kit, "main", RefWriteCondition::Match(h("a")), &h("b")).unwrap_err();
        assert!(matches!(err, RefError::Conflict(_)));
    }

    // --- INV-15: Match CAS must be atomic across uncoordinated
    // callers -------------------------------------------------------------

    /// Reproduces the lost-update race described in INV-15: two callers
    /// that do NOT share any lock (mimicking `branch -m` under
    /// `worktrees.lock` racing `commit` under `worktree.lock`, or two
    /// linked worktrees each holding their own `worktree.lock`) both
    /// read the ref's current value, both see it matches their
    /// expectation, and both `cas_write`. Without cross-process
    /// atomicity on the read-compare-write, both calls can report
    /// success even though only one write actually survives — silently
    /// losing the other caller's update.
    ///
    /// `layout_a`/`layout_b` are two distinct [`RepoLayout`]s (a
    /// "single" layout and a "linked" layout with a different
    /// `worktree_root`/`worktree_state_dir`) that share only
    /// `common_dir` — exactly the shape of two linked worktrees, each
    /// of which would hold its own separate `worktree.lock` and thus
    /// share no lock with the other over this CAS. A `Barrier` forces
    /// both threads to enter `update_ref` at (as close to) the same
    /// instant as the scheduler allows, and the loop repeats many
    /// iterations because the race window is a handful of syscalls wide
    /// and is not guaranteed to be hit on any single attempt.
    ///
    /// Before the fix (no lock around the `Match` arm) this
    /// reliably reproduces a "both succeeded" iteration within a few
    /// hundred attempts. After the fix, the per-ref
    /// `refs-<digest>.lock` both callers share makes the
    /// read-compare-write atomic across both callers, so this must
    /// never happen — exactly one of the two racing writers may
    /// succeed.
    #[test]
    fn cas_match_race_never_loses_an_update_across_uncoordinated_callers() {
        let (_dir, layout_a) = fresh_repo();
        let layout_b = RepoLayout::linked(
            layout_a.worktree_root().join("other-worktree"),
            layout_a.common_dir().join("worktrees").join("other"),
            layout_a.common_dir(),
        );

        let base = h("base");
        write_ref(&layout_a, "main", &base).unwrap();

        let iterations: usize = 500;
        let mut double_success_iteration = None;

        for i in 0..iterations {
            // Reset to a known base before each round. `Any` bypasses
            // CAS entirely, so this is not itself part of what's under
            // test.
            update_ref(&layout_a, "main", RefWriteCondition::Any, &base).unwrap();

            let val_a = h(&format!("race-a-{i}"));
            let val_b = h(&format!("race-b-{i}"));
            let barrier = Barrier::new(2);

            let (result_a, result_b) = std::thread::scope(|scope| {
                let handle_a = scope.spawn(|| {
                    barrier.wait();
                    update_ref(&layout_a, "main", RefWriteCondition::Match(base), &val_a)
                });
                let handle_b = scope.spawn(|| {
                    barrier.wait();
                    update_ref(&layout_b, "main", RefWriteCondition::Match(base), &val_b)
                });
                (handle_a.join().unwrap(), handle_b.join().unwrap())
            });

            if result_a.is_ok() && result_b.is_ok() {
                double_success_iteration = Some(i);
                break;
            }
        }

        assert!(
            double_success_iteration.is_none(),
            "both uncoordinated Match CAS callers reported success on iteration \
             {double_success_iteration:?} — an update was silently lost \
             (INV-15/INV-6 violation)"
        );
    }

    #[test]
    fn valid_long_ref_names_support_every_mutation() {
        let (_dir, layout) = fresh_repo();
        for name in [
            "_".repeat(80),
            format!("{}/{}", "a".repeat(130), "b".repeat(130)),
        ] {
            assert!(validate_ref_name(&name));
            update_ref(&layout, &name, RefWriteCondition::Missing, &h("base")).unwrap();
            assert!(matches!(
                update_ref(&layout, &name, RefWriteCondition::Missing, &h("other")),
                Err(RefError::Conflict(_))
            ));
            update_ref(
                &layout,
                &name,
                RefWriteCondition::Match(h("base")),
                &h("next"),
            )
            .unwrap();
            assert!(matches!(
                delete_ref_if_matches(&layout, &name, h("base")),
                Err(RefError::Conflict(_))
            ));
            assert_eq!(read_ref(&layout, &name).unwrap(), Some(h("next")));
            delete_ref_if_matches(&layout, &name, h("next")).unwrap();
            write_ref(&layout, &name, &h("base")).unwrap();
            delete_ref(&layout, &name).unwrap();

            update_tag(&layout, &name, RefWriteCondition::Missing, &h("base")).unwrap();
            update_tag(
                &layout,
                &name,
                RefWriteCondition::Match(h("base")),
                &h("next"),
            )
            .unwrap();
            write_tag(&layout, &name, &h("base")).unwrap();
            delete_tag(&layout, &name).unwrap();

            write_remote_ref(&layout, "default", &name, &h("base")).unwrap();
            let mut batch = RemoteRefBatch::new(&layout, "default").unwrap();
            batch.write(&name, &h("next")).unwrap();
            batch.commit().unwrap();
            assert_eq!(
                read_remote_ref(&layout, "default", &name).unwrap(),
                Some(h("next"))
            );
            delete_remote_ref(&layout, "default", &name).unwrap();

            #[cfg(feature = "history-mmr")]
            let _guards = acquire_history_mutation(&layout, &name).unwrap();
        }
    }

    #[test]
    fn ref_lock_keys_preserve_full_identity_without_filename_overflow() {
        let (_dir, layout) = fresh_repo();
        let names = ["_".repeat(80), "_".repeat(79), "a/b".into(), "a_2fb".into()];
        let mut keys = BTreeSet::new();
        for namespace in [HEADS_DIR, TAGS_DIR, "refs/remotes/default"] {
            for name in &names {
                let path = ref_path(layout.common_dir(), namespace, name);
                let key = cas_lock_name(layout.common_dir(), &path);
                assert!(key.len() <= 255);
                assert_eq!(key, cas_lock_name(layout.common_dir(), &path));
                assert!(
                    keys.insert(key),
                    "different full refs must have different keys"
                );
            }
        }
        #[cfg(feature = "history-mmr")]
        for name in &names {
            let key = history_lock_name(name);
            assert!(key.len() <= 255);
            assert!(
                keys.insert(key),
                "history and mutation guards must be distinct"
            );
        }
    }

    #[test]
    fn two_spellings_of_one_ref_share_one_lock_key() {
        let (_dir, layout) = fresh_repo();
        for namespace in [HEADS_DIR, TAGS_DIR, "refs/remotes/default"] {
            let lower = ref_path(layout.common_dir(), namespace, "release/v1");
            let mixed = ref_path(layout.common_dir(), namespace, "Release/V1");
            assert_eq!(
                cas_lock_name(layout.common_dir(), &lower),
                cas_lock_name(layout.common_dir(), &mixed)
            );
        }
        let branch = ref_path(layout.common_dir(), HEADS_DIR, "v1");
        let tag = ref_path(layout.common_dir(), TAGS_DIR, "v1");
        assert_ne!(
            cas_lock_name(layout.common_dir(), &branch),
            cas_lock_name(layout.common_dir(), &tag),
            "a branch and a tag keep distinct locks"
        );
        #[cfg(feature = "history-mmr")]
        assert_eq!(history_lock_name("Main"), history_lock_name("main"));
    }

    #[test]
    fn a_write_waits_for_the_lock_held_under_another_spelling_of_the_branch() {
        use std::sync::mpsc;
        use std::time::Duration;
        let (_dir, layout) = fresh_repo();
        update_ref(&layout, "main", RefWriteCondition::Any, &h("base")).unwrap();
        let held = crate::repo_lock::acquire_default(
            layout.common_dir(),
            &cas_lock_name(
                layout.common_dir(),
                &ref_path(layout.common_dir(), HEADS_DIR, "main"),
            ),
        )
        .unwrap();
        let (done_tx, done_rx) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let result = update_ref(&layout, "Main", RefWriteCondition::Any, &h("next"));
            done_tx.send(result).unwrap();
        });
        let premature = done_rx.recv_timeout(Duration::from_millis(200));
        drop(held);
        worker.join().unwrap();
        assert!(
            matches!(premature, Err(mpsc::RecvTimeoutError::Timeout)),
            "a write under `Main` ran while `main` was locked: {premature:?}"
        );
    }

    /// All mutations must join the CAS critical section, including calls
    /// from a linked tree with its own unrelated worktree lock.
    #[test]
    fn every_ref_mutation_waits_for_the_cas_guard() {
        use std::sync::mpsc;
        use std::time::Duration;
        for operation in 0..10 {
            let (_dir, layout) = fresh_repo();
            let branch = "mutation-guard";
            let sub_dir = match operation {
                5 | 6 => TAGS_DIR.to_string(),
                7..=9 => remote_ref_dir("default"),
                _ => HEADS_DIR.to_string(),
            };
            let path = ref_path(layout.common_dir(), &sub_dir, branch);
            cas_write(
                layout.common_dir(),
                &path,
                &encode_ref_wire(&h("base")),
                branch,
                RefWriteCondition::Any,
            )
            .unwrap();
            let lock = crate::repo_lock::acquire_default(
                layout.common_dir(),
                &cas_lock_name(layout.common_dir(), &path),
            )
            .unwrap();
            let linked = RepoLayout::linked(
                layout.worktree_root().join("linked"),
                layout.common_dir().join("worktrees/linked"),
                layout.common_dir(),
            );
            let (done_tx, done_rx) = mpsc::channel();
            let worker = std::thread::spawn(move || {
                let result = match operation {
                    0 => update_ref(&linked, branch, RefWriteCondition::Any, &h("next")),
                    1 => update_ref(&linked, branch, RefWriteCondition::Missing, &h("next")),
                    2 => delete_ref(&linked, branch),
                    3 => delete_ref_if_matches(&linked, branch, h("base")),
                    4 => update_ref(
                        &linked,
                        branch,
                        RefWriteCondition::Match(h("base")),
                        &h("next"),
                    ),
                    5 => write_tag(&linked, branch, &h("next")),
                    6 => delete_tag(&linked, branch),
                    7 => write_remote_ref(&linked, "default", branch, &h("next")),
                    8 => delete_remote_ref(&linked, "default", branch),
                    _ => {
                        let mut batch = RemoteRefBatch::new(&linked, "default").unwrap();
                        batch
                            .write(branch, &h("next"))
                            .and_then(|()| batch.commit())
                    }
                };
                done_tx.send(result).unwrap();
            });
            let premature = done_rx.recv_timeout(Duration::from_millis(100));
            let observed = fs::read(&path).ok().and_then(|b| decode_ref_wire(&b));
            drop(lock);
            worker.join().unwrap();
            assert!(
                matches!(premature, Err(mpsc::RecvTimeoutError::Timeout)),
                "operation {operation} bypassed the held CAS guard: {premature:?}"
            );
            assert_eq!(
                observed,
                Some(h("base")),
                "mutation must not precede guard acquisition"
            );
            let result = done_rx.recv_timeout(Duration::from_secs(2)).unwrap();
            assert_eq!(result.is_ok(), operation != 1);
        }
    }

    #[test]
    fn remote_batches_with_reversed_ref_order_finish_without_nested_ref_locks() {
        let (_dir, layout) = fresh_repo();
        let barrier = Barrier::new(2);
        std::thread::scope(|scope| {
            let a = scope.spawn(|| {
                barrier.wait();
                let mut batch = RemoteRefBatch::new(&layout, "default").unwrap();
                for branch in ["z", "a"] {
                    batch.write(branch, &h("a")).unwrap();
                }
                batch.commit().unwrap();
            });
            let b = scope.spawn(|| {
                barrier.wait();
                let mut batch = RemoteRefBatch::new(&layout, "default").unwrap();
                for branch in ["a", "z"] {
                    batch.write(branch, &h("b")).unwrap();
                }
                batch.commit().unwrap();
            });
            a.join().unwrap();
            b.join().unwrap();
        });
        for branch in ["a", "z"] {
            let value = read_remote_ref(&layout, "default", branch)
                .unwrap()
                .unwrap();
            assert!(value == h("a") || value == h("b"));
        }
    }

    /// Normal-case companion to the race test above: with no
    /// contention, a sequence of `Match` CAS writes on the same ref must
    /// still succeed every time and never wedge (guards against the
    /// per-ref `refs-<digest>.lock` acquire/release, added for,
    /// leaking or deadlocking across repeated calls from the same
    /// layout).
    #[test]
    fn cas_match_succeeds_repeatedly_when_uncontended() {
        let (_dir, kit) = fresh_repo();
        let mut current = h("seed");
        write_ref(&kit, "main", &current).unwrap();

        for i in 0..20 {
            let next = h(&format!("v{i}"));
            update_ref(&kit, "main", RefWriteCondition::Match(current), &next).unwrap();
            assert_eq!(read_ref(&kit, "main").unwrap(), Some(next));
            current = next;
        }
    }

    // --- INV-15: CAS-guarded delete must not lose a concurrent
    // Match-conditioned advance ---------------------------------------

    /// Primitive-level reproduction of "Race 1": a caller (e.g.
    /// `branch -m`) reads a branch's tip `T`, then — before it gets
    /// around to deleting the ref — a concurrent `Match(T)` CAS (e.g.
    /// `commit`'s fixed advance) lands, moving the ref to `C`. The
    /// caller's delete must detect that the ref no longer matches what
    /// it read and refuse, leaving `C` on disk untouched.
    ///
    /// Confirmed against the pre-fix shape of this codebase: pointing
    /// this same sequence at plain, unconditional [`delete_ref`] instead
    /// of [`delete_ref_if_matches`] removes the ref regardless of `T` vs
    /// `C`, silently destroying the concurrently-landed `C` — exactly
    /// the bug. [`delete_ref_if_matches`] must refuse
    /// instead.
    #[test]
    fn cas_delete_refuses_when_ref_moved_after_read() {
        let (_dir, kit) = fresh_repo();
        let t = h("t");
        let c = h("c");
        write_ref(&kit, "main", &t).unwrap();

        // Caller reads the tip...
        let read_t = read_ref(&kit, "main").unwrap().unwrap();
        assert_eq!(read_t, t);

        // ...then a concurrent Match(T) CAS (a fixed `commit`) lands
        // before the caller's delete runs.
        update_ref(&kit, "main", RefWriteCondition::Match(t), &c).unwrap();

        let err = delete_ref_if_matches(&kit, "main", read_t).unwrap_err();
        assert!(
            matches!(err, RefError::Conflict(_)),
            "expected Conflict, got {err:?}"
        );
        assert_eq!(
            read_ref(&kit, "main").unwrap(),
            Some(c),
            "the concurrently-landed commit must survive the refused delete untouched"
        );
    }

    /// `delete_ref_if_matches` refusing to delete must not remove the
    /// file at all — a second, correctly-conditioned delete against the
    /// NEW value must still succeed.
    #[test]
    fn cas_delete_refusal_leaves_ref_deletable_against_its_new_value() {
        let (_dir, kit) = fresh_repo();
        let t = h("t");
        let c = h("c");
        write_ref(&kit, "main", &t).unwrap();
        update_ref(&kit, "main", RefWriteCondition::Match(t), &c).unwrap();

        assert!(matches!(
            delete_ref_if_matches(&kit, "main", t).unwrap_err(),
            RefError::Conflict(_)
        ));
        delete_ref_if_matches(&kit, "main", c).unwrap();
        assert_eq!(read_ref(&kit, "main").unwrap(), None);
    }

    #[test]
    fn cas_delete_fails_on_missing_ref() {
        let (_dir, kit) = fresh_repo();
        let err = delete_ref_if_matches(&kit, "main", h("anything")).unwrap_err();
        assert!(matches!(err, RefError::Conflict(_)));
    }

    /// Racing-loop version of the reproduction above, mirroring
    /// [`cas_match_race_never_loses_an_update_across_uncoordinated_callers`]'s
    /// pattern: on each iteration, one thread performs a `Match`-guarded
    /// advance (mirroring a fixed `commit`) and the other performs a
    /// `delete_ref_if_matches` against the pre-advance value (mirroring
    /// `branch -m`'s rename), both released by the same `Barrier` so the
    /// scheduler is given its best shot at interleaving them. Because
    /// both operations serialize under the same per-ref lock
    /// ([`cas_lock_name`]), exactly one of the two may ever report
    /// success against a given prior value — never both, and the loser
    /// must never observe (or cause) a torn/lost state.
    #[test]
    fn cas_delete_vs_match_advance_race_never_lets_both_win_or_loses_the_advance() {
        let (_dir, kit) = fresh_repo();
        let iterations: usize = 500;
        let mut bad_iteration: Option<(usize, &'static str)> = None;

        for i in 0..iterations {
            let base = h(&format!("base-{i}"));
            write_ref(&kit, "main", &base).unwrap();
            let new_tip = h(&format!("advanced-{i}"));
            let barrier = Barrier::new(2);

            let (advance_result, delete_result) = std::thread::scope(|scope| {
                let advance_handle = scope.spawn(|| {
                    barrier.wait();
                    update_ref(&kit, "main", RefWriteCondition::Match(base), &new_tip)
                });
                let delete_handle = scope.spawn(|| {
                    barrier.wait();
                    delete_ref_if_matches(&kit, "main", base)
                });
                (
                    advance_handle.join().unwrap(),
                    delete_handle.join().unwrap(),
                )
            });

            match (&advance_result, &delete_result) {
                (Ok(()), Ok(())) => {
                    bad_iteration = Some((
                        i,
                        "both the concurrent advance and the concurrent delete reported success",
                    ));
                }
                (Ok(()), Err(RefError::Conflict(_))) => {
                    // The advance won the race; its value must survive.
                    if read_ref(&kit, "main").unwrap() != Some(new_tip) {
                        bad_iteration = Some((
                            i,
                            "advance reported success but its value is not on disk — lost update",
                        ));
                    }
                }
                (Err(RefError::Conflict(_)), Ok(())) => {
                    // The delete won the race before the advance landed;
                    // the ref must be gone (the advance must have then
                    // failed its own CAS, which the match arm above
                    // already confirms).
                    if read_ref(&kit, "main").unwrap().is_some() {
                        bad_iteration = Some((
                            i,
                            "delete reported success but the ref is still present on disk",
                        ));
                    }
                }
                (Err(RefError::Conflict(_)), Err(RefError::Conflict(_))) => {
                    // Both lost — impossible on a fresh `base` write each
                    // round with only these two writers, but not itself a
                    // safety violation; leave unhandled rather than
                    // silently accepting on a bug that could produce it.
                    bad_iteration = Some((
                        i,
                        "both the advance and the delete reported Conflict against a freshly-written base",
                    ));
                }
                _ => {
                    bad_iteration = Some((i, "unexpected error variant"));
                }
            }

            if bad_iteration.is_some() {
                break;
            }
        }

        assert!(
            bad_iteration.is_none(),
            "iteration {bad_iteration:?}: a concurrent Match-conditioned advance and a \
             CAS-guarded delete on the same ref did not serialize correctly"
        );
    }

    /// Cross-ref counterpart to the race test above: the lock
    /// was first one repo-wide `refs.lock`, so a `Match` CAS on branch "other"
    /// would block one on unrelated branch "main" for no reason —
    /// nothing about this CAS invariant spans refs. Now keyed per ref
    /// via [`cas_lock_name`]; proves an externally-held lock on
    /// "other"'s ref path does NOT block a `Match` CAS on "main"'s.
    #[test]
    fn cas_match_does_not_contend_across_different_refs() {
        let (_dir, kit) = fresh_repo();
        write_ref(&kit, "main", &h("m0")).unwrap();
        write_ref(&kit, "other", &h("o0")).unwrap();

        let other_path = ref_path(kit.common_dir(), HEADS_DIR, "other");
        let other_lock_name = cas_lock_name(kit.common_dir(), &other_path);
        let common_dir = kit.common_dir().to_path_buf();
        let (holding_tx, holding_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let holder = std::thread::spawn(move || {
            let _lock = crate::repo_lock::acquire_default(&common_dir, &other_lock_name).unwrap();
            holding_tx.send(()).unwrap();
            release_rx.recv().unwrap();
        });
        holding_rx.recv().unwrap();

        let start = std::time::Instant::now();
        update_ref(&kit, "main", RefWriteCondition::Match(h("m0")), &h("m1")).unwrap();
        let elapsed = start.elapsed();

        release_tx.send(()).unwrap();
        holder.join().unwrap();

        assert!(
            elapsed < std::time::Duration::from_secs(1),
            "Match CAS on \"main\" took {elapsed:?} while \"other\"'s ref lock was held \
             elsewhere — refs are contending when they shouldn't be"
        );
        assert_eq!(read_ref(&kit, "main").unwrap(), Some(h("m1")));
    }

    // --- name-validation enforcement -----------------------------------

    #[test]
    fn write_rejects_invalid_branch_name() {
        let (_dir, kit) = fresh_repo();
        let err = write_ref(&kit, "../escape", &h("x")).unwrap_err();
        assert!(matches!(err, RefError::InvalidRefName(_)));
        let err = write_head_branch(&kit, "bad//branch").unwrap_err();
        assert!(matches!(err, RefError::InvalidRefName(_)));
    }

    // --- tags ----------------------------------------------------------

    #[test]
    fn write_and_read_tag() {
        let (_dir, kit) = fresh_repo();
        let commit = h("v1.0");
        write_tag(&kit, "v1.0", &commit).unwrap();
        assert_eq!(read_tag(&kit, "v1.0").unwrap(), Some(commit));
    }

    #[test]
    fn list_tags_sorted() {
        let (_dir, kit) = fresh_repo();
        write_tag(&kit, "v2.0", &h("v2")).unwrap();
        write_tag(&kit, "v1.0", &h("v1")).unwrap();
        write_tag(&kit, "alpha", &h("a")).unwrap();
        let tags = list_tags(&kit).unwrap();
        assert_eq!(
            tags.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(),
            vec!["alpha", "v1.0", "v2.0"]
        );
    }

    #[test]
    fn tag_and_branch_same_name_independent() {
        let (_dir, kit) = fresh_repo();
        let tag = h("tag");
        let branch = h("branch");
        write_tag(&kit, "main", &tag).unwrap();
        write_ref(&kit, "main", &branch).unwrap();
        assert_eq!(read_tag(&kit, "main").unwrap(), Some(tag));
        assert_eq!(read_ref(&kit, "main").unwrap(), Some(branch));
    }

    #[test]
    fn delete_tag_basic() {
        let (_dir, kit) = fresh_repo();
        write_tag(&kit, "release", &h("r")).unwrap();
        delete_tag(&kit, "release").unwrap();
        assert_eq!(read_tag(&kit, "release").unwrap(), None);
    }

    #[test]
    fn delete_nonexistent_tag_errors() {
        let (_dir, kit) = fresh_repo();
        let err = delete_tag(&kit, "missing").unwrap_err();
        assert!(matches!(err, RefError::NotFound(_)));
    }

    // --- shallow boundaries --------------------------------------------

    #[test]
    fn load_shallow_returns_none_when_missing() {
        let (_dir, kit) = fresh_repo();
        assert_eq!(load_shallow_boundaries(&kit).unwrap(), None);
    }

    #[test]
    fn write_and_load_shallow_round_trip() {
        let (_dir, kit) = fresh_repo();
        let bs = vec![h("b1"), h("b2"), h("b3")];
        write_shallow_boundaries(&kit, &bs).unwrap();
        let loaded = load_shallow_boundaries(&kit).unwrap().unwrap();
        assert_eq!(loaded.len(), 3);
        for b in &bs {
            assert!(loaded.contains(b));
        }
    }

    #[test]
    fn write_empty_shallow_removes_file() {
        let (_dir, kit) = fresh_repo();
        write_shallow_boundaries(&kit, &[h("x")]).unwrap();
        assert!(load_shallow_boundaries(&kit).unwrap().is_some());
        write_shallow_boundaries(&kit, &[]).unwrap();
        assert_eq!(load_shallow_boundaries(&kit).unwrap(), None);
    }

    #[test]
    fn load_shallow_rejects_oversize_file() {
        // SPEC-REFS §6: the shallow file is capped at 1 MiB.
        let (_dir, kit) = fresh_repo();
        let path = kit.shallow_file();
        fs::write(
            &path,
            vec![b'a'; usize::try_from(SHALLOW_MAX_BYTES).unwrap() + 1],
        )
        .unwrap();
        let err = load_shallow_boundaries(&kit).unwrap_err();
        assert!(matches!(err, RefError::InvalidRef(_)));
    }

    #[test]
    fn load_shallow_skips_invalid_lines() {
        let (_dir, kit) = fresh_repo();
        let path = kit.shallow_file();
        let valid = h("ok");
        let valid_hex = to_hex(&valid);
        let mut content = String::new();
        content.push_str("short\n");
        content.push_str(&valid_hex);
        content.push('\n');
        content.push_str(&"z".repeat(64));
        content.push('\n');
        std::fs::write(&path, content).unwrap();
        let loaded = load_shallow_boundaries(&kit).unwrap().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0], valid);
    }

    // --- remote-ref batching --------------------------------------
    //
    // `push`/`fetch` publish one remote-tracking ref per branch in a loop
    // (`kit-bin`'s `remote_dispatch::push_all_with` /
    // `kit-sync`'s `fetch_objects_inner`). Each `write_remote_ref` call goes through
    // `cas_write` → `write_pointer`, which pays a parent-directory fsync
    // EVERY call (`durable::flush_dir`) — so N branches cost N
    // directory fsyncs, serially, even though they all land in the same
    // `refs/remotes/<remote>/` directory. `RemoteRefBatch` amortises that
    // into one fsync per distinct directory touched, however many refs
    // were written into it.

    /// Baseline (pre-fix): today's per-ref loop — exactly what
    /// `push_all_with`/`kit-sync`'s `fetch_objects_inner` do today — pays one
    /// directory fsync per ref, even though every ref lands in the same
    /// `refs/remotes/origin/` directory. This is the O(N) cost that batching
    /// exists to amortise; it must keep holding after the fix, since
    /// `write_remote_ref` itself (used elsewhere for single-ref writes)
    /// is intentionally left on the unbatched path.
    #[test]
    fn write_remote_ref_loop_pays_one_dir_sync_per_ref_today() {
        let (_dir, kit) = fresh_repo();
        let n: u64 = 25;
        crate::durable::testing::reset_dir_sync_calls();
        for i in 0..n {
            write_remote_ref(&kit, "origin", &format!("branch-{i}"), &h(&format!("c{i}"))).unwrap();
        }
        let calls = crate::durable::testing::dir_sync_calls();
        assert_eq!(
            calls, n,
            "the current per-ref write path must cost exactly one directory \
             fsync per ref (O(N)); got {calls} for {n} refs"
        );
    }

    /// The fix: staging N remote-tracking-ref writes into one
    /// `RemoteRefBatch` and committing once must cost O(1) directory
    /// fsyncs (one per distinct directory touched — here a single flat
    /// `refs/remotes/origin/` namespace, so exactly one), not O(N).
    #[test]
    fn remote_ref_batch_pays_one_dir_sync_for_many_refs() {
        let (_dir, kit) = fresh_repo();
        let n = 25;
        let entries: Vec<(String, Hash)> = (0..n)
            .map(|i| (format!("branch-{i}"), h(&format!("c{i}"))))
            .collect();

        crate::durable::testing::reset_dir_sync_calls();
        let mut batch = RemoteRefBatch::new(&kit, "origin").unwrap();
        for (branch, hash) in &entries {
            batch.write(branch, hash).unwrap();
        }
        batch.commit().unwrap();

        let calls = crate::durable::testing::dir_sync_calls();
        assert_eq!(
            calls, 1,
            "batching {n} tracking-ref writes into one flat remote \
             namespace must cost exactly one directory fsync (O(1)), got {calls}"
        );
    }

    /// Correctness: batched writes must produce the exact same final ref
    /// states as the old per-ref `write_remote_ref` loop — same hashes,
    /// same readability, for every branch.
    #[test]
    fn remote_ref_batch_matches_per_ref_loop_final_state() {
        let (_dir, old_path) = fresh_repo();
        let (_dir2, new_path) = fresh_repo();
        let n = 12;
        let entries: Vec<(String, Hash)> = (0..n)
            .map(|i| (format!("team/branch-{i}"), h(&format!("state{i}"))))
            .collect();

        for (branch, hash) in &entries {
            write_remote_ref(&old_path, "origin", branch, hash).unwrap();
        }

        let mut batch = RemoteRefBatch::new(&new_path, "origin").unwrap();
        for (branch, hash) in &entries {
            batch.write(branch, hash).unwrap();
        }
        batch.commit().unwrap();

        for (branch, hash) in &entries {
            let old_val = read_remote_ref(&old_path, "origin", branch).unwrap();
            let new_val = read_remote_ref(&new_path, "origin", branch).unwrap();
            assert_eq!(old_val, Some(*hash));
            assert_eq!(new_val, Some(*hash));
            assert_eq!(old_val, new_val, "branch {branch} diverged");
        }
    }

    /// Partial-failure semantics: best-effort / fail-fast, matching
    /// `WriteBatch::commit`'s documented contract (already-renamed
    /// entries stay visible; no rollback). An invalid branch name in the
    /// middle of a batch aborts every write from that point on — the
    /// refs staged before it stay visible and readable, exactly as they
    /// would have under the old per-ref loop had it hit the same
    /// mid-loop error (each earlier ref was already independently
    /// visible before the loop reached the bad one).
    #[test]
    fn remote_ref_batch_partial_failure_keeps_already_written_refs_visible() {
        let (_dir, kit) = fresh_repo();
        let mut batch = RemoteRefBatch::new(&kit, "origin").unwrap();
        batch.write("good-1", &h("g1")).unwrap();
        batch.write("good-2", &h("g2")).unwrap();
        let err = batch.write("bad//name", &h("x")).unwrap_err();
        assert!(matches!(err, RefError::InvalidRefName(_)));

        // Committing what was staged before the bad write must still
        // durably publish the good entries.
        batch.commit().unwrap();
        assert_eq!(
            read_remote_ref(&kit, "origin", "good-1").unwrap(),
            Some(h("g1"))
        );
        assert_eq!(
            read_remote_ref(&kit, "origin", "good-2").unwrap(),
            Some(h("g2"))
        );
        // "bad//name" was never a valid ref name in the first place —
        // nothing was ever staged for it, on either the old or new path.
        let never_written = read_remote_ref(&kit, "origin", "bad//name").unwrap_err();
        assert!(matches!(never_written, RefError::InvalidRefName(_)));
    }

    #[test]
    fn remote_ref_batch_rejects_invalid_remote_name() {
        let (_dir, kit) = fresh_repo();
        let err = RemoteRefBatch::new(&kit, "../escape").unwrap_err();
        assert!(matches!(err, RefError::InvalidRefName(_)));
    }

    #[test]
    fn remote_ref_batch_of_zero_entries_is_a_noop_commit() {
        let (_dir, kit) = fresh_repo();
        crate::durable::testing::reset_dir_sync_calls();
        let batch = RemoteRefBatch::new(&kit, "origin").unwrap();
        batch.commit().unwrap();
        assert_eq!(
            crate::durable::testing::dir_sync_calls(),
            0,
            "an empty batch must not touch any directory"
        );
    }

    #[cfg(feature = "history-mmr")]
    mod write_ref_recording_history_tests {
        use std::sync::{Arc, Barrier};

        use super::*;
        use crate::history::{AncestrySnapshot, Position, verify_inclusion};
        use crate::object::{Commit, Identity, Object};
        use crate::store::ObjectStore;

        fn write_commit(store: &ObjectStore, parents: Vec<Hash>, seed: u8) -> Hash {
            let commit = Commit::new_unannotated(
                [seed; 32],
                parents,
                Identity::ed25519([seed; 32]),
                [seed; 32],
                b"msg".to_vec(),
                0,
                [0u8; 64],
            );
            let bytes = crate::serialize::serialize(&Object::Commit(commit)).unwrap();
            store.write(&bytes).unwrap()
        }

        #[test]
        fn backfills_a_repo_written_without_history_from_the_object_store() {
            let td = tempfile::tempdir().unwrap();
            let layout = RepoLayout::single(td.path());
            let store = ObjectStore::init(&layout).unwrap();

            // Build a 3-commit chain through the object store and point
            // `refs/heads/main` at the tip directly. This simulates a repo
            // written without `history-mmr`: the ref exists, but no canonical
            // ancestry snapshot exists.
            let c0 = write_commit(&store, vec![], 1);
            let c1 = write_commit(&store, vec![c0], 2);
            let c2 = write_commit(&store, vec![c1], 3);
            write_ref(&layout, "main", &c2).unwrap();

            // The first history-aware write for this branch: a new commit on
            // top of the existing tip.
            let c3 = write_commit(&store, vec![c2], 4);
            write_ref_recording_history(&layout, "main", RefWriteCondition::Match(c2), &c3)
                .unwrap();

            assert_eq!(read_ref(&layout, "main").unwrap(), Some(c3));

            // The journal holds the backfilled chain and the new commit.
            let hist = AncestrySnapshot::load(&layout, "main").unwrap();
            assert_eq!(hist.len(), 4);
            let root = hist.root();
            for (i, c) in [c0, c1, c2, c3].into_iter().enumerate() {
                let pos = Position(i as u64);
                let proof = hist.prove(pos).unwrap();
                assert!(
                    verify_inclusion(&c, pos, &proof, &root),
                    "commit at position {i} failed inclusion proof after backfill"
                );
            }
        }

        #[test]
        fn does_not_backfill_a_fresh_branch() {
            let td = tempfile::tempdir().unwrap();
            let layout = RepoLayout::single(td.path());
            let store = ObjectStore::init(&layout).unwrap();

            // No ref exists: this is the first commit of a new branch, so
            // there is nothing to backfill.
            let c0 = write_commit(&store, vec![], 1);
            write_ref_recording_history(&layout, "main", RefWriteCondition::Missing, &c0).unwrap();

            let hist = AncestrySnapshot::load(&layout, "main").unwrap();
            assert_eq!(
                hist.len(),
                1,
                "only the one real write, no phantom backfill entries"
            );
        }

        /// The length of a chain that already exists on disk, with no journal.
        /// It simulates a repo that turns on `history-mmr` for the first time.
        const CONCURRENT_BACKFILL_CHAIN_LEN: usize = 500;

        /// Concurrent first publications build the ancestry under the history
        /// lock and produce one complete chain with no duplicate leaves.
        #[test]
        fn concurrent_backfill_does_not_duplicate_leaves() {
            let td = tempfile::tempdir().unwrap();
            let layout = Arc::new(RepoLayout::single(td.path()));
            let store = ObjectStore::init(&layout).unwrap();

            let mut tip: Option<Hash> = None;
            for seed in 0..CONCURRENT_BACKFILL_CHAIN_LEN {
                let seed = u8::try_from(seed % 256).expect("seed % 256 fits in u8");
                tip = Some(write_commit(&store, tip.into_iter().collect(), seed));
            }
            let tip = tip.unwrap();
            write_ref(&layout, "main", &tip).unwrap();

            // Two independent new commits race to be the first history-aware
            // write for this branch.
            let c_a = write_commit(&store, vec![tip], 250);
            let c_b = write_commit(&store, vec![tip], 251);

            let barrier = Arc::new(Barrier::new(2));
            let spawn = |commit: Hash| {
                let (layout, barrier) = (Arc::clone(&layout), Arc::clone(&barrier));
                std::thread::spawn(move || {
                    barrier.wait();
                    write_ref_recording_history(&layout, "main", RefWriteCondition::Any, &commit)
                })
            };
            let (t_a, t_b) = (spawn(c_a), spawn(c_b));
            t_a.join()
                .expect("thread a must not panic")
                .expect("writer a must succeed");
            t_b.join()
                .expect("thread b must not panic")
                .expect("writer b must succeed");

            let hist = AncestrySnapshot::load(&layout, "main").unwrap();
            assert_eq!(
                hist.len(),
                CONCURRENT_BACKFILL_CHAIN_LEN as u64 + 1,
                "the winning tip must have exactly its own first-parent ancestry; \
             the superseded sibling writer is not an ancestor"
            );
        }
    }

    // --- long names -------------------------------------------------------

    #[test]
    fn a_branch_with_a_250_byte_segment_is_written_and_read() {
        let (_dir, layout) = fresh_repo();
        let branch = "b".repeat(250);
        write_ref(&layout, &branch, &h("long")).unwrap();
        assert_eq!(read_ref(&layout, &branch).unwrap(), Some(h("long")));
    }

    #[test]
    fn a_remote_batch_writes_a_255_byte_segment() {
        let (_dir, layout) = fresh_repo();
        let branch = "r".repeat(255);
        let mut batch = RemoteRefBatch::new(&layout, "origin").unwrap();
        batch.write(&branch, &h("long")).unwrap();
        batch.commit().unwrap();
        assert_eq!(
            read_remote_ref(&layout, "origin", &branch).unwrap(),
            Some(h("long"))
        );
    }
}

#[cfg(test)]
mod staged_tests;
