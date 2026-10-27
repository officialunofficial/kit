//! Revision specifications.
//!
//! [`resolve_revision`] turns a revision string into one object
//! [`Hash`](tyalias@kit_core::Hash). Every command that names a revision
//! accepts the same grammar.
//!
//! Accepted grammar, a small subset of `git rev-parse`:
//!
//! - **Full hash**: exactly 64 hex characters, lower or upper case, that name
//!   an object in the store.
//! - **Short hash**: a hex prefix of at least [`MIN_SHORT_HASH`] characters that
//!   names exactly one object. A prefix with two or more matches is an error.
//!   A prefix with no match is an error.
//! - **Ref name**: a branch (`refs/heads/<name>`), a tag (`refs/tags/<name>`),
//!   a remote-tracking ref (`<remote>/<branch>`), or the literal `HEAD`. A
//!   branch wins over a tag when both have the name.
//! - **Suffix navigation**: a base from the forms above, then zero or more
//!   `~n`, `^` or `^n` steps along the commit graph. `~n` walks `n`
//!   first parents, and `~` alone means `~1`. `^n` selects the n-th parent
//!   (1-based), and `^` alone means `^1`. `^0` is the commit itself. For
//!   example `HEAD~2`, `main^` and `<hash>~1^2`.
//!
//! The grammar has no pathspecs, no `:/text` message search, no reflog
//! (`@{n}`) syntax and no ranges. A caller splits `A..B` before it passes
//! each end here.

use std::io;

use kit_core::hash::{self, HEX_LEN, Hash};
use kit_core::layout::RepoLayout;
use kit_core::object::Object;
use kit_core::refs::{self, RefError};
use kit_core::store::{ObjectStore, StoreError};

/// The shortest short-hash prefix that the resolver accepts. A shorter token
/// fails fast instead of triggering a scan, so a mistyped ref name does not
/// cost a directory read.
pub const MIN_SHORT_HASH: usize = 4;

/// Longest chain of tag objects that [`peel_tags`] follows.
const MAX_TAG_DEPTH: usize = 16;

/// Errors from resolving a revision.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The base token matched no ref and no object.
    #[error("unknown revision '{0}'")]
    Unknown(String),
    /// A short-hash prefix matched more than one object.
    #[error("ambiguous short hash '{0}' matches multiple objects")]
    Ambiguous(String),
    /// A `~` or `^` suffix walked off the end of the commit graph, or the
    /// suffix text is malformed.
    #[error("revision '{spec}': {detail}")]
    BadSuffix {
        /// The full spec that the caller supplied.
        spec: String,
        /// What went wrong.
        detail: String,
    },
    /// The base resolved, but a suffix step reached an object that has no
    /// parents, such as a tree or a blob.
    #[error("revision '{0}' resolves to a non-commit object; cannot walk parents")]
    NotACommit(String),
    /// HEAD could not be read.
    #[error("resolve HEAD: {0}")]
    ReadHead(RefError),
    /// The object directory could not be scanned for a short hash.
    #[error("scan objects: {0}")]
    ScanObjects(io::Error),
    /// An object could not be read.
    #[error("read object: {0}")]
    ReadObject(StoreError),
    /// The object is not a commit, a remix, a tree or a tag of one of them.
    #[error("{0} is not a commit, remix, or tree")]
    NotTreeish(String),
}

/// Resolve `spec` to a single object [`Hash`](tyalias@kit_core::Hash).
///
/// The module documentation lists the accepted grammar. The function reads the
/// repository only. It reads no environment and no working directory.
///
/// # Errors
/// Returns [`Error`] when the spec is unknown or ambiguous, when the
/// suffix navigation is invalid, or when the repository cannot be read.
pub fn resolve_revision(
    store: &ObjectStore,
    layout: &RepoLayout,
    spec: &str,
) -> Result<Hash, Error> {
    // Split the base from any trailing `~`/`^` navigation. The base is
    // everything up to the first `~` or `^`.
    let split_at = spec.find(['~', '^']).unwrap_or(spec.len());
    let (base, suffix) = spec.split_at(split_at);
    if base.is_empty() {
        return Err(Error::Unknown(spec.to_string()));
    }

    let mut current = resolve_base(store, layout, base)?;

    // Walk the suffix steps left-to-right.
    let mut rest = suffix;
    while !rest.is_empty() {
        let bytes = rest.as_bytes();
        match bytes[0] {
            b'~' => {
                let (n, consumed) = parse_count(&rest[1..]);
                current = walk_first_parent(store, spec, current, n)?;
                rest = &rest[1 + consumed..];
            }
            b'^' => {
                let (n, consumed) = parse_count(&rest[1..]);
                current = select_parent(store, spec, current, n)?;
                rest = &rest[1 + consumed..];
            }
            _ => {
                return Err(Error::BadSuffix {
                    spec: spec.to_string(),
                    detail: format!("unexpected character in suffix '{rest}'"),
                });
            }
        }
    }
    Ok(current)
}

/// Follow tag objects to the first object that is not a tag, so an annotated
/// or signed tag becomes the object it points at. A non-tag object, an
/// unreadable object, or a chain longer than 16 tags stops the walk. The
/// function returns the hash where the walk stopped.
#[must_use]
pub fn peel_tags(store: &ObjectStore, mut h: Hash) -> Hash {
    for _ in 0..MAX_TAG_DEPTH {
        match store.read_object(&h) {
            Ok(Object::Tag(t)) => h = t.target,
            _ => break,
        }
    }
    h
}

/// The tree that `h` names: the tree of a commit or a remix, or `h` itself
/// for a tree. Tag objects are peeled first.
///
/// # Errors
/// [`Error::ReadObject`] when an object cannot be read. [`Error::NotTreeish`]
/// when the object is a blob or another kind without a tree.
pub fn tree_of(store: &ObjectStore, h: &Hash) -> Result<Hash, Error> {
    let h = peel_tags(store, *h);
    match store.read_object(&h).map_err(Error::ReadObject)? {
        Object::Commit(c) => Ok(c.tree_hash),
        Object::Remix(r) => Ok(r.tree_hash),
        Object::Tree(_) => Ok(h),
        _ => Err(Error::NotTreeish(hash::to_hex(&h))),
    }
}

/// Resolve the base token (no `~`/`^` suffix) to a hash: ref, then
/// full/short hash.
fn resolve_base(store: &ObjectStore, layout: &RepoLayout, base: &str) -> Result<Hash, Error> {
    // 1. HEAD.
    if base == "HEAD" {
        return match refs::resolve_head(layout) {
            Ok(Some(h)) => Ok(h),
            Ok(None) => Err(Error::Unknown("HEAD".to_string())),
            Err(e) => Err(Error::ReadHead(e)),
        };
    }

    // 2. Explicit full ref paths: refs/heads/<b>, refs/tags/<t>,
    //    refs/remotes/<r>/<b>. These are unambiguous and checked
    //    before any short-form guessing.
    if let Some(short) = base.strip_prefix("refs/heads/") {
        if let Ok(Some(h)) = refs::read_ref(layout, short) {
            return Ok(h);
        }
        return Err(Error::Unknown(base.to_string()));
    }
    if let Some(short) = base.strip_prefix("refs/tags/") {
        if let Ok(Some(h)) = refs::read_tag(layout, short) {
            return Ok(h);
        }
        return Err(Error::Unknown(base.to_string()));
    }
    if let Some(rest) = base.strip_prefix("refs/remotes/") {
        if let Some((remote, branch)) = rest.split_once('/')
            && let Ok(Some(h)) = refs::read_remote_ref(layout, remote, branch)
        {
            return Ok(h);
        }
        return Err(Error::Unknown(base.to_string()));
    }

    // 3. Branch (refs/heads), then tag (refs/tags). `read_ref` /
    //    `read_tag` validate the name, returning `InvalidRefName` for a
    //    bad ref name — which we treat as "not a ref" and fall through
    //    to hash parsing (a bare hash is not a valid ref name anyway).
    // The grammar only, so a branch named before SPEC-REFS §3 bounded
    // names still resolves.
    if refs::validate_ref_name_grammar(base) {
        if let Ok(Some(h)) = refs::read_ref(layout, base) {
            return Ok(h);
        }
        if let Ok(Some(h)) = refs::read_tag(layout, base) {
            return Ok(h);
        }
        // 3b. Remote-tracking short form `<remote>/<branch>` (git's
        //     resolution order also places this after heads/tags).
        if let Some((remote, branch)) = base.split_once('/')
            && let Ok(Some(h)) = refs::read_remote_ref(layout, remote, branch)
        {
            return Ok(h);
        }
    }

    // 4. Full 64-hex hash that exists in the store.
    if base.len() == HEX_LEN
        && let Ok(h) = hash::from_hex(base)
    {
        if store.contains(&h) {
            return Ok(h);
        }
        return Err(Error::Unknown(base.to_string()));
    }

    // 5. Short hex prefix.
    if base.len() >= MIN_SHORT_HASH && base.len() < HEX_LEN && is_hex(base) {
        return resolve_short_hash(store, base);
    }

    Err(Error::Unknown(base.to_string()))
}

/// Find the unique object whose hex starts with `prefix`. Errors on
/// zero matches ([`Error::Unknown`]) or ≥ 2 matches
/// ([`Error::Ambiguous`]).
fn resolve_short_hash(store: &ObjectStore, prefix: &str) -> Result<Hash, Error> {
    let lower = prefix.to_ascii_lowercase();
    // Object layout: `objects/<2-hex>/<62-hex>`. The first two hex chars
    // (when present) name the shard directory, so we only scan one
    // shard. With a 1-char prefix (below MIN_SHORT_HASH, never reached)
    // we would have to scan 16 shards; the >= MIN_SHORT_HASH gate makes
    // the 2-char shard slice always available.
    let (shard, file_prefix) = lower.split_at(2);
    let shard_dir = store.objects_root().join(shard);
    let iter = match std::fs::read_dir(&shard_dir) {
        Ok(i) => i,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(Error::Unknown(prefix.to_string()));
        }
        Err(e) => return Err(Error::ScanObjects(e)),
    };

    let mut found: Option<Hash> = None;
    for entry in iter {
        let entry = entry.map_err(Error::ScanObjects)?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if name.len() != HEX_LEN - 2 || !name.starts_with(file_prefix) {
            continue;
        }
        let full = format!("{shard}{name}");
        let Ok(h) = hash::from_hex(&full) else {
            continue;
        };
        if found.is_some() {
            return Err(Error::Ambiguous(prefix.to_string()));
        }
        found = Some(h);
    }
    found.ok_or_else(|| Error::Unknown(prefix.to_string()))
}

/// Walk `n` first-parents from `commit`.
fn walk_first_parent(
    store: &ObjectStore,
    spec: &str,
    mut commit: Hash,
    n: u32,
) -> Result<Hash, Error> {
    for _ in 0..n {
        let parents = parents_of(store, spec, &commit)?;
        let Some(first) = parents.first() else {
            return Err(Error::BadSuffix {
                spec: spec.to_string(),
                detail: format!(
                    "commit {} has no parent (history root reached)",
                    hash::to_hex(&commit)
                ),
            });
        };
        commit = *first;
    }
    Ok(commit)
}

/// Select the `n`-th parent of `commit` (1-based). `n == 0` is the
/// commit itself.
fn select_parent(store: &ObjectStore, spec: &str, commit: Hash, n: u32) -> Result<Hash, Error> {
    if n == 0 {
        return Ok(commit);
    }
    let parents = parents_of(store, spec, &commit)?;
    let idx = (n - 1) as usize;
    parents.get(idx).copied().ok_or_else(|| Error::BadSuffix {
        spec: spec.to_string(),
        detail: format!(
            "commit {} has no parent #{n} (only {} parent(s))",
            hash::to_hex(&commit),
            parents.len()
        ),
    })
}

/// Read the parent list of a commit-or-remix object.
fn parents_of(store: &ObjectStore, spec: &str, commit: &Hash) -> Result<Vec<Hash>, Error> {
    match store.read_object(commit) {
        Ok(Object::Commit(c)) => Ok(c.parents),
        Ok(Object::Remix(r)) => Ok(r.parents),
        Ok(_) => Err(Error::NotACommit(spec.to_string())),
        Err(e) => Err(Error::ReadObject(e)),
    }
}

/// Parse a leading decimal count from `s`, returning `(count, consumed)`.
/// An absent count (next char is not a digit, or `s` is empty) yields
/// `(1, 0)` — matching `git`'s `~` == `~1` and `^` == `^1`.
fn parse_count(s: &str) -> (u32, usize) {
    let digits: String = s.chars().take_while(char::is_ascii_digit).collect();
    if digits.is_empty() {
        (1, 0)
    } else {
        // Saturate on overflow: a `~99999999999` walk would hit the
        // history root and error long before the count mattered, but we
        // must not panic on parse.
        let n = digits.parse::<u32>().unwrap_or(u32::MAX);
        (n, digits.len())
    }
}

fn is_hex(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kit_core::object::{Blob, Commit, Identity, Object, ObjectType, Tree};
    use kit_core::refs;
    use kit_core::serialize;
    use tempfile::TempDir;

    fn author() -> Identity {
        Identity::ed25519([0u8; 32])
    }

    /// Build a throwaway repo with an object store + ref dir.
    fn fresh_repo() -> (TempDir, ObjectStore, RepoLayout) {
        let dir = TempDir::new().unwrap();
        let layout = RepoLayout::single(dir.path());
        let store = ObjectStore::init(&layout).unwrap();
        refs::init(&layout).unwrap();
        (dir, store, layout)
    }

    /// Write a commit object with the given parents and return its hash.
    fn write_commit(store: &ObjectStore, parents: Vec<Hash>, seed: u8) -> Hash {
        let commit = Commit::new_unannotated(
            [seed; 32],
            parents,
            author(),
            [0u8; 32],
            vec![seed],
            u64::from(seed),
            [0u8; 64],
        );
        let bytes = serialize::serialize(&Object::Commit(commit)).unwrap();
        store.write(&bytes).unwrap()
    }

    #[test]
    fn resolves_full_hash() {
        let (_d, store, kit) = fresh_repo();
        let c = write_commit(&store, vec![], 1);
        let hex = hash::to_hex(&c);
        assert_eq!(resolve_revision(&store, &kit, &hex).unwrap(), c);
    }

    #[test]
    fn full_hash_not_in_store_is_unknown() {
        let (_d, store, kit) = fresh_repo();
        let hex = "ab".repeat(32);
        let err = resolve_revision(&store, &kit, &hex).unwrap_err();
        assert!(matches!(err, Error::Unknown(_)));
    }

    #[test]
    fn resolves_unambiguous_short_hash() {
        let (_d, store, kit) = fresh_repo();
        let c = write_commit(&store, vec![], 7);
        let hex = hash::to_hex(&c);
        let short = &hex[..12];
        assert_eq!(resolve_revision(&store, &kit, short).unwrap(), c);
    }

    #[test]
    fn ambiguous_short_hash_errors() {
        let (_d, store, kit) = fresh_repo();
        // Mine — in memory, hashing only — two blobs whose object hashes
        // share their first MIN_SHORT_HASH hex chars, then write JUST
        // those two to the store and query with the shared prefix. A
        // 4-nibble (16-bit) collision is found within a few hundred
        // candidates by the birthday bound, and we avoid fsync'ing
        // thousands of objects to disk. The two serialized payloads
        // resolve to the two object hashes (the store address is the
        // BLAKE3 of the serialized bytes).
        let mut seen: std::collections::HashMap<String, Vec<u8>> = std::collections::HashMap::new();
        let mut pair: Option<(String, Vec<u8>, Vec<u8>)> = None;
        for i in 0u32..200_000 {
            let bytes = serialize::serialize(&Object::Blob(Blob {
                data: i.to_le_bytes().to_vec(),
            }))
            .unwrap();
            let h = hash::hash(&bytes);
            let prefix = hash::to_hex(&h)[..MIN_SHORT_HASH].to_string();
            if let Some(prev) = seen.get(&prefix) {
                pair = Some((prefix, prev.clone(), bytes));
                break;
            }
            seen.insert(prefix, bytes);
        }
        let (prefix, a, b) = pair.expect("expected a 4-nibble prefix collision");
        store.write(&a).unwrap();
        store.write(&b).unwrap();
        let err = resolve_revision(&store, &kit, &prefix).unwrap_err();
        assert!(matches!(err, Error::Ambiguous(_)), "got {err:?}");
    }

    #[test]
    fn short_hash_no_match_is_unknown() {
        let (_d, store, kit) = fresh_repo();
        write_commit(&store, vec![], 3);
        // "ffff" almost certainly does not prefix our single commit.
        let err = resolve_revision(&store, &kit, "ffffffff").unwrap_err();
        assert!(matches!(err, Error::Unknown(_)));
    }

    #[test]
    fn resolves_branch_ref() {
        let (_d, store, kit) = fresh_repo();
        let c = write_commit(&store, vec![], 5);
        refs::write_ref(&kit, "feature", &c).unwrap();
        assert_eq!(resolve_revision(&store, &kit, "feature").unwrap(), c);
    }

    #[test]
    fn resolves_tag_ref() {
        let (_d, store, kit) = fresh_repo();
        let c = write_commit(&store, vec![], 6);
        refs::write_tag(&kit, "v1.0", &c).unwrap();
        assert_eq!(resolve_revision(&store, &kit, "v1.0").unwrap(), c);
    }

    #[test]
    fn resolves_head() {
        let (_d, store, kit) = fresh_repo();
        let c = write_commit(&store, vec![], 9);
        refs::write_ref(&kit, "main", &c).unwrap();
        assert_eq!(resolve_revision(&store, &kit, "HEAD").unwrap(), c);
    }

    #[test]
    fn resolves_head_tilde_n() {
        let (_d, store, kit) = fresh_repo();
        let root = write_commit(&store, vec![], 1);
        let mid = write_commit(&store, vec![root], 2);
        let tip = write_commit(&store, vec![mid], 3);
        refs::write_ref(&kit, "main", &tip).unwrap();
        assert_eq!(resolve_revision(&store, &kit, "HEAD").unwrap(), tip);
        assert_eq!(resolve_revision(&store, &kit, "HEAD~1").unwrap(), mid);
        assert_eq!(resolve_revision(&store, &kit, "HEAD~2").unwrap(), root);
        // `~` alone == `~1`.
        assert_eq!(resolve_revision(&store, &kit, "HEAD~").unwrap(), mid);
    }

    #[test]
    fn caret_selects_parent() {
        let (_d, store, kit) = fresh_repo();
        let p1 = write_commit(&store, vec![], 1);
        let p2 = write_commit(&store, vec![], 2);
        let merge = write_commit(&store, vec![p1, p2], 3);
        refs::write_ref(&kit, "main", &merge).unwrap();
        assert_eq!(resolve_revision(&store, &kit, "HEAD^").unwrap(), p1);
        assert_eq!(resolve_revision(&store, &kit, "HEAD^1").unwrap(), p1);
        assert_eq!(resolve_revision(&store, &kit, "HEAD^2").unwrap(), p2);
        assert_eq!(resolve_revision(&store, &kit, "HEAD^0").unwrap(), merge);
    }

    #[test]
    fn tilde_off_the_end_errors() {
        let (_d, store, kit) = fresh_repo();
        let root = write_commit(&store, vec![], 1);
        refs::write_ref(&kit, "main", &root).unwrap();
        let err = resolve_revision(&store, &kit, "HEAD~1").unwrap_err();
        assert!(matches!(err, Error::BadSuffix { .. }));
    }

    #[test]
    fn caret_past_parents_errors() {
        let (_d, store, kit) = fresh_repo();
        let p1 = write_commit(&store, vec![], 1);
        let c = write_commit(&store, vec![p1], 2);
        refs::write_ref(&kit, "main", &c).unwrap();
        let err = resolve_revision(&store, &kit, "HEAD^2").unwrap_err();
        assert!(matches!(err, Error::BadSuffix { .. }));
    }

    #[test]
    fn unknown_ref_errors() {
        let (_d, store, kit) = fresh_repo();
        let err = resolve_revision(&store, &kit, "nope").unwrap_err();
        assert!(matches!(err, Error::Unknown(_)));
    }

    #[test]
    fn too_short_prefix_is_unknown() {
        let (_d, store, kit) = fresh_repo();
        let c = write_commit(&store, vec![], 1);
        let hex = hash::to_hex(&c);
        // A 3-char prefix is below MIN_SHORT_HASH and not a valid ref.
        let err = resolve_revision(&store, &kit, &hex[..3]).unwrap_err();
        assert!(matches!(err, Error::Unknown(_)));
    }

    #[test]
    fn branch_wins_over_tag_on_collision() {
        let (_d, store, kit) = fresh_repo();
        let branch_c = write_commit(&store, vec![], 1);
        let tag_c = write_commit(&store, vec![], 2);
        refs::write_ref(&kit, "dup", &branch_c).unwrap();
        refs::write_tag(&kit, "dup", &tag_c).unwrap();
        assert_eq!(resolve_revision(&store, &kit, "dup").unwrap(), branch_c);
    }

    /// Write a tag object that points at `target`.
    fn write_tag(store: &ObjectStore, target: Hash, target_type: ObjectType, seed: u8) -> Hash {
        let tag = kit_core::object::Tag {
            target,
            target_type,
            name: vec![b'v', seed],
            tagger: author(),
            signer: [0u8; 32],
            message: vec![seed],
            timestamp: u64::from(seed),
            signature: [0u8; 64],
        };
        let bytes = serialize::serialize(&Object::Tag(tag)).unwrap();
        store.write(&bytes).unwrap()
    }

    #[test]
    fn peel_tags_follows_a_chain_to_the_commit() {
        let (_d, store, _kit) = fresh_repo();
        let c = write_commit(&store, vec![], 1);
        let inner = write_tag(&store, c, ObjectType::Commit, 2);
        let outer = write_tag(&store, inner, ObjectType::Tag, 3);
        assert_eq!(peel_tags(&store, outer), c);
        assert_eq!(peel_tags(&store, c), c);
    }

    #[test]
    fn peel_tags_returns_an_unreadable_hash_unchanged() {
        let (_d, store, _kit) = fresh_repo();
        assert_eq!(peel_tags(&store, [0xee; 32]), [0xee; 32]);
    }

    #[test]
    fn tree_of_maps_commit_tag_and_tree_to_the_tree() {
        let (_d, store, _kit) = fresh_repo();
        let c = write_commit(&store, vec![], 1);
        let Object::Commit(commit) = store.read_object(&c).unwrap() else {
            panic!("expected a commit");
        };
        let tagged = write_tag(&store, c, ObjectType::Commit, 2);
        assert_eq!(tree_of(&store, &c).unwrap(), commit.tree_hash);
        assert_eq!(tree_of(&store, &tagged).unwrap(), commit.tree_hash);
        let tree = serialize::serialize(&Object::Tree(Tree { entries: vec![] })).unwrap();
        let t = store.write(&tree).unwrap();
        assert_eq!(tree_of(&store, &t).unwrap(), t);
    }

    #[test]
    fn tree_of_refuses_a_blob_and_a_missing_object() {
        let (_d, store, _kit) = fresh_repo();
        let blob = serialize::serialize(&Object::Blob(Blob { data: vec![1] })).unwrap();
        let b = store.write(&blob).unwrap();
        assert!(matches!(tree_of(&store, &b), Err(Error::NotTreeish(_))));
        assert!(matches!(
            tree_of(&store, &[0xee; 32]),
            Err(Error::ReadObject(_))
        ));
    }
}
