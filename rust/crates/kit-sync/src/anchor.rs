//! Disposable record, next to each remote-tracking ref, of the last tip a
//! fetch that verified signatures published for that ref. The history of a
//! recorded tip was verified in full, so a later walk stops there: a fetch
//! verifies only the commits between a new tip and the tips already recorded.
//! See the sync README for the on-disk contract.
//!
//! The record states a fact about content-addressed objects, so it stays true
//! when the tracking ref moves on. A fetch with the opt-out, or an older kit,
//! can move the ref without updating the record. The ref then differs from the
//! record, and its new tip is no anchor. Loss or corruption of a record only
//! makes the next walk longer.

use std::path::{Path, PathBuf};

use kit_core::hash::{Hash, hash, to_hex};
use kit_core::layout::RepoLayout;
use kit_core::refs::parse_lowercase_hash;

use crate::verify::VerifiedHistory;

/// First field of a record. It names the record format and version.
const VERIFIED_TIP_TAG: &str = "kit-verified-tip-v1";

/// The largest record [`load`] accepts.
const RECORD_MAX_BYTES: usize = 256;

/// The most records [`load_all`] reads. A store with more only walks further.
const MAX_ANCHORS: usize = 65_536;

fn dir(layout: &RepoLayout) -> PathBuf {
    layout.applied_packs_dir().join(".verified")
}

/// Drop every record. A history walk then stops at no recorded tip.
///
/// # Errors
/// The records cannot be removed.
pub(crate) fn forget_all(layout: &RepoLayout) -> std::io::Result<()> {
    remove_dir_if_present(&dir(layout))
}

/// Remove `path` and everything under it; a missing one is already removed.
pub(crate) fn remove_dir_if_present(path: &std::path::Path) -> std::io::Result<()> {
    match std::fs::remove_dir_all(path) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

/// The record of `branch` of `remote`. Length prefixes keep two different
/// pairs from naming one file.
pub(crate) fn path(layout: &RepoLayout, remote: &str, branch: &str) -> PathBuf {
    let mut key = Vec::new();
    for part in [remote, branch] {
        key.extend_from_slice(&(part.len() as u64).to_le_bytes());
        key.extend_from_slice(part.as_bytes());
    }
    dir(layout).join(to_hex(&hash(&key)))
}

fn parse(bytes: &[u8]) -> Option<Hash> {
    let text = std::str::from_utf8(bytes).ok()?;
    let (body, checksum) = text.rsplit_once('\n')?;
    if parse_lowercase_hash(checksum.as_bytes())? != hash(body.as_bytes()) {
        return None;
    }
    let mut fields = body.split('\n');
    if fields.next()? != VERIFIED_TIP_TAG {
        return None;
    }
    let tip = parse_lowercase_hash(fields.next()?.as_bytes())?;
    fields.next().is_none().then_some(tip)
}

/// The tip a record names, or `None` for a missing, oversized or malformed
/// record.
pub(crate) fn load(path: &Path) -> Option<Hash> {
    use std::io::Read as _;
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .ok()?
        .take(RECORD_MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() > RECORD_MAX_BYTES {
        return None;
    }
    parse(&bytes)
}

/// Record that the history of `tip` was verified in full.
pub(crate) fn persist(path: &Path, tip: &Hash) -> std::io::Result<()> {
    let body = format!("{VERIFIED_TIP_TAG}\n{}", to_hex(tip));
    let bytes = format!("{body}\n{}", to_hex(&hash(body.as_bytes())));
    crate::applied_packs::write_atomic(path, bytes.as_bytes())
}

/// Whether the record of `branch` of `remote` names `tip`: a fetch that
/// verified signatures published the ref at `tip`.
pub(crate) fn names(layout: &RepoLayout, remote: &str, branch: &str, tip: &Hash) -> bool {
    load(&path(layout, remote, branch)) == Some(*tip)
}

/// The tips of every record of every remote, at most [`MAX_ANCHORS`] of
/// them. Only files named by a 64-hex digest are read, so a temporary file of
/// an interrupted write is skipped.
pub(crate) fn load_all(layout: &RepoLayout) -> VerifiedHistory {
    let Ok(entries) = std::fs::read_dir(dir(layout)) else {
        return VerifiedHistory::default();
    };
    entries
        .filter_map(Result::ok)
        .filter(|entry| {
            entry.file_name().to_str().is_some_and(|name| {
                name.len() == 64 && parse_lowercase_hash(name.as_bytes()).is_some()
            })
        })
        .take(MAX_ANCHORS)
        .filter_map(|entry| load(&entry.path()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_record_roundtrips_and_a_damaged_one_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let layout = RepoLayout::single(dir.path());
        let tip = hash(b"tip");
        let main = path(&layout, "origin", "main");
        assert_ne!(main, path(&layout, "origin/main", ""));
        assert!(load(&main).is_none());
        persist(&main, &tip).unwrap();
        assert_eq!(load(&main), Some(tip));
        assert!(names(&layout, "origin", "main", &tip));
        assert!(!names(&layout, "origin", "main", &hash(b"other")));
        assert!(!names(&layout, "upstream", "main", &tip));
        let other = path(&layout, "upstream", "dev");
        persist(&other, &hash(b"dev")).unwrap();
        // A temporary file an interrupted write left is not read.
        std::fs::write(main.with_file_name(".x.tmp"), b"junk").unwrap();
        assert_eq!(
            load_all(&layout),
            [tip, hash(b"dev")].into_iter().collect::<VerifiedHistory>()
        );

        let mut bytes = std::fs::read(&main).unwrap();
        let at = VERIFIED_TIP_TAG.len() + 3;
        bytes[at] = if bytes[at] == b'a' { b'b' } else { b'a' };
        std::fs::write(&main, &bytes).unwrap();
        assert!(load(&main).is_none());
        std::fs::write(&main, vec![b'a'; RECORD_MAX_BYTES + 1]).unwrap();
        assert!(load(&main).is_none());
        let body = format!("{VERIFIED_TIP_TAG}\n{}\nextra", to_hex(&tip));
        std::fs::write(&main, format!("{body}\n{}", to_hex(&hash(body.as_bytes())))).unwrap();
        assert!(load(&main).is_none());
    }
}
