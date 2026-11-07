//! Disposable record of the repository cursor that the last complete fetch
//! of a remote saw (SPEC-TRANSPORT §1.2). A fetch whose fresh cursor equals
//! the recorded one, while the remote-tracking refs are as that fetch left
//! them, has nothing to do and makes no other request. Loss or corruption of
//! the record only costs one full fetch.

use std::path::{Path, PathBuf};

use kit_core::hash::{Hash, hash, to_hex};
use kit_core::layout::RepoLayout;
use kit_core::protocol::{REPO_CURSOR_MAX_LEN, RepoCursor};
use kit_core::refs::{self, parse_lowercase_hash};

use crate::SyncError;
use crate::source::RemoteSource;

/// First field of a cursor record. It names the record format and version.
const FETCH_CURSOR_TAG: &str = "kit-fetch-cursor-v1";

/// The largest record [`parse`] accepts.
const RECORD_MAX_BYTES: usize = 512;

/// What one complete fetch saw.
#[derive(Clone, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub struct CursorRecord {
    /// The remote's cursor, read before the fetch listed the remote.
    pub cursor: RepoCursor,
    /// [`tracking_digest`] after the fetch.
    pub tracking: Hash,
    /// Whether the fetch verified signatures.
    pub signed: bool,
}

/// The record file of `remote`, keyed like a fetch checkpoint so that a
/// remote renamed to another repository never reuses it.
pub(crate) fn path(layout: &RepoLayout, source: &dyn RemoteSource, remote: &str) -> PathBuf {
    let (repository, origin) = source.repository_address().unwrap_or_default();
    let mut key = Vec::new();
    for part in [remote, &repository, &origin] {
        key.extend_from_slice(&(part.len() as u64).to_le_bytes());
        key.extend_from_slice(part.as_bytes());
    }
    layout
        .applied_packs_dir()
        .join(".cursors")
        .join(to_hex(&hash(&key)))
}

/// A digest of every remote-tracking ref of `remote`, names and values.
pub(crate) fn tracking_digest(layout: &RepoLayout, remote: &str) -> Result<Hash, SyncError> {
    Ok(digest_of(&mut refs::list_remote_refs(layout, remote)?))
}

/// The digest [`tracking_digest`] takes over `tracked`, which it sorts.
pub(crate) fn digest_of(tracked: &mut [refs::Ref]) -> Hash {
    tracked.sort_by(|a, b| a.name.cmp(&b.name));
    let mut input = Vec::new();
    for r in tracked.iter() {
        input.extend_from_slice(&(r.name.len() as u64).to_le_bytes());
        input.extend_from_slice(r.name.as_bytes());
        input.extend_from_slice(&r.hash.unwrap_or([0u8; 32]));
    }
    hash(&input)
}

/// Parse a record. `None` for anything but a well-formed record with a
/// matching checksum.
#[doc(hidden)]
#[must_use]
pub fn parse(bytes: &[u8]) -> Option<CursorRecord> {
    if bytes.len() > RECORD_MAX_BYTES {
        return None;
    }
    let text = std::str::from_utf8(bytes).ok()?;
    let (body, checksum) = text.rsplit_once('\n')?;
    if parse_lowercase_hash(checksum.as_bytes())? != hash(body.as_bytes()) {
        return None;
    }
    let mut fields = body.split('\n');
    if fields.next()? != FETCH_CURSOR_TAG {
        return None;
    }
    let cursor = parse_hex(fields.next()?)?;
    let tracking = parse_lowercase_hash(fields.next()?.as_bytes())?;
    let signed = match fields.next()? {
        "0" => false,
        "1" => true,
        _ => return None,
    };
    if fields.next().is_some() {
        return None;
    }
    Some(CursorRecord {
        cursor: RepoCursor::new(&cursor).ok()?,
        tracking,
        signed,
    })
}

/// Lowercase hex of at most [`REPO_CURSOR_MAX_LEN`] bytes.
fn parse_hex(text: &str) -> Option<Vec<u8>> {
    let digits = text.as_bytes();
    if !digits.len().is_multiple_of(2) || digits.len() > 2 * REPO_CURSOR_MAX_LEN {
        return None;
    }
    let nibble = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    digits
        .chunks_exact(2)
        .map(|pair| Some(nibble(pair[0])? << 4 | nibble(pair[1])?))
        .collect()
}

/// `bytes` as lowercase hex.
fn lower_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(2 * bytes.len());
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

impl CursorRecord {
    pub(crate) fn load(path: &Path) -> Option<Self> {
        use std::io::Read as _;
        let mut bytes = Vec::new();
        std::fs::File::open(path)
            .ok()?
            .take(RECORD_MAX_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .ok()?;
        parse(&bytes)
    }

    /// Write the record atomically, creating its directory.
    #[doc(hidden)]
    pub fn persist(&self, path: &Path) -> std::io::Result<()> {
        let body = format!(
            "{FETCH_CURSOR_TAG}\n{}\n{}\n{}",
            lower_hex(self.cursor.as_bytes()),
            to_hex(&self.tracking),
            u8::from(self.signed)
        );
        let bytes = format!("{body}\n{}", to_hex(&hash(body.as_bytes())));
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        crate::applied_packs::write_atomic(path, bytes.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_roundtrips_and_rejects_corruption() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a").join("record");
        let record = CursorRecord {
            cursor: RepoCursor::new(&[0xab; REPO_CURSOR_MAX_LEN]).unwrap(),
            tracking: hash(b"tracking"),
            signed: true,
        };
        record.persist(&path).unwrap();
        assert_eq!(CursorRecord::load(&path), Some(record.clone()));
        let good = std::fs::read(&path).unwrap();
        for i in 0..good.len() {
            let mut bad = good.clone();
            bad[i] ^= 0x01;
            assert_eq!(parse(&bad), None, "a flipped byte at {i}");
        }
        assert_eq!(parse(&good[..good.len() - 1]), None);
        let body = format!("{FETCH_CURSOR_TAG}\n\n{}\n1", to_hex(&hash(b"t")));
        let empty_cursor = format!("{body}\n{}", to_hex(&hash(body.as_bytes())));
        assert_eq!(parse(empty_cursor.as_bytes()), None);
        assert_eq!(parse(&vec![b'a'; RECORD_MAX_BYTES + 1]), None);
    }
}
