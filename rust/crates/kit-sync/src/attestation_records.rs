//! Disposable attestation synchronization records, separate from object packs.
//! Provenance is durable: its loss must never promote fetched bytes to local
//! authorship. Callers write provenance before saving a fetched envelope.

use crate::source::RemoteSource;
use kit_core::{
    hash::{self, Hash},
    layout::RepoLayout,
    refs::parse_lowercase_hash,
};
use std::collections::BTreeSet;
use std::path::PathBuf;

/// Maximum packs processed during one attestation chain walk.
pub const WALK_LIMIT: usize = 100_000;
/// Largest downloaded attestation pack-list node.
pub const NODE_BOUND: u64 = kit_core::transfer::packlist_node_bound(4096);

/// Most published ids retained by a push cache. Pruning preserves its warning.
pub const PUSH_CACHE_IDS: usize = 1_000_000;
/// Fixed fields including the longest head and checksum, with room to spare.
const FETCH_RECORD_OVERHEAD: usize = 192;

/// Processed attestmap head and pack ids, or published envelope ids.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Record {
    /// Last completely processed chain head; absent for a push cache.
    pub head: Option<Hash>,
    /// Processed packs for fetch; published attestation ids for push.
    pub ids: BTreeSet<Hash>,
    /// Whether the permanent-publication warning has been shown.
    pub warned: bool,
}

impl Record {
    /// Encode in sorted order with a checksum and a distinct record tag.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut body = format!(
            "kit-attestation-record-v1\n{}\n{}\n",
            self.head.as_ref().map_or_else(|| "-".into(), hash::to_hex),
            u8::from(self.warned)
        );
        for id in self.ids.iter().take(if self.head.is_some() {
            usize::MAX
        } else {
            PUSH_CACHE_IDS
        }) {
            body.push_str(&hash::to_hex(id));
            body.push('\n');
        }
        let checksum = hash::to_hex(&hash::hash(body.as_bytes()));
        body.push_str(&checksum);
        body.into_bytes()
    }

    /// Strict, bounded decode. Corruption invalidates the disposable cache.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        decode_with_push_limit(bytes, PUSH_CACHE_IDS)
    }
}

fn decode_with_push_limit(bytes: &[u8], push_limit: usize) -> Option<Record> {
    let text = std::str::from_utf8(bytes).ok()?;
    let (body, checksum) = text.rsplit_once('\n')?;
    let signed_len = body.len() + 1;
    if parse_lowercase_hash(checksum.as_bytes())? != hash::hash(&bytes[..signed_len]) {
        return None;
    }
    let mut lines = body.split('\n');
    if lines.next()? != "kit-attestation-record-v1" {
        return None;
    }
    let head = match lines.next()? {
        "-" => None,
        hex => Some(parse_lowercase_hash(hex.as_bytes())?),
    };
    if head.is_some() && bytes.len() > FETCH_RECORD_OVERHEAD + 65 * WALK_LIMIT {
        return None;
    }
    let warned = match lines.next()? {
        "0" => false,
        "1" => true,
        _ => return None,
    };
    let mut ids = BTreeSet::new();
    let mut previous = None;
    let mut count = 0usize;
    for line in lines {
        let id = parse_lowercase_hash(line.as_bytes())?;
        if previous.is_some_and(|old| old >= id) {
            return None;
        }
        count += 1;
        if head.is_some() && count > WALK_LIMIT {
            return None;
        }
        if head.is_some() || ids.len() < push_limit {
            ids.insert(id);
        }
        previous = Some(id);
    }
    Some(Record { head, ids, warned })
}

/// A remote cache path keyed by name, repository address and origin.
/// `push` selects published ids rather than the independent fetch record.
#[must_use]
pub fn path(
    layout: &RepoLayout,
    source: &dyn RemoteSource,
    remote: &str,
    url: &str,
    push: bool,
) -> PathBuf {
    let (repository, origin) = source.repository_address().unwrap_or_default();
    let mut key = Vec::new();
    for part in [remote, url, &repository, &origin] {
        key.extend_from_slice(&(part.len() as u64).to_le_bytes());
        key.extend_from_slice(part.as_bytes());
    }
    layout
        .applied_packs_dir()
        .join(".cursors")
        .join(hash::to_hex(&hash::hash(&key)))
        .with_extension(if push { "attest-push" } else { "attest-fetch" })
}

/// Durable global provenance marker for a fetched envelope, across all remotes.
/// Remote removal must retain these markers. A presence check (including an
/// unreadable marker) excludes the envelope from locally authored candidates.
#[must_use]
pub fn fetched_path(layout: &RepoLayout, id: &Hash) -> PathBuf {
    layout
        .attestations_dir()
        .join(".fetched")
        .join(hash::to_hex(id))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn record_roundtrip_and_corruption() {
        let record = Record {
            head: Some([2; 32]),
            ids: BTreeSet::from([[1; 32], [3; 32]]),
            warned: true,
        };
        let bytes = record.encode();
        assert_eq!(Record::decode(&bytes), Some(record));
        let mut corrupt = bytes;
        corrupt[30] ^= 1;
        assert!(Record::decode(&corrupt).is_none());
        assert!(Record::decode(&Record::default().encode()).is_some());
    }
    #[test]
    fn fetch_record_accepts_the_full_walk_and_push_exceeds_it() {
        let ids = (0..=WALK_LIMIT)
            .map(|n| {
                let mut h = [0; 32];
                h[..8].copy_from_slice(&(n as u64).to_be_bytes());
                h
            })
            .collect();
        let mut record = Record {
            head: None,
            ids,
            warned: true,
        };
        assert_eq!(Record::decode(&record.encode()), Some(record));
        record = Record {
            head: Some([1; 32]),
            ids: (0..WALK_LIMIT)
                .map(|n| {
                    let mut h = [0; 32];
                    h[..8].copy_from_slice(&(n as u64).to_be_bytes());
                    h
                })
                .collect(),
            warned: false,
        };
        assert_eq!(Record::decode(&record.encode()), Some(record));
    }

    #[test]
    fn push_pruning_preserves_the_warning_and_checks_the_whole_checksum() {
        let record = Record {
            head: None,
            ids: BTreeSet::from([[1; 32], [2; 32], [3; 32]]),
            warned: true,
        };
        let mut bytes = record.encode();
        let pruned = decode_with_push_limit(&bytes, 2).unwrap();
        assert!(pruned.warned);
        assert_eq!(pruned.ids.len(), 2);
        let last = bytes.len() - 1;
        bytes[last] = b'z';
        assert!(decode_with_push_limit(&bytes, 2).is_none());
    }

    #[test]
    fn url_is_part_of_each_cache_key() {
        use crate::source::TransportSource;
        let temp = tempfile::tempdir().unwrap();
        let layout = RepoLayout::single(temp.path());
        let transport = kit_transport_memory::MemoryTransport::new();
        let source = TransportSource::new(&transport);
        assert_ne!(
            path(&layout, &source, "origin", "kit+file:///a", true),
            path(&layout, &source, "origin", "kit+file:///b", true)
        );
        assert_ne!(
            path(&layout, &source, "origin", "kit+file:///a", true),
            path(&layout, &source, "origin", "kit+file:///a", false)
        );
    }
}
