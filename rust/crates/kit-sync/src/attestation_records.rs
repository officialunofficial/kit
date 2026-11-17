//! Disposable attestation synchronization records, separate from object packs.
//! Provenance is durable: its loss must never promote fetched bytes to local
//! authorship. Callers write provenance before saving a fetched envelope.

use crate::source::RemoteSource;
use kit_core::{
    hash::{self, Hash},
    layout::RepoLayout,
    refs::parse_lowercase_hash,
};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

/// Maximum packs processed during one attestation chain walk.
pub const WALK_LIMIT: usize = 100_000;
/// Total bytes downloaded during one attestation node walk.
pub const WALK_BYTES: u64 = 16 * 1024 * 1024;
/// Largest downloaded attestation pack-list node.
pub const NODE_BOUND: u64 = kit_core::transfer::packlist_node_bound(4096);

/// Most published ids retained by a push cache. Pruning preserves its warning.
pub const PUSH_CACHE_IDS: usize = 1_000_000;
/// Fixed fields including the longest head and checksum, with room to spare.
const FETCH_RECORD_OVERHEAD: usize = 192;

/// The cache role, known from its path rather than its optional checkpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordKind {
    /// Processed attestmap packs, including work before the first checkpoint.
    Fetch,
    /// Published envelope ids and the permanent-publication warning.
    Push,
}

/// Processed attestmap head and pack ids, or published envelope ids.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Record {
    /// Last completed or structurally rejected chain head; absent for push.
    pub head: Option<Hash>,
    /// Processed packs for fetch; published attestation ids for push.
    pub ids: BTreeSet<Hash>,
    /// Whether the permanent-publication warning has been shown.
    pub warned: bool,
    /// Missing subjects grouped by pack, retried only after one becomes local.
    pub pending: BTreeMap<Hash, BTreeSet<Hash>>,
}

impl Record {
    /// Encode in sorted order with a checksum and a distinct record tag.
    /// Fetch callers bound ids and pending pairs before persisting.
    #[must_use]
    pub fn encode(&self, kind: RecordKind) -> Vec<u8> {
        let mut body = format!(
            "kit-attestation-record-v2\n{}\n{}\n",
            self.head.as_ref().map_or_else(|| "-".into(), hash::to_hex),
            u8::from(self.warned)
        );
        for id in self.ids.iter().take(if kind == RecordKind::Push {
            PUSH_CACHE_IDS
        } else {
            usize::MAX
        }) {
            body.push_str(&hash::to_hex(id));
            body.push('\n');
        }
        body.push_str("pending\n");
        for (pack, subjects) in &self.pending {
            for subject in subjects {
                body.push_str(&hash::to_hex(pack));
                body.push(' ');
                body.push_str(&hash::to_hex(subject));
                body.push('\n');
            }
        }
        let checksum = hash::to_hex(&hash::hash(body.as_bytes()));
        body.push_str(&checksum);
        body.into_bytes()
    }

    /// Strict, bounded decode. Corruption invalidates the disposable cache.
    #[must_use]
    pub fn decode(bytes: &[u8], kind: RecordKind) -> Option<Self> {
        decode_with_push_limit(bytes, kind, PUSH_CACHE_IDS)
    }
}

fn decode_with_push_limit(bytes: &[u8], kind: RecordKind, push_limit: usize) -> Option<Record> {
    if kind == RecordKind::Fetch && bytes.len() > FETCH_RECORD_OVERHEAD + 195 * WALK_LIMIT {
        return None;
    }
    let text = std::str::from_utf8(bytes).ok()?;
    let (body, checksum) = text.rsplit_once('\n')?;
    let signed_len = body.len() + 1;
    if parse_lowercase_hash(checksum.as_bytes())? != hash::hash(&bytes[..signed_len]) {
        return None;
    }
    let mut lines = body.split('\n');
    if lines.next()? != "kit-attestation-record-v2" {
        return None;
    }
    let head = match lines.next()? {
        "-" => None,
        hex => Some(parse_lowercase_hash(hex.as_bytes())?),
    };
    if kind == RecordKind::Push && head.is_some() {
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
    let mut separator = false;
    for line in lines.by_ref() {
        if line == "pending" {
            separator = true;
            break;
        }
        let id = parse_lowercase_hash(line.as_bytes())?;
        if previous.is_some_and(|old| old >= id) {
            return None;
        }
        count += 1;
        if kind == RecordKind::Fetch && count > WALK_LIMIT {
            return None;
        }
        if kind == RecordKind::Fetch || ids.len() < push_limit {
            ids.insert(id);
        }
        previous = Some(id);
    }
    if !separator {
        return None;
    }
    let mut pending: BTreeMap<Hash, BTreeSet<Hash>> = BTreeMap::new();
    let mut previous = None;
    for (count, line) in lines.enumerate() {
        if kind == RecordKind::Push || count == WALK_LIMIT {
            return None;
        }
        let (pack, subject) = line.split_once(' ')?;
        let pair = (
            parse_lowercase_hash(pack.as_bytes())?,
            parse_lowercase_hash(subject.as_bytes())?,
        );
        if previous.is_some_and(|old| old >= pair) || !ids.contains(&pair.0) {
            return None;
        }
        pending.entry(pair.0).or_default().insert(pair.1);
        previous = Some(pair);
    }
    Some(Record {
        head,
        ids,
        warned,
        pending,
    })
}

/// A remote cache path keyed by name, URL, repository address, and origin.
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
            ..Record::default()
        };
        let bytes = record.encode(RecordKind::Fetch);
        assert_eq!(Record::decode(&bytes, RecordKind::Fetch), Some(record));
        let mut corrupt = bytes;
        corrupt[30] ^= 1;
        assert!(Record::decode(&corrupt, RecordKind::Fetch).is_none());
        assert!(
            Record::decode(
                &Record::default().encode(RecordKind::Fetch),
                RecordKind::Fetch
            )
            .is_some()
        );
    }
    #[test]
    fn pending_subjects_roundtrip_with_strict_order_and_bounds() {
        let record = Record {
            head: Some([4; 32]),
            ids: BTreeSet::from([[1; 32]]),
            pending: BTreeMap::from([([1; 32], BTreeSet::from([[2; 32], [3; 32]]))]),
            ..Record::default()
        };
        assert_eq!(
            Record::decode(&record.encode(RecordKind::Fetch), RecordKind::Fetch),
            Some(record.clone())
        );
        assert!(Record::decode(&record.encode(RecordKind::Push), RecordKind::Push).is_none());
        let mut invalid = record;
        invalid.ids.clear();
        assert!(Record::decode(&invalid.encode(RecordKind::Fetch), RecordKind::Fetch).is_none());
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
            ..Record::default()
        };
        assert_eq!(
            Record::decode(&record.encode(RecordKind::Push), RecordKind::Push),
            Some(record)
        );
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
            ..Record::default()
        };
        assert_eq!(
            Record::decode(&record.encode(RecordKind::Fetch), RecordKind::Fetch),
            Some(record)
        );
    }

    #[test]
    fn headless_fetch_records_still_use_fetch_bounds() {
        let record = Record {
            head: None,
            ids: (0..=WALK_LIMIT)
                .map(|n| {
                    let mut h = [0; 32];
                    h[..8].copy_from_slice(&(n as u64).to_be_bytes());
                    h
                })
                .collect(),
            warned: true,
            ..Record::default()
        };
        let bytes = record.encode(RecordKind::Fetch);
        assert!(Record::decode(&bytes, RecordKind::Fetch).is_none());
        assert_eq!(Record::decode(&bytes, RecordKind::Push), Some(record));
        let pending = Record {
            head: None,
            ids: BTreeSet::from([[1; 32]]),
            warned: false,
            ..Record::default()
        };
        assert_eq!(
            Record::decode(&pending.encode(RecordKind::Fetch), RecordKind::Fetch),
            Some(pending)
        );
    }

    #[test]
    fn push_pruning_preserves_the_warning_and_checks_the_whole_checksum() {
        let record = Record {
            head: None,
            ids: BTreeSet::from([[1; 32], [2; 32], [3; 32]]),
            warned: true,
            ..Record::default()
        };
        let mut bytes = record.encode(RecordKind::Push);
        let pruned = decode_with_push_limit(&bytes, RecordKind::Push, 2).unwrap();
        assert!(pruned.warned);
        assert_eq!(pruned.ids.len(), 2);
        let last = bytes.len() - 1;
        bytes[last] = b'z';
        assert!(decode_with_push_limit(&bytes, RecordKind::Push, 2).is_none());
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
