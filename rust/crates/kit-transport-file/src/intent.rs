//! The intent record of a multi-ref commit (SPEC-REFS §5.1.3).
//!
//! A commit of several refs makes this record durable under the locks of
//! every ref it names, after it has checked every condition. The record
//! becoming durable is the commit point: from then on a reader reports
//! the new value of each named ref whose file still holds the old one, and
//! any writer that later takes one of those stripes finishes the commit
//! first.
//!
//! ```text
//! kit-ref-intent-v1\n
//! <old> <new> <name>\n      one line per ref, names strictly ascending
//! ```
//!
//! `<old>` is the ref's id when the commit checked it, as 64 lowercase hex
//! digits, or `-` when the ref was absent. `<new>` is the id it commits.
//! `<name>` is the full ref name. Anything else is refused.

use kit_core::hash::Hash;
use kit_core::refs::{MAX_REF_NAME_BYTES, parse_lowercase_hash, validate_ref_name};

/// The first line of every intent record.
const MAGIC: &[u8] = b"kit-ref-intent-v1\n";

/// The most refs one commit names (SPEC-TRANSPORT §1.3).
pub use kit_core::protocol::MAX_COMMIT_REFS;

/// The largest intent record: the magic and [`MAX_COMMIT_REFS`] lines of
/// two ids, two spaces, a name and a newline.
pub const MAX_INTENT_BYTES: usize =
    MAGIC.len() + MAX_COMMIT_REFS * (64 + 1 + 64 + 1 + MAX_REF_NAME_BYTES + 1);

/// One ref of an intent record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The full ref name.
    pub name: String,
    /// The ref's id when the commit checked it; `None` when absent.
    pub old: Option<Hash>,
    /// The id the commit writes.
    pub new: Hash,
}

/// A parsed intent record: 1 to [`MAX_COMMIT_REFS`] entries, names strictly
/// ascending.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Intent {
    entries: Vec<Entry>,
}

impl Intent {
    /// An intent of `entries`, sorted by name. `None` for no entries, more
    /// than [`MAX_COMMIT_REFS`], an invalid name or a name named twice.
    #[must_use]
    pub fn new(mut entries: Vec<Entry>) -> Option<Self> {
        if entries.is_empty() || entries.len() > MAX_COMMIT_REFS {
            return None;
        }
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        let valid = entries.iter().all(|e| validate_ref_name(&e.name))
            && entries.windows(2).all(|w| w[0].name < w[1].name);
        valid.then_some(Self { entries })
    }

    /// The entries, names ascending.
    #[must_use]
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// The entry naming `name`, if any.
    #[must_use]
    pub fn entry(&self, name: &str) -> Option<&Entry> {
        self.entries
            .binary_search_by(|e| e.name.as_str().cmp(name))
            .ok()
            .map(|i| &self.entries[i])
    }

    /// The record's bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        for e in &self.entries {
            match &e.old {
                Some(old) => out.extend_from_slice(kit_core::hash::to_hex(old).as_bytes()),
                None => out.push(b'-'),
            }
            out.push(b' ');
            out.extend_from_slice(kit_core::hash::to_hex(&e.new).as_bytes());
            out.push(b' ');
            out.extend_from_slice(e.name.as_bytes());
            out.push(b'\n');
        }
        out
    }
}

/// Parse an intent record. `None` for anything [`Intent::encode`] would
/// not produce: a wrong magic, a malformed id, an invalid name, names out
/// of order or repeated, no entries, too many, or trailing bytes.
#[must_use]
pub fn parse(bytes: &[u8]) -> Option<Intent> {
    if bytes.len() > MAX_INTENT_BYTES {
        return None;
    }
    let body = bytes.strip_prefix(MAGIC)?;
    let body = std::str::from_utf8(body).ok()?;
    let lines = body.strip_suffix('\n')?;
    let mut entries = Vec::new();
    for line in lines.split('\n') {
        if entries.len() == MAX_COMMIT_REFS {
            return None;
        }
        let mut parts = line.splitn(3, ' ');
        let (old, new, name) = (parts.next()?, parts.next()?, parts.next()?);
        let old = match old {
            "-" => None,
            hex => Some(parse_lowercase_hash(hex.as_bytes())?),
        };
        entries.push(Entry {
            name: name.to_owned(),
            old,
            new: parse_lowercase_hash(new.as_bytes())?,
        });
    }
    let intent = Intent::new(entries)?;
    (intent.encode() == bytes).then_some(intent)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, old: Option<u8>, new: u8) -> Entry {
        Entry {
            name: name.to_owned(),
            old: old.map(|b| [b; 32]),
            new: [new; 32],
        }
    }

    #[test]
    fn a_record_round_trips_with_names_sorted() {
        let intent = Intent::new(vec![
            entry("refs/kit/packmap/main", Some(1), 2),
            entry("refs/heads/main", None, 3),
        ])
        .unwrap();
        assert_eq!(intent.entries()[0].name, "refs/heads/main");
        let bytes = intent.encode();
        assert_eq!(parse(&bytes), Some(intent.clone()));
        assert_eq!(intent.entry("refs/heads/main").unwrap().new, [3; 32]);
        assert!(intent.entry("refs/heads/other").is_none());
    }

    #[test]
    fn anything_else_is_refused() {
        let good = Intent::new(vec![entry("refs/heads/a", Some(1), 2)])
            .unwrap()
            .encode();
        assert!(parse(&good).is_some());
        let mut trailing = good.clone();
        trailing.push(b'x');
        assert!(parse(&trailing).is_none());
        assert!(parse(&good[..good.len() - 1]).is_none());
        assert!(parse(MAGIC).is_none(), "no entries");
        assert!(parse(&good.to_ascii_uppercase()).is_none());
        let wrong_magic = [b"kit-ref-intent-v2\n", &good[MAGIC.len()..]].concat();
        assert!(parse(&wrong_magic).is_none());
        let bad_name = String::from_utf8(good.clone())
            .unwrap()
            .replace("refs/heads/a", "refs/heads/.a");
        assert!(parse(bad_name.as_bytes()).is_none());
        // Out of order and repeated names.
        let a = entry("refs/heads/a", None, 1);
        let b = entry("refs/heads/b", None, 1);
        let mut swapped = MAGIC.to_vec();
        for e in [&b, &a] {
            swapped
                .extend_from_slice(&Intent::new(vec![e.clone()]).unwrap().encode()[MAGIC.len()..]);
        }
        assert!(parse(&swapped).is_none());
        assert!(Intent::new(vec![a.clone(), a]).is_none());
        let many: Vec<Entry> = (0..=MAX_COMMIT_REFS)
            .map(|i| entry(&format!("refs/heads/b{i:03}"), None, 1))
            .collect();
        assert!(Intent::new(many).is_none());
    }
}
