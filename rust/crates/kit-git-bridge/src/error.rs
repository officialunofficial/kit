//! Bridge error taxonomy.
//!
//! [`Refusal`] is the closed set of *policy* refusals from
//! SPEC-GIT-BRIDGE (§4, §6.2, §7.1, §8, §12.1): the object or ref is
//! valid kit data that the v1 mapping deliberately does not
//! translate. Everything else is a hard error.

use kit_core::Hash;
use kit_core::hash::to_hex;
use std::fmt;

/// A deliberate, spec'd refusal to translate (actionable; per-ref
/// granularity is the caller's job).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Refusal {
    /// Remix objects are not translated in v1 (SPEC-GIT-BRIDGE §8).
    Remix { object: Hash },
    /// Fixed-size chunked-blob manifests have no exact inverse
    /// (SPEC-GIT-BRIDGE §4).
    FixedSizeChunking { object: Hash, chunk_size: u32 },
    /// Content-defined manifest a conformant kit writer cannot have
    /// produced (≤ threshold total size, or boundaries that differ
    /// from the pinned `FastCDC` output) — it would not round-trip
    /// (SPEC-GIT-BRIDGE §4).
    NonCanonicalChunking { object: Hash, detail: &'static str },
    /// Commit/tag timestamp exceeds `i64::MAX` (SPEC-GIT-BRIDGE §6.2).
    TimestampOverflow { object: Hash, timestamp: u64 },
    /// Tag object name contains bytes outside the kit ref grammar
    /// (SPEC-GIT-BRIDGE §7.1).
    TagName { object: Hash },
    /// Ref name is kit-legal but git-illegal (SPEC-GIT-BRIDGE §12.1).
    RefName { name: String, reason: &'static str },
    /// Object prologue carries a schema version this mapping does not
    /// cover (SPEC-GIT-BRIDGE §1.2).
    SchemaVersion { object: Hash },
    /// Import: submodule gitlink entry (SPEC-GIT-IMPORT §3.3). The
    /// `object` is the zero-padded git tree sha1.
    Gitlink { object: Hash, path: String },
    /// Import: git tree-entry name kit cannot store (SPEC-OBJECTS
    /// §4.1 deserialize-time rules).
    TreeEntryName { object: Hash, name: String },
    /// Import: a git tree mode outside the pinned §3.3 table.
    UnknownTreeMode { object: Hash, mode: String },
    /// Import: a historic mode would normalize, but the state dir is
    /// fork-mode (normalization breaks shared-SHA passthrough).
    NormalizedModeInFork { object: Hash, mode: String },
    /// Import: pre-1970 git timestamp (kit timestamps are u64).
    NegativeTimestamp { object: Hash, timestamp: i64 },
    /// Import: structurally unparsable git object (SPEC-GIT-IMPORT
    /// §3.2/§3.5 — refused per-ref, never coerced).
    Unparsable { object: Hash, detail: String },
    /// A blob over the 1 GiB per-file cap: a git blob on import
    /// (SPEC-GIT-IMPORT §3.1) or a chunked blob on export (SPEC-GIT-BRIDGE
    /// §4).
    BlobTooLarge { object: Hash, size: u64 },
    /// Import: git tree with more entries than kit's decode cap —
    /// storing it would poison a signed object the store can never
    /// read back (SPEC-GIT-IMPORT §3.3).
    TooManyTreeEntries { object: Hash, count: usize },
    /// Import: a tree entry's git mode contradicts the actual kind of
    /// the object it names (e.g. mode 100644 → a commit). git tools
    /// barely tolerate these; kit's object model cannot represent
    /// them (SPEC-GIT-IMPORT §3.3).
    TreeEntryKind { object: Hash, name: String },
    /// Import: the translated object cannot serialize under
    /// SPEC-OBJECTS caps (oversize payload, illegal field) — refused
    /// per-ref rather than failing the whole run.
    Unrepresentable { object: Hash, detail: String },
    /// Import: more than 1000 parents (`MAX_PARENTS`).
    TooManyParents { object: Hash },
    /// Import: author/tagger identity payload empty or over 4096.
    AuthorPayload { object: Hash },
    /// Import: tag→tag chain beyond the pinned depth (16).
    TagChain { object: Hash },
    /// Import: duplicate entry names after re-sorting to kit order
    /// (git-representable as file+dir of one name; undecodable here).
    DuplicateTreeEntry { object: Hash },
    /// Import: tree nesting beyond `MAX_TREE_DEPTH` (128).
    TreeTooDeep { object: Hash },
}

impl fmt::Display for Refusal {
    #[allow(clippy::too_many_lines)] // one arm per refusal; flat by design
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Remix { object } => write!(
                f,
                "remix object {} is not translatable in bridge v1 (SPEC-GIT-BRIDGE §8)",
                to_hex(object)
            ),
            Self::FixedSizeChunking { object, chunk_size } => write!(
                f,
                "chunked blob {} uses fixed-size chunking ({chunk_size}); only \
                 content-defined manifests translate (SPEC-GIT-BRIDGE §4)",
                to_hex(object)
            ),
            Self::NonCanonicalChunking { object, detail } => write!(
                f,
                "chunked blob {} cannot have been produced by a conformant \
                 kit writer ({detail}); refusing a non-round-trippable \
                 translation (SPEC-GIT-BRIDGE §4)",
                to_hex(object)
            ),
            Self::TimestampOverflow { object, timestamp } => write!(
                f,
                "object {} timestamp {timestamp} exceeds the git-representable range",
                to_hex(object)
            ),
            Self::TagName { object } => write!(
                f,
                "tag object {} has a name outside the kit ref grammar; \
                 it cannot ride in a git tag header",
                to_hex(object)
            ),
            Self::RefName { name, reason } => {
                write!(f, "ref {name:?} is not a legal git ref name ({reason})")
            }
            Self::SchemaVersion { object } => write!(
                f,
                "object {} has a schema_version other than 1; bridge v1 maps schema 1 only",
                to_hex(object)
            ),
            Self::Gitlink { object, path } => write!(
                f,
                "git tree {} contains a submodule gitlink at {path:?}; submodules are out \
                 of scope (vendor the submodule, or exclude this ref) — SPEC-GIT-IMPORT §3.3",
                &to_hex(object)[..40]
            ),
            Self::TreeEntryName { object, name } => write!(
                f,
                "git tree {} entry {name:?} is not a storable kit name (SPEC-OBJECTS §4.1); \
                 rename it upstream or exclude this ref",
                &to_hex(object)[..40]
            ),
            Self::UnknownTreeMode { object, mode } => write!(
                f,
                "git tree {} carries mode {mode} outside the import mapping (SPEC-GIT-IMPORT §3.3)",
                &to_hex(object)[..40]
            ),
            Self::NormalizedModeInFork { object, mode } => write!(
                f,
                "git tree {} carries historic mode {mode}, which would normalize lossily; \
                 this state dir is fork-mode, where normalized trees cannot reproduce their \
                 original sha1 — refusing (SPEC-GIT-IMPORT §3.3)",
                &to_hex(object)[..40]
            ),
            Self::Unparsable { object, detail } => write!(
                f,
                "git object {} is structurally unparsable ({detail}); refused per SPEC-GIT-IMPORT §3.2",
                &to_hex(object)[..40]
            ),
            Self::TooManyTreeEntries { object, count } => write!(
                f,
                "git tree {} has {count} entries, over kit's decode cap (SPEC-GIT-IMPORT §3.3)",
                &to_hex(object)[..40]
            ),
            Self::TreeEntryKind { object, name } => write!(
                f,
                "git tree {} entry {name:?} names an object of a kind its mode contradicts (SPEC-GIT-IMPORT §3.3)",
                &to_hex(object)[..40]
            ),
            Self::Unrepresentable { object, detail } => write!(
                f,
                "git object {} does not serialize under SPEC-OBJECTS ({detail}); refused per SPEC-GIT-IMPORT §3",
                &to_hex(object)[..40]
            ),
            Self::BlobTooLarge { object, size } => write!(
                f,
                "blob {} is {size} bytes, over the 1 GiB per-file cap of the git bridge",
                &to_hex(object)[..40]
            ),
            Self::NegativeTimestamp { object, timestamp } => write!(
                f,
                "git object {} has pre-1970 timestamp {timestamp}; kit timestamps are unsigned",
                &to_hex(object)[..40]
            ),
            Self::TooManyParents { object } => write!(
                f,
                "git commit {} has more than 1000 parents (MAX_PARENTS)",
                &to_hex(object)[..40]
            ),
            Self::AuthorPayload { object } => write!(
                f,
                "git object {} has an author/tagger identity that is empty or over 4096 bytes",
                &to_hex(object)[..40]
            ),
            Self::TagChain { object } => write!(
                f,
                "git tag {} heads a tag chain deeper than 16; refusing (SPEC-GIT-IMPORT §3.4)",
                &to_hex(object)[..40]
            ),
            Self::DuplicateTreeEntry { object } => write!(
                f,
                "git tree {} contains entries whose names collide byte-equal in kit \
                 order (e.g. a file and a directory of one name); refusing",
                &to_hex(object)[..40]
            ),
            Self::TreeTooDeep { object } => write!(
                f,
                "git tree {} nests deeper than 128 levels; refusing (matches kit's \
                 MAX_TREE_DEPTH defense)",
                &to_hex(object)[..40]
            ),
        }
    }
}

/// Unified bridge error.
#[derive(Debug)]
pub enum BridgeError {
    /// A spec'd policy refusal (see [`Refusal`]).
    Refused(Refusal),
    /// Reading or decoding a source kit object failed.
    Source(String),
    /// Reconstruction input is not a bridge-emitted git object
    /// (missing/duplicate/unknown `kit-*` headers, malformed body,
    /// non-bridge mode bytes, …).
    NotBridgeObject(String),
    /// Reconstructed bytes failed an integrity check (BLAKE3 linkage
    /// or round-trip mismatch).
    Integrity(String),
    /// Filesystem error from the loose-object writer or map cache.
    Io(std::io::Error),
}

impl fmt::Display for BridgeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(r) => write!(f, "refused: {r}"),
            Self::Source(m) => write!(f, "source object: {m}"),
            Self::NotBridgeObject(m) => write!(f, "not a bridge-emitted git object: {m}"),
            Self::Integrity(m) => write!(f, "integrity: {m}"),
            Self::Io(e) => write!(f, "io: {e}"),
        }
    }
}

impl std::error::Error for BridgeError {}

impl From<std::io::Error> for BridgeError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<Refusal> for BridgeError {
    fn from(r: Refusal) -> Self {
        Self::Refused(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OBJECT: Hash = [0xab; 32];

    /// Every refusal names the object or ref it refuses and the detail that
    /// tells the user what to change.
    #[test]
    #[allow(clippy::too_many_lines)] // one case per refusal; flat by design
    fn every_refusal_names_what_it_refuses_and_why() {
        let object = to_hex(&OBJECT);
        let cases = [
            (Refusal::Remix { object: OBJECT }, vec!["remix", "§8"]),
            (
                Refusal::FixedSizeChunking {
                    object: OBJECT,
                    chunk_size: 4096,
                },
                vec!["fixed-size chunking (4096)"],
            ),
            (
                Refusal::NonCanonicalChunking {
                    object: OBJECT,
                    detail: "bad boundary",
                },
                vec!["(bad boundary)"],
            ),
            (
                Refusal::TimestampOverflow {
                    object: OBJECT,
                    timestamp: u64::MAX,
                },
                vec!["18446744073709551615"],
            ),
            (Refusal::TagName { object: OBJECT }, vec!["ref grammar"]),
            (
                Refusal::RefName {
                    name: "a..b".into(),
                    reason: "double dot",
                },
                vec!["\"a..b\"", "(double dot)"],
            ),
            (
                Refusal::SchemaVersion { object: OBJECT },
                vec!["schema_version"],
            ),
            (
                Refusal::Gitlink {
                    object: OBJECT,
                    path: "vendor/lib".into(),
                },
                vec!["\"vendor/lib\"", "gitlink"],
            ),
            (
                Refusal::TreeEntryName {
                    object: OBJECT,
                    name: "bad\u{1}name".into(),
                },
                vec!["storable kit name"],
            ),
            (
                Refusal::UnknownTreeMode {
                    object: OBJECT,
                    mode: "160000x".into(),
                },
                vec!["mode 160000x"],
            ),
            (
                Refusal::NormalizedModeInFork {
                    object: OBJECT,
                    mode: "100664".into(),
                },
                vec!["mode 100664", "fork-mode"],
            ),
            (
                Refusal::NegativeTimestamp {
                    object: OBJECT,
                    timestamp: -5,
                },
                vec!["timestamp -5"],
            ),
            (
                Refusal::Unparsable {
                    object: OBJECT,
                    detail: "short header".into(),
                },
                vec!["(short header)"],
            ),
            (
                Refusal::BlobTooLarge {
                    object: OBJECT,
                    size: 1 << 31,
                },
                vec!["2147483648 bytes"],
            ),
            (
                Refusal::TooManyTreeEntries {
                    object: OBJECT,
                    count: 99,
                },
                vec!["99 entries"],
            ),
            (
                Refusal::TreeEntryKind {
                    object: OBJECT,
                    name: "odd".into(),
                },
                vec!["\"odd\""],
            ),
            (
                Refusal::Unrepresentable {
                    object: OBJECT,
                    detail: "too big".into(),
                },
                vec!["(too big)"],
            ),
            (
                Refusal::TooManyParents { object: OBJECT },
                vec!["1000 parents"],
            ),
            (
                Refusal::AuthorPayload { object: OBJECT },
                vec!["4096 bytes"],
            ),
            (Refusal::TagChain { object: OBJECT }, vec!["deeper than 16"]),
            (
                Refusal::DuplicateTreeEntry { object: OBJECT },
                vec!["collide"],
            ),
            (Refusal::TreeTooDeep { object: OBJECT }, vec!["128 levels"]),
        ];
        for (refusal, details) in cases {
            let message = refusal.to_string();
            if !matches!(refusal, Refusal::RefName { .. }) {
                assert!(
                    message.contains(&object[..40]),
                    "{refusal:?} does not name its object: {message}"
                );
            }
            for detail in details {
                assert!(
                    message.contains(detail),
                    "{refusal:?} does not say {detail:?}: {message}"
                );
            }
        }
    }

    #[test]
    fn a_bridge_error_prefixes_the_refusal_it_carries() {
        let error = BridgeError::from(Refusal::Remix { object: OBJECT });
        assert!(error.to_string().starts_with("refused: remix object "));
    }
}
