//! Text forms of an object identity.
//!
//! [`short`] is for people. [`full`] is for machines, and a value that it
//! prints round-trips through the `user.identity` setting.
//!
//! [`parse_author`] reads the text of an author flag. [`decode_config`] reads
//! the value of the `user.identity` setting. [`resolve_author`] picks between
//! them and the key that signs.

use kit_core::{Identity, IdentityKind};

/// A DID key is shown as this prefix plus its first characters.
const DID_KEY_PREVIEW_CHARS: usize = 8;

/// A binary identity is shown as its kind plus this many leading bytes.
const BINARY_PREVIEW_BYTES: usize = 4;

/// The short form of `id`.
///
/// - An opaque key of 8 bytes shows as a little-endian decimal number.
/// - A DID key shows as `did:key:` plus a prefix of its payload.
/// - An opaque payload that is printable text shows as that text. An
///   imported git `Name <email>` is one example.
/// - Any other identity shows as `<kind>:<8 hex characters>`.
#[must_use]
pub fn short(id: &Identity) -> String {
    match id.kind {
        IdentityKind::Opaque if id.bytes.len() == 8 => u64_text(&id.bytes),
        IdentityKind::DidKey => {
            let text = String::from_utf8_lossy(&id.bytes);
            let prefix: String = text.chars().take(DID_KEY_PREVIEW_CHARS).collect();
            format!("did:key:{prefix}")
        }
        IdentityKind::Opaque if printable_text(&id.bytes).is_some() => {
            printable_text(&id.bytes).unwrap_or_default().to_owned()
        }
        kind => {
            let kind_name = match kind {
                IdentityKind::Ed25519 => "ed25519",
                IdentityKind::DidKey => "did:key",
                IdentityKind::Opaque => "opaque",
            };
            let take = id.bytes.len().min(BINARY_PREVIEW_BYTES);
            format!("{kind_name}:{}", to_hex(&id.bytes[..take]))
        }
    }
}

/// The full form of `id`.
///
/// - An opaque key of 8 bytes shows as `mid:<decimal>`.
/// - An Ed25519 key shows as `ed25519:<64 hex characters>`.
/// - A DID key shows as `did:key:<payload>`.
/// - Any other opaque payload shows as `opaque:<hex>`.
#[must_use]
pub fn full(id: &Identity) -> String {
    match id.kind {
        IdentityKind::Opaque if id.bytes.len() == 8 => format!("mid:{}", u64_text(&id.bytes)),
        IdentityKind::Ed25519 => format!("ed25519:{}", to_hex(&id.bytes)),
        IdentityKind::DidKey => format!("did:key:{}", String::from_utf8_lossy(&id.bytes)),
        IdentityKind::Opaque => format!("opaque:{}", to_hex(&id.bytes)),
    }
}

/// Errors from reading an identity.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseError {
    /// The hex of an `ed25519:` identity is not hex.
    #[error("ed25519:<hex> invalid hex")]
    BadHex,
    /// An `ed25519:` identity is not 32 bytes.
    #[error("ed25519:<hex> must decode to 32 bytes")]
    BadKeyLength,
    /// A `did:key:` payload is not a printable multibase string.
    #[error(
        "did:key:<multibase> must be a non-empty printable-ASCII multibase string (e.g. did:key:z6Mk…)"
    )]
    BadDidKey,
    /// An `opaque:` identity has no bytes.
    #[error("opaque:<bytes> must not be empty")]
    EmptyOpaque,
    /// The text has no known scheme.
    #[error(
        "unknown identity spec '{0}' — expected ed25519:<hex>, did:key:<multibase>, or opaque:<bytes>"
    )]
    UnknownSpec(String),
    /// The `user.identity` value is not lowercase hex.
    #[error("user.identity: not a lowercase hex string")]
    ConfigNotHex,
    /// The `user.identity` value has no room for the kind and the length.
    #[error("user.identity: too short (kind + len prefix missing)")]
    ConfigTooShort,
    /// The length in the `user.identity` value is not the payload length.
    #[error("user.identity: declared length does not match payload")]
    ConfigLengthMismatch,
    /// The kind byte of the `user.identity` value is unknown.
    #[error("user.identity: unknown kind byte {0:#04x}")]
    ConfigUnknownKind(u8),
    /// The Ed25519 payload of the `user.identity` value is not 32 bytes.
    #[error("user.identity: ed25519 payload must be exactly 32 bytes")]
    ConfigBadKeyLength,
}

/// Read the text of an author flag.
///
/// - `ed25519:<64 hex characters>` is a 32-byte Ed25519 key.
/// - `did:key:<multibase>` is a DID key. The payload after `did:key:` is kept
///   as it is. It must be a non-empty printable ASCII string, as the on-disk
///   form requires.
/// - `opaque:<bytes>` is raw UTF-8 bytes, kept as they are.
///
/// # Errors
/// [`ParseError`] for text that is none of these.
pub fn parse_author(spec: &str) -> Result<Identity, ParseError> {
    if let Some(hex) = spec.strip_prefix("ed25519:") {
        let bytes = kit_core::hash::from_hex_bytes(hex).ok_or(ParseError::BadHex)?;
        let key: [u8; 32] = bytes.try_into().map_err(|_| ParseError::BadKeyLength)?;
        return Ok(Identity::ed25519(key));
    }
    if let Some(payload) = spec.strip_prefix("did:key:") {
        let id = Identity {
            kind: IdentityKind::DidKey,
            bytes: payload.as_bytes().to_vec(),
        };
        return if id.is_valid() {
            Ok(id)
        } else {
            Err(ParseError::BadDidKey)
        };
    }
    if let Some(raw) = spec.strip_prefix("opaque:") {
        if raw.is_empty() {
            return Err(ParseError::EmptyOpaque);
        }
        return Ok(Identity::opaque(raw.as_bytes().to_vec()));
    }
    Err(ParseError::UnknownSpec(spec.to_owned()))
}

/// Read the value of the `user.identity` setting. It holds the canonical form
/// `[kind: u8][length: u16 little endian][bytes]` as lowercase hex.
///
/// # Errors
/// [`ParseError`] when the value is not that form.
pub fn decode_config(hex: &str) -> Result<Identity, ParseError> {
    let bytes = kit_core::hash::from_hex_bytes(hex).ok_or(ParseError::ConfigNotHex)?;
    if bytes.len() < 3 {
        return Err(ParseError::ConfigTooShort);
    }
    let kind_byte = bytes[0];
    let declared_len = u16::from(bytes[1]) | (u16::from(bytes[2]) << 8);
    if bytes.len() != usize::from(declared_len) + 3 {
        return Err(ParseError::ConfigLengthMismatch);
    }
    let payload = bytes[3..].to_vec();
    let kind = match kind_byte {
        0x01 => IdentityKind::Ed25519,
        0x02 => IdentityKind::DidKey,
        // 0x03 is the older kind of a machine identity. It shares the opaque
        // variant.
        0x03 | 0x04 => IdentityKind::Opaque,
        other => return Err(ParseError::ConfigUnknownKind(other)),
    };
    if kind == IdentityKind::Ed25519 && payload.len() != 32 {
        return Err(ParseError::ConfigBadKeyLength);
    }
    Ok(Identity {
        kind,
        bytes: payload,
    })
}

/// The author of a commit or a tag.
///
/// The author flag wins. Then comes the `user.identity` setting, and then the
/// identity that the public key of the signer makes. A caller with no flag
/// passes `None`.
///
/// # Errors
/// [`ParseError`] from the first source that applies.
pub fn resolve_author(
    author_flag: Option<&str>,
    config_user_identity: &str,
    signer_public: &[u8; 32],
) -> Result<Identity, ParseError> {
    if let Some(spec) = author_flag {
        return parse_author(spec);
    }
    if !config_user_identity.is_empty() {
        return decode_config(config_user_identity);
    }
    Ok(Identity::ed25519(*signer_public))
}

/// The decimal text of 8 little-endian bytes. The caller checks the length.
fn u64_text(bytes: &[u8]) -> String {
    let mut array = [0u8; 8];
    array.copy_from_slice(bytes);
    u64::from_le_bytes(array).to_string()
}

/// The payload as text when it is valid UTF-8 with no control character.
/// Such text is safe to print to a terminal.
fn printable_text(bytes: &[u8]) -> Option<&str> {
    let text = std::str::from_utf8(bytes).ok()?;
    (!text.is_empty() && !text.chars().any(char::is_control)).then_some(text)
}

fn to_hex(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(ALPHABET[usize::from(byte >> 4)] as char);
        out.push(ALPHABET[usize::from(byte & 0x0F)] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(kind: IdentityKind, bytes: &[u8]) -> Identity {
        Identity {
            kind,
            bytes: bytes.to_vec(),
        }
    }

    #[test]
    fn an_eight_byte_opaque_key_is_a_decimal_number() {
        let id = identity(IdentityKind::Opaque, &42u64.to_le_bytes());
        assert_eq!(short(&id), "42");
        assert_eq!(full(&id), "mid:42");
    }

    #[test]
    fn an_ed25519_key_keeps_four_bytes_in_the_short_form() {
        let id = identity(IdentityKind::Ed25519, &[0xab; 32]);
        assert_eq!(short(&id), "ed25519:abababab");
        assert_eq!(full(&id), format!("ed25519:{}", "ab".repeat(32)));
    }

    #[test]
    fn a_did_key_shows_a_prefix_in_the_short_form() {
        let id = identity(IdentityKind::DidKey, b"z6MkExampleKey");
        assert_eq!(short(&id), "did:key:z6MkExam");
        assert_eq!(full(&id), "did:key:z6MkExampleKey");
    }

    #[test]
    fn printable_opaque_text_shows_as_text() {
        let id = identity(IdentityKind::Opaque, b"Ada <ada@example.org>");
        assert_eq!(short(&id), "Ada <ada@example.org>");
        assert_eq!(
            full(&id),
            format!("opaque:{}", to_hex(b"Ada <ada@example.org>"))
        );
    }

    #[test]
    fn binary_opaque_data_shows_as_hex() {
        let id = identity(IdentityKind::Opaque, &[0, 1, 2, 3, 4]);
        assert_eq!(short(&id), "opaque:00010203");
        assert_eq!(full(&id), "opaque:0001020304");
    }

    #[test]
    fn an_empty_opaque_payload_is_not_printable_text() {
        let id = identity(IdentityKind::Opaque, b"");
        assert_eq!(short(&id), "opaque:");
        assert_eq!(full(&id), "opaque:");
    }

    #[test]
    fn a_control_character_blocks_the_text_form() {
        let id = identity(IdentityKind::Opaque, b"a\x1bb");
        assert_eq!(short(&id), "opaque:611b62");
    }

    #[test]
    fn an_author_flag_has_three_schemes() {
        let hex = "11".repeat(32);
        let id = parse_author(&format!("ed25519:{hex}")).unwrap();
        assert_eq!(id, Identity::ed25519([0x11; 32]));
        let id = parse_author("did:key:z6MkExample").unwrap();
        assert_eq!(
            (id.kind, id.bytes.as_slice()),
            (IdentityKind::DidKey, &b"z6MkExample"[..])
        );
        let id = parse_author("opaque:hello world").unwrap();
        assert_eq!(id, Identity::opaque(b"hello world".to_vec()));
    }

    #[test]
    fn an_author_flag_that_is_malformed_is_an_error() {
        assert_eq!(parse_author("ed25519:zzzz"), Err(ParseError::BadHex));
        assert_eq!(parse_author("ed25519:short"), Err(ParseError::BadHex));
        assert_eq!(parse_author("ed25519:abcd"), Err(ParseError::BadKeyLength));
        assert_eq!(parse_author("did:key:"), Err(ParseError::BadDidKey));
        assert_eq!(
            parse_author("did:key:has space"),
            Err(ParseError::BadDidKey)
        );
        assert_eq!(parse_author("opaque:"), Err(ParseError::EmptyOpaque));
        assert_eq!(
            parse_author("foo:bar"),
            Err(ParseError::UnknownSpec("foo:bar".to_owned()))
        );
        assert_eq!(
            parse_author(""),
            Err(ParseError::UnknownSpec(String::new()))
        );
    }

    #[test]
    fn the_config_value_is_the_kind_the_length_and_the_bytes() {
        let value = format!("012000{}", "ab".repeat(32));
        assert_eq!(
            decode_config(&value).unwrap(),
            Identity::ed25519([0xab; 32])
        );
        assert_eq!(decode_config("zz"), Err(ParseError::ConfigNotHex));
        assert_eq!(decode_config("0120"), Err(ParseError::ConfigTooShort));
        assert_eq!(
            decode_config("011000aabbcc"),
            Err(ParseError::ConfigLengthMismatch)
        );
        assert_eq!(
            decode_config("090100aa"),
            Err(ParseError::ConfigUnknownKind(9))
        );
        assert_eq!(
            decode_config("010100aa"),
            Err(ParseError::ConfigBadKeyLength)
        );
        assert_eq!(
            decode_config("030200aabb").unwrap().kind,
            IdentityKind::Opaque
        );
    }

    #[test]
    fn the_flag_wins_over_the_config_and_the_config_over_the_key() {
        let key = [7u8; 32];
        let flag = format!("ed25519:{}", "22".repeat(32));
        let config = format!("012000{}", "33".repeat(32));
        assert_eq!(
            resolve_author(Some(&flag), &config, &key).unwrap(),
            Identity::ed25519([0x22; 32])
        );
        assert_eq!(
            resolve_author(None, &config, &key).unwrap(),
            Identity::ed25519([0x33; 32])
        );
        assert_eq!(
            resolve_author(None, "", &key).unwrap(),
            Identity::ed25519(key)
        );
    }
}
