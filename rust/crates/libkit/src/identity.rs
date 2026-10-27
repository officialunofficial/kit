//! Text forms of an object identity.
//!
//! [`short`] is for people. [`full`] is for machines, and a value that it
//! prints round-trips through the `user.identity` setting.

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
}
