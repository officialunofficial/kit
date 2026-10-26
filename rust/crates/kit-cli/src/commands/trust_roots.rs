//! Shared trust-roots TOML file model.
//!
//! Three call sites read/write the same `[[trust_root]]` file format:
//! `kit trust {add,list,remove}` (`commands/trust.rs`), `kit verify
//! --trusted`/`--trust-roots` (`commands/verify.rs`), and `kit
//! verify-attest --trust-roots` (`commands/verify_attest.rs`). This
//! module owns the parser, the writer, and the repo-local path-fencing
//! policy so none of the three grow a second trust-file format.
//!
//! Grammar (a strict subset of TOML):
//!
//! ```toml
//! [[trust_root]]
//! keyid = "ed25519:..."
//! kind  = "ed25519"
//! pubkey_hex = "..."
//! ```
//!
//! * `kind` is one of `ed25519`, `secp256k1` (alias `secp256k1-sec1`) or
//!   `p256-sec1` (alias `p256`). Any other value is an error. The
//!   default is `ed25519`.
//! * `algorithm` is accepted as an alias for `kind`. A block must not
//!   set both.
//! * `pubkey_hex` is the raw public key bytes in hex. The length must
//!   fit `kind`.
//! * Every value is a plain double-quoted string.
//!
//! The parser fails closed. An unknown key, a repeated key, a line
//! outside a block, an unquoted value, bad hex, a keyid that does not
//! match its key or a repeated keyid is an error for the whole file.
//! Comments (`#`) and blank lines are the only text it skips. A missing
//! file parses to zero entries — the caller's documented "no
//! trust-roots configured" UX.

use std::io::Write;
use std::path::{Path, PathBuf};

use kit_attest::{Registry, TrustRoot};

use crate::exit;

/// One validated `[[trust_root]]` block: hex-decoded is deferred to
/// the consumer (registry build / commit-signer compare) so callers
/// that only need to list or rewrite the file never touch key bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustEntry {
    pub keyid: String,
    pub kind: String,
    pub pubkey_hex: String,
}

/// Resolve the user-scoped default trust-roots path:
/// `$XDG_CONFIG_HOME/kit/trust-roots.toml`.
///
/// # Errors
/// As [`crate::config::xdg_config_home`].
pub fn default_trust_roots_path() -> Result<PathBuf, String> {
    crate::config::xdg_config_home().map(|d| d.join("kit/trust-roots.toml"))
}

/// Resolve the trust-roots path: the `--trust-roots` value when given,
/// else the user-scoped default. Print the reason and return the config
/// exit code when no default path exists.
pub fn resolve_trust_roots_path(flag: Option<&str>) -> Result<PathBuf, u8> {
    match flag {
        Some(p) => Ok(PathBuf::from(p)),
        None => default_trust_roots_path().map_err(|e| super::error(&e, exit::CONFIG_ERROR)),
    }
}

/// Refuse to operate on an in-repo trust-roots file unless the user
/// passed `--trust-roots` explicitly. Without this gate, a hostile
/// cloned repo could ship `<repo>/.kit/trust-roots.toml` listing
/// attacker keys and a trust-consuming command would trust it
/// implicitly. See `docs/THREAT-MODEL.md` §5 "Trust-roots scope".
pub fn warn_if_unsafe_trust_roots(
    trust_path: &Path,
    kit_dir: &Path,
    user_provided_flag: bool,
) -> Result<(), u8> {
    if user_provided_flag {
        return Ok(());
    }
    if trust_path.starts_with(kit_dir) {
        return Err(super::error(
            &format!(
                "refusing to use in-repo trust-roots at {} — pass `--trust-roots` \
                 explicitly or move the file to {}",
                trust_path.display(),
                default_trust_roots_path().map_or_else(
                    |_| "the user config directory".to_owned(),
                    |p| p.display().to_string()
                )
            ),
            exit::CONFIG_ERROR,
        ));
    }
    Ok(())
}

/// Print a hint (not an error) when a trust-roots path passed a safety
/// check but the file doesn't exist yet. An empty registry means every
/// signer check will fail closed; the caller's own report loop covers
/// the substance, this is just so a first-time user isn't left
/// wondering why nothing verified.
pub fn note_if_missing(trust_path: &Path) {
    if !trust_path.exists() {
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(
            stderr,
            "note: trust-roots file not found at {} — no keys loaded",
            trust_path.display()
        );
    }
}

/// Parse the trust-roots file text. The file is a trust anchor, so the
/// parser fails closed. It returns an error for the first line it cannot
/// accept: an unknown key, a duplicate key, an unquoted value, a line
/// outside a block, a bad `kind`, bad hex, a wrong key length, a keyid
/// that does not match its key, or a repeated keyid. It never drops an
/// entry.
pub fn parse(text: &str) -> Result<Vec<TrustEntry>, String> {
    let mut out: Vec<TrustEntry> = Vec::new();
    let mut block: Option<Block> = None;

    for (idx, raw) in text.lines().enumerate() {
        let n = idx + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line == "[[trust_root]]" {
            if let Some(b) = block.take() {
                push_entry(b, &mut out)?;
            }
            block = Some(Block::new(n));
            continue;
        }
        let Some(b) = block.as_mut() else {
            return Err(format!("line {n}: text outside a [[trust_root]] block"));
        };
        let Some((k, v)) = line.split_once('=') else {
            return Err(format!("line {n}: expected `key = \"value\"`"));
        };
        let key = k.trim();
        let val = unquote(v.trim()).ok_or_else(|| {
            format!("line {n}: the value of `{key}` must be a plain double-quoted string")
        })?;
        let slot = match key {
            "keyid" => &mut b.keyid,
            "kind" | "algorithm" => &mut b.kind,
            "pubkey_hex" => &mut b.pubkey_hex,
            _ => return Err(format!("line {n}: unknown key `{key}`")),
        };
        if slot.is_some() {
            return Err(format!("line {n}: key `{key}` is set twice in one block"));
        }
        *slot = Some(val.to_owned());
    }
    if let Some(b) = block.take() {
        push_entry(b, &mut out)?;
    }
    Ok(out)
}

/// The fields of one `[[trust_root]]` block while the parser reads it.
struct Block {
    line: usize,
    keyid: Option<String>,
    kind: Option<String>,
    pubkey_hex: Option<String>,
}

impl Block {
    fn new(line: usize) -> Self {
        Self {
            line,
            keyid: None,
            kind: None,
            pubkey_hex: None,
        }
    }
}

/// Return the text between one pair of double quotes. Reject any other
/// shape: no quotes, a trailing comment, an escape or an inner quote.
fn unquote(v: &str) -> Option<&str> {
    let inner = v.strip_prefix('"')?.strip_suffix('"')?;
    if inner.contains(['"', '\\']) {
        return None;
    }
    Some(inner)
}

/// Is `pubkey_len` a valid byte length for a key of this `kind`?
fn key_length_ok(kind: &str, pubkey_len: usize) -> bool {
    match kind {
        "ed25519" => pubkey_len == 32,
        "secp256k1" | "secp256k1-sec1" | "p256-sec1" | "p256" => {
            pubkey_len == 33 || pubkey_len == 65
        }
        _ => false,
    }
}

fn push_entry(b: Block, out: &mut Vec<TrustEntry>) -> Result<(), String> {
    let at = b.line;
    let keyid = b
        .keyid
        .filter(|k| !k.is_empty())
        .ok_or_else(|| format!("block at line {at}: missing `keyid`"))?;
    let pubkey_hex = b
        .pubkey_hex
        .filter(|k| !k.is_empty())
        .ok_or_else(|| format!("block at line {at}: missing `pubkey_hex`"))?;
    let kind = b.kind.unwrap_or_else(|| "ed25519".to_owned());
    let Some(pk_bytes) = hex_decode(&pubkey_hex) else {
        return Err(format!("block at line {at}: `pubkey_hex` is not valid hex"));
    };
    if !key_length_ok(&kind, pk_bytes.len()) {
        return Err(format!(
            "block at line {at}: unknown `kind` or wrong key length for `{kind}`"
        ));
    }
    if !keyid_matches_pubkey(&keyid, &pk_bytes) {
        return Err(format!(
            "block at line {at}: keyid '{}' does not match its pubkey_hex",
            short_keyid(&keyid)
        ));
    }
    if out.iter().any(|e| e.keyid == keyid) {
        return Err(format!(
            "block at line {at}: keyid '{}' appears twice",
            short_keyid(&keyid)
        ));
    }
    out.push(TrustEntry {
        keyid,
        kind,
        pubkey_hex,
    });
    Ok(())
}

/// Load and parse the trust-roots file at `path`. A missing file
/// parses to an empty list (not an error).
pub fn load_entries(path: &Path) -> Result<Vec<TrustEntry>, (String, u8)> {
    match std::fs::read_to_string(path) {
        Ok(text) => parse(&text).map_err(|e| {
            (
                format!("invalid trust-roots file {}: {e}", path.display()),
                exit::CONFIG_ERROR,
            )
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err((format!("read {}: {e}", path.display()), exit::NOINPUT)),
    }
}

/// Load the trust-roots file at `path` into an `kit-attest` [`Registry`],
/// for DSSE attestation verification (`kit verify-attest`).
pub fn load_registry(path: &Path) -> Result<Registry, (String, u8)> {
    let entries = load_entries(path)?;
    let mut reg = Registry::new();
    for e in &entries {
        add_entry_to_registry(&mut reg, e);
    }
    Ok(reg)
}

fn add_entry_to_registry(reg: &mut Registry, e: &TrustEntry) {
    let Some(pk_bytes) = hex_decode(&e.pubkey_hex) else {
        return;
    };
    match e.kind.as_str() {
        "ed25519" if pk_bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&pk_bytes);
            reg.add(e.keyid.clone(), TrustRoot::Ed25519PubKey(arr));
        }
        "p256-sec1" | "p256" => {
            reg.add(e.keyid.clone(), TrustRoot::P256PubKeySec1(pk_bytes));
        }
        "secp256k1" | "secp256k1-sec1" => {
            reg.add(e.keyid.clone(), TrustRoot::Secp256k1PubKeySec1(pk_bytes));
        }
        _ => {}
    }
}

/// Does `entries` contain a live `ed25519` trust root whose pubkey
/// bytes equal `signer`? Used by `kit verify --trusted` to cross-check
/// a commit/remix/tag's embedded `signer` field — commit signing is
/// Ed25519-only today.
///
/// Returns the matching entry's `keyid` on success.
#[must_use]
pub fn find_ed25519_signer<'a>(entries: &'a [TrustEntry], signer: &[u8; 32]) -> Option<&'a str> {
    entries.iter().find_map(|e| {
        if e.kind != "ed25519" {
            return None;
        }
        let bytes = hex_decode(&e.pubkey_hex)?;
        if bytes.len() == 32 && bytes == signer {
            Some(e.keyid.as_str())
        } else {
            None
        }
    })
}

/// Serialize `entries` back to the `[[trust_root]]` file grammar.
/// Round-trips through `parse` (modulo comments — this rewrites the
/// whole file, so any hand-added comments in a file `kit trust`
/// subsequently edits are NOT preserved).
#[must_use]
pub fn serialize(entries: &[TrustEntry]) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    for e in entries {
        out.push_str("[[trust_root]]\n");
        let _ = writeln!(out, "keyid = \"{}\"", e.keyid);
        let _ = writeln!(out, "kind = \"{}\"", e.kind);
        let _ = writeln!(out, "pubkey_hex = \"{}\"", e.pubkey_hex);
        out.push('\n');
    }
    out
}

/// Write `entries` to `path`, creating parent directories as needed.
pub fn save(path: &Path, entries: &[TrustEntry]) -> Result<(), (String, u8)> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .map_err(|e| (format!("create {}: {e}", parent.display()), exit::CANTCREAT))?;
    }
    std::fs::write(path, serialize(entries))
        .map_err(|e| (format!("write {}: {e}", path.display()), exit::CANTCREAT))
}

/// Cross-check that `keyid` is consistent with the declared
/// public key bytes. The canonical keyid shape is `<prefix>:<body>`:
///
/// - `blake3:<hex>` — body is `blake3(pubkey)`; verify the digest.
/// - `ed25519` / `secp256k1` / `p256` / `<hex>` — body is
///   the raw lowercase-hex pubkey; verify it equals `pubkey_hex`.
/// - Anything else (unknown prefix, no `:` separator) is left
///   uncross-checked here — return `true` so forward-compatible
///   keyids are not dropped.
#[must_use]
pub fn keyid_matches_pubkey(keyid: &str, pubkey: &[u8]) -> bool {
    let Some((prefix, body)) = keyid.split_once(':') else {
        return true;
    };
    let body = body.to_ascii_lowercase();
    match prefix {
        "blake3" => {
            let digest = kit_core::hash::hash(pubkey);
            body == kit_core::hash::to_hex(&digest)
        }
        "ed25519" | "secp256k1" | "p256" => body == kit_core::hash::to_hex_bytes(pubkey),
        _ => true,
    }
}

/// Shorten a keyid for display: `<prefix>:<first-16-hex>…`.
#[must_use]
pub fn short_keyid(keyid: &str) -> String {
    match keyid.split_once(':') {
        Some((prefix, body)) if body.len() > 16 => {
            format!("{prefix}:{}…", &body[..16])
        }
        _ => keyid.to_owned(),
    }
}

#[must_use]
pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let hi = nibble(b[i])?;
        let lo = nibble(b[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

fn nibble(c: u8) -> Option<u8> {
    Some(match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => 10 + c - b'a',
        b'A'..=b'F' => 10 + c - b'A',
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_missing_file_is_empty() {
        assert!(parse("").unwrap().is_empty());
    }

    #[test]
    fn parse_round_trips_through_serialize() {
        let hex = "aa".repeat(32);
        let keyid = format!("ed25519:{hex}");
        let text = format!(
            "[[trust_root]]\nkeyid = \"{keyid}\"\nkind = \"ed25519\"\npubkey_hex = \"{hex}\"\n"
        );
        let entries = parse(&text).unwrap();
        assert_eq!(entries.len(), 1);
        let re_serialized = serialize(&entries);
        let re_parsed = parse(&re_serialized).unwrap();
        assert_eq!(entries, re_parsed);
    }

    #[test]
    fn parse_rejects_keyid_pubkey_mismatch() {
        let keyid_hex = "aa".repeat(32);
        let wrong_pubkey = "bb".repeat(32);
        let keyid = format!("ed25519:{keyid_hex}");
        let text = format!(
            "[[trust_root]]\nkeyid = \"{keyid}\"\nkind = \"ed25519\"\npubkey_hex = \"{wrong_pubkey}\"\n"
        );
        assert!(parse(&text).unwrap_err().contains("does not match"));
    }

    #[test]
    fn find_ed25519_signer_matches_pubkey_bytes_not_keyid() {
        let pk = [0x42u8; 32];
        let hex = kit_core::hash::to_hex_bytes(&pk);
        // Deliberately use a human label instead of the "ed25519:<hex>"
        // convention — the commit-trust check must key off pubkey
        // bytes, not a specific keyid shape.
        let entries = vec![TrustEntry {
            keyid: "alice-laptop".to_owned(),
            kind: "ed25519".to_owned(),
            pubkey_hex: hex,
        }];
        assert_eq!(find_ed25519_signer(&entries, &pk), Some("alice-laptop"));
        assert_eq!(find_ed25519_signer(&entries, &[0u8; 32]), None);
    }

    #[test]
    fn warn_if_unsafe_trust_roots_refuses_in_repo_path_without_explicit_flag() {
        let kit_dir = Path::new("/repo/.kit");
        let trust_path = kit_dir.join("trust-roots.toml");
        let err = warn_if_unsafe_trust_roots(&trust_path, kit_dir, false).unwrap_err();
        assert_eq!(err, exit::CONFIG_ERROR);
    }

    #[test]
    fn warn_if_unsafe_trust_roots_allows_explicit_flag() {
        let kit_dir = Path::new("/repo/.kit");
        let trust_path = kit_dir.join("trust-roots.toml");
        warn_if_unsafe_trust_roots(&trust_path, kit_dir, true).unwrap();
    }

    #[test]
    fn save_then_load_round_trips() {
        let td = tempfile::tempdir().unwrap();
        let path = td.path().join("tr.toml");
        let hex = "cc".repeat(32);
        let entries = vec![TrustEntry {
            keyid: format!("ed25519:{hex}"),
            kind: "ed25519".to_owned(),
            pubkey_hex: hex,
        }];
        save(&path, &entries).unwrap();
        let loaded = load_entries(&path).unwrap();
        assert_eq!(loaded, entries);
    }

    fn block(extra: &str) -> String {
        let hex = "aa".repeat(32);
        format!("[[trust_root]]\nkeyid = \"ed25519:{hex}\"\npubkey_hex = \"{hex}\"\n{extra}")
    }

    #[test]
    fn parse_accepts_comments_blank_lines_and_default_kind() {
        let text = format!("# note\n\n{}", block("kind = \"ed25519\"\n"));
        assert_eq!(parse(&text).unwrap().len(), 1);
        assert_eq!(parse(&block("")).unwrap()[0].kind, "ed25519");
    }

    #[test]
    fn parse_rejects_junk_and_unknown_keys() {
        assert!(parse("junk\n").is_err());
        assert!(parse(&format!("junk\n{}", block(""))).is_err());
        assert!(parse(&block("junk\n")).is_err());
        assert!(parse(&block("extra = \"x\"\n")).is_err());
        assert!(parse(&block("[table]\n")).is_err());
    }

    #[test]
    fn parse_rejects_bad_values() {
        assert!(parse(&block("kind = ed25519\n")).is_err());
        assert!(parse(&block("kind = \"ed25519\" # c\n")).is_err());
        assert!(parse(&block("kind = \"ed\\25519\"\n")).is_err());
        assert!(parse(&block("kind = \"rsa\"\n")).is_err());
        assert!(parse(&block("kind = \"p256\"\n")).is_err());
    }

    #[test]
    fn parse_rejects_duplicate_keys_and_both_kind_names() {
        assert!(parse(&block("kind = \"ed25519\"\nkind = \"ed25519\"\n")).is_err());
        assert!(parse(&block("kind = \"ed25519\"\nalgorithm = \"ed25519\"\n")).is_err());
        let hex = "aa".repeat(32);
        assert!(parse(&block(&format!("keyid = \"ed25519:{hex}\"\n"))).is_err());
    }

    #[test]
    fn parse_rejects_missing_fields_and_bad_hex() {
        assert!(parse("[[trust_root]]\n").is_err());
        assert!(parse("[[trust_root]]\nkeyid = \"alice\"\n").is_err());
        assert!(parse("[[trust_root]]\nkeyid = \"alice\"\npubkey_hex = \"zz\"\n").is_err());
        assert!(parse("[[trust_root]]\nkeyid = \"alice\"\npubkey_hex = \"aa\"\n").is_err());
    }

    #[test]
    fn parse_rejects_repeated_keyid() {
        let b = block("");
        assert!(parse(&format!("{b}{b}")).is_err());
    }

    #[test]
    fn load_entries_reports_invalid_file() {
        let td = tempfile::tempdir().unwrap();
        let path = td.path().join("tr.toml");
        std::fs::write(&path, "junk\n").unwrap();
        let (msg, code) = load_entries(&path).unwrap_err();
        assert_eq!(code, exit::CONFIG_ERROR);
        assert!(msg.contains("line 1"));
    }
}
