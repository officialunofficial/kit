//! The `kit-url-token:v1` statement and its signed token (SPEC-WRITE-GRANTS
//! §9.4).
//!
//! A token is `<statement>.<signature>`: the unpadded base64url of the
//! statement, a `.`, and the unpadded base64url of an Ed25519 signature over
//! the BLAKE3 of the statement. [`verify_url_token`] runs the stateless
//! checks. The caller reads the stored epoch and the visibility change time,
//! and compares them with [`UrlTokenStatement::epoch`] and
//! [`UrlTokenStatement::issued_ms`].

use base64::Engine as _;
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use kit_core::repo_identity::RepositoryIdentity;
use kit_core::write_auth::{is_hex, validate_audience};

use super::header::B64;
use super::text::{
    check_lifetime, decimal_millis, decimal_u64, encode_hex32, encode_millis, hex32, join_fields,
    split_fields,
};
use super::{DOMAIN_URL_TOKEN, GrantError, MAX_STATEMENT_BYTES};

/// Field count of a URL token statement.
const URL_TOKEN_FIELDS: usize = 8;
/// Longest token lifetime a statement may encode: 24 hours (§9.4).
pub const URL_TOKEN_MAX_LIFETIME_MS: i64 = 86_400_000;
/// Longest path in a `path:` target, in bytes (§9.4).
pub const MAX_TOKEN_PATH_BYTES: usize = 1024;
/// Length of a signature in bytes.
const SIGNATURE_LEN: usize = 64;

/// What a token names (§9.4). The token binds the unresolved target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TokenTarget {
    /// `object:<64 lowercase hex object id>`.
    Object([u8; 32]),
    /// `path:<ref>:<base64url path>`: a path in the tree a ref names. An
    /// empty path names the root tree.
    Path {
        /// A full ref name valid under SPEC-REFS §3.
        ref_name: String,
        /// Tree entry names joined by `/`, or empty.
        path: String,
    },
}

impl TokenTarget {
    /// Parse the canonical target text.
    ///
    /// # Errors
    /// `UrlTokenTarget` for any text outside the §9.4 grammar.
    pub fn parse(text: &str) -> Result<Self, GrantError> {
        if let Some(id) = text.strip_prefix("object:") {
            return Ok(Self::Object(
                hex32(id).map_err(|_| GrantError::UrlTokenTarget)?,
            ));
        }
        let rest = text
            .strip_prefix("path:")
            .ok_or(GrantError::UrlTokenTarget)?;
        // A ref name has no `:`, so the field splits at its first `:`.
        let (ref_name, encoded) = rest.split_once(':').ok_or(GrantError::UrlTokenTarget)?;
        let path = B64
            .decode(encoded)
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .ok_or(GrantError::UrlTokenTarget)?;
        let target = Self::Path {
            ref_name: ref_name.to_owned(),
            path,
        };
        target.check()?;
        Ok(target)
    }

    /// The canonical target text.
    ///
    /// # Errors
    /// `UrlTokenTarget` for a target [`TokenTarget::parse`] would reject.
    pub fn encode(&self) -> Result<String, GrantError> {
        self.check()?;
        Ok(match self {
            Self::Object(id) => format!("object:{}", encode_hex32(id)),
            Self::Path { ref_name, path } => {
                format!("path:{ref_name}:{}", B64.encode(path.as_bytes()))
            }
        })
    }

    fn check(&self) -> Result<(), GrantError> {
        let Self::Path { ref_name, path } = self else {
            return Ok(());
        };
        let entries_ok = path.is_empty()
            || path
                .split('/')
                .all(|entry| !entry.is_empty() && entry != "." && entry != "..");
        if !kit_core::refs::validate_ref_name(ref_name)
            || path.len() > MAX_TOKEN_PATH_BYTES
            || !entries_ok
            || path.chars().any(char::is_control)
        {
            return Err(GrantError::UrlTokenTarget);
        }
        Ok(())
    }
}

/// The key id of a URL-token key: the first 16 bytes of the BLAKE3 of its
/// 32-byte public key (§9.4).
#[must_use]
pub fn url_token_key_id(key: &VerifyingKey) -> [u8; 16] {
    let digest = kit_core::hash::hash(key.as_bytes());
    let mut id = [0; 16];
    id.copy_from_slice(&digest[..16]);
    id
}

fn encode_key_id(id: &[u8; 16]) -> String {
    use core::fmt::Write as _;
    id.iter().fold(String::new(), |mut out, b| {
        // Writing to a `String` cannot fail.
        let _ = write!(out, "{b:02x}");
        out
    })
}

fn parse_key_id(s: &str) -> Result<[u8; 16], GrantError> {
    if !is_hex(s, 16) {
        return Err(GrantError::Hex);
    }
    let mut id = [0; 16];
    for (byte, pair) in id.iter_mut().zip(s.as_bytes().chunks(2)) {
        let digits = core::str::from_utf8(pair).map_err(|_| GrantError::Hex)?;
        *byte = u8::from_str_radix(digits, 16).map_err(|_| GrantError::Hex)?;
    }
    Ok(id)
}

/// A parsed `kit-url-token:v1` statement (§9.4).
///
/// [`UrlTokenStatement::parse`] accepts exactly the canonical encoding and
/// [`UrlTokenStatement::encode`] reproduces it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UrlTokenStatement {
    /// The issuing deployment's auth v2 audience.
    pub audience: String,
    /// A full identity `<namespace>/<name>` (§7.4).
    pub repository: RepositoryIdentity,
    /// The unresolved target.
    pub target: TokenTarget,
    /// The namespace's stored epoch when the token was issued.
    pub epoch: u64,
    /// Issue time, epoch milliseconds.
    pub issued_ms: i64,
    /// Expiry, epoch milliseconds: `issued < expiry <= issued +
    /// URL_TOKEN_MAX_LIFETIME_MS`.
    pub expiry_ms: i64,
    /// The key id of the signing key.
    pub key_id: [u8; 16],
}

impl UrlTokenStatement {
    /// Parse a statement, enforcing the §3.1 rules and the §9.4 fields.
    /// Never repairs.
    ///
    /// # Errors
    /// The [`GrantError`] of the first failed rule.
    pub fn parse(bytes: &[u8]) -> Result<Self, GrantError> {
        let f = split_fields(bytes, URL_TOKEN_FIELDS)?;
        if f[0] != DOMAIN_URL_TOKEN {
            return Err(GrantError::Domain);
        }
        validate_audience(f[1]).map_err(|_| GrantError::Audience)?;
        let repository = RepositoryIdentity::parse(f[2]).map_err(|_| GrantError::Repository)?;
        let target = TokenTarget::parse(f[3])?;
        let epoch = decimal_u64(f[4])?;
        let issued_ms = decimal_millis(f[5])?;
        let expiry_ms = decimal_millis(f[6])?;
        let key_id = parse_key_id(f[7])?;
        check_lifetime(issued_ms, expiry_ms, URL_TOKEN_MAX_LIFETIME_MS)?;
        Ok(Self {
            audience: f[1].to_owned(),
            repository,
            target,
            epoch,
            issued_ms,
            expiry_ms,
            key_id,
        })
    }

    /// Encode the canonical statement. Validates every rule
    /// [`UrlTokenStatement::parse`] enforces.
    ///
    /// # Errors
    /// The [`GrantError`] of the first failed rule.
    pub fn encode(&self) -> Result<Vec<u8>, GrantError> {
        validate_audience(&self.audience).map_err(|_| GrantError::Audience)?;
        if self.repository.namespace().is_none() {
            return Err(GrantError::Repository);
        }
        check_lifetime(self.issued_ms, self.expiry_ms, URL_TOKEN_MAX_LIFETIME_MS)?;
        join_fields(&[
            DOMAIN_URL_TOKEN,
            &self.audience,
            &self.repository.to_string(),
            &self.target.encode()?,
            &self.epoch.to_string(),
            &encode_millis(self.issued_ms)?,
            &encode_millis(self.expiry_ms)?,
            &encode_key_id(&self.key_id),
        ])
    }
}

/// Sign a statement with the deployment's URL-token key and return the
/// token (§9.4).
///
/// # Errors
/// The [`GrantError`] of [`UrlTokenStatement::encode`], or `UnknownKeyId`
/// when `key_id` is not the id of `key`.
pub fn sign_url_token(
    statement: &UrlTokenStatement,
    key: &SigningKey,
) -> Result<String, GrantError> {
    if url_token_key_id(&key.verifying_key()) != statement.key_id {
        return Err(GrantError::UnknownKeyId);
    }
    let bytes = statement.encode()?;
    let signature = key.sign(&kit_core::hash::hash(&bytes));
    Ok(format!(
        "{}.{}",
        B64.encode(&bytes),
        B64.encode(signature.to_bytes())
    ))
}

/// The request a token is checked against (§9.4 verification).
#[derive(Clone, Copy, Debug)]
pub struct UrlTokenRequest<'a> {
    /// The deployment's own audience.
    pub audience: &'a str,
    /// The repository of the request.
    pub repository: &'a RepositoryIdentity,
    /// The unresolved target of the request.
    pub target: &'a TokenTarget,
    /// The clock reading, epoch milliseconds.
    pub now_ms: i64,
}

/// A token that passed the stateless checks of §9.4 at one `now`. It has no
/// public constructor. The caller still compares [`UrlTokenStatement::epoch`]
/// with the stored epoch and [`UrlTokenStatement::issued_ms`] with the
/// visibility change time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedUrlToken {
    statement: UrlTokenStatement,
}

impl VerifiedUrlToken {
    /// The verified statement.
    #[must_use]
    pub fn statement(&self) -> &UrlTokenStatement {
        &self.statement
    }
}

/// Run the stateless §9.4 checks, in this order: the token decodes, the
/// statement parses, the key id names a key in `keys`, the signature
/// verifies with the strict predicate of SPEC-SIGNING §1, the audience, the
/// repository and the target equal the request's byte for byte, and `now <
/// expiry`.
///
/// # Errors
/// The [`GrantError`] of the first failed check: `TokenFormat`,
/// `TokenBase64`, a statement error, `UnknownKeyId`, `SignatureLength`,
/// `BadSignature`, `AudienceNotListed`, `RepositoryMismatch`,
/// `TargetMismatch` or `Expired`.
pub fn verify_url_token(
    token: &str,
    keys: &[VerifyingKey],
    request: &UrlTokenRequest<'_>,
) -> Result<VerifiedUrlToken, GrantError> {
    let (statement_part, signature_part) = token.split_once('.').ok_or(GrantError::TokenFormat)?;
    if statement_part.is_empty() || signature_part.is_empty() || signature_part.contains('.') {
        return Err(GrantError::TokenFormat);
    }
    // The statement is bounded by `MAX_STATEMENT_BYTES`; refuse a longer
    // segment before it is decoded.
    if statement_part.len() > MAX_STATEMENT_BYTES.div_ceil(3) * 4 {
        return Err(GrantError::StatementTooLong);
    }
    let bytes = B64
        .decode(statement_part)
        .map_err(|_| GrantError::TokenBase64)?;
    let signature = B64
        .decode(signature_part)
        .map_err(|_| GrantError::TokenBase64)?;
    let statement = UrlTokenStatement::parse(&bytes)?;
    let key = keys
        .iter()
        .find(|k| url_token_key_id(k) == statement.key_id)
        .ok_or(GrantError::UnknownKeyId)?;
    let signature: &[u8; SIGNATURE_LEN] = signature
        .as_slice()
        .try_into()
        .map_err(|_| GrantError::SignatureLength)?;
    key.verify_strict(
        &kit_core::hash::hash(&bytes),
        &Signature::from_bytes(signature),
    )
    .map_err(|_| GrantError::BadSignature)?;
    if statement.audience != request.audience {
        return Err(GrantError::AudienceNotListed);
    }
    if statement.repository != *request.repository {
        return Err(GrantError::RepositoryMismatch);
    }
    if statement.target != *request.target {
        return Err(GrantError::TargetMismatch);
    }
    if request.now_ms >= statement.expiry_ms {
        return Err(GrantError::Expired);
    }
    Ok(VerifiedUrlToken { statement })
}

#[cfg(test)]
mod tests {
    use super::*;

    const REPO: &str = "0x8ba1f109551bd432803012645ac136ddd64dba72/website";
    const AUDIENCE: &str = "https://git.example.com";
    const ISSUED: i64 = 1_790_000_000_000;
    const EXPIRY: i64 = ISSUED + 900_000;

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[11; 32])
    }

    fn statement(target: TokenTarget) -> UrlTokenStatement {
        UrlTokenStatement {
            audience: AUDIENCE.to_owned(),
            repository: RepositoryIdentity::parse(REPO).unwrap(),
            target,
            epoch: 3,
            issued_ms: ISSUED,
            expiry_ms: EXPIRY,
            key_id: url_token_key_id(&key().verifying_key()),
        }
    }

    fn object() -> TokenTarget {
        TokenTarget::Object([0xab; 32])
    }

    fn path(ref_name: &str, path: &str) -> TokenTarget {
        TokenTarget::Path {
            ref_name: ref_name.to_owned(),
            path: path.to_owned(),
        }
    }

    fn request<'a>(
        repository: &'a RepositoryIdentity,
        target: &'a TokenTarget,
        now_ms: i64,
    ) -> UrlTokenRequest<'a> {
        UrlTokenRequest {
            audience: AUDIENCE,
            repository,
            target,
            now_ms,
        }
    }

    #[test]
    fn statement_roundtrips() {
        for target in [
            object(),
            path("refs/heads/main", ""),
            path("refs/heads/main", "src/lib.rs"),
        ] {
            let s = statement(target);
            let bytes = s.encode().unwrap();
            assert_eq!(UrlTokenStatement::parse(&bytes).unwrap(), s);
        }
    }

    #[test]
    fn targets_reject_each_rule() {
        let bad = [
            "object:AB",
            "object:",
            "path:refs/heads/main",
            "path:refs/heads/.x:eA",
            "path:refs/heads/main:c3JjLw",
            "path:refs/heads/main:Lw",
            "path:refs/heads/main:YS8vYg",
            "path:refs/heads/main:Li4",
            "path:refs/heads/main:YS8uLi9i",
            "path:refs/heads/main:YQ==",
            "path:refs/heads/main:YQo",
            "path:refs/heads/main:/w",
            "tree:abc",
        ];
        for text in bad {
            assert_eq!(
                TokenTarget::parse(text),
                Err(GrantError::UrlTokenTarget),
                "{text}"
            );
        }
        let long = "a".repeat(MAX_TOKEN_PATH_BYTES + 1);
        assert!(path("refs/heads/main", &long).encode().is_err());
        assert!(
            path("refs/heads/main", &"a".repeat(MAX_TOKEN_PATH_BYTES))
                .encode()
                .is_ok()
        );
    }

    #[test]
    fn statement_rejects_each_rule() {
        let good = statement(object()).encode().unwrap();
        let text = String::from_utf8(good).unwrap();
        let fields: Vec<&str> = text.split('\n').collect();
        let with = |i: usize, value: &str| {
            let mut f = fields.clone();
            f[i] = value;
            f.join("\n").into_bytes()
        };
        let reject = |bytes: &[u8], err: GrantError| {
            assert_eq!(UrlTokenStatement::parse(bytes), Err(err));
        };
        reject(fields[..7].join("\n").as_bytes(), GrantError::FieldCount);
        reject(&with(0, "kit-write-epoch:v1"), GrantError::Domain);
        reject(
            &with(1, "https://git.example.com:443"),
            GrantError::Audience,
        );
        reject(
            &with(1, "https://a.example,https://b.example"),
            GrantError::Audience,
        );
        reject(&with(2, "website"), GrantError::Repository);
        reject(&with(4, "03"), GrantError::Decimal);
        reject(&with(5, "1790000900000"), GrantError::ExpiryNotAfterCreated);
        reject(&with(6, "1790086400001"), GrantError::LifetimeTooLong);
        reject(&with(7, &"AB".repeat(16)), GrantError::Hex);
        reject(&with(7, &"ab".repeat(15)), GrantError::Hex);
    }

    #[test]
    fn token_verifies_and_binds_its_request() {
        let target = path("refs/heads/main", "data/a.bin");
        let repository = RepositoryIdentity::parse(REPO).unwrap();
        let token = sign_url_token(&statement(target.clone()), &key()).unwrap();
        let keys = [key().verifying_key()];
        let ok = verify_url_token(&token, &keys, &request(&repository, &target, ISSUED)).unwrap();
        assert_eq!(ok.statement().epoch, 3);
        let at = |now| verify_url_token(&token, &keys, &request(&repository, &target, now));
        assert!(at(EXPIRY - 1).is_ok());
        assert_eq!(at(EXPIRY).unwrap_err(), GrantError::Expired);
        let other_target = object();
        assert_eq!(
            verify_url_token(&token, &keys, &request(&repository, &other_target, ISSUED))
                .unwrap_err(),
            GrantError::TargetMismatch
        );
        let other_repo = RepositoryIdentity::parse(&REPO.replace("website", "docs")).unwrap();
        assert_eq!(
            verify_url_token(&token, &keys, &request(&other_repo, &target, ISSUED)).unwrap_err(),
            GrantError::RepositoryMismatch
        );
        let mut other_audience = request(&repository, &target, ISSUED);
        other_audience.audience = "https://git.example.org";
        assert_eq!(
            verify_url_token(&token, &keys, &other_audience).unwrap_err(),
            GrantError::AudienceNotListed
        );
        let stranger = [SigningKey::from_bytes(&[12; 32]).verifying_key()];
        assert_eq!(
            verify_url_token(&token, &stranger, &request(&repository, &target, ISSUED))
                .unwrap_err(),
            GrantError::UnknownKeyId
        );
    }

    #[test]
    fn token_rejects_malformed_and_forged_values() {
        let target = object();
        let repository = RepositoryIdentity::parse(REPO).unwrap();
        let token = sign_url_token(&statement(target.clone()), &key()).unwrap();
        let keys = [key().verifying_key()];
        let check = |t: &str| {
            verify_url_token(t, &keys, &request(&repository, &target, ISSUED)).unwrap_err()
        };
        let (body, sig) = token.split_once('.').unwrap();
        assert_eq!(check(body), GrantError::TokenFormat);
        assert_eq!(check(&format!("{token}.{sig}")), GrantError::TokenFormat);
        assert_eq!(check(&format!(".{sig}")), GrantError::TokenFormat);
        assert_eq!(check(&format!("{body}.")), GrantError::TokenFormat);
        assert_eq!(check(&format!("{body}=.{sig}")), GrantError::TokenBase64);
        assert_eq!(
            check(&format!("{body}.{}", &sig[..sig.len() - 1])),
            GrantError::TokenBase64
        );
        let short = B64.encode([0u8; 63]);
        assert_eq!(
            check(&format!("{body}.{short}")),
            GrantError::SignatureLength
        );
        let wrong = B64.encode([0u8; 64]);
        assert_eq!(check(&format!("{body}.{wrong}")), GrantError::BadSignature);
        let other = sign_url_token(&statement(path("refs/heads/main", "")), &key()).unwrap();
        let (other_body, _) = other.split_once('.').unwrap();
        assert_eq!(
            check(&format!("{other_body}.{sig}")),
            GrantError::BadSignature
        );
        let long = "A".repeat(MAX_STATEMENT_BYTES.div_ceil(3) * 4 + 1);
        assert_eq!(
            check(&format!("{long}.{sig}")),
            GrantError::StatementTooLong
        );
    }

    #[test]
    fn signing_refuses_another_key() {
        let s = statement(object());
        let other = SigningKey::from_bytes(&[12; 32]);
        assert_eq!(sign_url_token(&s, &other), Err(GrantError::UnknownKeyId));
    }
}
