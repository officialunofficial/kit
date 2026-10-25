//! URL token golden vectors (SPEC-WRITE-GRANTS §9.4): `url-token-ed25519.json`.
//!
//! Each vector is a statement signed by the fixed URL-token seed `1111…11`,
//! with its id, signature and token, plus accept and reject request
//! contexts. The `rejects` list holds tokens that fail one rule each, with
//! the request context and the expected `GrantError::reason`.
//!
//! `scripts/golden/grants_ref.py` rebuilds every statement, re-signs it and
//! re-runs every context through its own verifier.

use base64::Engine as _;
use ed25519_dalek::{Signer as _, VerifyingKey};
use kit_attest::grant::{
    MAX_TOKEN_PATH_BYTES, TokenTarget, URL_TOKEN_MAX_LIFETIME_MS, UrlTokenRequest,
    UrlTokenStatement, sign_url_token, url_token_key_id, verify_url_token,
};

use super::*;

const URL_SEED: [u8; 32] = [0x11; 32];
const OTHER_URL_SEED: [u8; 32] = [0x12; 32];
const AUDIENCE: &str = "https://git.example.com";
const ISSUED: i64 = 1_790_000_000_000;
const TTL_MS: i64 = 900_000;
const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

fn url_key() -> SigningKey {
    SigningKey::from_bytes(&URL_SEED)
}

fn key_id_hex(key: &SigningKey) -> String {
    hex(&url_token_key_id(&key.verifying_key()))
}

fn repository(name: &str) -> RepositoryIdentity {
    RepositoryIdentity::new(Some(addr_ns()), name).unwrap()
}

fn path(ref_name: &str, path: &str) -> TokenTarget {
    TokenTarget::Path {
        ref_name: ref_name.to_owned(),
        path: path.to_owned(),
    }
}

fn statement(target: TokenTarget, epoch: u64, expiry_ms: i64) -> UrlTokenStatement {
    UrlTokenStatement {
        audience: AUDIENCE.to_owned(),
        repository: repository("website"),
        target,
        epoch,
        issued_ms: ISSUED,
        expiry_ms,
        key_id: url_token_key_id(&url_key().verifying_key()),
    }
}

/// `(name, statement)`.
fn url_vectors() -> Vec<(&'static str, UrlTokenStatement)> {
    vec![
        (
            "object",
            statement(TokenTarget::Object([0xab; 32]), 3, ISSUED + TTL_MS),
        ),
        (
            "path-root-tree",
            statement(path("refs/heads/main", ""), 0, ISSUED + TTL_MS),
        ),
        (
            "path-nested",
            statement(
                path("refs/heads/release/1.0", "docs/guide/intro.md"),
                7,
                ISSUED + TTL_MS,
            ),
        ),
        (
            "path-non-ascii",
            statement(path("refs/tags/v1", "é/ü.txt"), 1, ISSUED + TTL_MS),
        ),
        (
            "path-1024-bytes",
            statement(
                path("refs/heads/main", &"a".repeat(MAX_TOKEN_PATH_BYTES)),
                2,
                ISSUED + TTL_MS,
            ),
        ),
        (
            "max-lifetime-max-epoch",
            statement(
                TokenTarget::Object([0x00; 32]),
                u64::MAX,
                ISSUED + URL_TOKEN_MAX_LIFETIME_MS,
            ),
        ),
    ]
}

/// A request context: `(name, audience, repository, target, now)`.
type Context = (&'static str, String, String, String, i64);

fn context_of(
    name: &'static str,
    s: &UrlTokenStatement,
    change: impl FnOnce(&mut Context),
    now: i64,
) -> Context {
    let mut c = (
        name,
        s.audience.clone(),
        s.repository.to_string(),
        s.target.encode().unwrap(),
        now,
    );
    change(&mut c);
    c
}

fn run(token: &str, c: &Context) -> Result<(), GrantError> {
    let repository = RepositoryIdentity::parse(&c.2).unwrap();
    let target = TokenTarget::parse(&c.3).unwrap();
    let keys: [VerifyingKey; 1] = [url_key().verifying_key()];
    verify_url_token(
        token,
        &keys,
        &UrlTokenRequest {
            audience: &c.1,
            repository: &repository,
            target: &target,
            now_ms: c.4,
        },
    )
    .map(|_| ())
}

fn context_json(c: &Context, err: Option<GrantError>) -> Value {
    json!({
        "name": c.0, "audience": c.1, "repository": c.2, "target": c.3, "now": c.4,
        "expected_error": err.map(GrantError::reason),
    })
}

fn accept_contexts(s: &UrlTokenStatement) -> Vec<Context> {
    vec![
        context_of("at-issued", s, |_| {}, s.issued_ms),
        context_of("last-ms-before-expiry", s, |_| {}, s.expiry_ms - 1),
    ]
}

fn reject_contexts(s: &UrlTokenStatement) -> Vec<(Context, GrantError)> {
    let other_target = match s.target {
        TokenTarget::Object(_) => path("refs/heads/main", "x").encode().unwrap(),
        TokenTarget::Path { .. } => format!("object:{}", "cd".repeat(32)),
    };
    vec![
        (
            context_of("at-expiry", s, |_| {}, s.expiry_ms),
            GrantError::Expired,
        ),
        (
            context_of(
                "other-audience",
                s,
                |c| "https://git.example.org".clone_into(&mut c.1),
                s.issued_ms,
            ),
            GrantError::AudienceNotListed,
        ),
        (
            context_of(
                "other-repository",
                s,
                |c| c.2 = repository("docs").to_string(),
                s.issued_ms,
            ),
            GrantError::RepositoryMismatch,
        ),
        (
            context_of("other-target", s, |c| c.3 = other_target, s.issued_ms),
            GrantError::TargetMismatch,
        ),
    ]
}

/// The token of arbitrary statement bytes, signed by `key`.
fn token_of(bytes: &[u8], key: &SigningKey) -> String {
    let signature = key.sign(blake3::hash(bytes).as_bytes());
    format!("{}.{}", B64.encode(bytes), B64.encode(signature.to_bytes()))
}

fn fields_of(s: &UrlTokenStatement) -> Vec<String> {
    String::from_utf8(s.encode().unwrap())
        .unwrap()
        .split('\n')
        .map(str::to_owned)
        .collect()
}

fn fields_json(s: &UrlTokenStatement) -> Value {
    let f = fields_of(s);
    json!({
        "audience": f[1], "repository": f[2], "target": f[3], "epoch": f[4],
        "issued": f[5], "expiry": f[6], "key_id": f[7],
    })
}

/// `(name, rule, token, context)`; the expected error is the verifier's.
type Reject = (&'static str, &'static str, String, Context);

#[allow(clippy::too_many_lines)] // a data table
fn rejects() -> Vec<Reject> {
    let base = statement(path("refs/heads/main", "docs/a.md"), 3, ISSUED + TTL_MS);
    let key = url_key();
    let ctx = context_of("base", &base, |_| {}, ISSUED);
    let token = sign_url_token(&base, &key).unwrap();
    let (body, sig) = token.split_once('.').unwrap();
    let fields = fields_of(&base);
    let edit = |i: usize, value: &str| -> String {
        let mut f = fields.clone();
        value.clone_into(&mut f[i]);
        token_of(f.join("\n").as_bytes(), &key)
    };
    let mut flipped = B64.decode(sig).unwrap();
    flipped[0] ^= 1;
    let mut big_s = B64.decode(sig).unwrap();
    {
        // Replace s with s + L (the same value mod L).
        let l: [u8; 32] = [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
        ];
        let mut carry = 0u16;
        for (i, l) in l.iter().enumerate() {
            let sum = u16::from(big_s[32 + i]) + u16::from(*l) + carry;
            big_s[32 + i] = sum.to_le_bytes()[0];
            carry = sum >> 8;
        }
        assert_eq!(carry, 0);
    }
    let other = SigningKey::from_bytes(&OTHER_URL_SEED);
    let mut other_statement = base.clone();
    other_statement.key_id = url_token_key_id(&other.verifying_key());
    let long_segment = "A".repeat(5465);
    let lifetime_over = (ISSUED + URL_TOKEN_MAX_LIFETIME_MS + 1).to_string();
    let rows: Vec<(&'static str, &'static str, String)> = vec![
        ("no-dot", "token format", body.to_owned()),
        ("two-dots", "token format", format!("{token}.{sig}")),
        ("empty-statement", "token format", format!(".{sig}")),
        ("empty-signature", "token format", format!("{body}.")),
        ("padded-statement", "token base64", format!("{body}=.{sig}")),
        (
            "signature-truncated-char",
            "token base64",
            format!("{body}.{}", &sig[..sig.len() - 1]),
        ),
        (
            "statement-segment-too-long",
            "statement too long",
            format!("{long_segment}.{sig}"),
        ),
        (
            "signature-63-bytes",
            "signature length",
            format!("{body}.{}", B64.encode(&B64.decode(sig).unwrap()[..63])),
        ),
        (
            "signature-bit-flipped",
            "bad signature",
            format!("{body}.{}", B64.encode(&flipped)),
        ),
        (
            "signature-s-not-canonical",
            "bad signature",
            format!("{body}.{}", B64.encode(&big_s)),
        ),
        (
            "signed-by-other-key-same-key-id",
            "bad signature",
            token_of(&base.encode().unwrap(), &other),
        ),
        (
            "signed-by-other-key",
            "unknown key id",
            token_of(&other_statement.encode().unwrap(), &other),
        ),
        ("domain-epoch", "domain", edit(0, "kit-write-epoch:v1")),
        (
            "audience-default-port",
            "audience",
            edit(1, "https://git.example.com:443"),
        ),
        (
            "audience-list",
            "audience",
            edit(1, "https://git.example.com,https://git.example.org"),
        ),
        ("repository-bare-name", "repository", edit(2, "website")),
        (
            "target-unknown-kind",
            "url token target",
            edit(3, &format!("tree:{}", "ab".repeat(32))),
        ),
        (
            "target-object-uppercase",
            "url token target",
            edit(3, &format!("object:{}", "AB".repeat(32))),
        ),
        (
            "target-ref-invalid",
            "url token target",
            edit(3, &format!("path:refs/heads/.x:{}", B64.encode("x"))),
        ),
        (
            "target-path-padded",
            "url token target",
            edit(3, "path:refs/heads/main:eA=="),
        ),
        (
            "target-path-dot-dot",
            "url token target",
            edit(3, &format!("path:refs/heads/main:{}", B64.encode("a/../b"))),
        ),
        (
            "target-path-empty-entry",
            "url token target",
            edit(3, &format!("path:refs/heads/main:{}", B64.encode("a//b"))),
        ),
        (
            "target-path-leading-slash",
            "url token target",
            edit(3, &format!("path:refs/heads/main:{}", B64.encode("/a"))),
        ),
        (
            "target-path-control-character",
            "url token target",
            edit(3, &format!("path:refs/heads/main:{}", B64.encode("a\nb"))),
        ),
        (
            "target-path-not-utf8",
            "url token target",
            edit(3, &format!("path:refs/heads/main:{}", B64.encode([0xff]))),
        ),
        (
            "target-path-1025-bytes",
            "url token target",
            edit(
                3,
                &format!(
                    "path:refs/heads/main:{}",
                    B64.encode("a".repeat(MAX_TOKEN_PATH_BYTES + 1))
                ),
            ),
        ),
        ("epoch-leading-zero", "noncanonical decimal", edit(4, "03")),
        (
            "epoch-2-pow-64",
            "decimal out of range",
            edit(4, "18446744073709551616"),
        ),
        (
            "expiry-equals-issued",
            "expiry not after created",
            edit(6, &ISSUED.to_string()),
        ),
        (
            "lifetime-over-24-hours",
            "lifetime too long",
            edit(6, &lifetime_over),
        ),
        (
            "key-id-uppercase",
            "noncanonical hex",
            edit(7, &fields[7].to_uppercase()),
        ),
        (
            "key-id-30-hex",
            "noncanonical hex",
            edit(7, &fields[7][..30]),
        ),
        (
            "field-count-7",
            "field count",
            token_of(fields[..7].join("\n").as_bytes(), &key),
        ),
    ];
    rows.into_iter()
        .map(|(name, rule, token)| (name, rule, token, ctx.clone()))
        .collect()
}

fn vector_json(name: &str, s: &UrlTokenStatement) -> Value {
    let bytes = s.encode().unwrap();
    let token = sign_url_token(s, &url_key()).unwrap();
    let signature = url_key().sign(blake3::hash(&bytes).as_bytes());
    json!({
        "name": name,
        "fields": fields_json(s),
        "statement": String::from_utf8(bytes.clone()).unwrap(),
        "id": hex(blake3::hash(&bytes).as_bytes()),
        "signature_hex": hex(&signature.to_bytes()),
        "token": token,
        "accept_contexts": accept_contexts(s).iter().map(|c| context_json(c, None)).collect::<Vec<_>>(),
        "reject_contexts": reject_contexts(s).iter().map(|(c, e)| context_json(c, Some(*e))).collect::<Vec<_>>(),
    })
}

fn url_token_file() -> Value {
    let key = url_key();
    let rejects: Vec<Value> = rejects()
        .iter()
        .map(|(name, rule, token, ctx)| {
            let err = run(token, ctx).unwrap_err();
            let mut v = context_json(ctx, Some(err));
            v["name"] = json!(name);
            v["rule"] = json!(rule);
            v["token"] = json!(token);
            v
        })
        .collect();
    json!({
        "spec": "SPEC-WRITE-GRANTS §9.4",
        "key_seed": hex(&URL_SEED),
        "public_key": hex(key.verifying_key().as_bytes()),
        "key_id": key_id_hex(&key),
        "vectors": url_vectors().iter().map(|(n, s)| vector_json(n, s)).collect::<Vec<_>>(),
        "rejects": rejects,
    })
}

/// Writes the fixture; the caller then rewrites `MANIFEST.txt`.
pub(super) fn write_url_token() {
    write_json("url-token-ed25519.json", &url_token_file());
}

#[test]
fn url_token_goldens() {
    maybe_write();
    let file = read("url-token-ed25519.json");
    assert_eq!(file, url_token_file());
    for (fixture, (name, s)) in file["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .zip(url_vectors())
    {
        assert_eq!(fixture["name"], name);
        let token = fixture["token"].as_str().unwrap();
        let bytes = fixture["statement"].as_str().unwrap().as_bytes();
        assert_eq!(UrlTokenStatement::parse(bytes).unwrap(), s, "{name}");
        for c in accept_contexts(&s) {
            assert_eq!(run(token, &c), Ok(()), "{name}/{}", c.0);
        }
        for (c, err) in reject_contexts(&s) {
            assert_eq!(run(token, &c), Err(err), "{name}/{}", c.0);
        }
    }
}

/// Every reject fixture fails with exactly its error, and every rule the
/// verifier can name appears.
#[test]
fn url_token_reject_goldens() {
    maybe_write();
    let file = read("url-token-ed25519.json");
    let mut seen = std::collections::BTreeSet::new();
    for r in file["rejects"].as_array().unwrap() {
        let expected = r["expected_error"].as_str().unwrap();
        let token = r["token"].as_str().unwrap();
        let ctx: Context = (
            "",
            r["audience"].as_str().unwrap().to_owned(),
            r["repository"].as_str().unwrap().to_owned(),
            r["target"].as_str().unwrap().to_owned(),
            r["now"].as_i64().unwrap(),
        );
        let got = run(token, &ctx).unwrap_err();
        assert_eq!(got.reason(), expected, "{}", r["name"]);
        assert_eq!(r["rule"].as_str().unwrap(), expected, "{}", r["name"]);
        seen.insert(expected.to_owned());
    }
    for reason in [
        GrantError::TokenFormat,
        GrantError::TokenBase64,
        GrantError::StatementTooLong,
        GrantError::SignatureLength,
        GrantError::BadSignature,
        GrantError::UnknownKeyId,
        GrantError::Domain,
        GrantError::Audience,
        GrantError::Repository,
        GrantError::UrlTokenTarget,
        GrantError::Decimal,
        GrantError::DecimalOutOfRange,
        GrantError::ExpiryNotAfterCreated,
        GrantError::LifetimeTooLong,
        GrantError::Hex,
        GrantError::FieldCount,
    ] {
        assert!(seen.contains(reason.reason()), "no reject for {reason:?}");
    }
}
