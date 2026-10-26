//! Shared guardrail-enforcing fuzz target bodies.
//!
//! Both the `cargo +nightly fuzz` libfuzzer binaries and the plain
//! `cargo test` shims call into the functions exposed here. The six
//! `docs/FUZZ.md` guardrails are encoded once and reused so an audit
//! reads them in a single place:
//!
//! 1. `MAX_ITER = 100`               — iteration cap (in-target counter).
//! 2. `MAX_INPUT = 64 * 1024`        — per-iteration input cap.
//! 3. **Bounded allocations** — the input cap above plus per-op output
//!    caps inside `kit-core` (`delta::decode` caps initial capacity,
//!    `pack::PackReader` enforces `MAX_ENTRIES` and `MAX_PAYLOAD`)
//!    keep the worst-case heap to ~1 MiB per iteration. Defensive
//!    pre-checks in the harness refuse obviously-malicious headers
//!    before invoking core.
//! 4. `PER_ITER = Duration::from_millis(100)` — wall-clock cap; abort on overrun.
//! 5. No `loop {}` / `while true {}` — we use `for i in 0..MAX_ITER` exclusively.
//! 6. Seeded deterministic PRNG — `RNG_SEED` is a constant. Most targets
//!    use splitmix64 (`run_iterated_unit`); the `rpc_decode` pilot drives
//!    the body through commonware-invariants `minifuzz`, whose ChaCha8
//!    sampler is seeded with the same `RNG_SEED` via `with_seed`, so it is
//!    likewise deterministic and reproducible (see its `#[test]`).
//!
//! Inputs from libfuzzer come in as raw `&[u8]`; the unit-test path
//! synthesises inputs from the seeded PRNG (splitmix64, or minifuzz's
//! ChaCha8 sampler for `rpc_decode`). Either way each body slices to
//! <= 64 KiB before doing work.

#![forbid(unsafe_code)]

use std::time::{Duration, Instant};

/// Per-iteration wall-clock budget. Exceeding this aborts the rest of
/// the run with `Err(GuardrailError::IterationTooSlow)`.
pub const PER_ITER: Duration = Duration::from_millis(100);
/// Iteration cap — every fuzz body MUST stop at or before this.
pub const MAX_ITER: u32 = 100;
/// Per-iteration input cap. libfuzzer inputs longer than this are
/// truncated; PRNG-driven inputs sample lengths in `0..=MAX_INPUT`.
pub const MAX_INPUT: usize = 64 * 1024;
/// Deterministic seed for the PRNG-driven path. Changing this rotates
/// the corpus; do not change without also updating any pinned regression
/// hashes.
pub const RNG_SEED: u64 = 0xDEAD_BEEF_CAFE_F00D;

/// Errors a fuzz body can return without panicking.
#[derive(Debug, PartialEq, Eq)]
pub enum GuardrailError {
    IterationTooSlow,
}

/// Splitmix64 PRNG. Seeded once per fuzz invocation.
pub struct SplitMix(pub u64);
impl SplitMix {
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self(seed.wrapping_add(1))
    }
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    pub fn fill(&mut self, dst: &mut [u8]) {
        let mut i = 0usize;
        while i < dst.len() {
            let bytes = self.next_u64().to_le_bytes();
            let end = (i + 8).min(dst.len());
            dst[i..end].copy_from_slice(&bytes[..end - i]);
            i = end;
        }
    }
    pub fn range_usize(&mut self, max_inclusive: usize) -> usize {
        if max_inclusive == 0 {
            return 0;
        }
        (self.next_u64() % (max_inclusive as u64 + 1)) as usize
    }
}

/// Apply the `delta::decode` parser against `input`, freeing the
/// reconstructed buffer immediately. The parser MUST NOT panic and
/// MUST NOT read OOB on any input.
pub fn delta_one_iteration(input: &[u8]) {
    // Truncate per guardrail.
    let input = &input[..input.len().min(MAX_INPUT)];
    if input.len() < 2 {
        return;
    }
    // Split: first half = base, second half = stream candidate.
    let split = input.len() / 2;
    let base = &input[..split];
    let stream = &input[split..];
    // Defensive pre-check on the stream header. `delta::decode` already
    // caps the initial `Vec::with_capacity` against stream length, but
    // we also refuse obviously-malicious declared-result-lengths here
    // so the fuzz loop makes progress on more interesting inputs per
    // unit of CPU (`MAX_INPUT * 4` matches the practical ceiling the
    // decoder can reach from a 64 KiB stream).
    if stream.len() < 9 {
        let _ = kit_core::delta::decode(base, stream);
        return;
    }
    let claimed_result_len = u32::from_le_bytes([stream[5], stream[6], stream[7], stream[8]]);
    if claimed_result_len as usize > MAX_INPUT * 4 {
        return;
    }
    let _ = kit_core::delta::decode(base, stream);
}

/// Shared pre-check for [`pack_reader_one_iteration`] / [`pack_reader_one_iteration_with_store`]:
/// truncate per guardrail and refuse to feed packs whose declared
/// `entry_count` would force a giant `Vec::with_capacity` (the reader
/// already enforces `MAX_ENTRIES`, but the cap here prevents the test
/// from even trying). Returns `None` when the iteration should be
/// skipped.
fn pack_validated_input(input: &[u8]) -> Option<&[u8]> {
    let input = &input[..input.len().min(MAX_INPUT)];
    if input.len() < 12 {
        return None;
    }
    let claimed_entries = u32::from_le_bytes([input[8], input[9], input[10], input[11]]);
    if claimed_entries > 100_000 {
        return None;
    }
    Some(input)
}

/// Apply `PackReader::read` against `input` — same panic/UB invariant.
/// Uses an in-process tempdir so the store side-effect is isolated and
/// auto-cleaned at scope exit. Real libfuzzer / `fuzz_target!` runs call
/// this directly, where per-call isolation matters; the unit-test loop
/// uses [`pack_reader_one_iteration_with_store`] instead to reuse one store
/// across all `MAX_ITER` iterations.
pub fn pack_reader_one_iteration(input: &[u8]) {
    let Some(input) = pack_validated_input(input) else {
        return;
    };
    let dir = match tempfile::TempDir::new() {
        Ok(d) => d,
        Err(_) => return,
    };
    let layout = kit_core::layout::RepoLayout::single(dir.path());
    let store = match kit_core::store::ObjectStore::init(&layout) {
        Ok(s) => s,
        Err(_) => return,
    };
    let _ = kit_core::pack::PackReader::read(input, &store);
}

/// As [`pack_reader_one_iteration`], but against a caller-provided store
/// instead of a fresh tempdir. Lets the unit-test loop amortize the
/// tempdir + `ObjectStore::init` cost across all `MAX_ITER` iterations
/// instead of paying for 100 real filesystem inits per `cargo test`
/// invocation.
pub fn pack_reader_one_iteration_with_store(input: &[u8], store: &kit_core::store::ObjectStore) {
    let Some(input) = pack_validated_input(input) else {
        return;
    };
    let _ = kit_core::pack::PackReader::read(input, store);
}

/// Apply `serialize::deserialize` against `input` — covers the tree
/// decoder path (and every other object decoder, since deserialize
/// dispatches on type byte).
pub fn object_deserialize_one_iteration(input: &[u8]) {
    let input = &input[..input.len().min(MAX_INPUT)];
    let _ = kit_core::serialize::deserialize(input);
}

/// Apply the git-bridge import parsers against `input` — the
/// untrusted-input boundary of `kit git import` (SPEC-GIT-IMPORT §2).
/// These accept arbitrary upstream bytes, so they must never panic,
/// over-allocate, or hang on adversarial input.
pub fn git_commit_parse_one_iteration(input: &[u8]) {
    let input = &input[..input.len().min(MAX_INPUT)];
    if let Ok(c) = kit_git_bridge::gitparse::parse_commit(input) {
        // Real invariant: the identity is a slice of the input, so it
        // can never exceed the input length.
        assert!(c.author.identity.len() <= input.len());
    }
}

/// Apply the git tag parser against `input`.
pub fn git_tag_parse_one_iteration(input: &[u8]) {
    let input = &input[..input.len().min(MAX_INPUT)];
    let _ = kit_git_bridge::gitparse::parse_tag(input);
}

/// SPEC-WRITE-GRANTS grant codec (`grant_parse`): `Grant::parse` and
/// `SignedHeader::parse` never panic, and anything they accept re-encodes to
/// exactly the input bytes (one canonical encoding, so one grant id).
pub fn grant_and_header_parse_one_iteration(input: &[u8]) {
    use kit_attest::grant::{Grant, SignedHeader};
    let input = &input[..input.len().min(MAX_INPUT)];
    if let Ok(grant) = Grant::parse(input) {
        assert_eq!(
            grant.encode().expect("accepted grant must re-encode"),
            input,
            "accepted grant must re-encode byte for byte"
        );
    }
    if let Ok(text) = core::str::from_utf8(input)
        && let Ok(header) = SignedHeader::parse(text)
    {
        assert_eq!(
            header.encode().expect("accepted header must re-encode"),
            text,
            "accepted header must re-encode byte for byte"
        );
        if let Ok(grant) = Grant::parse(&header.statement) {
            assert_eq!(
                grant.encode().expect("accepted grant must re-encode"),
                header.statement
            );
        }
    }
}

/// Config text parser (`config_parse`): `apply_text` never panics. A
/// repo-scope parse accepts no forbidden key, so the sentinel values that a
/// hostile repo plants never reach the merged config.
pub fn config_parse_one_iteration(input: &[u8]) {
    use kit_storage::config::{Config, ConfigScope, apply_text};
    let input = &input[..input.len().min(MAX_INPUT)];
    let Ok(text) = core::str::from_utf8(input) else {
        return;
    };
    let path = std::path::Path::new("fuzz-config");
    for scope in [ConfigScope::Repo, ConfigScope::User] {
        let mut cfg = Config::default();
        let _ = apply_text(&mut cfg, text, path, scope, false);
        if scope == ConfigScope::Repo {
            // A repo file must never set a user-scoped key.
            assert!(cfg.trusted_remote_endpoint.is_empty());
            assert!(cfg.http_ssl_ca_info.is_empty());
            assert!(cfg.pull_require_signed.is_empty());
        }
    }
}

/// Stash manifest decoder (`stash_list`): `deserialize_list` never panics,
/// and anything it accepts re-encodes to exactly the input bytes.
pub fn stash_list_one_iteration(input: &[u8]) {
    use kit_core::ops::stash::{deserialize_list, serialize_list};
    let input = &input[..input.len().min(MAX_INPUT)];
    if let Ok(list) = deserialize_list(input) {
        assert_eq!(
            serialize_list(&list).expect("accepted list must re-encode"),
            input,
            "accepted stash list must re-encode byte for byte"
        );
    }
}

/// Git bridge map and ref-state files (`bridge_map`): the loaders never
/// panic on any file content.
pub fn bridge_map_one_iteration(input: &[u8]) {
    use kit_git_bridge::map::{load_import_ref_state, load_map, load_map_inverse, map_is_intact};
    let input = &input[..input.len().min(MAX_INPUT)];
    let dir = tempfile::tempdir().expect("tempdir");
    for name in ["map", "refs", "refs-import"] {
        std::fs::write(dir.path().join(name), input).expect("write fixture");
    }
    let _ = map_is_intact(dir.path());
    let _ = load_map(dir.path());
    let _ = load_map_inverse(dir.path());
    let _ = load_import_ref_state(dir.path());
}

/// SPEC-WRITE-GRANTS epoch, visibility and URL token statements and the
/// stateless verifier (`epoch_visibility_parse`): `EpochStatement::parse`,
/// `VisibilityStatement::parse` and `UrlTokenStatement::parse` never panic,
/// and anything they accept re-encodes to exactly the input bytes. The input,
/// read as a URL token, also runs through `verify_url_token` with an empty
/// key set, which must not panic and must refuse it. The input, read as an
/// `X-Write-Grant` value, also runs through every verifier entry point,
/// which must not panic, and whose accepted statements are the canonical
/// bytes of the header. The input also drives the `webauthn-p256` parsers
/// (see [`webauthn_assertion_checks`]).
pub fn statement_and_token_parse_one_iteration(input: &[u8]) {
    use kit_attest::grant::{
        AcceptedSchemes, Capability, EpochStatement, GrantRequest, OwnerScheme, RepoScope,
        RepositoryIdentity, SignedHeader, TokenTarget, UrlTokenRequest, UrlTokenStatement,
        VerifierConfig, VisibilityStatement, verify_epoch_statement, verify_for_registration,
        verify_grant_owner, verify_url_token, verify_visibility_statement,
    };
    const NOW_MS: i64 = 1_790_000_000_000;
    let input = &input[..input.len().min(MAX_INPUT)];
    if let Ok(s) = EpochStatement::parse(input) {
        assert_eq!(
            s.encode().expect("accepted epoch statement must re-encode"),
            input,
            "accepted epoch statement must re-encode byte for byte"
        );
    }
    if let Ok(s) = VisibilityStatement::parse(input) {
        assert_eq!(
            s.encode()
                .expect("accepted visibility statement must re-encode"),
            input,
            "accepted visibility statement must re-encode byte for byte"
        );
    }
    if let Ok(s) = UrlTokenStatement::parse(input) {
        assert_eq!(
            s.encode().expect("accepted token statement must re-encode"),
            input,
            "accepted token statement must re-encode byte for byte"
        );
    }
    webauthn_assertion_checks(input);
    let Ok(text) = core::str::from_utf8(input) else {
        return;
    };
    if let Ok(target) = TokenTarget::parse(text) {
        assert_eq!(
            target.encode().ok().as_deref(),
            Some(text),
            "accepted token target must re-encode byte for byte"
        );
    }
    let repository = RepositoryIdentity::parse("0x8ba1f109551bd432803012645ac136ddd64dba72/fuzz")
        .expect("fixed repository is valid");
    let target = TokenTarget::Object([0; 32]);
    assert!(
        verify_url_token(
            text,
            &[],
            &UrlTokenRequest {
                audience: "https://git.example.com",
                repository: &repository,
                target: &target,
                now_ms: NOW_MS,
            },
        )
        .is_err(),
        "a token never verifies against an empty key set"
    );
    let Ok(header) = SignedHeader::parse(text) else {
        return;
    };
    let cfg = VerifierConfig::new(
        "https://git.example.com",
        AcceptedSchemes::of(&[
            OwnerScheme::Ed25519,
            OwnerScheme::Secp256k1Eip191,
            OwnerScheme::WebAuthnP256,
        ]),
        vec![fuzz_relying_party()],
    )
    .expect("fixed fuzz config is valid");
    if let Ok(v) = verify_epoch_statement(&cfg, text, NOW_MS) {
        assert_eq!(v.statement().encode().ok(), Some(header.statement.clone()));
    }
    if let Ok(s) = VisibilityStatement::parse(&header.statement)
        && let Ok(v) = verify_visibility_statement(&cfg, text, &s.repository, NOW_MS)
    {
        assert_eq!(v.statement(), &s);
    }
    if let Ok(owner) = verify_grant_owner(&cfg, text) {
        let g = owner.statement();
        assert_eq!(g.encode().ok(), Some(header.statement.clone()));
        let repository = match &g.scope {
            RepoScope::Repository(id) => id.clone(),
            RepoScope::Namespace => RepositoryIdentity::new(Some(g.namespace), "fuzz")
                .expect("fixed repository name is valid"),
        };
        for capability in [Capability::Read, Capability::Write] {
            let _ = owner.check(
                &cfg,
                &GrantRequest {
                    repository: &repository,
                    signer: &g.grantee,
                    capability,
                    now_ms: NOW_MS,
                },
            );
        }
        let _ = verify_for_registration(&cfg, text, &g.grantee);
    }
}

fn fuzz_relying_party() -> kit_attest::grant::RelyingParty {
    kit_attest::grant::RelyingParty::new("example.com", ["https://example.com"])
        .expect("fixed relying party is valid")
}

/// The `webauthn-p256` owner scheme's parsers (SPEC-WRITE-GRANTS §4, §4.3):
/// `input` as a whole blob, which never panics and, when its framing
/// parses, re-encodes to exactly the input; and `input` as the
/// `clientDataJSON` of an assertion that passes every check before the
/// client data (owner key: the P-256 generator; `authenticatorData` for
/// `example.com` with UP set), so the strict JSON walk sees arbitrary bytes.
/// The signature `(1, 1)` never verifies, so neither may succeed.
pub fn webauthn_assertion_checks(input: &[u8]) {
    use kit_attest::grant::{
        AcceptedSchemes, Namespace, OwnerScheme, VerifierConfig, WebAuthnAssertion,
        verify_owner_signature,
    };
    /// The P-256 generator `x ‖ y` (SEC 2 §2.4.2).
    const G: [u8; 64] = [
        0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40,
        0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98,
        0xc2, 0x96, 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c,
        0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68,
        0x37, 0xbf, 0x51, 0xf5,
    ];
    /// SHA-256("example.com").
    const RP_HASH: [u8; 32] = [
        0xa3, 0x79, 0xa6, 0xf6, 0xee, 0xaf, 0xb9, 0xa5, 0x5e, 0x37, 0x8c, 0x11, 0x80, 0x34, 0xe2,
        0x75, 0x1e, 0x68, 0x2f, 0xab, 0x9f, 0x2d, 0x30, 0xab, 0x13, 0xd2, 0x12, 0x55, 0x86, 0xce,
        0x19, 0x47,
    ];
    let input = &input[..input.len().min(MAX_INPUT)];
    let cfg = VerifierConfig::new(
        "https://git.example.com",
        AcceptedSchemes::of(&[OwnerScheme::WebAuthnP256]),
        vec![fuzz_relying_party()],
    )
    .expect("fixed fuzz config is valid");
    let namespace = Namespace::Address(
        kit_attest::eth::address_p256(&G).expect("the generator is a P-256 point"),
    );
    let statement = b"kit-write-grant:v1";
    let _ = verify_owner_signature(
        &cfg,
        OwnerScheme::WebAuthnP256,
        statement,
        input,
        &namespace,
    );
    if let Ok(assertion) = WebAuthnAssertion::parse(input) {
        assert_eq!(
            assertion.encode().expect("a parsed assertion re-encodes"),
            input,
            "a parsed webauthn blob must re-encode byte for byte"
        );
    }
    let mut authenticator_data = RP_HASH.to_vec();
    authenticator_data.extend_from_slice(&[0x01, 0, 0, 0, 0]);
    let mut signature = [0u8; 64];
    signature[31] = 1;
    signature[63] = 1;
    let blob = WebAuthnAssertion {
        public_key: G,
        authenticator_data,
        client_data_json: input.to_vec(),
        signature,
    }
    .encode()
    .expect("a bounded assertion encodes");
    assert!(
        verify_owner_signature(
            &cfg,
            OwnerScheme::WebAuthnP256,
            statement,
            &blob,
            &namespace
        )
        .is_err()
    );
}

/// Apply the git tree parser + mode classifier against `input`.
pub fn git_tree_parse_one_iteration(input: &[u8]) {
    let input = &input[..input.len().min(MAX_INPUT)];
    if let Ok(entries) = kit_git_bridge::gitparse::parse_tree(input) {
        for e in entries {
            let _ = kit_git_bridge::gitparse::map_mode(&e.mode);
        }
    }
}

/// Apply the encrypted software-key record decoder against `input`.
pub fn software_key_record_one_iteration(input: &[u8]) {
    let input = &input[..input.len().min(MAX_INPUT)];
    let _ = kit_keystore::fuzz_decode_software_key_record(input);
}

/// Fuzz the kit-rpc wire decoders. Two properties per iteration:
///
/// 1. **Decode never panics.** Both protocol roots (`SignerFrame`,
///    `SshFrame`) are decoded from the raw input, through the
///    production decode caps (`frame_decode_options`) and the bare
///    decoder. Any input may fail to decode; none may panic.
/// 2. **Wire roundtrip.** The input entropy drives
///    `arbitrary::Arbitrary` to build structurally valid frames
///    (kit-rpc's `arbitrary` feature, from buffa
///    `generate_arbitrary` codegen); encode → decode → re-encode must
///    reproduce the same wire bytes. (Value equality would not hold:
///    an `Arbitrary` open-enum `Unknown(v)` for a known wire value `v`
///    is canonicalized to `Known(_)` on decode, yet both encode to the
///    same bytes.)
pub fn rpc_decode_one_iteration(input: &[u8]) {
    use arbitrary::Arbitrary;
    use buffa::Message;
    use kit_rpc::kit::rpc::v1::signer::SignerFrame;
    use kit_rpc::kit::rpc::v1::ssh::SshFrame;

    let input = &input[..input.len().min(MAX_INPUT)];

    let _ = kit_rpc::frame_decode_options().decode_from_slice::<SignerFrame>(input);
    let _ = kit_rpc::frame_decode_options().decode_from_slice::<SshFrame>(input);
    let _ = SignerFrame::decode_from_slice(input);
    let _ = SshFrame::decode_from_slice(input);

    // Wire-level roundtrip, NOT value-level: `Arbitrary` can build an
    // open-enum field as `EnumValue::Unknown(v)` for a `v` that IS a
    // known wire value, which the decoder canonicalizes back to
    // `Known(_)` — so `frame == decoded` legitimately diverges. The
    // property that must hold is that re-encoding the decoded message
    // reproduces the same bytes (both representations encode `v`
    // identically).
    let mut u = arbitrary::Unstructured::new(input);
    if let Ok(frame) = SignerFrame::arbitrary(&mut u) {
        let bytes = frame.encode_to_vec();
        let decoded = SignerFrame::decode_from_slice(&bytes).expect("re-decode SignerFrame");
        assert_eq!(
            bytes,
            decoded.encode_to_vec(),
            "SignerFrame wire roundtrip diverged"
        );
    }
    if let Ok(frame) = SshFrame::arbitrary(&mut u) {
        let bytes = frame.encode_to_vec();
        let decoded = SshFrame::decode_from_slice(&bytes).expect("re-decode SshFrame");
        assert_eq!(
            bytes,
            decoded.encode_to_vec(),
            "SshFrame wire roundtrip diverged"
        );
    }
}

/// Decode a packlist node from untrusted bytes — the
/// `Transport::download_blob` boundary of the delta-push discovery chain
/// (transfer.rs, now backed by `commonware-codec`). It accepts arbitrary
/// remote bytes, so it must never panic, over-allocate, or hang. When a
/// blob decodes, re-encoding it MUST reproduce a blob that decodes to the
/// same node (encode∘decode stability over the codec body).
pub fn merkle_packlist_one_iteration(input: &[u8]) {
    let input = &input[..input.len().min(MAX_INPUT)];
    if let Ok(node) = kit_core::transfer::decode_packlist(input)
        && let Ok(re) = kit_core::transfer::encode_packlist(node.prev, &node.packs)
    {
        assert_eq!(
            kit_core::transfer::decode_packlist(&re),
            Ok(node),
            "packlist re-encode must round-trip"
        );
    }
}

/// Exercise merkle object identity and inclusion-proof verification on
/// arbitrary input. Building an id must never panic and always yields 32
/// bytes; a freshly built proof must verify; and `verify_*` over
/// adversarial proof bytes must reject cleanly (never panic).
pub fn merkle_proof_one_iteration(input: &[u8]) {
    use kit_core::merkle;
    use kit_core::object::{ChunkedBlob, EntryMode, Tree, TreeEntry};
    let input = &input[..input.len().min(MAX_INPUT)];

    // Build a ChunkedBlob from up to 64 chunk ids carved from `input`.
    let chunks: Vec<[u8; 32]> = input
        .chunks(32)
        .take(64)
        .map(|c| {
            let mut h = [0u8; 32];
            h[..c.len()].copy_from_slice(c);
            h
        })
        .collect();
    let cb = ChunkedBlob {
        total_size: input.len() as u64,
        chunk_size: 0,
        chunks: chunks.clone(),
    };
    let cid = merkle::compute_chunked_id(&cb);
    assert_eq!(cid.len(), 32);
    if !chunks.is_empty() {
        // position 0 is the meta leaf; chunk i is at position i+1.
        let pos = (input.first().copied().unwrap_or(0) as usize % chunks.len()) as u32 + 1;
        if let Ok(proof) = merkle::build_chunk_proof(&cb, pos) {
            merkle::verify_chunk(&cid, &chunks[(pos - 1) as usize], pos, &proof)
                .expect("freshly built chunk proof must verify");
        }
        // Adversarial proof bytes / position must reject without panicking.
        // `input` is arbitrary fuzzer bytes, not necessarily a valid encoded
        // `Proof`; decode it first (bounded) and only pass a successfully
        // decoded proof to `verify_chunk` — a decode failure is itself a
        // clean rejection.
        if let Ok(proof) = merkle::Proof::decode(input, 1) {
            let _ = merkle::verify_chunk(&cid, &chunks[0], 0, &proof);
        }
    }

    // A Tree from the same bytes (one entry, name derived from input).
    let tree = Tree {
        entries: vec![TreeEntry {
            name: if input.is_empty() {
                b"x".to_vec()
            } else {
                vec![input[0].max(1)]
            },
            mode: EntryMode::Blob,
            object_hash: chunks.first().copied().unwrap_or([0u8; 32]),
        }],
    };
    let tid = merkle::compute_tree_id(&tree);
    assert_eq!(tid.len(), 32);
    if let Ok(p) = merkle::build_tree_entry_proof(&tree, 0) {
        merkle::verify_tree_entry(&tid, &tree.entries[0], 0, &p)
            .expect("freshly built tree proof must verify");
    }
    // Adversarial proof bytes must reject without panicking (see the
    // chunk-proof comment above for why we decode first).
    if let Ok(p) = merkle::Proof::decode(input, 1) {
        let _ = merkle::verify_tree_entry(&tid, &tree.entries[0], 0, &p);
    }
}

/// Decode a partial-disclosure bundle (SPEC-DISCLOSURE)
/// from arbitrary input against a fixed dummy commit id.
/// `verify::verify_disclosure` decodes the bundle before ever comparing
/// against the caller's id, so this exercises the decoder's bounds
/// (oversize bundle, bad magic/version, over-cap `Vec`/`Proof` lengths,
/// trailing bytes) on adversarial bytes: it must never panic, and must
/// never allocate based on an unvalidated length.
pub fn disclosure_decode_one_iteration(input: &[u8]) {
    let input = &input[..input.len().min(MAX_INPUT)];
    let commit_id = [0u8; 32];
    let _ = kit_core::verify::verify_disclosure(&commit_id, input);
}

const GOOD_SPAN: &[u8] = include_bytes!("../../tests/golden/http-objects/span_two_chunks.bin");

/// Exercise the KDSP verifier on arbitrary bytes. The trusted id is the
/// committed fixture's real commit, and a copy of the input with that commit
/// spliced into the header is also verified, so mutated containers get past
/// the commit comparison and reach the anchor and chunk checks.
pub fn span_decode_one_iteration(input: &[u8]) {
    let input = &input[..input.len().min(MAX_INPUT)];
    let commit: [u8; 32] = GOOD_SPAN[5..37].try_into().expect("committed commit id");
    let _ = kit_core::verify::span::verify_disclosure_span(&commit, input);
    if input.len() >= 37 && input.starts_with(b"KDSP\x01") {
        let mut patched = input.to_vec();
        patched[5..37].copy_from_slice(&commit);
        let _ = kit_core::verify::span::verify_disclosure_span(&commit, &patched);
    }
}

const SPAN_CHUNK: usize = 48;
const SPAN_CHUNKS: usize = 4;

/// A small chunked-file repository for [`verify_span_one_iteration_with`].
pub struct SpanFixture {
    _dir: tempfile::TempDir,
    store: kit_core::store::ObjectStore,
    commit_id: [u8; 32],
    plaintext: Vec<u8>,
}

/// Build a [`SpanFixture`]: one signed commit over a four-chunk file.
pub fn build_span_fixture() -> SpanFixture {
    use kit_core::hash::ZERO;
    use kit_core::layout::RepoLayout;
    use kit_core::object::{
        Blob, ChunkedBlob, Commit, EntryMode, Identity, Object, Tree, TreeEntry,
    };
    use kit_core::sign::{KeyPair, sign_commit};
    use kit_core::store::ObjectStore;

    const CHUNK: usize = SPAN_CHUNK;
    const CHUNKS: usize = SPAN_CHUNKS;
    let dir = tempfile::TempDir::new().expect("tempdir");
    let store = ObjectStore::init(&RepoLayout::single(dir.path())).expect("store init");
    let plaintext: Vec<u8> = (0..CHUNK * CHUNKS)
        .map(|i| u8::try_from(i % 251).expect("byte") ^ 0x5a)
        .collect();
    let chunk_ids: Vec<[u8; 32]> = plaintext
        .chunks(CHUNK)
        .map(|c| {
            let bytes = kit_core::serialize::serialize(&Object::Blob(Blob { data: c.to_vec() }))
                .expect("serialize chunk");
            store.write(&bytes).expect("write chunk")
        })
        .collect();
    let manifest = ChunkedBlob {
        total_size: plaintext.len() as u64,
        chunk_size: CHUNK as u32,
        chunks: chunk_ids,
    };
    let leaf = store
        .write(&kit_core::serialize::serialize(&Object::ChunkedBlob(manifest)).expect("manifest"))
        .expect("write manifest");
    let tree = Tree {
        entries: vec![TreeEntry {
            name: b"f.bin".to_vec(),
            mode: EntryMode::Blob,
            object_hash: leaf,
        }],
    };
    let tree_hash = store
        .write(&kit_core::serialize::serialize(&Object::Tree(tree)).expect("serialize tree"))
        .expect("write tree");
    let kp = KeyPair::from_seed([0x43; 32]);
    let mut commit = Commit {
        tree_hash,
        parents: vec![],
        author: Identity::ed25519(kp.public.0),
        signer: kp.public.0,
        message: b"span fuzz fixture".to_vec(),
        timestamp: 1,
        message_hash: ZERO,
        content_digest: ZERO,
        signature: [0u8; 64],
    };
    commit.signature = sign_commit(&commit, &kp).expect("sign commit").0;
    let commit_id = store
        .write(&kit_core::serialize::serialize(&Object::Commit(commit)).expect("commit"))
        .expect("write commit");

    SpanFixture {
        _dir: dir,
        store,
        commit_id,
        plaintext,
    }
}

/// Build a fresh fixture and run [`verify_span_one_iteration_with`].
pub fn verify_span_one_iteration(input: &[u8]) {
    verify_span_one_iteration_with(input, &build_span_fixture());
}

/// Build an input-driven range proof over the fixture, verify it, then flip
/// an input-driven byte and require that any acceptance still returns the
/// file's true plaintext for the range it names. Raw bytes also go through
/// the verifier against the fixture's real commit.
pub fn verify_span_one_iteration_with(input: &[u8], fixture: &SpanFixture) {
    use kit_core::verify::span::{RangeProof, build_range_proof_from};

    const CHUNK: usize = SPAN_CHUNK;
    const CHUNKS: usize = SPAN_CHUNKS;
    let SpanFixture {
        store,
        commit_id,
        plaintext,
        ..
    } = fixture;
    let commit_id = *commit_id;
    let input = &input[..input.len().min(MAX_INPUT)];
    let byte = |i: usize| u64::from(input.get(i).copied().unwrap_or(0));
    let word = |i: usize| byte(i) | (byte(i + 1) << 8);

    let total = plaintext.len() as u64;
    let offset = word(0) % total;
    let len = 1 + word(2) % (total - offset);
    let boundaries: Vec<u64> = (0..=CHUNKS as u64).map(|i| i * CHUNK as u64).collect();
    let hints = (byte(4) & 1 == 1).then_some(boundaries.as_slice());
    let proof = build_range_proof_from(store, &commit_id, &[b"f.bin"], offset, len, hints)
        .expect("in-range proof must build");
    let expected = &plaintext
        [usize::try_from(offset).expect("offset")..usize::try_from(offset + len).expect("end")];
    let container = match proof {
        RangeProof::Mkdp(bytes) => {
            let disclosed = kit_core::verify::verify_disclosure(&commit_id, &bytes)
                .expect("fresh KDPB must verify");
            assert!(matches!(
                disclosed.payload,
                kit_core::verify::DisclosedPayload::Range { .. }
            ));
            return;
        }
        RangeProof::Mkds(bytes) => bytes,
        _ => unreachable!("non-exhaustive RangeProof"),
    };
    let verified = kit_core::verify::span::verify_disclosure_span(&commit_id, &container)
        .expect("fresh span must verify");
    assert_eq!(verified.bytes, expected);

    let mut mutated = container;
    let at = usize::try_from(word(5)).expect("position") % mutated.len();
    mutated[at] ^= input.get(7).copied().unwrap_or(1).max(1);
    if let Ok(accepted) = kit_core::verify::span::verify_disclosure_span(&commit_id, &mutated) {
        // A flipped header field may legitimately request another range, but
        // whatever verifies must be that range's true plaintext.
        let begin = usize::try_from(accepted.offset).expect("accepted offset");
        assert_eq!(
            accepted.bytes,
            plaintext[begin..begin + accepted.bytes.len()],
            "a mutated span verified bytes that are not the file's"
        );
    }
    let _ = kit_core::verify::span::verify_disclosure_span(&commit_id, input);
}

/// A small native `ObjectStore`-backed fixture for
/// [`verify_disclosure_one_iteration`]: one committed file, disclosed as
/// a real `Selector::Object` bundle. Built once by
/// [`build_disclosure_fixture`] and reused across all iterations of the
/// unit-test loop via [`run_iterated_unit_with`]; real libfuzzer runs
/// build a fresh one per call for isolation (mirrors
/// [`pack_reader_one_iteration`] vs [`pack_reader_one_iteration_with_store`]).
pub struct DisclosureFixture {
    _dir: tempfile::TempDir,
    commit_id: [u8; 32],
    good_bundle: Vec<u8>,
}

/// Build a [`DisclosureFixture`]. Never fails in practice (every step is
/// a fixed, valid construction over fixed bytes); panics only on a
/// genuine environment failure (no writable temp dir), same posture as
/// [`pack_reader_one_iteration_with_store`]'s `ObjectStore::init`.
pub fn build_disclosure_fixture() -> DisclosureFixture {
    use kit_core::hash::ZERO;
    use kit_core::layout::RepoLayout;
    use kit_core::object::{Commit, EntryMode, Identity, Object, Tree, TreeEntry};
    use kit_core::sign::{KeyPair, sign_commit};
    use kit_core::store::ObjectStore;
    use kit_core::verify::{self, Selector};
    use kit_core::worktree::store_file_object;

    let dir = tempfile::TempDir::new().expect("tempdir");
    let store = ObjectStore::init(&RepoLayout::single(dir.path())).expect("store init");
    let blob_id =
        store_file_object(&store, b"disclosure fuzz fixture content").expect("store file");
    let tree = Tree {
        entries: vec![TreeEntry {
            name: b"f.txt".to_vec(),
            mode: EntryMode::Blob,
            object_hash: blob_id,
        }],
    };
    let tree_hash = store
        .write(&kit_core::serialize::serialize(&Object::Tree(tree)).expect("serialize tree"))
        .expect("write tree");
    let kp = KeyPair::from_seed([0x42; 32]);
    let mut commit = Commit {
        tree_hash,
        parents: vec![],
        author: Identity::ed25519(kp.public.0),
        signer: kp.public.0,
        message: b"disclosure fuzz fixture".to_vec(),
        timestamp: 1,
        message_hash: ZERO,
        content_digest: ZERO,
        signature: [0u8; 64],
    };
    commit.signature = sign_commit(&commit, &kp).expect("sign commit").0;
    let commit_bytes =
        kit_core::serialize::serialize(&Object::Commit(commit)).expect("serialize commit");
    let commit_id = store.write(&commit_bytes).expect("write commit");
    let good_bundle = verify::build_disclosure(&store, &commit_id, &[b"f.txt"], Selector::Object)
        .expect("build disclosure");
    DisclosureFixture {
        _dir: dir,
        commit_id,
        good_bundle,
    }
}

/// Exercise `verify::verify_disclosure` against a real fixture. Three
/// properties per iteration: (1) the freshly built bundle MUST verify;
/// (2) an input-driven single-byte mutation of that bundle MUST reject
/// cleanly (never panic) — mutating one byte of a genuine bundle can
/// never happen to re-verify unless the mutation lands in a truly
/// don't-care byte, which `verify_disclosure`'s exhaustive checks (id,
/// hash, every proof, every Bao slice) leave essentially none of; (3)
/// raw fuzzer bytes verified directly against the fixture's real commit
/// id must never panic.
pub fn verify_disclosure_one_iteration(input: &[u8]) {
    let fixture = build_disclosure_fixture();
    verify_disclosure_one_iteration_with(input, &fixture);
}

/// As [`verify_disclosure_one_iteration`], but against a caller-provided
/// [`DisclosureFixture`] instead of building a fresh one — lets the
/// unit-test loop amortize the tempdir/store/signing cost across all
/// `MAX_ITER` iterations.
pub fn verify_disclosure_one_iteration_with(input: &[u8], fixture: &DisclosureFixture) {
    use kit_core::verify;

    let input = &input[..input.len().min(MAX_INPUT)];

    let disclosed = verify::verify_disclosure(&fixture.commit_id, &fixture.good_bundle)
        .expect("freshly built disclosure must verify");
    // Builder fills `inner_root` from the parent tree; verify wrap-checks
    // it then requires the proof fold to equal the declared field. Re-check
    // the wrap of every authenticated root here so a builder/verifier
    // disagreement cannot slip through a successful round-trip.
    use kit_core::merkle::{self, ObjectKind};
    if let Some(root) = disclosed.step_inner_roots.first() {
        assert_eq!(
            merkle::wrap_id(ObjectKind::Tree, root),
            disclosed.tree_hash,
            "step 0 inner_root must wrap to tree_hash"
        );
    }
    if let Some(root) = disclosed.chunk_inner_root {
        assert_eq!(
            merkle::wrap_id(ObjectKind::ChunkedBlob, &root),
            disclosed.leaf_id,
            "chunk inner_root must wrap to the leaf ChunkedBlob id"
        );
    }

    if !fixture.good_bundle.is_empty() && input.len() >= 2 {
        let mut mutated = fixture.good_bundle.clone();
        let pos = usize::from(input[0]) % mutated.len();
        let flip = input[1].max(1); // guaranteed non-zero XOR
        mutated[pos] ^= flip;
        let _ = verify::verify_disclosure(&fixture.commit_id, &mutated);
    }

    let _ = verify::verify_disclosure(&fixture.commit_id, input);
}

/// Store-less pack iterator: never panics on adversarial bytes. When
/// `PackReader::read` accepts a pack, `PackEntries::new` accepts it too
/// and yields `raw_count + delta_count` items. `decode_entries_with`
/// over `NoExternalBases` agrees with `PackReader::read` into an empty
/// store on every input: same accept/reject, same error, same ids.
pub fn pack_entries_one_iteration(input: &[u8]) {
    let Some(input) = pack_validated_input(input) else {
        return;
    };
    let parsed = kit_core::pack::PackEntries::new(input);
    if let Ok(entries) = parsed {
        let mut n = 0usize;
        for item in entries {
            match item {
                Ok(_) => n += 1,
                Err(_) => break,
            }
        }
        let _ = n;
    }

    let dir = match tempfile::TempDir::new() {
        Ok(d) => d,
        Err(_) => return,
    };
    let layout = kit_core::layout::RepoLayout::single(dir.path());
    let store = match kit_core::store::ObjectStore::init(&layout) {
        Ok(s) => s,
        Err(_) => return,
    };
    let read = kit_core::pack::PackReader::read(input, &store);
    // Into an empty store, the store-less decoder with no external bases
    // must accept exactly the packs the reader accepts, with the same
    // error and the same ids in pack order.
    let decoded = kit_core::pack::decode_entries_with(
        input,
        &mut kit_core::pack::NoExternalBases,
        // No budget: this body pins agreement with the reader, which has
        // none. The budget itself is covered by kit-core unit tests.
        kit_core::pack::DecodeLimits::default().with_max_decoded_bytes(u64::MAX),
        |_| Ok(()),
    );
    match (&read, &decoded) {
        (Ok(report), Ok(decoded)) => assert_eq!(
            report.stored, decoded.ids,
            "decode_entries_with must yield PackReader's ids in pack order"
        ),
        (Err(a), Err(b)) => assert_eq!(
            a.to_string(),
            b.to_string(),
            "decode_entries_with must fail exactly as PackReader::read"
        ),
        _ => panic!(
            "decode_entries_with(NoExternalBases) and PackReader::read into an empty \
             store disagree: reader {:?}, decoder {:?}",
            read.as_ref().map(|_| ()),
            decoded.as_ref().map(|_| ())
        ),
    }
    if let Ok(report) = read {
        let entries = kit_core::pack::PackEntries::new(input)
            .expect("PackReader-accepted pack must parse as PackEntries");
        let got = entries.filter(|e| e.is_ok()).count();
        assert_eq!(
            got,
            (report.raw_count + report.delta_count) as usize,
            "PackEntries must yield one item per PackReader-stored entry"
        );
    }
}

/// A tiny native fixture for [`verify_closure_one_iteration`]: one
/// committed file, exported as a snapshot closure.
pub struct ClosureFixture {
    _dir: tempfile::TempDir,
    store: kit_core::store::ObjectStore,
    root: [u8; 32],
    manifest: Vec<u8>,
    packs: Vec<Vec<u8>>,
}

/// Build a [`ClosureFixture`]. Panics only on a genuine environment
/// failure (no writable temp dir).
pub fn build_closure_fixture() -> ClosureFixture {
    use kit_core::ClosureMode;
    use kit_core::hash::ZERO;
    use kit_core::layout::RepoLayout;
    use kit_core::object::{Commit, EntryMode, Identity, Object, Tree, TreeEntry};
    use kit_core::sign::{KeyPair, sign_commit};
    use kit_core::store::ObjectStore;
    use kit_core::verify::export_closure;
    use kit_core::worktree::store_file_object;

    let dir = tempfile::TempDir::new().expect("tempdir");
    let store = ObjectStore::init(&RepoLayout::single(dir.path())).expect("store init");
    let blob_id = store_file_object(&store, b"closure fuzz fixture").expect("store file");
    let tree = Tree {
        entries: vec![TreeEntry {
            name: b"f.txt".to_vec(),
            mode: EntryMode::Blob,
            object_hash: blob_id,
        }],
    };
    let tree_hash = store
        .write(&kit_core::serialize::serialize(&Object::Tree(tree)).expect("serialize tree"))
        .expect("write tree");
    let kp = KeyPair::from_seed([0x43; 32]);
    let mut commit = Commit {
        tree_hash,
        parents: vec![],
        author: Identity::ed25519(kp.public.0),
        signer: kp.public.0,
        message: b"closure fuzz fixture".to_vec(),
        timestamp: 1,
        message_hash: ZERO,
        content_digest: ZERO,
        signature: [0u8; 64],
    };
    commit.signature = sign_commit(&commit, &kp).expect("sign commit").0;
    let commit_bytes =
        kit_core::serialize::serialize(&Object::Commit(commit)).expect("serialize commit");
    let root = store.write(&commit_bytes).expect("write commit");
    let export = export_closure(&store, &root, ClosureMode::Snapshot).expect("export closure");
    ClosureFixture {
        _dir: dir,
        store,
        root,
        manifest: export.manifest,
        packs: export.packs,
    }
}

/// Never panics. A freshly exported closure MUST verify; a mutated
/// manifest or pack MUST reject cleanly; raw input as a pack MUST not
/// panic.
pub fn verify_closure_one_iteration(input: &[u8]) {
    let fixture = build_closure_fixture();
    verify_closure_one_iteration_with(input, &fixture);
}

/// As [`verify_closure_one_iteration`], amortizing fixture construction.
pub fn verify_closure_one_iteration_with(input: &[u8], fixture: &ClosureFixture) {
    use kit_core::verify;

    let input = &input[..input.len().min(MAX_INPUT)];
    let pack_refs: Vec<&[u8]> = fixture.packs.iter().map(Vec::as_slice).collect();
    verify::verify_closure_manifest(&fixture.root, &fixture.manifest, &pack_refs)
        .expect("freshly exported closure must verify")
        .is_complete()
        .then_some(())
        .expect("freshly exported closure must be complete");

    let mut objects = Vec::new();
    for pack in &fixture.packs {
        for entry in
            kit_core::pack::PackEntries::new(pack).expect("freshly exported closure must parse")
        {
            let kit_core::pack::PackEntry::Raw { bytes } =
                entry.expect("freshly exported closure entries must parse")
            else {
                panic!("freshly exported closure must be raw-only");
            };
            objects.push(bytes.into_owned());
        }
    }
    let map_report = verify::verify_closure(
        &fixture.root,
        kit_core::ClosureMode::Snapshot,
        objects.iter().map(Vec::as_slice),
    )
    .expect("freshly exported closure map path must verify");
    let store_report = verify::verify_closure_store(
        &fixture.store,
        &fixture.root,
        kit_core::ClosureMode::Snapshot,
    )
    .expect("freshly exported closure store path must verify");
    assert_eq!(map_report.missing, store_report.missing);
    assert_eq!(map_report.verified, store_report.verified);
    assert_eq!(map_report.is_complete(), store_report.is_complete());

    if !fixture.manifest.is_empty() && input.len() >= 2 {
        let mut mutated = fixture.manifest.clone();
        let pos = usize::from(input[0]) % mutated.len();
        mutated[pos] ^= input[1].max(1);
        let _ = verify::verify_closure_manifest(&fixture.root, &mutated, &pack_refs);
    }
    let _ = verify::verify_closure(&fixture.root, kit_core::ClosureMode::Snapshot, [input]);
    let _ = kit_core::pack::PackEntries::new(input);

    // Feed raw fuzzer input directly as closure pack buffers (not wrapped
    // in valid PackEntries framing), both whole and split into two, so the
    // profile/framing checks in verify_closure_packs and
    // verify_closure_manifest see adversarial bytes a legitimate exporter
    // could never produce. Any `Ok` report must still be internally
    // consistent.
    let single_pack: [&[u8]; 1] = [input];
    if let Ok(report) =
        verify::verify_closure_packs(&fixture.root, kit_core::ClosureMode::Snapshot, &single_pack)
    {
        assert_closure_report_consistent(&report);
    }
    if let Ok(report) =
        verify::verify_closure_manifest(&fixture.root, &fixture.manifest, &single_pack)
    {
        assert_closure_report_consistent(&report);
    }

    let mid = input.len() / 2;
    let split_pack: [&[u8]; 2] = [&input[..mid], &input[mid..]];
    if let Ok(report) =
        verify::verify_closure_packs(&fixture.root, kit_core::ClosureMode::Snapshot, &split_pack)
    {
        assert_closure_report_consistent(&report);
    }
    if let Ok(report) =
        verify::verify_closure_manifest(&fixture.root, &fixture.manifest, &split_pack)
    {
        assert_closure_report_consistent(&report);
    }
}

/// `is_complete()` must imply no `missing`/`corrupt` entries, for any
/// report produced from adversarial pack bytes.
fn assert_closure_report_consistent(report: &kit_core::verify::ClosureReport) {
    if report.is_complete() {
        assert!(
            report.missing.is_empty(),
            "complete report has missing entries"
        );
        assert!(
            report.corrupt.is_empty(),
            "complete report has corrupt entries"
        );
    }
}

/// Exercise the sparse-checkout build/verify pair on arbitrary input.
/// `build_sparse` must never panic; a freshly built delivery must
/// verify; and `verify_sparse` over adversarial proof/manifest bytes
/// (garbage bitmap, wrong-length bitmap, mismatched filter) must
/// reject cleanly — never panic. `kit-core`'s `sparse-checkout`
/// feature is enabled unconditionally on this crate's dependency (see
/// `Cargo.toml`), so this needs no feature gate of its own.
pub fn sparse_verify_one_iteration(input: &[u8]) {
    use kit_core::object::{EntryMode, Tree, TreeEntry};
    use kit_core::sparse::{SparseProof, build_sparse, verify_sparse};
    use std::path::PathBuf;

    let input = &input[..input.len().min(MAX_INPUT)];
    if input.is_empty() {
        return;
    }

    // A small tree (<= 32 lex-sorted two-letter-named entries) whose
    // object hashes are carved from `input`.
    let n = usize::from(input[0]) % 32 + 1;
    let mut entries = Vec::with_capacity(n);
    for i in 0..n {
        let a = b'a' + u8::try_from(i / 26).unwrap_or(0);
        let b = b'a' + u8::try_from(i % 26).unwrap_or(0);
        let mut hash = [0u8; 32];
        let start = (i * 7) % input.len();
        for (j, byte) in hash.iter_mut().enumerate() {
            *byte = input[(start + j) % input.len()];
        }
        entries.push(TreeEntry {
            name: vec![a, b],
            mode: EntryMode::Blob,
            object_hash: hash,
        });
    }
    let tree = Tree { entries };

    // A filter selecting a pseudo-random subset of the same two-letter
    // names, so it sometimes matches and sometimes doesn't.
    let filter_count = input
        .get(1)
        .copied()
        .map_or(0, |b| usize::from(b) % (n + 1));
    let mut filter = Vec::with_capacity(filter_count);
    for i in 0..filter_count {
        let a = b'a' + u8::try_from(i / 26).unwrap_or(0);
        let b = b'a' + u8::try_from(i % 26).unwrap_or(0);
        filter.push(PathBuf::from(format!("{}{}", a as char, b as char)));
    }

    let Ok(mut response) = build_sparse(&tree, &filter) else {
        return;
    };
    let root = kit_core::sparse::tree_hash(&tree);
    assert!(
        verify_sparse(&root, &filter, &response).is_ok(),
        "fresh witness must verify"
    );
    let honest = response.proof.clone();
    response.proof = SparseProof {
        tree_bytes: input.to_vec(),
    };
    let _ = verify_sparse(&root, &filter, &response);
    response.proof = honest;
    response.proof.tree_bytes.pop();
    let _ = verify_sparse(&root, &filter, &response);
}

/// One ssh session over a fresh repository: a valid `Hello`, then `input`
/// as the raw byte stream of the client. The session must end. Afterwards the
/// repository holds only complete files: every pack hashes to its name, no
/// upload temp file stays, and nothing exists outside `packs/`, `refs/` and
/// `.kit/refs/`.
pub fn ssh_session_one_iteration(input: &[u8]) {
    use kit_core::hash::{hash, to_hex};
    use kit_rpc::kit::rpc::v1::ProtocolVersion;
    use kit_rpc::kit::rpc::v1::ssh::{Hello, SshFrame, ssh_frame};
    use kit_serve::{ReadFrames, Repo, SessionConfig, WriteFrames, WritePolicy, serve_session};

    let input = &input[..input.len().min(MAX_INPUT)];
    let mut stream = Vec::new();
    let hello = SshFrame {
        body: Some(ssh_frame::Body::Hello(Box::new(
            Hello::default().with_proto(ProtocolVersion::ProtocolVersion1),
        ))),
        ..Default::default()
    };
    kit_rpc::write_frame(&mut stream, &hello).expect("encode Hello");
    stream.extend_from_slice(input);

    let dir = tempfile::TempDir::new().expect("tempdir");
    let repo = Repo::open(dir.path(), WritePolicy::Open).expect("open repo");
    let mut src = ReadFrames(std::io::Cursor::new(stream));
    let mut sink = WriteFrames(Vec::new());
    let _ = serve_session(
        &repo,
        None,
        &mut src,
        &mut sink,
        &SessionConfig::new("fuzz"),
    );

    let mut dirs = vec![dir.path().to_path_buf()];
    while let Some(d) = dirs.pop() {
        for entry in std::fs::read_dir(&d).expect("read dir") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                dirs.push(path);
                continue;
            }
            let rel = path.strip_prefix(dir.path()).expect("under root");
            let top = rel.components().next().expect("a component");
            if top.as_os_str() == "packs" {
                let name = rel.file_name().expect("name").to_string_lossy();
                let bytes = std::fs::read(&path).expect("read pack");
                assert_eq!(name, to_hex(&hash(&bytes)), "a pack must hash to its name");
            } else {
                assert!(
                    top.as_os_str() == "refs" || rel.starts_with(".kit/refs"),
                    "unexpected file {}",
                    rel.display()
                );
            }
        }
    }
}

/// Single-shot: invoke `body(input)` with the per-iteration wall-clock
/// cap. libfuzzer harnesses call this from their `fuzz_target!` body; the
/// iteration counter lives one level up, in `run_iterated_unit`.
///
/// A busy machine can stall one call for more than the cap. A call that
/// exceeds the cap therefore runs once more. Only a second slow call fails,
/// because a real slowdown in the body is slow on every call.
pub fn run_one(input: &[u8], body: fn(&[u8])) -> Result<(), GuardrailError> {
    for _ in 0..2 {
        let start = Instant::now();
        body(input);
        if start.elapsed() <= PER_ITER {
            return Ok(());
        }
    }
    Err(GuardrailError::IterationTooSlow)
}

/// PRNG-driven runner used by the unit-test shim. Deterministically
/// generates `MAX_ITER` inputs from `RNG_SEED` and runs `body` against
/// each, enforcing the per-iteration time cap. Any cap miss aborts.
pub fn run_iterated_unit(body: fn(&[u8])) -> Result<(), GuardrailError> {
    let mut prng = SplitMix::new(RNG_SEED);
    let mut buf = vec![0u8; MAX_INPUT];
    for _ in 0..MAX_ITER {
        let len = prng.range_usize(MAX_INPUT);
        prng.fill(&mut buf[..len]);
        run_one(&buf[..len], body)?;
    }
    Ok(())
}

/// As [`run_iterated_unit`], but threads a caller-owned `state: &T`
/// through to `body` on every iteration instead of requiring `body` to
/// build its own per-call state — used by the pack target
/// to reuse one tempdir/store across all `MAX_ITER` iterations.
pub fn run_iterated_unit_with<T>(state: &T, body: fn(&[u8], &T)) -> Result<(), GuardrailError> {
    let mut prng = SplitMix::new(RNG_SEED);
    let mut buf = vec![0u8; MAX_INPUT];
    for _ in 0..MAX_ITER {
        let len = prng.range_usize(MAX_INPUT);
        prng.fill(&mut buf[..len]);
        let start = Instant::now();
        body(&buf[..len], state);
        if start.elapsed() > PER_ITER {
            return Err(GuardrailError::IterationTooSlow);
        }
    }
    Ok(())
}

/// Attestation envelope decoder (`envelope_decode`): `envelope::decode`
/// never panics, and anything it accepts re-encodes to exactly the input
/// bytes (one canonical encoding, so one attestation id). The two shapes
/// that `encode` refuses are exempt.
pub fn envelope_decode_one_iteration(input: &[u8]) {
    let input = &input[..input.len().min(MAX_INPUT)];
    if let Ok(env) = kit_attest::envelope::decode(input) {
        // The decoder accepts an empty signature list and an empty payload
        // type. The verifier rejects both later, and `encode` refuses
        // them, so there is no re-encoding to compare.
        if env.signatures.is_empty() || env.payload_type.is_empty() {
            return;
        }
        assert_eq!(
            kit_attest::envelope::encode(&env)
                .expect("accepted envelope must re-encode")
                .as_bytes(),
            input,
            "accepted envelope must re-encode byte for byte"
        );
    }
    // `decode_expecting` accepts exactly the envelopes whose `payloadType`
    // is the expected type, so an empty or different type never passes.
    for expected in [
        kit_attest::PAYLOAD_TYPE_REDACTION_NOTICE,
        kit_attest::PAYLOAD_TYPE_IN_TOTO,
    ] {
        match (
            kit_attest::envelope::decode(input),
            kit_attest::envelope::decode_expecting(input, expected),
        ) {
            (Ok(env), Ok(typed)) => {
                assert_eq!(env.payload_type, expected);
                assert_eq!(env, typed);
            }
            (Ok(env), Err(e)) => {
                assert_ne!(env.payload_type, expected);
                assert!(matches!(e, kit_attest::Error::UnsupportedPayloadType));
            }
            (Err(_), Err(_)) => {}
            (Err(_), Ok(_)) => panic!("typed decode accepted what decode refused"),
        }
    }
}

/// Ref file wire decoder (`ref_wire_decode`): `decode_ref_wire` and
/// `parse_lowercase_hash` never panic, and an accepted hash survives an
/// encode and decode round trip.
pub fn ref_wire_decode_one_iteration(input: &[u8]) {
    use kit_core::refs::{decode_ref_wire, encode_ref_wire, parse_lowercase_hash};
    let input = &input[..input.len().min(MAX_INPUT)];
    if let Some(h) = decode_ref_wire(input) {
        assert_eq!(decode_ref_wire(&encode_ref_wire(&h)), Some(h));
    }
    if let Some(h) = parse_lowercase_hash(input) {
        assert_eq!(
            parse_lowercase_hash(kit_core::to_hex(&h).as_bytes()),
            Some(h)
        );
    }
}

/// Index file decoder (`index_decode`): `index::deserialize` never panics,
/// and an accepted index survives a serialize and deserialize round trip.
pub fn index_decode_one_iteration(input: &[u8]) {
    let input = &input[..input.len().min(MAX_INPUT)];
    if let Ok(index) = kit_core::index::deserialize(input) {
        let again = kit_core::index::deserialize(&index.serialize())
            .expect("a serialized index must deserialize");
        assert_eq!(again, index);
    }
}

/// History walk state decoder (`history_order_decode`): `TimestampDiscovery::decode`
/// never panics, and anything it accepts re-encodes to exactly the input
/// bytes.
pub fn history_order_decode_one_iteration(input: &[u8]) {
    let input = &input[..input.len().min(MAX_INPUT)];
    if let Ok(walk) = kit_core::TimestampDiscovery::decode(input) {
        assert_eq!(
            walk.encode(),
            input,
            "accepted walk state must re-encode byte for byte"
        );
    }
}

/// Conflict state decoder (`conflict_state_decode`): `deserialize_conflicts`
/// never panics, and an accepted list survives a serialize and deserialize
/// round trip.
pub fn conflict_state_decode_one_iteration(input: &[u8]) {
    use kit_core::ops::conflict_state::{deserialize_conflicts, serialize_conflicts};
    let input = &input[..input.len().min(MAX_INPUT)];
    if let Ok(records) = deserialize_conflicts(input) {
        let again = deserialize_conflicts(&serialize_conflicts(&records))
            .expect("serialized conflict records must deserialize");
        assert_eq!(again, records);
    }
}

/// Sparse checkout wire decoders (`sparse_wire_decode`):
/// `decode_sparse_response` and `decode_sparse_cache` never panic on any
/// input.
pub fn sparse_wire_decode_one_iteration(input: &[u8]) {
    let input = &input[..input.len().min(MAX_INPUT)];
    let _ = kit_core::decode_sparse_response(input);
    let _ = kit_core::decode_sparse_cache(input);
}

/// Git object and bridge header parsers (`git_object_parse`):
/// `GitObject::parse_raw`, the `kit-*` header parsers, `parse_timestamp`
/// and `parse_person` never panic. An accepted raw object re-renders to
/// exactly the input bytes.
pub fn git_object_parse_one_iteration(input: &[u8]) {
    use kit_git_bridge::{author, gitobj::GitObject, gitparse, headers};
    let input = &input[..input.len().min(MAX_INPUT)];
    if let Some(obj) = GitObject::parse_raw(input) {
        assert_eq!(obj.raw(), input, "accepted object must re-render exactly");
    }
    let _ = author::parse_timestamp(input);
    let _ = gitparse::parse_person(input);
    if let Ok(text) = core::str::from_utf8(input) {
        let _ = headers::parse_identity(text);
        let _ = headers::parse_hash(text);
        let _ = headers::parse_signature(text);
    }
}

/// Repository and remote identity parsers (`repo_identity_parse`): every
/// `parse` and `parse_bare_allowed` never panics, and an accepted value
/// re-parses from its text form to the same text.
pub fn repo_identity_parse_one_iteration(input: &[u8]) {
    use kit_core::repo_identity::{
        Namespace, OpaqueNamespace, RemoteIdentity, RemoteNamespace, RepositoryIdentity,
    };
    let input = &input[..input.len().min(MAX_INPUT)];
    let Ok(text) = core::str::from_utf8(input) else {
        return;
    };
    if let Ok(v) = Namespace::parse(text) {
        assert_eq!(v.to_string(), text, "namespace text is canonical");
    }
    if let Ok(v) = OpaqueNamespace::parse(text) {
        assert_eq!(v.to_string(), text, "opaque namespace text is canonical");
    }
    if let Ok(v) = RemoteNamespace::parse(text) {
        assert_eq!(v.to_string(), text, "remote namespace text is canonical");
    }
    for v in [
        RepositoryIdentity::parse(text),
        RepositoryIdentity::parse_bare_allowed(text),
    ]
    .into_iter()
    .flatten()
    {
        let shown = v.to_string();
        assert_eq!(
            RepositoryIdentity::parse_bare_allowed(&shown)
                .expect("shown identity must parse")
                .to_string(),
            shown
        );
    }
    for v in [
        RemoteIdentity::parse(text),
        RemoteIdentity::parse_bare_allowed(text),
    ]
    .into_iter()
    .flatten()
    {
        let shown = v.to_string();
        assert_eq!(
            RemoteIdentity::parse_bare_allowed(&shown)
                .expect("shown identity must parse")
                .to_string(),
            shown
        );
    }
}

/// Write authorization commitment parser (`commitment_parse`):
/// `ContentCommitment::parse` never panics, and anything it accepts
/// displays as exactly the input text.
pub fn commitment_parse_one_iteration(input: &[u8]) {
    use kit_core::write_auth::ContentCommitment;
    let input = &input[..input.len().min(MAX_INPUT)];
    let Ok(text) = core::str::from_utf8(input) else {
        return;
    };
    if let Ok(c) = ContentCommitment::parse(text) {
        assert_eq!(c.to_string(), text, "accepted commitment is canonical");
    }
}

/// Ignore and sparse pattern files (`ignore_parse`): `ignore::parse` and
/// `parse_sparse_patterns` never panic, and the parsed ignore list answers
/// a match query on the input path without panicking.
pub fn ignore_parse_one_iteration(input: &[u8]) {
    let input = &input[..input.len().min(MAX_INPUT)];
    let Ok(text) = core::str::from_utf8(input) else {
        return;
    };
    let list = kit_core::ignore::parse(text);
    let _ = list.is_ignored("a/b/c.txt", false);
    let _ = list.is_ignored("dir", true);
    let _ = kit_core::ops::restore::parse_sparse_patterns(text);
}

/// Resumable pack cursor decoder (`pack_cursor_decode`):
/// `WindowCursor::from_bytes` never panics on the raw input. The same input
/// with a valid trailing checksum also reaches the field geometry checks,
/// and an accepted cursor re-encodes to exactly its input.
pub fn pack_cursor_decode_one_iteration(input: &[u8]) {
    use kit_core::pack::window::WindowCursor;
    let input = &input[..input.len().min(MAX_INPUT)];
    let _ = WindowCursor::from_bytes(input);
    let mut sealed = input[..input.len().min(4096 - 32)].to_vec();
    sealed.extend_from_slice(&kit_core::hash::hash(&sealed));
    if let Ok(cursor) = WindowCursor::from_bytes(&sealed) {
        assert_eq!(
            cursor.to_bytes(),
            sealed,
            "accepted cursor must re-encode byte for byte"
        );
    }
}

/// Chunked blob manifest builder (`chunked_blob_build`):
/// `chunked_blob_from_bytes` never panics on any content, and the manifest
/// records the exact input length with one id per chunk.
pub fn chunked_blob_build_one_iteration(input: &[u8]) {
    let input = &input[..input.len().min(MAX_INPUT)];
    let manifest =
        kit_core::worktree::chunked_blob_from_bytes(input).expect("a bounded input always chunks");
    assert_eq!(manifest.total_size, input.len() as u64);
    assert_eq!(manifest.chunk_size, 0);
    assert_eq!(manifest.chunks.is_empty(), input.is_empty());
}

/// Trust-roots file text (`trust_roots_parse`): `parse` never panics. An
/// accepted file serializes to text that parses back to the same entries,
/// and every accepted entry has valid hex and a key length that fits its
/// kind. `hex_decode` never panics, and an accepted string round trips.
pub fn trust_roots_parse_one_iteration(input: &[u8]) {
    use kit_storage::commands::trust_roots::{hex_decode, parse, serialize};
    let input = &input[..input.len().min(MAX_INPUT)];
    let Ok(text) = core::str::from_utf8(input) else {
        return;
    };
    if let Some(bytes) = hex_decode(text) {
        assert_eq!(
            kit_core::hash::to_hex_bytes(&bytes),
            text.to_ascii_lowercase(),
            "accepted hex must round trip"
        );
    }
    if let Ok(entries) = parse(text) {
        let again = parse(&serialize(&entries)).expect("accepted entries must re-parse");
        assert_eq!(entries, again, "accepted trust roots must round trip");
        for e in &entries {
            let key = hex_decode(&e.pubkey_hex).expect("accepted key is hex");
            assert!(!e.keyid.is_empty());
            match e.kind.as_str() {
                "ed25519" => assert_eq!(key.len(), 32),
                "secp256k1" | "secp256k1-sec1" | "p256-sec1" | "p256" => {
                    assert!(key.len() == 33 || key.len() == 65);
                }
                other => panic!("parse accepted the unknown key kind `{other}`"),
            }
        }
    }
}

/// `kit+ssh://` URL text (`ssh_url_parse`): `parse_kit_ssh_url` and
/// `validate_ssh_path` never panic. An accepted target has a non-empty user
/// and host without control bytes, and a path that `validate_ssh_path`
/// accepts.
pub fn ssh_url_parse_one_iteration(input: &[u8]) {
    use kit_transport_ssh::{KIT_SSH_PREFIX, parse_kit_ssh_url, validate_ssh_path};
    let input = &input[..input.len().min(MAX_INPUT)];
    let Ok(text) = core::str::from_utf8(input) else {
        return;
    };
    let _ = validate_ssh_path(text);
    if let Ok(target) = parse_kit_ssh_url(text) {
        assert!(text.starts_with(KIT_SSH_PREFIX));
        assert!(!target.user.is_empty() && !target.host.is_empty());
        for part in [&target.user, &target.host, &target.path] {
            assert!(
                !part.bytes().any(|b| b == 0 || b == b'\r' || b == b'\n'),
                "accepted target must hold no control byte"
            );
        }
        assert!(!target.user.starts_with('-') && !target.host.starts_with('-'));
        assert!(validate_ssh_path(&target.path).is_ok());
    }
}

/// The field-level grant parsers (`grant_fields_parse`): the `text` helpers,
/// `Capabilities`, `RefFlags`, `RefPattern`, `RefScopes`,
/// `AcceptedSchemes::from_tokens`, `is_loopback_origin` and
/// `Grant::parse_with_id` never panic. Every accepted value re-encodes to
/// exactly the input, and an accepted grant id is the hash of the input.
pub fn grant_field_parsers_one_iteration(input: &[u8]) {
    use kit_attest::grant::text::{
        audiences, decimal_millis, decimal_u64, encode_audiences, encode_hex32, encode_millis,
        hex32, join_fields, split_fields,
    };
    use kit_attest::grant::{
        AcceptedSchemes, Capabilities, Grant, RefFlags, RefPattern, RefScopes, is_loopback_origin,
    };
    let input = &input[..input.len().min(MAX_INPUT)];
    for n in 1..=4 {
        if let Ok(fields) = split_fields(input, n) {
            assert_eq!(
                join_fields(&fields).expect("accepted fields must join"),
                input,
                "accepted fields must join back byte for byte"
            );
        }
    }
    if let Ok((grant, id)) = Grant::parse_with_id(input) {
        assert_eq!(id, kit_core::hash::hash(input));
        assert_eq!(grant.id().ok(), Some(id));
    }
    let Ok(text) = core::str::from_utf8(input) else {
        return;
    };
    if let Ok(v) = decimal_u64(text) {
        assert_eq!(v.to_string(), text);
    }
    if let Ok(v) = decimal_millis(text) {
        assert_eq!(encode_millis(v).ok().as_deref(), Some(text));
    }
    if let Ok(v) = hex32(text) {
        assert_eq!(encode_hex32(&v), text);
    }
    if let Ok(v) = audiences(text) {
        assert_eq!(encode_audiences(&v).ok().as_deref(), Some(text));
    }
    let _ = Capabilities::parse(text);
    if let Ok(v) = RefFlags::parse(text) {
        assert_eq!(v.to_string(), text);
    }
    if let Ok(v) = RefPattern::parse(text) {
        assert_eq!(v.to_string(), text);
    }
    if let Ok(v) = RefScopes::parse(text) {
        assert_eq!(v.to_string(), text);
    }
    let _ = AcceptedSchemes::from_tokens(text.split(','));
    let _ = is_loopback_origin(text);
}

/// Capped stream read (`read_to_end_capped`): the first four input bytes
/// pick the size hint and the limit, and the rest is the stream. The read
/// returns the stream exactly when it fits the limit. Otherwise it returns
/// `ObjectTooLarge`. No other error occurs on an in-memory stream.
pub fn read_to_end_capped_one_iteration(input: &[u8]) {
    use kit_core::store::{StoreError, fuzz_read_to_end_capped};
    let input = &input[..input.len().min(MAX_INPUT)];
    let Some((head, stream)) = input.split_first_chunk::<4>() else {
        return;
    };
    let size = usize::from(u16::from_le_bytes([head[0], head[1]]));
    let limit = usize::from(u16::from_le_bytes([head[2], head[3]]));
    match fuzz_read_to_end_capped(stream, size, limit) {
        Ok(bytes) => {
            assert!(
                stream.len() <= limit,
                "an over-limit stream must be refused"
            );
            assert_eq!(bytes, stream, "an accepted stream must come back whole");
        }
        Err(StoreError::ObjectTooLarge) => {
            assert!(
                stream.len() > limit,
                "a stream within the limit must be read"
            );
        }
        Err(e) => panic!("an in-memory read failed for another reason: {e}"),
    }
}

/// Release archive extraction (`self_update_extract`). The raw input as an
/// archive never panics, and an accepted binary fits the unpacked cap. The
/// first byte then selects a mode for a well-formed archive that holds the
/// rest of the input as the `kit` member. The member comes back whole. A
/// cap below one tar header gives `UnpackedTooLarge`. An entry cap of one
/// gives `TooManyEntries`.
pub fn self_update_extract_one_iteration(input: &[u8]) {
    use kit_storage::commands::self_update::{ExtractError, fuzz_extract_binary_within};
    const STAGE: &str = "kit-0.0.0-fuzz";
    let input = &input[..input.len().min(MAX_INPUT)];
    if let Ok(bin) = fuzz_extract_binary_within(input, STAGE, 256 * 1024, 16) {
        assert!(
            bin.len() <= 256 * 1024,
            "the binary must fit the unpacked cap"
        );
    }
    let Some((&mode, body)) = input.split_first() else {
        return;
    };
    let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
        Vec::new(),
        flate2::Compression::fast(),
    ));
    for (name, data) in [("other", &b"decoy"[..]), ("kit", body)] {
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o755);
        header.set_cksum();
        builder
            .append_data(&mut header, format!("{STAGE}/{name}"), data)
            .expect("an in-memory archive entry must append");
    }
    let archive = builder
        .into_inner()
        .and_then(flate2::write::GzEncoder::finish)
        .expect("an in-memory archive must finish");
    match mode % 3 {
        0 => {
            let bin = fuzz_extract_binary_within(&archive, STAGE, 1024 * 1024, 8)
                .expect("a well-formed archive within the caps must extract");
            assert_eq!(bin, body, "the member must come back whole");
        }
        1 => assert!(matches!(
            fuzz_extract_binary_within(&archive, STAGE, 511, 8),
            Err(ExtractError::UnpackedTooLarge { max: 511 })
        )),
        _ => assert!(matches!(
            fuzz_extract_binary_within(&archive, STAGE, 1024 * 1024, 1),
            Err(ExtractError::TooManyEntries { max: 1 })
        )),
    }
}

/// Release version and tag parsing (`self_update_version`). The input text
/// holds up to three versions, one per line. A version that parses equals
/// itself. The order is antisymmetric and transitive. A tag is valid exactly
/// when it starts with `v` and the rest parses.
pub fn self_update_version_one_iteration(input: &[u8]) {
    use kit_storage::commands::self_update::{fuzz_cmp_versions, fuzz_validate_tag};
    use std::cmp::Ordering;
    let input = &input[..input.len().min(MAX_INPUT)];
    let Ok(text) = core::str::from_utf8(input) else {
        return;
    };
    let mut lines = text.splitn(3, '\n');
    let mut next = || lines.next().unwrap_or("");
    let versions = [next(), next(), next()];
    for v in versions {
        if let Ok(order) = fuzz_cmp_versions(v, v) {
            assert_eq!(order, Ordering::Equal, "a version must equal itself");
        }
        let rest_parses = v
            .strip_prefix('v')
            .is_some_and(|rest| fuzz_cmp_versions(rest, rest).is_ok());
        assert_eq!(fuzz_validate_tag(v).is_ok(), rest_parses);
    }
    for a in versions {
        for b in versions {
            let (ab, ba) = (fuzz_cmp_versions(a, b), fuzz_cmp_versions(b, a));
            assert_eq!(ab.is_ok(), ba.is_ok());
            if let (Ok(x), Ok(y)) = (ab, ba) {
                assert_eq!(x, y.reverse(), "the order must be antisymmetric");
            }
        }
    }
    let [a, b, c] = versions;
    if let (Ok(ab), Ok(bc), Ok(ac)) = (
        fuzz_cmp_versions(a, b),
        fuzz_cmp_versions(b, c),
        fuzz_cmp_versions(a, c),
    ) && ab != Ordering::Greater
        && bc != Ordering::Greater
    {
        assert_ne!(ac, Ordering::Greater, "the order must be transitive");
    }
}

/// User config base directory (`absolute_config_home`). The first input
/// byte says which of `XDG_CONFIG_HOME` and `HOME` are set. The rest is two
/// lines of text, one per variable. A result is always absolute. A set,
/// non-empty `XDG_CONFIG_HOME` wins and is never repaired. Otherwise an
/// absolute `HOME` gives `HOME/.config`. Anything else is an error.
pub fn absolute_config_home_one_iteration(input: &[u8]) {
    use kit_storage::config::fuzz_absolute_config_home;
    use std::path::{Path, PathBuf};
    let input = &input[..input.len().min(MAX_INPUT)];
    let Some((&flags, rest)) = input.split_first() else {
        return;
    };
    let Ok(text) = core::str::from_utf8(rest) else {
        return;
    };
    let (xdg_text, home_text) = text.split_once('\n').unwrap_or((text, ""));
    let xdg = (flags & 1 != 0).then_some(xdg_text);
    let home = (flags & 2 != 0).then_some(home_text);
    let result = fuzz_absolute_config_home(xdg, home);
    if let Ok(path) = &result {
        assert!(path.is_absolute(), "the config base must be absolute");
    }
    match xdg.filter(|v| !v.is_empty()) {
        Some(x) if Path::new(x).is_absolute() => assert_eq!(result, Ok(PathBuf::from(x))),
        Some(_) => assert!(
            result.is_err(),
            "a relative XDG_CONFIG_HOME must be refused"
        ),
        None => match home.filter(|h| Path::new(h).is_absolute()) {
            Some(h) => assert_eq!(result, Ok(Path::new(h).join(".config"))),
            None => assert!(result.is_err(), "no absolute base must be refused"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_git_commit_parse() {
        run_iterated_unit(git_commit_parse_one_iteration).unwrap();
        // Fixed structured cases: valid, truncated, continuation-heavy.
        for case in [
            &b"tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\nauthor A <a@x> 5 +0000\ncommitter A <a@x> 5 +0000\n\nm"[..],
            b"tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\nauthor",
            b"gpgsig x\n a\n b\n c\n\nm",
        ] {
            run_one(case, git_commit_parse_one_iteration).unwrap();
        }
    }

    #[test]
    fn unit_git_tag_parse() {
        run_iterated_unit(git_tag_parse_one_iteration).unwrap();
        for case in [
            &b"object ce013625030ba8dba906f756967f9e9ca394464a\ntype commit\ntag v1\n\nm"[..],
            b"object zz\ntype commit\ntag v1\n\nm",
            b"\n\n",
        ] {
            run_one(case, git_tag_parse_one_iteration).unwrap();
        }
    }

    #[test]
    fn unit_git_tree_parse() {
        run_iterated_unit(git_tree_parse_one_iteration).unwrap();
        let mut entry = b"100644 a\x00".to_vec();
        entry.extend_from_slice(&[9u8; 20]);
        for case in [&entry[..], b"160000 sub\x00short", b"77 x"] {
            run_one(case, git_tree_parse_one_iteration).unwrap();
        }
    }

    #[test]
    fn unit_grant_parse() {
        run_iterated_unit(grant_and_header_parse_one_iteration).unwrap();
        // The SPEC-WRITE-GRANTS §3.4 example, a near miss, and its header.
        let grant = "kit-write-grant:v1\n\
            0x8ba1f109551bd432803012645ac136ddd64dba72\n\
            0x8ba1f109551bd432803012645ac136ddd64dba72/website\n\
            3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29\n\
            read,write\n\
            https://git.example.com,https://git.example.org\n\
            refs/heads/main=cu;refs/heads/wip/*=cufd\n\
            0\n1790000000000\n1792592000000\n\
            9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
        assert!(kit_attest::grant::Grant::parse(grant.as_bytes()).is_ok());
        let header = kit_attest::grant::SignedHeader {
            statement: grant.as_bytes().to_vec(),
            scheme: kit_attest::grant::OwnerScheme::Ed25519,
            blob: vec![7; 64],
        }
        .encode()
        .unwrap();
        let near_miss = grant.replace("=cu;", "=uc;");
        for case in [
            grant.as_bytes(),
            near_miss.as_bytes(),
            header.as_bytes(),
            b"YQ==.ed25519.YQ",
            b"QR.ed25519.YQ",
            b"",
            &[0xFF; 64][..],
        ] {
            run_one(case, grant_and_header_parse_one_iteration).unwrap();
        }
    }

    #[test]
    fn unit_config_parse() {
        run_iterated_unit(config_parse_one_iteration).unwrap();
        for case in [
            &b"default_branch = main\n"[..],
            b"http.sslcainfo = /tmp/ca.pem\ntrusted_remote_endpoint = x\n",
            b"pull.require_signed\n",
            b"pull.require_signed = nope\n",
            b"core.editor = vim\n",
            b"remote.a.url = x\nbranch.b.merge = y\n",
            b"\xff\xfe",
            b"",
        ] {
            run_one(case, config_parse_one_iteration).unwrap();
        }
    }

    #[test]
    fn unit_envelope_decode() {
        run_iterated_unit(envelope_decode_one_iteration).unwrap();
        for case in [
            &b""[..],
            b"{\"payload\":",
            b"{\"payload\":\"\",\"payloadType\":\"t\",\"signatures\":[]}",
            &[b'{'; 300][..],
        ] {
            run_one(case, envelope_decode_one_iteration).unwrap();
        }
    }

    #[test]
    fn unit_ref_wire_decode() {
        run_iterated_unit(ref_wire_decode_one_iteration).unwrap();
        let valid = "ab".repeat(32) + "\n";
        for case in [&b""[..], b"\n", valid.as_bytes(), &[b'A'; 64][..]] {
            run_one(case, ref_wire_decode_one_iteration).unwrap();
        }
    }

    #[test]
    fn unit_index_decode() {
        run_iterated_unit(index_decode_one_iteration).unwrap();
        let empty = kit_core::index::Index::default().serialize();
        for case in [&b""[..], b"\x00", &empty[..], &[0xFF; 64][..]] {
            run_one(case, index_decode_one_iteration).unwrap();
        }
    }

    #[test]
    fn unit_history_order_decode() {
        run_iterated_unit(history_order_decode_one_iteration).unwrap();
        for case in [&b""[..], b"\x00", &[0xFF; 64][..]] {
            run_one(case, history_order_decode_one_iteration).unwrap();
        }
    }

    #[test]
    fn unit_conflict_state_decode() {
        run_iterated_unit(conflict_state_decode_one_iteration).unwrap();
        for case in [&b""[..], b"\n", b"x\ty\tz\n", &[0xFF; 64][..]] {
            run_one(case, conflict_state_decode_one_iteration).unwrap();
        }
    }

    #[test]
    fn unit_sparse_wire_decode() {
        run_iterated_unit(sparse_wire_decode_one_iteration).unwrap();
        for case in [&b""[..], b"KSP1", &[0xFF; 64][..]] {
            run_one(case, sparse_wire_decode_one_iteration).unwrap();
        }
    }

    #[test]
    fn unit_git_object_parse() {
        run_iterated_unit(git_object_parse_one_iteration).unwrap();
        for case in [
            &b"blob 3\0abc"[..],
            b"blob 4\0abc",
            b"tree 0\0",
            b"x 1\0",
            b"Jane <j@x> 5 +0000",
        ] {
            run_one(case, git_object_parse_one_iteration).unwrap();
        }
    }

    #[test]
    fn unit_repo_identity_parse() {
        run_iterated_unit(repo_identity_parse_one_iteration).unwrap();
        for case in [
            &b""[..],
            b"name",
            b"ed25519:00/name",
            b"root/name",
            b"A/b",
            b"//",
        ] {
            run_one(case, repo_identity_parse_one_iteration).unwrap();
        }
    }

    #[test]
    fn unit_commitment_parse() {
        run_iterated_unit(commitment_parse_one_iteration).unwrap();
        let body = format!("body:{}", "ab".repeat(32));
        for case in [&b""[..], b"part:", b"body:zz", body.as_bytes()] {
            run_one(case, commitment_parse_one_iteration).unwrap();
        }
    }

    #[test]
    fn unit_ignore_parse() {
        run_iterated_unit(ignore_parse_one_iteration).unwrap();
        for case in [&b""[..], b"*.log\n!keep.log\r\n", b"**/a/**\n", b"[\n\\\n"] {
            run_one(case, ignore_parse_one_iteration).unwrap();
        }
    }

    #[test]
    fn unit_stash_list() {
        run_iterated_unit(stash_list_one_iteration).unwrap();
        let valid = kit_core::ops::stash::serialize_list(&kit_core::ops::stash::StashList {
            entries: vec![kit_core::ops::stash::StashEntry {
                commit_hash: [1; 32],
                parent_hash: [2; 32],
                timestamp: 7,
                message: "wip".to_owned(),
            }],
        })
        .unwrap();
        for case in [&b""[..], b"\x00", &[0xFF; 64][..], &valid[..]] {
            run_one(case, stash_list_one_iteration).unwrap();
        }
    }

    #[test]
    fn unit_trust_roots_parse() {
        run_iterated_unit(trust_roots_parse_one_iteration).unwrap();
        let hex = "aa".repeat(32);
        let valid = format!(
            "[[trust_root]]\nkeyid = \"ed25519:{hex}\"\nkind = \"ed25519\"\npubkey_hex = \"{hex}\"\n"
        );
        let junk = format!("{valid}junk\n");
        for case in [
            valid.as_bytes(),
            junk.as_bytes(),
            b"",
            b"[[trust_root]]\n",
            b"zz",
            &[0xFF; 64][..],
        ] {
            run_one(case, trust_roots_parse_one_iteration).unwrap();
        }
    }

    #[test]
    fn unit_ssh_url_parse() {
        run_iterated_unit(ssh_url_parse_one_iteration).unwrap();
        for case in [
            &b"kit+ssh://git@example.com/repo"[..],
            b"kit+ssh://git@example.com:2222/a/b",
            b"kit+ssh://example.com/repo",
            b"kit+ssh://git@example.com/../x",
            b"kit+ssh://git@example.com/a\nb",
            b"kit+ssh://-oProxyCommand@example.com/repo",
            b"kit+ssh://git@-J/repo",
            b"kit+ssh://",
            b"",
            &[0xFF; 64][..],
        ] {
            run_one(case, ssh_url_parse_one_iteration).unwrap();
        }
    }

    #[test]
    fn unit_grant_fields_parse() {
        run_iterated_unit(grant_field_parsers_one_iteration).unwrap();
        for case in [
            &b"cu"[..],
            b"uc",
            b"refs/heads/main=cu;refs/heads/wip/*=cufd",
            b"read,write",
            b"write,read",
            b"https://git.example.com,https://git.example.org",
            b"1790000000000",
            b"01",
            b"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
            b"a\nb\nc",
            b"",
            &[0xFF; 64][..],
        ] {
            run_one(case, grant_field_parsers_one_iteration).unwrap();
        }
    }

    #[test]
    fn unit_bridge_map() {
        run_iterated_unit(bridge_map_one_iteration).unwrap();
        for case in [&b""[..], b"zz zz\n", b"\xff\xfe\n", &[b'a'; 200][..]] {
            run_one(case, bridge_map_one_iteration).unwrap();
        }
    }

    #[test]
    fn unit_epoch_visibility_parse() {
        use kit_attest::grant::{OwnerScheme, SignedHeader};
        run_iterated_unit(statement_and_token_parse_one_iteration).unwrap();
        let epoch = "kit-write-epoch:v1\n\
            ed25519-3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29\n\
            5\nhttps://git.example.com\n1790000000000\n1790086400000\n\
            9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
        let visibility = "kit-repo-visibility:v1\n\
            0x8ba1f109551bd432803012645ac136ddd64dba72/website\n\
            private\nhttps://git.example.com\n1790000000000\n1790086400000\n\
            9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
        assert!(kit_attest::grant::EpochStatement::parse(epoch.as_bytes()).is_ok());
        assert!(kit_attest::grant::VisibilityStatement::parse(visibility.as_bytes()).is_ok());
        let headers: Vec<String> = [epoch, visibility]
            .iter()
            .flat_map(|s| {
                [
                    OwnerScheme::Ed25519,
                    OwnerScheme::Secp256k1Eip191,
                    OwnerScheme::WebAuthnP256,
                ]
                .map(|scheme| {
                    SignedHeader {
                        statement: s.as_bytes().to_vec(),
                        scheme,
                        blob: vec![7; 64],
                    }
                    .encode()
                    .unwrap()
                })
            })
            .collect();
        let near_miss = epoch.replace("\n5\n", "\n05\n");
        let mut cases: Vec<&[u8]> = vec![
            epoch.as_bytes(),
            visibility.as_bytes(),
            near_miss.as_bytes(),
            b"",
            &[0xFF; 64],
            br#"{"type":"webauthn.get","challenge":"x","origin":"https://example.com"}"#,
            br#"{"type":"webauthn.get","type":"webauthn.get"}"#,
            br#"{"a":[{"b":{"c":"\ud800"}}]}"#,
            &[0; 16],
        ];
        cases.extend(headers.iter().map(String::as_bytes));
        for case in cases {
            run_one(case, statement_and_token_parse_one_iteration).unwrap();
        }
    }

    /// Guardrail: MAX_ITER caps every PRNG run at 100.
    #[test]
    fn delta_target_runs_within_caps() {
        run_iterated_unit(delta_one_iteration).expect("guardrails held");
    }

    #[test]
    fn pack_target_runs_within_caps() {
        // One tempdir/store reused across all MAX_ITER
        // iterations instead of 100 real filesystem inits — the
        // per-iteration isolation `pack_reader_one_iteration` gives real
        // libfuzzer runs isn't needed by this deterministic PRNG-driven
        // loop, which only cares whether the reader panics/UB's.
        let dir = tempfile::TempDir::new().expect("tempdir");
        let store =
            kit_core::store::ObjectStore::init(&kit_core::layout::RepoLayout::single(dir.path()))
                .expect("store init");
        run_iterated_unit_with(&store, pack_reader_one_iteration_with_store)
            .expect("guardrails held");
    }

    #[test]
    fn tree_target_runs_within_caps() {
        run_iterated_unit(object_deserialize_one_iteration).expect("guardrails held");
    }

    #[test]
    fn software_key_record_target_runs_within_caps() {
        run_iterated_unit(software_key_record_one_iteration).expect("guardrails held");
    }

    #[test]
    fn merkle_packlist_target_runs_within_caps() {
        run_iterated_unit(merkle_packlist_one_iteration).expect("guardrails held");
        // A couple of explicit boundary cases.
        for case in [&b""[..], &b"KPKL\x01"[..], &[0xFF; 64]] {
            run_one(case, merkle_packlist_one_iteration).expect("guardrails held");
        }
    }

    #[test]
    fn merkle_proof_target_runs_within_caps() {
        run_iterated_unit(merkle_proof_one_iteration).expect("guardrails held");
        for case in [&b""[..], &[0u8; 32][..], &[0xAB; 200][..]] {
            run_one(case, merkle_proof_one_iteration).expect("guardrails held");
        }
    }

    #[test]
    fn disclosure_decode_target_runs_within_caps() {
        run_iterated_unit(disclosure_decode_one_iteration).expect("guardrails held");
        for case in [&b""[..], b"KDPB\x01", &[0xFF; 64][..]] {
            run_one(case, disclosure_decode_one_iteration).expect("guardrails held");
        }
    }

    #[test]
    fn span_decode_target_runs_within_caps() {
        run_iterated_unit(span_decode_one_iteration).expect("guardrails held");
        for case in [&b""[..], b"KDSP\x01", &[0xff; 64][..]] {
            run_one(case, span_decode_one_iteration).expect("guardrails held");
        }
        let mut nonminimal = GOOD_SPAN[..53].to_vec();
        nonminimal.extend_from_slice(&[0x80, 0]);
        let mut over_count = GOOD_SPAN[..53].to_vec();
        over_count.extend_from_slice(&[0, 0xc1, 0x84, 0x3d]);
        for case in [&nonminimal, &over_count] {
            run_one(case, span_decode_one_iteration).expect("guardrails held");
        }
    }

    #[test]
    fn verify_span_target_runs_within_caps() {
        let fixture = build_span_fixture();
        run_iterated_unit_with(&fixture, verify_span_one_iteration_with).expect("guardrails held");
        for case in [&b""[..], b"KDPB\x02", &[0xff; 64][..]] {
            let started = Instant::now();
            verify_span_one_iteration_with(case, &fixture);
            assert!(started.elapsed() <= PER_ITER, "iteration exceeded PER_ITER");
        }
    }

    #[test]
    fn ssh_session_target_runs_within_caps() {
        run_iterated_unit(ssh_session_one_iteration).expect("guardrails held");
        for case in [
            &b""[..],
            &[0xff; 64][..],
            &[0, 0, 0, 0][..],
            &[1, 0, 0, 0, 0xff][..],
        ] {
            run_one(case, ssh_session_one_iteration).expect("guardrails held");
        }
    }

    #[test]
    fn pack_entries_target_runs_within_caps() {
        run_iterated_unit(pack_entries_one_iteration).expect("guardrails held");
        for case in [
            &b""[..],
            b"KIT\0\x01\x00\x00\x00\x00\x00\x00\x00",
            &[0xFF; 64][..],
        ] {
            run_one(case, pack_entries_one_iteration).expect("guardrails held");
        }
    }

    #[test]
    fn verify_closure_target_runs_within_caps() {
        let fixture = build_closure_fixture();
        run_iterated_unit_with(&fixture, verify_closure_one_iteration_with)
            .expect("guardrails held");
        for case in [&b""[..], &[0u8; 32][..], &[0xAB; 200][..]] {
            let start = std::time::Instant::now();
            verify_closure_one_iteration_with(case, &fixture);
            assert!(start.elapsed() <= PER_ITER, "iteration exceeded PER_ITER");
        }
    }

    #[test]
    fn verify_disclosure_target_runs_within_caps() {
        // Amortize the tempdir/store/signing cost across all MAX_ITER
        // iterations, same rationale as the pack target above.
        let fixture = build_disclosure_fixture();
        run_iterated_unit_with(&fixture, verify_disclosure_one_iteration_with)
            .expect("guardrails held");
        for case in [&b""[..], &[0u8; 32][..], &[0xAB; 200][..]] {
            let start = std::time::Instant::now();
            verify_disclosure_one_iteration_with(case, &fixture);
            assert!(start.elapsed() <= PER_ITER, "iteration exceeded PER_ITER");
        }
    }

    #[test]
    fn sparse_verify_target_runs_within_caps() {
        run_iterated_unit(sparse_verify_one_iteration).expect("guardrails held");
        for case in [&b""[..], &[0u8; 32][..], &[0xFF; 64][..], &[0x01; 512][..]] {
            run_one(case, sparse_verify_one_iteration).expect("guardrails held");
        }
    }

    /// Runs on `minifuzz` (commonware-invariants) — the same
    /// in-process harness upstream commonware uses for its in-tree
    /// property tests. It replaces the bespoke splitmix64 loop
    /// (`run_iterated_unit`) for this one target and honours the
    /// FUZZ.md guardrails: `with_search_limit(MAX_ITER)` caps iterations
    /// `with_seed(RNG_SEED)` keeps the run deterministic, and
    /// the body truncates each input to `MAX_INPUT` and applies the
    /// per-iteration wall-clock cap via `run_one`. minifuzz's
    /// mutational sampler caps its buffer at 8 KiB, so inputs stay well
    /// under the 64 KiB ceiling. On failure it prints a
    /// `MINIFUZZ_BRANCH = 0x...` token; replay it with
    /// `Builder::default().with_reproduce("0x...")`.
    #[test]
    fn rpc_decode_target_runs_within_caps() {
        commonware_invariants::minifuzz::Builder::default()
            .with_search_limit(u64::from(MAX_ITER))
            .with_seed(RNG_SEED)
            .test(|u| {
                let take = u.len().min(MAX_INPUT);
                let input = u.bytes(take)?;
                run_one(input, rpc_decode_one_iteration).expect("guardrails held");
                Ok(())
            });
        // minifuzz's mutational sampler tops out near 8 KiB, so on its own
        // it would not exercise the 8 KiB–64 KiB regime the old splitmix
        // loop covered (large-frame length-prefix handling near the
        // MAX_INPUT cap). Preserve that explicitly with a deterministic
        // large-input sweep up to 64 KiB, seeded from the same RNG_SEED so
        // failures still reproduce.
        let mut prng = SplitMix::new(RNG_SEED);
        let mut buf = vec![0u8; MAX_INPUT];
        for len in [4096usize, 16_384, 49_152, MAX_INPUT] {
            prng.fill(&mut buf[..len]);
            run_one(&buf[..len], rpc_decode_one_iteration).expect("guardrails held");
        }
    }

    /// Pin a few hand-crafted inputs so the targets keep accepting them
    /// even under refactors of the parser surface.
    #[test]
    fn delta_target_handles_known_corruption() {
        // Empty.
        delta_one_iteration(&[]);
        // Header-only, no ops.
        let mut h = vec![0x01u8];
        h.extend_from_slice(&0u32.to_le_bytes());
        h.extend_from_slice(&0u32.to_le_bytes());
        delta_one_iteration(&h);
        // Reserved opcode.
        let mut bad = h.clone();
        bad.push(0x00);
        delta_one_iteration(&bad);
    }

    #[test]
    fn pack_target_handles_known_corruption() {
        // Wrong magic.
        pack_reader_one_iteration(b"XXXX\x01\x00\x00\x00\x00\x00\x00\x00");
        // Empty.
        pack_reader_one_iteration(&[]);
        // Bogus count below the defensive cap.
        pack_reader_one_iteration(b"KIT\0\x01\x00\x00\x00\xFF\xFF\x00\x00");
    }

    #[test]
    fn tree_target_handles_known_corruption() {
        object_deserialize_one_iteration(&[]);
        // Tree prologue + count = u32::MAX → must reject TooManyEntries.
        let mut bad = vec![0x02u8, b'K', b'O', b'B', b'1', 0x01];
        bad.extend_from_slice(&u32::MAX.to_le_bytes());
        object_deserialize_one_iteration(&bad);
    }

    #[test]
    fn software_key_record_target_handles_fixed_cases() {
        let valid = hex_to_bytes(
            "4b49544b5356310001010104000000746573742000000024242424242424242424242424242424242424242424242424242424242424240e000000656432353531393a737461626c651800000022222222222222222222222222222222222222222222222220000000fffde0ffe7e285b4b5bcb4b4b4c7dbd2c0c3d5c6d1b3b4b4b4d0d1d2d5c1d8c030000000c125a54e1efba6d6a70f5689ff3be3a070d5819657dcb8a6220934a533a21b67f5d431c5ce8294ae3de45124fbce7b24",
        );
        software_key_record_one_iteration(&valid);
        software_key_record_one_iteration(&[]);
        software_key_record_one_iteration(b"KITKSV1\0\x01\x01\x01");
        let mut bad = b"KITKSV1\0".to_vec();
        bad.extend_from_slice(&[1, 1, 1]);
        bad.extend_from_slice(&u32::MAX.to_le_bytes());
        software_key_record_one_iteration(&bad);
    }

    #[test]
    fn rpc_decode_target_handles_fixed_cases() {
        use buffa::Message;
        use kit_rpc::kit::rpc::v1::signer::{SignerFrame, signer_frame};

        // Empty and truncated inputs.
        rpc_decode_one_iteration(&[]);
        rpc_decode_one_iteration(&[0x0A]);
        // A valid encoded frame must decode (and roundtrip) cleanly.
        let frame = kit_rpc::signer_error_frame(
            kit_rpc::kit::rpc::v1::ErrorCode::Internal,
            "fuzz fixed case",
        );
        rpc_decode_one_iteration(&frame.encode_to_vec());
        // Field-1 tag with an absurd length prefix — classic truncation.
        rpc_decode_one_iteration(&[0x0A, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F]);
        // Suppress unused-import warning for the oneof module while
        // keeping the import for future fixed cases.
        let _: Option<signer_frame::Body> = SignerFrame::default().body;
    }

    #[test]
    fn unit_pack_cursor_decode() {
        run_iterated_unit(pack_cursor_decode_one_iteration).unwrap();
        for case in [&b""[..], &[1u8; 31][..], &[0u8; 4097][..], &[2u8; 80][..]] {
            run_one(case, pack_cursor_decode_one_iteration).unwrap();
        }
    }

    #[test]
    fn unit_chunked_blob_build() {
        run_iterated_unit(chunked_blob_build_one_iteration).unwrap();
        let large = vec![7u8; MAX_INPUT];
        for case in [&b""[..], b"a", &large[..]] {
            run_one(case, chunked_blob_build_one_iteration).unwrap();
        }
    }

    #[test]
    fn unit_read_to_end_capped() {
        run_iterated_unit(read_to_end_capped_one_iteration).unwrap();
        for case in [
            &b""[..],
            b"\x04\x00\x03\x00abc",
            b"\x04\x00\x03\x00abcd",
            b"\x00\x00\x00\x00",
            b"\xff\xff\x00\x00x",
            b"\x00\x00\xff\xffxyz",
        ] {
            run_one(case, read_to_end_capped_one_iteration).unwrap();
        }
    }

    #[test]
    fn unit_self_update_extract() {
        run_iterated_unit(self_update_extract_one_iteration).unwrap();
        let large = vec![9u8; MAX_INPUT];
        for case in [
            &b""[..],
            b"\x00",
            b"\x00#!/bin/sh\n",
            b"\x01bin",
            b"\x02bin",
            &[0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0, 0, 0xff][..],
            &large[..],
        ] {
            run_one(case, self_update_extract_one_iteration).unwrap();
        }
    }

    #[test]
    fn unit_self_update_version() {
        run_iterated_unit(self_update_version_one_iteration).unwrap();
        for case in [
            &b""[..],
            b"1.2.3\n1.2.4\n1.3.0",
            b"1.0.0-rc.1\n1.0.0\n1.0.0-rc.2",
            b"v0.4.0\nv1.2.3-rc.1\nvx",
            b"1.2\n1.2.3.4\n01a.2.3",
            b"1.2.3-\n1.2.3-a..b\n99999999999999999999.0.0",
            b"\xff\xfe",
        ] {
            run_one(case, self_update_version_one_iteration).unwrap();
        }
    }

    #[test]
    fn unit_absolute_config_home() {
        run_iterated_unit(absolute_config_home_one_iteration).unwrap();
        for case in [
            &b""[..],
            b"\x03/x\n/h",
            b"\x03rel\n/h",
            b"\x03\n/h",
            b"\x03\nrel",
            b"\x02/x\n/h",
            b"\x01/x\n/h",
            b"\x00/x\n/h",
            b"\x01rel",
            b"\xff\xfe",
        ] {
            run_one(case, absolute_config_home_one_iteration).unwrap();
        }
    }

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        assert_eq!(hex.len() % 2, 0);
        (0..hex.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).expect("hex byte"))
            .collect()
    }
}
