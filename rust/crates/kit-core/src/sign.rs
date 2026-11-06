//! Ed25519 commit / remix signing.
//!
//! Spec: `docs/specs/SPEC-SIGNING.md`. The exact bytes covered by an Ed25519
//! signature, and the domain separator used, are normative; this module
//! reproduces them byte-for-byte. The golden tests in
//! `tests/golden_sign.rs` pin the output.
//!
//! Briefly:
//!
//! * Algorithm: Ed25519 per RFC 8032, signing the **BLAKE3 digest** of
//! `domain || signing_bytes` (`PureEdDSA` over a pre-hashed message —
//! the digest itself is what is signed; we do *not* use Ed25519ph).
//! * Domain separator is byte-prepended to the signing bytes; the
//! trailing `\x00` is part of the domain (see SPEC §2).
//! * `commit_signing_bytes` and `remix_signing_bytes` deliberately
//! exclude `signature`, `message_hash`, and `content_digest` (commit
//! only) — see SPEC §3.
//!
//! Keys live on disk as the raw 32-byte Ed25519 seed at
//! `.kit/keys/default.key`, mode 0600. Public-key derivation is
//! deterministic from the seed.

use crate::hash::{HASH_LEN, Hash};
use crate::object::{
    Commit, Identity, KitError, MAGIC, Object, ObjectType, Remix, SCHEMA_VERSION, Tag,
};

use core::fmt;
use std::collections::BTreeMap;
use std::path::Path;

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{IsIdentity, VartimeMultiscalarMul};
use ed25519_dalek::{PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH, SIGNATURE_LENGTH, Signer, SigningKey};
use sha2::{Digest as _, Sha512};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Effective uid for Unix key-file owner checks.
#[cfg(unix)]
#[must_use]
pub fn effective_uid() -> u32 {
    // SAFETY: `geteuid(2)` is a parameterless syscall that always succeeds,
    // never reads or writes user memory, and is reentrant.
    #[allow(unsafe_code)]
    unsafe {
        libc::geteuid()
    }
}

/// Domain separator used when signing commit objects. The trailing
/// `\x00` is load-bearing — see `docs/specs/SPEC-SIGNING.md` §2. Eleven bytes.
pub const COMMIT_DOMAIN: &[u8] = b"kit.commit\x00";

/// Domain separator used when signing remix objects. Ten bytes
/// including the trailing `\x00`.
pub const REMIX_DOMAIN: &[u8] = b"kit.remix\x00";

/// Domain separator used when signing annotated/signed tag objects.
/// Eight bytes including the trailing `\x00`.
///
/// DELIBERATELY DISTINCT from [`COMMIT_DOMAIN`] / [`REMIX_DOMAIN`] so a
/// tag signature can never be replayed as a commit/remix signature, or
/// vice versa — see `docs/specs/SPEC-SIGNING.md` §2 and §4a.
pub const TAG_DOMAIN: &[u8] = b"kit.tag\x00";

/// 32-byte Ed25519 public key.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey(pub [u8; PUBLIC_KEY_LENGTH]);

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PublicKey").field(&"…").finish()
    }
}

/// 32-byte Ed25519 *seed* (the private value we persist to disk).
///
/// This is **not** the expanded RFC 8032 secret key; it is the raw
/// 32-byte input to `SHA512(seed)` from which the scalar and prefix are
/// derived. We deliberately mirror what `.kit/keys/default.key` stores.
///
/// The wrapped bytes are zeroed on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretSeed(pub [u8; SECRET_KEY_LENGTH]);

impl fmt::Debug for SecretSeed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SecretSeed").field(&"<redacted>").finish()
    }
}

impl PartialEq for SecretSeed {
    /// Constant-time equality via [`subtle::ConstantTimeEq`]. The
    /// previous hand-rolled XOR-OR loop was correct in practice but
    /// LLVM is permitted to short-circuit such loops, so we delegate
    /// to a primitive whose contract pins constant-time semantics.
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }
}
impl Eq for SecretSeed {}

/// 64-byte Ed25519 signature (R || s).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Signature(pub [u8; SIGNATURE_LENGTH]);

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Signature").field(&"…").finish()
    }
}

/// Ed25519 keypair: seed plus the deterministically-derived public key.
#[derive(Debug, PartialEq, Eq)]
pub struct KeyPair {
    pub public: PublicKey,
    pub secret: SecretSeed,
}

impl KeyPair {
    /// Generate a fresh keypair using the system CSPRNG (`getrandom`).
    ///
    /// # Zeroization
    ///
    /// The local seed lives inside a [`Zeroizing`] wrapper that scrubs
    /// the buffer at end of scope, so the only remaining copy is the
    /// one inside the returned `KeyPair` (zeroized on drop via
    /// `SecretSeed`'s [`ZeroizeOnDrop`]).
    pub fn generate() -> Result<Self, KitError> {
        let mut seed: Zeroizing<[u8; SECRET_KEY_LENGTH]> = Zeroizing::new([0u8; SECRET_KEY_LENGTH]);
        getrandom::fill(seed.as_mut_slice()).map_err(|_| KitError::RngFailure)?;
        Ok(Self::from_seed_zeroizing(&seed))
    }

    /// Reconstruct a keypair deterministically from a 32-byte seed.
    /// Pure function: same seed always yields the same public key.
    ///
    /// This is a **self-scrubbing convenience constructor**: it zeroes
    /// the `seed` argument it owns before returning (see the body), so
    /// the moved-in buffer never lingers. It is kept as a public,
    /// ergonomic entry point for callers that already hold a bare
    /// `[u8; 32]` (e.g. test vectors, golden fixtures, and downstream /
    /// WASM consumers that decode a seed from their own format).
    ///
    /// # Zeroization
    ///
    /// The contract this constructor guarantees: the `[u8; 32]` *passed
    /// by value into this function* is scrubbed before return. What it
    /// CANNOT do is reach back and scrub a `Copy` the caller left on
    /// *their own* stack — `[u8; 32]: Copy`, so the argument is a moved
    /// copy of whatever the caller held. Callers that keep sensitive
    /// seed material on their own frame MUST therefore either:
    ///
    /// * Prefer [`KeyPair::from_seed_zeroizing`], which takes a
    ///   [`Zeroizing`]-wrapped reference and never creates a Copy on
    ///   the caller's frame (this is what ALL internal kit signing-path
    ///   code uses — `generate`, `load_key`, the attest signer factory,
    ///   and the WASM bindings), or
    /// * Wrap their seed in [`Zeroizing`] themselves, or
    /// * `seed.zeroize()` the buffer after this call returns.
    ///
    /// [`KeyPair::generate`] and [`load_key`] already use the
    /// `Zeroizing` path internally; no production call site passes a
    /// bare `[u8; 32]` here. The contract above is pinned by the
    /// `from_seed_zeroizing_matches_from_seed`,
    /// `secret_seed_zeroize_clears_bytes` and
    /// `keypair_drop_runs_zeroize_on_secret` regression tests. (The
    /// owned-argument scrub two lines below is unobservable from
    /// outside the function and is therefore covered by review, not by
    /// a test — a previous test only ever scrubbed its own local
    /// copy.)
    #[must_use]
    pub fn from_seed(mut seed: [u8; SECRET_KEY_LENGTH]) -> Self {
        let signing = SigningKey::from_bytes(&seed);
        let public = PublicKey(signing.verifying_key().to_bytes());
        // `[u8; 32]: Copy`, so moving `seed` into `SecretSeed` would
        // leave the original stack slot live. Build the wrapper first,
        // then scrub the parameter — `SecretSeed`'s `ZeroizeOnDrop`
        // owns the only remaining copy.
        let secret = SecretSeed(seed);
        seed.zeroize();
        Self { public, secret }
    }

    /// Reconstruct a keypair from a [`Zeroizing`]-wrapped 32-byte seed
    /// without forcing the caller to keep a `Copy` of the raw bytes on
    /// their own stack. This is the preferred constructor for
    /// signing-path code that loads keys from disk (see [`load_key`])
    /// or generates them on the fly (see [`KeyPair::generate`]).
    ///
    /// # Zeroization
    ///
    /// Borrowing the seed means this function never creates a fresh
    /// `[u8; 32]` `Copy` on the caller's frame. The only memory copy
    /// is the one owned by the returned `KeyPair::secret` field, which
    /// zeroes on drop.
    #[must_use]
    pub fn from_seed_zeroizing(seed: &Zeroizing<[u8; SECRET_KEY_LENGTH]>) -> Self {
        let signing = SigningKey::from_bytes(seed);
        let public = PublicKey(signing.verifying_key().to_bytes());
        // `**seed` would be a `Copy` of the inner array — to avoid
        // that we initialise the destination zeroed and `copy_from_slice`
        // through the borrow, so the inner array never materialises a
        // second `Copy` on this frame.
        let mut secret_bytes = [0u8; SECRET_KEY_LENGTH];
        secret_bytes.copy_from_slice(seed.as_slice());
        let secret = SecretSeed(secret_bytes);
        // Scrub our local stack scratch even though we just moved the
        // bytes into `SecretSeed` — the stack slot would otherwise
        // retain the seed until the frame is reused.
        secret_bytes.zeroize();
        Self { public, secret }
    }

    /// Sign `signing_bytes` under the given domain. The actual Ed25519
    /// input is `BLAKE3(len_le16(domain) || domain || signing_bytes)` — see
    /// SPEC §2.2.
    #[must_use]
    pub fn sign(&self, domain: &[u8], signing_bytes: &[u8]) -> Signature {
        let digest = domain_digest(domain, signing_bytes);
        let signing = SigningKey::from_bytes(&self.secret.0);
        let sig = signing.sign(&digest);
        Signature(sig.to_bytes())
    }
}

/// Verify a signature over `BLAKE3(len_le16(domain) || domain || signing_bytes)`
/// against the embedded public key with [`verify_ed25519`].
pub fn verify(
    public: &PublicKey,
    domain: &[u8],
    signing_bytes: &[u8],
    sig: &Signature,
) -> Result<(), KitError> {
    let digest = domain_digest(domain, signing_bytes);
    verify_ed25519(&public.0, &digest, &sig.0)
}

/// The Ed25519 acceptance predicate of SPEC-SIGNING §1. Every Ed25519
/// check in kit calls this function or [`verify_ed25519_batch`], so all
/// verifiers reach the same verdict on every input.
///
/// `A` and `R` must be canonical encodings of points that are not of small
/// order, `s` must be below `L`, and the cofactored equation
/// `[8]([s]B - R - [k]A) = 0` must hold, with `k = SHA-512(R || A || M) mod L`.
pub fn verify_ed25519(public: &[u8; 32], message: &[u8], sig: &[u8; 64]) -> Result<(), KitError> {
    let key = decode_key(public)?;
    let item = Ed25519Item::decode(public, message, sig)?;
    let r = EdwardsPoint::vartime_double_scalar_mul_basepoint(&item.k, &-key, &item.s);
    if (r - item.r).mul_by_cofactor().is_identity() {
        Ok(())
    } else {
        Err(KitError::SignatureInvalid)
    }
}

/// Check many `(public key, message, signature)` triples with one
/// randomized equation. Accepts exactly when [`verify_ed25519`] accepts
/// every entry, except with probability about `2^-128`.
///
/// Each entry passes the same per-entry checks first. The weights `z_i`
/// are 128-bit values from the operating system's random source, drawn
/// fresh on every call, so whoever built the batch cannot predict them.
/// The batch then checks
/// `[8]([sum z_i s_i]B - sum [z_i]R_i - sum_A [sum_{i: A_i = A} z_i k_i]A) = 0`:
/// entries that share a public key share one term, so a batch from few
/// signers multiplies fewer points. Because the equation is cofactored, a
/// torsion component in any entry vanishes in both this check and
/// [`verify_ed25519`]. On failure the caller learns only that some entry is
/// invalid; it calls [`verify_ed25519`] per entry to find which.
pub fn verify_ed25519_batch(entries: &[(&[u8; 32], &[u8], &[u8; 64])]) -> Result<(), KitError> {
    if entries.is_empty() {
        return Ok(());
    }
    let mut weights = vec![0u8; 16 * entries.len()];
    getrandom::fill(&mut weights).map_err(|_| KitError::RngFailure)?;
    let mut key_index: BTreeMap<[u8; 32], usize> = BTreeMap::new();
    let mut keys: Vec<EdwardsPoint> = Vec::new();
    let mut key_coefficients: Vec<Scalar> = Vec::new();
    let mut b_coefficient = Scalar::ZERO;
    let mut r_coefficients = Vec::with_capacity(entries.len());
    let mut commitments = Vec::with_capacity(entries.len());
    for ((public, message, sig), w) in entries.iter().zip(weights.chunks_exact(16)) {
        let index = if let Some(&index) = key_index.get(*public) {
            index
        } else {
            keys.push(decode_key(public)?);
            key_coefficients.push(Scalar::ZERO);
            key_index.insert(**public, keys.len() - 1);
            keys.len() - 1
        };
        let item = Ed25519Item::decode(public, message, sig)?;
        let mut z = [0u8; 16];
        z.copy_from_slice(w);
        let z = Scalar::from(u128::from_le_bytes(z));
        b_coefficient += z * item.s;
        r_coefficients.push(-z);
        commitments.push(item.r);
        key_coefficients[index] -= z * item.k;
    }
    let scalars = core::iter::once(b_coefficient)
        .chain(r_coefficients)
        .chain(key_coefficients);
    let points = core::iter::once(ED25519_BASEPOINT_POINT)
        .chain(commitments)
        .chain(keys);
    if EdwardsPoint::vartime_multiscalar_mul(scalars, points)
        .mul_by_cofactor()
        .is_identity()
    {
        Ok(())
    } else {
        Err(KitError::SignatureInvalid)
    }
}

/// Decode a public key with checks 1 and 2 of SPEC-SIGNING §1: a canonical
/// encoding of a point that is not of small order.
fn decode_key(public: &[u8; 32]) -> Result<EdwardsPoint, KitError> {
    let key = canonical_point(public).ok_or(KitError::InvalidPublicKey)?;
    if key.is_small_order() {
        return Err(KitError::SignatureInvalid);
    }
    Ok(key)
}

/// One signature after the per-entry checks of SPEC-SIGNING §1: the
/// commitment `R`, the scalar `s` and the challenge
/// `k = SHA-512(R || A || M) mod L`. The key `A` is checked by
/// [`decode_key`].
struct Ed25519Item {
    r: EdwardsPoint,
    s: Scalar,
    k: Scalar,
}

impl Ed25519Item {
    fn decode(public: &[u8; 32], message: &[u8], sig: &[u8; 64]) -> Result<Self, KitError> {
        let mut r_bytes = [0u8; 32];
        r_bytes.copy_from_slice(&sig[..32]);
        let mut s_bytes = [0u8; 32];
        s_bytes.copy_from_slice(&sig[32..]);
        let commitment = canonical_point(&r_bytes).ok_or(KitError::SignatureInvalid)?;
        if commitment.is_small_order() {
            return Err(KitError::SignatureInvalid);
        }
        let scalar = Option::<Scalar>::from(Scalar::from_canonical_bytes(s_bytes))
            .ok_or(KitError::SignatureInvalid)?;
        let mut hasher = Sha512::new();
        hasher.update(r_bytes);
        hasher.update(public);
        hasher.update(message);
        let challenge = Scalar::from_bytes_mod_order_wide(&hasher.finalize().into());
        Ok(Self {
            r: commitment,
            s: scalar,
            k: challenge,
        })
    }
}

/// Decode a point and require `y < p`, which decompression alone does not
/// check: it reduces `y` modulo `p`. The other non-canonical form, a sign
/// bit on `x = 0`, needs no test here: `x = 0` holds only for the identity
/// and the point of order 2, which check 2 of SPEC-SIGNING §1 rejects.
fn canonical_point(bytes: &[u8; 32]) -> Option<EdwardsPoint> {
    let mut y = *bytes;
    y[31] &= 0x7f;
    // y >= p = 2^255 - 19 exactly when the high 248 bits are all set and
    // the low byte is at least 0xed.
    if y[31] == 0x7f && y[1..31].iter().all(|b| *b == 0xff) && y[0] >= 0xed {
        return None;
    }
    CompressedEdwardsY(*bytes).decompress()
}

// -------------------------------------------------------------------
// Signing-bytes builders
// -------------------------------------------------------------------

/// Compute `BLAKE3(len_le16(domain) || domain || signing_bytes)`.
/// Always 32 bytes.
///
/// Thin wrapper around the public [`crate::hash::domain_digest`].
/// Kept as a module-private alias because the original v0.1.0
/// signature scheme is golden-vector-pinned through this symbol; the
/// public hoist (Reuse B2) added the same routine to `kit_core::hash`
/// for re-use by `sparse` etc., but the sign-path call sites
/// deliberately retain this local indirection so a future refactor of
/// the public function can't silently change signature output.
///
/// The 2-byte little-endian length prefix closes a latent ambiguity
/// that `BLAKE3(domain || signing_bytes)` alone would carry: without
/// a length prefix, the concatenation `domain || signing_bytes` is
/// not uniquely parseable back into its two halves. Two distinct
/// `(domain, signing_bytes)` pairs could in principle produce the
/// same input to the hash (e.g. `("ab", "cX")` vs `("abc", "X")`).
///
/// Domain strings are fixed constants (`COMMIT_DOMAIN` /
/// `REMIX_DOMAIN`) and always fit in `u16`; construction-time asserts
/// this in `sign()` / `verify()` call sites.
///
#[must_use]
fn domain_digest(domain: &[u8], signing_bytes: &[u8]) -> [u8; HASH_LEN] {
    crate::hash::domain_digest(domain, signing_bytes)
}

/// Public helper:
/// `BLAKE3(len_le16(COMMIT_DOMAIN) || COMMIT_DOMAIN || commit_signing_bytes(c))`.
pub fn commit_signing_hash(c: &Commit) -> Result<Hash, KitError> {
    let sb = commit_signing_bytes(c)?;
    Ok(domain_digest(COMMIT_DOMAIN, &sb))
}

/// Public helper:
/// `BLAKE3(len_le16(REMIX_DOMAIN) || REMIX_DOMAIN || remix_signing_bytes(r))`.
pub fn remix_signing_hash(r: &Remix) -> Result<Hash, KitError> {
    let sb = remix_signing_bytes(r)?;
    Ok(domain_digest(REMIX_DOMAIN, &sb))
}

/// Public helper:
/// `BLAKE3(len_le16(TAG_DOMAIN) || TAG_DOMAIN || tag_signing_bytes(t))`.
pub fn tag_signing_hash(t: &Tag) -> Result<Hash, KitError> {
    let sb = tag_signing_bytes(t)?;
    Ok(domain_digest(TAG_DOMAIN, &sb))
}

fn write_prologue(buf: &mut Vec<u8>, t: ObjectType) {
    buf.push(t as u8);
    buf.extend_from_slice(&MAGIC);
    buf.push(SCHEMA_VERSION);
}

fn write_identity(buf: &mut Vec<u8>, id: &Identity) -> Result<(), KitError> {
    if !id.is_valid() {
        return Err(KitError::InvalidIdentity);
    }
    buf.push(id.kind as u8);
    let len = u16::try_from(id.bytes.len()).map_err(|_| KitError::IdentityTooLarge)?;
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(&id.bytes);
    Ok(())
}

/// Serialize a commit's fields for signing. SPEC-SIGNING §3.
///
/// INCLUDED, in order:
/// 1. Object prologue: `[type=0x03][magic="KOB1"][schema_version=0x01]`.
/// 2. `tree_hash` (32).
/// 3. `parent_count` (u32 LE) and `parent_hash` × `parent_count` (32 each).
/// 4. Identity author: `[kind:u8][len:u16 LE][payload:len]`.
/// 5. `message_len` (u32 LE) and message bytes.
/// 6. `timestamp` (u64 LE).
/// 7. `signer` (32).
///
/// EXCLUDED: `signature`, `message_hash`, `content_digest`.
pub fn commit_signing_bytes(c: &Commit) -> Result<Vec<u8>, KitError> {
    let mut buf = Vec::with_capacity(
        6 + 32 + 4 + c.parents.len() * 32 + 3 + c.author.bytes.len() + 4 + c.message.len() + 8 + 32,
    );
    write_prologue(&mut buf, ObjectType::Commit);
    buf.extend_from_slice(&c.tree_hash);
    let parent_count = u32::try_from(c.parents.len()).map_err(|_| KitError::TooManyParents)?;
    buf.extend_from_slice(&parent_count.to_le_bytes());
    for p in &c.parents {
        buf.extend_from_slice(p);
    }
    write_identity(&mut buf, &c.author)?;
    let mlen = u32::try_from(c.message.len()).map_err(|_| KitError::UnexpectedEof)?;
    buf.extend_from_slice(&mlen.to_le_bytes());
    buf.extend_from_slice(&c.message);
    buf.extend_from_slice(&c.timestamp.to_le_bytes());
    buf.extend_from_slice(&c.signer);
    Ok(buf)
}

/// Serialize a remix's fields for signing. SPEC-SIGNING §4. Same shape
/// as commit, with `source_count || sources` between parents and author.
pub fn remix_signing_bytes(r: &Remix) -> Result<Vec<u8>, KitError> {
    let mut buf = Vec::with_capacity(
        6 + 32
            + 4
            + r.parents.len() * 32
            + 4
            + r.sources.len() * 64
            + 3
            + r.author.bytes.len()
            + 4
            + r.message.len()
            + 8
            + 32,
    );
    write_prologue(&mut buf, ObjectType::Remix);
    buf.extend_from_slice(&r.tree_hash);
    let parent_count = u32::try_from(r.parents.len()).map_err(|_| KitError::TooManyParents)?;
    buf.extend_from_slice(&parent_count.to_le_bytes());
    for p in &r.parents {
        buf.extend_from_slice(p);
    }
    let source_count = u32::try_from(r.sources.len()).map_err(|_| KitError::TooManySources)?;
    buf.extend_from_slice(&source_count.to_le_bytes());
    for s in &r.sources {
        buf.extend_from_slice(&s.upstream_id);
        buf.extend_from_slice(&s.commit_hash);
    }
    write_identity(&mut buf, &r.author)?;
    let mlen = u32::try_from(r.message.len()).map_err(|_| KitError::UnexpectedEof)?;
    buf.extend_from_slice(&mlen.to_le_bytes());
    buf.extend_from_slice(&r.message);
    buf.extend_from_slice(&r.timestamp.to_le_bytes());
    buf.extend_from_slice(&r.signer);
    Ok(buf)
}

/// Serialize a tag's fields for signing. SPEC-SIGNING §4a.
///
/// INCLUDED, in order:
/// 1. Object prologue: `[type=0x07][magic="KOB1"][schema_version=0x01]`.
/// 2. `target` (32) and `target_type` (u8).
/// 3. `name`: `[len:u32 LE][name bytes]`.
/// 4. Identity tagger: `[kind:u8][len:u16 LE][payload:len]`.
/// 5. `message`: `[len:u32 LE][message bytes]`.
/// 6. `timestamp` (u64 LE).
/// 7. `signer` (32).
///
/// EXCLUDED: `signature` (a signature cannot cover itself).
pub fn tag_signing_bytes(t: &Tag) -> Result<Vec<u8>, KitError> {
    if !t.name_is_valid() {
        return Err(KitError::TagNameInvalid);
    }
    if matches!(t.target_type, ObjectType::Delta) {
        return Err(KitError::TagTargetTypeInvalid(t.target_type as u8));
    }
    let mut buf = Vec::with_capacity(
        6 + 32 + 1 + 4 + t.name.len() + 3 + t.tagger.bytes.len() + 4 + t.message.len() + 8 + 32,
    );
    write_prologue(&mut buf, ObjectType::Tag);
    buf.extend_from_slice(&t.target);
    buf.push(t.target_type as u8);
    let nlen = u32::try_from(t.name.len()).map_err(|_| KitError::TagNameInvalid)?;
    buf.extend_from_slice(&nlen.to_le_bytes());
    buf.extend_from_slice(&t.name);
    write_identity(&mut buf, &t.tagger)?;
    let mlen = u32::try_from(t.message.len()).map_err(|_| KitError::UnexpectedEof)?;
    buf.extend_from_slice(&mlen.to_le_bytes());
    buf.extend_from_slice(&t.message);
    buf.extend_from_slice(&t.timestamp.to_le_bytes());
    buf.extend_from_slice(&t.signer);
    Ok(buf)
}

/// Sign a tag object.
pub fn sign_tag(t: &Tag, kp: &KeyPair) -> Result<Signature, KitError> {
    let sb = tag_signing_bytes(t)?;
    Ok(kp.sign(TAG_DOMAIN, &sb))
}

/// Verify a tag against the public key embedded in `t.signer`.
pub fn verify_tag(t: &Tag) -> Result<(), KitError> {
    let sb = tag_signing_bytes(t)?;
    let pk = PublicKey(t.signer);
    let sig = Signature(t.signature);
    verify(&pk, TAG_DOMAIN, &sb, &sig)
}

/// Sign a commit object. Returns the 64-byte signature.
pub fn sign_commit(c: &Commit, kp: &KeyPair) -> Result<Signature, KitError> {
    let sb = commit_signing_bytes(c)?;
    Ok(kp.sign(COMMIT_DOMAIN, &sb))
}

/// Sign a remix object.
pub fn sign_remix(r: &Remix, kp: &KeyPair) -> Result<Signature, KitError> {
    let sb = remix_signing_bytes(r)?;
    Ok(kp.sign(REMIX_DOMAIN, &sb))
}

/// Verify a commit against the public key embedded in `c.signer`.
///
/// Returns `Ok(())` on success. Note: this does *not* check whether
/// `c.author`'s payload matches `c.signer` — that is an application
/// policy decision (see SPEC §6).
pub fn verify_commit(c: &Commit) -> Result<(), KitError> {
    let sb = commit_signing_bytes(c)?;
    let pk = PublicKey(c.signer);
    let sig = Signature(c.signature);
    verify(&pk, COMMIT_DOMAIN, &sb, &sig)
}

/// Verify a remix against the public key embedded in `r.signer`.
pub fn verify_remix(r: &Remix) -> Result<(), KitError> {
    let sb = remix_signing_bytes(r)?;
    let pk = PublicKey(r.signer);
    let sig = Signature(r.signature);
    verify(&pk, REMIX_DOMAIN, &sb, &sig)
}

/// Verify the signature a signed object carries: [`verify_commit`],
/// [`verify_remix`] or [`verify_tag`] by type. `Blob`, `Tree`,
/// `ChunkedBlob` and `Delta` carry no signature and return `Ok(())`.
///
/// The one per-object signature dispatch shared by push verification
/// (`kit_core::verify::verify_push`) and the CLI's fetch-side check.
///
/// # Errors
///
/// The underlying `verify_*` error for a commit, remix or tag whose
/// signature does not verify under its embedded `signer`.
pub fn verify_object_signature(obj: &Object) -> Result<(), KitError> {
    match obj {
        Object::Commit(c) => verify_commit(c),
        Object::Remix(r) => verify_remix(r),
        Object::Tag(t) => verify_tag(t),
        Object::Blob(_) | Object::Tree(_) | Object::ChunkedBlob(_) | Object::Delta(_) => Ok(()),
    }
}

// -------------------------------------------------------------------
// Key file I/O — `.kit/keys/default.key`
// -------------------------------------------------------------------
//
// The on-disk contract (SPEC-SIGNING §7):
// - Path: caller-provided, conventionally `<repo>/.kit/keys/default.key`.
// - Contents: raw 32-byte Ed25519 seed (NOT the expanded secret key).
// - Permissions: file 0600, parent directory 0700.
// - Owner: must equal the calling process's effective uid.
// - Symlink-resistant: open(2) uses `O_NOFOLLOW`; both the file and
// any path component above it are refused if they're symlinks.
// - Crash-atomic write: tmp + fsync + rename + dir-fsync.

/// Load a keypair from `path`. Enforces the full disk contract above.
///
/// On non-Unix hosts the symlink/owner/mode checks are a no-op;
/// callers should keep keys under `%USERPROFILE%` and rely on default
/// ACLs (documented in `docs/specs/SPEC-SIGNING.md` §7).
pub fn load_key(path: &Path) -> Result<KeyPair, KitError> {
    let seed = load_raw_32(path)?;
    // Borrowing through `from_seed_zeroizing` avoids the `*seed` Copy
    // the older path would synthesise on this frame.
    Ok(KeyPair::from_seed_zeroizing(&seed))
}

/// Load a raw 32-byte secret from `path` with the same Unix hardening
/// `load_key` uses for the Ed25519 seed path.
///
/// On Unix this rejects symlinks both at the final component and in any
/// existing ancestor above it.
pub fn load_raw_32(path: &Path) -> Result<zeroize::Zeroizing<[u8; 32]>, KitError> {
    #[cfg(unix)]
    {
        use std::io::Read as _;
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        ensure_no_symlink_ancestors(path)?;
        let mut f = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(|e| {
                if e.raw_os_error() == Some(libc::ELOOP) {
                    KitError::KeyPathIsSymlink(path.display().to_string())
                } else {
                    KitError::KeyIo(format!("open: {e}"))
                }
            })?;

        // fstat the open handle, NOT the path — closes the TOCTOU
        // window in which an attacker could rename(2) a hostile inode
        // into place between a path-based `metadata()` and `read()`.
        let meta = f
            .metadata()
            .map_err(|e| KitError::KeyIo(format!("fstat: {e}")))?;

        let mode = meta.mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(KitError::InsecureKeyPermissions { actual: mode });
        }

        // SAFETY: `geteuid(2)` is a parameterless syscall that always
        // succeeds, never reads or writes user memory, and is reentrant
        // and async-signal-safe per POSIX. This is one of two reviewed
        // `unsafe` blocks in `kit-core` (the other being the
        // `F_BARRIERFSYNC` fcntl in `batch.rs`); the crate keeps
        // `deny(unsafe_code)` so each opt-out is reviewable.
        let euid = effective_uid();
        if meta.uid() != euid {
            return Err(KitError::InsecureKeyOwner {
                actual: meta.uid(),
                euid,
            });
        }

        // Refuse to load when the parent directory itself is loose.
        // We only check the immediate parent — auditing every
        // ancestor is policy that belongs in the install/setup flow,
        // not in every signing call.
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            check_parent_dir_secure(parent)?;
        }

        let mut seed = zeroize::Zeroizing::new([0u8; SECRET_KEY_LENGTH]);
        if let Err(e) = f.read_exact(seed.as_mut_slice()) {
            return if e.kind() == std::io::ErrorKind::UnexpectedEof {
                Err(KitError::InvalidKeyLength {
                    actual: usize::try_from(meta.len()).unwrap_or(usize::MAX),
                })
            } else {
                Err(KitError::KeyIo(format!("read: {e}")))
            };
        }
        // Reject longer files: we read 32 bytes, so anything left over
        // is junk that almost certainly means the file isn't a valid
        // kit seed.
        let mut probe = [0u8; 1];
        let trailing = f
            .read(&mut probe)
            .map_err(|e| KitError::KeyIo(format!("read trailing byte: {e}")))?;
        if trailing != 0 {
            return Err(KitError::InvalidKeyLength {
                actual: usize::try_from(meta.len()).unwrap_or(usize::MAX),
            });
        }
        Ok(seed)
    }
    #[cfg(not(unix))]
    {
        let raw = std::fs::read(path).map_err(|e| KitError::KeyIo(format!("read: {e}")))?;
        if raw.len() != SECRET_KEY_LENGTH {
            return Err(KitError::InvalidKeyLength { actual: raw.len() });
        }
        let mut seed = zeroize::Zeroizing::new([0u8; SECRET_KEY_LENGTH]);
        seed.copy_from_slice(&raw);
        let mut raw = raw;
        raw.zeroize();
        Ok(seed)
    }
}

#[cfg(unix)]
fn check_parent_dir_secure(parent: &Path) -> Result<(), KitError> {
    use std::os::unix::fs::MetadataExt;
    // If the parent doesn't exist, defer to the file open above which
    // will already have failed; not our error to report.
    let Ok(meta) = std::fs::metadata(parent) else {
        return Ok(());
    };
    let mode = meta.mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(KitError::InsecureKeyDir { actual: mode });
    }
    Ok(())
}

#[cfg(unix)]
fn ensure_no_symlink_ancestors(path: &Path) -> Result<(), KitError> {
    let mut current = path.parent();
    for _ in 0..3 {
        let Some(dir) = current else {
            break;
        };
        if dir.as_os_str().is_empty() {
            break;
        }
        match std::fs::symlink_metadata(dir) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(KitError::KeyPathIsSymlink(dir.display().to_string()));
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(KitError::KeyIo(format!("lstat {}: {e}", dir.display()))),
        }
        current = dir.parent();
    }
    if let Ok(meta) = std::fs::symlink_metadata(path)
        && meta.file_type().is_symlink()
    {
        return Err(KitError::KeyPathIsSymlink(path.display().to_string()));
    }
    Ok(())
}

/// Create `parent` and any missing ancestors with mode 0700. A directory
/// that already exists keeps its mode, because the caller did not create
/// it. A caller may pass `.` or a shared directory.
#[cfg(unix)]
fn create_secure_dir_all(parent: &Path) -> Result<(), KitError> {
    use std::os::unix::fs::DirBuilderExt;

    ensure_no_symlink_ancestors(parent)?;
    let mut missing = Vec::new();
    let mut cur = Some(parent);
    while let Some(dir) = cur {
        if dir.as_os_str().is_empty() || dir.exists() {
            break;
        }
        missing.push(dir);
        cur = dir.parent();
    }
    for dir in missing.into_iter().rev() {
        match std::fs::DirBuilder::new().mode(0o700).create(dir) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && dir.is_dir() => {}
            Err(e) => return Err(KitError::KeyIo(format!("mkdir {}: {e}", dir.display()))),
        }
    }
    Ok(())
}

/// Persist a keypair to `path` as the raw 32-byte seed.
///
/// **Atomicity contract.** The write is crash-safe:
///
/// 1. Ensure the parent directory exists at mode 0700.
/// 2. Write the seed to a uniquely-named tmp file in the same
/// directory using `O_CREAT | O_EXCL | O_NOFOLLOW` and mode 0600.
/// `O_EXCL` defeats a pre-created symlink at the tmp name; same
/// directory ensures `rename(2)` is atomic on the same filesystem.
/// 3. `fsync` the tmp file's data to disk.
/// 4. `rename(2)` the tmp file to the final path. Replaces an
/// existing key atomically; never leaves a half-written final.
/// 5. `fsync` the parent directory so the rename itself is durable.
///
/// On Windows the file is written with default ACLs; users should keep
/// `.kit/keys/` inside `%USERPROFILE%` (SPEC-SIGNING §7).
pub fn save_key(path: &Path, kp: &KeyPair) -> Result<(), KitError> {
    save_raw_32(path, &kp.secret.0)
}

/// Persist a raw 32-byte secret to `path` crash-atomically.
pub fn save_raw_32(path: &Path, secret: &[u8; 32]) -> Result<(), KitError> {
    let parent: &Path = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };

    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt;
        create_secure_dir_all(parent)?;

        let filename = path
            .file_name()
            .ok_or_else(|| KitError::KeyIo(format!("path has no filename: {}", path.display())))?;
        // `.<name>.tmp.<pid>` is unique enough across concurrent
        // `keygen` runs and within the same dir guarantees rename is
        // atomic.
        let tmp_name = {
            let mut s = std::ffi::OsString::from(".");
            s.push(filename);
            s.push(format!(".tmp.{}", std::process::id()));
            s
        };
        let tmp_path = parent.join(&tmp_name);

        // Open with O_CREAT|O_EXCL|O_NOFOLLOW + mode 0600.
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(0o600)
            .open(&tmp_path)
            .map_err(|e| KitError::KeyIo(format!("open tmp {}: {e}", tmp_path.display())))?;
        if let Err(e) = f.write_all(secret) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(KitError::KeyIo(format!("write: {e}")));
        }
        if let Err(e) = f.sync_all() {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(KitError::KeyIo(format!("fsync tmp: {e}")));
        }
        // Drop the file handle before rename; some filesystems are
        // happier this way.
        drop(f);

        if let Err(e) = std::fs::rename(&tmp_path, path) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(KitError::KeyIo(format!("rename: {e}")));
        }

        // fsync the directory so the rename is durable across power
        // loss. Failing this isn't a security issue (the previous
        // committed state still verifies); it's a durability one.
        let dir = std::fs::File::open(parent)
            .map_err(|e| KitError::KeyIo(format!("open dir for fsync: {e}")))?;
        dir.sync_all()
            .map_err(|e| KitError::KeyIo(format!("fsync dir: {e}")))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(parent)
            .map_err(|e| KitError::KeyIo(format!("mkdir {}: {e}", parent.display())))?;
        // Windows path: write to a tmp file in the same directory, then
        // rename. No POSIX permission knobs; the user-profile ACL is
        // the only protection.
        let filename = path
            .file_name()
            .ok_or_else(|| KitError::KeyIo(format!("path has no filename: {}", path.display())))?;
        let mut tmp_name = std::ffi::OsString::from(".");
        tmp_name.push(filename);
        tmp_name.push(format!(".tmp.{}", std::process::id()));
        let tmp_path = parent.join(&tmp_name);
        std::fs::write(&tmp_path, secret)
            .map_err(|e| KitError::KeyIo(format!("write tmp: {e}")))?;
        if let Err(e) = std::fs::rename(&tmp_path, path) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(KitError::KeyIo(format!("rename: {e}")));
        }
    }
    Ok(())
}

/// Persist a raw 32-byte secret only if `path` does not already exist.
///
/// Returns `Ok(true)` when the key was created and `Ok(false)` when the
/// destination already existed. The successful write path is crash-atomic and
/// preserves the same parent-directory hardening as [`save_raw_32`].
pub fn save_raw_32_create_new(path: &Path, secret: &[u8; 32]) -> Result<bool, KitError> {
    let parent: &Path = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };

    #[cfg(unix)]
    create_secure_dir_all(parent)?;
    #[cfg(not(unix))]
    std::fs::create_dir_all(parent)
        .map_err(|e| KitError::KeyIo(format!("mkdir {}: {e}", parent.display())))?;

    crate::atomic::write_create_new(path, secret, false)
        .map_err(|e| KitError::KeyIo(format!("create key: {e}")))
}

// -------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::{ZERO, hash};
    use crate::object::{Identity, IdentityKind, ObjectType, RemixSource, Tag};

    fn fixed_kp() -> KeyPair {
        KeyPair::from_seed([0x42; 32])
    }

    fn ed25519_id(pk: [u8; 32]) -> Identity {
        Identity {
            kind: IdentityKind::Ed25519,
            bytes: pk.to_vec(),
        }
    }

    // ------------------------------------------------------------------
    // Sign/verify roundtrip and tamper detection
    // ------------------------------------------------------------------

    #[test]
    fn sign_verify_roundtrip() {
        let kp = fixed_kp();
        let bytes = b"some signing bytes";
        let sig = kp.sign(COMMIT_DOMAIN, bytes);
        verify(&kp.public, COMMIT_DOMAIN, bytes, &sig).expect("verify ok");
    }

    #[test]
    fn verify_rejects_tampered_input() {
        let kp = fixed_kp();
        let bytes = b"original".to_vec();
        let sig = kp.sign(COMMIT_DOMAIN, &bytes);
        let mut tampered = bytes.clone();
        tampered[0] ^= 0x01;
        assert!(matches!(
            verify(&kp.public, COMMIT_DOMAIN, &tampered, &sig),
            Err(KitError::SignatureInvalid)
        ));
    }

    #[test]
    fn verify_object_signature_dispatches_by_type() {
        use crate::object::{Blob, Commit, Identity, Object};
        let kp = fixed_kp();
        let mut commit = Commit {
            tree_hash: [1u8; 32],
            parents: vec![],
            author: Identity::ed25519(kp.public.0),
            signer: kp.public.0,
            message: b"m".to_vec(),
            timestamp: 1,
            message_hash: [0u8; 32],
            content_digest: [0u8; 32],
            signature: [0u8; 64],
        };
        commit.signature = sign_commit(&commit, &kp).expect("sign").0;
        verify_object_signature(&Object::Commit(commit.clone())).expect("signed commit");
        commit.message = b"tampered".to_vec();
        assert!(matches!(
            verify_object_signature(&Object::Commit(commit)),
            Err(KitError::SignatureInvalid)
        ));
        verify_object_signature(&Object::Blob(Blob { data: vec![] })).expect("unsigned kind");
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let kp1 = fixed_kp();
        let kp2 = KeyPair::from_seed([0x55; 32]);
        let bytes = b"x";
        let sig = kp1.sign(COMMIT_DOMAIN, bytes);
        assert!(matches!(
            verify(&kp2.public, COMMIT_DOMAIN, bytes, &sig),
            Err(KitError::SignatureInvalid)
        ));
    }

    /// Regression guard on strict-verification compliance.
    ///
    /// Signatures from our own signer must pass [`verify_ed25519`]. If
    /// `ed25519-dalek` ever produced a non-canonical `R` or a high `s`,
    /// this test fails first.
    #[test]
    fn our_signatures_verify() {
        let kp = fixed_kp();
        // Sample the signature space across several different inputs;
        // a subtle drift in `s` normalization (e.g. if the underlying
        // crate changed its reduction strategy) would surface on at
        // least one of these.
        for (i, input) in [
            b"" as &[u8],
            b"a",
            b"00000000000000000000000000000000",
            &[0xff; 64],
            &(0u8..=255).collect::<Vec<u8>>(),
        ]
        .iter()
        .enumerate()
        {
            let sig = kp.sign(COMMIT_DOMAIN, input);
            verify(&kp.public, COMMIT_DOMAIN, input, &sig)
                .unwrap_or_else(|e| panic!("input #{i} failed to verify: {e:?}"));
        }
    }

    /// A crafted, known non-canonical signature: take a signature our
    /// own signer produced and replace its `s` component with `s + L`
    /// (`L` = the Ed25519 base-point order). `s + L` is congruent to
    /// the original `s` modulo `L` — the same scalar the verification
    /// equation cares about — but is not the canonical
    /// least-representative encoding SPEC-SIGNING §1
    /// requires. This is the classic Ed25519 high-`s` malleability
    /// vector (<https://hdevalence.ca/blog/2020-10-04-its-25519am>),
    /// constructed deterministically rather than by mutating a random
    /// byte of an otherwise-valid signature.
    #[test]
    fn verify_rejects_non_canonical_high_s_signature() {
        // L = 2^252 + 27742317777372353535851937790883648493, little-endian.
        const L: [u8; 32] = [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x10,
        ];

        let kp = fixed_kp();
        let bytes = b"malleability test payload";
        let sig = kp.sign(COMMIT_DOMAIN, bytes);
        verify(&kp.public, COMMIT_DOMAIN, bytes, &sig).expect("original signature must verify");

        // s_malleated = s + L, computed as a 256-bit little-endian
        // addition (s < L < 2^253, so s + L < 2^254 — no overflow past
        // 32 bytes).
        let mut malleated = sig.0;
        let mut carry: u16 = 0;
        for i in 0..32 {
            let sum = u16::from(malleated[32 + i]) + u16::from(L[i]) + carry;
            malleated[32 + i] = (sum & 0xFF) as u8;
            carry = sum >> 8;
        }
        assert_eq!(carry, 0, "s + L must not overflow 32 bytes");
        assert_ne!(
            malleated[32..],
            sig.0[32..],
            "the malleated signature must differ from the original"
        );

        let bad_sig = Signature(malleated);
        assert!(matches!(
            verify(&kp.public, COMMIT_DOMAIN, bytes, &bad_sig),
            Err(KitError::SignatureInvalid)
        ));
    }

    /// A signature built from a real secret scalar `a`, a nonce `r` and an
    /// optional torsion point added to `R`. Returns the signature bytes.
    fn sign_with_r_offset(kp: &KeyPair, message: &[u8], r: u64, offset: EdwardsPoint) -> [u8; 64] {
        use ed25519_dalek::hazmat::ExpandedSecretKey;

        let expanded_hash: [u8; 64] = Sha512::digest(kp.secret.0).into();
        let a = ExpandedSecretKey::from_bytes(&expanded_hash).scalar;
        let r = Scalar::from(r);
        let r_bytes = (r * ED25519_BASEPOINT_POINT + offset).compress().to_bytes();
        let mut h = Sha512::new();
        h.update(r_bytes);
        h.update(kp.public.0);
        h.update(message);
        let k = Scalar::from_bytes_mod_order_wide(&h.finalize().into());
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&r_bytes);
        sig[32..].copy_from_slice((r + k * a).as_bytes());
        sig
    }

    /// A key holder can pad `R` with an 8-torsion point. The cofactored
    /// equation accepts the result, and so does the batch check, whatever
    /// its random weights: the two never disagree on it.
    #[test]
    fn torsion_padded_r_verifies_alone_and_in_a_batch() {
        use curve25519_dalek::constants::EIGHT_TORSION;

        let kp = fixed_kp();
        let message = domain_digest(COMMIT_DOMAIN, b"torsion-padded R probe");
        for (i, torsion) in EIGHT_TORSION.iter().enumerate().skip(1) {
            let sig = sign_with_r_offset(&kp, &message, 7 + i as u64, *torsion);
            verify_ed25519(&kp.public.0, &message, &sig)
                .unwrap_or_else(|e| panic!("torsion point {i}: {e:?}"));
            let honest = kp.sign(COMMIT_DOMAIN, b"honest");
            let honest_digest = domain_digest(COMMIT_DOMAIN, b"honest");
            for _ in 0..16 {
                verify_ed25519_batch(&[
                    (&kp.public.0, &message[..], &sig),
                    (&kp.public.0, &honest_digest[..], &honest.0),
                ])
                .unwrap_or_else(|e| panic!("batch with torsion point {i}: {e:?}"));
            }
        }
    }

    /// With the identity as public key, `R` = identity and `s` = 0 satisfy
    /// the equation for every message. The small-order check rejects it.
    #[test]
    fn verify_rejects_the_universal_weak_key_signature() {
        let mut identity = [0u8; 32];
        identity[0] = 1;
        let mut sig = [0u8; 64];
        sig[0] = 1;
        let message = domain_digest(COMMIT_DOMAIN, b"any message");
        assert!(matches!(
            verify_ed25519(&identity, &message, &sig),
            Err(KitError::SignatureInvalid)
        ));
        assert!(verify_ed25519_batch(&[(&identity, &message[..], &sig)]).is_err());
    }

    /// `R` = identity with `s = k * a` satisfies the equation for a normal
    /// key. The small-order check on `R` rejects it.
    #[test]
    fn verify_rejects_a_small_order_r() {
        use ed25519_dalek::hazmat::ExpandedSecretKey;

        let kp = fixed_kp();
        let message = domain_digest(COMMIT_DOMAIN, b"small-order R probe");
        let expanded_hash: [u8; 64] = Sha512::digest(kp.secret.0).into();
        let a = ExpandedSecretKey::from_bytes(&expanded_hash).scalar;
        let mut r_bytes = [0u8; 32];
        r_bytes[0] = 1;
        let mut h = Sha512::new();
        h.update(r_bytes);
        h.update(kp.public.0);
        h.update(message);
        let k = Scalar::from_bytes_mod_order_wide(&h.finalize().into());
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&r_bytes);
        sig[32..].copy_from_slice((k * a).as_bytes());
        assert!(matches!(
            verify_ed25519(&kp.public.0, &message, &sig),
            Err(KitError::SignatureInvalid)
        ));
        assert!(verify_ed25519_batch(&[(&kp.public.0, &message[..], &sig)]).is_err());
    }

    /// A `y` coordinate at or above `p` names the same point as `y - p`.
    /// The canonical-encoding check rejects it for both `A` and `R`.
    #[test]
    fn verify_rejects_non_canonical_point_encodings() {
        // y = 2^255 - 19 + 1: the identity's y-coordinate (1) plus p.
        let mut high = [0xffu8; 32];
        high[0] = 0xee;
        high[31] = 0x7f;
        assert!(CompressedEdwardsY(high).decompress().is_some());
        assert!(canonical_point(&high).is_none());
        // x = 0 with the sign bit set decodes to the identity, which the
        // small-order check rejects.
        let mut negative_zero = [0u8; 32];
        negative_zero[0] = 1;
        negative_zero[31] = 0x80;
        assert!(canonical_point(&negative_zero).unwrap().is_small_order());

        let kp = fixed_kp();
        let sig = kp.sign(COMMIT_DOMAIN, b"x");
        let message = domain_digest(COMMIT_DOMAIN, b"x");
        let mut bad_r = sig.0;
        bad_r[..32].copy_from_slice(&high);
        assert!(verify_ed25519(&kp.public.0, &message, &bad_r).is_err());
        assert!(matches!(
            verify_ed25519(&high, &message, &sig.0),
            Err(KitError::InvalidPublicKey)
        ));
    }

    /// Together with the small-order check, the byte-level canonical check
    /// accepts exactly the points whose encoding survives decoding and
    /// re-encoding, on every edge encoding and on random bytes.
    #[test]
    fn canonical_point_matches_re_encoding() {
        let reference = |bytes: &[u8; 32]| {
            CompressedEdwardsY(*bytes)
                .decompress()
                .filter(|p| p.compress().as_bytes() == bytes)
        };
        let mut cases: Vec<[u8; 32]> = Vec::new();
        // y = p - 1 .. p + 18 with both signs: around the reduction edge.
        for low in 0xecu8..=0xff {
            for sign in [0u8, 0x80] {
                let mut b = [0xffu8; 32];
                b[0] = low;
                b[31] = 0x7f | sign;
                cases.push(b);
            }
        }
        for low in 0u8..19 {
            for sign in [0u8, 0x80] {
                let mut b = [0u8; 32];
                b[0] = low;
                b[31] = sign;
                cases.push(b);
            }
        }
        let mut state = [7u8; 32];
        for _ in 0..4096 {
            state = Sha512::digest(state)[..32].try_into().unwrap();
            cases.push(state);
        }
        let accepted = |p: Option<EdwardsPoint>| p.filter(|p| !p.is_small_order());
        for b in &cases {
            assert_eq!(
                accepted(canonical_point(b)).map(|p| p.compress()),
                accepted(reference(b)).map(|p| p.compress()),
                "encoding {b:02x?}"
            );
        }
    }

    /// Entries that share a key share one term in the batch. A batch from
    /// two signers verifies, and one bad signature among them fails it.
    #[test]
    fn batch_with_repeated_signers() {
        let keys = [KeyPair::from_seed([1; 32]), KeyPair::from_seed([2; 32])];
        let mut owned: Vec<([u8; 32], [u8; HASH_LEN], [u8; 64])> = (0..40u8)
            .map(|i| {
                let kp = &keys[usize::from(i % 2)];
                (
                    kp.public.0,
                    domain_digest(COMMIT_DOMAIN, &[i]),
                    kp.sign(COMMIT_DOMAIN, &[i]).0,
                )
            })
            .collect();
        let refs: Vec<_> = owned.iter().map(|(p, m, s)| (p, &m[..], s)).collect();
        verify_ed25519_batch(&refs).expect("every entry is valid");

        // Swap the signatures of two entries by the same key.
        let sig = owned[0].2;
        owned[0].2 = owned[2].2;
        owned[2].2 = sig;
        let refs: Vec<_> = owned.iter().map(|(p, m, s)| (p, &m[..], s)).collect();
        assert!(matches!(
            verify_ed25519_batch(&refs),
            Err(KitError::SignatureInvalid)
        ));
    }

    #[test]
    fn batch_accepts_valid_entries_and_rejects_one_bad_entry() {
        let keys: Vec<KeyPair> = (0..24u8).map(|i| KeyPair::from_seed([i; 32])).collect();
        let messages: Vec<[u8; HASH_LEN]> = (0..24u8)
            .map(|i| domain_digest(COMMIT_DOMAIN, &[i]))
            .collect();
        let mut sigs: Vec<[u8; 64]> = keys
            .iter()
            .zip(0..24u8)
            .map(|(kp, i)| kp.sign(COMMIT_DOMAIN, &[i]).0)
            .collect();
        let entries = |sigs: &[[u8; 64]]| -> Vec<([u8; 32], [u8; HASH_LEN], [u8; 64])> {
            keys.iter()
                .zip(&messages)
                .zip(sigs)
                .map(|((kp, m), s)| (kp.public.0, *m, *s))
                .collect()
        };
        let owned = entries(&sigs);
        let refs: Vec<_> = owned.iter().map(|(p, m, s)| (p, &m[..], s)).collect();
        verify_ed25519_batch(&refs).expect("every entry is valid");
        verify_ed25519_batch(&[]).expect("an empty batch has nothing to reject");

        sigs[11][40] ^= 1;
        let owned = entries(&sigs);
        let refs: Vec<_> = owned.iter().map(|(p, m, s)| (p, &m[..], s)).collect();
        assert!(matches!(
            verify_ed25519_batch(&refs),
            Err(KitError::SignatureInvalid)
        ));
    }

    // ------------------------------------------------------------------
    // Domain separation guard (SPEC §2.1)
    // ------------------------------------------------------------------

    #[test]
    fn domain_separation_commit_vs_remix() {
        let kp = fixed_kp();
        let bytes = b"shared bytes";
        let sig = kp.sign(COMMIT_DOMAIN, bytes);
        // Same bytes, same key, but the wrong domain → MUST fail.
        assert!(matches!(
            verify(&kp.public, REMIX_DOMAIN, bytes, &sig),
            Err(KitError::SignatureInvalid)
        ));
    }

    #[test]
    fn domain_digest_differs_per_domain() {
        let bytes = b"abc";
        let a = domain_digest(COMMIT_DOMAIN, bytes);
        let b = domain_digest(REMIX_DOMAIN, bytes);
        assert_ne!(a, b);
    }

    /// `domain_digest` hashes a 2-byte LE length prefix before the
    /// domain label, so
    /// `BLAKE3(len_le16(D) || D || M)` — not `BLAKE3(D || M)`. This
    /// closes a latent ambiguity between a domain `"ab"` + message
    /// `"cX"` vs domain `"abc"` + message `"X"` (same concatenation).
    ///
    /// Regression guard: compute the expected digest by hand and
    /// assert it matches. If anyone reverts the length prefix this
    /// trips before any golden-vector drift is noticed.
    #[test]
    fn domain_digest_includes_length_prefix() {
        let domain = b"ab";
        let msg = b"cX";
        let got = domain_digest(domain, msg);
        let mut want = blake3::Hasher::new();
        let len = u16::try_from(domain.len()).unwrap();
        want.update(&len.to_le_bytes());
        want.update(domain);
        want.update(msg);
        assert_eq!(got, *want.finalize().as_bytes());

        // And the ambiguous case with different domain/message split
        // MUST produce a different digest.
        let other = domain_digest(b"abc", b"X");
        assert_ne!(got, other);
    }

    // ------------------------------------------------------------------
    // RFC 8032 §7.1 known-answer test 1.
    //
    // The reference vector covers a *raw* empty message. PureEdDSA over
    // an empty input should produce the published signature. Since the
    // only thing our `sign()` API exposes is "domain || signing_bytes",
    // the simplest way to reproduce the vector is to call into the
    // dalek `SigningKey` directly. This guards against any accidental
    // change to the underlying primitive (e.g. someone swapping in
    // Ed25519ph would silently break interop).
    // ------------------------------------------------------------------

    #[test]
    fn ed25519_rfc8032_vector_1() {
        // Test vector 1 from RFC 8032 §7.1.
        let seed_hex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
        let pk_hex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
        let sig_hex = concat!(
            "e5564300c360ac729086e2cc806e828a",
            "84877f1eb8e5d974d873e06522490155",
            "5fb8821590a33bacc61e39701cf9b46b",
            "d25bf5f0595bbe24655141438e7a100b",
        );
        let seed: [u8; 32] = hex::decode(seed_hex).unwrap().try_into().unwrap();
        let kp = KeyPair::from_seed(seed);
        // Round-trip the public key.
        assert_eq!(hex::encode(kp.public.0), pk_hex);
        // Sign the empty message — bypass our domain-prefix path so the
        // test reads as the RFC vector.
        let signing = SigningKey::from_bytes(&kp.secret.0);
        let sig = signing.sign(b"");
        assert_eq!(hex::encode(sig.to_bytes()), sig_hex);
    }

    // ------------------------------------------------------------------
    // Commit / remix sign + verify (uses the full pipeline).
    // ------------------------------------------------------------------

    fn build_commit(kp: &KeyPair, msg: &[u8]) -> Commit {
        Commit {
            tree_hash: hash(b"tree"),
            parents: vec![],
            author: ed25519_id(kp.public.0),
            signer: kp.public.0,
            message: msg.to_vec(),
            timestamp: 1_711_300_000,
            message_hash: ZERO,
            content_digest: ZERO,
            signature: [0u8; 64],
        }
    }

    #[test]
    fn sign_then_verify_commit() {
        let kp = fixed_kp();
        let mut c = build_commit(&kp, b"hello");
        c.signature = sign_commit(&c, &kp).unwrap().0;
        verify_commit(&c).expect("verify ok");
    }

    #[test]
    fn tampered_commit_message_fails_verify() {
        let kp = fixed_kp();
        let mut c = build_commit(&kp, b"hello");
        c.signature = sign_commit(&c, &kp).unwrap().0;
        c.message = b"tampered".to_vec();
        assert!(matches!(verify_commit(&c), Err(KitError::SignatureInvalid)));
    }

    #[test]
    fn message_hash_does_not_affect_signing_bytes() {
        // Spec §3: `message_hash` and `content_digest` are EXCLUDED from
        // the signing bytes. Two commits differing only in those fields
        // must have identical signing bytes (and therefore identical
        // signatures under the same key).
        let kp = fixed_kp();
        let mut c1 = build_commit(&kp, b"x");
        let mut c2 = c1.clone();
        c2.message_hash = hash(b"some annotation");
        c2.content_digest = hash(b"another annotation");
        let sb1 = commit_signing_bytes(&c1).unwrap();
        let sb2 = commit_signing_bytes(&c2).unwrap();
        assert_eq!(sb1, sb2);
        c1.signature = sign_commit(&c1, &kp).unwrap().0;
        c2.signature = c1.signature;
        verify_commit(&c2).expect("annotation fields are not signed");
    }

    #[test]
    fn sign_then_verify_remix() {
        let kp = fixed_kp();
        let mut r = Remix {
            tree_hash: hash(b"tree"),
            parents: vec![],
            sources: vec![RemixSource {
                upstream_id: hash(b"upstream"),
                commit_hash: hash(b"commit"),
            }],
            author: ed25519_id(kp.public.0),
            signer: kp.public.0,
            message: b"remix".to_vec(),
            timestamp: 2_000,
            signature: [0u8; 64],
        };
        r.signature = sign_remix(&r, &kp).unwrap().0;
        verify_remix(&r).expect("verify ok");
    }

    // ------------------------------------------------------------------
    // Tag sign + verify + cross-protocol domain separation.
    // ------------------------------------------------------------------

    fn build_tag(kp: &KeyPair, msg: &[u8]) -> Tag {
        Tag {
            target: hash(b"target"),
            target_type: ObjectType::Commit,
            name: b"v1.0.0".to_vec(),
            tagger: ed25519_id(kp.public.0),
            signer: kp.public.0,
            message: msg.to_vec(),
            timestamp: 1_711_300_000,
            signature: [0u8; 64],
        }
    }

    #[test]
    fn sign_then_verify_tag() {
        let kp = fixed_kp();
        let mut t = build_tag(&kp, b"release");
        t.signature = sign_tag(&t, &kp).unwrap().0;
        verify_tag(&t).expect("verify ok");
    }

    #[test]
    fn tampered_tag_message_fails_verify() {
        let kp = fixed_kp();
        let mut t = build_tag(&kp, b"release");
        t.signature = sign_tag(&t, &kp).unwrap().0;
        t.message = b"tampered".to_vec();
        assert!(matches!(verify_tag(&t), Err(KitError::SignatureInvalid)));
    }

    #[test]
    fn tampered_tag_target_fails_verify() {
        let kp = fixed_kp();
        let mut t = build_tag(&kp, b"release");
        t.signature = sign_tag(&t, &kp).unwrap().0;
        t.target = hash(b"other");
        assert!(matches!(verify_tag(&t), Err(KitError::SignatureInvalid)));
    }

    #[test]
    fn annotated_unsigned_tag_fails_verify() {
        // A tag carrying a full, otherwise-legitimate annotation body
        // (name, tagger, message, timestamp) but an all-zero signature
        // — the sentinel git-bridge import produces for an
        // annotated-but-unsigned git tag — must never verify. The
        // all-zero bytes are not a magic "no signature" marker; they
        // are just another (invalid) signature value.
        let kp = fixed_kp();
        let mut t = build_tag(&kp, b"release");
        t.signature = [0u8; 64];
        assert!(matches!(verify_tag(&t), Err(KitError::SignatureInvalid)));
    }

    #[test]
    fn tag_domain_differs_from_commit_and_remix() {
        // The three domains must be pairwise distinct constants.
        assert_ne!(TAG_DOMAIN, COMMIT_DOMAIN);
        assert_ne!(TAG_DOMAIN, REMIX_DOMAIN);
        let bytes = b"abc";
        let dt = domain_digest(TAG_DOMAIN, bytes);
        assert_ne!(dt, domain_digest(COMMIT_DOMAIN, bytes));
        assert_ne!(dt, domain_digest(REMIX_DOMAIN, bytes));
    }

    /// Cross-protocol replay guard: a signature produced over the tag
    /// domain MUST NOT verify under the commit/remix domain (and vice
    /// versa), even with the same key and the same signing bytes.
    #[test]
    fn tag_signature_does_not_verify_as_commit_or_remix() {
        let kp = fixed_kp();
        let bytes = b"shared signing bytes";
        let tag_sig = kp.sign(TAG_DOMAIN, bytes);
        assert!(matches!(
            verify(&kp.public, COMMIT_DOMAIN, bytes, &tag_sig),
            Err(KitError::SignatureInvalid)
        ));
        assert!(matches!(
            verify(&kp.public, REMIX_DOMAIN, bytes, &tag_sig),
            Err(KitError::SignatureInvalid)
        ));
        // And the converse: a commit-domain signature must not verify
        // under the tag domain.
        let commit_sig = kp.sign(COMMIT_DOMAIN, bytes);
        assert!(matches!(
            verify(&kp.public, TAG_DOMAIN, bytes, &commit_sig),
            Err(KitError::SignatureInvalid)
        ));
    }

    // ------------------------------------------------------------------
    // Determinism — Ed25519 deterministic signatures (RFC 8032).
    // ------------------------------------------------------------------

    #[test]
    fn signing_is_deterministic() {
        let kp = fixed_kp();
        let bytes = b"deterministic";
        let s1 = kp.sign(COMMIT_DOMAIN, bytes);
        let s2 = kp.sign(COMMIT_DOMAIN, bytes);
        assert_eq!(s1.0, s2.0);
    }

    // ------------------------------------------------------------------
    // Key file I/O.
    // ------------------------------------------------------------------

    #[test]
    fn save_then_load_roundtrip() {
        // The key directory is new, so save creates it at mode 0700.
        let dir = tempdir().join("keys");
        let p = dir.join("default.key");
        let kp = KeyPair::from_seed([0x77; 32]);
        save_key(&p, &kp).unwrap();
        let kp2 = load_key(&p).unwrap();
        assert_eq!(kp.public.0, kp2.public.0);
        assert_eq!(kp.secret.0, kp2.secret.0);
    }

    #[cfg(unix)]
    #[test]
    fn save_key_writes_mode_0600() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempdir();
        let p = dir.join("default.key");
        let kp = KeyPair::from_seed([0x33; 32]);
        save_key(&p, &kp).unwrap();
        let meta = std::fs::metadata(&p).unwrap();
        assert_eq!(meta.mode() & 0o777, 0o600);
    }

    /// If the key file already exists with a wider mode (e.g. from an
    /// older kit that wrote 0o644), saving again MUST tighten it to
    /// 0o600. The hardened path writes a fresh temp file created at mode
    /// 0o600 (via `O_CREAT|O_EXCL`) and `rename(2)`s it over the target,
    /// so the wide-mode inode is replaced wholesale — the resulting file
    /// carries the temp file's tight mode regardless of the old mode, and
    /// there is no `open()`/`set_permissions()` window for an attacker to
    /// swap in a different inode.
    #[cfg(unix)]
    #[test]
    fn save_key_tightens_preexisting_wide_mode_to_0600() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let dir = tempdir();
        let p = dir.join("default.key");
        // Pre-seed a wide-mode file at the target path.
        std::fs::write(&p, b"old contents").unwrap();
        let mut perm = std::fs::metadata(&p).unwrap().permissions();
        perm.set_mode(0o644);
        std::fs::set_permissions(&p, perm).unwrap();
        assert_eq!(
            std::fs::metadata(&p).unwrap().mode() & 0o777,
            0o644,
            "sanity: pre-seeded 0o644"
        );

        let kp = KeyPair::from_seed([0x55; 32]);
        save_key(&p, &kp).unwrap();

        let meta = std::fs::metadata(&p).unwrap();
        assert_eq!(meta.mode() & 0o777, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn load_key_rejects_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir();
        let p = dir.join("default.key");
        let kp = KeyPair::from_seed([0x33; 32]);
        save_key(&p, &kp).unwrap();
        // Loosen perms to 0644 — load must reject.
        let mut perm = std::fs::metadata(&p).unwrap().permissions();
        perm.set_mode(0o644);
        std::fs::set_permissions(&p, perm).unwrap();
        match load_key(&p) {
            Err(KitError::InsecureKeyPermissions { actual }) => {
                assert_eq!(actual, 0o644);
            }
            other => panic!("expected InsecureKeyPermissions, got {other:?}"),
        }
    }

    #[test]
    fn load_key_rejects_wrong_length() {
        let dir = tempdir();
        let p = dir.join("short.key");
        std::fs::write(&p, b"too short").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // File mode 0600 + parent dir 0700 — load_key gates on
            // both (parent dir mode was added with the
            // hardening pass).
            let mut perm = std::fs::metadata(&p).unwrap().permissions();
            perm.set_mode(0o600);
            std::fs::set_permissions(&p, perm).unwrap();
            let mut dperm = std::fs::metadata(&dir).unwrap().permissions();
            dperm.set_mode(0o700);
            std::fs::set_permissions(&dir, dperm).unwrap();
        }
        assert!(matches!(
            load_key(&p),
            Err(KitError::InvalidKeyLength { actual: 9 })
        ));
    }

    /// `load_key` opens with `O_NOFOLLOW` and refuses any path
    /// whose final component is a symlink. Defends against an attacker
    /// who can pre-create the path as a symlink and redirect us to a
    /// 32-byte file they control.
    #[cfg(unix)]
    #[test]
    fn load_key_rejects_symlink() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir();
        let real = dir.join("real.key");
        let kp = KeyPair::from_seed([0xAB; 32]);
        save_key(&real, &kp).unwrap();
        // Create a symlink at `link.key` → `real.key`. Both files end
        // up under the same 0o700 parent dir.
        let link = dir.join("link.key");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let mut perm = std::fs::metadata(&dir).unwrap().permissions();
        perm.set_mode(0o700);
        std::fs::set_permissions(&dir, perm).unwrap();
        match load_key(&link) {
            Err(KitError::KeyPathIsSymlink(_)) => {}
            other => panic!("expected KeyPathIsSymlink, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn load_key_rejects_symlinked_ancestor() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir();
        let real_parent = dir.join("realkeys");
        std::fs::create_dir_all(&real_parent).unwrap();
        let mut parent_perm = std::fs::metadata(&real_parent).unwrap().permissions();
        parent_perm.set_mode(0o700);
        std::fs::set_permissions(&real_parent, parent_perm).unwrap();

        let real = real_parent.join("default.key");
        let kp = KeyPair::from_seed([0xBC; 32]);
        save_key(&real, &kp).unwrap();

        let symlink_parent = dir.join("symlink-keys");
        std::os::unix::fs::symlink(&real_parent, &symlink_parent).unwrap();
        match load_key(&symlink_parent.join("default.key")) {
            Err(KitError::KeyPathIsSymlink(_)) => {}
            other => panic!("expected KeyPathIsSymlink, got {other:?}"),
        }
    }

    /// `load_key` refuses when the immediate parent directory
    /// is group/world-accessible — `inotify`-watch + symlink-swap
    /// attacks are out of scope, but we don't make them easy.
    #[cfg(unix)]
    #[test]
    fn load_key_rejects_world_readable_parent() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir();
        let p = dir.join("default.key");
        let kp = KeyPair::from_seed([0xCD; 32]);
        save_key(&p, &kp).unwrap();
        // save_key just tightened the dir to 0o700; loosen it again
        // to simulate a host where `.kit/keys/` was created via a
        // non-kit tool that ignored the mode.
        let mut perm = std::fs::metadata(&dir).unwrap().permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(&dir, perm).unwrap();
        match load_key(&p) {
            Err(KitError::InsecureKeyDir { actual }) => {
                assert_eq!(actual, 0o755);
            }
            other => panic!("expected InsecureKeyDir, got {other:?}"),
        }
    }

    /// `save_key` writes via a tmp file in the same directory
    /// and renames atomically. Verifies a pre-existing key at the
    /// target path is replaced cleanly (matches the old "tighten
    /// pre-existing wide mode" regression in spirit).
    #[cfg(unix)]
    #[test]
    fn save_key_replaces_existing_key_atomically() {
        use std::os::unix::fs::MetadataExt;
        // The key directory is new, so save creates it at mode 0700.
        let dir = tempdir().join("keys");
        let p = dir.join("default.key");
        let kp1 = KeyPair::from_seed([0x11; 32]);
        save_key(&p, &kp1).unwrap();
        let inode_before = std::fs::metadata(&p).unwrap().ino();

        let kp2 = KeyPair::from_seed([0x22; 32]);
        save_key(&p, &kp2).unwrap();
        let meta_after = std::fs::metadata(&p).unwrap();
        // Atomic rename gives us a fresh inode — unchanged inode would
        // mean we had truncated-in-place, the bug we removed.
        assert_ne!(
            meta_after.ino(),
            inode_before,
            "save_key must replace via rename, not truncate-in-place"
        );
        assert_eq!(meta_after.mode() & 0o777, 0o600);
        let kp_loaded = load_key(&p).unwrap();
        assert_eq!(kp_loaded.public.0, kp2.public.0);
    }

    /// A directory that exists before the save keeps its mode. The save
    /// does not chmod a directory it did not create, such as `.`.
    #[cfg(unix)]
    #[test]
    fn save_key_leaves_preexisting_dir_mode_alone() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        save_key(&dir.join("default.key"), &KeyPair::from_seed([0x44; 32])).unwrap();
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o755);
    }

    /// Every directory the save creates gets mode 0700.
    #[cfg(unix)]
    #[test]
    fn save_key_creates_missing_dirs_at_0700() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir();
        let p = dir.join("a").join("b").join("default.key");
        save_key(&p, &KeyPair::from_seed([0x55; 32])).unwrap();
        for d in [dir.join("a"), dir.join("a").join("b")] {
            let mode = std::fs::metadata(&d).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "{}", d.display());
        }
    }

    #[test]
    fn save_raw_32_create_new_refuses_existing_key() {
        // The key directory is new, so save creates it at mode 0700.
        let dir = tempdir().join("keys");
        let p = dir.join("default.key");
        assert!(save_raw_32_create_new(&p, &[0x11; 32]).unwrap());
        assert!(!save_raw_32_create_new(&p, &[0x22; 32]).unwrap());
        assert_eq!(&*load_raw_32(&p).unwrap(), &[0x11; 32]);
    }

    #[cfg(unix)]
    #[test]
    fn save_key_rejects_symlinked_ancestor() {
        let dir = tempdir();
        let real_parent = dir.join("realkeys");
        std::fs::create_dir_all(&real_parent).unwrap();
        let symlink_parent = dir.join("symlink-keys");
        std::os::unix::fs::symlink(&real_parent, &symlink_parent).unwrap();
        let kp = KeyPair::from_seed([0x44; 32]);
        match save_key(&symlink_parent.join("default.key"), &kp) {
            Err(KitError::KeyPathIsSymlink(_)) => {}
            other => panic!("expected KeyPathIsSymlink, got {other:?}"),
        }
    }

    // ------------------------------------------------------------------
    // Zeroization regression guards
    // ------------------------------------------------------------------

    /// Direct invariant on `SecretSeed::zeroize()`: calling it must
    /// scrub the inner bytes in place. This is the contract the
    /// `ZeroizeOnDrop` impl relies on; if a future refactor swapped
    /// `SecretSeed` for a type that didn't actually zero, this would
    /// catch it before the drop-time test could.
    #[test]
    fn secret_seed_zeroize_clears_bytes() {
        let mut s = SecretSeed([0xAAu8; SECRET_KEY_LENGTH]);
        s.zeroize();
        assert_eq!(s.0, [0u8; SECRET_KEY_LENGTH]);
    }

    /// Round-trip the new `from_seed_zeroizing` constructor: it must
    /// produce the same `(public, secret)` pair as `from_seed`. The
    /// public-key check is the easy half; the secret-bytes check is
    /// the load-bearing one — it pins that no derivation step silently
    /// rotates the stored seed.
    #[test]
    fn from_seed_zeroizing_matches_from_seed() {
        let raw = [0x9Au8; SECRET_KEY_LENGTH];
        let wrapped: Zeroizing<[u8; SECRET_KEY_LENGTH]> = Zeroizing::new(raw);
        let a = KeyPair::from_seed(raw);
        let b = KeyPair::from_seed_zeroizing(&wrapped);
        assert_eq!(a.public.0, b.public.0);
        assert_eq!(a.secret.0, b.secret.0);
        // And a sign / verify roundtrip with `b` to make sure the
        // constructor doesn't silently break the signing pipeline.
        let sig = b.sign(COMMIT_DOMAIN, b"x");
        verify(&b.public, COMMIT_DOMAIN, b"x", &sig).expect("verify");
    }

    /// Structural pin on the REAL type's drop-time scrub wiring:
    /// `SecretSeed` (the only owner of `KeyPair`'s secret bytes) must
    /// keep implementing `ZeroizeOnDrop`. If a refactor removed the
    /// derive (turning drop into a plain memory release), this stops
    /// compiling — the value-level half (a `zeroize()` pass actually
    /// clearing the bytes) is pinned by
    /// `secret_seed_zeroize_clears_bytes` above. Together they cover
    /// what the old sentinel-struct test only pretended to: the real
    /// `SecretSeed`, not a test-local stand-in.
    #[test]
    fn keypair_drop_runs_zeroize_on_secret() {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<SecretSeed>();

        // And the field wiring: the secret a `KeyPair` holds IS a
        // `SecretSeed` (not a raw array that would drop without a
        // scrub), carrying the caller's seed bytes.
        let kp = KeyPair::from_seed([0xDEu8; 32]);
        let seed_ref: &SecretSeed = &kp.secret;
        assert_eq!(seed_ref.0, [0xDEu8; 32]);
        drop(kp);
    }

    // Tiny self-contained tempdir helper — we don't want to pull in the
    // `tempfile` crate just for two tests. Each call returns a fresh
    // dir under `std::env::temp_dir()` named with a per-process counter
    // and a high-resolution timestamp.
    fn tempdir() -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::time::{SystemTime, UNIX_EPOCH};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let p =
            std::env::temp_dir().join(format!("kit-sign-test-{nanos}-{n}-{}", std::process::id()));
        std::fs::create_dir_all(&p).unwrap();
        p
    }
}
