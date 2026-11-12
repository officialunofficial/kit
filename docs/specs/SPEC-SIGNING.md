---
spec: SPEC-SIGNING
version: 2
status: stable-normative
audience: implementers of compatible commit/remix signers and verifiers
---

# SPEC-SIGNING &mdash; kit v1 signature domains

Status: **Normative** for kit v1. See SPEC-CONVENTIONS §1 for the
RFC 2119/8174 boilerplate this document's MUST/SHOULD language relies
on, and §6 for the no-vendor-references rule this document follows:
verification is specified below as a mathematical predicate, not as a
named library function.
Scope: the exact bytes covered by an Ed25519 signature on a commit or
remix, and the domain separator used.

This document puts a version and magic in the signing bytes and
separates signature domains.

---

## 1. Signing primitives

- **Hash:** BLAKE3 default mode (no keyed hashing, no derive-key at the
  signing layer). Output: 32 bytes.
- **Signature:** Ed25519 per RFC 8032 only. kit-core does NOT support
  any other signature algorithm; multi-algorithm signing (if any) lives
  in `kit-attest`/SPEC-ATTESTATIONS and is out of scope here.
  Public key 32 bytes, seed 32 bytes, signature 64 bytes.
- **Signers sign a BLAKE3 digest of the signing bytes (§2.1), not the
  raw signing bytes.** This is PureEdDSA (RFC 8032's `Sign`/`Verify` as
  defined &mdash; no HashEdDSA prehashing indirection) applied to a
  32-byte *message* that happens to itself be a hash. It is
  deliberately **not** Ed25519ph (RFC 8032 §5.1, the "prehash" variant):
  Ed25519ph runs the message through SHA-512 internally as part of the
  signature algorithm and prepends its own `dom2` domain-separation
  context, producing a different signature over the same bytes than
  PureEdDSA would. kit signs a 32-byte value with plain PureEdDSA; that
  value happens to be `BLAKE3(domain ‖ signing_bytes)` rather than the
  object's raw signing bytes, purely so a signer implementation (in
  particular a hardware or remote signer, SPEC-EXTERNAL-SIGNER) only
  ever needs to handle a fixed-size 32-byte input regardless of object
  size &mdash; it never streams or buffers a variable-length message.
  **Security consequence, stated explicitly:** because the signed
  message is a hash rather than the object itself, this construction's
  unforgeability reduces to two independent assumptions instead of one &mdash;
  Ed25519's EUF-CMA security *and* BLAKE3's collision resistance (an
  attacker who can find `signing_bytes ≠ signing_bytes'` with
  `BLAKE3(domain ‖ signing_bytes) = BLAKE3(domain ‖ signing_bytes')` can
  transplant a valid signature onto different object content). BLAKE3
  has no known collision weakness and this reduction is the same one
  every hash-then-sign scheme accepts (this is exactly what
  Ed25519ph's `dom2`-wrapped SHA-512 prehash also relies on) &mdash; but it is
  a real, stated precondition, not a free property of "PureEdDSA."
- **Verification acceptance predicate:** a signature `(R, S)` over
  message `M` under public key `A` is accepted if and only if all of
  the following hold:
  1. `A` and `R` each decode as **canonical** encodings of points on
     the curve (the top bit is the sign bit; the remaining 255 bits,
     interpreted little-endian, MUST be strictly less than the field
     prime `p = 2²⁵⁵ - 19`; an encoding using a value ≥ p is rejected
     rather than reduced mod `p`, and an encoding of `x = 0` with the
     sign bit set is rejected). `x = 0` holds only for the identity and
     the point of order 2, so check 2 rejects that second form as well.
  2. `A` and `R` are **not** of small order, that is, `[8]A` and `[8]R`
     are not the identity. A point with a torsion component and a
     prime-order component is not of small order and passes this check.
  3. `S` is **canonical**: interpreted as a little-endian integer,
     `0 ≤ S < L` where `L` is the order of the curve's prime-order
     subgroup (`2²⁵² + 27742317777372353535851937790883648493`); a
     value `S ≥ L` is rejected rather than reduced mod `L`.
  4. The **cofactored** equation holds:
     `[8]([S]B - R - [k]A)` is the identity, where `B` is the base point
     and `k = SHA-512(R ‖ A ‖ M) mod L`, computed over the encodings of
     `R` and `A` as received.

  Checks 1–3 look at each signature alone, and check 4 is the equation a
  randomized batch check can reproduce. So a batch verifier (below) and a
  single verifier accept exactly the same signatures. Check 4 is the
  ZIP-215 equation. Checks 1 and 2 are stricter than ZIP-215, which
  accepts non-canonical encodings and small-order points: with a
  small-order `A`, `R` = identity and `S` = 0 satisfy check 4 for every
  message, and a second encoding of `A` or `R` would give one signature,
  key or object more than one byte form. Check 3 is the same as in
  ZIP-215.

  Every Ed25519 verification in kit (commits, remixes, tags,
  attestations, write grants, URL tokens, auth envelopes) MUST apply this
  predicate, so that every verifier reaches the same verdict on every
  input. The golden vectors in `rust/tests/golden/ed25519/` pin it.
- **Batch verification:** a verifier MAY check `n` signatures at once.
  It MUST first apply checks 1–3 to every entry and reject the batch if
  any entry fails them. It then draws `n` independent, uniformly random
  128-bit weights `z_i` from a cryptographically secure source, fresh
  for each batch and never derived from the batch contents, and accepts
  the batch if and only if
  `[8]([Σ z_i S_i]B - Σ [z_i]R_i - Σ [z_i k_i]A_i)` is the identity. A
  batch of entries that each pass the predicate always passes. A batch
  with any failing entry passes with probability at most about `2⁻¹²⁸`.
  When a batch fails, the verifier checks each entry with the predicate
  to find the failing one.

---

## 2. Domain separation

kit defines three distinct signing domains. They MUST produce disjoint
signable byte strings for any possible input.

```
COMMIT_DOMAIN   = "kit.commit\x00"       (11 bytes)
REMIX_DOMAIN    = "kit.remix\x00"        (10 bytes)
TAG_DOMAIN      = "kit.tag\x00"          (8 bytes)
```

The terminal `\x00` is part of the domain string. Disjointness here does
not depend on it &mdash; the §2.1 length prefix already makes every domain
string self-delimiting, so no well-formed domain can be a prefix of
another regardless of the terminator. The `\x00` is retained because it
makes that prefix-freeness property visually obvious to a reader
inspecting the raw bytes, which is a readability aid, not a
cryptographic requirement (BLAKE3 is not vulnerable to length-extension
in the way some earlier hash constructions were, so nothing here is
compensating for that).

`COMMIT_DOMAIN` covers commits, `REMIX_DOMAIN` covers remixes, and
`TAG_DOMAIN` covers annotated/signed tag objects (§4a). The
tag domain is **deliberately distinct** from the commit/remix domains so
a tag signature can never be replayed as a commit/remix signature, or
vice versa.

### 2.1 Signing-hash derivation

Implementations MUST compute the signing digest with a 16-bit little-endian
domain length prefix, followed by the full domain string and canonical signing
bytes:

```
digest = BLAKE3(u16_le(domain.len) || domain || signing_bytes)
```

Where `domain` is the full domain string *including* the trailing
`\x00`. This is the shape kit commits to on the wire and in test vectors.

The length prefix makes the `(domain, signing_bytes)` boundary explicit. A
verifier MUST NOT use BLAKE3 `derive_key`, bare `BLAKE3(domain ||
signing_bytes)`, or any other domain construction for v1 signatures.

---

## 3. Commit signing bytes

For a commit C (as defined in SPEC-OBJECTS §5), the canonical signing
bytes are:

```
signing_bytes = PROLOGUE
              || tree_hash
              || u32 LE(parent_count) || parent_hash * parent_count
              || Identity(author)
              || u32 LE(message_len) || message_bytes
              || u64 LE(timestamp)
              || signer_pubkey
```

Where `PROLOGUE` is the 6 bytes defined in SPEC-OBJECTS §2:
`[object_type=0x03] [magic="KOB1"] [schema_version=0x01]`.

**Included fields, in order:**

1. Object prologue (6 bytes) &mdash; binds the signature to the object type
   and schema version.
2. `tree_hash` (32 bytes) &mdash; content the commit points at.
3. `parent_count` (4 LE) and `parent_count` × `parent_hash` (32 each) &mdash;
   commit history.
4. `Identity author` (variable; see SPEC-OBJECTS §9) &mdash; length-prefixed,
   so field length ambiguity is impossible.
5. `message_len` (4 LE) and message bytes &mdash; length-prefixed.
6. `timestamp` (8 LE).
7. `signer` (32 bytes) &mdash; the public key that will verify the signature.

**Excluded fields and why:**

- `signature` (64 bytes) &mdash; a signature cannot cover itself.
- `message_hash` (32 bytes) &mdash; optional off-chain annotation field;
  irrelevant to core commit identity. Including it would mean any
  downstream re-computation shifts the commit hash.
- `content_digest` (32 bytes) &mdash; same reasoning: downstream pack-digest
  annotation. Not a commit identity input.

These two exclusions keep the annotations out of the signing bytes. They are the only commit-
struct fields excluded from signing bytes.

Both annotation fields are therefore **unsigned**. Anyone can copy a signed
commit and set or change `message_hash` or `content_digest`. The copy keeps a
valid signature. It has a different commit id, because the id covers the whole
serialized object. A verifier MUST NOT treat the annotations as authenticated.
A verifier MUST NOT treat "same signature" as "same commit id".

The **signing hash** is then:

```
signing_hash = BLAKE3(u16_le(11) || "kit.commit\x00" || signing_bytes)
```

And the commit's `signature` field is `Ed25519.sign(signer_seed,
signing_hash)`.

---

## 4. Remix signing bytes

For a remix R (SPEC-OBJECTS §6):

```
signing_bytes = PROLOGUE                   // object_type=0x04
              || tree_hash
              || u32 LE(parent_count) || parent_hash * parent_count
              || u32 LE(source_count) || (upstream_id || commit_hash) * source_count
              || Identity(author)
              || u32 LE(message_len) || message_bytes
              || u64 LE(timestamp)
              || signer_pubkey
```

Excluded: `signature`.

```
signing_hash = BLAKE3(u16_le(10) || "kit.remix\x00" || signing_bytes)
```

---

## 4a. Tag signing bytes

For a tag T (SPEC-OBJECTS §6a):

```
signing_bytes = PROLOGUE                   // object_type=0x07
              || target                    // 32 bytes, hash of tagged object
              || target_type               // 1 byte ObjectType
              || u32 LE(name_len) || name_bytes
              || Identity(tagger)
              || u32 LE(message_len) || message_bytes
              || u64 LE(timestamp)
              || signer_pubkey
```

Excluded: `signature` (a signature cannot cover itself). Every other tag
field is covered, so flipping the `target`, `target_type`, `name`,
`tagger`, `message`, `timestamp`, or `signer` invalidates the signature.

```
signing_hash = BLAKE3(u16_le(8) || "kit.tag\x00" || signing_bytes)
```

The tag's `signature` field is `Ed25519.sign(signer_seed, signing_hash)`.

An **annotated, unsigned** tag (`kit tag -a`) carries an all-zero
`signature` (`0x00`×64). It is a valid object but not a valid signature:
`verify_tag` over an all-zero signature fails the Ed25519 predicate of §1.
A **signed** tag (`kit tag -s`) carries a real signature that
`kit verify <tag>` accepts.

---

## 5. Cross-domain collision proof sketch

Commit signing input always begins with `u16_le(11)` followed by the 11-byte
domain string `"kit.commit\x00"`; remix signing input begins with
`u16_le(10)` followed by the 10-byte string `"kit.remix\x00"`; tag
signing input begins with `u16_le(8)` followed by the 8-byte string
`"kit.tag\x00"`.

- All three domain *lengths* (11/10/8) differ, so the 2-byte LE
  length prefix alone already distinguishes them before any domain byte
  is read.
- All three domain strings share the 4-byte prefix `"kit."` (bytes
  0–3) and then diverge at byte index 4 &mdash; `'c'` (0x63) for
  `"kit.commit\x00"`, `'r'` (0x72) for `"kit.remix\x00"`, and `'t'`
  (0x74) for `"kit.tag\x00"` &mdash; giving a second, independent separator
  once the length check is bypassed (for example by a hypothetical
  length-collision in some future fourth domain).

Because the domain length and the first differing domain byte occur strictly
before any possible user-controlled content (domains are compile-time
constants), no user input can make one domain's hash input equal another's.
BLAKE3 is collision-resistant, so distinct inputs have cryptographically
distinct digests.

Therefore, a signature over any one of the commit/remix/tag domain
digests cannot be replayed as a signature over either of the other two.
§8 extends this argument to the auth v2, grant, DSSE and SSH roles.

This is the defense against cross-domain signature confusion. The previous scheme used only the
ObjectType tag byte (0x03/0x04) as separator &mdash; one byte of domain &mdash; and
was fragile. v1 uses ≥ 11 bytes of high-entropy ASCII plus a null
terminator.

---

## 6. Verification algorithm

Given a commit C retrieved from the store:

1. Check object prologue (SPEC-OBJECTS §2).
2. Re-build signing bytes per §3. (It's the caller's responsibility to
   retrieve the exact `signer` field from C; the verifier does not
   accept a public key from elsewhere.)
3. Compute `signing_hash = BLAKE3(u16_le(11) || "kit.commit\x00" || signing_bytes)`.
4. Parse `signer` as an Ed25519 public key. Invalid point → verify fails.
5. `Ed25519.verify(signer, signing_hash, C.signature)`. Any failure →
   verify fails.

A verifier MUST NOT accept a signature merely because the `Identity
author` field's payload matches the `signer` public key. Those are two
independent fields. Identity is an attribution claim; `signer` is the
verification key. Pairing is adapter/application policy, not a core
invariant.

### 6.1 Trust binding (application policy)

The algorithm above proves only that `signer` produced `C.signature` &mdash;
it says nothing about whether `signer` is a key the caller has any
reason to accept. `kit verify <rev>` implements exactly the five steps
above and nothing more: a signature from a freshly generated,
never-seen-before key verifies identically to one from a key the caller
actually trusts.

`kit verify --trusted` (and the equivalent `--trust-roots <path>`
form) is the shipped instance of the "application policy" this section
defers to: it runs the algorithm above unchanged, then additionally
looks up `signer` in a caller-supplied trust-roots registry (the same
`[[trust_root]]` TOML format `kit verify-attest` reads, managed via
`kit trust add/list/remove`) and fails closed &mdash; a nonzero exit, distinct
from a bad-signature failure &mdash; when `signer` is not a registered
Ed25519 key. See `rust/crates/kit-bin/src/commands/verify.rs` and
`docs/THREAT-MODEL.md` §5.


---

## 7. Key file format

```
Path:           caller-provided; the convention is .kit/keys/default.key
Contents:       raw 32 bytes (Ed25519 SEED — NOT expanded secret key)
File mode:      0600 (mandatory on POSIX)
Parent-dir mode: 0700 (mandatory on POSIX)
```

The seed is passed to the Ed25519 deterministic key-pair constructor
to recover `(public_key, secret_key)` on load. No PEM, no DER, no
password wrapping in v1.

### 7.1 Write contract

Writers MUST use the following crash-atomic sequence on POSIX:

1. Ensure the parent directory exists at mode 0700. Refuse if any
   ancestor (up to three levels) is a symlink → `KeyPathIsSymlink`.
2. Open a sibling temp file (`.<file>.tmp.<pid>`) with
   `O_CREAT | O_EXCL | O_NOFOLLOW` and mode 0600. `O_EXCL` defeats a
   pre-created symlink at the tmp name.
3. Write the 32-byte seed, `fsync` the file.
4. `rename(2)` the tmp file to the final path. Atomic on the same
   filesystem; replaces any existing key.
5. `fsync` the parent directory so the rename itself is durable.

A `save_raw_32_create_new` variant exists for keygen flows that MUST
NOT clobber an existing key; it returns `Ok(false)` if the destination
already exists.

### 7.2 Load contract

Loaders MUST enforce on POSIX:

- Open with `O_NOFOLLOW`. ELOOP → `KeyPathIsSymlink(path)`.
- Reject if any of the three ancestor directories is a symlink →
  `KeyPathIsSymlink(dir)`.
- `fstat` the open file descriptor (not the path &mdash; closes a TOCTOU
  rename(2) window).
- File mode `& 0o077 != 0` → `InsecureKeyPermissions{actual}`.
- File owner uid ≠ process euid → `InsecureKeyOwner{actual, euid}`.
- Immediate parent directory mode `& 0o077 != 0` →
  `InsecureKeyDir{actual}`.
- File length ≠ 32 bytes (short or long) → `InvalidKeyLength{actual}`.

Any I/O failure surfaces as `KeyIo(String)`. Public-key bytes that do
not decode to a valid Edwards point → `InvalidPublicKey`. RNG failure
during `KeyPair::generate()` → `RngFailure`. Signature verification
failure → `SignatureInvalid` (the underlying Ed25519 layer does not
distinguish among bad-signature, wrong-key, tampered-input, or wrong-
domain).

On non-POSIX hosts the symlink, owner, and mode checks degrade to
no-ops; implementations SHOULD use the host's equivalent access
restriction (for example keep keys under `%USERPROFILE%` so default Windows
ACLs apply).

---

## 8. Signing roles and cross-role separation

One Ed25519 seed MAY sign several kinds of message. This section lists
every Ed25519 signing role in kit, gives the exact message each one
signs, and shows that the messages of two different roles cannot be the
same byte string. `rust/crates/kit-attest/tests/signing_roles.rs` checks
the prefix rules below against the production constants and encoders.
A new role adds a row here and a row to that test.

### 8.1 Role table

Eight roles sign a 32-byte BLAKE3 digest. They are the **digest roles**.
The DSSE role signs the raw PAE. SSH is outside kit.

| Role | Signed message | Length | First bytes of the hashed input (digest roles) or of the message | Key |
|---|---|---|---|---|
| Commit (§3) | `BLAKE3(u16_le(11) ‖ "kit.commit\0" ‖ signing_bytes)` | 32 | `0b 00 "kit.commit\0"` | the signer's key |
| Remix (§4) | `BLAKE3(u16_le(10) ‖ "kit.remix\0" ‖ signing_bytes)` | 32 | `0a 00 "kit.remix\0"` | the signer's key |
| Tag (§4a) | `BLAKE3(u16_le(8) ‖ "kit.tag\0" ‖ signing_bytes)` | 32 | `08 00 "kit.tag\0"` | the signer's key |
| Auth v2 request (SPEC-TRANSPORT-CONNECT §7.1) | `BLAKE3(canonical request)` | 32 | `"kit-write:v2\n"` | the signer's key |
| Write grant (SPEC-WRITE-GRANTS §3, §4) | `BLAKE3(canonical statement)` | 32 | `"kit-write-grant:v1\n"` | the namespace key |
| Epoch statement (SPEC-WRITE-GRANTS §5.1) | `BLAKE3(canonical statement)` | 32 | `"kit-write-epoch:v1\n"` | the namespace key |
| Visibility statement (SPEC-WRITE-GRANTS §9.1) | `BLAKE3(canonical statement)` | 32 | `"kit-repo-visibility:v1\n"` | the namespace key |
| URL token (SPEC-WRITE-GRANTS §9.4) | `BLAKE3(canonical statement)` | 32 | `"kit-url-token:v1\n"` | a dedicated deployment key, never a user key |
| DSSE attestation (SPEC-ATTESTATIONS §2.1, §6.2) | `PAE(payloadType, payload)` | at least 13, variable | `"DSSEv1 "` | the repo key |
| SSH public-key authentication (RFC 4252 §7) | the SSH signed blob | more than 32 | `00 00 00 xx` (the session id length) | an SSH identity, only if the same key is imported there |

Every Ed25519 `verify` call in kit belongs to one of these rows. Other
signature schemes (secp256k1, P-256, WebAuthn) have their own keys and
are outside this section.

Three code paths sign bytes the caller supplies without adding a prefix.
They are not roles. They sign messages built for a row above, and they do
not check which row:

- `KeySigner::sign` (kit-keystore) signs the bytes it receives. The
  keystore commit path passes a commit digest, and the Connect envelope
  path passes an auth v2 digest.
- `ed25519_sign(msg, seed)` (kit-wasm) signs any `msg`.
- `kit-sign-file` signs the `payload` of a `SignRequest` and does not
  require it to be a PAE.

A caller that can reach one of them can obtain a signature over any role's
message, so access to these paths is the trust boundary for the key
(SPEC-EXTERNAL-SIGNER, SPEC-KEYSTORE). Domain separation does not defend
against a signer that is willing to sign any bytes.

### 8.2 Separation argument

Ed25519 binds a signature to the whole message. By the strong
unforgeability of §8.3, a signature made over `M` verifies only over `M`.
Two roles can therefore share a signature only if one message is a valid
message of both roles. The cases below show that this cannot happen.

**Two digest roles.** The two messages are equal only if the two hash
inputs hash to the same digest. The hash inputs differ and neither is a
prefix of the other, because their first bytes differ:

- An object role starts with `u16_le(len)` of its domain, so its first
  byte is `0x0b`, `0x0a` or `0x08` and its second byte is `0x00`. The
  three domains also differ in length and in the first byte after
  `"kit."` (§5).
- An auth v2 request or a statement starts with its domain and a line
  feed. The first byte is `k` (`0x6b`), which no object role uses. Every
  field of these texts is free of the line feed, so the first line is
  exactly the domain. The four statement domains and `kit-write:v2` are
  different strings, and none of them followed by a line feed starts with
  another: `kit-write:v2` and `kit-write-grant:v1` differ at byte 9.

Different inputs that hash to the same digest are a BLAKE3 collision.
**Assumption: BLAKE3 collision resistance.** No other assumption is used
for these roles. The two encodings (length prefix for objects, line feed
for text) are both unambiguous on their own and are separated from each
other by the first byte.

**A digest role and DSSE.** A PAE can be 32 bytes long. For example
`"DSSEv1 1 t 18 "` followed by 18 payload bytes is 32 bytes. The length of
the message therefore does not separate DSSE from the digest roles. A
message of any other length is separated by its length alone, since a
digest role always signs exactly 32 bytes.

For the 32-byte case the digest would have to be a PAE. A PAE starts
with `"DSSEv1 "`, then a decimal length, a space, the type, a space, a
decimal length and a space. A 32-byte PAE has two decimal lengths that
cannot both be one digit, so at least 13 of its 32 bytes are fixed by
the format. A digest that equals such a string needs a match on at least
13 fixed bytes (104 bits) of a hash output the attacker does not control.
**Assumption: BLAKE3 outputs cannot be steered to match 104 chosen bits
cheaply, that is, about 2¹⁰⁴ hash evaluations.** The attacker can search
over the object content, but must then get the victim to sign that
content. Conversely, a PAE signature is useful as a digest-role signature
only if the same 32 bytes are the digest of a well-formed object, which
is the same event.

**A digest role and SSH.** An SSH publickey-authentication blob starts
with the length of the session id, a field of at least 20 bytes, and then
holds the message number and five more fields, so it is longer than 100
bytes and never equals a digest-role message. SSH needs no hash assumption against the
digest roles. An SSH agent, however, signs any bytes a client asks it to
sign. A host that holds a forwarded agent connection can request a
signature over any 32 bytes, which includes the digest of a commit of its
choosing. Separation does not hold against that signer.

**DSSE and SSH.** A PAE starts with `D` (`0x44`) and an SSH blob starts
with `0x00`. The two cannot be equal.

**Same role, different object.** Within one role the domain is fixed, and
the rest of the message encodes every field with a length prefix or a fixed
width (§3 to §4a, SPEC-WRITE-GRANTS §3), so two different objects have
different messages up to a BLAKE3 collision.

### 8.3 Signature properties kit relies on

The §1 predicate checks that `A` and `R` are canonical and not of small
order, that `S < L`, and the cofactored equation. Together with the
unforgeability of Ed25519, the predicate gives the two properties below
for a key that an honest signer generated.

- **EUF-CMA** (existential unforgeability under chosen messages). A
  verifier that accepts a signature only as proof that the key holder
  signed the message needs this. Every row of §8.1 uses it.
- **SUF-CMA** (strong unforgeability under chosen messages). A third party
  who sees a valid signature cannot produce a second, different valid
  signature on the same message. kit needs this where the signature
  bytes are part of an identifier: an object id covers the 64-byte
  signature of a commit, remix or tag, and an attestation id covers the
  signatures of its envelope. Without SUF-CMA a third party could mint
  a second id for the same content. The checks on `R` and `S` in §1
  remove the malleable encodings that would break it.

kit does not claim either property, or any binding of a signature to a
single key, for a public key that an adversary chose.

### 8.4 Key reuse

Nothing in the protocol REQUIRES a single key. Commit, remix, tag, auth v2
and DSSE signing share the repo key by default. The separation argument
above covers those roles and the grant roles. It does not cover a key that
also signs SSH sessions, because kit does not control what an SSH client
or agent signs (§8.2).

A deployment SHOULD keep a separate Ed25519 key for SSH and MUST NOT
assume that sharing one key with SSH is safe. OpenSSH does not accept a
raw seed as an identity. Its `id_ed25519` file uses the `openssh-key-v1`
container (a bcrypt-KDF-wrapped, base64, PEM-bracketed structure), so
using a kit seed for SSH takes an explicit conversion that this document
does not cover. The URL token key is already separate (SPEC-WRITE-GRANTS
§9.4).

---

## 9. Test vectors

1. **Deterministic commit signing bytes**: fixed-input commit with
   `Identity{kind=0x01, len=32, payload=[0xAA;32]}`, zero
   `message_hash`/`content_digest`, timestamp `1_700_000_000`,
   empty message, zero tree_hash, zero parents, signer = identity
   payload. Record the exact `signing_bytes` hex and `signing_hash` hex.
2. **Ed25519 sign over vector 1** using seed `[0x01;32]` → record
   64-byte signature hex.
3. **Verify tampered message**: flip one bit in the message, verify
   MUST fail.
4. **Domain confusion negative test**: attempt to verify a signed commit
   using `"kit.remix\x00"` domain (or any other string). MUST fail.
5. **Zero `message_hash`/`content_digest` do not affect signing hash**:
   two commits differing only in those fields MUST produce identical
   signing_hash bytes.
6. **Remix signing vector**: two-source remix sorted correctly,
   fixed author, fixed message, fixed timestamp. Record hash.
7. **Key file roundtrip**: generate keypair, write seed, re-load,
   sign-then-verify a commit. Round-trip stable.
8. **Tag signing bytes + hash + signature**: annotated tag with
   `target_type=0x03`, fixed ed25519 tagger, non-empty message, fixed
   timestamp; record `tag_signing_bytes`, `signing_hash`, and (signing
   with seed `[0x07;32]`) the 64-byte signature. Pinned under
   `rust/tests/golden/tags/`.
9. **Tag cross-domain negative**: a tag-domain signature MUST NOT verify
   under `"kit.commit\x00"` or `"kit.remix\x00"`, and vice versa.
10. **Role prefixes**: the message prefixes of every role in §8.1 are
    pairwise distinct and none extends another. Checked by
    `rust/crates/kit-attest/tests/signing_roles.rs`.

---

## 10. Non-goals

- No post-quantum signatures in this version. Ed25519 only.
- No signer rotation at the core level. A new `signer` = a new commit.
- No timestamp authority. `timestamp` is self-reported and unverified.
- No partial/threshold signatures.
- No nested signatures (signing a signature) &mdash; always sign a BLAKE3
  digest directly.

---

## 11. Invariants

Properties that MUST hold for every v1 commit/remix/tag signature,
and the mechanism that enforces or detects each.

| Invariant | Enforced by |
|---|---|
| A signature in one domain never verifies in another (commit ↔ remix ↔ tag) | `u16_le(domain.len)` prefix + disjoint domain strings, both preceding any user-controlled byte (§2.1, §5) |
| No message of one signing role is a valid message of another | distinct, prefix-free message prefixes; BLAKE3 collision resistance between digest roles; the DSSE case rests on a 104-bit match (§8.2) |
| Flipping any covered field (tree, parents, author, message, timestamp, signer, tag target/type/name) invalidates the signature | signing bytes cover every identity field of the object (§3, §4, §4a) |
| No field-boundary ambiguity in signing bytes | every variable-length field is length-prefixed (`Identity`, `message_len`, `parent_count`, `name_len`) (§3, §4, §4a) |
| A signature is bound to one object type and schema version | the 6-byte PROLOGUE leads the signing bytes (§3) |
| `message_hash`/`content_digest` annotations never shift the signing hash | both fields excluded from signing bytes (§3) |
| Malleable/non-canonical signatures are rejected identically by all verifiers | the §1 acceptance predicate's checks 1–3 (non-canonical/low-order `R` or `A`, non-canonical or out-of-range `S` all fail) (§1) |
| An annotated-but-unsigned tag never passes verification | all-zero signature fails the Ed25519 predicate of §1 (§4a) |
| The verification key is the object's own `signer` field, never caller-supplied | verifier rebuilds signing bytes and parses `signer` from the object (§6) |
| `author == signer` is never assumed | a verifier MUST NOT accept on identity match; pairing is application policy (§6) |
| Signing hash is deterministic across machines | all count/length/timestamp fields fixed little-endian; domains are compile-time constants (§2, §3) |
| The key file is never world-readable, symlink-swapped, or raced at load (POSIX) | `O_NOFOLLOW`, ancestor-symlink rejection, `fstat` on the open fd, mode/owner/length checks (§7.2) |
| Key writes are crash-atomic and clobber-safe | `O_EXCL` temp create + fsync + `rename(2)` + parent fsync; `create_new` variant for keygen (§7.1) |

Test vectors 3–5 and 9 (§9) pin the tamper-detection and cross-domain
rows as executable negatives. The key-file rows degrade to no-ops on
non-POSIX hosts per §7.2.
