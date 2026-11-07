# THREAT-MODEL &mdash; kit security boundaries

Status: **Informative**. Companion document to `SECURITY.md` and the
SPEC-* normative specs. Audience: integrators, auditors, and
contributors changing crypto- or key-handling code.

This document states what kit defends, what it does not, and where
the lines are drawn. It is the source of truth a reviewer consults
when a change touches signing, key files, configuration, transport
auth, or the release pipeline.

---

## 1. Scope

kit is a content-addressed VCS with cryptographic signing
(`specs/SPEC-SIGNING.md`) and an attestation subsystem
(`specs/SPEC-ATTESTATIONS.md`, `specs/SPEC-EXTERNAL-SIGNER.md`). kit defends:

- The integrity of objects, packs, refs, and attestations stored in a
  repository &mdash; content addressing plus signed commits and DSSE
  envelopes detect tampering.
- The integrity of signatures produced by `kit commit`, `kit attest`,
  and external signers reachable through the documented protocol.
- The local user's signing keys, to the extent the host kernel and
  filesystem allow.

kit does NOT defend:

- The semantics of an attestation predicate. kit moves bytes; the
  consumer decides what they mean.
- Any property a signer chooses not to provide (for example, timestamping
  unless the signer binds a transparency log entry).
- The host kernel, the user's TTY, the user's shell history, or any
  other process running as the same UID as `kit`.

---

## 2. Trust boundaries

The following boundaries cross trust domains. Code that moves data
across one of these lines MUST treat the input as untrusted.

| Boundary                                     | Trusted side          | Untrusted side                              |
|----------------------------------------------|-----------------------|---------------------------------------------|
| Local user ↔ remote repo author              | the running user      | files inside a cloned tree, including       |
|                                              |                       | the repo's `.kit/config`                   |
| Local user ↔ same-host other UID             | the running user      | other UIDs on the host                      |
| Transport peer (network)                     | the peer the user     | every other host on the path                |
|                                              | configured            |                                             |
| Release pipeline runner                      | the workflow YAML     | any artifact a third-party action emits     |

The "remote repo author" line is load-bearing. A user who runs
`kit clone` accepts the remote's content into the working tree;
they do NOT thereby accept the remote's choice of signing key, key
file path, external signer binary, or trust-roots file.

---

## 3. Attacker models

For each attacker, this document enumerates what kit claims to defend and what
it does not. "Defend" means the design intends a security property
and the implementation has tests or fuzz coverage backing it.

### 3.1 Hostile remote repo author

Attacker controls every file in the cloned tree, including
`.kit/config`, working-tree contents, ref files, packs, and any
attestation envelope they push.

kit defends:

- Object/pack/ref integrity. Tampered bytes fail BLAKE3 verification
  on read; pack readers refuse oversize allocations
  (`specs/SPEC-PACKFILE.md`, `specs/SPEC-DELTA.md`).
- Worktree containment. Symlinks pointing outside the repo root, and
  paths matching `.kit` / `.git` (case-insensitive), are rejected
  during checkout.
- Signature and attestation verification. Trust roots come from the
  user-scoped trust-roots file (§5), not from the cloned repo.
- Choice of key material and external processes. Per §4, a hostile
  `.kit/config` cannot select which key file is read, which binary
  is spawned as an external signer, which keystore backend/key ref is
  used, or what argv an external signer gets.
- Unsigned/forged history on `clone`/`pull`/`fetch`. Every
  commit/remix/tag a fetch newly introduces is run through
  `kit_core::sign::{verify_commit,verify_remix,verify_tag}` &mdash; the same
  check `kit verify <rev>` runs manually &mdash; before the remote-tracking
  ref is published; a structurally invalid or missing signature aborts
  the fetch and leaves local state untouched. This is a
  default, not a guarantee against every key an attacker could produce:
  it proves the signature is well-formed over the object's own bytes,
  not that the signing key is one the user trusts (no trust-root /
  authorized-signer binding exists yet). Opt-out is
  explicit and user-scoped only (`--no-verify-signatures` / the
  user-scoped `pull.require_signed = false` config, never settable from
  a cloned repo's own `.kit/config` &mdash; see §4).

kit does NOT defend:

- The semantic content of a verified attestation. A predicate that
  says "this commit is safe to deploy" is only as strong as the
  signer's policy.
- A user who manually runs `kit config attest.external_signer_path
  /tmp/evil` after cloning. Local choice is the user's responsibility.

### 3.1a Hostile git upstream (`git-bridge` import)

Attacker controls a git repository that the user imports or fetches
with `kit git import`/`fetch`/`pull` (feature `git-bridge`): every
object byte, ref name, tag chain, and the transport-level ref
advertisement.

kit defends:

- Parser containment. Upstream bytes are read through a hardened
  parser layer (`gitparse`, fuzzed: commit/tag/tree targets) behind a
  `git cat-file --batch` subprocess; header blocks are size-capped,
  tag chains depth-capped (16), trees depth-capped (128).
- A refusal matrix instead of best-effort coercion. Gitlinks
  (submodules), unknown tree modes, duplicate/illegal tree entry
  names, negative or overflowing timestamps, oversized author
  payloads, and kit-illegal ref names refuse per-ref with a warning
  &mdash; a hostile object cannot silently produce a misleading kit twin
  (SPEC-GIT-IMPORT §3).
- Translation provenance. Every translated commit/tag is signed by
  the local IMPORT key, original raw bytes are retained
  sha1-addressed under `.kit/git/<name>/raw/` as audit evidence, and
  each imported head gets a `git-import/v1` attestation binding the
  git commit id, remote identity, and kit twin. For a local source
  the attestation names the fixed string `local`, not a path.
  `kit git verify` re-checks all of it offline.
- Tracking-ref containment. Fetches only move
  `refs/remotes/<name>/*` (plus tags); upstream force-pushes rewind
  tracking refs with a loud warning and never touch local branches.
- Accidental-overwrite guards on the way back. The origin guard
  refuses plain export toward any recorded import source, so a
  hostile (or merely confused) flow cannot replace an upstream with a
  disconnected re-translation that passes its push lease
  (SPEC-GIT-BRIDGE §14.2).

kit does NOT defend:

- The semantic content of imported history. The import signature
  means "this is a faithful translation of those git bytes", not
  "those bytes are good". A hostile upstream's malicious source code
  imports faithfully.
- SHA-1 strength beyond its locator role. Object identity inside
  kit is BLAKE3; sha1 is a locator for the git side. Fork-audit
  byte-checks (re-derivation plus raw-bytes hashing) detect a swapped
  object for everything they check; sha1 collisions elsewhere are
  out of scope (SPEC-GIT-BRIDGE §14.3).
- A user who shares the import key with an untrusted party &mdash; the
  designated-importer model (SPEC-GIT-IMPORT §4) makes that key the
  root of the imported history's authenticity.

### 3.2 Local same-host attacker, different UID

Attacker has a shell on the same host under a different UID.

kit defends:

- Key file confidentiality at the filesystem layer. Key files are
  mode `0600`, owner-checked against the running euid, and opened
  with `O_NOFOLLOW` so a symlink planted by another UID cannot
  redirect reads. The parent directory is created `0700` and its
  ownership is checked.

kit does NOT defend against:

- A different-UID attacker who can read `/proc/<kit-pid>/mem` (for example,
  Linux without `kernel.yama.ptrace_scope = 1`).

### 3.3 Local same-host attacker who later gains code execution as the user

Attacker runs as the same UID as `kit`, either by tricking the user
into running their code or by exploiting an unrelated process.

kit does NOT defend against this case. Once an attacker runs as the
same UID, they can read the key file, spawn arbitrary external
signers, edit `.kit/config`, and so on. kit's threat model assumes
the local UID is trusted.

The mitigations in §4 and §5 are about preventing a *remote* repo
from escalating into this position via on-disk config.

### 3.4 MITM on SSH or HTTPS transport

Attacker is on the network path between the client and the remote.

kit defends:

- HTTPS &mdash; native Connect uses bundled Mozilla roots, augmented by
  certificates explicitly selected through `KIT_SSL_CA_FILE` or the
  user-scoped `http.sslCAInfo`. Certificate-chain and hostname verification stay enabled.
  Browser clients use browser-managed trust.
- SSH &mdash; via the user's `ssh(1)` configuration (see
  `SSH-SECURITY.md`). kit does not implement its own SSH. A
  per-repo `ssh.user_known_hosts_file` and `ssh.identity_file`
  scoped to user config (§4) let a careful user pin trust without
  affecting other SSH sessions.

kit does NOT defend:

- A user who disables host-key checking at the OpenSSH layer.
- A user who pins a known-bad CA in their system trust store.

### 3.5 Compromised release pipeline runner

Attacker has code execution on the GitHub Actions runner that
produces release artifacts.

kit defends:

- A best-effort reproducible build (`docs/RELEASE.md`). A third party can
  rebuild the tag and compare hashes. A CI job builds the Linux binary twice
  in two directories and compares the hashes. That job proves the build does
  not depend on the path. It does not prove a match with the published
  binary, and the result is not guaranteed to match.
- Provenance via cosign keyless signatures and CycloneDX SBOM
  (`docs/RELEASE.md`).
- Pinning third-party actions by SHA so a compromised tag cannot
  silently swap an action's code.

kit does NOT defend:

- A compromise of the GitHub Actions OIDC issuer or Sigstore root.
  Defense is transitive.

### 3.6 Hostile download path for the installer

Attacker controls the network path or the host that serves release
archives. The attacker does not control the host that serves `install.sh`.

`install.sh` defends:

- Authenticity of the archive. The script requires `cosign` and verifies the
  archive against its `.cosign.bundle`. The pinned certificate identity is the
  `release.yml` workflow of `officialunofficial/kit` at the exact tag being installed.
  A valid signature for any other tag fails the check.
  The pinned issuer is the GitHub Actions OIDC issuer. The script exits when
  `cosign` or the bundle is missing. Only `--insecure-skip-cosign` or
  `KIT_SKIP_COSIGN=1` turns this off.
- Integrity of the archive. The script checks the SHA256 sum after the cosign
  check. The sum comes from the same origin as the archive, so it detects
  corruption only.
- Silent downgrade. The script records the installed tag in two files. It
  refuses a downgrade through "latest". It refuses to run when the two files
  disagree.
- A replaced binary. The script refuses an install directory that is group or
  world writable. It installs with an atomic rename.

`install.sh` does NOT defend:

- A compromise of the host that serves `install.sh`. The user trusts the
  script on download. Cosign verifies the binary, not the script. A user who
  needs more reads the script first, or downloads a pinned archive and
  verifies it by hand (`docs/INSTALL.md`).
- A compromise of the release workflow or of the Sigstore roots (see 3.5).

---

## 4. Configuration scope split

kit reads two configuration files. Their scope is partitioned by
attacker model: a hostile clone can write `<repo>/.kit/config` but
it cannot write the user-scoped file at
`$XDG_CONFIG_HOME/kit/config` (`~/.config/kit/config` by default).

Security-sensitive keys &mdash; anything that selects a key path or an
external process &mdash; live only in user scope. A repo config that
attempts to set them is rejected with a warning; the value is
ignored.

| Key                                 | Scope     | Rationale                                                 |
|-------------------------------------|-----------|-----------------------------------------------------------|
| `signer`                            | **User**  | Selects raw-file vs keystore commit signing.              |
| `key.backend`                       | **User**  | Selects the keystore backend family.                      |
| `key.default_ref`                   | **User**  | Selects a private signing key reference.                  |
| `key.ed25519_ref`                   | **User**  | Selects the Ed25519 private signing key reference.        |
| `key.secp256k1_ref`                 | **User**  | Selects the secp256k1 private signing key reference.      |
| `key.p256_ref`                      | **User**  | Selects the P-256 private signing key reference.          |
| `signing_key`                       | **User**  | Selects which key file is read for commit signing.        |
| `attest.signer`                     | **User**  | Selects `repo-key` / `external` / `keystore`.             |
| `attest.default_algorithm`          | **User**  | Selects the attestation signing algorithm.                |
| `attest.external_signer_path`       | **User**  | Selects which binary is spawned as a signer.              |
| `attest.external_signer_args`       | **User**  | Argv for the signer subprocess.                           |
| `attest.secp256k1_key_path`         | **User**  | Selects which secp256k1 key file is read.                 |
| `attest.p256_key_path`              | **User**  | Selects which P-256 key file is read.                     |
| `ssh.strict_host_key_checking`      | **User**  | Could weaken host-key verification.                       |
| `ssh.user_known_hosts_file`         | **User**  | Selects which file is the source of trust.                |
| `ssh.identity_file`                 | **User**  | Selects which private key SSH presents.                   |
| `user.identity`                     | **User**  | Author identity; cannot be repo-selected for signed data. |
| `pull.require_signed`               | **User**  | Disables post-fetch signature verification (§3.1).  |
| `default_branch`                    | Repo      | UX default. No security weight.                           |
| `remote_endpoint`                   | Repo      | Address; trust is on the user's transport config.         |
| `remote_bucket`                     | Repo      | Address.                                                  |
| `remote_type`                       | Repo      | Dispatch hint to the transport layer.                     |

Repo-safe keys are applied after the user file and may override user
defaults. The security fence is narrower and stricter: private-key,
signer, executable, trust-root, and host-key selectors are user-only
and are ignored when they appear in repo config.

The per-key classification, the read-site fence, the runtime credential
gate on `remote_endpoint`, and the rules for adding a new config key
are codified in `docs/specs/SPEC-CONFIG-SECURITY.md`. That spec is the
authoritative reference when reviewing a change that touches
`libkit/src/config.rs` or a transport that consumes a
config-derived endpoint, key path, or credential.

`remote_endpoint`, `remote_bucket`, and `remote_type` are repo-safe
to *read* (a clone needs to be able to nominate a default mirror),
but `kit push`, `kit pull`, and `kit fetch` will refuse to attach
ambient `KIT_API_TOKEN` or `KIT_S3_*` credentials to a
repo-configured endpoint unless the user has explicitly listed that
endpoint in user-scoped `trusted_remote_endpoint`. This closes the
hostile-clone credential-exfiltration channel without breaking safe portable defaults for unauthenticated mirrors
and SSH-bearing remotes.

The gate is enforced at a single transport-dispatch choke point
(`remote_dispatch::open_trusted`), which runs the per-endpoint check
*before* it constructs any credential-bearing transport. The check is
keyed on the **resolved endpoint plus its provenance** &mdash; `repo_chosen`
(selected by repo-scoped config: the flat `remote_endpoint` or a
`remote.<name>.url` entry) versus user-chosen (user-scoped config or an
explicit CLI argument) &mdash; never on a remote *name*. This means the same
fence applies uniformly whether the credential-bearing endpoint comes
from the single-remote field or from a named remote: a hostile
clone cannot smuggle ambient credentials to a new host by hiding the
endpoint behind a named remote, and a user-chosen endpoint with the
user's own credentials is never second-guessed. Unauthenticated and
SSH/file flows carry no ambient HTTP/S3 credentials and pass the gate
unchanged.

---

## 5. Trust-roots scope

`kit verify-attest` and `kit verify --trusted` both load
trust roots from `$XDG_CONFIG_HOME/kit/trust-roots.toml` by default.
The path is **not** repo-local for the same reason as §4: a hostile
clone must not choose its own verifier. `kit trust add/list/remove`
manages the same file.

A user can override the path on the command line (`--trust-roots
<path>`) for ad-hoc verification, but the override is per-invocation;
there is no repo config knob that sets it. Both commands additionally
refuse an in-repo trust-roots path unless `--trust-roots` was passed
explicitly (`warn_if_unsafe_trust_roots` in
`rust/crates/kit-bin/src/commands/trust_roots.rs`) &mdash; a hostile clone
that ships `.kit/trust-roots.toml` listing attacker keys cannot get it
selected implicitly.

Without `--trusted`, `kit verify` proves only that the object's
embedded `signer` produced its signature &mdash; it does not consult trust
roots at all (SPEC-SIGNING §6.1). A signature from an unlisted,
attacker-controlled key is indistinguishable from a trusted one unless
the caller opts into `--trusted`. `kit clone`/`pull`/`fetch` run the
same check by default (§3.1): they verify each signature against its
embedded `signer`, not against trust roots.

---

## 6. Key file format and protections

| Property                | Value                                                            |
|-------------------------|------------------------------------------------------------------|
| Format                  | raw 32-byte Ed25519 seed (no PEM, no DER, no password wrap in v1) |
| Permissions             | mode `0600`, MUST be set on creation                              |
| Owner                   | euid of the running process; mismatch is a hard failure           |
| Open flag               | `O_NOFOLLOW` &mdash; symlink in the path is a hard failure              |
| Parent directory        | `0700`, owner-checked                                             |
| Write strategy          | tempfile in same directory, fsync, atomic rename, fsync of parent |
| Zeroization             | seed buffers scrubbed at generation and file-I/O boundaries       |

`KeyPair::generate` scrubs its local seed buffer after constructing the
keypair. `KeyPair::from_seed` takes `[u8;32]`; callers that own long-lived
secret buffers must use a zeroizing owner before and after the call.

The same protections apply to the secp256k1 and P-256 key files
selected via `attest.secp256k1_key_path` and `attest.p256_key_path`.

### 6.1 Keystore backends

User-scoped software, macOS Keychain, and Linux Secret Service backends are
selected by `kit key ...`,
`signer = keystore`, and `attest.signer = keystore`.

Security assumptions:

- Keystores are user-scoped, not repo-scoped. On Unix-like systems the software
  default root is `$XDG_DATA_HOME/kit/keys/`, falling back to
  `~/.local/share/kit/keys/`; `software-raw` persists under a raw-specific
  subtree.
- Keystore selectors (`signer`, `key.backend`, and every `key.*_ref`) are
  user-scoped. A hostile repo cannot select a backend, label, key reference, or
  signing mode.
- `software:<label>` stores encrypted-at-rest software records. It protects
  against offline disk/backup disclosure to the extent the local OS-protected
  envelope material remains unavailable to the attacker. It does not protect
  against malware running as the user. Production `kit-bin` builds enable the
  target OS protector features; the `kit-keystore` library keeps default
  features empty for lean builds and tests.
- `software-raw:<label>` is the explicit raw-file backend. It
  keeps deterministic raw-key behavior for tests and is not the secure
  default.
- Linux Secret Service and macOS Keychain store extractable 32-byte signing
  secrets behind their
  platform protection boundary. They do not claim hardware binding,
  non-extractability, or user presence unless a future implementation changes
  the storage primitive and capability report together.
- Linux Secret Service is a desktop/session backend and may fail when no D-Bus
  service is available or the session is locked. The encrypted `software`
  backend selects Secret Service only when a desktop session is detected and
  the protector opens cleanly. Errors fail closed. No headless Linux protector
  is implemented.
- `systemd-creds` and YubiKey are reserved backend names. Opening either returns
  `BackendUnavailable`; neither stores keys nor signs. Hardware binding,
  OpenPGP/PIV slot discovery, PIN/touch handling, and FIDO2/CTAP label routing
  are not implemented in these backends. WebAuthn assertions use the external
  signer path, whose protocol carries the full assertion metadata.
- Signing commands never auto-generate keystore keys. Users must run
  `kit key generate` or `kit key import` explicitly.

Keystore non-goals in V1:

- Protection against malware or another process already running as the same
  UID. Such an attacker can request signatures from unlocked software/OS
  backends or read extractable secrets from software/raw/platform stores.
- Side-channel resistance beyond the underlying crypto/hardware libraries.

---

## 7. Out of scope

The following are explicitly out of scope. kit makes no claim and
takes no defensive posture against them.

- Compromise of the host kernel, CPU microcode, or RAM (cold-boot,
  Rowhammer, side-channel attacks).
- An attacker with `root` or `Administrator` on the host.
- A multi-user host where `/proc/<pid>/mem` is readable by a
  non-`root` user. On Linux, set
  `kernel.yama.ptrace_scope = 1` (or stricter) before relying on
  kit's key-file protections.
- Recovery from a compromised signing key. There is no onchain or
  in-band revocation; the user's recourse is to publish a new key
  and re-sign forward history.
- A `.kit/` directory served from a network filesystem (NFS, SMB/CIFS,
  or most FUSE-backed network mounts). Every fail-closed exclusion
  guarantee that depends on `kit-core::repo_lock` &mdash; including
  `SPEC-GC.md`'s GC-vs-writer guarantee and every lock in
  `SPEC-CONCURRENCY.md`'s inventory &mdash; assumes `flock`/`fcntl` advisory
  locking is coherent across all lock holders. That assumption holds on
  a local filesystem; it is **not guaranteed** on NFS (locking is
  commonly offloaded to an absent or inconsistent `rpc.statd`/NLM side
  channel under NFSv3, and even NFSv4's in-protocol locking depends on
  server/client support kit does not verify) or on SMB/CIFS. kit
  performs no detection of the underlying filesystem type and has no
  fallback locking strategy. Repositories that must be shared across
  hosts should use one of kit's network transports
  (`docs/specs/SPEC-TRANSPORT.md`) instead of a shared network-mounted
  `.kit/` directory. See `rust/crates/kit-core/src/repo_lock.rs`'s
  module doc for the full caveat.

---

## 8. Verification gates

The following tests, fuzz targets, and CI gates keep this
document honest. A change that weakens any of these requires a
matching update here.

- Golden vectors at `rust/tests/golden/` pin signing-byte and
  signing-hash shapes (`specs/SPEC-SIGNING.md` §3, `specs/SPEC-ATTESTATIONS.md` §4).
- `kit-keystore` golden vectors pin deterministic imported-key behavior for
  explicit `software-raw` Ed25519, secp256k1, and P-256 signing, while unit
  storage tests assert that `software` writes encrypted records rather than raw
  seeds.
- Keystore capability tests assert that each backend advertises only supported
  algorithms, export/import/listing, user-presence, device-bound, and
  non-extractability properties.
- `cargo fuzz` targets cover the parsers of untrusted input,
  among them delta decode, the pack reader, the object deserializer, the
  encrypted software key record parser, and the disclosure, closure and
  span verifiers (`docs/FUZZ.md` lists each target).
- Integration tests assert that a hostile `<repo>/.kit/config`
  cannot set any user-scoped key (warning plus ignored). Per-key
  coverage lives in `rust/crates/kit-bin/tests/repo_config_forbidden_keys.rs`,
  and the in-process meta-test
  `every_forbidden_key_is_actually_dropped_from_repo_scope` iterates
  the entire `REPO_FORBIDDEN_KEYS` list against a sentinel value.
  The exact stderr warning shape is pinned by an `insta` snapshot.
- Integration tests assert key-file owner / mode / `O_NOFOLLOW`
  behavior and the atomic-write contract.
- CI matrix: `cargo fmt --check`, `cargo clippy --all-targets --
  -D warnings`, `cargo test --workspace --locked`, keystore backend feature
  jobs for Linux/macOS with opt-in live native-backend roundtrips,
  `cargo deny`, double-build hash comparison, `kit version` byte-exact
  assertion.
  Windows is not a supported build/test/release target (see
  `docs/INVARIANTS.md`).

---

## 9. Reporting issues

See [`SECURITY.md`](../SECURITY.md). Use GitHub Security Advisories.
Do not file public issues for vulnerabilities.
