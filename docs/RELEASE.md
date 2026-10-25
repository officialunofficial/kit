# Cutting a kit release

This is the single release runbook. It covers the checklist,
signing and verification, supply-chain policy, reproducibility and
crates.io publishing.

Contents:

- [What gets published](#what-gets-published)
- [Pre-release checklist](#pre-release-checklist)
- [Cutting a release](#cutting-a-release)
- [Publishing to crates.io](#publishing-to-cratesio)
- [Signing and verification](#signing-and-verification)
- [Supply-chain policy](#supply-chain-policy)
- [Reproducibility](#reproducibility)
- [Required GitHub Actions secrets and variables](#required-github-actions-secrets-and-variables)

## What gets published

A single `vX.Y.Z` tag drives the binary release through
[`.github/workflows/release.yml`](../.github/workflows/release.yml).
A maintainer publishes the crates to crates.io by hand from the same tag.

Both steps use the same signed tag. Before `release.yml` publishes anything,
it verifies that the tag is strict semver, annotated, GPG-signed by an
allowlisted release fingerprint, and points at a commit reachable from
`origin/main`. It then produces:

1. **GitHub Release** with native `kit` binaries for four
   targets:
   - `aarch64-apple-darwin`
   - `x86_64-apple-darwin`
   - `aarch64-unknown-linux-gnu`
   - `x86_64-unknown-linux-gnu`

   Windows is not a supported target (see `docs/INVARIANTS.md`).
   Windows users should run kit under WSL, which uses the Linux binary.

   Each target ships one archive, `kit-X.Y.Z-<target>.tar.gz`: the `kit`
   binary, licenses, README, optional changelog, `share/man/man1/kit.1`, and
   shell completions under `share/completions/`.

   Each archive is cosign-signed (keyless OIDC, Rekor logged) and ships
   alongside per-archive `.sig`/`.crt`/`.cosign.bundle`, an aggregate
   `SHA256SUMS` (also cosign-signed), a CycloneDX `sbom.cdx.json`, a
   `THIRD-PARTY-NOTICES` file, and a standards-based SLSA build provenance
   attestation (`actions/attest-build-provenance`), verifiable with `gh
   attestation verify` or `slsa-verifier` in addition to cosign. The SBOM
   and the notices cover the whole workspace.

   The `kit` binary is built with `-p kit-storage --bin kit`: a bare `--bin
   kit` selects every workspace member, and cargo unifies features across
   every selected package, so it would compile the shipped CLI with other
   members' features. After the build,
   [`scripts/check-release-artifact-features.sh`](../scripts/check-release-artifact-features.sh)
   reads cargo's compiler-artifact messages and scans the stripped binary.
   `kit` must compile only packages listed in
   [`scripts/release/kit-packages.golden`](../scripts/release/kit-packages.golden),
   no server-only package or feature, tower-http only with reqwest's
   features, no `SQLite`, and no test seam. A new CLI dependency fails the check until
   `scripts/check-release-artifact-features.sh --update-golden` is run and
   the golden diff is committed with the change that brought it in.

   [`release-artifact-check.yml`](../.github/workflows/release-artifact-check.yml)
   runs the same build and check for `x86_64-unknown-linux-gnu` on PRs
   to `main` (and pushes to it), and checks the golden list is current, so
   drift shows up before a tag rather than at it.

2. **crates.io** &mdash; every workspace crate without `publish = false`, in
   dependency order. See [Publishing to crates.io](#publishing-to-cratesio).

## Pre-release checklist

> **Homebrew tap status: provisioned, no formula yet.** The
> `officialunofficial/homebrew-tap` repository exists and is public, but holds
> only LICENSE plus README &mdash; there is no `Formula/` directory, so `brew install`
> fails until a formula is pushed. The Distribution step that targets the tap
> is live and expected to be performed at the next release.

Run top to bottom. Do not skip steps.

### Pre-tag

- [ ] `main` is green in CI (build plus test).
- [ ] `cd rust && cargo test --workspace` passes on a fresh clone.
- [ ] The release build passes for each release target (the command
      `release.yml` runs): `cargo build --release --locked -p kit-storage --bin kit`:
  - [ ] `--target=aarch64-apple-darwin`
  - [ ] `--target=x86_64-apple-darwin`
  - [ ] `--target=x86_64-unknown-linux-gnu`
  - [ ] `--target=aarch64-unknown-linux-gnu`
- [ ] `[workspace.package].version` in `rust/Cargo.toml` is bumped to a version
      **not already published** (crates.io versions are immutable &mdash; a re-publish
      of an existing version fails the whole `cargo publish` run).
- [ ] `CHANGELOG.md` has an entry for this version; move items from
      `## [Unreleased]` into `## [X.Y.Z] - YYYY-MM-DD`.
- [ ] Version bumped wherever it is hard-coded: README install snippets,
      `docs/INSTALL.md` (three sites: two
      `VERSION=` snippets and the expected `kit version` output), and the
      `vX.Y.Z` examples in `install.sh` usage text.
- [ ] [Signing and verification](#signing-and-verification) and
      [Reproducibility](#reproducibility) still accurate for this release.
- [ ] `KIT_RELEASE_GPG_FINGERPRINTS` repo/org Actions variable contains the
      release tag signing key fingerprint.
- [ ] The release tag signing public key is published to `keys.openpgp.org` or
      `keyserver.ubuntu.com` so the workflow can import it before
      `git verify-tag`.
- [ ] `SECURITY.md` disclosure contact confirmed reachable.
- [ ] Manually dispatch `rust.yml`'s `keystore-backends` job
      (`gh workflow run rust.yml --ref main`) and confirm both legs
      (Linux Secret Service+systemd-creds+YubiKey, macOS Keychain+YubiKey)
      succeed. It stays `workflow_dispatch`-only (2-OS matrix cost) and is
      not exercised by any automatic trigger, so this is the only
      per-release check that native keystore backends still work.

### Wait for the release workflows

- [ ] `release.yml` succeeded through `validate-release-tag` and all four
      platform builds.
- [ ] GitHub Release created as a non-draft.
- [ ] Archives present:
      `kit-X.Y.Z-aarch64-apple-darwin.tar.gz`,
      `kit-X.Y.Z-x86_64-apple-darwin.tar.gz`,
      `kit-X.Y.Z-aarch64-unknown-linux-gnu.tar.gz`, and
      `kit-X.Y.Z-x86_64-unknown-linux-gnu.tar.gz`.
- [ ] `sbom.cdx.json` present.
- [ ] `THIRD-PARTY-NOTICES` present.
- [ ] `SHA256SUMS`, `SHA256SUMS.sig`, `SHA256SUMS.crt`,
      `SHA256SUMS.cosign.bundle` present.
- [ ] Per-archive `.cosign.bundle` present for every archive.
- [ ] `kit-X.Y.Z.provenance.jsonl` (SLSA build provenance) present, and
      `gh attestation verify <archive> --repo officialunofficial/kit`
      succeeds for at least one archive.

### Smoke test

On at least one Linux box and one macOS box, download the archive for your
platform, then run the mechanized checklist below instead of the steps by
hand:

```sh
# Linux / macOS
scripts/release-smoke.sh --archive kit-X.Y.Z-<target>.tar.gz --version X.Y.Z
```

The script covers every item below in one pass: cosign signature, the
`SHA256SUMS` entry, `kit version` against the tag, the bundled man page
and completions, a basic `kit init` → `kit keygen` → add a file →
`kit commit` flow. It's the
same script used for a pre-flight dry run against a locally packaged
archive before tagging (missing sidecars like the cosign bundle are
skipped with a warning, not a failure, in that case) &mdash; this
checklist is the spec of record the script implements, so if the two ever
disagree, fix the script:

- [ ] Download the archive for your platform.
- [ ] Verify the cosign signature (see [below](#verify-a-downloaded-archive)).
- [ ] Verify `SHA256SUMS` matches the archive.
- [ ] Extract and run `./kit-X.Y.Z-<target>/kit version` &mdash; version
      string matches the tag.
- [ ] Extracted archive contains `share/man/man1/kit.1`,
      `share/completions/kit.bash`, `share/completions/_kit`, and
      `share/completions/kit.fish`.
- [ ] Basic flow: `kit init` → add a file → `kit commit`.

### Distribution and announce

- [ ] In `officialunofficial/homebrew-tap`, write `Formula/kit.rb` with the new
      version and the archive hashes from release `SHA256SUMS`.
- [ ] Release notes reviewed (auto-generated by `softprops/action-gh-release`
      plus the signing snippet).
- [ ] Pin the release in the repo sidebar; post in relevant channels.
- [ ] Once the Homebrew step above is done, dispatch
      [`release-verify.yml`](../.github/workflows/release-verify.yml)
      (`gh workflow run release-verify.yml -f version=X.Y.Z`) to check
      every distribution channel end to end in an isolated environment —
      `cargo install`, `cargo binstall`, the curl-pipe install
      script (Debian/Ubuntu/Fedora), and Homebrew. Not a substitute for the
      smoke test above (which verifies the archive itself); this verifies
      every OTHER way a user actually gets `kit` onto their machine.

### Post-release

- [ ] Verify the release-prep PR left a fresh `## [Unreleased]` heading at
      the top of `CHANGELOG.md`.
- [ ] After a crate's first publish, add co-owners:
      `cargo owner --add <maintainer> <crate>` for each maintainer. Confirm
      the owners with `cargo owner --list <crate>`.
- [ ] Record anything the smoke test found, and fix it before the next release.

## Cutting a release

1. Land everything on `main`. Confirm CI is green.
2. Bump `[workspace.package].version` in `rust/Cargo.toml` (to a version not yet
   on crates.io). Update `CHANGELOG.md` (move `Unreleased` items into
   `[X.Y.Z] - YYYY-MM-DD`, leaving a fresh `[Unreleased]` heading above it).
3. Open a release-prep PR, merge it.
4. Tag the merge commit on `main`:
   ```sh
   git tag -s vX.Y.Z -m "kit X.Y.Z"
   git push origin vX.Y.Z
   ```
   Signed, annotated tags only. The signing key fingerprint must be listed in
   the `KIT_RELEASE_GPG_FINGERPRINTS` repository or organization variable and
   its public key must be available from `keys.openpgp.org` or
   `keyserver.ubuntu.com`. Verify the exact fingerprint before pushing:
   ```sh
   git tag -v vX.Y.Z
   ```
   The release workflow rejects lightweight tags, invalid signatures,
   fingerprints not listed in `KIT_RELEASE_GPG_FINGERPRINTS`, tags outside the
   strict `vX.Y.Z[-prerelease]` form, and tag targets not reachable from
   `origin/main`.
5. Watch the workflows. `release.yml` job order is:
   `validate-release-tag` → `build` (× 4 archs) → `sbom` / `third-party-notices` (parallel) →
   `release`.
6. Run the [smoke test](#smoke-test).

## Publishing to crates.io

No workflow in this repository publishes to crates.io. A maintainer checks out
the signed tag and runs `cargo publish --workspace --locked`. The command
publishes every workspace member without `publish = false` to crates.io in
dependency order, waiting for each to index before the next. Before the run,
check that the tag matches the workspace version (`kit-core`'s version in
`rust/Cargo.toml` at the tagged tree).

### What publishes vs. what doesn't

| Publishes to crates.io | Stays off crates.io (`publish = false`) |
|---|---|
| The library crates (`kit-core`, `kit-rpc`, `kit-client`, `kit-sync`, `kit-attest`, `kit-keystore`, `kit-git-bridge`, `kit-serve`, `kit-transport-{file,memory,s3,ssh,connect}`) plus `kit-storage` (so `cargo install kit-storage` works) | `kit-sign-file`, `kit-test-util`, `kit-formal-conformance`, `fuzz`, `benches`. |

The published crates depend only on each other, forming a closed,
dependency-ordered set; `cargo publish --workspace` computes that order and
skips any `publish = false` member.

Notes on the published set:

- **`kit-storage`** &mdash; published so `cargo install kit-storage` installs the `kit`
  binary; it also ships via the signed GitHub Release archives and `cargo
  install --git`. Its library surface is unstable CLI internals, deliberately
  **not** a public API &mdash; kept out of the pre-publish semver gate. Depend on the `kit-*`
  library crates, not on `kit_storage::…`.
- **The crates.io `kit` name** belongs to an unrelated project; the CLI is
  published as **`kit-storage`**. Do not run `cargo install kit`.

### Token

`cargo publish` needs a crates.io API token with the publish-new and
publish-update scopes. The account must own the `kit-*` crates. A token is
required because a brand-new crate cannot use trusted publishing on its first
publish. Keep the token out of the repository.

### Gotchas

- **Immutable versions**: crates.io never lets you overwrite a published
  version. Always bump before tagging; never re-publish an existing version.
- **Partial publish**: if a publish fails mid-train, the crates that landed
  cannot be published again. Run the next attempt with `--exclude` for each
  crate that landed.
- **Native deps**: `cargo publish` builds each crate with **default** features,
  so no `libpcsclite` is needed (`kit-keystore`'s `backend-yubikey` is off by
  default); only `protoc` is required (for
  `kit-rpc`).

## Signing and verification

Every kit release is signed with
[cosign](https://docs.sigstore.dev/cosign/overview/) using **keyless OIDC**: the
signing identity is the GitHub Actions workflow itself
(`.github/workflows/release.yml`), authenticated by GitHub's OIDC provider, and
every signature is recorded in the
[Rekor transparency log](https://docs.sigstore.dev/logging/overview/).

Cosign signatures are keyless and bound to the artifact hash, so a stolen
release signature cannot be reused on any other artifact. The installer
(`install.sh`) enforces this same trust boundary by default.

### Artifacts attached to every release

For each of the four targets, release archives build the production
`kit-storage` target for that platform. The CLI enables the matching keystore
software-protector feature so `software` keys are encrypted at rest on supported
targets without changing the lean default feature set of the `kit-keystore`
library crate.

| File | Purpose |
| --- | --- |
| `kit-X.Y.Z-<triple>.tar.gz` | Binary, licenses, README, manpage, completions. |
| `...sha256` | SHA256 of the archive (convenience). Every archive has the full set of sidecars. |
| `...sig` | Raw cosign signature (base64). |
| `...crt` | Fulcio-issued code-signing certificate. |
| `...cosign.bundle` | Bundle: sig plus cert plus Rekor entry. |

Plus one top-level set for the aggregate:

| File | Purpose |
| --- | --- |
| `SHA256SUMS` | Hashes of every archive plus SBOMs plus notices. |
| `SHA256SUMS.{sig,crt,cosign.bundle}` | Cosign signature of `SHA256SUMS`. |
| `sbom.cdx.json` | CycloneDX SBOM of the release. |
| `THIRD-PARTY-NOTICES` | Consolidated third-party license attribution for the Rust dependency graph, generated by `cargo about generate` (see [`NOTICE`](../NOTICE)). |
| `kit-X.Y.Z.provenance.jsonl` | GitHub-native SLSA build provenance attestation (`actions/attest-build-provenance`) over the archives. Verified with `gh attestation verify` or `slsa-verifier`. |

### Verify a downloaded archive

Install cosign: <https://docs.sigstore.dev/cosign/installation/>. Then:

```sh
VERSION=X.Y.Z
TARGET=aarch64-apple-darwin
ARCHIVE="kit-${VERSION}-${TARGET}.tar.gz"

cosign verify-blob \
  --certificate-identity "https://github.com/officialunofficial/kit/.github/workflows/release.yml@refs/tags/v${VERSION}" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --bundle "${ARCHIVE}.cosign.bundle" \
  "${ARCHIVE}"
```

Expected output: `Verified OK`. The `--certificate-identity` option pins the
signature to the release workflow build of this exact tag; a signature produced by any
other workflow (a fork, a branch build, a locally-run cosign) fails
verification.

The archive's sibling `.sha256` file is not an authenticity signal on its own
because it is served from the same origin as the archive. Treat it as
defense-in-depth after cosign, not instead of it.

### Inspect the Rekor transparency log entry

The `.cosign.bundle` contains a Rekor log index. To view the public entry, add
`--rekor-url "https://rekor.sigstore.dev"` to the `cosign verify-blob` command
above, or search by the archive's sha256 at
<https://search.sigstore.dev/?hash=sha256:DIGEST>.

### Verify the SBOM

The SBOM (`sbom.cdx.json`) is included in the top-level `SHA256SUMS`, which is
itself cosign-signed. The chain is:

1. Verify `SHA256SUMS.cosign.bundle` signs `SHA256SUMS` (cosign).
2. Verify `sbom.cdx.json`'s sha256 matches its entry in `SHA256SUMS`.

```sh
cosign verify-blob \
  --certificate-identity "https://github.com/officialunofficial/kit/.github/workflows/release.yml@refs/tags/v${VERSION}" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --bundle SHA256SUMS.cosign.bundle \
  SHA256SUMS

grep ' sbom.cdx.json$' SHA256SUMS > sbom.cdx.json.sha256
sha256sum -c sbom.cdx.json.sha256 || shasum -a 256 -c sbom.cdx.json.sha256
```

### Verify THIRD-PARTY-NOTICES

`THIRD-PARTY-NOTICES` is generated by `cargo about generate` (config:
`rust/about.toml` plus `rust/about.hbs`) from the `rust` workspace's resolved
dependency graph, and is covered by the same `SHA256SUMS` chain as the SBOM:

```sh
grep ' THIRD-PARTY-NOTICES$' SHA256SUMS > THIRD-PARTY-NOTICES.sha256
sha256sum -c THIRD-PARTY-NOTICES.sha256 || shasum -a 256 -c THIRD-PARTY-NOTICES.sha256
```

`cargo about generate` fails the `third-party-notices` job outright if any
dependency's license isn't in `rust/about.toml`'s `accepted` list &mdash; that list
is kept in lockstep with `rust/deny.toml`'s `[licenses] allow` list (the
license check cargo-deny already runs on every PR via `.github/workflows/rust-security.yml`).
`.github/workflows/third-party-notices.yml` runs the same `cargo about
generate` check on every PR that touches the dependency graph, so an
unapproved license is caught before a release attempt, not during one.

### Verify the SLSA build provenance attestation

Every archive also carries a standard
[SLSA build provenance](https://slsa.dev/spec/v1.0/provenance) attestation,
generated by [`actions/attest-build-provenance`](https://github.com/actions/attest-build-provenance)
and recorded in the Sigstore public-good transparency log. Unlike the cosign
signature above (a kit-specific verification path), this attestation is
checkable with off-the-shelf, standards-aware tooling and requires no
kit-specific parsing:

```sh
gh attestation verify kit-X.Y.Z-<target>.tar.gz --repo officialunofficial/kit
```

or with [`slsa-verifier`](https://github.com/slsa-framework/slsa-verifier):

```sh
slsa-verifier verify-artifact kit-X.Y.Z-<target>.tar.gz \
  --provenance-path kit-X.Y.Z.provenance.jsonl \
  --source-uri github.com/officialunofficial/kit \
  --source-tag vX.Y.Z
```

This is additive: it does not replace the cosign signature, which remains in
place and is independently verified above.

### macOS Gatekeeper

macOS binaries are **not Developer ID-signed and not notarized**. The trust
boundary is the cosign verification above, not Apple notarization. Users on
Ventura+ may see a Gatekeeper warning when launching a freshly-downloaded binary
from Finder. After you verify the archive, either run `kit` from a terminal or
clear quarantine explicitly:

```sh
xattr -d com.apple.quarantine /path/to/kit
```

Notarization is future work: `release.yml` has no notarization step today
(only a placeholder comment). When it is wired, it will authenticate with
`APPLE_ID`, `APPLE_APP_SPECIFIC_PASSWORD`, and `APPLE_TEAM_ID` secrets. If
notarized macOS releases ever ship, the release notes and this document will
say so explicitly.

## Supply-chain policy

kit's supply chain is intentionally narrow. The binary users run traces back to
a small, auditable set of inputs. This section is the contract.

### Current state

- **Rust dependencies:** fully pinned via `Cargo.lock`. Every transitive dep is
  hash-pinned on each release build. The workspace's direct deps are kept
  deliberately small &mdash; see `rust/Cargo.toml` and each crate's `[dependencies]`.
- **System libs:** default release builds link musl (Linux) or the platform C
  runtime (macOS). Optional keystore backend features may use platform services
  (Security.framework, D-Bus Secret Service, PC/SC, `systemd-creds`). These
  are off by default, platform-gated, and fail closed
  when the required service or device is unavailable. The Linux Secret Service
  feature selects the pure-Rust crypto runtime, not OpenSSL. Production
  `kit-storage` builds enable the target-appropriate software protector feature so
  `software:<label>` stores encrypted records by default, while the
  `kit-keystore` library keeps an empty default feature set.
- **Build inputs:** the Rust toolchain (pinned in `rust-toolchain.toml`), the
  source tree at a tagged Git commit, and the `--target=` / profile flags
  documented under [Reproducibility](#reproducibility).

### Adding a Rust dependency

Every new direct dependency added to a workspace `Cargo.toml` must:

1. Be **version-pinned** in `Cargo.toml` and reflected in `Cargo.lock`.
2. Have its source reviewed by **two maintainers** (sign-off in the PR).
3. Have a stated purpose &mdash; what does kit gain, and what would implementing it
   in-tree cost? The default answer should be "implement in-tree"; deps are the
   exception.
4. Be compatible with **MIT OR Apache-2.0**. The CI dependency-review action
   denies GPL/LGPL families when the repo has Dependency Graph enabled and
   `ENABLE_DEPENDENCY_REVIEW=1`.
5. Have a cross-platform build. If the dep breaks on one of the four release
   targets, it doesn't land.

### Keystore backend dependency review

The optional keystore backend and envelope-encryption dependencies
were reviewed for the V1 keystore. All are pinned in `Cargo.toml`, reflected in
`Cargo.lock`, sourced from crates.io, accepted by `cargo deny`, and isolated
from default builds unless listed as always-on.

| Dependency | Use | Gate | License |
|---|---|---|---|
| `chacha20poly1305 = 0.10.1` | XChaCha20-Poly1305 software-key envelope encryption | always-on keystore crypto | Apache-2.0 OR MIT |
| `zeroize = 1.8.2` | Secret-memory clearing | always-on keystore crypto | Apache-2.0 OR MIT |
| `security-framework = 3.7.0` | macOS Keychain bindings | `backend-macos-keychain` (macOS only) | MIT OR Apache-2.0 |
| `keyring-core = 1.0.0` | Shared keyring abstraction | `backend-linux-secret-service` | MIT OR Apache-2.0 |
| `zbus-secret-service-keyring-store = 1.0.0` | Linux Secret Service store | `backend-linux-secret-service` (Linux only; OpenSSL-free) | MIT OR Apache-2.0 |
| `card-backend-pcsc = 0.5.1` | PC/SC card discovery | `backend-yubikey` | MIT OR Apache-2.0 |
| `openpgp-card = 0.6.1` | OpenPGP card protocol | `backend-yubikey` | MIT OR Apache-2.0 |
| `secrecy = 0.10.3` | PIN handling wrappers | `backend-yubikey` | Apache-2.0 OR MIT |
| `der = 0.8.0` | DER parsing for PIV certs | `backend-yubikey` | Apache-2.0 OR MIT |
| `yubikey = 0.9.0-pre.0` | YubiKey PIV discovery plus signing | `backend-yubikey` | BSD-2-Clause |

The `yubikey` prerelease is accepted because V1 PIV support needs mature PIV
APDUs and no stable alternative matched the API; risk is contained by optional
feature gating, existing-key-only support, fail-closed behavior, CI feature
builds, and manual hardware validation. Remaining direct support deps are
exact-pinned (`ed25519-dalek`, `getrandom`, `k256`, `p256`, `sha2`, `thiserror`,
dev-only `tempfile`).

`cargo deny check` finishes with `advisories ok, bans ok, licenses ok, sources
ok`. Remaining warnings are duplicate crate versions from ecosystem splits and
optional YubiKey/RustCrypto prerelease transitive stacks; they stay
warnings, not release blockers, because they introduce no unapproved sources,
yanked crates, or denied licenses. Live OS-native keystore tests are opt-in via
`KIT_RUN_NATIVE_KEYSTORE_TESTS=1`.

### GitHub Actions dependencies

All third-party actions in `.github/workflows/` must be pinned to a major
version tag (`@v4`) or a full SHA. No `@main`, no `@latest`. Trusted publishers:
`actions/*`, `dtolnay/rust-toolchain`, `sigstore/cosign-installer`,
`anchore/sbom-action`, `softprops/action-gh-release`, `ossf/scorecard-action`.
Any new action from an untrusted publisher needs the same two-maintainer review
as a Rust dep.

### Release artifact integrity, SBOM lifecycle, vulnerability response

Every release archive is **hashed** (per-archive `SHA256SUMS`), **signed**
(cosign keyless OIDC, tied to this repo's release workflow identity), **logged**
in the public Rekor transparency log, and **inventoried** in a CycloneDX SBOM.
Package-manager manifests must reference the GitHub Releases archive URL directly
(never a re-hosted copy); the `sha256` in the manifest is the authoritative pin.

A fresh SBOM is generated at release time only (the `sbom` job in
`release.yml`); there is **no** scheduled SBOM regeneration for `main`. The
weekly cadence is `cargo audit` via `rust-security.yml` (Mondays 06:00 UTC),
which sweeps for newly published advisories against the unchanged dependency
tree. Restoring a scheduled SBOM-drift job is an open follow-up. A CVE against
any shipped dep is a P1: patch, test, tag a new release,
open a GitHub Security Advisory citing the CVE, update `CHANGELOG.md` under
`### Security`, and coordinate disclosure via the `SECURITY.md` contact.

## Reproducibility

A kit release binary is a function of a small, pinned set of inputs. If all of
them match, any machine that can run the same Rust toolchain will produce a
byte-identical binary to the one published on GitHub Releases.

### The inputs

1. **Rust toolchain version** &mdash; pinned in `rust-toolchain.toml`; the workflow
   installs it verbatim.
2. **Target triple** &mdash; one of the four release triples, passed as
   `--target=<triple>`.
3. **Build profile** &mdash; `release`.
4. **Source tree hash** &mdash; the Git commit the tag points at; every source file is
   tracked in Git.
5. **Dependency fingerprint** &mdash; `Cargo.lock`, fully pinning every transitive
   dependency. Any `cargo update` is a visible change to that file.

### Reproducing a published binary

```sh
# 1. Clone at the release tag.
git clone --depth 1 --branch vX.Y.Z https://github.com/officialunofficial/kit.git
cd kit/rust
# 2. rustup picks up rust-toolchain.toml on first `cargo` invocation.
# 3. Build for your target with release.yml's command (`-p kit-storage`
#    selects only the CLI; a bare `--bin kit` unifies other members'
#    features and differs).
export RUSTFLAGS="-C codegen-units=1 -C strip=symbols"
TARGET=x86_64-unknown-linux-gnu
cargo build --release --locked --target "$TARGET" -p kit-storage --bin kit
# 4. Hash the binary.
shasum -a 256 "target/$TARGET/release/kit"
# 5. Compare against the SHA256SUMS inside each release archive.
```

If the hashes don't match, treat it as a supply-chain incident: open an issue
with your host OS, `rustc --version`, the sha256 you got, and the expected one.
`diffoscope` on the two binaries usually isolates the culprit.

### CI safety net and what is not guaranteed

There is currently **no** automated reproducibility check: no CI job builds
kit twice and compares the outputs. The manual procedure above is the
verification path. Restoring an automated double-build job is an open
follow-up. A divergence between two builds of the same commit means a
non-deterministic input has crept in (embedded timestamps, random seeds,
absolute paths in debug info, unsorted directory reads) and must be fixed
before the next tag.

Binaries built on your local macOS are not expected to match GitHub's `macos-14`
runner byte-for-byte unless your OS, SDK, and linker versions match. The Linux
x86_64 build is the most reliable reproducibility target for third parties.

## Required GitHub Actions secrets and variables

cosign keyless signing runs on the GitHub OIDC token. No release step needs a
repository secret.

| Variable | Purpose | Required for |
| --- | --- | --- |
| `KIT_RELEASE_GPG_FINGERPRINTS` | Space-separated trusted 40-hex GPG fingerprints allowed to sign release tags (public keys must be on `keys.openpgp.org` or `keyserver.ubuntu.com`) | `release.yml` preflight |
