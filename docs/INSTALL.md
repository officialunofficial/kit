# Installing kit

kit ships through three distribution channels. This guide is the
long-form companion to the install section in
[`README.md`](../README.md): pick a channel, follow its steps, then
verify the result.

## Table of contents

1. [Pick your channel](#pick-your-channel)
2. [From source](#from-source)
3. [From GitHub Releases](#from-github-releases)
4. [Hardware signers](#hardware-signers)
5. [Verify your install](#verify-your-install)
6. [Updating](#updating)

## Pick your channel

| Use case                              | Channel                              | Command                                                                                              |
|---------------------------------------|--------------------------------------|------------------------------------------------------------------------------------------------------|
| CLI on a dev machine (Linux/macOS)    | Release archive or `cargo install --git` | `curl kit.storage \| sh` *or* `cargo install --git https://github.com/officialunofficial/kit kit-storage` |
| CLI on a dev machine (Windows)        | Not supported &mdash; use WSL         | run the above `install.sh` (or `cargo install`) inside WSL |
| CI / backend (pin a version)          | Release archive                      | `curl -LO …/releases/download/v<VERSION>/kit-<VERSION>-<target>.tar.gz && tar -xzf kit-<VERSION>-<target>.tar.gz` |
| Library inside another Rust crate     | crates.io (or git dependency)        | `kit-core = "0.5"`                                                                                  |

Pick the leftmost channel that satisfies your constraints &mdash; release
archives are the lowest-overhead path for end users, source builds the
right answer for contributors and air-gapped CI.

## From source

Source builds are the right path for contributors and air-gapped CI. For
everyday CLI use, `cargo install kit-storage` from crates.io (see
[`README.md`](../README.md)) is the shortest route.

**Toolchain.** Rust 1.95, edition 2024, pinned by
[`rust/rust-toolchain.toml`](../rust/rust-toolchain.toml). `rustup` will
auto-install on the first build.

**Install the CLI:**

```sh
cargo install kit-storage                                                   # from crates.io
cargo install --git https://github.com/officialunofficial/kit kit-storage  # from git HEAD
```

Drops `kit` into `~/.cargo/bin/`. Make sure that directory is on your
`PATH`.

**Build modes.** From a checkout of the repository:

```sh
cd rust
cargo build --release        # kit binary → rust/target/release/kit
cargo build                  # debug build, faster compile, slower runtime
cargo test --workspace       # all crates, all tests
```

**Workspace layout.** The Rust tree is one Cargo workspace under
[`rust/`](../rust/). The publishable surface is in `rust/crates/`:

| Crate                                | Role                                                       |
|--------------------------------------|------------------------------------------------------------|
| `kit-core`                          | object model, store, chunker, packs, refs, transports, ops |
| `kit-attest`                        | DSSE plus in-toto v1, multi-algo signers                      |
| `kit-keystore`                      | key vault interface plus backends                             |
| `kit-git-bridge`                    | git import/export bridge                                   |
| `kit-sync`                          | native clone/fetch/pull as a library                       |
| `kit-rpc`                           | shared stdio framing for subprocess protocols              |
| `kit-serve`                         | self-host server: the ssh frame session over a repository  |
| `kit-storage`                           | the `kit` binary                                          |
| `kit-transport-{memory,file,connect,s3,ssh}` | one crate per transport scheme                    |

## From GitHub Releases

The [`release.yml`](../.github/workflows/release.yml) workflow fires on
strict-semver `v*.*.*` tags after verifying the tag is an annotated GPG-signed
tag from an allowlisted release signer and points at a commit reachable from
`main`. It then produces a per-target archive plus signing material:

- `kit-<version>-<target>.tar.gz` &mdash; the archive (binary, licenses,
  README, optional changelog, `share/man/man1/kit.1`, shell completions,
  and per-archive `SHA256SUMS`).
- `kit-<version>-<target>.tar.gz.sha256` &mdash; archive-level checksum.
- `kit-<version>-<target>.tar.gz.cosign.bundle` &mdash; keyless OIDC
  signature (Sigstore Fulcio plus Rekor).

Targets shipped today:

- `aarch64-apple-darwin` (macOS, Apple Silicon)
- `x86_64-apple-darwin` (macOS, Intel)
- `x86_64-unknown-linux-gnu` (Linux x86_64)
- `aarch64-unknown-linux-gnu` (Linux arm64)

Windows is not a supported target (see `docs/INVARIANTS.md`).
Windows users should run kit under WSL, which uses the Linux binary.

**Linux glibc requirement.** The published x86_64 and aarch64 Linux
archives require **glibc 2.39 or newer**.
Check your glibc with `ldd --version | head -1`.

| Release archives | Distributions |
|------------------|---------------|
| Run on | Ubuntu 24.04 or newer, Debian 13 or newer, Fedora 40 or newer |
| Do not run on | Debian 12, Ubuntu 22.04, RHEL/Rocky/Alma 9, Fedora 39 |

On older systems, build from source with `cargo install kit-storage`, which
links against your host's glibc, or use a newer distro/container.

If you want "latest", use the hosted installer:
`curl kit.storage | sh` (Linux/macOS, including WSL; or the explicit
`curl -sSfL https://kit.storage/install.sh | sh`). It resolves the current
tag, fetches the matching archive for your platform, and verifies cosign
by default. Direct release URLs are best when you want a pinned artifact.

> [!NOTE]
> Like any `curl | sh`, the *installer script* is trusted on download
> &mdash; cosign verifies the downloaded **binary**, not the script itself.
> The script is served over HTTPS from `kit.storage`; `https://kit.storage/install.sh`
> and the byte-identical
> [`raw.githubusercontent.com/.../main/install.sh`](https://raw.githubusercontent.com/officialunofficial/kit/main/install.sh)
> are the same file. If you'd rather not trust the hosted script, read it
> first (`curl -sSfL https://kit.storage/install.sh | less`) or skip it and use
> the pinned release plus cosign steps below.

**Download a pinned release for your platform:**

```sh
VERSION=0.5.0
TARGET=aarch64-apple-darwin
curl -LO "https://github.com/officialunofficial/kit/releases/download/v${VERSION}/kit-${VERSION}-${TARGET}.tar.gz"
tar -xzf "kit-${VERSION}-${TARGET}.tar.gz"
```

**Pin a version (recommended for CI):**

```sh
VERSION=0.5.0
TARGET=x86_64-unknown-linux-gnu
TAG="v${VERSION}"
URL="https://github.com/officialunofficial/kit/releases/download/${TAG}/kit-${VERSION}-${TARGET}.tar.gz"
curl -LO "$URL"
tar -xzf "kit-${VERSION}-${TARGET}.tar.gz"
```

**Verify the SHA256.** Each archive ships with a sibling `.sha256`:

```sh
curl -LO "${URL}.sha256"
sha256sum -c "kit-${VERSION}-${TARGET}.tar.gz.sha256" || \
  shasum -a 256 -c "kit-${VERSION}-${TARGET}.tar.gz.sha256"
```

**Verify the cosign signature.** Keyless OIDC, no public key needed.
This is the real authenticity check: it proves the archive was signed by
this repo's `release.yml` workflow on a strict-semver tag. The sibling
`.sha256` file is same-origin defense in depth only.

```sh
curl -LO "${URL}.cosign.bundle"
cosign verify-blob \
  --bundle "kit-${VERSION}-${TARGET}.tar.gz.cosign.bundle" \
  --certificate-identity-regexp '^https://github\.com/officialunofficial/kit/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "kit-${VERSION}-${TARGET}.tar.gz"
```

Full reproducibility, signing, and supply-chain notes live under
[`docs/RELEASE.md`](RELEASE.md).

## Hardware signers

External signers are separate binaries that kit drives over the
[v1 stdio protocol](specs/SPEC-EXTERNAL-SIGNER.md). Wire one up with
`attest.external_signer_path` in `.kit/config`.

This repository ships one signer: `kit-sign-file`. It is a pure software
signer. Use it for development and as the contract test for the protocol.

```sh
git clone https://github.com/officialunofficial/kit
cd kit/rust
cargo install --path crates/kit-sign-file
```

Hardware signers for the Secure Enclave, TPM 2.0 and FIDO2 are not part of
this repository. Any program that speaks the protocol works.

## Verify your install

After any install path, confirm the binary speaks the expected
version:

```sh
$ kit version
kit 0.5.0
```

The exact format `kit <X.Y.Z>\n` (no extra whitespace, no banner) is
contract-tested in
[`.github/workflows/rust.yml`](../.github/workflows/rust.yml) under the
`Version contract` step &mdash; if you ever see anything else, the binary
on your `PATH` is not a release build of this repo.

Run `kit --help` to enumerate subcommands, then jump into the
[CLI reference](CLI.md) or the
[attestation spec](specs/SPEC-ATTESTATIONS.md).

## Updating

If you installed via the install script (`curl kit.storage | sh`), the
binary can update itself:

```sh
kit self update            # update to the latest release
kit self update --check    # just report whether an update exists
kit self update --version v0.5.0   # pin a specific release
```

`self update` downloads the release archive for your platform. It needs
`cosign` on `PATH`, like the install script. It checks the cosign
signature and the sha256 sidecar of the archive before it runs or
installs any of the archive. It refuses a release that lacks either
asset. It has no option to skip the checks. It refuses silent
downgrades, swaps the binary atomically, and rewrites the same
receipts `install.sh` writes, so the two stay interchangeable.

Installs it does **not** manage are refused with pointers to the right
channel instead:

- Homebrew: `brew upgrade kit`
- cargo: `cargo install --locked kit-storage` (or `cargo binstall kit-storage`)

kit never checks for updates in the background; `self update` acts
only when you run it. Full details (receipts, downgrade policy,
environment variables) are in [CLI.md](CLI.md); the release signing
and verification model is in [RELEASE.md](RELEASE.md).
