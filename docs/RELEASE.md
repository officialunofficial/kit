# Cutting a kit release

This is the single release runbook. It covers the checklist,
signing and verification, supply-chain policy, reproducibility, crates.io
publishing and npm publishing.

Contents:

- [What gets published](#what-gets-published)
- [Pre-release checklist](#pre-release-checklist)
- [Cutting a release](#cutting-a-release)
- [The release PR](#the-release-pr)
- [Publishing to crates.io](#publishing-to-cratesio)
- [Publishing to npm](#publishing-to-npm)
- [Signing and verification](#signing-and-verification)
- [Supply-chain policy](#supply-chain-policy)
- [Reproducibility](#reproducibility)
- [Required GitHub Actions secrets and variables](#required-github-actions-secrets-and-variables)

## What gets published

A single signed `vX.Y.Z` tag drives the binary release, registry
publishing, and stable Homebrew updates in
[`.github/workflows/release.yml`](../.github/workflows/release.yml).

Before publishing, the workflow verifies the tag format, the annotation,
the signature against the release fingerprint allowlist, and the tagged
commit's ancestry on `origin/main`. It then publishes the following artifacts.

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

   The `kit` binary is built with `-p kit-bin --bin kit`: a bare `--bin
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

   The `release-artifact-check` step of
   [`cloudbuild/supply.yaml`](../cloudbuild/supply.yaml)
   runs the same build and check for `x86_64-unknown-linux-gnu` on PRs
   to `main` (and pushes to it), and checks the golden list is current, so
   drift shows up before a tag rather than at it.

2. **npm** &mdash; the `kit-wasm` package, published as
   `@officialunofficial/kit-wasm` at the version of the tag. See
   [Publishing to npm](#publishing-to-npm).

3. **crates.io** &mdash; every workspace crate without `publish = false`, in
   dependency order, by the `publish-crates` job. See
   [Publishing to crates.io](#publishing-to-cratesio).

4. **Homebrew** &mdash; for stable releases, `update-homebrew` updates
   `Formula/kit.rb` in `officialunofficial/homebrew-tap` after the GitHub
   Release and both registry jobs succeed. It renders the formula from the
   published release's `SHA256SUMS` and commits it to the tap. The
   `validate-release-tag` job checks tap write access before any build,
   including for prereleases. Both jobs use `HOMEBREW_TAP_TOKEN`.

## Pre-release checklist

Run top to bottom. Do not skip steps.

### Pre-tag

- [ ] `main` is green in CI (build plus test).
- [ ] `cd rust && cargo test --workspace` passes on a fresh clone.
- [ ] The release build passes for each release target (the command
      `release.yml` runs): `cargo build --release --locked -p kit-bin --bin kit`:
  - [ ] `--target=aarch64-apple-darwin`
  - [ ] `--target=x86_64-apple-darwin`
  - [ ] `--target=x86_64-unknown-linux-gnu`
  - [ ] `--target=aarch64-unknown-linux-gnu`
- [ ] `bash scripts/check-publish.sh` passes. It dry-runs the crates.io
      publish of the whole workspace. See
      [Dry run](#dry-run).
- [ ] `[workspace.package].version` in `rust/Cargo.toml` is bumped to a version
      **not already published** (crates.io versions are immutable &mdash; a re-publish
      of an existing version fails the whole `cargo publish` run).
- [ ] `CHANGELOG.md` has an entry for this version; move items from
      `## [Unreleased]` into `## [X.Y.Z] - YYYY-MM-DD`. If a dated section
      for this version already exists, fold the `Unreleased` items into it
      and set its date to the release date, so the file holds one section
      for the version.
- [ ] Version bumped wherever it is hard-coded: README install snippets,
      `docs/INSTALL.md` (four sites: two `VERSION=` snippets, the expected
      `kit version` output, and the pinned `kit self update` example),
      `docs/LIBKIT.md` (the two `libkit` dependency snippets), the `"=X.Y.Z"`
      example in `CONTRIBUTING.md`, and the `vX.Y.Z` examples in `install.sh`
      usage text.
- [ ] [Signing and verification](#signing-and-verification) and
      [Reproducibility](#reproducibility) still accurate for this release.
- [ ] `bash scripts/wasm-package.sh <empty dir>` builds the npm package, and
      `npm pack --dry-run` in that directory lists the files you expect.
      CI runs the same build. npm publishing needs npm 11.5.1 or newer, and
      the `publish-npm` job stops on an older npm.
- [ ] The trusted publisher of `@officialunofficial/kit-wasm` on npm names
      `release.yml` and the environment `npm` (see
      [Publishing to npm](#publishing-to-npm)).
- [ ] Every publishable crate has a trusted publisher on crates.io that names
      `release.yml` and the environment `crates-io`, and the GitHub environment
      `crates-io` exists and allows only `v*` tags (see
      [Publishing to crates.io](#one-time-setup)). Without the trusted
      publishers, the `publish-crates` job fails after the GitHub Release
      exists. A job that names an environment that does not exist creates it
      with no rules, so create the environment with the tag rule first.
- [ ] `HOMEBREW_TAP_TOKEN` is available to the release workflow and grants
      Contents write access to `officialunofficial/homebrew-tap`.
- [ ] `KIT_RELEASE_GPG_FINGERPRINTS` repo/org Actions variable contains the
      release tag signing key fingerprint.
- [ ] The release tag signing public key is published to `keys.openpgp.org` or
      `keyserver.ubuntu.com` so the workflow can import it before
      `git verify-tag`.
- [ ] `SECURITY.md` disclosure contact confirmed reachable.
- [ ] Confirm that the `kit-ci-main` build on Cloud Build and the macOS leg
      (`macos.yml`) both succeeded on the release commit. The macOS leg runs
      only on pushes to `main` and on demand
      (`gh workflow run macos.yml --ref main`). It is the only check that
      runs the native macOS Keychain backend.

### Wait for the release workflows

- [ ] `release.yml` succeeded through `validate-release-tag`, `verify-crates`
      and all four platform builds.
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
- [ ] The `publish-npm` job succeeded, and `npm view
      @officialunofficial/kit-wasm@X.Y.Z version` prints `X.Y.Z`.
- [ ] The `publish-crates` job succeeded, and `cargo info kit-core@X.Y.Z`
      (or the crate page) shows the version for every crate in
      [the table](#what-publishes-vs-what-doesnt). If either publish job failed,
      re-run the failed job alone (see
      [Rerun a failed publish](#rerun-a-failed-publish)). Do not move on while
      npm and crates.io hold different versions.
- [ ] `npm audit signatures` passes in a project that installs
      `@officialunofficial/kit-wasm@X.Y.Z`. It checks the registry signature
      and the provenance attestation.

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

- [ ] For a stable release, confirm `update-homebrew` succeeded and
      `officialunofficial/homebrew-tap/Formula/kit.rb` has the new version
      and the archive hashes from the published `SHA256SUMS`.
- [ ] Release notes reviewed (auto-generated by `softprops/action-gh-release`
      plus the signing snippet).
- [ ] Pin the release in the repo sidebar; post in relevant channels.
- [ ] After the stable release formula is current, dispatch
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
2. Prepare the release PR. Use the release PR that release-plz opens (see
   [The release PR](#the-release-pr)), or prepare it by hand: bump
   `[workspace.package].version` in `rust/Cargo.toml` (to a version not yet
   on crates.io) and update `CHANGELOG.md` (move `Unreleased` items into
   `[X.Y.Z] - YYYY-MM-DD`, leaving a fresh `[Unreleased]` heading above it).
   If a dated section for that version already exists, fold the `Unreleased`
   items into it, merge the entries by kind, and set its date to the release
   date, so the file holds one section for the version.
3. Review the release PR and merge it.
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
   `validate-release-tag` → `build` (× 4 archs) / `verify-crates` (parallel) →
   `sbom` / `third-party-notices` (parallel) → `release` → `publish-npm` and
   `publish-crates` (parallel) → `update-homebrew` for stable releases.
6. Run the [smoke test](#smoke-test).

### The release PR

The workflow `.github/workflows/release-plz.yml` runs release-plz. A
maintainer starts it with `workflow_dispatch`. It does nothing until the
repository variable `KIT_RELEASE_PLZ_ENABLED` is `true`.

release-plz reads the Conventional Commits since the last `vX.Y.Z` tag. It
opens one PR that bumps the shared version of all crates and adds the new
entry to `CHANGELOG.md`. It checks the public API for breaking changes with
`cargo-semver-checks`. Edit the PR if the entry needs better wording.

release-plz does not tag, publish or create a GitHub release. After the merge,
a maintainer cuts the signed tag and the `release.yml` run for that tag publishes the crates. The
settings are in `rust/release-plz.toml`.

## Publishing to crates.io

The `publish-crates` job of `release.yml` publishes every workspace member
without `publish = false` to crates.io. It uses crates.io trusted publishing:
the job asks GitHub for an OIDC token, and crates.io exchanges it for a
publish token. The token lasts 30 minutes, covers only the crates whose
trusted publisher matches the run, and the
[`rust-lang/crates-io-auth-action`](https://github.com/rust-lang/crates-io-auth-action)
step revokes it when the job ends. No crates.io token or repository secret
exists. The trusted publisher cannot publish a new crate, only a new version of
a crate that is on crates.io.

Two jobs do the work, both on the commit that `validate-release-tag` checked.

The `verify-crates` job runs `cargo publish --workspace --dry-run --locked`.
It packs and builds every crate to publish. The GitHub Release waits for it,
so a build failure stops the release before anything is published. It has no `id-token` permission and no
environment. The build scripts and proc macros of the dependencies run there,
and they have no way to get a crates.io token. A crate that is already on
crates.io only makes the dry run warn.

The `publish-crates` job runs in the GitHub environment `crates-io`, after the
GitHub Release and `verify-crates` succeed. It runs beside `publish-npm` and
does not wait for it, so the two never block each other. The job:

1. Checks that every publishable crate has the version of the tag. A
   mismatch stops the job before any upload.
2. Asks the crates.io API about each crate at that version (200 means
   published, 404 means not yet, anything else stops the job). A 404 also
   stops the job when the crate has no version at all, because a trusted
   publisher cannot create a crate. The job excludes each published crate with
   `--exclude` and ends if all of them are published. cargo does not do this
   itself: it stops with `crate X@V already exists` when any selected crate is
   on the registry, before it uploads anything.
3. Gets the token and runs `cargo publish --workspace --locked --no-verify`
   with the same `--exclude` flags. `--no-verify` skips the build because
   `verify-crates` built the same commit with the same lockfile. The job
   therefore runs no third-party build code while it can reach an OIDC token or
   the publish token. cargo publishes the crates in dependency order and
   waits for each to index before the next.

A crate that publishes cannot be republished, so a problem found after the
first upload needs a new version.

### Dry run

Run `bash scripts/check-publish.sh` before you tag. The script runs
`cargo publish --workspace --dry-run --locked`. The `--dry-run` flag is fixed
in the script, so the script cannot publish. It accepts no other argument
than `--allow-dirty`, which is for a local tree with uncommitted changes.

The kit crates depend on each other, and none is on the registry before the
first release. A dry run of one crate with `cargo publish -p <crate>
--dry-run` fails for that reason. The `--workspace` form packs the crates in
dependency order and verifies each crate against the packed copies of the
others. Use it for every dry run.

The script then packs each publishable crate and fails when an archive is
larger than 5 MB. crates.io rejects an archive larger than 10 MB. The
`publish-dry-run` step of
[`cloudbuild/supply.yaml`](../cloudbuild/supply.yaml) runs the script on each
pull request that changes a manifest, the lockfile or the script.

The dry run prints one warning for each test file and each example that a
crate does not ship, such as the kit-core example
`generate_refs_index_goldens`, the kit-sync example `gen_zstd_fixture` and
the libkit example `open_repo`. The warnings are expected.

### Semver check

The workflow `.github/workflows/semver.yml` runs `scripts/check-semver.sh`
on each pull request that changes `rust/`. The script runs
`cargo semver-checks` on each published crate. The baseline is the latest
release tag, built with the `Cargo.lock` of that tag. A build of the
published crate resolves its dependencies again, and a later dependency
release can break that build. The locked build avoids this.

A breaking change fails the check unless the workspace version bump allows
it. In a 0.x release, a minor bump allows a breaking change. The check skips
`kit-bin`, whose library surface is not a public API.

Run the same check by hand before you tag:

```sh
bash scripts/check-semver.sh
```

### What a crate ships

Each publishable crate sets `include` in its `Cargo.toml`. The list names
`src/`, `README.md`, the two license files and, where the crate needs them,
`build.rs`, `generated/` and `proto/`. Nothing else ships.

The `tests/`, `examples/` and `proptest-regressions/` directories do not
ship. The tests read golden vectors and helper crates in the repository, and
those files are not in a published copy. Run the tests from a checkout of the
tag.

Each crate directory holds a `README.md` and links to `LICENSE-APACHE` and
`LICENSE-MIT`. Each manifest sets `description`, `license`, `repository`,
`readme`, `keywords` (at most five), `categories` and `rust-version`. A crate
with features sets `[package.metadata.docs.rs]` with `rustdoc-args = ["--cfg",
"docsrs"]`.

Review the file list of a crate with `cargo package --list -p <crate>`.

### What publishes vs. what doesn't

| Publishes to crates.io | Stays off crates.io (`publish = false`) |
|---|---|
| In publish (dependency) order: `kit-core`, `kit-rpc`, `kit-attest`, `kit-keystore`, `kit-transport-file`, `kit-serve`, `kit-client`, `kit-sync`, `kit-transport-memory`, `kit-transport-connect`, `kit-transport-s3`, `kit-transport-ssh`, `kit-git-bridge`, `libkit`, and `kit-bin` (so `cargo install kit-bin` works) | `kit-sign-file`, `kit-test-util`, `kit-formal-conformance`, `fuzz`, `benches`, and `kit-wasm`, which `release.yml` publishes to npm. |

The published crates depend only on each other, forming a closed,
dependency-ordered set. The table lists them in that order.
`cargo publish --workspace` works the order out itself and skips any
`publish = false` member, so no crate is published by hand one at a time.

Notes on the published set:

- **`kit-bin`** &mdash; published so `cargo install kit-bin` installs the `kit`
  binary; it also ships via the signed GitHub Release archives and `cargo
  install --git`. Its library surface is unstable CLI internals, deliberately
  **not** a public API &mdash; kept out of the pre-publish semver gate. Depend on the `kit-*`
  library crates, not on `kit_bin::…`.
- **The crates.io `kit` name** belongs to an unrelated project; the CLI is
  published as **`kit-bin`**. Do not run `cargo install kit`.

### One-time setup

Do this once, before the tag that first runs the job. Every published crate
is already on crates.io, so the setup can be done at any time before the tag.

1. In the repository settings on GitHub, create the environment
   `crates-io`. Under deployment branches and tags, allow only tags that match
   `v*`. crates.io checks the repository, the workflow filename and the
   environment of the run, not its ref, so this rule is what keeps a branch
   from getting a token. Required reviewers are optional. A required reviewer
   makes the job wait for approval.
2. For each crate in [the table](#what-publishes-vs-what-doesnt), an owner of
   the crate opens `https://crates.io/crates/<crate>/settings`, goes to
   Trusted Publishing, and adds a GitHub configuration:

   | Field | Value |
   | --- | --- |
   | Repository owner | `officialunofficial` |
   | Repository name | `kit` |
   | Workflow filename | `release.yml` |
   | Environment | `crates-io` |

   Fill in the environment. The form marks it optional, but a configuration
   without an environment accepts a token from any job of `release.yml`,
   including the jobs that build and sign. The configuration belongs to one
   crate, so repeat it for each of the crates. You must own the crate, have a
   verified email address and have a linked GitHub account. crates.io checks
   that the GitHub owner exists when you save. It checks the repository, the
   workflow filename and the environment only when a run asks for a token. The token of
   a run covers exactly the crates that have a matching configuration, so a
   crate without one cannot publish, and the job fails at the upload of that
   crate. A crate that is configured for one environment name only accepts a
   run from that environment.
3. After the first successful publish from the job, optionally enable
   "Require trusted publishing for all new versions" for each crate on the same
   settings page. An API token can then no longer publish the crate, and the
   [manual fallback](#manual-fallback) stops working until you turn the
   setting off.

crates.io emails the owners of a crate when a trusted publisher is added, and
for each publish to owners who have publish notifications turned on.

### Rerun a failed publish

Re-run only the failed job from the Actions UI ("Re-run failed jobs") or with
`gh run rerun <run-id> --failed`. The job reads the registry again, excludes
the crates that landed and publishes the rest, so it never fails on, and never
changes, a version that is on crates.io. When the job fails after the GitHub
Release and `publish-npm` succeeded, only `publish-crates` runs again. Do the
same for `publish-npm` when it is the one that failed: it also skips a version
that is already on npm.

The rerun checks out the commit that the first run validated, not a branch.
When GitHub no longer allows a rerun of the run, use the manual fallback
below.

### Manual fallback

Use this only when the job cannot run. A maintainer who owns the crates checks
out the signed tag, checks that the version of every crate in `rust/Cargo.toml`
equals the tag, and finds the crates that are already published (`cargo info
<crate>@X.Y.Z`). Then, with a crates.io API token that has the publish-update
scope in `CARGO_REGISTRY_TOKEN`:

```sh
cd rust
cargo publish --workspace --dry-run --locked --exclude <crate> ...
cargo publish --workspace --locked --exclude <crate> ...
```

Pass one `--exclude` for each published crate and none when none is
published. Keep the token out of the repository and revoke it afterwards.

### Gotchas

- **Immutable versions**: crates.io never lets you overwrite a published
  version. Always bump before tagging; never re-publish an existing version.
- **Partial publish**: if a publish fails mid-train, the crates that landed
  cannot be published again. The job excludes them on a rerun, and the manual
  fallback does the same with `--exclude`.
- **Token lifetime**: the token lasts 30 minutes from the moment the job gets
  it, and the publish waits for each crate to index. A run that outlasts the
  token fails on the next upload. Re-run the job to continue.
- **`--no-verify`**: the job passes it because `verify-crates` already built the
  crates, so the job runs no build while it holds a token. Do not use it
  anywhere else. A publish that skips the build checks nothing.
- **Native deps**: `cargo publish` builds each crate with **default** features.
  No `protoc` is needed, because `kit-rpc` ships its generated code in
  `generated/`. No hardware keystore backend is implemented.

## Publishing to npm

The `publish-npm` job of `release.yml` publishes the `kit-wasm` package as
`@officialunofficial/kit-wasm`. It runs after the GitHub Release exists, on
the commit that `validate-release-tag` checked. It uses npm trusted
publishing: the job asks GitHub for an OIDC token and npm exchanges it for a
short-lived publish credential. No npm token or repository secret exists.
The job runs in the GitHub environment `npm`, and the trusted publisher names
that environment. Other jobs of `release.yml` hold `id-token: write` for
cosign, but their tokens carry no environment, so they do not match the
trusted publisher. npm adds a provenance attestation to the version without a
flag.

The job:

1. Asks the registry whether the version is on npm, and ends if it is. npm
   versions are immutable, so a re-run of the workflow after a publish does
   nothing.
2. Installs the pinned Rust toolchain, the `wasm-bindgen` version of
   `rust/Cargo.lock` and Node 24, and stops when npm is older than 11.5.1.
3. Runs `scripts/wasm-package.sh`, checks that `package.json` has the name
   and the version of the tag, and lists the files with `npm pack --dry-run`.
4. Runs `npm publish --access public`. The tag `latest` moves to the new
   version. A version with a prerelease suffix, such as `0.8.0-rc.1`, gets the
   tag `next` and never becomes `latest`.

The version on npm equals the version of the tag and of the workspace. A
build that has to change after a publish needs a new version.

### One-time setup

npm can configure a trusted publisher only for a package that exists, so the
first version goes up by hand.

1. An owner of the `officialunofficial` npm scope publishes a first version
   with a throwaway number, for example `0.0.0-init`, using
   `npm publish --access public --tag init`. A directory with a
   `package.json` (name, version, license, repository) and a one-line README is
   enough. Use an npm account with two-factor authentication. The registry
   may set `latest` on this first version, and `latest` stays there until the
   first release from the workflow.
2. In the repository settings on GitHub, create the environment `npm`. Under
   deployment branches and tags, allow only tags that match `v*`. Without that
   rule, a branch whose copy of `release.yml` names the environment gets a
   token that npm accepts. Required reviewers are optional.
3. In the package settings on npmjs.com, add a trusted publisher: provider
   GitHub Actions, organization `officialunofficial`, repository `kit`,
   workflow filename `release.yml`, environment `npm`. The fields are
   case-sensitive, and npm does not check them until a publish.
4. Push the release tag. A new trusted publisher expires unless it sees a
   successful publish within 2 days. Create it right before the tag, and
   delete and create it again if it expires.
5. After the first publish from the workflow, remove the throwaway version:
   `npm dist-tag rm @officialunofficial/kit-wasm init` and `npm deprecate
   @officialunofficial/kit-wasm@0.0.0-init "not a release"`. In the package
   settings, require two-factor authentication and disallow tokens.

Every plain release moves `latest` to its version, so release in version
order.

Trusted publishing runs only on GitHub-hosted runners and needs npm 11.5.1 or
newer. The `repository.url` in `package.json` must match the GitHub
repository, or the provenance check fails. `scripts/wasm-package.sh` writes
it from the workspace.

A tag runs the `release.yml` it points at, and a workflow that is dispatched by
hand runs the `release.yml` of the ref it was dispatched from. The tag of a
release must contain the `publish-npm` job to publish to npm.

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
`kit-bin` target for that platform. The CLI enables the matching keystore
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
license check cargo-deny already runs on every PR in the `supply` step of
`cloudbuild/ci.yaml`). The `third-party-notices` step of
`cloudbuild/supply.yaml` runs the same `cargo about generate` check on every
PR that touches the dependency graph, so an unapproved license is caught
before a release attempt, not during one.

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
- **System libs:** default release builds link glibc (Linux) or the platform C
  runtime (macOS). OS keystore features use Security.framework or D-Bus Secret
  Service. They are platform-gated and fail closed when the service is
  unavailable. The Linux Secret Service
  feature selects the pure-Rust crypto runtime, not OpenSSL. Production
  `kit-bin` builds enable the target-appropriate software protector feature so
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
are sourced from crates.io. `Cargo.toml` sets their lower bounds, and
`Cargo.lock` pins their resolved versions. The library enables OS backends
only through features; production CLI builds enable the matching OS feature.

| Dependency | Use | Gate | License |
|---|---|---|---|
| `chacha20poly1305 = 0.11.0` | XChaCha20-Poly1305 software-key envelope encryption | always-on keystore crypto | Apache-2.0 OR MIT |
| `zeroize = 1.9.1` | Secret-memory clearing | always-on keystore crypto | Apache-2.0 OR MIT |
| `security-framework = 3.7.0` | macOS Keychain bindings | `backend-macos-keychain` (macOS only) | MIT OR Apache-2.0 |
| `keyring-core = 1.0.1` | Shared keyring abstraction | `backend-linux-secret-service` | MIT OR Apache-2.0 |
| `zbus-secret-service-keyring-store = 1.0.1` | Linux Secret Service store | `backend-linux-secret-service` (Linux only; OpenSSL-free) | MIT OR Apache-2.0 |

`systemd-creds` and YubiKey are reserved backend names with no implementation
or Cargo feature. No PC/SC or YubiKey dependency is in the keystore manifest.
The remaining direct dependencies are listed in
`rust/crates/kit-keystore/Cargo.toml`. Live OS backend tests are opt-in via
`KIT_RUN_NATIVE_KEYSTORE_TESTS=1`.

### GitHub Actions dependencies

All third-party actions in `.github/workflows/` must be pinned to a major
version tag (`@v4`) or a full SHA. No `@main`, no `@latest`. Trusted publishers:
`actions/*`, `dtolnay/rust-toolchain`, `sigstore/cosign-installer`,
`anchore/sbom-action`, `softprops/action-gh-release`, `ossf/scorecard-action`,
`rust-lang/crates-io-auth-action` (the crates.io project's own action, pinned to
a full SHA in `release.yml`).
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
weekly cadence is `cargo audit` in the `kit-ci-weekly` Cloud Build run (Mondays 06:00 UTC),
which sweeps for newly published advisories against the unchanged dependency
tree. Restoring a scheduled SBOM-drift job is an open follow-up. A CVE against
any shipped dep is a P1: patch, test, tag a new release,
open a GitHub Security Advisory citing the CVE, update `CHANGELOG.md` under
`### Security`, and coordinate disclosure via the `SECURITY.md` contact.

## Reproducibility

Reproducibility is best effort. A kit release binary is a function of a small,
pinned set of inputs. If all of them match, a machine with the same Rust
toolchain should produce a byte-identical binary to the one on GitHub Releases.
No CI job proves this. A CI job proves only that two builds of one commit
agree on one runner. See [what is not guaranteed](#ci-safety-net-and-what-is-not-guaranteed).

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
6. **Path prefixes** &mdash; the release build remaps the checkout path to `/build`
   and the cargo home to `/cargo`, so host paths stay out of the binary.

### Reproducing a published binary

```sh
# 1. Clone at the release tag.
git clone --depth 1 --branch vX.Y.Z https://github.com/officialunofficial/kit.git
cd kit/rust
# 2. rustup picks up rust-toolchain.toml on first `cargo` invocation.
# 3. Build for your target with release.yml's command (`-p kit-bin`
#    selects only the CLI; a bare `--bin kit` unifies other members'
#    features and differs).
export RUSTFLAGS="-C codegen-units=1 -C strip=symbols --remap-path-prefix=$(cd .. && pwd)=/build --remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo"
TARGET=x86_64-unknown-linux-gnu
cargo build --release --locked --target "$TARGET" -p kit-bin --bin kit
# 4. Hash the binary.
shasum -a 256 "target/$TARGET/release/kit"
# 5. Compare against the SHA256SUMS inside each release archive.
```

If the hashes don't match, treat it as a supply-chain incident: open an issue
with your host OS, `rustc --version`, the sha256 you got, and the expected one.
`diffoscope` on the two binaries usually isolates the culprit.

### CI safety net and what is not guaranteed

The `reproducible-build.yml` workflow builds `kit` twice from one commit. It
uses `release.yml`'s flags and command for `x86_64-unknown-linux-gnu`. Each
build runs in its own directory, and the two paths have different lengths. The
job fails when the sha256 hashes differ. It proves that, on one runner image
with the pinned toolchain, the binary does not depend on the checkout path or
the build time.

The job does **not** prove a match with the binary on GitHub Releases. It does
not prove a match on another operating system, linker or toolchain version. The
manual procedure above is the verification path for a published binary. A
divergence between two builds of the same commit means a non-deterministic
input has crept in (embedded timestamps, random seeds, absolute paths in debug
info, unsorted directory reads) and must be fixed before the next tag.

Binaries built on your local macOS are not expected to match GitHub's `macos-26`
runner byte-for-byte unless your OS, SDK, and linker versions match. The Linux
x86_64 build is the most reliable reproducibility target for third parties.

## Required GitHub Actions secrets and variables

Cosign keyless signing and trusted publishing to npm and crates.io use
GitHub OIDC.

| Secret or variable | Purpose | Required for |
| --- | --- | --- |
| `HOMEBREW_TAP_TOKEN` (secret) | Contents write access to `officialunofficial/homebrew-tap` | `release.yml` tap preflight and formula update |
| `KIT_RELEASE_GPG_FINGERPRINTS` | Space-separated trusted 40-hex GPG fingerprints allowed to sign release tags (public keys must be on `keys.openpgp.org` or `keyserver.ubuntu.com`) | `release.yml` preflight |
| `KIT_RELEASE_PLZ_ENABLED` | Set to `true` to let `release-plz.yml` run | `release-plz.yml` |

The release PR workflow also needs the secrets `RELEASE_PLZ_APP_ID` and
`RELEASE_PLZ_APP_PRIVATE_KEY`. They identify a GitHub App that opens the PR.
