# Cloud Build CI for kit

The Rust CI of kit runs on Google Cloud Build. This directory holds the build
configurations. `scripts/setup-cloud-build.sh` sets up the Google Cloud side
and creates the triggers. A maintainer runs that script once. No build runs it.

## Why Cloud Build

- **A durable cache.** A build runs as a service account. `sccache` reaches a
  Cloud Storage bucket through the metadata server. No key file is needed.
- **Large machines.** The main build uses 32 vCPUs and a 200 GB disk. The
  steps run in parallel on one VM.
- **One toolchain image.** `Dockerfile.ci` pins every tool once. Each run uses
  the same environment.

## Scope

Cloud Build owns every gate that runs on a Linux container. GitHub Actions
owns only the work that Cloud Build cannot do:

| Work | Where | Why |
|---|---|---|
| Format, lint, tests, docs, generated code, golden checks, writing and unsafe checks, fuzz smoke, supply checks | Cloud Build (`ci.yaml`) | Runs on Linux. |
| Third-party notices, release artifact check, publish dry run | Cloud Build (`supply.yaml`) | Runs on Linux. |
| Latest-release probe of the Connect stack | Cloud Build (`connect-latest.yaml`) | Runs on Linux. |
| Public Rust checks (`rust.yml`) | GitHub Actions | Contributors read the result on GitHub. |
| Weekly advisory sweep (`rust-security.yml`) | GitHub Actions | It runs on a schedule, and it shows the result on GitHub. |
| macOS tests (`macos.yml`) | GitHub Actions | Cloud Build has no macOS machines. |
| Release (`release.yml`) | GitHub Actions | The signing identity is the workflow itself. |
| Release verification (`release-verify.yml`) | GitHub Actions | It runs by hand after a release, and it needs macOS runners for the Homebrew check. |
| Nightly fuzz (`fuzz.yml`) | GitHub Actions | It needs a floating nightly toolchain, a matrix of one job per target, and crash artifacts that GitHub keeps. |
| Nightly formal verification (`formal.yml`) | GitHub Actions | It needs Java, Node and Apalache, which the builder image does not hold. |

Only `rust.yml`, `rust-security.yml`, `docs-lint.yml`, `proto.yml` and
`third-party-notices.yml` repeat the gate commands of Cloud Build. They run the same commands, so a result on one service predicts the
other. `scripts/test-ci-gates.py` fails when any other workflow file repeats a
gate command of Cloud Build.

### Why each remaining workflow stays

- `rust.yml` stays because contributors read the result on GitHub. Its jobs run the commands of the `fmt`, `lint`, `tests-misc`, `version` and nextest steps. Its `Rust CI gate` job is the one GitHub check to require.
- `rust-security.yml` stays because it runs on a schedule and shows the result on GitHub. It runs the commands of the `supply` step.
- `docs-lint.yml` stays because contributors read the spec and path checks on GitHub when they change a document.
- `actionlint.yml` stays because contributors read the workflow lint on GitHub when they change a workflow. The `workflows` step of `ci.yaml` runs the same tool.
- `dependabot-auto-merge.yml` stays because it acts on GitHub pull requests of Dependabot. Cloud Build cannot do that.
- `semver.yml` stays because it needs the release tags in the git history. It runs `scripts/check-semver.sh`, which checks the public API of each published crate against the latest release tag.
- `mutants.yml` stays because it runs for hours. A pull request mutates only the changed lines, and a weekly run sweeps the security crates.
- `proto.yml` stays because the `buf` breaking check compares a pull request with its base branch on GitHub. It also runs the generated-code check.
- `release-plz.yml` stays because it opens the release pull request on GitHub. It does nothing until a maintainer enables it with a repository variable.
- `third-party-notices.yml` stays because contributors read the license check on GitHub when a dependency changes.
- `macos.yml` stays because Cloud Build has no macOS machines.
- `release.yml` stays because the signing identity is the workflow itself.
- `reproducible-build.yml` stays because it builds the release binary twice in two directories with the flags of `release.yml`, which a Cloud Build step has no need to repeat. It compares the hashes on the runner image that `release.yml` uses.
- `release-verify.yml` stays because a person starts it by hand after a release, and its Homebrew check needs a macOS runner.
- `fuzz.yml` stays because it needs a floating nightly toolchain and runs one job per target. It also keeps crash artifacts on GitHub. The `fuzz-smoke` step of `ci.yaml` covers the pinned nightly.
- `formal.yml` stays because it needs Java, Node and Apalache. The builder image does not hold them, and the jobs run for hours.

## Files

| File | Purpose |
|---|---|
| `Dockerfile.ci` | The toolchain image: the Rust version of `rust/rust-toolchain.toml`, protoc, mold, nextest, sccache, cargo-deny, cargo-audit, cargo-geiger, cargo-about, cargo-fuzz, b3sum, wasm-bindgen-cli, Node, actionlint, and a dated nightly toolchain for cargo-fuzz. Every tool has one exact version. |
| `builder.yaml` | Builds `Dockerfile.ci` and pushes the image. It reads the Rust version from `rust/rust-toolchain.toml`. Run it again when `Dockerfile.ci` or that file changes. |
| `ci.yaml` | The main suite. See the steps below. |
| `supply.yaml` | The `third-party-notices`, `release-artifact-check` and `publish-dry-run` steps. |
| `connect-latest.yaml` | The `connect-latest` step. |

## Steps of `ci.yaml`

All steps start at once. The exceptions are the test steps that need the
archive. They wait for `nextest-archive`.

| Step | Gate |
|---|---|
| `fmt` | `cargo fmt --check`. |
| `lint` | `clippy -D warnings` over every target and feature. The minimum Rust version gate: the image compiler, `rust-version` and `rust-toolchain.toml` must agree, and `cargo check` passes on every target. |
| `docs` | `cargo doc` with `-Dwarnings`. |
| `nextest-archive` | Builds every workspace test binary once. This is the only step that links with mold. |
| `nextest-1`, `nextest-2`, `nextest-3` | The workspace tests in three partitions. They run from the archive. Each step calls `scripts/ci-nextest.sh` with its partition number. |
| `ignored-lane` | The serial lane for ignored tests. It runs from the archive. |
| `tests-misc` | Doctests, and the `libkit` feature sets. |
| `version` | `kit version` prints exactly `kit <X.Y.Z>`. |
| `cli-baseline` | The default `kit` build has no server code. |
| `wasm` | `kit-client` builds for wasm32 with the default and the minimal feature set. `kit-wasm` builds for wasm32 as a release build. The generated Node bindings then pass `scripts/wasm-smoke.sh`. |
| `fuzz-smoke` | The fuzz bodies run as tests. Every libFuzzer target builds and runs for 5 seconds. |
| `golden` | Spec status, spec magics, crypto stack version, exact dependency versions, format constants and the independent Python checks of the golden vectors. |
| `generated` | The checked-in protocol code matches the `.proto` files. |
| `writing` | The writing rules over the tree and over new commit messages, the Conventional Commits form of new commit messages, the cited paths and the installer test. |
| `unsafe` | A SAFETY comment on every `unsafe` site, the unsafe policy of every crate root and the cargo-geiger ceilings. |
| `supply` | `cargo deny`, `cargo audit` and the deadline of the advisory ignore. |
| `workflows` | `actionlint` over the remaining GitHub workflow files. |
| `ci-gates` | `scripts/test-ci-gates.py`. It pins the invariants of these files. |

Every step must pass. No step may fail without failing the build. A step that
runs several gates runs all of them and fails at the end, so one run shows
every failure.

The commit message scan in `writing` needs an `origin/main` ref in the
checkout. It skips itself when the ref is missing. Triggers fetch the
repository with git. A manual `gcloud builds submit` uploads the source
without `.git`, so `writing`, `unsafe` and the other steps that read git fail
there. Use a trigger to reproduce a build.

## Triggers

All triggers use the branch `^main$`. A pull request from an organization
collaborator starts at once. A pull request from an external contributor waits
for a maintainer comment `/gcbrun`.

| Trigger | Configuration | Runs |
|---|---|---|
| `kit-ci-pr`, `kit-ci-main` | `ci.yaml` | Every pull request and every push to `main`. No path filter, because the writing and path checks read the documents too. |
| `kit-supply-pr`, `kit-supply-main` | `supply.yaml` | When a manifest, the lockfile, the notices policy, the release scripts, the publish check or the `kit-bin` crate changes. |
| `kit-connect-pr` | `connect-latest.yaml` | When a manifest, a lockfile or the probe script changes. |
| `kit-ci-weekly`, `kit-connect-weekly` | `ci.yaml`, `connect-latest.yaml` | Mondays at 06:00 and 05:23 UTC. Opt in with `ENABLE_SCHEDULED_TRIGGERS=1`. A new advisory can match a dependency tree that did not change. |

### Required checks

Make only `kit-ci-pr` a required check. The other pull request triggers use
path filters. A path filter leaves no check on a pull request that touches
none of those paths, and a required check that never appears blocks the merge.
The GitHub workflow `CI: macOS` runs on `main` and on demand, never on a pull
request, so it is not a required check either. The GitHub job `Rust CI gate`
of `rust.yml` runs on every pull request, so a maintainer can require it.

## Test compilation and linking

The `nextest-archive` step builds all test binaries once. It uses two settings
that bound its cost:

- `--build-jobs 4` limits the compiler processes. Many steps share one VM, and
  an unbounded build can exhaust its memory.
- `RUSTFLAGS=-C link-arg=-fuse-ld=mold` links the test binaries with mold. No
  other step sets `RUSTFLAGS`.

**The effect of mold is not yet measured on kit.** A comparable project
measured no change from mold alone, because its link step is not the
bottleneck. Its gain came from the bounded parallel jobs. Treat mold on kit as
unproven until the first runs record numbers.

The step prints one line with the label `ci-timing`:

```text
ci-timing: step=nextest-archive linker=mold build-jobs=4 seconds=<N> status=<0|1>
```

Search the build log for `ci-timing:` and record the value of the first runs.
Then change the linker or the job bound in one commit and compare. Remove mold
from `ci.yaml` and `Dockerfile.ci` if it gives no gain.

## Compiler wrapper

Every step that compiles Rust sets `RUSTC_WRAPPER` to
`scripts/ci-rustc-wrapper.sh`. The wrapper runs `sccache`. Cargo's JSON
renderer drops raw stdout, including the signal messages that sccache prints
when a compiler dies. On failure the wrapper copies that output to stderr and
keeps the exit code. The `unsafe` step has no wrapper, because cargo-geiger
drives `rustc` itself.

## Test failure reporting

Every nextest run uses `--no-fail-fast`, so one failing test does not hide
the others. The partitions use the `ci` profile of `rust/.config/nextest.toml`.
That profile allows two retries and longer time limits for slow tests. The
ignored lane uses the `ignored-lane` profile.

## Secrets

The configuration files hold no secret. `sccache` and the image push use the
identity of the build service account. `scripts/test-ci-gates.py` fails when a
configuration file names a secret.

## Changing the toolchain version

`rust/rust-toolchain.toml` is the one source of the Rust version.
`scripts/toolchain-version.sh` prints it. The image build, the setup script and
the GitHub workflows call that script.

Three places cannot read the file. They are the image tag in the `_CI_IMAGE`
default of every configuration, `msrv` in `clippy.toml` and `rust-version` in
`rust/Cargo.toml`. Change the toolchain file and those places in one commit.
Then run `builder.yaml`, which fails when the image tag differs from the file.
The other configurations run the image by its digest, so a tag that moves
cannot change what runs. After each run of `builder.yaml`, read the new digest
and write it after `@` in the `_CI_IMAGE` default of `ci.yaml`,
`connect-latest.yaml` and `supply.yaml`:

```sh
gcloud artifacts docker images describe \
  us-east4-docker.pkg.dev/$PROJECT_ID/docker/kit-ci:rust-<version> \
  --format='value(image_summary.digest)'
```

The date of the nightly toolchain appears in `Dockerfile.ci` and in the
`fuzz-smoke` step. `scripts/test-ci-gates.py` checks all of these places.
