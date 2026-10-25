# Contributing to kit

kit is security software. Every change meets the same review bar. This file
states that bar.

Report a vulnerability in private. Do not open a public issue. Follow
[`SECURITY.md`](SECURITY.md).

## License

You license your contribution under MIT OR Apache-2.0. See
[`LICENSE-MIT`](LICENSE-MIT) and [`LICENSE-APACHE`](LICENSE-APACHE). There is no
CLA.

## Where things live

| Area | Path |
|---|---|
| Rust workspace | `rust/` |
| The `kit` binary | `rust/crates/kit-storage/` |
| Objects, packs, refs, signing | `rust/crates/kit-core/` |
| Attestations | `rust/crates/kit-attest/` |
| Transports | `rust/crates/kit-transport-*/` |
| Format specs | `docs/specs/SPEC-*.md` |
| Golden vectors | `rust/tests/golden/` |
| Fuzz targets | `rust/fuzz/` |
| Check scripts | `scripts/` |

## Set up

The toolchain version is in `rust/rust-toolchain.toml`. `rustup` installs it on
the first build.

```sh
cd rust
cargo build --workspace
cargo test --workspace
```

`cargo t` runs the tests with `cargo nextest`. Install it with
`cargo install cargo-nextest --locked`.

## Checks before you commit

Run all of these. CI runs them too.

```sh
cd rust
cargo fmt --check
cargo clippy --locked --all-targets --all-features --workspace -- -D warnings
cargo test --locked --workspace
cd ..
bash scripts/check-writing.sh
bash scripts/test-check-writing.sh
bash scripts/check-unsafe-safety.sh
bash scripts/check-unsafe-policy.sh
bash scripts/check-doc-paths.sh
python3 -I -B scripts/check-format-constants.py
```

## Rules for code

These rules come from [`AGENTS.md`](AGENTS.md). Read that file first.

- Parse hostile input strictly. Reject malformed, non-canonical and trailing
  bytes.
- Check a limit before you allocate. Never size an allocation from a length in
  the input.
- Verify hashes, signatures and attestations before you use the data they cover.
- Never write secrets to logs, errors or test snapshots.
- Do not use `unsafe` without a `// SAFETY:` comment.
- Give each domain-separation tag, magic and predicate URI a unique value.
- Fail closed on an unknown version, algorithm or field.
- Do not vendor code. Depend on published crates at exact versions.
- Add a dependency only when the code cannot do without it.
- Do not leave dead code. Do not add speculative options.
- Do not check in generated output unless a build needs it. Say why next to the
  file.

## Tests

- Every new behavior needs a test.
- A bug fix includes a test that fails without the fix.
- Every parser needs a fuzz target in `rust/fuzz/`.

## Format changes

A format change updates the spec and the golden vectors in the same commit. The
golden vectors must pass in the Rust code and in an independent reference check.
Never change a published tag, magic or constant to fix a style issue.

## Writing

Docs, comments, commits and issues use short, active sentences in the present
tense. They use one term for one concept. They do not name phases, stages,
tickets, pull requests, trackers, tools or models. They describe what the code
does now.

## Commits

- Sign every commit.
- Make one logical change per commit.
- Write a subject of 72 characters or fewer, in the imperative mood.
- Write a body that explains why the change is needed.
- Add no trailer that names a tool or a model.
