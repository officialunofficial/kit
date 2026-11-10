# Contributing to kit

kit is security software. Every change meets the same review bar. This file
states that bar.

Report a vulnerability in private. Do not open a public issue. Follow
[`SECURITY.md`](SECURITY.md).

All contributors follow the [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

## License

You license your contribution under MIT OR Apache-2.0. See
[`LICENSE-MIT`](LICENSE-MIT) and [`LICENSE-APACHE`](LICENSE-APACHE). There is no
CLA.

## Where things live

| Area | Path |
|---|---|
| Rust workspace | `rust/` |
| The `kit` binary | `rust/crates/kit-bin/` |
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
bash scripts/test-check-commit-messages.sh
bash scripts/check-unsafe-safety.sh
bash scripts/check-unsafe-policy.sh
bash scripts/check-doc-paths.sh
bash scripts/test-check-doc-paths.sh
python3 -I -B scripts/check-format-constants.py
python3 -I -B scripts/check-dependency-versions.py
bash scripts/test-check-dependency-versions.sh
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
- Do not vendor code. Depend on published crates.
- Add a dependency only when the code cannot do without it.
- Do not leave dead code. Do not add speculative options.
- Do not check in generated output unless a build needs it. Say why next to the
  file.

## Dependency versions

`Cargo.lock` is committed. It holds the exact version of each external crate.
CI builds with `--locked`, so a build never picks a newer version.

A published library crate must let its users resolve a dependency. So each
external requirement is a caret requirement, such as `"1.2.3"`. The lower bound
is a full version and equals the version in `Cargo.lock`. Do not write `=`,
`*`, `~` or a short version such as `"1.2"`.

All kit crates share one version. Each kit-* requirement is exact, such as
`"=0.8.0"`, and has a `path`. A dependency with a `path` and no version is valid
only in `dev-dependencies` or in a crate with `publish = false`.

The rules cover every manifest, including binary, fuzz and bench crates.
`scripts/check-dependency-versions.py` checks them. Run `cargo update --package
<name>` and then edit the lower bound to change an external version. Both
changes go in one commit.

## Rust style

Clippy enforces these rules in CI, with `rustfmt`.

- Do not call `unwrap()` outside tests. Use `expect("why this cannot fail")`
  only for a documented invariant.
- Do not use glob imports (`use foo::*`) outside test modules and preludes.
- Do not commit `todo!()` or `dbg!()`.
- Put a `// SAFETY:` comment on every `unsafe` block. State the invariant it
  relies on.
- Add a doc comment to each public item. Use comments to explain why, not what.
- Prefer small functions and early returns. Match every variant of an enum that
  the crate owns. Do not use a wildcard arm.

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
- Write the subject as a Conventional Commits header: `type(scope): subject`. The type is `feat`, `fix`, `docs`,
  `refactor`, `perf`, `test`, `build`, `ci` or `chore`. The scope names the crate or area and is optional. Add `!` after
  the scope for a breaking change.
- Keep the header at 72 characters or fewer. Write the subject in the imperative mood.
- Write a body that explains why the change is needed.
- Add no trailer that names a tool or a model.

`scripts/check-commit-messages.py` checks the header form, the type, the header length and the trailers. It checks
the commits of a pull request only, and it skips merge commits. CI runs it. It cannot check the imperative mood, so a
reviewer does.
