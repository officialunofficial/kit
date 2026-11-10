# AGENTS.md

kit is a content-addressed, signed version-control system. Security comes first. Keep the code small.

## Security

- Parse hostile input strictly. Reject malformed, non-canonical and trailing bytes.
- Bound every allocation by a limit that is checked before the allocation, never by a length read from the input.
- Verify before trust. Check hashes, signatures and attestations before you use the data they cover.
- Never write secrets, keys, tokens or passphrases to logs, errors, debug output or test snapshots.
- Do not use `unsafe` without a `// SAFETY:` comment that states the invariant and why it holds.
- Declare `#![forbid(unsafe_code)]` in every crate root. Use `#![deny(unsafe_code)]` only where a justified `#[allow(unsafe_code)]` site exists. `scripts/check-unsafe-policy.sh` checks this.
- Give every domain-separation tag, magic and predicate URI a unique value. Never reuse one across purposes.
- Fail closed. An unknown version, algorithm or field is an error.

## Formats

- A format change updates the spec and the golden vectors in the same commit.
- Golden vectors must pass in the Rust code and in an independent reference check.
- Run `scripts/check-golden.sh` when you change a golden vector or a spec. CI runs it.
- Never change a published tag, magic or constant to fix a style issue.

## Code

- Do not vendor code. Depend on published crates.
- Commit `Cargo.lock`. It holds the exact audited version of each external crate. CI builds with `--locked`.
- Write each external requirement as a caret requirement with a full lower bound, such as `"1.2.3"`. The lower bound equals the version in `Cargo.lock`.
- Write each kit-* requirement as `"=<workspace version>"` with a `path`. All kit crates share one version.
- `scripts/check-dependency-versions.py` checks these rules. CI runs it.
- Do not check in generated output unless a build requires it. If you do, say why next to the file.
- Do not leave dead code. Do not add speculative features, options or abstractions.
- Add a dependency only when the code cannot reasonably do without it.
- Every new behavior needs a test. Every parser needs a fuzz target.
- Run `cargo fmt`, `cargo clippy -- -D warnings` and `cargo test` before you commit.
- Run `scripts/check-writing.sh` and `scripts/check-unsafe-safety.sh` before you commit. CI runs both.

## Linux on an Apple machine

- Some code and tests build only on Linux. On an Apple machine, run them in a Linux container before you commit a change that they cover.
- Use Apple's `container` command for that. Do not use another container or virtual machine tool when `container` is installed.
- `CONTRIBUTING.md` has the command.

## Writing

- Code, docs, commits and issues must not mention phases, stages, parts, work packages, ticket numbers, PR numbers, trackers, tools or models.
- Describe what the code does now. Do not describe how it got there.
- Write short, active sentences. Use one term for one concept.

## Commits

- Sign every commit.
- Make one logical change per commit.
- Write the subject as a Conventional Commits header: `type(scope): subject`. The type is `feat`, `fix`, `docs`,
  `refactor`, `perf`, `test`, `build`, `ci` or `chore`. The scope names the crate or area and is optional. Add `!` after
  the scope for a breaking change.
- Keep the header at 72 characters or fewer. Write the subject in the imperative mood.
- Write a body that explains why the change is needed, not only what it does.
- Add no trailers that name a tool or a model.
